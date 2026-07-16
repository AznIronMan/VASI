import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { constants, createWriteStream } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { finished } from "node:stream/promises";
import { fileURLToPath } from "node:url";

import { parse as parseYAML } from "yaml";

import policy from "../config/assurance-policy.json" with { type: "json" };
import {
  parseProtectedOverlay,
  validateActivationConfigurationValue,
} from "./activate-production-release.mjs";
import { parseEdgeMonitorConfiguration } from "./edge-monitor-contract.mjs";
import {
  auditPublicIngressConfiguration,
  PUBLIC_INGRESS_EXAMPLE_SETTINGS,
  renderPublicIngressConfiguration,
} from "./public-ingress-config.mjs";
import { discoverSensitiveRoutes } from "./probe-public-route-isolation.mjs";
import { isDirectExecution } from "./direct-execution.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const forbiddenPathPatterns = [
  /(^|\/)\.env(?:\.|$)/,
  /(^|\/)\.private\//,
  /(^|\/)\.tasks\//,
  /(^|\/)data\//,
  /(^|\/)VASI\.settings$/,
  /\.(?:jks|key|p12|pfx)$/i,
];
const secretPatterns = [
  { name: "private-key", pattern: /-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----/ },
  { name: "github-token", pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { name: "google-api-key", pattern: /\bAIza[0-9A-Za-z_-]{32,}\b/ },
  { name: "slack-token", pattern: /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/ },
  { name: "aws-access-key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  {
    name: "credentialed-database-url",
    pattern: /\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?):\/\/[^\s/:]+:[^\s/@]+@/i,
  },
];
export const DIRECT_EXECUTION_ENTRYPOINTS = Object.freeze([
  "scripts/activate-production-release.mjs",
  "scripts/backup-continuity.mjs",
  "scripts/backup-custody.mjs",
  "scripts/backup.mjs",
  "scripts/edge-monitor-contract.mjs",
  "scripts/pilot-gate-evidence.mjs",
  "scripts/probe-capacity-readiness.mjs",
  "scripts/probe-deployment-readiness.mjs",
  "scripts/probe-engine-egress-boundary.mjs",
  "scripts/probe-gateway-operational-readiness.mjs",
  "scripts/probe-operational-readiness.mjs",
  "scripts/probe-public-ingress.mjs",
  "scripts/probe-public-route-isolation.mjs",
  "scripts/probe-readiness-load.mjs",
  "scripts/public-ingress-config.mjs",
  "scripts/readiness-trust-anchor.mjs",
  "scripts/release-assurance.mjs",
  "scripts/render-database-egress-policy.mjs",
  "scripts/render-private-ingress-egress-policy.mjs",
  "scripts/stage-production-release.mjs",
  "scripts/verify-codeql-sarif.mjs",
  "scripts/verify-pilot-admission-evidence.mjs",
  "scripts/verify-readiness-dossier.mjs",
  "scripts/verify-engine-host-runtime.mjs",
  "services/database-gateway/server.mjs",
]);
const prohibitedRuntimeToolPaths = Object.freeze([
  "/usr/bin/npm",
  "/usr/bin/npx",
  "/usr/local/bin/npm",
  "/usr/local/bin/npx",
  "/usr/local/lib/node_modules/npm",
]);
const runtimeDependencyInspector = `
import { existsSync } from "node:fs";

let candidates;
try {
  candidates = JSON.parse(Buffer.from(process.argv[1] || "", "base64url").toString("utf8"));
} catch {
  process.exit(2);
}
if (
  !Array.isArray(candidates) || candidates.length > 10000 ||
  candidates.some((candidate) => typeof candidate !== "string" || candidate.length > 1200)
) process.exit(2);
const present = candidates.filter((candidate) => existsSync(candidate));
process.stdout.write(JSON.stringify({
  present: present.slice(0, 32),
  presentCount: present.length,
  total: candidates.length,
}));
`;

export async function inspectTrackedSource(repositoryRoot = root) {
  const tracked = (await capture("git", ["ls-files", "-z"], { cwd: repositoryRoot }))
    .split("\0")
    .filter(Boolean)
    .sort();
  const forbiddenPaths = tracked.filter((filename) =>
    forbiddenPathPatterns.some((pattern) => pattern.test(filename))
  );
  const secretFindings = [];
  const unboundedGatewayJSONParsers = [];
  const files = [];
  for (const filename of tracked) {
    const absolute = path.join(repositoryRoot, filename);
    const handle = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    let contents;
    try {
      const before = await handle.stat();
      if (!before.isFile()) throw new Error(`Tracked source is not a physical file: ${filename}`);
      contents = await handle.readFile();
      const after = await handle.stat();
      if (
        contents.length !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
      ) {
        throw new Error(`Tracked source changed while it was inspected: ${filename}`);
      }
    } finally {
      await handle.close();
    }
    files.push({
      bytes: contents.length,
      path: filename,
      sha256: createHash("sha256").update(contents).digest("hex"),
    });
    if (contents.includes(0) || contents.length > 4 * 1024 * 1024) continue;
    const text = contents.toString("utf8");
    if (
      /^(?:src\/app\/api|src\/lib)\/.+\.[cm]?[jt]sx?$/.test(filename) &&
      /\brequest\.json\s*\(/.test(text)
    ) {
      unboundedGatewayJSONParsers.push(filename);
    }
    for (const candidate of secretPatterns) {
      if (candidate.pattern.test(text)) {
        secretFindings.push({ path: filename, rule: candidate.name });
      }
    }
  }
  return { files, forbiddenPaths, secretFindings, unboundedGatewayJSONParsers };
}

export async function validateVersionAlignment(repositoryRoot = root) {
  const packageJSON = JSON.parse(await readFile(path.join(repositoryRoot, "package.json"), "utf8"));
  const packageLock = JSON.parse(await readFile(path.join(repositoryRoot, "package-lock.json"), "utf8"));
  const readme = await readFile(path.join(repositoryRoot, "README.md"), "utf8");
  const agents = await readFile(path.join(repositoryRoot, "AGENTS.md"), "utf8");
  const expected = packageJSON.version;
  const actual = {
    agents: /current VASI version is `([^`]+)`/.exec(agents)?.[1],
    package: expected,
    packageLock: packageLock.version,
    packageLockRoot: packageLock.packages?.[""]?.version,
    readme: /^Version: `([^`]+)`/m.exec(readme)?.[1],
  };
  const runtimeSources = [
    ["gateway-health", "src/app/api/health/route.ts", /version:\s*"([^"]+)"/],
    ["engine", "services/engine/server.mjs", /ENGINE_VERSION\s*=\s*"([^"]+)"/],
    ["evidence-events", "services/engine/evidence-events.mjs", /ENGINE_VERSION\s*=\s*"([^"]+)"/],
    ["lifecycle", "services/engine/lifecycle-store.mjs", /ENGINE_VERSION\s*=\s*"([^"]+)"/],
    ["private-ingress", "services/private-ingress/server.mjs", /ENGINE_VERSION\s*=\s*"([^"]+)"/],
    ["worker", "services/worker/worker.mjs", /ENGINE_VERSION\s*=\s*"([^"]+)"/],
    ["integration-gateway", "services/integration-gateway/server.mjs", /VERSION\s*=\s*"([^"]+)"/],
    ["database-gateway", "services/database-gateway/server.mjs", /DATABASE_GATEWAY_VERSION\s*=\s*"([^"]+)"/],
    ["egress-boundary", "scripts/probe-engine-egress-boundary.mjs", /EGRESS_BOUNDARY_VERSION\s*=\s*"([^"]+)"/],
  ];
  for (const [name, filename, pattern] of runtimeSources) {
    actual[`runtime:${name}`] = pattern.exec(await readFile(path.join(repositoryRoot, filename), "utf8"))?.[1];
  }
  for (const [contract, filename] of [["gateway", "compose.production.yaml"], ["engine", "compose.engine.yaml"]]) {
    const compose = parseYAML(await readFile(path.join(repositoryRoot, filename), "utf8"));
    for (const [service, definition] of Object.entries(compose?.services || {})) {
      const image = definition?.image;
      if (typeof image !== "string" || !image.startsWith("vasi")) continue;
      actual[`image:${contract}.${service}`] = /:([^:@]+)$/.exec(image)?.[1];
    }
  }
  const mismatches = Object.entries(actual)
    .filter(([, version]) => version !== expected)
    .map(([source, version]) => ({ expected, source, version: version || null }));
  return { actual, expected, mismatches };
}

export async function validateComposeContracts(repositoryRoot = root) {
  const production = parseYAML(await readFile(path.join(repositoryRoot, "compose.production.yaml"), "utf8"));
  const engine = parseYAML(await readFile(path.join(repositoryRoot, "compose.engine.yaml"), "utf8"));
  const failures = [];
  const hardened = [
    ["gateway.app", production?.services?.app],
    ["engine.engine", engine?.services?.engine],
    ["engine.integration-gateway", engine?.services?.["integration-gateway"]],
    ["engine.worker", engine?.services?.worker],
    ["engine.private-ingress", engine?.services?.["private-ingress"]],
    ["engine.database-gateway", engine?.services?.["database-gateway"]],
  ];
  const maintenance = [
    ["gateway.maintenance", production?.services?.maintenance],
    ["engine.maintenance", engine?.services?.maintenance],
    ["gateway.capacity", production?.services?.capacity],
    ["engine.capacity", engine?.services?.capacity],
    ["engine.egress-policy", engine?.services?.["egress-policy"]],
  ];
  for (const [name, service] of hardened) {
    if (!service) {
      failures.push(`${name} is missing`);
      continue;
    }
    if (service.read_only !== true) failures.push(`${name} must be read-only`);
    if (!arrayContains(service.cap_drop, "ALL")) failures.push(`${name} must drop all capabilities`);
    if (!arrayContains(service.security_opt, "no-new-privileges:true")) {
      failures.push(`${name} must prohibit privilege escalation`);
    }
    if (service.restart !== "unless-stopped") failures.push(`${name} must restart unless stopped`);
    if (!hasReadOnlyDataMount(service.volumes)) failures.push(`${name} must mount data read-only`);
  }
  for (const [name, service] of maintenance) {
    if (!service) {
      failures.push(`${name} is missing`);
      continue;
    }
    if (service.read_only !== true) failures.push(`${name} must be read-only`);
    if (!arrayContains(service.cap_drop, "ALL")) failures.push(`${name} must drop all capabilities`);
    if (!arrayContains(service.security_opt, "no-new-privileges:true")) {
      failures.push(`${name} must prohibit privilege escalation`);
    }
    if (service.user !== "1000:1000") failures.push(`${name} must run as the maintenance user`);
    if (!hasReadOnlyDataMount(service.volumes)) failures.push(`${name} must mount data read-only`);
    if (!arrayContains(service.profiles, "tools")) failures.push(`${name} must remain in the tools profile`);
    if (service.ports?.length) failures.push(`${name} must not publish a port`);
    if (name.endsWith(".capacity") && !hasBoundedCapacityProcMounts(service.volumes)) {
      failures.push(`${name} must mount only the bounded aggregate proc inputs`);
    }
  }
  for (const name of ["engine", "integration-gateway", "worker"]) {
    if (engine?.services?.[name]?.ports?.length) failures.push(`engine.${name} must not publish a port`);
  }
  if (!portsAreLoopback(production?.services?.app?.ports)) failures.push("gateway.app must bind only loopback");
  if (!portsAreLoopback(engine?.services?.["private-ingress"]?.ports)) {
    failures.push("engine.private-ingress must bind only loopback in the sanitized contract");
  }
  const expectedNetworks = {
    capacity: ["database-egress"],
    "database-gateway": ["database-egress", "engine-data"],
    "egress-policy": ["database-egress"],
    engine: ["engine-data", "engine-private"],
    "integration-gateway": ["engine-data", "engine-integrations", "integration-egress"],
    maintenance: ["database-egress"],
    migrate: ["database-egress"],
    "private-ingress": ["engine-data", "engine-private", "private-ingress-listener"],
    settings: ["database-egress"],
    worker: ["engine-data", "engine-integrations"],
  };
  for (const [name, expected] of Object.entries(expectedNetworks)) {
    const actual = serviceNetworks(engine?.services?.[name]);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      failures.push(`engine.${name} must use only its approved networks`);
    }
  }
  for (const name of ["engine-data", "engine-integrations", "engine-private"]) {
    if (engine?.networks?.[name]?.internal !== true) failures.push(`engine network ${name} must be internal`);
  }
  for (const name of ["database-egress", "integration-egress", "private-ingress-listener"]) {
    if (!engine?.networks?.[name] || engine.networks[name].internal === true) {
      failures.push(`engine network ${name} must be a dedicated external network`);
    }
  }
  for (const name of [
    "database-egress",
    "engine-data",
    "engine-integrations",
    "engine-private",
    "integration-egress",
    "private-ingress-listener",
  ]) {
    if (engine?.networks?.[name]?.enable_ipv6 !== false) {
      failures.push(`engine network ${name} must keep IPv6 disabled`);
    }
  }
  const expectedSubnets = {
    "database-egress": "172.29.254.0/28",
    "private-ingress-listener": "172.29.254.16/28",
    "engine-private": "172.29.254.32/28",
    "engine-data": "172.29.254.48/28",
    "engine-integrations": "172.29.254.64/28",
    "integration-egress": "172.29.254.80/28",
  };
  for (const [name, expectedSubnet] of Object.entries(expectedSubnets)) {
    const subnets = engine?.networks?.[name]?.ipam?.config;
    if (!Array.isArray(subnets) || subnets.length !== 1 || subnets[0]?.subnet !== expectedSubnet) {
      failures.push(`engine ${name} must use its reviewed stable IPv4 subnet`);
    }
  }
  if (engine?.services?.["private-ingress"]?.networks?.["private-ingress-listener"]?.gw_priority !== 1) {
    failures.push("engine.private-ingress must use the listener bridge as its default gateway");
  }
  for (const name of ["engine", "integration-gateway", "private-ingress", "worker"]) {
    if (!hasReadOnlyDatabaseTransportMarker(engine?.services?.[name]?.volumes)) {
      failures.push(`engine.${name} must mount the fixed database transport marker read-only`);
    }
  }
  for (const [name, service] of Object.entries(engine?.services || {})) {
    if (service?.network_mode === "host") failures.push(`engine.${name} must not use host networking`);
    if (arrayContains(service?.cap_add, "NET_ADMIN")) failures.push(`engine.${name} must not receive NET_ADMIN`);
    if ((service?.volumes || []).some(isDockerSocketMount)) failures.push(`engine.${name} must not mount the Docker socket`);
  }
  for (const [name, service] of [...hardened, ...maintenance, ["gateway.settings", production?.services?.settings], ["engine.settings", engine?.services?.settings]]) {
    for (const key of environmentKeys(service?.environment)) {
      if (/(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY)$/i.test(key)) {
        failures.push(`${name} contains secret-like environment key ${key}`);
      }
    }
  }
  return { failures, servicesChecked: [...hardened, ...maintenance].map(([name]) => name) };
}

export async function validateAutomationContract(repositoryRoot = root) {
  const filename = path.join(repositoryRoot, ".github", "workflows", "release-assurance.yml");
  const workflow = parseYAML(await readFile(filename, "utf8"));
  const failures = [];
  if (workflow?.permissions?.contents !== "read" || Object.keys(workflow?.permissions || {}).length !== 1) {
    failures.push("release workflow must have read-only contents permission");
  }
  const jobs = Object.values(workflow?.jobs || {});
  const releaseImages = policy.images.runtimeContracts.map((contract) => contract.image).sort();
  if (!jobs.length) failures.push("release workflow must define a job");
  for (const job of jobs) {
    for (const step of job?.steps || []) {
      if (step.uses && !/@[a-f0-9]{40}$/.test(step.uses)) {
        failures.push(`workflow action is not commit-pinned: ${step.uses}`);
      }
    }
  }
  const steps = jobs.flatMap((job) => job?.steps || []);
  const build = steps.find((step) => step?.name === "Build exact production images")?.run || "";
  const scan = steps.find((step) => step?.name === "Create exact image SBOM and vulnerability evidence")?.run || "";
  for (const image of releaseImages) {
    if (!String(build).includes(`--tag "${image}:`)) failures.push(`release workflow does not build ${image}`);
    if (!String(scan).includes(`"${image}:`)) failures.push(`release workflow does not scan ${image}`);
  }
  return { failures, jobs: jobs.length, releaseImagesChecked: releaseImages };
}

export async function validateCodeScanningContract(repositoryRoot = root) {
  const filename = path.join(repositoryRoot, ".github", "workflows", "codeql-analysis.yml");
  const failures = [];
  let workflow;
  try {
    workflow = parseYAML(await readFile(filename, "utf8"));
  } catch {
    return { actionsChecked: 0, failures: ["CodeQL workflow is missing or invalid"], languages: [] };
  }

  const triggers = Object.keys(workflow?.on || {}).sort();
  if (JSON.stringify(triggers) !== JSON.stringify(["pull_request", "push", "schedule"])) {
    failures.push("CodeQL workflow must use only pull request, main push, and schedule triggers");
  }
  for (const event of ["pull_request", "push"]) {
    if (JSON.stringify(workflow?.on?.[event]?.branches) !== JSON.stringify(["main"])) {
      failures.push(`CodeQL ${event} trigger must target only main`);
    }
  }
  if (
    !Array.isArray(workflow?.on?.schedule) || workflow.on.schedule.length !== 1 ||
    workflow.on.schedule[0]?.cron !== "23 4 * * 1"
  ) {
    failures.push("CodeQL workflow must retain the reviewed weekly schedule");
  }

  const permissions = workflow?.permissions || {};
  if (
    permissions.contents !== "read" || permissions["security-events"] !== "write" ||
    JSON.stringify(Object.keys(permissions).sort()) !== JSON.stringify(["contents", "security-events"])
  ) {
    failures.push("CodeQL workflow permissions must be read-only contents plus security-event upload");
  }
  if (
    workflow?.concurrency?.group !== "codeql-${{ github.workflow }}-${{ github.ref }}" ||
    workflow?.concurrency?.["cancel-in-progress"] !== true
  ) {
    failures.push("CodeQL workflow must cancel superseded runs in its exact concurrency group");
  }

  const jobNames = Object.keys(workflow?.jobs || {});
  const job = workflow?.jobs?.analyze;
  if (JSON.stringify(jobNames) !== JSON.stringify(["analyze"]) || !job) {
    failures.push("CodeQL workflow must define only the analyze job");
  }
  if (
    job?.["runs-on"] !== "ubuntu-24.04" || job?.["timeout-minutes"] !== 30 ||
    job?.strategy?.["fail-fast"] !== false ||
    JSON.stringify(job?.strategy?.matrix?.language) !== JSON.stringify(["javascript"])
  ) {
    failures.push("CodeQL analyze job runtime, timeout, and language matrix drifted");
  }

  const steps = job?.steps || [];
  if (steps.length !== 4 || steps.slice(0, 3).some((step) => typeof step?.run === "string")) {
    failures.push("CodeQL analyze job must contain only the four reviewed steps");
  }
  const expectedActions = [
    "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
    "github/codeql-action/init@7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
    "github/codeql-action/analyze@7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
  ];
  const actualActions = steps.slice(0, 3).map((step) => step?.uses);
  if (JSON.stringify(actualActions) !== JSON.stringify(expectedActions)) {
    failures.push("CodeQL workflow actions are missing, reordered, or not pinned to reviewed commits");
  }
  for (const action of actualActions.filter(Boolean)) {
    if (!/@[a-f0-9]{40}$/.test(action)) failures.push(`CodeQL action is not commit-pinned: ${action}`);
  }
  const initialize = steps[1];
  if (
    initialize?.with?.languages !== "${{ matrix.language }}" ||
    initialize?.with?.queries !== "security-extended"
  ) {
    failures.push("CodeQL initialization must analyze JavaScript with security-extended queries");
  }
  if (
    steps[2]?.id !== "analyze" ||
    steps[2]?.with?.category !==
      ".github/workflows/codeql-analysis.yml:analyze/language:${{ matrix.language }}"
  ) {
    failures.push("CodeQL result category must preserve the historical JavaScript analysis identity");
  }
  if (
    steps[3]?.name !== "Reject high and critical security results" ||
    steps[3]?.env?.VASI_CODEQL_SARIF_DIR !== "${{ steps.analyze.outputs.sarif-output }}" ||
    steps[3]?.run !== 'node scripts/verify-codeql-sarif.mjs "$VASI_CODEQL_SARIF_DIR"' ||
    steps[3]?.uses !== undefined
  ) {
    failures.push("CodeQL analysis must retain the reviewed fail-closed SARIF verification step");
  }

  return {
    actionsChecked: actualActions.filter(Boolean).length,
    failures,
    languages: job?.strategy?.matrix?.language || [],
  };
}

export async function validateOperationalSchedulerContract(repositoryRoot = root) {
  const directory = path.join(repositoryRoot, "deployment", "systemd");
  const serviceCommon = [
    "Type=oneshot",
    "User=root",
    "Group=root",
    "UMask=0077",
    "LockPersonality=yes",
    "NoNewPrivileges=yes",
    "PrivateDevices=yes",
    "PrivateTmp=yes",
    "ProtectControlGroups=yes",
    "ProtectHome=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelTunables=yes",
    "ProtectSystem=strict",
    "RestrictSUIDSGID=yes",
    "SystemCallArchitectures=native",
  ];
  const requirements = {};
  const addService = (filename, lines) => {
    requirements[filename] = [...serviceCommon, ...lines];
  };
  const addTimer = (filename, service, { active, boot, inactive }) => {
    requirements[filename] = [
      `OnActiveSec=${active}`,
      `OnBootSec=${boot}`,
      `OnUnitInactiveSec=${inactive}`,
      "Persistent=yes",
      `Unit=${service}`,
      "WantedBy=timers.target",
    ];
  };

  addService("vasi-edge-image-assurance.service", [
    "After=docker.service network-online.target",
    "ExecStart=/bin/sh scripts/edge-image-assurance.sh /var/lib/vasi-edge/monitor.json",
    "WorkingDirectory=/opt/vasi-edge/current",
    "ReadWritePaths=/var/lib/vasi-edge /var/cache/vasi-edge /run/lock",
    "RestrictAddressFamilies=AF_UNIX",
  ]);
  addTimer("vasi-edge-image-assurance.timer", "vasi-edge-image-assurance.service", {
    active: "30min", boot: "30min", inactive: "24h",
  });
  addService("vasi-edge-runtime-readiness.service", [
    "After=docker.service network-online.target",
    "ExecStart=/bin/sh scripts/probe-edge-runtime.sh /var/lib/vasi-edge/monitor.json",
    "WorkingDirectory=/opt/vasi-edge/current",
    "ReadWritePaths=/var/lib/vasi-edge /run/lock /run/vasi-edge",
    "RuntimeDirectory=vasi-edge",
    "RuntimeDirectoryMode=0700",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
  ]);
  addTimer("vasi-edge-runtime-readiness.timer", "vasi-edge-runtime-readiness.service", {
    active: "2min", boot: "2min", inactive: "15min",
  });

  addService("vasi-engine-database-egress-policy.service", [
      "After=docker.service network-online.target",
      "ExecStart=/bin/sh scripts/apply-database-egress-policy.sh apply",
      "WorkingDirectory=/opt/vasi-engine/current",
      "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
  ]);
  addTimer("vasi-engine-database-egress-policy.timer", "vasi-engine-database-egress-policy.service", {
    active: "15s", boot: "15s", inactive: "2min",
  });
  addService("vasi-engine-egress-boundary.service", [
      "After=docker.service network-online.target vasi-engine-database-egress-policy.service",
      "ExecStart=/usr/bin/env node scripts/probe-engine-egress-boundary.mjs",
      "WorkingDirectory=/opt/vasi-engine/current",
      "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
  ]);
  addTimer("vasi-engine-egress-boundary.timer", "vasi-engine-egress-boundary.service", {
    active: "2min", boot: "2min", inactive: "5min",
  });

  for (const role of ["gateway", "engine"]) {
    const working = role === "gateway" ? "/opt/vasi/current" : "/opt/vasi-engine/current";
    const compose = role === "gateway" ? "compose.production.yaml" : "compose.engine.yaml";
    const backup = role === "gateway"
      ? "/var/lib/vasi/backups/maintenance/scheduled"
      : "/var/lib/vasi-engine/backups/maintenance/scheduled";
    for (const action of ["create", "check"]) {
      const readOnly = action === "check" ? ":ro" : "";
      const name = `vasi-${role}-backup-${action}`;
      addService(`${name}.service`, [
        `WorkingDirectory=${working}`,
        `ExecStart=/usr/bin/docker compose -f ${compose} --profile tools run --rm -T --no-deps -v ${backup}:/backup${readOnly} maintenance scripts/backup-continuity.mjs ${action} /backup`,
        "RestrictAddressFamilies=AF_UNIX",
      ]);
      addTimer(`${name}.timer`, `${name}.service`, action === "create"
        ? { active: "30min", boot: "30min", inactive: "24h" }
        : { active: "15min", boot: "15min", inactive: "12h" });
    }

    const capacity = `vasi-${role}-capacity-readiness`;
    addService(`${capacity}.service`, [
      `WorkingDirectory=${working}`,
      `ExecStart=/usr/bin/docker compose -f ${compose} --profile tools run --rm -T --no-deps -v /var/lib/vasi-capacity:/host/storage/system:ro capacity --scope ${role} --storage system=/host/storage/system`,
      "RestrictAddressFamilies=AF_UNIX",
    ]);
    addTimer(`${capacity}.timer`, `${capacity}.service`, {
      active: "5min", boot: "5min", inactive: "1h",
    });
  }

  addService("vasi-gateway-deployment-readiness.service", [
    "WorkingDirectory=/opt/vasi/current",
    "ExecStart=/usr/bin/docker compose -f compose.production.yaml --profile tools run --rm -T --no-deps -v /opt/vasi/releases:/host-storage:ro maintenance scripts/probe-deployment-readiness.mjs --scope gateway --storage /host-storage",
    "RestrictAddressFamilies=AF_UNIX",
  ]);
  addTimer("vasi-gateway-deployment-readiness.timer", "vasi-gateway-deployment-readiness.service", {
    active: "10min", boot: "10min", inactive: "6h",
  });
  addService("vasi-gateway-operational-readiness.service", [
    "WorkingDirectory=/opt/vasi/current",
    "ExecStart=/usr/bin/docker compose -f compose.production.yaml --profile tools run --rm -T --no-deps maintenance scripts/probe-gateway-operational-readiness.mjs",
    "RestrictAddressFamilies=AF_UNIX",
  ]);
  addTimer("vasi-gateway-operational-readiness.timer", "vasi-gateway-operational-readiness.service", {
    active: "3min", boot: "3min", inactive: "5min",
  });
  addService("vasi-engine-deployment-readiness.service", [
    "WorkingDirectory=/opt/vasi-engine/current",
    "ExecStartPre=/usr/bin/env node /usr/local/libexec/vasi/verify-engine-host-runtime.mjs",
    "ExecStart=/usr/bin/env node scripts/probe-deployment-readiness.mjs --scope engine --storage /opt/vasi-engine/releases",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
  ]);
  addTimer("vasi-engine-deployment-readiness.timer", "vasi-engine-deployment-readiness.service", {
    active: "10min", boot: "10min", inactive: "6h",
  });
  addService("vasi-engine-operational-readiness.service", [
    "WorkingDirectory=/opt/vasi-engine/current",
    "ExecStart=/usr/bin/docker compose -f compose.engine.yaml --profile tools run --rm -T --no-deps maintenance scripts/probe-operational-readiness.mjs",
    "RestrictAddressFamilies=AF_UNIX",
  ]);
  addTimer("vasi-engine-operational-readiness.timer", "vasi-engine-operational-readiness.service", {
    active: "3min", boot: "3min", inactive: "5min",
  });

  const monitoredByRole = {
    edge: [
      "vasi-edge-image-assurance.service",
      "vasi-edge-runtime-readiness.service",
    ],
    engine: [
      "vasi-engine-backup-check.service",
      "vasi-engine-backup-create.service",
      "vasi-engine-capacity-readiness.service",
      "vasi-engine-database-egress-policy.service",
      "vasi-engine-deployment-readiness.service",
      "vasi-engine-egress-boundary.service",
      "vasi-engine-operational-readiness.service",
    ],
    gateway: [
      "vasi-gateway-backup-check.service",
      "vasi-gateway-backup-create.service",
      "vasi-gateway-capacity-readiness.service",
      "vasi-gateway-deployment-readiness.service",
      "vasi-gateway-operational-readiness.service",
    ],
  };
  const alertState = {
    edge: "/var/lib/vasi-edge/operations-alerts",
    engine: "/var/lib/vasi-engine/operations-alerts",
    gateway: "/var/lib/vasi/operations-alerts",
  };
  for (const role of ["edge", "engine", "gateway"]) {
    for (const filename of monitoredByRole[role]) {
      requirements[filename].push(`OnFailure=vasi-${role}-alert-record@%n.service`);
    }
    const stateDirectory = alertState[role].replace("/var/lib/", "");
    const alertCommon = [
      "CapabilityBoundingSet=",
      "PrivateNetwork=yes",
      "ProtectProc=invisible",
      "ProcSubset=pid",
      `StateDirectory=${stateDirectory}`,
      "StateDirectoryMode=0700",
      `ReadWritePaths=${alertState[role]}`,
      "RestrictAddressFamilies=AF_UNIX",
      "RestrictNamespaces=yes",
      "RestrictRealtime=yes",
      "SystemCallFilter=~@network-io",
    ];
    addService(`vasi-${role}-alert-record@.service`, [
      ...alertCommon,
      `ExecStart=/bin/sh /usr/local/libexec/vasi/operational-alert-spool.sh record ${role} %i`,
    ]);
    addService(`vasi-${role}-alert-readiness.service`, [
      ...alertCommon,
      `ExecStart=/bin/sh /usr/local/libexec/vasi/operational-alert-spool.sh status ${role}`,
    ]);
    addTimer(`vasi-${role}-alert-readiness.timer`, `vasi-${role}-alert-readiness.service`, {
      active: "30s", boot: "30s", inactive: "1min",
    });
  }

  const failures = [];
  let actual = [];
  try {
    actual = (await readdir(directory))
      .filter((filename) => filename.endsWith(".service") || filename.endsWith(".timer"))
      .sort();
  } catch {
    failures.push("deployment/systemd is missing");
  }
  const expected = Object.keys(requirements).sort();
  for (const filename of expected.filter((filename) => !actual.includes(filename))) {
    failures.push(`${filename} is missing`);
  }
  for (const filename of actual.filter((filename) => !expected.includes(filename))) {
    failures.push(`${filename} is not part of the reviewed scheduler contract`);
  }
  for (const [filename, required] of Object.entries(requirements)) {
    let contents;
    try {
      contents = await readFile(path.join(directory, filename), "utf8");
    } catch {
      failures.push(`${filename} is missing`);
      continue;
    }
    for (const line of required) {
      if (!contents.split("\n").includes(line)) failures.push(`${filename} is missing ${line}`);
    }
    if (
      filename === "vasi-engine-deployment-readiness.service" &&
      contents.split("\n").includes("MemoryDenyWriteExecute=yes")
    ) {
      failures.push(`${filename} cannot deny executable memory to the direct Node runtime`);
    }
    if (
      filename.includes("-alert-") &&
      contents.split("\n").some((line) => line.startsWith("OnFailure="))
    ) {
      failures.push(`${filename} must not recursively trigger operational alerts`);
    }
    if (
      /Environment(?:File)?=|compose\.live\.yaml|\.private|\.tasks|VASI-\d|https?:\/\/|\/home\/|docker\.sock|--privileged|--network(?:=|\s+)host/.test(contents)
    ) {
      failures.push(`${filename} contains a prohibited privilege or configuration path`);
    }
  }
  return { failures, unitsChecked: Object.keys(requirements) };
}

export async function validateOperationalAlertHandoffContract(repositoryRoot = root) {
  const failures = [];
  let source = "";
  try {
    source = await readFile(
      path.join(repositoryRoot, "scripts", "operational-alert-spool.sh"),
      "utf8",
    );
  } catch {
    failures.push("the durable operational-alert handoff is missing");
  }
  const lines = source.split("\n");
  for (const required of [
    "set -eu",
    "umask 077",
    "MAX_PENDING=256",
    "MAX_ACKNOWLEDGED=1024",
    "    gateway) printf '%s' /var/lib/vasi/operations-alerts ;;",
    "    engine) printf '%s' /var/lib/vasi-engine/operations-alerts ;;",
    "    edge) printf '%s' /var/lib/vasi-edge/operations-alerts ;;",
    "  [ \"$(id -u)\" -eq 0 ] || fail",
    "  [ \"$(file_uid \"$directory\")\" = \"$EXPECTED_UID\" ] || fail",
    "  [ \"$(file_mode \"$directory\")\" = 700 ] || fail",
    "  [ \"$(file_mode \"$filename\")\" = 600 ] || return 1",
    "  acquire_lock",
    "  sync_state",
    "    validate_record \"$source\" || fail",
  ]) {
    if (!lines.includes(required)) failures.push(`the durable operational-alert handoff is missing ${required}`);
  }
  for (const schema of [
    "vasi-operational-alert/v1",
    "vasi-operational-alert-overflow/v1",
    "vasi-operational-alert-spool/v1",
    "vasi-operational-alert-acknowledgement/v1",
  ]) {
    if (!source.includes(schema)) failures.push(`the durable operational-alert handoff is missing ${schema}`);
  }
  const expectedUnits = [
    "gateway:vasi-gateway-backup-check.service",
    "gateway:vasi-gateway-backup-create.service",
    "gateway:vasi-gateway-capacity-readiness.service",
    "gateway:vasi-gateway-deployment-readiness.service",
    "gateway:vasi-gateway-operational-readiness.service",
    "engine:vasi-engine-backup-check.service",
    "engine:vasi-engine-backup-create.service",
    "engine:vasi-engine-capacity-readiness.service",
    "engine:vasi-engine-database-egress-policy.service",
    "engine:vasi-engine-deployment-readiness.service",
    "engine:vasi-engine-egress-boundary.service",
    "engine:vasi-engine-operational-readiness.service",
    "edge:vasi-edge-image-assurance.service",
    "edge:vasi-edge-runtime-readiness.service",
  ].sort();
  const actualUnits = [...source.matchAll(/(?:gateway|engine|edge):vasi-(?:gateway|engine|edge)-[a-z0-9-]+\.service/g)]
    .map((match) => match[0])
    .sort();
  if (JSON.stringify(actualUnits) !== JSON.stringify(expectedUnits)) {
    failures.push("the durable operational-alert source-unit allowlist is not exact");
  }
  if (
    /\b(?:curl|wget|nc|ssh|mailx?)\b|https?:\/\/|EnvironmentFile=|\.env\b|\beval\b|rm\s+-rf|chmod\s+(?:0?777|a\+w)/.test(source)
  ) {
    failures.push("the durable operational-alert handoff contains transport, ambient configuration, or destructive behavior");
  }
  return { failures, filesChecked: 1 };
}

export async function validateEngineHostRuntimeContract(repositoryRoot = root) {
  const failures = [];
  let directExecution = "";
  let preparation = "";
  let verifier = "";
  let packageJSON;
  try {
    directExecution = await readFile(path.join(repositoryRoot, "scripts", "direct-execution.mjs"), "utf8");
  } catch {
    failures.push("engine host runtime direct-execution helper is missing");
  }
  try {
    preparation = await readFile(path.join(repositoryRoot, "scripts", "prepare-engine-host-runtime.sh"), "utf8");
  } catch {
    failures.push("engine host runtime preparation is missing");
  }
  try {
    verifier = await readFile(path.join(repositoryRoot, "scripts", "verify-engine-host-runtime.mjs"), "utf8");
  } catch {
    failures.push("engine host runtime verifier is missing");
  }
  try {
    packageJSON = JSON.parse(await readFile(path.join(repositoryRoot, "package.json"), "utf8"));
  } catch {
    failures.push("engine host runtime package contract is unavailable");
  }

  const preparationLines = preparation.split("\n");
  const exactInstall = "NODE_ENV=production npm_config_engine_strict=true npm ci --omit=dev --omit=optional --ignore-scripts --no-audit --no-fund $offline";
  for (const required of [
    "set -eu",
    "umask 022",
    "if [ \"$(id -u)\" -ne 0 ]; then",
    exactInstall,
    "/usr/bin/install -d -o root -g root -m 0755 /usr/local/libexec/vasi",
    "/usr/bin/install -o root -g root -m 0644 scripts/direct-execution.mjs \\",
    "  /usr/local/libexec/vasi/direct-execution.mjs",
    "/usr/bin/install -o root -g root -m 0644 scripts/verify-engine-host-runtime.mjs \\",
    "  /usr/local/libexec/vasi/verify-engine-host-runtime.mjs",
    "exec node /usr/local/libexec/vasi/verify-engine-host-runtime.mjs",
  ]) {
    if (!preparationLines.includes(required)) failures.push(`engine host runtime preparation is missing ${required}`);
  }
  if (
    /\bnpm\s+(?:i|install)\b|--(?:force|foreground-scripts|ignore-engines|include=dev)\b|Environment(?:File)?=|\.env\b/.test(preparation)
  ) {
    failures.push("engine host runtime preparation weakens exact production installation");
  }
  for (const marker of [
    "vasi-engine-host-runtime/v1",
    "production_dependency_missing",
    "production_dependency_mismatch",
    "nonproduction_dependency_present",
    "settings_runtime_unavailable",
  ]) {
    if (!verifier.includes(marker)) failures.push(`engine host runtime verifier is missing ${marker}`);
  }
  if (!directExecution.includes("export function isDirectExecution(moduleURL, invocationPath)")) {
    failures.push("engine host runtime direct-execution helper is invalid");
  }
  if (packageJSON?.scripts?.["host:prepare:engine"] !== "/bin/sh scripts/prepare-engine-host-runtime.sh") {
    failures.push("package.json is missing the exact engine host runtime preparation command");
  }
  return { failures, filesChecked: 4 };
}

export async function validateRuntimeImageBuildContract(repositoryRoot = root) {
  const failures = [];
  let gatewayDockerfile = "";
  let engineDockerfile = "";
  try {
    gatewayDockerfile = await readFile(path.join(repositoryRoot, "Dockerfile"), "utf8");
  } catch {
    failures.push("Dockerfile is missing");
  }
  try {
    engineDockerfile = await readFile(path.join(repositoryRoot, "Dockerfile.engine"), "utf8");
  } catch {
    failures.push("Dockerfile.engine is missing");
  }

  const exactInstall = "RUN npm ci --omit=dev --omit=optional --ignore-scripts --no-audit --no-fund";
  for (const [filename, contents, stage] of [
    ["Dockerfile", gatewayDockerfile, "production-dependencies"],
    ["Dockerfile.engine", engineDockerfile, "dependencies"],
  ]) {
    const body = dockerfileStage(contents, stage);
    if (!body) {
      failures.push(`${filename} is missing the ${stage} stage`);
      continue;
    }
    const installLines = body.split("\n").filter((line) => /^RUN npm\s/.test(line));
    if (installLines.length !== 1 || installLines[0] !== exactInstall) {
      failures.push(`${filename} ${stage} must use the exact production dependency install`);
    }
  }

  const standaloneCopy = gatewayDockerfile.indexOf(
    "COPY --from=builder --chown=node:node /app/.next/standalone ./",
  );
  const optionalRemoval = gatewayDockerfile.indexOf("RUN rm -rf /app/node_modules/pg-cloudflare");
  const nonRootTransition = gatewayDockerfile.indexOf("\nUSER node", standaloneCopy);
  if (
    standaloneCopy < 0 || optionalRemoval <= standaloneCopy ||
    nonRootTransition < 0 || optionalRemoval >= nonRootTransition
  ) {
    failures.push("Dockerfile must remove the unrelated standalone optional dependency before USER node");
  }
  return { failures, filesChecked: 2 };
}

export async function validatePublicIngressContract(repositoryRoot = root) {
  const failures = [];
  let example = "";
  let overlay = "";
  let packageJSON = {};
  let pageBoundary = "";
  let authenticationBoundary = "";
  let probe = "";
  let routeProbe = "";
  let accessDenial = "";
  const accessSources = [];
  const protectedPageSources = [];
  let sensitiveRoutes = [];
  try {
    example = await readFile(
      path.join(repositoryRoot, "deployment", "nginx", "vasi-public.conf.example"),
      "utf8",
    );
  } catch {
    failures.push("the sanitized public ingress example is missing");
  }
  try {
    overlay = await readFile(
      path.join(repositoryRoot, "deployment", "nginx", "Dockerfile.overlay"),
      "utf8",
    );
  } catch {
    failures.push("the immutable public ingress overlay Dockerfile is missing");
  }
  try {
    packageJSON = JSON.parse(await readFile(path.join(repositoryRoot, "package.json"), "utf8"));
  } catch {
    failures.push("package.json is unavailable for public ingress assurance");
  }
  try {
    pageBoundary = await readFile(path.join(repositoryRoot, "src", "proxy.ts"), "utf8");
  } catch {
    failures.push("the public page method boundary is missing");
  }
  try {
    authenticationBoundary = await readFile(
      path.join(repositoryRoot, "src", "app", "api", "auth", "[...all]", "route.ts"),
      "utf8",
    );
  } catch {
    failures.push("the public authentication response boundary is missing");
  }
  try {
    probe = await readFile(path.join(repositoryRoot, "scripts", "probe-public-ingress.mjs"), "utf8");
  } catch {
    failures.push("the public ingress black-box probe is missing");
  }
  try {
    routeProbe = await readFile(
      path.join(repositoryRoot, "scripts", "probe-public-route-isolation.mjs"),
      "utf8",
    );
  } catch {
    failures.push("the public sensitive-route isolation probe is missing");
  }
  try {
    accessDenial = await readFile(path.join(repositoryRoot, "src", "lib", "access-denial.ts"), "utf8");
  } catch {
    failures.push("the bounded gateway access-denial helper is missing");
  }
  for (const filename of ["admin-access.ts", "owner-access.ts", "participant-access.ts"]) {
    try {
      accessSources.push([filename, await readFile(path.join(repositoryRoot, "src", "lib", filename), "utf8")]);
    } catch {
      failures.push(`the gateway ${filename} source is missing`);
    }
  }
  for (const filename of [
    "src/app/admin/page.tsx",
    "src/app/admin/evidence/page.tsx",
    "src/app/owner/page.tsx",
    "src/app/workspace/page.tsx",
  ]) {
    try {
      protectedPageSources.push([filename, await readFile(path.join(repositoryRoot, filename), "utf8")]);
    } catch {
      failures.push(`the protected gateway page ${filename} is missing`);
    }
  }
  try {
    sensitiveRoutes = await discoverSensitiveRoutes(repositoryRoot);
  } catch {
    failures.push("the sensitive gateway route inventory cannot be derived safely");
  }
  if (example) {
    if (example !== renderPublicIngressConfiguration(PUBLIC_INGRESS_EXAMPLE_SETTINGS)) {
      failures.push("the sanitized public ingress example differs from canonical rendering");
    }
    try {
      const audit = auditPublicIngressConfiguration(example, PUBLIC_INGRESS_EXAMPLE_SETTINGS);
      failures.push(...audit.failures.map((failure) => `public ingress: ${failure}`));
    } catch {
      failures.push("the sanitized public ingress example cannot be parsed safely");
    }
  }
  const expectedOverlay = [
    "ARG BASE_IMAGE",
    "FROM ${BASE_IMAGE}",
    "COPY --chown=root:root vasi.conf /etc/nginx/conf.d/vasi.conf",
    "RUN chmod 0644 /etc/nginx/conf.d/vasi.conf && nginx -t",
  ];
  const overlayLines = overlay.split("\n").map((line) => line.trim()).filter(Boolean);
  if (JSON.stringify(overlayLines) !== JSON.stringify(expectedOverlay)) {
    failures.push("the public ingress overlay must replace only vasi.conf on an explicit base and run nginx -t");
  }
  if (packageJSON?.scripts?.["ingress:config"] !== "node scripts/public-ingress-config.mjs") {
    failures.push("package.json is missing the public ingress configuration command");
  }
  if (packageJSON?.scripts?.["assurance:ingress"] !== "node scripts/probe-public-ingress.mjs") {
    failures.push("package.json is missing the public ingress black-box assurance command");
  }
  if (packageJSON?.scripts?.["assurance:routes"] !== "node scripts/probe-public-route-isolation.mjs") {
    failures.push("package.json is missing the public sensitive-route assurance command");
  }
  for (const marker of [
    'const PAGE_METHODS = new Set(["GET", "HEAD"]);',
    'if (pathname === "/api" || pathname.startsWith("/api/")) return "allow";',
    'Allow: "GET, HEAD"',
    '"Cache-Control": "no-store"',
    "status: 405",
    'matcher: ["/((?!api(?:/|$)|_next(?:/|$)).*)"]',
  ]) {
    if (!pageBoundary.includes(marker)) failures.push(`the public page method boundary is missing ${marker}`);
  }
  if (/NextResponse\.(?:redirect|rewrite)|cookies\.(?:set|delete)|\bfetch\s*\(/.test(pageBoundary)) {
    failures.push("the public page method boundary contains a redirect, cookie, rewrite, or network side effect");
  }
  for (const marker of [
    'headers.set("Cache-Control", "no-store");',
    "return noStoreAuthenticationResponse(bounded.response);",
    "return noStoreAuthenticationResponse(await handlers[method](request));",
    "return noStoreAuthenticationResponse(new Response(null, { status: 404 }));",
  ]) {
    if (!authenticationBoundary.includes(marker)) {
      failures.push(`the public authentication response boundary is missing ${marker}`);
    }
  }
  if (/return\s+handlers\[method\]\(request\)/.test(authenticationBoundary)) {
    failures.push("the public authentication response boundary can bypass no-store enforcement");
  }
  for (const marker of [
    'const PAGE_METHODS_DENIED = Object.freeze(["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);',
    'const SUPPORTED_TLS_PROTOCOLS = Object.freeze(["TLSv1.2", "TLSv1.3"]);',
    "const NORMALIZATION_TARGETS = Object.freeze([",
    'crossOriginPreflight: "denied"',
    'schema: "vasi-public-ingress-probe/v3"',
    "inspectAdversarialBoundary",
    'new URL("/api/auth/get-session", publicOrigin)',
    '"x-http-method-override": "GET"',
    'sessionPrivacy: "no_store_null"',
    '"content-security-policy"',
    '"strict-transport-security"',
    '"access-control-allow-origin"',
  ]) {
    if (!probe.includes(marker)) failures.push(`the public ingress black-box probe is missing ${marker}`);
  }
  for (const marker of [
    'const SENSITIVE_API_NAMESPACES = Object.freeze(["admin", "evidence", "owner", "workspace"]);',
    'const AUTHENTICATION_DENIAL = \'{"error":"Authentication required."}\';',
    'const PRIVATE_PAGE_MARKERS = Object.freeze([',
    'const malformedJSONBody = ["GET", "HEAD"].includes(entry.method)',
    'schema: "vasi-public-route-isolation-probe/v1"',
    '"access-control-allow-origin"',
    '"set-cookie"',
  ]) {
    if (!routeProbe.includes(marker)) failures.push(`the public sensitive-route probe is missing ${marker}`);
  }
  for (const marker of [
    '"Cache-Control": "no-store"',
    'Vary: "Host"',
    "status: 404",
    "Response.json({ error }",
  ]) {
    if (!accessDenial.includes(marker)) failures.push(`the bounded gateway access-denial helper is missing ${marker}`);
  }
  for (const [filename, source] of accessSources) {
    if (!source.includes('from "@/lib/access-denial"')) {
      failures.push(`${filename} does not use the bounded gateway access-denial helper`);
    }
    if (/new Response\(null,\s*\{\s*status:\s*404|Response\.json\(\{\s*error:/.test(source)) {
      failures.push(`${filename} contains an ungoverned access-denial response`);
    }
  }
  for (const [filename, source] of protectedPageSources) {
    if (/export\s+const\s+metadata\s*[:=]/.test(source)) {
      failures.push(`${filename} contains unauthenticated static protected-page metadata`);
    }
  }
  const namespaceMethods = Object.fromEntries(
    ["admin", "evidence", "owner", "request", "workspace"].map((namespace) => [
      namespace,
      sensitiveRoutes.filter((entry) => entry.namespace === namespace).length,
    ]),
  );
  return {
    failures,
    filesChecked: 16,
    routeIsolation: {
      methodCount: sensitiveRoutes.length,
      namespaceMethods,
    },
  };
}

export async function validateEdgeMonitorContract(repositoryRoot = root) {
  const failures = [];
  let edgePolicy = {};
  let packageJSON = {};
  let example = {};
  let gatewayDockerfile = "";
  let engineDockerfile = "";
  const scripts = {};
  try {
    edgePolicy = JSON.parse(await readFile(
      path.join(repositoryRoot, "config", "edge-monitor-policy.json"),
      "utf8",
    ));
  } catch {
    failures.push("the edge monitor tool policy is unavailable");
  }
  try {
    packageJSON = JSON.parse(await readFile(path.join(repositoryRoot, "package.json"), "utf8"));
  } catch {
    failures.push("package.json is unavailable for edge monitor assurance");
  }
  try {
    example = JSON.parse(await readFile(
      path.join(repositoryRoot, "deployment", "nginx", "vasi-edge-monitor.example.json"),
      "utf8",
    ));
    parseEdgeMonitorConfiguration(example);
  } catch {
    failures.push("the sanitized edge monitor example is invalid");
  }
  try {
    gatewayDockerfile = await readFile(path.join(repositoryRoot, "Dockerfile"), "utf8");
    engineDockerfile = await readFile(path.join(repositoryRoot, "Dockerfile.engine"), "utf8");
  } catch {
    failures.push("the release Dockerfiles are unavailable for edge auditor pinning");
  }
  for (const filename of [
    "edge-monitor-common.sh",
    "edge-image-assurance.sh",
    "probe-edge-runtime.sh",
  ]) {
    try {
      scripts[filename] = await readFile(path.join(repositoryRoot, "scripts", filename), "utf8");
    } catch {
      failures.push(`${filename} is unavailable`);
      scripts[filename] = "";
    }
  }

  const policyKeys = [
    "auditorImage",
    "maximumArtifactBytes",
    "maximumConfigurationBytes",
    "maximumRetainedScans",
    "maximumScanAgeHours",
    "maximumVulnerabilityDatabaseAgeHours",
    "scannerImage",
    "schema",
  ];
  if (
    JSON.stringify(Object.keys(edgePolicy).sort()) !== JSON.stringify(policyKeys.sort()) ||
    edgePolicy.schema !== "vasi-edge-monitor-policy/v1" ||
    !isDigestPinnedImage(edgePolicy.auditorImage) ||
    !isDigestPinnedImage(edgePolicy.scannerImage) ||
    edgePolicy.scannerImage !== policy.images.scannerImage ||
    edgePolicy.maximumConfigurationBytes !== 65_536 ||
    edgePolicy.maximumArtifactBytes !== 16_777_216 ||
    edgePolicy.maximumVulnerabilityDatabaseAgeHours !== 26 ||
    edgePolicy.maximumScanAgeHours !== 168 ||
    edgePolicy.maximumRetainedScans !== 60
  ) {
    failures.push("the edge monitor tool policy is weakened or inconsistent");
  }
  const nodeBases = [...`${gatewayDockerfile}\n${engineDockerfile}`.matchAll(
    /^FROM (node:24-alpine@sha256:[a-f0-9]{64})(?:\s|$)/gm,
  )].map((match) => match[1]);
  if (!nodeBases.length || nodeBases.some((image) => image !== edgePolicy.auditorImage)) {
    failures.push("the edge auditor is not pinned to the exact reviewed Node base");
  }
  if (packageJSON?.scripts?.["assurance:edge-image"] !== "/bin/sh scripts/edge-image-assurance.sh") {
    failures.push("package.json is missing the exact edge image assurance command");
  }
  if (packageJSON?.scripts?.["assurance:edge-runtime"] !== "/bin/sh scripts/probe-edge-runtime.sh") {
    failures.push("package.json is missing the exact edge runtime assurance command");
  }

  for (const filename of ["edge-image-assurance.sh", "probe-edge-runtime.sh"]) {
    const lines = scripts[filename].split("\n");
    if (!lines.includes("set -eu") || !lines.includes("umask 077")) {
      failures.push(`${filename} is missing fail-closed shell initialization`);
    }
  }
  const requiredMarkers = {
    "edge-monitor-common.sh": [
      "[ \"$(id -u)\" -eq 0 ] || edge_fail",
      "[ \"$(stat -c %a -- \"$EDGE_CONFIGURATION_FILE\")\" = \"600\" ] || edge_fail",
      "flock -w 240 9 || edge_fail",
      "--cap-drop ALL --security-opt no-new-privileges:true",
      ".[0].HostConfig.RestartPolicy.Name == \"always\"",
      ".[0].HostConfig.RestartPolicy.Name == \"no\"",
    ],
    "edge-image-assurance.sh": [
      "docker image save \"$edge_scanned_image_id\" > \"$edge_image_archive\" || edge_fail",
      "--skip-db-update --offline-scan --scanners vuln --format json",
      "--skip-db-update --offline-scan --scanners vuln --format cyclonedx",
      "create-manifest /evidence \"$edge_scan_name\" \"$edge_scanned_image_id\"",
      "mv -f -- \"$edge_latest_temporary\" \"$EDGE_SCAN_ROOT/latest.json\" || edge_fail",
    ],
    "probe-edge-runtime.sh": [
      "docker exec \"$EDGE_LIVE_CONTAINER\" nginx -t >/dev/null 2>&1 || edge_fail",
      "edge_temporary_directory=$(mktemp -d /run/vasi-edge/runtime.XXXXXX) || edge_fail",
      "node scripts/public-ingress-config.mjs audit",
      "--write-out '%{http_code}' \"https://$EDGE_PUBLIC_HOST/api/health\") || edge_fail",
      "--write-out '%{http_code}' \"https://$EDGE_RETIRED_HOST/\") || edge_fail",
      "node scripts/edge-monitor-contract.mjs verify-evidence",
    ],
  };
  for (const [filename, markers] of Object.entries(requiredMarkers)) {
    for (const marker of markers) {
      if (!scripts[filename].includes(marker)) failures.push(`${filename} is missing ${marker}`);
    }
  }
  const combinedScripts = Object.values(scripts).join("\n");
  if (
    /docker\.sock|--privileged|--network(?:=|\s+)host|Environment(?:File)?=|\.env\b/.test(combinedScripts)
  ) {
    failures.push("the edge monitor scripts contain prohibited privilege or environment state");
  }
  const imageScan = scripts["edge-image-assurance.sh"];
  if ((imageScan.match(/docker run --rm --network none/g) || []).length !== 5) {
    failures.push("the edge evidence and auditor containers are not consistently network-isolated");
  }
  return { failures, filesChecked: 9 };
}

export async function validateProductionActivationContract(repositoryRoot = root) {
  const failures = [];
  let packageJSON = {};
  let source = "";
  try {
    packageJSON = JSON.parse(await readFile(path.join(repositoryRoot, "package.json"), "utf8"));
  } catch {
    failures.push("package.json is unavailable for production activation assurance");
  }
  try {
    source = await readFile(path.join(repositoryRoot, "scripts", "activate-production-release.mjs"), "utf8");
  } catch {
    failures.push("the production release activation command is unavailable");
  }
  for (const role of ["gateway", "engine"]) {
    try {
      const configuration = validateActivationConfigurationValue(JSON.parse(await readFile(
        path.join(repositoryRoot, "deployment", "activation", `${role}.example.json`),
        "utf8",
      )));
      const listener = parseProtectedOverlay(await readFile(
        path.join(repositoryRoot, "deployment", "activation", `${role}.live.example.yaml`),
        "utf8",
      ), role);
      if (
        configuration.role !== role ||
        configuration.overlayFile !== `/var/lib/vasi-release/${role}.live.yaml` ||
        listener.service !== (role === "gateway" ? "app" : "private-ingress")
      ) {
        failures.push(`the sanitized ${role} production activation example is inconsistent`);
      }
    } catch {
      failures.push(`the sanitized ${role} production activation example is invalid`);
    }
  }
  if (packageJSON?.scripts?.["release:activate"] !== "node scripts/activate-production-release.mjs") {
    failures.push("package.json is missing the exact production activation command");
  }
  for (const marker of [
    "vasi-production-release-activation/v1",
    "releaseOwnerUid",
    "The candidate release data binding is not the configured shared data root.",
    "The protected Compose overlay changed more than the approved listener.",
    "base.name !== contract.projectName",
    "await validateDirectory(path.dirname(configuration.overlayFile), [0, uid], true)",
    "dockerEnvironment()",
    '"image", "inspect", "--format", "{{.Id}}"',
    '"up", "-d", "--no-build", "--wait", "--wait-timeout", "120"',
    'JSON.stringify(service.volumes || []).includes("docker.sock")',
    "The selected rollback release is not ready.",
    "await restoreCurrent(configuration.currentLink, prepared.previousTarget)",
    "await stopRuntime(prepared, commandRunner)",
    "VASI production release activation failed closed.",
  ]) {
    if (!source.includes(marker)) failures.push(`the production activation command is missing ${marker}`);
  }
  if (
    /--remove-orphans|\/(?:var\/run|run)\/docker\.sock|--privileged|--network(?:=|\s+)host|COMPOSE_FILE|COMPOSE_PROJECT_NAME|NODE_OPTIONS/.test(source)
  ) {
    failures.push("the production activation command contains prohibited destructive, privileged, or ambient state");
  }
  return { failures, filesChecked: 6 };
}

export async function validateProductionStagingContract(repositoryRoot = root) {
  const failures = [];
  const files = {
    documentation: "docs/architecture/fail-closed-release-activation.md",
    package: "package.json",
    source: "scripts/stage-production-release.mjs",
    test: "scripts/stage-production-release.test.mjs",
  };
  const sources = {};
  for (const [name, filename] of Object.entries(files)) {
    try {
      sources[name] = await readFile(path.join(repositoryRoot, filename), "utf8");
    } catch {
      failures.push(`the production release staging ${name} source is unavailable`);
      sources[name] = "";
    }
  }
  for (const marker of [
    'RELEASE_STAGING_SCHEMA = "vasi-production-release-staging/v1"',
    "const MAXIMUM_ARCHIVE_BYTES = 64 * 1024 * 1024",
    "const MAXIMUM_DECOMPRESSED_BYTES = 160 * 1024 * 1024",
    "constants.O_NOFOLLOW",
    "Readable.from([archiveContents])",
    'fail("archive_digest_mismatch")',
    'typeFlag !== "0" && typeFlag !== "5"',
    "forbiddenPathPatterns",
    "await readlink(absolute) !== expectedTarget",
    "publishDirectoryNoReplace",
    '"--no-clobber", "--no-target-directory"',
    "VASI production release staging failed closed.",
  ]) {
    if (!sources.source.includes(marker)) failures.push(`the production release staging command is missing ${marker}`);
  }
  if (
    /(?<!\.)\b(?:exec|execFile|fork)\s*\(|spawn\s*\(\s*["'`](?:tar|unzip)|["'`](?:docker|podman)["'`]|--remove-orphans|process\.env/.test(sources.source)
  ) {
    failures.push("the production release staging command contains prohibited archive, runtime, or ambient behavior");
  }
  for (const marker of [
    "inspects a physical Git archive without changing live state",
    "normalizes ownership and modes, binds protected state, and publishes once",
    "rejects traversal, private material, special entries, and duplicate paths",
    "rejects malformed checksums, ambiguous executable modes, and oversized entries before payload reads",
    "does not bypass an existing staging lock",
    "fails with one generic CLI error and no archive or installation facts",
  ]) {
    if (!sources.test.includes(marker)) failures.push(`the production release staging test is missing ${marker}`);
  }
  try {
    const packageJSON = JSON.parse(sources.package);
    if (packageJSON?.scripts?.["release:stage"] !== "node scripts/stage-production-release.mjs") {
      failures.push("package.json is missing the exact production staging command");
    }
  } catch {
    failures.push("the production release staging package command is invalid");
  }
  for (const marker of [
    "npm run release:stage -- CONFIG_FILE ARCHIVE_FILE RELEASE_ID EXPECTED_SHA256 --dry-run",
    "does not build images, run migrations, change Docker,",
    "or change the `current` selector",
  ]) {
    if (!sources.documentation.includes(marker)) failures.push(`the production release staging documentation is missing ${marker}`);
  }
  return { failures, filesChecked: Object.keys(files).length };
}

export async function validateDirectExecutionContract(
  repositoryRoot = root,
  trackedFiles = DIRECT_EXECUTION_ENTRYPOINTS,
) {
  const failures = [];
  const expected = new Set(DIRECT_EXECUTION_ENTRYPOINTS);
  if (
    !Array.isArray(trackedFiles) || trackedFiles.length > 2_048 ||
    trackedFiles.some((filename) => typeof filename !== "string" || filename.length > 512)
  ) {
    return {
      cliFiles: [...DIRECT_EXECUTION_ENTRYPOINTS],
      failures: ["the direct-execution source inventory is invalid"],
      filesChecked: 0,
    };
  }
  const candidates = trackedFiles.filter((filename) =>
    /^(?:scripts|services)\/.+\.mjs$/.test(filename) &&
    !filename.endsWith(".test.mjs") && !filename.includes("..")
  ).sort();

  let helper = "";
  let helperTest = "";
  let engineDockerfile = "";
  try {
    helper = await readFile(path.join(repositoryRoot, "scripts", "direct-execution.mjs"), "utf8");
    helperTest = await readFile(path.join(repositoryRoot, "scripts", "direct-execution.test.mjs"), "utf8");
    engineDockerfile = await readFile(path.join(repositoryRoot, "Dockerfile.engine"), "utf8");
  } catch {
    failures.push("the direct-execution helper, regression test, or runtime image contract is unavailable");
  }
  for (const marker of [
    "const MAXIMUM_ENTRYPOINT_BYTES = 4_096;",
    "Buffer.byteLength(invocationPath) > MAXIMUM_ENTRYPOINT_BYTES",
    'invocationPath.includes("\\0")',
    "fileURLToPath(moduleURL)",
    "realpathSync(modulePath) === realpathSync(path.resolve(invocationPath))",
    "catch {",
    "return false;",
  ]) {
    if (!helper.includes(marker)) failures.push(`the direct-execution helper is missing ${marker}`);
  }
  for (const marker of [
    "release-selector paths",
    "fails closed for unrelated, missing, malformed, and oversized paths",
    "runs the activation CLI through a selected release path",
    "does not execute main when the activation module is imported",
    "runs the staging CLI through a selected release path",
    "does not execute main when the staging module is imported",
  ]) {
    if (!helperTest.includes(marker)) failures.push(`the direct-execution regression test is missing ${marker}`);
  }
  if (!engineDockerfile.includes("COPY scripts/direct-execution.mjs ./scripts/direct-execution.mjs")) {
    failures.push("the database gateway runtime image is missing the direct-execution helper");
  }

  const discovered = new Set();
  for (const filename of candidates) {
    let source;
    try {
      source = await readFile(path.join(repositoryRoot, filename), "utf8");
    } catch {
      failures.push(`the tracked operational source ${filename} is unavailable`);
      continue;
    }
    if (/import\.meta\.url\s*===\s*pathToFileURL\s*\(/.test(source)) {
      failures.push(`${filename} contains the vulnerable literal direct-execution comparison`);
    }
    const guards = source.match(/if \(isDirectExecution\(import\.meta\.url, process\.argv\[1\]\)\) \{/g) || [];
    if (!guards.length) continue;
    discovered.add(filename);
    if (!expected.has(filename)) {
      failures.push(`${filename} is an unreviewed direct-execution entrypoint`);
      continue;
    }
    const importPath = filename.startsWith("services/")
      ? "../../scripts/direct-execution.mjs"
      : "./direct-execution.mjs";
    if (
      guards.length !== 1 ||
      !source.includes(`import { isDirectExecution } from "${importPath}";`)
    ) failures.push(`${filename} does not use the exact direct-execution helper contract`);
  }
  for (const filename of expected) {
    if (!discovered.has(filename)) failures.push(`${filename} is missing its direct-execution guard`);
  }
  return {
    cliFiles: [...DIRECT_EXECUTION_ENTRYPOINTS],
    failures,
    filesChecked: DIRECT_EXECUTION_ENTRYPOINTS.length + 3,
  };
}

export async function validateAuthProviderReadinessContract(repositoryRoot = root) {
  const failures = [];
  const filenames = {
    admin: "src/lib/admin-users.ts",
    authentication: "src/lib/auth.ts",
    declaration: "packages/auth-provider-readiness/index.d.mts",
    documentation: "docs/architecture/identity-provider-activation-readiness.md",
    library: "packages/auth-provider-readiness/index.mjs",
    panel: "src/components/admin/provider-readiness-panel.tsx",
    settings: "scripts/settings-core.mjs",
    test: "packages/auth-provider-readiness/index.test.mjs",
    userDocumentation: "docs/authentication.md",
    wrapper: "src/lib/auth-providers.ts",
  };
  const files = {};
  for (const [name, filename] of Object.entries(filenames)) {
    try {
      files[name] = await readFile(path.join(repositoryRoot, filename), "utf8");
    } catch {
      failures.push(`the identity-provider readiness ${name} source is missing`);
      files[name] = "";
    }
  }
  for (const marker of [
    "export const AUTH_PROVIDER_IDS",
    "export const ZOHO_ACCOUNTS_ORIGINS",
    "partial_credentials",
    "visibility_requires_credentials",
    "invalid_visibility_setting",
    "unsupported_accounts_origin",
    '!ZOHO_ACCOUNTS_ORIGINS.includes(parsed.origin)',
    'parsed.pathname !== "/"',
    "validateAuthProviderConfiguration",
  ]) {
    if (!files.library.includes(marker)) {
      failures.push(`the shared identity-provider readiness library is missing ${marker}`);
    }
  }
  for (const origin of [
    "https://accounts.zoho.com",
    "https://accounts.zoho.eu",
    "https://accounts.zoho.in",
    "https://accounts.zoho.com.au",
    "https://accounts.zoho.jp",
    "https://accounts.zohocloud.ca",
    "https://accounts.zoho.sa",
    "https://accounts.zoho.uk",
  ]) {
    if (!files.library.includes(`"${origin}"`)) {
      failures.push(`the shared identity-provider readiness library is missing ${origin}`);
    }
  }
  if (/\bfetch\s*\(/.test(files.library)) {
    failures.push("the shared identity-provider readiness library must remain offline");
  }
  for (const marker of [
    "AuthProviderReadinessStatus",
    "AuthProviderReadiness",
    "normalizeZohoAccountsOrigin",
  ]) {
    if (!files.declaration.includes(marker)) {
      failures.push(`the identity-provider readiness declaration is missing ${marker}`);
    }
  }
  for (const marker of [
    'from "../../packages/auth-provider-readiness/index.mjs"',
    "resolveAuthProviderReadiness(settings)",
    "validateSharedAuthProviderConfiguration(settings)",
  ]) {
    if (!files.wrapper.includes(marker)) {
      failures.push(`the gateway identity-provider wrapper is missing ${marker}`);
    }
  }
  for (const marker of [
    "validateAuthProviderConfiguration(settings);",
    "normalizeZohoAccountsOrigin(settings.ZOHO_ACCOUNTS_ORIGIN)",
  ]) {
    if (!files.authentication.includes(marker)) {
      failures.push(`the authentication runtime is missing ${marker}`);
    }
  }
  for (const marker of [
    'if (scope === "gateway") {',
    "validateAuthProviderConfiguration(runtimeSettings);",
    "getAuthProviderReadiness(runtimeSettings, {",
    "adminOrigin: runtimeSettings.VASI_ADMIN_ORIGIN",
    "publicOrigin: runtimeSettings.BETTER_AUTH_URL",
  ]) {
    if (!files.settings.includes(marker)) {
      failures.push(`settings validation is missing ${marker}`);
    }
  }
  for (const marker of [
    "getAuthProviderReadiness(settings, {",
    "adminOrigin: serverSettings.adminOrigin",
    "publicOrigin: serverSettings.baseURL",
  ]) {
    if (!files.admin.includes(marker)) {
      failures.push(`the private administrator data boundary is missing ${marker}`);
    }
  }
  for (const marker of [
    "Credential values are never shown.",
    "provider.publicCallback",
    "provider.adminCallback",
    "unsupported Zoho account origin",
  ]) {
    if (!files.panel.includes(marker)) {
      failures.push(`the private provider-readiness panel is missing ${marker}`);
    }
  }
  for (const marker of [
    "One framework-independent contract owns",
    "Multi-DC OAuth documentation",
    "provider/operator activation gates",
  ]) {
    if (!files.documentation.includes(marker)) {
      failures.push(`the identity-provider readiness documentation is missing ${marker}`);
    }
  }
  for (const marker of [
    "partial tuple",
    "documented HTTPS account",
    "settings validate",
  ]) {
    if (!files.userDocumentation.includes(marker)) {
      failures.push(`the authentication documentation is missing ${marker}`);
    }
  }
  for (const marker of [
    'expect(serialized).not.toContain(secret)',
    '"https://accounts.zoho.example"',
    "visibility_requires_credentials",
  ]) {
    if (!files.test.includes(marker)) {
      failures.push(`the identity-provider readiness tests are missing ${marker}`);
    }
  }
  return { failures, filesChecked: Object.keys(files).length };
}

export async function validateReadinessDossierVerifierContract(repositoryRoot = root) {
  const failures = [];
  const files = {
    bridge: "src/lib/readiness-dossier.ts",
    cli: "scripts/verify-readiness-dossier.mjs",
    cliTest: "scripts/verify-readiness-dossier.test.mjs",
    crypto: "packages/engine-crypto/index.mjs",
    documentation: "docs/architecture/pilot-readiness-dossier.md",
    package: "package.json",
    productStore: "services/engine/product-store.mjs",
    productStoreTest: "services/engine/product-store.test.mjs",
    route: "src/app/api/admin/product/tenant-readiness-exports/route.ts",
    routeTest: "src/app/api/admin/product/tenant-readiness-exports/route.test.ts",
    signingProvider: "services/engine/signing-provider.mjs",
    trustAnchor: "scripts/readiness-trust-anchor.mjs",
    trustAnchorTest: "scripts/readiness-trust-anchor.test.mjs",
    verifier: "packages/readiness-dossier/index.mjs",
    verifierTest: "packages/readiness-dossier/index.test.mjs",
  };
  const sources = {};
  for (const [name, filename] of Object.entries(files)) {
    try {
      sources[name] = await readFile(path.join(repositoryRoot, filename), "utf8");
    } catch {
      failures.push(`the readiness dossier verifier ${name} source is unavailable`);
      sources[name] = "";
    }
  }

  for (const marker of [
    "const MAXIMUM_READINESS_DOSSIER_BYTES = 2_097_152",
    "constants.O_NOFOLLOW",
    "renderReadinessDossierHTML(exported) !== text",
    'id="vasi-readiness-export"',
    'fail("expected_digest_mismatch")',
    'fail("expected_key_mismatch")',
    'status: "pass"',
    "READINESS_DOSSIER_LIMITATIONS",
    'SIGNED_READINESS_EXPORT_SCHEMA = "vasi-tenant-readiness-export/v2"',
    "verifyDetachedIntegritySeal(attestation",
    "verifyCertificateSeal(attestation",
    'integritySeal: "not_present"',
  ]) {
    if (!sources.verifier.includes(marker)) failures.push(`the readiness dossier verifier is missing ${marker}`);
  }
  if (/\bconsole\.|process\.(?:stdout|stderr)|JSON\.stringify\(error/.test(sources.verifier)) {
    failures.push("the readiness dossier verifier package contains an output or error-disclosure path");
  }
  for (const marker of [
    'from "../packages/readiness-dossier/index.mjs"',
    "VASI readiness dossier verification failed.",
    "--expected-key-fingerprint",
    ["if (isDirectExecution(import.meta.url, ", "process.argv[1])) {"].join(""),
  ]) {
    if (!sources.cli.includes(marker)) failures.push(`the readiness dossier verifier CLI is missing ${marker}`);
  }
  if (!sources.bridge.includes('from "../../packages/readiness-dossier/index.mjs"') ||
      !sources.bridge.includes("exported.schema !== SIGNED_READINESS_EXPORT_SCHEMA")) {
    failures.push("the gateway readiness dossier renderer does not use the shared verifier package");
  }
  for (const marker of [
    "createReadinessAttestation",
    "signingProvider.signDetached(attestation, READINESS_DOSSIER_SEAL_PROFILE)",
    "readinessExportSchema: TENANT_READINESS_EXPORT_SCHEMA",
    "validateReadinessExport(exported);",
  ]) {
    if (!sources.productStore.includes(marker)) failures.push(`the readiness dossier engine export is missing ${marker}`);
  }
  for (const marker of [
    "rolls back the disclosure event when the signing provider returns an invalid seal",
    'schema: "vasi-tenant-readiness-export/v2"',
    "signingKeys: exported.attestation.signingKeys",
  ]) {
    if (!sources.productStoreTest.includes(marker)) failures.push(`the readiness dossier engine test is missing ${marker}`);
  }
  if (!sources.signingProvider.includes("signDetached(payload, profile)")) {
    failures.push("the readiness dossier engine does not use the shared signing-provider boundary");
  }
  for (const marker of [
    "hashCanonicalJSON(seal.certificate)",
    "hashCanonicalJSON(seal.publicJWK)",
    'seal.validationScope !== "leaf_signature_and_key_match"',
  ]) {
    if (!sources.crypto.includes(marker)) failures.push(`the certificate seal verifier is missing ${marker}`);
  }
  if (!sources.route.includes('"x-vasi-integrity-key-sha256"')) {
    failures.push("the readiness export response does not expose the public trust-anchor fingerprint");
  }
  for (const marker of [
    "fails closed when the engine returns an invalid readiness signature",
    "fails closed when the live engine returns an unsigned legacy export",
    'response.headers.get("x-vasi-integrity-key-sha256")',
  ]) {
    if (!sources.routeTest.includes(marker)) failures.push(`the readiness dossier gateway test is missing ${marker}`);
  }
  for (const marker of [
    "preserves exact 0.47.0 exports as explicitly unsigned legacy evidence",
    "rejects attestation, signature, signing-key, event, and seal-role tampering",
    "verifies an optional certificate leaf seal and binds its exact public metadata",
    "rejects presentation edits, executable additions, duplicate embeddings, and noncanonical JSON",
    "bounds bytes and requires one physical regular UTF-8 file",
  ]) {
    if (!sources.verifierTest.includes(marker)) failures.push(`the readiness dossier verifier test is missing ${marker}`);
  }
  if (!sources.bridge.includes("The live VASI readiness export must be signed.")) {
    failures.push("the live readiness export boundary permits unsigned legacy evidence");
  }
  for (const marker of [
    "privacy-bounded output",
    "fails with one generic error and no exported facts",
    "fails generically for an untrusted expected signing key",
    "remains import-safe",
  ]) {
    if (!sources.cliTest.includes(marker)) failures.push(`the readiness dossier verifier CLI test is missing ${marker}`);
  }
  for (const marker of [
    'READINESS_TRUST_ANCHOR_SCHEMA = "vasi-readiness-trust-anchor/v1"',
    "readRuntimeSettings,",
    'readSettings({ bootstrap, scope: "engine" })',
    "createSigningProvider",
    "signingKeyFingerprint(value)",
    "VASI readiness trust anchor unavailable.",
    ["if (isDirectExecution(import.meta.url, ", "process.argv[1])) {"].join(""),
  ]) {
    if (!sources.trustAnchor.includes(marker)) failures.push(`the readiness trust-anchor CLI is missing ${marker}`);
  }
  for (const marker of [
    "returns only the configured public integrity identity",
    'not.toContain("publicJWK")',
    "fails closed for invalid provider records and unexpected arguments",
    "remains import-safe",
  ]) {
    if (!sources.trustAnchorTest.includes(marker)) failures.push(`the readiness trust-anchor test is missing ${marker}`);
  }
  if (!sources.documentation.includes("npm run readiness:verify -- DOSSIER_FILE") ||
      !sources.documentation.includes("--expected-key-fingerprint LOWERCASE_SHA256") ||
      !sources.documentation.includes("npm run readiness:trust-anchor")) {
    failures.push("the offline readiness dossier verification command is undocumented");
  }
  try {
    const packageJSON = JSON.parse(sources.package);
    if (packageJSON.scripts?.["readiness:verify"] !== "node scripts/verify-readiness-dossier.mjs") {
      failures.push("package.json is missing the exact readiness dossier verification command");
    }
    if (packageJSON.scripts?.["readiness:trust-anchor"] !== "node scripts/readiness-trust-anchor.mjs") {
      failures.push("package.json is missing the exact readiness trust-anchor command");
    }
  } catch {
    failures.push("the readiness dossier verifier package command is invalid");
  }
  return { failures, filesChecked: Object.keys(files).length };
}

export async function validatePilotGateEvidenceContract(repositoryRoot = root) {
  const failures = [];
  const files = {
    adminPanel: "src/components/admin/tenant-admission-panel.tsx",
    browser: "src/lib/pilot-gate-manifest-import.ts",
    browserInteropTest: "packages/pilot-gate-evidence/browser-import.test.mjs",
    browserTest: "src/lib/pilot-gate-manifest-import.test.ts",
    cli: "scripts/pilot-gate-evidence.mjs",
    cliTest: "scripts/pilot-gate-evidence.test.mjs",
    contract: "config/pilot-gate-evidence-contract.json",
    documentation: "docs/architecture/pilot-gate-evidence-packages.md",
    library: "packages/pilot-gate-evidence/index.mjs",
    libraryTest: "packages/pilot-gate-evidence/index.test.mjs",
    package: "package.json",
  };
  const sources = {};
  for (const [name, filename] of Object.entries(files)) {
    try {
      sources[name] = await readFile(path.join(repositoryRoot, filename), "utf8");
    } catch {
      failures.push(`the pilot-gate evidence ${name} source is unavailable`);
      sources[name] = "";
    }
  }

  for (const marker of [
    'from "../../config/pilot-gate-evidence-contract.json" with { type: "json" }',
    "pilotGateContract.limits.artifactBytes",
    "pilotGateContract.limits.totalBytes",
    "constants.O_NOFOLLOW",
    "before.nlink !== 1n",
    "(Number(before.mode) & 0o7777) !== 0o600",
    "(Number(metadata.mode) & 0o7777) !== 0o700",
    "await realpath(resolved) !== resolved",
    'fail("evidence_inventory_mismatch")',
    'fail("unreferenced_artifact")',
    'item.outcome !== "satisfied" && item.outcome !== "accepted_exception"',
    "digestCanonical(normalized) !== packageDigest",
    "sameMetadata(boundary.metadata, finalMetadata)",
  ]) {
    if (!sources.library.includes(marker)) failures.push(`the pilot-gate evidence library is missing ${marker}`);
  }
  if (/\bconsole\.|process\.(?:stdout|stderr)|JSON\.stringify\(error|node:(?:child_process|http|https)|\bfetch\s*\(/.test(sources.library)) {
    failures.push("the pilot-gate evidence library contains an output, network, process, or error-disclosure path");
  }
  try {
    const contract = JSON.parse(sources.contract);
    const expectedChecklists = {
      accessibility: [
        "automated_accessibility", "keyboard_navigation", "screen_reader", "zoom_and_reflow",
        "motion_and_animation", "media_alternatives", "supported_browser_device",
      ],
      capacity_support: [
        "pilot_owner_users_scenarios", "concurrency_and_volume_limits", "load_evidence",
        "alert_destination_and_escalation", "incident_contacts", "support_hours",
        "rollback_and_stop_criteria",
      ],
      exact_release: [
        "source_assurance", "image_assurance", "build_test_conformance",
        "backup_settings_migrations", "rollback_readiness",
      ],
      identity_delivery: [
        "approved_identity_providers", "callback_and_origin_policy", "mfa_or_conditional_access",
        "authentication_mail", "tenant_delivery_path", "account_recovery_support",
      ],
      isolation_integrity: [
        "first_party_isolation_tamper", "public_private_tenant_scope",
        "independent_penetration_assessment", "finding_disposition",
      ],
      malware_content: [
        "content_risk_classification", "scanner_or_trusted_source_policy", "external_media_policy",
        "content_owner_acceptance", "outage_and_retry_policy",
      ],
      privacy_legal: [
        "notice_and_consent_language", "field_and_disclosure_inventory", "data_request_process",
        "retention_and_hold_policy", "jurisdiction_analysis", "electronic_act_analysis",
      ],
      recovery_custody: [
        "disposable_recovery_drill", "rpo_and_rto", "encrypted_off_host_custody",
        "key_rotation_and_revocation", "break_glass_process", "certificate_tsa_hsm_decision",
      ],
    };
    const expectedLimitations = [
      "This manifest proves the integrity and completeness of the indexed local files; it does not establish that a review was sufficient or correct.",
      "VASI does not ingest, copy, upload, interpret, certify, or approve the indexed evidence artifacts.",
      "Opaque references identify separately controlled scope, reviewer, and records; they do not prove identity, authority, independence, or legal capacity.",
      "A satisfied checklist item or accepted exception records the review package assertion only; the accountable admission owner must make the gate decision.",
      "The manifest SHA-256 detects changes to the canonical manifest and artifact digests; it is not a digital signature, trusted timestamp, or certificate opinion.",
    ];
    const expectedMediaExtensions = {
      "application/json": ".json",
      "application/pdf": ".pdf",
      "application/zip": ".zip",
      "text/csv": ".csv",
      "text/html": ".html",
      "text/markdown": ".md",
      "text/plain": ".txt",
    };
    if (Object.keys(contract).sort().join("\0") !==
          ["checklists", "limitations", "limits", "mediaExtensions", "schemas"].join("\0") ||
        JSON.stringify(contract.checklists) !== JSON.stringify(expectedChecklists) ||
        JSON.stringify(contract.limitations) !== JSON.stringify(expectedLimitations) ||
        JSON.stringify(contract.mediaExtensions) !== JSON.stringify(expectedMediaExtensions) ||
        contract.schemas?.descriptor !== "vasi-pilot-gate-evidence-descriptor/v1" ||
        contract.schemas?.manifest !== "vasi-pilot-gate-evidence-manifest/v1" ||
        contract.schemas?.verification !== "vasi-pilot-gate-evidence-verification/v1" ||
        contract.limits?.descriptorBytes !== 262_144 || contract.limits?.manifestBytes !== 1_048_576 ||
        contract.limits?.artifacts !== 64 || contract.limits?.artifactBytes !== 16 * 1024 * 1024 ||
        contract.limits?.totalBytes !== 128 * 1024 * 1024) {
      failures.push("the shared pilot-gate evidence contract is incomplete or weakened");
    }
  } catch {
    failures.push("the shared pilot-gate evidence contract is invalid");
  }
  for (const marker of [
    'from "../../config/pilot-gate-evidence-contract.json"',
    "file.size > pilotGateContract.limits.manifestBytes",
    "contents.byteLength !== file.size",
    "text.length > pilotGateContract.limits.manifestBytes",
    'new TextDecoder("utf-8", { fatal: true })',
    "gateId !== expectedGateId",
    "await digestCanonical(normalized) !== packageDigest",
    "globalThis.crypto?.subtle",
    "prettyCanonicalJSON({ ...normalized, packageDigest }) !== text",
    "The offline evidence manifest could not be verified locally.",
    "approval: Object.freeze({",
  ]) {
    if (!sources.browser.includes(marker)) failures.push(`the browser-local pilot-gate verifier is missing ${marker}`);
  }
  if (/\bfetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\b|\bFormData\b|\bfile\.name\b/.test(sources.browser)) {
    failures.push("the browser-local pilot-gate verifier contains a network, submission, or filename-disclosure path");
  }
  for (const marker of [
    "verifies the shared canonical contract and returns admission fields plus aggregates only",
    "rejects a manifest for a different admission gate",
    "rejects structural, checklist, limitation, reference, and digest tampering",
    "requires exact canonical JSON presentation",
    "reads one bounded strict-UTF-8 local file without using its name",
    "uses one generic failure for every rejected local input",
  ]) {
    if (!sources.browserTest.includes(marker)) failures.push(`the browser-local pilot-gate verifier test is missing ${marker}`);
  }
  for (const marker of [
    "accepts an exact offline-library manifest through the browser-local verifier",
    "createPilotGateEvidenceManifest",
    "pilotGateManifestJSON(manifest)",
    "verifyPilotGateManifestText",
  ]) {
    if (!sources.browserInteropTest.includes(marker)) {
      failures.push(`the pilot-gate browser interoperability test is missing ${marker}`);
    }
  }
  for (const marker of [
    "verifyPilotGateManifestFile(file, gate.id)",
    "Verified only in this browser. The manifest is not uploaded",
    "Artifact bytes were not reverified by this browser and the gate is not yet approved.",
    'type="file"',
  ]) {
    if (!sources.adminPanel.includes(marker)) failures.push(`the pilot-gate admission handoff is missing ${marker}`);
  }
  if (/data\.get\(["'](?:manifest|artifact)|name=["'](?:manifest|artifact)/i.test(sources.adminPanel)) {
    failures.push("the pilot-gate admission handoff submits a manifest or artifact field");
  }
  for (const marker of [
    'from "../packages/pilot-gate-evidence/index.mjs"',
    "--expected-sha256",
    "VASI pilot-gate evidence operation failed.",
    ["if (isDirectExecution(import.meta.url, ", "process.argv[1])) {"].join(""),
  ]) {
    if (!sources.cli.includes(marker)) failures.push(`the pilot-gate evidence CLI is missing ${marker}`);
  }
  for (const marker of [
    "creates deterministic canonical manifests and verifies aggregate results",
    "defines a complete, closed checklist contract for every admission gate",
    "rejects manifest field, digest, expected-digest, and artifact-content tampering",
    "rejects extra, linked, permissive, oversized, and overlapping filesystem inputs",
  ]) {
    if (!sources.libraryTest.includes(marker)) failures.push(`the pilot-gate evidence library test is missing ${marker}`);
  }
  for (const marker of [
    "creates and independently verifies an aggregate-only package result",
    "uses one generic operational failure without disclosing inputs",
    "is import-safe and executes through a selected-release path",
  ]) {
    if (!sources.cliTest.includes(marker)) failures.push(`the pilot-gate evidence CLI test is missing ${marker}`);
  }
  for (const marker of [
    "npm run pilot:evidence -- create DESCRIPTOR_FILE EVIDENCE_DIRECTORY OUTPUT_MANIFEST",
    "npm run pilot:evidence -- verify MANIFEST_FILE EVIDENCE_DIRECTORY",
    "Integrity packaging is not approval",
    "must remain outside the VASI release tree",
    "The browser does not upload the manifest",
    "does not re-read or verify the indexed artifact files",
  ]) {
    if (!sources.documentation.includes(marker)) failures.push(`the pilot-gate evidence documentation is missing ${marker}`);
  }
  try {
    const packageJSON = JSON.parse(sources.package);
    if (packageJSON.scripts?.["pilot:evidence"] !== "node scripts/pilot-gate-evidence.mjs") {
      failures.push("package.json is missing the exact pilot-gate evidence command");
    }
  } catch {
    failures.push("the pilot-gate evidence package command is invalid");
  }
  return { failures, filesChecked: Object.keys(files).length };
}

export async function validatePilotAdmissionEvidenceContract(repositoryRoot = root) {
  const failures = [];
  const files = {
    cli: "scripts/verify-pilot-admission-evidence.mjs",
    cliTest: "scripts/verify-pilot-admission-evidence.test.mjs",
    documentation: "docs/architecture/pilot-admission-evidence-verification.md",
    fixture: "packages/pilot-admission-evidence/test-fixture.mjs",
    library: "packages/pilot-admission-evidence/index.mjs",
    libraryTest: "packages/pilot-admission-evidence/index.test.mjs",
    package: "package.json",
  };
  const sources = {};
  for (const [name, filename] of Object.entries(files)) {
    try {
      sources[name] = await readFile(path.join(repositoryRoot, filename), "utf8");
    } catch {
      failures.push(`the pilot-admission evidence ${name} source is unavailable`);
      sources[name] = "";
    }
  }

  for (const marker of [
    'from "../pilot-gate-evidence/index.mjs"',
    'from "../readiness-dossier/index.mjs"',
    '"vasi-pilot-admission-evidence-verification/v1"',
    '"vasi-pilot-admission-evidence-verification/v2"',
    "TENANT_ADMISSION_GATES.map((gateId) => `${gateId}.json`).sort()",
    "const expectedArtifactDirectoryNames = Object.freeze([...TENANT_ADMISSION_GATES].sort())",
    "constants.O_NOFOLLOW",
    "Buffer.byteLength(value) > 4_096",
    "before.nlink !== 1n",
    "(Number(before.mode) & 0o7777) !== 0o600",
    "(Number(metadata.mode) & 0o7777) !== 0o700",
    'fail("manifest_inventory_mismatch")',
    'fail("artifact_directory_inventory_mismatch")',
    "isWithinOrEqual(dossierDirectory.path, artifactBoundary.path)",
    "verifyReadinessDossierBytes(contents, options)",
    "validateReadinessExport(exported);",
    "exported.schema !== SIGNED_READINESS_EXPORT_SCHEMA",
    'admission.status !== "admitted"',
    "gate.evidenceDigest !== manifest.packageDigest",
    "gate.evidenceReference !== manifest.evidenceReference",
    "gate.reviewerReference !== manifest.reviewerReference",
    "scopes.size !== 1",
    "reviewedAt > decidedAt || decidedAt > revisionCreatedAt || decidedAt > capturedAt",
    "const verification = await verifyPilotGateEvidenceManifest(",
    "artifacts += verification.artifacts",
    "bytes += verification.totalBytes",
    'artifactVerification: artifactSummary ? "matched" : "not_performed"',
  ]) {
    if (!sources.library.includes(marker)) {
      failures.push(`the pilot-admission evidence library is missing ${marker}`);
    }
  }
  if (/\bconsole\.|process\.(?:stdout|stderr)|JSON\.stringify\(error|node:(?:child_process|http|https)|\bfetch\s*\(/.test(sources.library)) {
    failures.push("the pilot-admission evidence library contains an output, network, process, or error-disclosure path");
  }
  for (const marker of [
    'from "../packages/pilot-admission-evidence/index.mjs"',
    "--expected-sha256",
    "--expected-key-fingerprint",
    "--artifact-root",
    "VASI pilot-admission evidence verification failed.",
    ["if (isDirectExecution(import.meta.url, ", "process.argv[1])) {"].join(""),
  ]) {
    if (!sources.cli.includes(marker)) failures.push(`the pilot-admission evidence CLI is missing ${marker}`);
  }
  for (const marker of [
    "binds exactly eight canonical manifests to signed JSON and HTML dossiers",
    "rejects every signed dossier-to-manifest reference or digest mismatch",
    "rejects mixed review scopes and impossible review, decision, or capture ordering",
    "requires a signed dossier whose immutable technical admission is complete",
    "rejects missing, extra, renamed, linked, or gate-substituted manifests",
    "requires private physical inputs and exact canonical UTF-8 presentation",
    "uses one generic error type for nested dossier, manifest, and filesystem failures",
    "reverifies every underlying artifact across the exact eight-gate directory set",
    "rejects changed, linked, permissive, missing, extra, or overlapping artifact roots",
  ]) {
    if (!sources.libraryTest.includes(marker)) {
      failures.push(`the pilot-admission evidence library test is missing ${marker}`);
    }
  }
  for (const marker of [
    "verifies complete artifacts through physical and selected-release paths with aggregate-only output",
    "fails with one generic message and no dossier or evidence facts",
    "remains import-safe and rejects malformed or duplicate options",
  ]) {
    if (!sources.cliTest.includes(marker)) {
      failures.push(`the pilot-admission evidence CLI test is missing ${marker}`);
    }
  }
  for (const marker of [
    "exactly one canonical manifest for every admission gate",
    "npm run pilot:admission:verify -- DOSSIER_FILE MANIFEST_DIRECTORY",
    '`artifactVerification: "not_performed"`',
    '`artifactVerification: "matched"`',
    "--artifact-root ARTIFACT_DIRECTORY_ROOT",
    "recomputes every underlying artifact byte count and SHA-256",
    "This is a binding and optional byte-integrity check, not another approval.",
    "The original manifest-only mode remains available",
    "The verifier has no network, API, database, settings, credential, or signing",
  ]) {
    if (!sources.documentation.includes(marker)) {
      failures.push(`the pilot-admission evidence documentation is missing ${marker}`);
    }
  }
  for (const marker of [
    "createPilotGateEvidenceManifest",
    "createReadinessExportFixture",
    "pilotGateAdmissionEvidence(manifest)",
    "pilotGateManifestJSON(manifest)",
    "artifactDirectoryRoot",
  ]) {
    if (!sources.fixture.includes(marker)) {
      failures.push(`the pilot-admission evidence fixture is missing ${marker}`);
    }
  }
  try {
    const packageJSON = JSON.parse(sources.package);
    if (
      packageJSON.scripts?.["pilot:admission:verify"] !==
      "node scripts/verify-pilot-admission-evidence.mjs"
    ) failures.push("package.json is missing the exact pilot-admission evidence command");
  } catch {
    failures.push("the pilot-admission evidence package command is invalid");
  }
  return { failures, filesChecked: Object.keys(files).length };
}

async function sourceAssurance(output, { allowDirty }) {
  const dirtyOutput = await capture("git", ["status", "--porcelain=v1"], { cwd: root });
  const dirty = Boolean(dirtyOutput.trim());
  if (dirty && !allowDirty) throw new Error("Release assurance requires a clean Git worktree.");
  const commit = (await capture("git", ["rev-parse", "HEAD"], { cwd: root })).trim();
  const source = await inspectTrackedSource(root);
  const directExecution = await validateDirectExecutionContract(root, source.files.map((entry) => entry.path));
  const authProviderReadiness = await validateAuthProviderReadinessContract(root);
  const pilotAdmissionEvidence = await validatePilotAdmissionEvidenceContract(root);
  const pilotGateEvidence = await validatePilotGateEvidenceContract(root);
  const readinessDossierVerifier = await validateReadinessDossierVerifierContract(root);
  const versions = await validateVersionAlignment(root);
  const compose = await validateComposeContracts(root);
  const automation = await validateAutomationContract(root);
  const codeScanning = await validateCodeScanningContract(root);
  const engineHostRuntime = await validateEngineHostRuntimeContract(root);
  const operationalAlertHandoff = await validateOperationalAlertHandoffContract(root);
  const operationalSchedulers = await validateOperationalSchedulerContract(root);
  const publicIngress = await validatePublicIngressContract(root);
  const edgeMonitor = await validateEdgeMonitorContract(root);
  const productionActivation = await validateProductionActivationContract(root);
  const productionStaging = await validateProductionStagingContract(root);
  const runtimeImageBuild = await validateRuntimeImageBuildContract(root);
  if (source.forbiddenPaths.length) throw new Error(`Forbidden tracked paths: ${source.forbiddenPaths.join(", ")}.`);
  if (source.secretFindings.length) {
    throw new Error(`Tracked secret policy failed: ${source.secretFindings.map((entry) => `${entry.path}:${entry.rule}`).join(", ")}.`);
  }
  if (source.unboundedGatewayJSONParsers.length) {
    throw new Error(
      `Gateway request handling uses unbounded request.json(): ${source.unboundedGatewayJSONParsers.join(", ")}.`,
    );
  }
  if (directExecution.failures.length) {
    throw new Error(`Operational CLI execution hardening failed: ${directExecution.failures.join("; ")}.`);
  }
  if (authProviderReadiness.failures.length) {
    throw new Error(`Identity-provider readiness hardening failed: ${authProviderReadiness.failures.join("; ")}.`);
  }
  if (pilotAdmissionEvidence.failures.length) {
    throw new Error(`Pilot-admission evidence hardening failed: ${pilotAdmissionEvidence.failures.join("; ")}.`);
  }
  if (pilotGateEvidence.failures.length) {
    throw new Error(`Pilot-gate evidence hardening failed: ${pilotGateEvidence.failures.join("; ")}.`);
  }
  if (readinessDossierVerifier.failures.length) {
    throw new Error(`Readiness dossier verifier hardening failed: ${readinessDossierVerifier.failures.join("; ")}.`);
  }
  if (versions.mismatches.length) throw new Error("VASI version declarations are not aligned.");
  if (compose.failures.length) throw new Error(`Compose hardening failed: ${compose.failures.join("; ")}.`);
  if (automation.failures.length) throw new Error(`Release automation hardening failed: ${automation.failures.join("; ")}.`);
  if (codeScanning.failures.length) throw new Error(`Code scanning hardening failed: ${codeScanning.failures.join("; ")}.`);
  if (engineHostRuntime.failures.length) {
    throw new Error(`Engine host runtime hardening failed: ${engineHostRuntime.failures.join("; ")}.`);
  }
  if (operationalSchedulers.failures.length) {
    throw new Error(`Operational scheduler hardening failed: ${operationalSchedulers.failures.join("; ")}.`);
  }
  if (operationalAlertHandoff.failures.length) {
    throw new Error(`Operational alert handoff hardening failed: ${operationalAlertHandoff.failures.join("; ")}.`);
  }
  if (publicIngress.failures.length) {
    throw new Error(`Public ingress hardening failed: ${publicIngress.failures.join("; ")}.`);
  }
  if (edgeMonitor.failures.length) {
    throw new Error(`Public edge monitor hardening failed: ${edgeMonitor.failures.join("; ")}.`);
  }
  if (productionActivation.failures.length) {
    throw new Error(`Production activation hardening failed: ${productionActivation.failures.join("; ")}.`);
  }
  if (productionStaging.failures.length) {
    throw new Error(`Production staging hardening failed: ${productionStaging.failures.join("; ")}.`);
  }
  if (runtimeImageBuild.failures.length) {
    throw new Error(`Runtime image build hardening failed: ${runtimeImageBuild.failures.join("; ")}.`);
  }

  await writeJSON(path.join(output, "tracked-source-files.json"), {
    files: source.files,
    schema: "vasi-tracked-source-files/v1",
  });
  const auditPath = path.join(output, "npm-audit.json");
  const productionAuditPath = path.join(output, "npm-audit-production.json");
  await commandToFile("npm", ["audit", "--json"], auditPath, { allowedExitCodes: [0, 1], cwd: root });
  await commandToFile("npm", ["audit", "--omit=dev", "--json"], productionAuditPath, { allowedExitCodes: [0, 1], cwd: root });
  const audit = JSON.parse(await readFile(auditPath, "utf8"));
  const productionAudit = JSON.parse(await readFile(productionAuditPath, "utf8"));
  assertAudit(audit, "complete dependency graph");
  assertAudit(productionAudit, "production dependency graph");
  await commandToFile("npm", ["sbom", "--sbom-format", "cyclonedx"], path.join(output, "source-sbom.cdx.json"), { cwd: root });
  await commandToFile("npm", ["sbom", "--sbom-format", "cyclonedx", "--omit=dev"], path.join(output, "source-sbom-production.cdx.json"), { cwd: root });
  return {
    commit,
    automation,
    authProviderReadiness,
    codeScanning,
    compose,
    directExecution,
    dirty,
    edgeMonitor,
    engineHostRuntime,
    operationalAlertHandoff,
    operationalSchedulers,
    pilotAdmissionEvidence,
    pilotGateEvidence,
    productionActivation,
    productionStaging,
    publicIngress,
    readinessDossierVerifier,
    runtimeImageBuild,
    sourceFileCount: source.files.length,
    versions: versions.actual,
    vulnerabilityCounts: {
      all: audit.metadata?.vulnerabilities || {},
      production: productionAudit.metadata?.vulnerabilities || {},
    },
  };
}

async function imageAssurance(output, images, { dockerSudo }) {
  if (!images.length) throw new Error("Provide at least one release image to scan.");
  const docker = dockerSudo ? { args: ["docker"], command: "sudo" } : { args: [], command: "docker" };
  const scannerVersion = await dockerCapture(docker, ["run", "--rm", policy.images.scannerImage, "--version"]);
  const packageJSON = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  const packageLock = JSON.parse(await readFile(path.join(root, "package-lock.json"), "utf8"));
  const summaries = [];
  const session = await mkdtemp(path.join(tmpdir(), `vasi-images-${randomUUID()}-`));
  const cachePath = path.join(session, "cache");
  await mkdir(cachePath, { mode: 0o700 });
  try {
    for (const [index, image] of images.entries()) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$/.test(image)) throw new Error(`Invalid image reference ${image}.`);
      const runtimeContract = runtimeContractForImage(image);
      const configuredUser = JSON.parse((await dockerCapture(
        docker,
        ["image", "inspect", image, "--format", "{{json .Config.User}}"],
      )).trim());
      if (configuredUser !== runtimeContract.imageUser) {
        throw new Error(`Release image ${image} has an unexpected configured runtime user.`);
      }
      const dependencyAudit = runtimeDependencyAuditPaths(
        packageJSON,
        packageLock,
        runtimeContract.allowedOptionalPackagePaths,
      );
      const prohibitedPaths = [
        ...dependencyAudit.prohibitedPackagePaths.map((packagePath) => `/app/${packagePath}`),
        ...dependencyAudit.prohibitedToolPaths,
      ].sort();
      const dependencyPayload = Buffer.from(JSON.stringify(prohibitedPaths)).toString("base64url");
      if (Buffer.byteLength(dependencyPayload) > 64 * 1024) {
        throw new Error("The runtime dependency inventory exceeds its assurance command bound.");
      }
      const inspectionText = await dockerCapture(docker, [
        "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--user", runtimeContract.runUser,
        "--entrypoint", "node", image, "--input-type=module", "--eval",
        runtimeDependencyInspector, dependencyPayload,
      ]);
      const inspection = parseRuntimeDependencyInspection(inspectionText, prohibitedPaths);
      if (inspection.presentCount > 0) {
        throw new Error(
          `Release image ${image} contains prohibited runtime dependency paths: ${inspection.present.join(", ")}`,
        );
      }
      for (const entrypoint of runtimeContract.entrypoints) {
        await dockerCapture(docker, [
          "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
          "--security-opt", "no-new-privileges:true", "--user", runtimeContract.runUser,
          "--entrypoint", "node", image, "--check", entrypoint,
        ]);
      }
      const temporary = path.join(session, `image-${index}`);
      await mkdir(temporary, { mode: 0o700 });
      const tarPath = path.join(temporary, "image.tar");
      const filename = image.replaceAll(/[^A-Za-z0-9._-]/g, "_");
      const vulnerabilityPath = path.join(output, `${filename}-vulnerabilities.json`);
      const sbomPath = path.join(output, `${filename}-sbom.cdx.json`);
      try {
        await dockerToFile(docker, ["image", "save", image], tarPath);
        await chmod(tarPath, 0o600);
        const mount = `${temporary}:/scan:ro`;
        const cache = `${cachePath}:/trivy-cache`;
        const user = `${process.getuid?.() ?? 65534}:${process.getgid?.() ?? 65534}`;
        const base = ["run", "--rm", "--user", user, "-v", mount, "-v", cache, policy.images.scannerImage, "image", "--cache-dir", "/trivy-cache", "--quiet", "--input", "/scan/image.tar"];
        await dockerToFile(docker, [...base, "--scanners", "vuln", "--format", "json"], vulnerabilityPath);
        await dockerToFile(docker, [...base, "--format", "cyclonedx"], sbomPath);
        const report = JSON.parse(await readFile(vulnerabilityPath, "utf8"));
        const vulnerabilities = (report.Results || []).flatMap((result) => result.Vulnerabilities || []);
        const blocking = vulnerabilities.filter((entry) => policy.images.failSeverities.includes(entry.Severity));
        summaries.push({
          blocking: blocking.map((entry) => ({ id: entry.VulnerabilityID, package: entry.PkgName, severity: entry.Severity })),
          digest: (await dockerCapture(docker, ["image", "inspect", image, "--format", "{{.Id}}"])) .trim(),
          image,
          dependencySurface: {
            allowedOptionalPackagePaths: runtimeContract.allowedOptionalPackagePaths,
            prohibitedPathsChecked: prohibitedPaths.length,
            verified: true,
          },
          runtimeContract: {
            entrypoints: runtimeContract.entrypoints,
            imageUser: runtimeContract.imageUser,
            runUser: runtimeContract.runUser,
            verified: true,
          },
          vulnerabilities: vulnerabilities.length,
        });
      } finally {
        await rm(temporary, { force: true, recursive: true });
      }
    }
  } finally {
    await rm(session, { force: true, recursive: true });
  }
  const blocking = summaries.flatMap((summary) => summary.blocking.map((finding) => ({ ...finding, image: summary.image })));
  if (blocking.length) {
    throw new Error(`Release images contain blocking vulnerabilities: ${blocking.map((entry) => `${entry.image}:${entry.id}:${entry.package}`).join(", ")}.`);
  }
  return { scannerImage: policy.images.scannerImage, scannerVersion: scannerVersion.trim(), summaries };
}

export function runtimeContractForImage(image, contracts = policy.images.runtimeContracts) {
  if (typeof image !== "string" || !Array.isArray(contracts)) {
    throw new Error("The release image runtime contract is invalid.");
  }
  const repository = image.split("@", 1)[0];
  const slash = repository.lastIndexOf("/");
  const colon = repository.lastIndexOf(":");
  const untagged = colon > slash ? repository.slice(0, colon) : repository;
  const name = untagged.slice(untagged.lastIndexOf("/") + 1);
  const contract = contracts.find((entry) => entry?.image === name);
  if (
    !contract || !Array.isArray(contract.allowedOptionalPackagePaths) ||
    contract.allowedOptionalPackagePaths.length > 64 ||
    contract.allowedOptionalPackagePaths.some((packagePath) => !isSafeNodeModulesPackagePath(packagePath)) ||
    new Set(contract.allowedOptionalPackagePaths).size !== contract.allowedOptionalPackagePaths.length ||
    !Array.isArray(contract.entrypoints) || !contract.entrypoints.length ||
    contract.entrypoints.length > 16 || contract.entrypoints.some((entrypoint) =>
      typeof entrypoint !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/.test(entrypoint) ||
      entrypoint.includes("..")
    ) || new Set(contract.entrypoints).size !== contract.entrypoints.length ||
    !/^(?:0|1000):(?:0|1000)$/.test(contract.runUser) ||
    !["", "node"].includes(contract.imageUser)
  ) {
    throw new Error(`Release image ${image} has no supported runtime contract.`);
  }
  return Object.freeze({
    allowedOptionalPackagePaths: Object.freeze([...contract.allowedOptionalPackagePaths].sort()),
    entrypoints: Object.freeze([...contract.entrypoints]),
    image: contract.image,
    imageUser: contract.imageUser,
    runUser: contract.runUser,
  });
}

export function runtimeDependencyAuditPaths(packageJSON, packageLock, allowedOptionalPackagePaths = []) {
  if (
    !isPlainRecord(packageJSON) || !isPlainRecord(packageLock) ||
    ![2, 3].includes(packageLock.lockfileVersion) ||
    !isPlainRecord(packageLock.packages) || !isPlainRecord(packageLock.packages[""]) ||
    !Array.isArray(allowedOptionalPackagePaths) || allowedOptionalPackagePaths.length > 64 ||
    new Set(allowedOptionalPackagePaths).size !== allowedOptionalPackagePaths.length
  ) {
    throw new Error("The runtime dependency inventory contract is invalid.");
  }
  const packageEntries = Object.entries(packageLock.packages);
  if (packageEntries.length < 1 || packageEntries.length > 10000) {
    throw new Error("The runtime dependency inventory package graph is outside its assurance bound.");
  }
  const productionDependencies = dependencyNames(packageJSON.dependencies, "production");
  const developmentDependencies = dependencyNames(packageJSON.devDependencies, "development");
  const prohibited = new Set(
    developmentDependencies
      .filter((name) => !productionDependencies.includes(name))
      .map((name) => `node_modules/${name}`),
  );
  for (const [packagePath, metadata] of packageEntries) {
    if (packagePath === "") continue;
    if (!isSafeNodeModulesPackagePath(packagePath) || !isPlainRecord(metadata)) {
      throw new Error("The runtime dependency inventory contains an unsafe package-lock path.");
    }
    for (const flag of ["dev", "devOptional", "optional"]) {
      if (metadata[flag] !== undefined && typeof metadata[flag] !== "boolean") {
        throw new Error("The runtime dependency inventory contains malformed package-lock flags.");
      }
    }
    if (metadata.dev === true || metadata.devOptional === true || metadata.optional === true) {
      prohibited.add(packagePath);
    }
  }
  for (const allowedPath of allowedOptionalPackagePaths) {
    if (!isSafeNodeModulesPackagePath(allowedPath) || !prohibited.has(allowedPath)) {
      throw new Error("The runtime dependency inventory contains an unsupported optional-package exception.");
    }
    prohibited.delete(allowedPath);
  }
  return Object.freeze({
    allowedOptionalPackagePaths: Object.freeze([...allowedOptionalPackagePaths].sort()),
    lockPackageCount: packageEntries.length,
    prohibitedPackagePaths: Object.freeze([...prohibited].sort()),
    prohibitedToolPaths: prohibitedRuntimeToolPaths,
  });
}

function dependencyNames(value, label) {
  if (value === undefined) return [];
  if (!isPlainRecord(value)) {
    throw new Error(`The runtime dependency inventory has invalid ${label} dependencies.`);
  }
  const names = Object.keys(value);
  if (
    names.length > 1000 || names.some((name) => !isSafeNpmPackageName(name)) ||
    Object.values(value).some((version) => typeof version !== "string" || !version.trim())
  ) {
    throw new Error(`The runtime dependency inventory has invalid ${label} dependencies.`);
  }
  return names.sort();
}

function dockerfileStage(contents, stageName) {
  if (typeof contents !== "string") return "";
  const body = [];
  let selected = false;
  for (const line of contents.split("\n")) {
    const from = /^FROM\s+\S+(?:\s+AS\s+([A-Za-z0-9_-]+))?\s*$/i.exec(line);
    if (from) {
      if (selected) break;
      selected = from[1]?.toLowerCase() === stageName.toLowerCase();
      continue;
    }
    if (selected) body.push(line);
  }
  return body.join("\n");
}

function isPlainRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isSafeNpmPackageName(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 214) return false;
  const segments = value.startsWith("@") ? value.slice(1).split("/") : [value];
  if (segments.length !== (value.startsWith("@") ? 2 : 1)) return false;
  return segments.every((segment) =>
    segment.length > 0 && segment.length <= 128 && segment !== "." && segment !== ".." &&
    /^[A-Za-z0-9._-]+$/.test(segment)
  );
}

function isSafeNodeModulesPackagePath(value) {
  if (typeof value !== "string" || value.length < 14 || value.length > 1024) return false;
  const segments = value.split("/");
  let cursor = 0;
  while (cursor < segments.length) {
    if (segments[cursor] !== "node_modules") return false;
    cursor += 1;
    if (cursor >= segments.length) return false;
    if (segments[cursor].startsWith("@")) {
      if (
        cursor + 1 >= segments.length ||
        !isSafeNpmPackageName(`${segments[cursor]}/${segments[cursor + 1]}`)
      ) return false;
      cursor += 2;
    } else {
      if (!isSafeNpmPackageName(segments[cursor])) return false;
      cursor += 1;
    }
  }
  return true;
}

function parseRuntimeDependencyInspection(text, expectedPaths) {
  let inspection;
  try {
    inspection = JSON.parse(text);
  } catch {
    throw new Error("A release image returned malformed runtime dependency evidence.");
  }
  const expected = new Set(expectedPaths);
  if (
    !isPlainRecord(inspection) || inspection.total !== expectedPaths.length ||
    !Number.isSafeInteger(inspection.presentCount) || inspection.presentCount < 0 ||
    inspection.presentCount > expectedPaths.length || !Array.isArray(inspection.present) ||
    inspection.present.length !== Math.min(inspection.presentCount, 32) ||
    new Set(inspection.present).size !== inspection.present.length ||
    inspection.present.some((candidate) => typeof candidate !== "string" || !expected.has(candidate))
  ) {
    throw new Error("A release image returned invalid runtime dependency evidence.");
  }
  return inspection;
}

async function main() {
  const parsed = parseArguments(process.argv.slice(2));
  await mkdir(parsed.output, { mode: 0o700, recursive: false });
  try {
    const result = {};
    if (parsed.command === "source" || parsed.command === "all") {
      result.source = await sourceAssurance(parsed.output, parsed);
    }
    if (parsed.command === "images" || parsed.command === "all") {
      result.images = await imageAssurance(parsed.output, parsed.images, parsed);
    }
    const artifacts = await artifactDigests(parsed.output);
    await writeJSON(path.join(parsed.output, "assurance-manifest.json"), {
      artifacts,
      generatedAt: new Date().toISOString(),
      policy,
      result,
      schema: "vasi-release-assurance-manifest/v1",
    });
    console.info(`VASI release assurance passed; ${artifacts.length + 1} evidence files were written.`);
  } catch (error) {
    await rm(parsed.output, { force: true, recursive: true });
    throw error;
  }
}

function parseArguments(args) {
  const [command, outputSource, ...rest] = args;
  if (!["all", "images", "source"].includes(command) || !outputSource) usage();
  const images = [];
  let allowDirty = false;
  let dockerSudo = false;
  for (const argument of rest) {
    if (argument === "--allow-dirty") allowDirty = true;
    else if (argument === "--docker-sudo") dockerSudo = true;
    else if (argument.startsWith("--")) throw new Error(`Unknown assurance option ${argument}.`);
    else images.push(argument);
  }
  if (command === "source" && images.length) throw new Error("Source assurance does not accept image references.");
  const output = path.resolve(outputSource);
  const relative = path.relative(root, output);
  if (relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..")) {
    throw new Error("Assurance evidence must be written outside the Git repository.");
  }
  return { allowDirty, command, dockerSudo, images, output };
}

function assertAudit(report, label) {
  const counts = report.metadata?.vulnerabilities;
  if (!counts) throw new Error(`npm audit did not return vulnerability metadata for the ${label}.`);
  const blocking = policy.source.failAuditSeverities.filter((severity) => Number(counts[severity] || 0) > 0);
  if (blocking.length) throw new Error(`npm audit found ${blocking.join("/")} vulnerabilities in the ${label}.`);
}

function arrayContains(value, expected) {
  return Array.isArray(value) && value.includes(expected);
}

function hasReadOnlyDataMount(volumes) {
  return Array.isArray(volumes) && volumes.some((volume) => {
    if (typeof volume === "string") return /(?:^|\/)data:\/app\/data:ro$/.test(volume);
    return volume?.target === "/app/data" && volume?.read_only === true;
  });
}

function hasBoundedCapacityProcMounts(volumes) {
  if (!Array.isArray(volumes)) return false;
  const procMounts = volumes
    .filter((volume) => typeof volume === "object" && String(volume?.target || "").startsWith("/host/proc"))
    .map((volume) => ({ readOnly: volume.read_only, source: volume.source, target: volume.target }))
    .sort((left, right) => left.target.localeCompare(right.target));
  return JSON.stringify(procMounts) === JSON.stringify([
    { readOnly: true, source: "/proc/loadavg", target: "/host/proc/loadavg" },
    { readOnly: true, source: "/proc/meminfo", target: "/host/proc/meminfo" },
    { readOnly: true, source: "/proc/pressure", target: "/host/proc/pressure" },
    { readOnly: true, source: "/proc/stat", target: "/host/proc/stat" },
  ]);
}

function hasReadOnlyDatabaseTransportMarker(volumes) {
  return Array.isArray(volumes) && volumes.some((volume) => {
    if (typeof volume === "string") {
      return volume === "./config/database-gateway-transport.json:/run/vasi/database-gateway.json:ro";
    }
    return volume?.source === "./config/database-gateway-transport.json" &&
      volume?.target === "/run/vasi/database-gateway.json" && volume?.read_only === true;
  });
}

function serviceNetworks(service) {
  const networks = service?.networks;
  if (Array.isArray(networks)) return [...networks].sort();
  if (networks && typeof networks === "object") return Object.keys(networks).sort();
  return [];
}

function isDockerSocketMount(volume) {
  if (typeof volume === "string") return volume.split(":", 1)[0] === "/var/run/docker.sock";
  return volume?.source === "/var/run/docker.sock" || volume?.target === "/var/run/docker.sock";
}

function isDigestPinnedImage(value) {
  return typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._/:@-]{12,255}@sha256:[a-f0-9]{64}$/.test(value) &&
    value.indexOf("@sha256:") === value.lastIndexOf("@sha256:");
}

function portsAreLoopback(ports) {
  return Array.isArray(ports) && ports.length > 0 && ports.every((entry) => {
    if (typeof entry === "string") return entry.startsWith("127.0.0.1:");
    return entry?.host_ip === "127.0.0.1";
  });
}

function environmentKeys(environment) {
  if (Array.isArray(environment)) return environment.map((entry) => String(entry).split("=", 1)[0]);
  return environment && typeof environment === "object" ? Object.keys(environment) : [];
}

async function artifactDigests(directory) {
  const { readdir } = await import("node:fs/promises");
  const names = (await readdir(directory)).filter((name) => name !== "assurance-manifest.json").sort();
  return Promise.all(names.map(async (name) => {
    const contents = await readFile(path.join(directory, name));
    return { bytes: contents.length, name, sha256: createHash("sha256").update(contents).digest("hex") };
  }));
}

async function capture(command, args, { cwd = root, maximumBytes = 8 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    let size = 0;
    child.stdout.on("data", (chunk) => {
      size += chunk.length;
      if (size <= maximumBytes) stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);
    child.once("exit", (code) => {
      if (size > maximumBytes) return reject(new Error(`${command} output exceeded its assurance bound.`));
      if (code !== 0) return reject(new Error(`${command} failed: ${Buffer.concat(stderr).toString("utf8").trim()}`));
      resolve(Buffer.concat(stdout).toString("utf8"));
    });
  });
}

async function commandToFile(command, args, destination, { allowedExitCodes = [0], cwd = root } = {}) {
  const output = createWriteStream(destination, { flags: "wx", mode: 0o600 });
  const child = spawn(command, args, { cwd, stdio: ["ignore", "pipe", "inherit"] });
  child.stdout.pipe(output);
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  await finished(output);
  if (!allowedExitCodes.includes(code)) throw new Error(`${command} exited with status ${code}.`);
}

function dockerCapture(docker, args) {
  return capture(docker.command, [...docker.args, ...args]);
}

function dockerToFile(docker, args, destination) {
  return commandToFile(docker.command, [...docker.args, ...args], destination);
}

async function writeJSON(filename, value) {
  await writeFile(filename, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 });
}

function usage() {
  console.info(`VASI release assurance:
  node scripts/release-assurance.mjs source OUTPUT_DIRECTORY [--allow-dirty]
  node scripts/release-assurance.mjs images OUTPUT_DIRECTORY IMAGE... [--docker-sudo]
  node scripts/release-assurance.mjs all OUTPUT_DIRECTORY IMAGE... [--allow-dirty] [--docker-sudo]`);
  process.exit(1);
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : "VASI release assurance failed.");
    process.exitCode = 1;
  });
}
