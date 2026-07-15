import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { finished } from "node:stream/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

import { parse as parseYAML } from "yaml";

import policy from "../config/assurance-policy.json" with { type: "json" };

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

export async function inspectTrackedSource(repositoryRoot = root) {
  const tracked = (await capture("git", ["ls-files", "-z"], { cwd: repositoryRoot }))
    .split("\0")
    .filter(Boolean)
    .sort();
  const forbiddenPaths = tracked.filter((filename) =>
    forbiddenPathPatterns.some((pattern) => pattern.test(filename))
  );
  const secretFindings = [];
  const files = [];
  for (const filename of tracked) {
    const absolute = path.join(repositoryRoot, filename);
    const metadata = await stat(absolute);
    if (!metadata.isFile()) continue;
    const contents = await readFile(absolute);
    files.push({
      bytes: contents.length,
      path: filename,
      sha256: createHash("sha256").update(contents).digest("hex"),
    });
    if (contents.includes(0) || contents.length > 4 * 1024 * 1024) continue;
    const text = contents.toString("utf8");
    for (const candidate of secretPatterns) {
      if (candidate.pattern.test(text)) {
        secretFindings.push({ path: filename, rule: candidate.name });
      }
    }
  }
  return { files, forbiddenPaths, secretFindings };
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
      /Environment(?:File)?=|compose\.live\.yaml|\.private|\.tasks|VASI-\d|https?:\/\/|\/home\/|docker\.sock|--privileged|--network(?:=|\s+)host/.test(contents)
    ) {
      failures.push(`${filename} contains a prohibited privilege or configuration path`);
    }
  }
  return { failures, unitsChecked: Object.keys(requirements) };
}

async function sourceAssurance(output, { allowDirty }) {
  const dirtyOutput = await capture("git", ["status", "--porcelain=v1"], { cwd: root });
  const dirty = Boolean(dirtyOutput.trim());
  if (dirty && !allowDirty) throw new Error("Release assurance requires a clean Git worktree.");
  const commit = (await capture("git", ["rev-parse", "HEAD"], { cwd: root })).trim();
  const source = await inspectTrackedSource(root);
  const versions = await validateVersionAlignment(root);
  const compose = await validateComposeContracts(root);
  const automation = await validateAutomationContract(root);
  const operationalSchedulers = await validateOperationalSchedulerContract(root);
  if (source.forbiddenPaths.length) throw new Error(`Forbidden tracked paths: ${source.forbiddenPaths.join(", ")}.`);
  if (source.secretFindings.length) {
    throw new Error(`Tracked secret policy failed: ${source.secretFindings.map((entry) => `${entry.path}:${entry.rule}`).join(", ")}.`);
  }
  if (versions.mismatches.length) throw new Error("VASI version declarations are not aligned.");
  if (compose.failures.length) throw new Error(`Compose hardening failed: ${compose.failures.join("; ")}.`);
  if (automation.failures.length) throw new Error(`Release automation hardening failed: ${automation.failures.join("; ")}.`);
  if (operationalSchedulers.failures.length) {
    throw new Error(`Operational scheduler hardening failed: ${operationalSchedulers.failures.join("; ")}.`);
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
    compose,
    dirty,
    operationalSchedulers,
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
    !contract || !Array.isArray(contract.entrypoints) || !contract.entrypoints.length ||
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
    entrypoints: Object.freeze([...contract.entrypoints]),
    image: contract.image,
    imageUser: contract.imageUser,
    runUser: contract.runUser,
  });
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : "VASI release assurance failed.");
    process.exitCode = 1;
  });
}
