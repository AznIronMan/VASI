import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

export const EGRESS_BOUNDARY_VERSION = "0.21.1";
export const EGRESS_BOUNDARY_SCHEMA = "vasi-engine-egress-boundary/v1";
const DEFAULT_DATABASE_CHAIN = "VASI_DATABASE_EGRESS";
const DEFAULT_PROJECT_NAME = "vasi-engine";
const PUBLIC_CANARY = "https://example.com/";
const PRIVATE_SERVICES = ["database-gateway", "engine", "private-ingress", "worker"];
const HEALTHY_SERVICES = new Set(["database-gateway", "engine", "integration-gateway"]);
const ALL_SERVICES = [...PRIVATE_SERVICES, "integration-gateway"];
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export async function probeEngineEgressBoundary({
  chain = DEFAULT_DATABASE_CHAIN,
  projectName = DEFAULT_PROJECT_NAME,
  repositoryRoot = root,
  runner = runBounded,
} = {}) {
  const checkedChain = validatedChain(chain);
  const checkedProjectName = validatedProjectName(projectName);
  const compose = composeArguments(repositoryRoot, checkedProjectName);
  const containers = Object.fromEntries(await Promise.all(ALL_SERVICES.map(async (service) => [
    service,
    await composeContainer({ compose, repositoryRoot, runner, service }),
  ])));

  await verifyRuntimeHealth({ containers, runner });
  await verifyDatabaseFirewall({ chain: checkedChain, compose, projectName: checkedProjectName, repositoryRoot, runner });
  await Promise.all(PRIVATE_SERVICES.map(async (service) => {
    const result = await runner("docker", canaryArguments(containers[service]), { timeoutMilliseconds: 10_000 });
    if (result.code !== 42) throw new Error("The VASI private service egress boundary is unavailable.");
  }));
  const integration = await runner("docker", canaryArguments(containers["integration-gateway"]), {
    timeoutMilliseconds: 10_000,
  });
  if (integration.code !== 0) throw new Error("The VASI integration egress path is unavailable.");

  const database = await runner("docker", databaseProbeArguments(containers.engine), {
    timeoutMilliseconds: 10_000,
  });
  if (database.code !== 0) throw new Error("The VASI database transport path is unavailable.");

  return Object.freeze({
    checks: Object.freeze({
      databasePolicy: "ok",
      databaseTransport: "ok",
      deniedPrivateServices: PRIVATE_SERVICES.length,
      integrationEgress: "ok",
      runtimeHealth: "ok",
    }),
    schema: EGRESS_BOUNDARY_SCHEMA,
    status: "ok",
    version: EGRESS_BOUNDARY_VERSION,
  });
}

export function verifyDatabaseFirewallRules(expectedText, actualText, chain = DEFAULT_DATABASE_CHAIN) {
  const checkedChain = validatedChain(chain);
  const expected = chainRules(expectedText, checkedChain);
  const actual = chainRules(actualText, checkedChain);
  const jumps = String(actualText).split("\n")
    .filter((line) => line === `-A DOCKER-USER -j ${checkedChain}`);
  if (!expected.length || JSON.stringify(actual) !== JSON.stringify(expected) || jumps.length !== 1) {
    throw new Error("The VASI database egress firewall policy is unavailable.");
  }
  return true;
}

function chainRules(value, chain) {
  return String(value).split("\n")
    .filter((line) => line.startsWith(`-A ${chain} `))
    .map((line) => line.replace(/--ctstate ([A-Z,]+)/, (_match, states) =>
      `--ctstate ${states.split(",").sort().join(",")}`));
}

function composeArguments(repositoryRoot, projectName) {
  const args = ["compose", "--project-name", projectName, "-f", "compose.engine.yaml"];
  if (existsSync(path.join(repositoryRoot, "compose.live.yaml"))) {
    args.push("-f", "compose.live.yaml");
  }
  return args;
}

async function composeContainer({ compose, repositoryRoot, runner, service }) {
  const result = await runner("docker", [...compose, "ps", "-q", service], {
    cwd: repositoryRoot,
    timeoutMilliseconds: 10_000,
  });
  const identifiers = result.stdout.trim().split(/\s+/).filter(Boolean);
  if (result.code !== 0 || identifiers.length !== 1 || !/^[a-f0-9]{12,64}$/.test(identifiers[0])) {
    throw new Error("The VASI engine runtime boundary is unavailable.");
  }
  return identifiers[0];
}

async function verifyRuntimeHealth({ containers, runner }) {
  await Promise.all(Object.entries(containers).map(async ([service, identifier]) => {
    const result = await runner("docker", [
      "inspect", "--format",
      "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
      identifier,
    ], { timeoutMilliseconds: 10_000 });
    const expected = HEALTHY_SERVICES.has(service) ? "running|healthy" : "running|";
    if (result.code !== 0 || result.stdout.trim() !== expected) {
      throw new Error("The VASI engine runtime boundary is unavailable.");
    }
  }));
}

async function verifyDatabaseFirewall({ chain, compose, projectName, repositoryRoot, runner }) {
  const network = await runner("docker", [
    "network", "inspect", `${projectName}_database-egress`, "--format",
    "{{(index .IPAM.Config 0).Subnet}}",
  ], { timeoutMilliseconds: 10_000 });
  const subnet = network.stdout.trim();
  if (network.code !== 0 || !/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(subnet)) {
    throw new Error("The VASI database egress firewall policy is unavailable.");
  }
  const expected = await runner("docker", [
    ...compose, "--profile", "tools", "run", "--rm", "--no-deps",
    "egress-policy", "--subnet", subnet, "--chain", chain,
  ], { cwd: repositoryRoot, timeoutMilliseconds: 30_000 });
  const actual = await runner("iptables-save", ["-t", "filter"], { timeoutMilliseconds: 10_000 });
  if (expected.code !== 0 || actual.code !== 0) {
    throw new Error("The VASI database egress firewall policy is unavailable.");
  }
  verifyDatabaseFirewallRules(expected.stdout, actual.stdout, chain);
}

function validatedChain(value) {
  const chain = String(value || "");
  if (!/^[A-Z][A-Z0-9_]{0,27}$/.test(chain)) {
    throw new Error("The VASI egress boundary arguments are invalid.");
  }
  return chain;
}

function validatedProjectName(value) {
  const projectName = String(value || "");
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(projectName)) {
    throw new Error("The VASI egress boundary arguments are invalid.");
  }
  return projectName;
}

function parseArguments(args) {
  const parsed = { chain: DEFAULT_DATABASE_CHAIN, projectName: DEFAULT_PROJECT_NAME };
  const seen = new Set();
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (!value || seen.has(option) || !["--chain", "--project-name"].includes(option)) {
      throw new Error("The VASI egress boundary arguments are invalid.");
    }
    seen.add(option);
    if (option === "--chain") parsed.chain = validatedChain(value);
    if (option === "--project-name") parsed.projectName = validatedProjectName(value);
  }
  return parsed;
}

function canaryArguments(identifier) {
  return [
    "exec", identifier, "node", "-e",
    `fetch(${JSON.stringify(PUBLIC_CANARY)},{redirect:'error',signal:AbortSignal.timeout(5000)}).then(r=>process.exit(r.ok?0:41)).catch(()=>process.exit(42))`,
  ];
}

function databaseProbeArguments(identifier) {
  return [
    "exec", identifier, "node", "-e",
    "import('./scripts/settings-core.mjs').then(async m=>{const p=m.createSettingsPool();try{await p.query('select 1')}finally{await p.end()}}).catch(()=>process.exit(1))",
  ];
}

function runBounded(command, args, { cwd = root, timeoutMilliseconds = 15_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"] });
    const output = { stderr: "", stdout: "" };
    let exceeded = false;
    const timer = setTimeout(() => {
      exceeded = true;
      child.kill("SIGKILL");
    }, timeoutMilliseconds);
    timer.unref();
    for (const stream of ["stdout", "stderr"]) {
      child[stream].setEncoding("utf8");
      child[stream].on("data", (chunk) => {
        if (output[stream].length <= 65_536) output[stream] += chunk;
        if (output[stream].length > 65_536) child.kill("SIGKILL");
      });
    }
    child.once("error", () => {
      clearTimeout(timer);
      resolve({ code: 127, stderr: "", stdout: "" });
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      resolve({ code: exceeded ? 124 : (code ?? 1), ...output });
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let parsed;
  try {
    parsed = parseArguments(process.argv.slice(2));
  } catch {
    console.error("VASI engine egress boundary probe failed.");
    process.exitCode = 1;
  }
  if (parsed) probeEngineEgressBoundary(parsed)
    .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
    .catch(() => {
      console.error("VASI engine egress boundary probe failed.");
      process.exitCode = 1;
    });
}
