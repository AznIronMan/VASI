import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import {
  lstat,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ACTIVATION_SCHEMA = "vasi-production-release-activation/v1";

const roles = Object.freeze({
  gateway: Object.freeze({
    composeFile: "compose.production.yaml",
    containerPort: 3000,
    defaultHostPort: 3000,
    images: Object.freeze(["vasi", "vasi-settings", "vasi-engine-maintenance"]),
    projectName: "vasi",
    runtimeImages: Object.freeze({ app: "vasi" }),
    runtimeServices: Object.freeze(["app"]),
    targetService: "app",
  }),
  engine: Object.freeze({
    composeFile: "compose.engine.yaml",
    containerPort: 8443,
    defaultHostPort: 11121,
    images: Object.freeze([
      "vasi-engine",
      "vasi-engine-tools",
      "vasi-engine-maintenance",
      "vasi-database-gateway",
    ]),
    projectName: "vasi-engine",
    runtimeImages: Object.freeze({
      "database-gateway": "vasi-database-gateway",
      engine: "vasi-engine",
      "integration-gateway": "vasi-engine",
      "private-ingress": "vasi-engine",
      worker: "vasi-engine",
    }),
    runtimeServices: Object.freeze([
      "database-gateway",
      "engine",
      "integration-gateway",
      "worker",
      "private-ingress",
    ]),
    targetService: "private-ingress",
  }),
});

export async function activateProductionRelease(
  configurationFile,
  releaseId,
  {
    commandRunner = runBounded,
    dryRun = false,
    scriptRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
    uid = process.getuid?.() ?? 0,
  } = {},
) {
  if (typeof releaseId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(releaseId)) {
    throw new Error("The release identifier is invalid.");
  }
  const configuration = await loadProtectedConfiguration(configurationFile, uid);
  if (dryRun) {
    const prepared = await prepareActivation(configuration, releaseId, { commandRunner, scriptRoot, uid });
    return activationResult(prepared, "ready");
  }

  const lock = `${configuration.currentLink}.activation-lock`;
  try {
    await mkdir(lock, { mode: 0o700 });
  } catch (error) {
    if (error?.code === "EEXIST") throw new Error("Another production release activation is in progress.");
    throw error;
  }

  let createdOverlayLink = false;
  let selectorChanged = false;
  let prepared;
  try {
    prepared = await prepareActivation(configuration, releaseId, { commandRunner, scriptRoot, uid });
    if (prepared.overlayLinkMissing) {
      await symlink(configuration.overlayFile, prepared.candidateOverlay);
      createdOverlayLink = true;
    }
    try {
      await pointCurrent(configuration.currentLink, prepared.candidate);
      selectorChanged = true;
      await reconcile(prepared, commandRunner);
      await verifyRunningServices(prepared, commandRunner);
    } catch (error) {
      let rollbackFailed = false;
      if (selectorChanged) {
        try {
          await restoreCurrent(configuration.currentLink, prepared.previousTarget);
        } catch {
          rollbackFailed = true;
        }
        if (!rollbackFailed && prepared.previousTarget && prepared.previousTarget !== prepared.candidate) {
          try {
            await reconcile({ ...prepared, candidate: prepared.previousTarget }, commandRunner);
          } catch {
            rollbackFailed = true;
          }
        } else if (!rollbackFailed && !prepared.previousTarget) {
          try {
            await stopRuntime(prepared, commandRunner);
          } catch {
            rollbackFailed = true;
          }
        }
      }
      if (createdOverlayLink) await rm(prepared.candidateOverlay, { force: true });
      if (rollbackFailed) throw new Error("Production release activation and runtime rollback both failed.");
      throw error;
    }
    return activationResult(prepared, "activated");
  } finally {
    await rm(lock, { force: true, recursive: true });
  }
}

export function validateActivationConfigurationValue(value) {
  const expected = ["currentLink", "dataRoot", "overlayFile", "releaseOwnerUid", "releaseRoot", "role", "schema"];
  if (!isPlainRecord(value) || Object.keys(value).sort().join(",") !== expected.join(",")) {
    throw new Error("The production release activation configuration fields are invalid.");
  }
  if (value.schema !== ACTIVATION_SCHEMA || !roles[value.role]) {
    throw new Error("The production release activation configuration is unsupported.");
  }
  if (!Number.isInteger(value.releaseOwnerUid) || value.releaseOwnerUid < 0 || value.releaseOwnerUid > 4_294_967_294) {
    throw new Error("The production release activation releaseOwnerUid is invalid.");
  }
  const paths = {};
  for (const name of ["currentLink", "dataRoot", "overlayFile", "releaseRoot"]) {
    if (
      typeof value[name] !== "string" || !path.isAbsolute(value[name]) ||
      path.normalize(value[name]) !== value[name] || /[\0\r\n]/.test(value[name])
    ) {
      throw new Error(`The production release activation ${name} is invalid.`);
    }
    paths[name] = value[name];
  }
  if (
    paths.currentLink === paths.releaseRoot || paths.currentLink === paths.dataRoot ||
    paths.currentLink === paths.overlayFile || isWithin(paths.releaseRoot, paths.currentLink) ||
    isWithin(paths.dataRoot, paths.currentLink) ||
    paths.releaseRoot === paths.dataRoot || isWithin(paths.releaseRoot, paths.dataRoot) ||
    isWithin(paths.dataRoot, paths.releaseRoot) || isWithin(paths.releaseRoot, paths.overlayFile) ||
    isWithin(paths.dataRoot, paths.overlayFile)
  ) {
    throw new Error("The production release activation paths overlap unsafely.");
  }
  return Object.freeze({ ...paths, releaseOwnerUid: value.releaseOwnerUid, role: value.role, schema: value.schema });
}

export function parseProtectedOverlay(source, role) {
  const contract = roles[role];
  if (!contract || typeof source !== "string" || Buffer.byteLength(source) > 4096) {
    throw new Error("The protected Compose overlay is unsupported.");
  }
  const match = source.match(/^services:\n  ([a-z0-9-]+):\n    ports: !override\n      - ([^\s]+)\n$/);
  if (!match || match[1] !== contract.targetService) {
    throw new Error("The protected Compose overlay may replace only the approved listener.");
  }
  const binding = match[2].match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5}):(\d{1,5})$/);
  if (!binding || isIP(binding[1]) !== 4 || !isApprovedListenerIPv4(binding[1])) {
    throw new Error("The protected Compose listener must use loopback or an RFC1918 IPv4 address.");
  }
  const hostPort = boundedPort(binding[2]);
  const containerPort = boundedPort(binding[3]);
  if (containerPort !== contract.containerPort) {
    throw new Error("The protected Compose listener targets the wrong container port.");
  }
  return Object.freeze({ containerPort, host: binding[1], hostPort, service: contract.targetService });
}

export function validateMergedCompose(base, merged, { listener, role, version }) {
  const contract = roles[role];
  if (!contract || !isPlainRecord(base) || !isPlainRecord(merged) || !isPlainRecord(base.services) || !isPlainRecord(merged.services)) {
    throw new Error("The rendered Compose model is invalid.");
  }
  if (canonical(base.services && Object.keys(base.services).sort()) !== canonical(Object.keys(merged.services).sort())) {
    throw new Error("The protected Compose overlay changed the service inventory.");
  }
  if (base.name !== contract.projectName || merged.name !== contract.projectName) {
    throw new Error("The rendered Compose project identity is invalid.");
  }
  const baseService = base.services[contract.targetService];
  const mergedService = merged.services[contract.targetService];
  if (!isPlainRecord(baseService) || !isPlainRecord(mergedService)) {
    throw new Error("The rendered Compose listener service is missing.");
  }
  assertPort(baseService.ports, {
    containerPort: contract.containerPort,
    host: "127.0.0.1",
    hostPort: contract.defaultHostPort,
  });
  assertPort(mergedService.ports, listener);

  const normalizedMerged = structuredClone(merged);
  normalizedMerged.services[contract.targetService].ports = structuredClone(baseService.ports);
  if (canonical(base) !== canonical(normalizedMerged)) {
    throw new Error("The protected Compose overlay changed more than the approved listener.");
  }
  for (const [service, image] of Object.entries(contract.runtimeImages)) {
    if (base.services[service]?.image !== `${image}:${version}` || merged.services[service]?.image !== `${image}:${version}`) {
      throw new Error("The rendered Compose model does not use the exact release images.");
    }
    validateRuntimeHardening(merged.services[service]);
  }
  for (const [service, definition] of Object.entries(merged.services)) {
    if (service !== contract.targetService && Array.isArray(definition?.ports) && definition.ports.length) {
      throw new Error("The rendered Compose model publishes an unexpected listener.");
    }
  }
  return Object.freeze({ images: contract.images.length, services: contract.runtimeServices.length });
}

async function prepareActivation(configuration, releaseId, { commandRunner, scriptRoot, uid }) {
  const contract = roles[configuration.role];
  const releaseOwners = uniqueNumbers([0, uid, configuration.releaseOwnerUid]);
  await validateDirectory(configuration.releaseRoot, releaseOwners, false);
  await validateDirectory(configuration.dataRoot, uniqueNumbers([...releaseOwners, 1000]), true);
  await validateDirectory(path.dirname(configuration.currentLink), releaseOwners, false);
  const releaseRoot = await realpath(configuration.releaseRoot);
  const candidate = path.join(releaseRoot, releaseId);
  await validateDirectory(candidate, releaseOwners, false);
  if (path.dirname(candidate) !== releaseRoot || await realpath(candidate) !== candidate) {
    throw new Error("The candidate release is outside the configured release root.");
  }
  const previousTarget = await validateCurrentLink(configuration.currentLink, releaseRoot, releaseOwners);
  const activatorRoot = await realpath(scriptRoot);
  if (activatorRoot !== candidate && activatorRoot !== previousTarget) {
    throw new Error("The activation command must run from the candidate or selected trusted release.");
  }
  await validateDirectory(path.dirname(configuration.overlayFile), [0, uid], true);
  await validateProtectedFile(configuration.overlayFile, [0, uid], 4096);
  const protectedOverlaySource = await readFile(configuration.overlayFile, "utf8");
  const listener = parseProtectedOverlay(protectedOverlaySource, configuration.role);
  const candidateOverlay = path.join(candidate, "compose.live.yaml");
  const overlayLinkMissing = await validateCandidateOverlay(candidateOverlay, configuration.overlayFile);
  const candidateRuntime = await inspectReleaseRuntime(
    candidate, configuration, contract, listener, commandRunner, releaseOwners,
  );
  if (previousTarget && previousTarget !== candidate) {
    try {
      await inspectReleaseRuntime(previousTarget, configuration, contract, listener, commandRunner, releaseOwners);
      await validateRollbackOverlay(
        path.join(previousTarget, "compose.live.yaml"),
        configuration.overlayFile,
        protectedOverlaySource,
        releaseOwners,
      );
    } catch {
      throw new Error("The selected rollback release is not ready.");
    }
  }
  return Object.freeze({
    candidate,
    candidateOverlay,
    composeFile: candidateRuntime.composeFile,
    configuration,
    contract,
    overlayLinkMissing,
    previousTarget,
    summary: candidateRuntime.summary,
    version: candidateRuntime.version,
  });
}

async function inspectReleaseRuntime(releaseDirectory, configuration, contract, listener, commandRunner, releaseOwners) {
  await validateDirectory(releaseDirectory, releaseOwners, false);
  const packageFile = path.join(releaseDirectory, "package.json");
  const composeFile = path.join(releaseDirectory, contract.composeFile);
  await validateSourceFile(packageFile, releaseOwners, 128 * 1024);
  await validateSourceFile(composeFile, releaseOwners, 512 * 1024);
  const packageJSON = JSON.parse(await readFile(packageFile, "utf8"));
  const version = typeof packageJSON?.version === "string" && /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(packageJSON.version)
    ? packageJSON.version
    : null;
  if (!version) throw new Error("A release version is invalid.");
  const composeSource = await readFile(composeFile, "utf8");
  if (/\$\{|(?:^|\n)\s*(?:environment|env_file|extends|include):|!include|\.env\b/.test(composeSource)) {
    throw new Error("A release Compose source contains unsupported external state.");
  }
  const dataLink = path.join(releaseDirectory, "data");
  const dataMetadata = await lstat(dataLink);
  if (!dataMetadata.isSymbolicLink() || await realpath(dataLink) !== await realpath(configuration.dataRoot)) {
    throw new Error("The candidate release data binding is not the configured shared data root.");
  }
  const base = parseJSON(await commandRunner(
    "docker", composeArguments(releaseDirectory, composeFile, null, ["config", "--format", "json"]),
    { cwd: releaseDirectory },
  ));
  const merged = parseJSON(await commandRunner(
    "docker", composeArguments(releaseDirectory, composeFile, configuration.overlayFile, ["config", "--format", "json"]),
    { cwd: releaseDirectory },
  ));
  const summary = validateMergedCompose(base, merged, { listener, role: configuration.role, version });
  const imageOutput = await commandRunner(
    "docker",
    ["image", "inspect", "--format", "{{.Id}}", ...contract.images.map((image) => `${image}:${version}`)],
    { cwd: releaseDirectory },
  );
  const imageIds = imageOutput.trim().split("\n").filter(Boolean);
  if (imageIds.length !== contract.images.length || imageIds.some((id) => !/^sha256:[a-f0-9]{64}$/.test(id))) {
    throw new Error("The exact release images are unavailable.");
  }
  return Object.freeze({ composeFile, summary, version });
}

async function loadProtectedConfiguration(filename, uid) {
  const resolved = path.resolve(filename);
  await validateDirectory(path.dirname(resolved), [0, uid], true);
  await validateProtectedFile(resolved, [0, uid], 64 * 1024);
  return validateActivationConfigurationValue(JSON.parse(await readFile(resolved, "utf8")));
}

async function validateProtectedFile(filename, owners, maximumBytes) {
  const metadata = await lstat(filename);
  if (
    !metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 2 || metadata.size > maximumBytes ||
    (metadata.mode & 0o777) !== 0o600 || !owners.includes(metadata.uid) || await realpath(filename) !== filename
  ) {
    throw new Error("A protected production release activation file failed validation.");
  }
}

async function validateDirectory(directory, owners, exactPrivateMode) {
  const metadata = await lstat(directory);
  const mode = metadata.mode & 0o777;
  if (
    !metadata.isDirectory() || metadata.isSymbolicLink() || await realpath(directory) !== directory ||
    !owners.includes(metadata.uid) || (exactPrivateMode ? mode !== 0o700 : Boolean(mode & 0o022))
  ) {
    throw new Error("A production release activation directory failed validation.");
  }
}

async function validateSourceFile(filename, owners, maximumBytes) {
  const metadata = await lstat(filename);
  if (
    !metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 2 || metadata.size > maximumBytes ||
    !owners.includes(metadata.uid) || Boolean(metadata.mode & 0o022) || await realpath(filename) !== filename
  ) {
    throw new Error("A candidate release source file failed validation.");
  }
}

async function validateCandidateOverlay(candidateOverlay, protectedOverlay) {
  try {
    const metadata = await lstat(candidateOverlay);
    if (!metadata.isSymbolicLink() || await realpath(candidateOverlay) !== await realpath(protectedOverlay)) {
      throw new Error("The candidate release contains an unapproved live Compose overlay.");
    }
    return false;
  } catch (error) {
    if (error?.code === "ENOENT") return true;
    throw error;
  }
}

async function validateRollbackOverlay(rollbackOverlay, protectedOverlay, protectedOverlaySource, releaseOwners) {
  const metadata = await lstat(rollbackOverlay);
  if (metadata.isSymbolicLink()) {
    if (await realpath(rollbackOverlay) !== await realpath(protectedOverlay)) {
      throw new Error("The rollback release uses a different protected overlay.");
    }
    return;
  }
  await validateProtectedFile(rollbackOverlay, releaseOwners, 4096);
  if (await readFile(rollbackOverlay, "utf8") !== protectedOverlaySource) {
    throw new Error("The rollback release live overlay does not match the protected overlay.");
  }
}

async function validateCurrentLink(currentLink, releaseRoot, releaseOwners) {
  try {
    const metadata = await lstat(currentLink);
    if (!metadata.isSymbolicLink()) throw new Error("The current release selector is not a symbolic link.");
    const target = await realpath(currentLink);
    if (path.dirname(target) !== releaseRoot) throw new Error("The current release is outside the configured release root.");
    await validateDirectory(target, releaseOwners, false);
    return target;
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

async function pointCurrent(currentLink, target) {
  const temporary = path.join(path.dirname(currentLink), `.vasi-current-${randomUUID()}`);
  await symlink(target, temporary);
  try {
    await rename(temporary, currentLink);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

async function restoreCurrent(currentLink, previousTarget) {
  if (previousTarget) await pointCurrent(currentLink, previousTarget);
  else await rm(currentLink, { force: true });
}

async function reconcile(prepared, commandRunner) {
  const composeFile = path.join(prepared.candidate, prepared.contract.composeFile);
  await commandRunner(
    "docker",
    composeArguments(prepared.candidate, composeFile, prepared.configuration.overlayFile, [
      "up", "-d", "--no-build", "--wait", "--wait-timeout", "120", ...prepared.contract.runtimeServices,
    ]),
    { cwd: prepared.candidate },
  );
}

async function verifyRunningServices(prepared, commandRunner) {
  const output = await commandRunner(
    "docker",
    composeArguments(prepared.candidate, prepared.composeFile, prepared.configuration.overlayFile, ["ps", "--format", "json"]),
    { cwd: prepared.candidate },
  );
  const rows = parseJSONLines(output);
  const byService = new Map(rows.map((row) => [row.Service, row]));
  if (rows.length !== prepared.contract.runtimeServices.length || byService.size !== prepared.contract.runtimeServices.length) {
    throw new Error("The reconciled runtime service inventory is invalid.");
  }
  for (const service of prepared.contract.runtimeServices) {
    const row = byService.get(service);
    const image = `${prepared.contract.runtimeImages[service]}:${prepared.version}`;
    if (!row || row.Image !== image || row.State !== "running" || (row.Health && row.Health !== "healthy")) {
      throw new Error("A reconciled runtime service failed readiness validation.");
    }
  }
}

async function stopRuntime(prepared, commandRunner) {
  await commandRunner(
    "docker",
    composeArguments(prepared.candidate, prepared.composeFile, prepared.configuration.overlayFile, [
      "stop", "--timeout", "30", ...prepared.contract.runtimeServices,
    ]),
    { cwd: prepared.candidate },
  );
}

function composeArguments(projectDirectory, composeFile, overlayFile, command) {
  return [
    "compose", "--project-directory", projectDirectory,
    "-f", composeFile,
    ...(overlayFile ? ["-f", overlayFile] : []),
    ...command,
  ];
}

function activationResult(prepared, status) {
  return Object.freeze({
    images: prepared.summary.images,
    role: prepared.configuration.role,
    schema: ACTIVATION_SCHEMA,
    services: prepared.summary.services,
    status,
    version: prepared.version,
  });
}

function assertPort(value, expected) {
  if (!Array.isArray(value) || value.length !== 1 || !isPlainRecord(value[0])) {
    throw new Error("The rendered Compose listener is invalid.");
  }
  const port = value[0];
  if (
    port.host_ip !== expected.host || Number(port.published) !== expected.hostPort ||
    Number(port.target) !== expected.containerPort || port.protocol !== "tcp"
  ) {
    throw new Error("The rendered Compose listener does not match the protected contract.");
  }
}

function validateRuntimeHardening(service) {
  if (
    !isPlainRecord(service) || service.read_only !== true || service.privileged === true ||
    service.network_mode === "host" || !Array.isArray(service.cap_drop) || !service.cap_drop.includes("ALL") ||
    !Array.isArray(service.security_opt) || !service.security_opt.includes("no-new-privileges:true") ||
    JSON.stringify(service.volumes || []).includes("docker.sock")
  ) {
    throw new Error("The rendered Compose runtime hardening is invalid.");
  }
}

function boundedPort(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > 65535) throw new Error("The protected Compose port is invalid.");
  return number;
}

function isApprovedListenerIPv4(value) {
  const parts = value.split(".").map(Number);
  return value === "127.0.0.1" || parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168);
}

function isWithin(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function isPlainRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function uniqueNumbers(values) {
  return [...new Set(values)];
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isPlainRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function parseJSON(value) {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error("Docker Compose returned malformed configuration data.");
  }
}

function parseJSONLines(value) {
  const trimmed = value.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("[")) {
    const parsed = parseJSON(trimmed);
    if (!Array.isArray(parsed) || parsed.some((row) => !isPlainRecord(row))) throw new Error("Docker Compose returned malformed runtime data.");
    return parsed;
  }
  try {
    const parsed = trimmed.split("\n").map((line) => JSON.parse(line));
    if (parsed.some((row) => !isPlainRecord(row))) throw new Error("malformed");
    return parsed;
  } catch {
    throw new Error("Docker Compose returned malformed runtime data.");
  }
}

async function runBounded(command, argumentsList, { cwd, maximumBytes = 4 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, argumentsList, {
      cwd,
      env: dockerEnvironment(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks = [];
    let bytes = 0;
    const collect = (chunk) => {
      bytes += chunk.length;
      if (bytes > maximumBytes) child.kill("SIGKILL");
      else chunks.push(chunk);
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.once("error", reject);
    child.once("exit", (code) => {
      if (bytes > maximumBytes) reject(new Error("A production activation command exceeded its output bound."));
      else if (code !== 0) reject(new Error("A production activation command failed."));
      else resolve(Buffer.concat(chunks).toString("utf8"));
    });
  });
}

function dockerEnvironment() {
  return Object.fromEntries(
    ["PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR"]
      .filter((name) => typeof process.env[name] === "string")
      .map((name) => [name, process.env[name]]),
  );
}

function usage() {
  console.error("Usage: node scripts/activate-production-release.mjs CONFIG_FILE RELEASE_ID [--dry-run]");
  process.exitCode = 1;
}

async function main(argumentsList) {
  const [configurationFile, releaseId, option, ...extra] = argumentsList;
  if (!configurationFile || !releaseId || extra.length || (option && option !== "--dry-run")) return usage();
  try {
    const result = await activateProductionRelease(configurationFile, releaseId, { dryRun: option === "--dry-run" });
    console.info(JSON.stringify(result));
  } catch {
    console.error("VASI production release activation failed closed.");
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
