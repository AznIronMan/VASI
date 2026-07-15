import { access, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import { isDirectExecution } from "./direct-execution.mjs";

export const ENGINE_HOST_RUNTIME_SCHEMA = "vasi-engine-host-runtime/v1";

export class EngineHostRuntimeError extends Error {
  constructor(code) {
    super("The VASI engine host runtime is not ready.");
    this.code = code;
  }
}

export async function verifyEngineHostRuntime({
  importSettingsCore = defaultImportSettingsCore,
  nodeVersion = process.versions.node,
  pathExists = defaultPathExists,
  readText = (filename) => readFile(filename, "utf8"),
  rootDirectory = process.cwd(),
} = {}) {
  const root = path.resolve(rootDirectory);
  const packageJSON = await readJSON(path.join(root, "package.json"), readText, "manifest_invalid");
  const packageLock = await readJSON(path.join(root, "package-lock.json"), readText, "lockfile_invalid");
  const minimumNodeMajor = requiredNodeMajor(packageJSON?.engines?.node);
  const actualNodeMajor = nodeMajor(nodeVersion);
  if (actualNodeMajor < minimumNodeMajor) fail("node_unsupported");

  const dependencies = validatedDependencies(packageJSON?.dependencies);
  const developmentDependencies = validatedDependencies(packageJSON?.devDependencies, {
    allowEmpty: true,
    maximum: 128,
  });
  const lockedRoot = packageLock?.packages?.[""];
  if (
    packageLock?.lockfileVersion !== 3 ||
    lockedRoot?.name !== packageJSON?.name ||
    lockedRoot?.version !== packageJSON?.version ||
    !sameObject(lockedRoot?.dependencies, dependencies) ||
    !sameObject(lockedRoot?.devDependencies, developmentDependencies)
  ) {
    fail("manifest_lock_drift");
  }

  const lockPackages = Object.entries(packageLock.packages || {});
  if (!lockPackages.length || lockPackages.length > 10_000) fail("lockfile_invalid");
  const excludedPackagePaths = new Set(
    Object.keys(developmentDependencies)
      .filter((name) => !Object.hasOwn(dependencies, name))
      .map((name) => `node_modules/${name}`),
  );
  for (const [packagePath, locked] of lockPackages) {
    if (!packagePath.startsWith("node_modules/")) continue;
    if (!validLockPackagePath(packagePath)) fail("lockfile_invalid");
    if (
      locked && typeof locked === "object" &&
      (locked.dev === true || locked.devOptional === true || locked.optional === true) &&
      !Object.hasOwn(dependencies, packagePath.slice("node_modules/".length))
    ) {
      excludedPackagePaths.add(packagePath);
    }
  }
  for (const packagePath of excludedPackagePaths) {
    let present;
    try {
      present = await pathExists(path.join(root, packagePath, "package.json"));
    } catch {
      fail("dependency_inventory_unavailable");
    }
    if (present) fail("nonproduction_dependency_present");
  }

  for (const [name, expectedVersion] of Object.entries(dependencies).sort(([left], [right]) =>
    left.localeCompare(right)
  )) {
    if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(expectedVersion)) {
      fail("dependency_not_pinned");
    }
    const locked = packageLock.packages?.[`node_modules/${name}`];
    if (
      locked?.version !== expectedVersion ||
      typeof locked?.integrity !== "string" ||
      !locked.integrity.startsWith("sha512-")
    ) {
      fail("manifest_lock_drift");
    }
    let installed;
    try {
      installed = JSON.parse(await readText(path.join(root, "node_modules", name, "package.json")));
    } catch {
      fail("production_dependency_missing");
    }
    if (installed?.name !== name || installed?.version !== expectedVersion) {
      fail("production_dependency_mismatch");
    }
  }

  let settingsCore;
  try {
    settingsCore = await importSettingsCore(root);
  } catch {
    fail("settings_runtime_unavailable");
  }
  if (
    typeof settingsCore?.loadBootstrapSettings !== "function" ||
    typeof settingsCore?.readRuntimeSettings !== "function"
  ) {
    fail("settings_runtime_unavailable");
  }

  return Object.freeze({
    dependencies: Object.keys(dependencies).length,
    nodeMajor: actualNodeMajor,
    schema: ENGINE_HOST_RUNTIME_SCHEMA,
    status: "ready",
    version: packageJSON.version,
  });
}

export function engineHostRuntimeFailure(error) {
  return Object.freeze({
    reason: error instanceof EngineHostRuntimeError ? error.code : "host_runtime_invalid",
    schema: ENGINE_HOST_RUNTIME_SCHEMA,
    status: "critical",
  });
}

function validatedDependencies(value, { allowEmpty = false, maximum = 64 } = {}) {
  if (!value || Array.isArray(value) || typeof value !== "object") fail("manifest_invalid");
  const entries = Object.entries(value);
  if ((!allowEmpty && !entries.length) || entries.length > maximum) fail("manifest_invalid");
  for (const [name, version] of entries) {
    if (!/^(?:@[a-z0-9][a-z0-9._-]{0,63}\/)?[a-z0-9][a-z0-9._-]{0,127}$/.test(name)) {
      fail("manifest_invalid");
    }
    if (typeof version !== "string" || version.length > 64) fail("manifest_invalid");
  }
  return Object.fromEntries(entries);
}

function validLockPackagePath(value) {
  const name = "(?:@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,127}";
  return new RegExp(`^node_modules/${name}(?:/node_modules/${name})*$`).test(value);
}

function requiredNodeMajor(value) {
  const match = /^>=([1-9][0-9]*)\.0\.0$/.exec(String(value || ""));
  if (!match) fail("manifest_invalid");
  return Number(match[1]);
}

function nodeMajor(value) {
  const match = /^([1-9][0-9]*)\./.exec(String(value || ""));
  if (!match) fail("node_unsupported");
  return Number(match[1]);
}

function sameObject(left, right) {
  if (!left || Array.isArray(left) || typeof left !== "object") return false;
  const leftEntries = Object.entries(left).sort(([a], [b]) => a.localeCompare(b));
  const rightEntries = Object.entries(right).sort(([a], [b]) => a.localeCompare(b));
  return JSON.stringify(leftEntries) === JSON.stringify(rightEntries);
}

async function readJSON(filename, readText, code) {
  try {
    return JSON.parse(await readText(filename));
  } catch {
    fail(code);
  }
}

async function defaultImportSettingsCore(root) {
  return import(pathToFileURL(path.join(root, "scripts", "settings-core.mjs")).href);
}

async function defaultPathExists(filename) {
  try {
    await access(filename);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function fail(code) {
  throw new EngineHostRuntimeError(code);
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  verifyEngineHostRuntime()
    .then((result) => console.info(JSON.stringify(result)))
    .catch((error) => {
      console.error(JSON.stringify(engineHostRuntimeFailure(error)));
      process.exitCode = 1;
    });
}
