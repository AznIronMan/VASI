import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  engineHostRuntimeFailure,
  verifyEngineHostRuntime,
} from "./verify-engine-host-runtime.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoots = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("engine host runtime verification", () => {
  it("verifies the current exact production dependency and settings import contract", async () => {
    await expect(verifyEngineHostRuntime({
      pathExists: async () => false,
      rootDirectory: repositoryRoot,
    })).resolves.toMatchObject({
      dependencies: 7,
      nodeMajor: 24,
      schema: "vasi-engine-host-runtime/v1",
      status: "ready",
    });
  });

  it("accepts a pinned exact fixture without exposing its path", async () => {
    const root = await fixture();
    const result = await verifyEngineHostRuntime({
      importSettingsCore: async () => readySettingsCore(),
      nodeVersion: "24.1.0",
      rootDirectory: root,
    });
    expect(result).toEqual({
      dependencies: 1,
      nodeMajor: 24,
      schema: "vasi-engine-host-runtime/v1",
      status: "ready",
      version: "1.2.3",
    });
    expect(JSON.stringify(result)).not.toContain(root);
  });

  it("fails unsupported Node and package/lock drift with bounded reasons", async () => {
    const root = await fixture();
    await expect(verifyEngineHostRuntime({
      importSettingsCore: async () => readySettingsCore(),
      nodeVersion: "22.9.0",
      rootDirectory: root,
    })).rejects.toMatchObject({ code: "node_unsupported" });

    await writeFile(path.join(root, "package.json"), JSON.stringify(packageManifest("^8.22.0")));
    await expect(verifyEngineHostRuntime({
      importSettingsCore: async () => readySettingsCore(),
      rootDirectory: root,
    })).rejects.toMatchObject({ code: "manifest_lock_drift" });
  });

  it("distinguishes missing and mismatched installed production packages", async () => {
    const missing = await fixture({ installed: false });
    await expect(verifyEngineHostRuntime({
      importSettingsCore: async () => readySettingsCore(),
      rootDirectory: missing,
    })).rejects.toMatchObject({ code: "production_dependency_missing" });

    const mismatched = await fixture({ installedVersion: "8.21.0" });
    await expect(verifyEngineHostRuntime({
      importSettingsCore: async () => readySettingsCore(),
      rootDirectory: mismatched,
    })).rejects.toMatchObject({ code: "production_dependency_mismatch" });
  });

  it("rejects a physically present declared or lock-marked nonproduction package", async () => {
    const root = await fixture();
    const lockPath = path.join(root, "package-lock.json");
    const lock = JSON.parse(await readFile(lockPath, "utf8"));
    lock.packages[""].devDependencies = { vitest: "4.1.10" };
    lock.packages["node_modules/vitest"] = {
      devOptional: true,
      integrity: "sha512-fixture",
      version: "4.1.10",
    };
    await writeFile(lockPath, JSON.stringify(lock));
    const manifestPath = path.join(root, "package.json");
    const manifest = packageManifest("8.22.0");
    manifest.devDependencies = { vitest: "4.1.10" };
    await writeFile(manifestPath, JSON.stringify(manifest));
    await mkdir(path.join(root, "node_modules", "vitest"), { recursive: true });
    await writeFile(path.join(root, "node_modules", "vitest", "package.json"), JSON.stringify({
      name: "vitest",
      version: "4.1.10",
    }));
    await expect(verifyEngineHostRuntime({
      importSettingsCore: async () => readySettingsCore(),
      rootDirectory: root,
    })).rejects.toMatchObject({ code: "nonproduction_dependency_present" });
  });

  it("fails closed when the protected settings runtime cannot load", async () => {
    const root = await fixture();
    let caught;
    try {
      await verifyEngineHostRuntime({
        importSettingsCore: async () => { throw new Error(`sensitive ${root}`); },
        rootDirectory: root,
      });
    } catch (error) {
      caught = error;
    }
    expect(engineHostRuntimeFailure(caught)).toEqual({
      reason: "settings_runtime_unavailable",
      schema: "vasi-engine-host-runtime/v1",
      status: "critical",
    });
    expect(JSON.stringify(engineHostRuntimeFailure(caught))).not.toContain(root);
  });
});

async function fixture({ installed = true, installedVersion = "8.22.0" } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "vasi-engine-host-runtime-"));
  temporaryRoots.push(root);
  await mkdir(path.join(root, "scripts"), { recursive: true });
  await writeFile(path.join(root, "package.json"), JSON.stringify(packageManifest("8.22.0")));
  await writeFile(path.join(root, "package-lock.json"), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": {
        dependencies: { pg: "8.22.0" },
        devDependencies: {},
        name: "vasi-fixture",
        version: "1.2.3",
      },
      "node_modules/pg": {
        integrity: "sha512-fixture",
        version: "8.22.0",
      },
    },
  }));
  if (installed) {
    await mkdir(path.join(root, "node_modules", "pg"), { recursive: true });
    await writeFile(path.join(root, "node_modules", "pg", "package.json"), JSON.stringify({
      name: "pg",
      version: installedVersion,
    }));
  }
  return root;
}

function packageManifest(pgVersion) {
  return {
    dependencies: { pg: pgVersion },
    devDependencies: {},
    engines: { node: ">=24.0.0" },
    name: "vasi-fixture",
    version: "1.2.3",
  };
}

function readySettingsCore() {
  return {
    loadBootstrapSettings() {},
    readRuntimeSettings() {},
  };
}
