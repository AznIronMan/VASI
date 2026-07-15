import { chmod, lstat, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  activateProductionRelease,
  parseProtectedOverlay,
  validateActivationConfigurationValue,
  validateMergedCompose,
} from "./activate-production-release.mjs";

const roots = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("fail-closed production release activation", () => {
  it("accepts only the exact role listener overlay on an RFC1918 address", () => {
    expect(parseProtectedOverlay(overlay("gateway"), "gateway")).toEqual({
      containerPort: 3000,
      host: "10.0.0.10",
      hostPort: 14443,
      service: "app",
    });
    expect(parseProtectedOverlay(overlay("engine"), "engine")).toEqual({
      containerPort: 8443,
      host: "10.0.0.11",
      hostPort: 11121,
      service: "private-ingress",
    });
    expect(parseProtectedOverlay(overlay("gateway").replace("10.0.0.10", "127.0.0.1"), "gateway").host)
      .toBe("127.0.0.1");
    for (const source of [
      overlay("gateway").replace("10.0.0.10", "0.0.0.0"),
      overlay("gateway").replace("10.0.0.10", "127.0.0.2"),
      overlay("gateway").replace("10.0.0.10", "203.0.113.10"),
      overlay("gateway").replace("3000", "3001"),
      `${overlay("gateway")}    environment:\n      SECRET: exposed\n`,
      overlay("gateway").replace("app", "worker"),
      overlay("gateway").replace("ports: !override", "ports:"),
    ]) expect(() => parseProtectedOverlay(source, "gateway")).toThrow();
  });

  it("rejects unknown, relative, and overlapping activation configuration", () => {
    const valid = configuration("gateway");
    expect(validateActivationConfigurationValue(valid)).toEqual(valid);
    expect(() => validateActivationConfigurationValue({ ...valid, unknown: true })).toThrow("fields");
    expect(() => validateActivationConfigurationValue({ ...valid, currentLink: "current" })).toThrow("currentLink");
    expect(() => validateActivationConfigurationValue({ ...valid, releaseOwnerUid: -1 })).toThrow("releaseOwnerUid");
    expect(() => validateActivationConfigurationValue({ ...valid, dataRoot: `${valid.releaseRoot}/data` })).toThrow("overlap");
    expect(() => validateActivationConfigurationValue({ ...valid, currentLink: `${valid.releaseRoot}/current` })).toThrow("overlap");
  });

  it("allows exactly one listener replacement and preserves runtime hardening", () => {
    const base = composeModel("engine", "0.47.0");
    const merged = structuredClone(base);
    merged.services["private-ingress"].ports = [port("10.0.0.11", 11121, 8443)];
    expect(validateMergedCompose(base, merged, {
      listener: parseProtectedOverlay(overlay("engine"), "engine"),
      role: "engine",
      version: "0.47.0",
    })).toEqual({ images: 4, services: 5 });

    const environmentDrift = structuredClone(merged);
    environmentDrift.services.engine.environment = ["SECRET=value"];
    expect(() => validateMergedCompose(base, environmentDrift, {
      listener: parseProtectedOverlay(overlay("engine"), "engine"), role: "engine", version: "0.47.0",
    })).toThrow("more than");
    const weakened = structuredClone(merged);
    weakened.services.worker.read_only = false;
    expect(() => validateMergedCompose(base, weakened, {
      listener: parseProtectedOverlay(overlay("engine"), "engine"), role: "engine", version: "0.47.0",
    })).toThrow();
    const wrongProject = structuredClone(merged);
    wrongProject.name = "other-project";
    expect(() => validateMergedCompose(base, wrongProject, {
      listener: parseProtectedOverlay(overlay("engine"), "engine"), role: "engine", version: "0.47.0",
    })).toThrow("project identity");
  });

  it("dry-runs without changing the selector, overlay link, or Docker runtime", async () => {
    const fixture = await activationFixture("gateway");
    const runner = commandRunner("gateway");
    const result = await activateProductionRelease(fixture.configurationFile, fixture.releaseId, {
      commandRunner: runner.run,
      dryRun: true,
      scriptRoot: fixture.candidate,
      uid: process.getuid(),
    });
    expect(result).toEqual({
      images: 3,
      role: "gateway",
      schema: "vasi-production-release-activation/v1",
      services: 1,
      status: "ready",
      version: "0.47.0",
    });
    expect(await realpath(fixture.currentLink)).toBe(fixture.previous);
    await expect(lstat(path.join(fixture.candidate, "compose.live.yaml"))).rejects.toMatchObject({ code: "ENOENT" });
    expect(runner.calls.some((call) => call.argumentsList.includes("up"))).toBe(false);
  });

  it("allows the selected trusted release to drive an upgrade or rollback", async () => {
    const fixture = await activationFixture("gateway");
    const result = await activateProductionRelease(fixture.configurationFile, fixture.releaseId, {
      commandRunner: commandRunner("gateway").run,
      dryRun: true,
      scriptRoot: fixture.previous,
      uid: process.getuid(),
    });
    expect(result.status).toBe("ready");
    expect(await realpath(fixture.currentLink)).toBe(fixture.previous);
    await expect(lstat(path.join(fixture.candidate, "compose.live.yaml"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("atomically activates the complete merged project without orphan removal", async () => {
    const fixture = await activationFixture("engine");
    const runner = commandRunner("engine");
    const result = await activateProductionRelease(fixture.configurationFile, fixture.releaseId, {
      commandRunner: runner.run,
      scriptRoot: fixture.candidate,
      uid: process.getuid(),
    });
    expect(result.status).toBe("activated");
    expect(await realpath(fixture.currentLink)).toBe(fixture.candidate);
    expect(await realpath(path.join(fixture.candidate, "compose.live.yaml"))).toBe(fixture.overlayFile);
    const activation = runner.calls.find((call) => call.argumentsList.includes("up"));
    expect(activation.argumentsList).toContain("--no-build");
    expect(activation.argumentsList).toContain("--wait");
    expect(runner.calls.flatMap((call) => call.argumentsList)).not.toContain("--remove-orphans");
    await expect(lstat(`${fixture.currentLink}.activation-lock`)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("restores the prior selector and runtime when candidate reconciliation fails", async () => {
    const fixture = await activationFixture("gateway");
    const runner = commandRunner("gateway", { failCandidateUp: fixture.candidate });
    await expect(activateProductionRelease(fixture.configurationFile, fixture.releaseId, {
      commandRunner: runner.run,
      scriptRoot: fixture.candidate,
      uid: process.getuid(),
    })).rejects.toThrow("reconciliation failed");
    expect(await realpath(fixture.currentLink)).toBe(fixture.previous);
    await expect(lstat(path.join(fixture.candidate, "compose.live.yaml"))).rejects.toMatchObject({ code: "ENOENT" });
    const upDirectories = runner.calls
      .filter((call) => call.argumentsList.includes("up"))
      .map((call) => call.argumentsList[call.argumentsList.indexOf("--project-directory") + 1]);
    expect(upDirectories).toEqual([fixture.candidate, fixture.previous]);
  });

  it("rejects duplicate runtime replicas and restores the selected release", async () => {
    const fixture = await activationFixture("gateway");
    const runner = commandRunner("gateway", { duplicateRuntimeRow: true });
    await expect(activateProductionRelease(fixture.configurationFile, fixture.releaseId, {
      commandRunner: runner.run,
      scriptRoot: fixture.candidate,
      uid: process.getuid(),
    })).rejects.toThrow("inventory");
    expect(await realpath(fixture.currentLink)).toBe(fixture.previous);
    expect(runner.calls.filter((call) => call.argumentsList.includes("up"))).toHaveLength(2);
  });

  it("stops a failed first activation when no prior release exists", async () => {
    const fixture = await activationFixture("engine");
    await rm(fixture.currentLink);
    const runner = commandRunner("engine", { failCandidateUp: fixture.candidate });
    await expect(activateProductionRelease(fixture.configurationFile, fixture.releaseId, {
      commandRunner: runner.run,
      scriptRoot: fixture.candidate,
      uid: process.getuid(),
    })).rejects.toThrow("reconciliation failed");
    await expect(lstat(fixture.currentLink)).rejects.toMatchObject({ code: "ENOENT" });
    expect(runner.calls.some((call) => call.argumentsList.includes("stop"))).toBe(true);
  });

  it("refuses cutover when the selected rollback release is not exact", async () => {
    const fixture = await activationFixture("gateway");
    await writeFile(path.join(fixture.previous, "compose.live.yaml"), `${overlay("gateway")}# drift\n`);
    await expect(activateProductionRelease(fixture.configurationFile, fixture.releaseId, {
      commandRunner: commandRunner("gateway").run,
      dryRun: true,
      scriptRoot: fixture.candidate,
      uid: process.getuid(),
    })).rejects.toThrow("rollback release is not ready");
    expect(await realpath(fixture.currentLink)).toBe(fixture.previous);
  });

  it("rejects loose protected files and an incorrect shared data binding", async () => {
    const fixture = await activationFixture("gateway");
    await chmod(fixture.configurationFile, 0o644);
    await expect(activateProductionRelease(fixture.configurationFile, fixture.releaseId, {
      commandRunner: commandRunner("gateway").run,
      dryRun: true,
      scriptRoot: fixture.candidate,
      uid: process.getuid(),
    })).rejects.toThrow("protected");
    await chmod(fixture.configurationFile, 0o600);
    await rm(path.join(fixture.candidate, "data"));
    await symlink(fixture.previous, path.join(fixture.candidate, "data"));
    await expect(activateProductionRelease(fixture.configurationFile, fixture.releaseId, {
      commandRunner: commandRunner("gateway").run,
      dryRun: true,
      scriptRoot: fixture.candidate,
      uid: process.getuid(),
    })).rejects.toThrow("data binding");
  });
});

async function activationFixture(role) {
  const temporary = await mkdtemp(path.join(tmpdir(), "vasi-activation-"));
  const root = await realpath(temporary);
  roots.push(root);
  await chmod(root, 0o700);
  const installation = path.join(root, "installation");
  const releaseRoot = path.join(installation, "releases");
  const dataRoot = path.join(root, "data");
  const protectedRoot = path.join(root, "protected");
  await mkdir(installation, { mode: 0o700 });
  await mkdir(releaseRoot, { mode: 0o755 });
  await mkdir(dataRoot, { mode: 0o700 });
  await mkdir(protectedRoot, { mode: 0o700 });
  const previous = path.join(releaseRoot, "0.40.2-old");
  const releaseId = "0.47.0-candidate";
  const candidate = path.join(releaseRoot, releaseId);
  const composeFile = role === "gateway" ? "compose.production.yaml" : "compose.engine.yaml";
  for (const [directory, version] of [[previous, "0.40.2"], [candidate, "0.47.0"]]) {
    await mkdir(directory, { mode: 0o755 });
    await writeFile(path.join(directory, "package.json"), `${JSON.stringify({ version })}\n`, { mode: 0o644 });
    await writeFile(path.join(directory, composeFile), `name: vasi-${role}\nservices:\n`, { mode: 0o644 });
    await symlink(dataRoot, path.join(directory, "data"));
  }
  const currentLink = path.join(installation, "current");
  await symlink(previous, currentLink);
  const overlayFile = path.join(protectedRoot, `${role}.live.yaml`);
  await writeFile(overlayFile, overlay(role), { mode: 0o600 });
  await writeFile(path.join(previous, "compose.live.yaml"), overlay(role), { mode: 0o600 });
  const value = {
    currentLink,
    dataRoot,
    overlayFile,
    releaseOwnerUid: process.getuid(),
    releaseRoot,
    role,
    schema: "vasi-production-release-activation/v1",
  };
  const configurationFile = path.join(protectedRoot, `${role}.json`);
  await writeFile(configurationFile, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  return { candidate, configurationFile, currentLink, dataRoot, overlayFile, previous, releaseId, releaseRoot, root };
}

function commandRunner(role, { duplicateRuntimeRow = false, failCandidateUp } = {}) {
  const calls = [];
  const run = async (command, argumentsList, options) => {
    calls.push({ argumentsList: [...argumentsList], command, options });
    if (argumentsList[0] === "image") {
      const count = role === "gateway" ? 3 : 4;
      return Array.from({ length: count }, (_, index) => `sha256:${String(index + 1).repeat(64)}`).join("\n");
    }
    if (argumentsList.includes("config")) {
      const version = options.cwd.endsWith("0.40.2-old") ? "0.40.2" : "0.47.0";
      const model = composeModel(role, version);
      if (argumentsList.filter((argument) => argument === "-f").length === 2) {
        const service = role === "gateway" ? "app" : "private-ingress";
        model.services[service].ports = [role === "gateway"
          ? port("10.0.0.10", 14443, 3000)
          : port("10.0.0.11", 11121, 8443)];
      }
      return JSON.stringify(model);
    }
    if (argumentsList.includes("up")) {
      const directory = argumentsList[argumentsList.indexOf("--project-directory") + 1];
      if (directory === failCandidateUp) throw new Error("candidate reconciliation failed");
      return "";
    }
    if (argumentsList.includes("ps")) {
      const rows = runtimeRows(role, "0.47.0");
      if (duplicateRuntimeRow) rows.push({ ...rows[0] });
      return rows.map((row) => JSON.stringify(row)).join("\n");
    }
    if (argumentsList.includes("stop")) return "";
    throw new Error("Unexpected command in activation test.");
  };
  return { calls, run };
}

function overlay(role) {
  return role === "gateway"
    ? "services:\n  app:\n    ports: !override\n      - 10.0.0.10:14443:3000\n"
    : "services:\n  private-ingress:\n    ports: !override\n      - 10.0.0.11:11121:8443\n";
}

function configuration(role) {
  return {
    currentLink: `/opt/vasi-${role}/current`,
    dataRoot: `/var/lib/vasi-${role}/data`,
    overlayFile: `/var/lib/vasi-release/${role}.live.yaml`,
    releaseOwnerUid: 1000,
    releaseRoot: `/opt/vasi-${role}/releases`,
    role,
    schema: "vasi-production-release-activation/v1",
  };
}

function composeModel(role, version) {
  if (role === "gateway") {
    return {
      name: "vasi",
      services: {
        app: hardened("vasi", version, [port("127.0.0.1", 3000, 3000)]),
      },
    };
  }
  return {
    name: "vasi-engine",
    services: {
      "database-gateway": hardened("vasi-database-gateway", version),
      engine: hardened("vasi-engine", version),
      "integration-gateway": hardened("vasi-engine", version),
      "private-ingress": hardened("vasi-engine", version, [port("127.0.0.1", 11121, 8443)]),
      worker: hardened("vasi-engine", version),
    },
  };
}

function hardened(image, version, ports) {
  return {
    cap_drop: ["ALL"],
    image: `${image}:${version}`,
    read_only: true,
    security_opt: ["no-new-privileges:true"],
    ...(ports ? { ports } : {}),
  };
}

function port(host, published, target) {
  return { host_ip: host, mode: "ingress", protocol: "tcp", published: String(published), target };
}

function runtimeRows(role, version) {
  const images = role === "gateway"
    ? { app: "vasi" }
    : {
        "database-gateway": "vasi-database-gateway",
        engine: "vasi-engine",
        "integration-gateway": "vasi-engine",
        "private-ingress": "vasi-engine",
        worker: "vasi-engine",
      };
  return Object.entries(images).map(([Service, image]) => ({
    Health: ["app", "database-gateway", "engine", "integration-gateway"].includes(Service) ? "healthy" : "",
    Image: `${image}:${version}`,
    Service,
    State: "running",
  }));
}
