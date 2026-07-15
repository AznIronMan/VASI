import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  inspectTrackedSource,
  runtimeDependencyAuditPaths,
  runtimeContractForImage,
  validateAutomationContract,
  validateComposeContracts,
  validateEngineHostRuntimeContract,
  validateOperationalSchedulerContract,
  validateRuntimeImageBuildContract,
  validateVersionAlignment,
} from "./release-assurance.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("release assurance policy", () => {
  it("keeps private/runtime material out of tracked source", async () => {
    const result = await inspectTrackedSource(root);
    expect(result.forbiddenPaths).toEqual([]);
    expect(result.secretFindings).toEqual([]);
    expect(result.unboundedGatewayJSONParsers).toEqual([]);
    expect(result.files.length).toBeGreaterThan(100);
  });

  it("aligns all authoritative version declarations", async () => {
    const result = await validateVersionAlignment(root);
    expect(result.mismatches).toEqual([]);
  });

  it("keeps public and private runtime services hardened", async () => {
    const result = await validateComposeContracts(root);
    expect(result.failures).toEqual([]);
    expect(result.servicesChecked).toContain("gateway.capacity");
    expect(result.servicesChecked).toContain("engine.capacity");
    expect(result.servicesChecked).toContain("engine.database-gateway");
    expect(result.servicesChecked).toContain("engine.egress-policy");
  });

  it("keeps release automation least-privileged and commit-pinned", async () => {
    const result = await validateAutomationContract(root);
    expect(result.failures).toEqual([]);
    expect(result.jobs).toBeGreaterThan(0);
    expect(result.releaseImagesChecked).toEqual([
      "vasi",
      "vasi-database-gateway",
      "vasi-engine",
      "vasi-engine-maintenance",
      "vasi-engine-tools",
      "vasi-settings",
    ]);
  });

  it("packages every persistent least-privileged operational scheduler", async () => {
    const result = await validateOperationalSchedulerContract(root);
    expect(result.failures).toEqual([]);
    expect(result.unitsChecked).toHaveLength(24);
    expect(result.unitsChecked).toContain("vasi-engine-operational-readiness.timer");
    expect(result.unitsChecked).toContain("vasi-gateway-operational-readiness.timer");
    expect(result.unitsChecked).toContain("vasi-gateway-backup-check.timer");
  });

  it("keeps the direct engine host runtime exact and lifecycle-script-free", async () => {
    const result = await validateEngineHostRuntimeContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 3 });
  });

  it("keeps every production image dependency stage exact and minimized", async () => {
    const result = await validateRuntimeImageBuildContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 2 });
  });

  it("rejects weakened production image dependency installation or pruning", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-image-build-assurance-"));
    try {
      await cp(path.join(root, "Dockerfile"), path.join(fixture, "Dockerfile"));
      await cp(path.join(root, "Dockerfile.engine"), path.join(fixture, "Dockerfile.engine"));
      const gateway = path.join(fixture, "Dockerfile");
      const engine = path.join(fixture, "Dockerfile.engine");
      await writeFile(
        gateway,
        (await readFile(gateway, "utf8"))
          .replace(" --omit=optional --ignore-scripts --no-audit --no-fund", "")
          .replace("RUN rm -rf /app/node_modules/pg-cloudflare\n", ""),
      );
      await writeFile(
        engine,
        (await readFile(engine, "utf8")).replace("--ignore-scripts", "--foreground-scripts"),
      );
      const result = await validateRuntimeImageBuildContract(fixture);
      expect(result.failures).toContain(
        "Dockerfile production-dependencies must use the exact production dependency install",
      );
      expect(result.failures).toContain(
        "Dockerfile.engine dependencies must use the exact production dependency install",
      );
      expect(result.failures).toContain(
        "Dockerfile must remove the unrelated standalone optional dependency before USER node",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects a weakened engine host runtime preparation contract", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-host-runtime-assurance-"));
    try {
      await mkdir(path.join(fixture, "scripts"));
      await cp(
        path.join(root, "scripts", "prepare-engine-host-runtime.sh"),
        path.join(fixture, "scripts", "prepare-engine-host-runtime.sh"),
      );
      await cp(
        path.join(root, "scripts", "verify-engine-host-runtime.mjs"),
        path.join(fixture, "scripts", "verify-engine-host-runtime.mjs"),
      );
      const packageSource = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
      packageSource.scripts["host:prepare:engine"] = "npm install";
      await writeFile(path.join(fixture, "package.json"), JSON.stringify(packageSource));
      const preparation = path.join(fixture, "scripts", "prepare-engine-host-runtime.sh");
      await writeFile(
        preparation,
        (await readFile(preparation, "utf8")).replace("--ignore-scripts", "--foreground-scripts"),
      );
      const result = await validateEngineHostRuntimeContract(fixture);
      expect(result.failures).toContain(
        "engine host runtime preparation weakens exact production installation",
      );
      expect(result.failures).toContain(
        "package.json is missing the exact engine host runtime preparation command",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects weakened or installation-specific scheduler state", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-systemd-assurance-"));
    try {
      await cp(path.join(root, "deployment"), path.join(fixture, "deployment"), { recursive: true });
      const timer = path.join(fixture, "deployment", "systemd", "vasi-engine-operational-readiness.timer");
      await writeFile(timer, (await readFile(timer, "utf8")).replace("Persistent=yes", "Persistent=no"));
      const service = path.join(fixture, "deployment", "systemd", "vasi-gateway-backup-create.service");
      await writeFile(service, `${await readFile(service, "utf8")}\nEnvironmentFile=/home/customer/.env\n`);
      const nodeService = path.join(
        fixture,
        "deployment",
        "systemd",
        "vasi-engine-deployment-readiness.service",
      );
      await writeFile(
        nodeService,
        `${(await readFile(nodeService, "utf8")).replace(
          "ExecStartPre=/usr/bin/env node /usr/local/libexec/vasi/verify-engine-host-runtime.mjs\n",
          "",
        )}\nMemoryDenyWriteExecute=yes\n`,
      );
      const result = await validateOperationalSchedulerContract(fixture);
      expect(result.failures).toContain("vasi-engine-operational-readiness.timer is missing Persistent=yes");
      expect(result.failures).toContain(
        "vasi-gateway-backup-create.service contains a prohibited privilege or configuration path",
      );
      expect(result.failures).toContain(
        "vasi-engine-deployment-readiness.service cannot deny executable memory to the direct Node runtime",
      );
      expect(result.failures).toContain(
        "vasi-engine-deployment-readiness.service is missing ExecStartPre=/usr/bin/env node /usr/local/libexec/vasi/verify-engine-host-runtime.mjs",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("requires an explicit non-root readability contract for every release image role", () => {
    expect(runtimeContractForImage("vasi:0.37.0")).toMatchObject({
      allowedOptionalPackagePaths: [
        "node_modules/@img/colour",
        "node_modules/@img/sharp-libvips-linuxmusl-x64",
        "node_modules/@img/sharp-linuxmusl-x64",
        "node_modules/detect-libc",
        "node_modules/semver",
        "node_modules/sharp",
      ],
      entrypoints: ["server.js"],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage("registry.example.test/vasi-engine:0.37.0")).toMatchObject({
      entrypoints: [
        "scripts/engine-migrate.mjs",
        "services/engine/server.mjs",
        "services/integration-gateway/server.mjs",
        "services/private-ingress/server.mjs",
        "services/worker/worker.mjs",
      ],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage(`vasi-engine-tools@sha256:${"a".repeat(64)}`)).toMatchObject({
      entrypoints: [
        "scripts/probe-engine-egress-boundary.mjs",
        "scripts/render-database-egress-policy.mjs",
        "scripts/render-private-ingress-egress-policy.mjs",
        "scripts/settings.mjs",
      ],
      imageUser: "",
      runUser: "0:0",
    });
    expect(runtimeContractForImage("vasi-engine-maintenance:0.37.0")).toMatchObject({
      entrypoints: [
        "scripts/backup-custody.mjs",
        "scripts/backup-continuity.mjs",
        "scripts/backup.mjs",
        "scripts/probe-capacity-readiness.mjs",
        "scripts/probe-deployment-readiness.mjs",
        "scripts/probe-gateway-operational-readiness.mjs",
        "scripts/probe-operational-readiness.mjs",
        "scripts/tenant-transfer.mjs",
      ],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage("vasi-database-gateway:0.37.0")).toMatchObject({
      entrypoints: ["services/database-gateway/server.mjs"],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(() => runtimeContractForImage("unreviewed-image:latest")).toThrow(/no supported runtime contract/i);
    expect(() => runtimeContractForImage("vasi:latest", [{
      entrypoints: ["../server.js"],
      image: "vasi",
      imageUser: "node",
      runUser: "1000:1000",
    }])).toThrow(/no supported runtime contract/i);
  });

  it("derives a bounded physical prohibition inventory from the exact lock graph", async () => {
    const packageJSON = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
    const packageLock = JSON.parse(await readFile(path.join(root, "package-lock.json"), "utf8"));
    const allowed = runtimeContractForImage("vasi:0.37.0").allowedOptionalPackagePaths;
    const result = runtimeDependencyAuditPaths(packageJSON, packageLock, allowed);
    expect(result.lockPackageCount).toBeGreaterThan(400);
    expect(result.prohibitedPackagePaths).toContain("node_modules/vitest");
    expect(result.prohibitedPackagePaths).toContain("node_modules/vite");
    expect(result.prohibitedPackagePaths).toContain("node_modules/pg-cloudflare");
    expect(result.prohibitedPackagePaths).not.toContain("node_modules/sharp");
    expect(result.prohibitedToolPaths).toContain("/usr/local/bin/npm");
    expect(result.prohibitedToolPaths).toContain("/usr/local/bin/npx");
    expect(() => runtimeDependencyAuditPaths(
      packageJSON,
      packageLock,
      ["node_modules/not-a-reviewed-optional-package"],
    )).toThrow(/unsupported optional-package exception/i);
  });

  it("rejects unsafe, malformed, and unbounded dependency inventories", () => {
    const packageJSON = {
      dependencies: { pg: "8.22.0" },
      devDependencies: { vitest: "4.1.10" },
    };
    const valid = {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/pg": {},
        "node_modules/vitest": { dev: true },
      },
    };
    expect(runtimeDependencyAuditPaths(packageJSON, valid).prohibitedPackagePaths).toEqual([
      "node_modules/vitest",
    ]);
    expect(() => runtimeDependencyAuditPaths(packageJSON, {
      ...valid,
      packages: { ...valid.packages, "node_modules/../escape": { dev: true } },
    })).toThrow(/unsafe package-lock path/i);
    expect(() => runtimeDependencyAuditPaths(packageJSON, {
      ...valid,
      packages: { ...valid.packages, "node_modules/bad": { optional: "yes" } },
    })).toThrow(/malformed package-lock flags/i);
    expect(() => runtimeDependencyAuditPaths(packageJSON, {
      ...valid,
      packages: Object.fromEntries([
        ["", {}],
        ...Array.from({ length: 10000 }, (_, index) => [
          `node_modules/package-${index}`,
          { dev: true },
        ]),
      ]),
    })).toThrow(/outside its assurance bound/i);
  });
});
