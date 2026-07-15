import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  inspectTrackedSource,
  runtimeContractForImage,
  validateAutomationContract,
  validateComposeContracts,
  validateEngineHostRuntimeContract,
  validateOperationalSchedulerContract,
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
    expect(runtimeContractForImage("vasi:0.36.2")).toMatchObject({
      entrypoints: ["server.js"],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage("registry.example.test/vasi-engine:0.36.2")).toMatchObject({
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
    expect(runtimeContractForImage("vasi-engine-maintenance:0.36.2")).toMatchObject({
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
    expect(runtimeContractForImage("vasi-database-gateway:0.36.2")).toMatchObject({
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
});
