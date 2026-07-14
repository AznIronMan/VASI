import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  inspectTrackedSource,
  runtimeContractForImage,
  validateAutomationContract,
  validateComposeContracts,
  validateOperationalSchedulerContract,
  validateVersionAlignment,
} from "./release-assurance.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("release assurance policy", () => {
  it("keeps private/runtime material out of tracked source", async () => {
    const result = await inspectTrackedSource(root);
    expect(result.forbiddenPaths).toEqual([]);
    expect(result.secretFindings).toEqual([]);
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
    expect(result.unitsChecked).toHaveLength(22);
    expect(result.unitsChecked).toContain("vasi-engine-operational-readiness.timer");
    expect(result.unitsChecked).toContain("vasi-gateway-backup-check.timer");
  });

  it("rejects weakened or installation-specific scheduler state", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-systemd-assurance-"));
    try {
      await cp(path.join(root, "deployment"), path.join(fixture, "deployment"), { recursive: true });
      const timer = path.join(fixture, "deployment", "systemd", "vasi-engine-operational-readiness.timer");
      await writeFile(timer, (await readFile(timer, "utf8")).replace("Persistent=yes", "Persistent=no"));
      const service = path.join(fixture, "deployment", "systemd", "vasi-gateway-backup-create.service");
      await writeFile(service, `${await readFile(service, "utf8")}\nEnvironmentFile=/home/customer/.env\n`);
      const result = await validateOperationalSchedulerContract(fixture);
      expect(result.failures).toContain("vasi-engine-operational-readiness.timer is missing Persistent=yes");
      expect(result.failures).toContain(
        "vasi-gateway-backup-create.service contains a prohibited privilege or configuration path",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("requires an explicit non-root readability contract for every release image role", () => {
    expect(runtimeContractForImage("vasi:0.24.0")).toMatchObject({
      entrypoints: ["server.js"],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage("registry.example.test/vasi-engine:0.24.0")).toMatchObject({
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
    expect(runtimeContractForImage("vasi-engine-maintenance:0.24.0")).toMatchObject({
      entrypoints: [
        "scripts/backup-continuity.mjs",
        "scripts/backup.mjs",
        "scripts/probe-capacity-readiness.mjs",
        "scripts/probe-deployment-readiness.mjs",
        "scripts/probe-operational-readiness.mjs",
        "scripts/tenant-transfer.mjs",
      ],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage("vasi-database-gateway:0.24.0")).toMatchObject({
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
