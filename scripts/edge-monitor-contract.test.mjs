import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  createEdgeImageManifest,
  parseEdgeMonitorConfiguration,
  verifyEdgeImageEvidence,
} from "./edge-monitor-contract.mjs";

const imageId = `sha256:${"a".repeat(64)}`;
const configuration = Object.freeze({
  gatewayUpstreamName: "vasi_gateway",
  imageReference: "vasi-edge:current",
  listenerPorts: [80, 443],
  liveContainer: "vasi_edge",
  maximumScanAgeHours: 26,
  publicHost: "vsign.example.com",
  retainedScans: 14,
  retiredHost: "vasi.example.com",
  rollbackContainer: "vasi_edge_rollback",
  scanRoot: "/var/lib/vasi-edge/scans",
  scannerCache: "/var/cache/vasi-edge/trivy",
  schema: "vasi-edge-monitor/v1",
});

describe("edge monitor contract", () => {
  it("accepts only a strict bounded product-neutral configuration", () => {
    expect(parseEdgeMonitorConfiguration(configuration)).toEqual({
      ...configuration,
      listenerPorts: [80, 443],
    });
    for (const changed of [
      { ...configuration, unexpected: true },
      { ...configuration, liveContainer: configuration.rollbackContainer },
      { ...configuration, imageReference: "nginx:latest;touch /tmp/x" },
      { ...configuration, publicHost: "UPPER.example.com" },
      { ...configuration, listenerPorts: [80] },
      { ...configuration, scanRoot: "/tmp/scans" },
      { ...configuration, maximumScanAgeHours: 169 },
    ]) expect(() => parseEdgeMonitorConfiguration(changed)).toThrow();
  });

  it("creates and independently verifies exact bounded scan evidence", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "vasi-edge-evidence-"));
    const scanName = "scan-20260715T120000Z";
    const directory = path.join(root, scanName);
    await mkdir(directory, { mode: 0o700 });
    await writeArtifacts(directory, imageId, []);
    const manifest = await createEdgeImageManifest({
      directory,
      imageId,
      now: new Date("2026-07-15T12:00:00Z"),
      scanDirectory: scanName,
    });
    expect(manifest.status).toBe("pass");
    await writeFile(path.join(root, "latest.json"), await readFile(path.join(directory, "manifest.json")));
    await expect(verifyEdgeImageEvidence({
      configuration,
      evidenceRoot: root,
      expectedImageId: imageId,
      now: new Date("2026-07-15T13:00:00Z"),
    })).resolves.toEqual({
      ageSeconds: 3600,
      artifacts: 5,
      blockingFindings: 0,
      schema: "vasi-edge-image-evidence-result/v1",
      status: "pass",
    });
  });

  it("rejects blocking, stale, mismatched, divergent, and tampered evidence", async () => {
    const scenarios = ["blocking", "stale", "image", "latest", "artifact"];
    for (const scenario of scenarios) {
      const root = await mkdtemp(path.join(tmpdir(), `vasi-edge-${scenario}-`));
      const scanName = "scan-20260715T120000Z";
      const directory = path.join(root, scanName);
      await mkdir(directory, { mode: 0o700 });
      await writeArtifacts(directory, imageId, scenario === "blocking" ? ["HIGH"] : []);
      await createEdgeImageManifest({
        directory,
        imageId,
        now: new Date("2026-07-15T12:00:00Z"),
        scanDirectory: scanName,
      });
      await writeFile(path.join(root, "latest.json"), await readFile(path.join(directory, "manifest.json")));
      if (scenario === "latest") await writeFile(path.join(root, "latest.json"), "{}\n");
      if (scenario === "artifact") await writeFile(path.join(directory, "packages.txt"), "changed\n");
      await expect(verifyEdgeImageEvidence({
        configuration,
        evidenceRoot: root,
        expectedImageId: scenario === "image" ? `sha256:${"b".repeat(64)}` : imageId,
        now: new Date(scenario === "stale" ? "2026-07-17T00:00:01Z" : "2026-07-15T13:00:00Z"),
      })).rejects.toThrow();
    }
  });

  it("rejects a stale vulnerability database before otherwise-fresh scan evidence", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "vasi-edge-stale-database-"));
    const scanName = "scan-20260715T120000Z";
    const directory = path.join(root, scanName);
    await mkdir(directory, { mode: 0o700 });
    await writeArtifacts(directory, imageId, []);
    await createEdgeImageManifest({
      directory,
      imageId,
      now: new Date("2026-07-15T12:00:00Z"),
      scanDirectory: scanName,
    });
    await writeFile(path.join(root, "latest.json"), await readFile(path.join(directory, "manifest.json")));
    await expect(verifyEdgeImageEvidence({
      configuration: { ...configuration, maximumScanAgeHours: 168 },
      evidenceRoot: root,
      expectedImageId: imageId,
      now: new Date("2026-07-16T13:00:01Z"),
    })).rejects.toThrow(/vulnerability database/i);
  });
});

async function writeArtifacts(directory, expectedImageId, severities) {
  await writeFile(path.join(directory, "image-id.txt"), `${expectedImageId}\n`);
  await writeFile(path.join(directory, "packages.txt"), "nginx-1.0 x86_64\n");
  await writeFile(path.join(directory, "scanner-version.json"), JSON.stringify({
    Version: "1.0.0",
    VulnerabilityDB: {
      DownloadedAt: "2026-07-15T11:30:00.000000000Z",
      NextUpdate: "2026-07-15T18:00:00.000000000Z",
      UpdatedAt: "2026-07-15T11:00:00.000000000Z",
      Version: 2,
    },
  }));
  await writeFile(path.join(directory, "sbom.cdx.json"), JSON.stringify({
    bomFormat: "CycloneDX",
    components: [],
    specVersion: "1.6",
  }));
  await writeFile(path.join(directory, "vulnerabilities.json"), JSON.stringify({
    Results: [{ Vulnerabilities: severities.map((Severity) => ({ Severity })) }],
  }));
}
