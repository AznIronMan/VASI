import { X509Certificate } from "node:crypto";
import { rootCertificates } from "node:tls";

import { describe, expect, it } from "vitest";

import packageJSON from "../package.json" with { type: "json" };
import {
  certificateWindowsFromPEM,
  runDeploymentReadinessProbe,
} from "./probe-deployment-readiness.mjs";

const certificate = rootCertificates.find((value) => {
  const parsed = new X509Certificate(value);
  return Date.parse(parsed.validTo) - Date.parse(parsed.validFrom) > 365 * 86_400_000;
});
const parsedCertificate = new X509Certificate(certificate);
const certificateMidpoint = new Date((Date.parse(parsedCertificate.validFrom) + Date.parse(parsedCertificate.validTo)) / 2);

describe("deployment perimeter readiness", () => {
  it("returns aggregate ready state without target, path, certificate, or setting material", async () => {
    const result = await runDeploymentReadinessProbe(readyOptions());
    expect(result).toMatchObject({
      expectedVersion: packageJSON.version,
      observedVersion: packageJSON.version,
      reasons: [],
      scope: "gateway",
      status: "ready",
      storage: { freeBytes: 8_000_000_000, totalBytes: 10_000_000_000, usedPercent: 20 },
    });
    expect(result.serviceCertificates.map((entry) => entry.code)).toEqual(["gateway_client", "engine_server_ca"]);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("example.test");
    expect(serialized).not.toContain("host-storage");
    expect(serialized).not.toContain("BEGIN CERTIFICATE");
    expect(serialized).not.toContain("ENGINE_CLIENT_CERT");
  });

  it("fails all applicable version, TLS, service-certificate, and capacity thresholds", async () => {
    const certificateExpiry = new Date(parsedCertificate.validTo);
    const now = new Date(certificateExpiry.getTime() - 5 * 86_400_000);
    await expect(runDeploymentReadinessProbe({
      ...readyOptions(now),
      fetchHealth: async () => ({ milliseconds: 3, version: "0.0.0" }),
      inspectPublicTLS: async () => ({
        expiresAt: new Date(now.getTime() + 5 * 86_400_000).toISOString(),
        validFrom: new Date(now.getTime() - 86_400_000).toISOString(),
      }),
      inspectStorage: async () => ({ freeBytes: 1_000_000_000, totalBytes: 10_000_000_000 }),
    })).rejects.toMatchObject({
      result: {
        reasons: [
          "public_tls_expiring",
          "public_version_mismatch",
          "service_certificate_expiring",
          "storage_pressure",
        ],
        status: "critical",
      },
    });
  });

  it("reports bounded component reasons when dependencies are unreachable", async () => {
    await expect(runDeploymentReadinessProbe({
      ...readyOptions(),
      fetchHealth: async () => { throw new Error("network details"); },
      inspectPublicTLS: async () => { throw new Error("tls details"); },
      inspectStorage: async () => { throw new Error("filesystem details"); },
      readSettings: async () => { throw new Error("database details"); },
    })).rejects.toMatchObject({
      result: {
        reasons: [
          "public_health_unavailable",
          "public_tls_unavailable",
          "service_settings_unavailable",
          "storage_unavailable",
        ],
      },
    });
  });

  it("maps malformed component responses to bounded unavailable reasons", async () => {
    await expect(runDeploymentReadinessProbe({
      ...readyOptions(),
      fetchHealth: async () => ({ milliseconds: Number.NaN, version: packageJSON.version }),
      inspectPublicTLS: async () => ({ expiresAt: "invalid", validFrom: "invalid" }),
      inspectStorage: async () => ({ freeBytes: 2, totalBytes: 1 }),
    })).rejects.toMatchObject({
      result: {
        reasons: ["public_health_unavailable", "public_tls_unavailable", "storage_unavailable"],
      },
    });
  });

  it("rejects missing and malformed service certificate sets", async () => {
    await expect(runDeploymentReadinessProbe({ ...readyOptions(), readSettings: async () => ({}) }))
      .rejects.toMatchObject({ result: { reasons: ["service_certificate_missing"] } });
    await expect(runDeploymentReadinessProbe({
      ...readyOptions(),
      readSettings: async () => ({ ENGINE_CA_CERT: "invalid", ENGINE_CLIENT_CERT: "invalid" }),
    })).rejects.toMatchObject({ result: { reasons: ["service_certificate_invalid"] } });
    expect(() => certificateWindowsFromPEM("not a certificate", certificateMidpoint)).toThrow("malformed");
  });

  it("covers the engine service and optional evidence certificate set", async () => {
    const result = await runDeploymentReadinessProbe({
      ...readyOptions(),
      readSettings: async () => ({
        ENGINE_AUTHORIZED_CLIENT_CA_CERT: certificate,
        ENGINE_INGRESS_TLS_CERT: certificate,
        EVIDENCE_CERTIFICATE_CHAIN_PEM: certificate,
      }),
      scope: "engine",
    });
    expect(result.serviceCertificates.map((entry) => entry.code)).toEqual([
      "engine_server",
      "authorized_client_ca",
      "evidence_certificate",
    ]);

    const beforeServiceValidity = new Date(Date.parse(parsedCertificate.validFrom) - 86_400_000);
    await expect(runDeploymentReadinessProbe({
      ...readyOptions(beforeServiceValidity),
    })).rejects.toMatchObject({ result: { reasons: ["service_certificate_not_yet_valid"] } });
  });

  it("requires a credential-free HTTPS origin, known scope, absolute storage path, and bounded policy", async () => {
    await expect(runDeploymentReadinessProbe({ ...readyOptions(), origin: "http://example.test" }))
      .rejects.toThrow("HTTPS origin");
    await expect(runDeploymentReadinessProbe({ ...readyOptions(), scope: "other" }))
      .rejects.toThrow("gateway or engine");
    await expect(runDeploymentReadinessProbe({ ...readyOptions(), storagePath: "relative" }))
      .rejects.toThrow("absolute path");
    await expect(runDeploymentReadinessProbe({ ...readyOptions(), minimumCertificateDays: 0 }))
      .rejects.toThrow("minimum certificate days");
  });
});

function readyOptions(now = certificateMidpoint) {
  return {
    fetchHealth: async () => ({ milliseconds: 12.345, version: packageJSON.version }),
    inspectPublicTLS: async () => ({
      expiresAt: new Date(now.getTime() + 365 * 86_400_000).toISOString(),
      validFrom: new Date(now.getTime() - 86_400_000).toISOString(),
    }),
    inspectStorage: async () => ({ freeBytes: 8_000_000_000, totalBytes: 10_000_000_000 }),
    now,
    origin: "https://example.test",
    readSettings: async () => ({ ENGINE_CA_CERT: certificate, ENGINE_CLIENT_CERT: certificate }),
    scope: "gateway",
    storagePath: "/host-storage",
  };
}
