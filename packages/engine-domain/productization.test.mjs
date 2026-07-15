import { describe, expect, it } from "vitest";

import {
  applyTenantAdmissionDecision,
  BUILT_IN_ADAPTERS,
  defaultInstallationProfile,
  defaultTenantAdmission,
  defaultTenantProfile,
  integrationDestinationAllowed,
  TENANT_ADMISSION_GATES,
  validateInstallationProfile,
  validateIntegrationBindingCommand,
  validateTenantAdmission,
  validateTenantAdmissionDecisionCommand,
  validateTenantProductionStopCommand,
  validateTenantReadinessExportCommand,
  validateTenantProfile,
  validateTenantProvisionInput,
} from "./productization.mjs";

const graphTenantId = "11111111-1111-4111-8111-111111111111";
const graphClientId = "22222222-2222-4222-8222-222222222222";
const evidenceDigest = "a".repeat(64);

describe("productized installation and tenant profiles", () => {
  it("normalizes product-neutral defaults", () => {
    expect(validateInstallationProfile(defaultInstallationProfile())).toMatchObject({
      deployment: { mode: "self_hosted", publicIngress: "gateway_only" },
      adapters: {
        microsoftGraphAllowedClientIds: [],
        microsoftGraphAllowedSenders: [],
        microsoftGraphAllowedTenantIds: [],
        malwareScannerAllowedHosts: [],
        smtpAllowedHosts: [],
        webhookAllowedHosts: [],
      },
      product: { organizationName: "VASI", productName: "V·Sign" },
    });
    expect(validateTenantProfile(defaultTenantProfile("Example Company"))).toMatchObject({
      branding: { displayName: "Example Company" },
      policies: { defaultRetentionProfile: "tenant_default" },
      quotas: { maxMembers: 100 },
    });
    expect(BUILT_IN_ADAPTERS.map((adapter) => adapter.id)).toEqual([
      "disabled", "scan_disabled", "https_malware_scanner", "microsoft_graph", "smtp", "webhook",
    ]);
  });

  it("preserves the canonical shape of pre-Graph installation profiles", () => {
    const current = defaultInstallationProfile();
    const legacy = {
      ...current,
      adapters: {
        allow: ["disabled", "smtp", "webhook"],
        smtpAllowedHosts: [],
        webhookAllowedHosts: [],
      },
    };
    expect(validateInstallationProfile(legacy)).toEqual(legacy);
  });

  it("rejects public engine exposure and inconsistent artifact limits", () => {
    expect(() => validateInstallationProfile({
      ...defaultInstallationProfile(),
      deployment: {
        ...defaultInstallationProfile().deployment,
        publicIngress: "engine",
      },
    })).toThrow(/public ingress/i);
    expect(() => validateTenantProfile({
      ...defaultTenantProfile(),
      quotas: {
        ...defaultTenantProfile().quotas,
        maxArtifactBytes: 1_048_576,
        maxArtifactBytesPerArtifact: 2_097_152,
      },
    })).toThrow(/per-artifact/i);
  });

  it("requires administrator-ready tenant slugs and bounded profiles", () => {
    expect(validateTenantProvisionInput({
      commandId: "33333333-3333-4333-8333-333333333333",
      name: "Example Company",
      ownerEmail: " OWNER@EXAMPLE.COM ",
      slug: "example-company",
    })).toMatchObject({
      commandId: "33333333-3333-4333-8333-333333333333",
      name: "Example Company",
      ownerEmail: "owner@example.com",
      slug: "example-company",
    });
    expect(() => validateTenantProvisionInput({ name: "Example", slug: "UPPER CASE" })).toThrow(/slug/i);
    expect(validateTenantProvisionInput({ name: "Legacy Company", slug: "legacy-company" }).commandId).toBeNull();
    expect(() => validateTenantProvisionInput({
      commandId: "not-a-uuid",
      name: "Example",
      slug: "example",
    })).toThrow(/UUID/i);
  });
});

describe("tenant production admission", () => {
  it("derives pending and admitted states from the exact required gate set", () => {
    let admission = defaultTenantAdmission();
    expect(admission.status).toBe("pending");
    expect(admission.gates.map((gate) => gate.id)).toEqual(TENANT_ADMISSION_GATES);
    for (const gateId of TENANT_ADMISSION_GATES) {
      admission = applyTenantAdmissionDecision(admission, {
        decision: "approved",
        evidenceDigest,
        evidenceReference: `evidence:${gateId}`,
        expectedRevision: 1,
        gateId,
        reviewerReference: `reviewer:${gateId}`,
        tenantId: "tenant-1",
      }, new Date("2026-07-14T20:00:00.000Z"));
    }
    expect(validateTenantAdmission(admission).status).toBe("admitted");
    expect(admission.gates.every((gate) => gate.decidedAt === "2026-07-14T20:00:00.000Z")).toBe(true);
  });

  it("rejects asserted status, missing gates, URLs, narrative, and malformed digests", () => {
    expect(() => validateTenantAdmission({
      ...defaultTenantAdmission(),
      status: "admitted",
    })).toThrow(/inconsistent/i);
    expect(() => validateTenantAdmission({
      ...defaultTenantAdmission(),
      gates: defaultTenantAdmission().gates.slice(1),
    })).toThrow(/incomplete/i);
    expect(() => validateTenantAdmissionDecisionCommand({
      decision: "approved",
      evidenceDigest: "not-a-digest",
      evidenceReference: "https://evidence.example.test/item",
      expectedRevision: 1,
      gateId: "privacy_legal",
      reviewerReference: "Legal reviewer with narrative",
      tenantId: "tenant-1",
    })).toThrow(/SHA-256/i);
    expect(() => validateTenantAdmissionDecisionCommand({
      decision: "approved",
      evidenceDigest,
      evidenceReference: "https://evidence.example.test/item",
      expectedRevision: 1,
      gateId: "privacy_legal",
      reviewerReference: "legal-reviewer",
      tenantId: "tenant-1",
    })).toThrow(/opaque identifier/i);
  });

  it("clears approval provenance when an administrator revokes a gate", () => {
    const approved = applyTenantAdmissionDecision(defaultTenantAdmission(), {
      decision: "approved",
      evidenceDigest,
      evidenceReference: "evidence:release",
      expectedRevision: 1,
      gateId: "exact_release",
      reviewerReference: "release-owner",
      tenantId: "tenant-1",
    }, new Date("2026-07-14T20:00:00.000Z"));
    const pending = applyTenantAdmissionDecision(approved, {
      decision: "pending",
      expectedRevision: 2,
      gateId: "exact_release",
      tenantId: "tenant-1",
    }, new Date("2026-07-14T21:00:00.000Z"));
    expect(pending.gates[0]).toEqual({ id: "exact_release", state: "pending" });
  });

  it("accepts only bounded, opaque tenant production-stop commands", () => {
    expect(validateTenantProductionStopCommand({
      commandId: "stop-command-1",
      expectedRevision: 9,
      gateId: "isolation_integrity",
      incidentReference: "incident:2026-0714",
      reasonCode: "security_incident",
      tenantId: "tenant-1",
    })).toEqual({
      commandId: "stop-command-1",
      expectedRevision: 9,
      gateId: "isolation_integrity",
      incidentReference: "incident:2026-0714",
      reasonCode: "security_incident",
      tenantId: "tenant-1",
    });
    expect(() => validateTenantProductionStopCommand({
      commandId: "stop-command-2",
      expectedRevision: 9,
      gateId: "isolation_integrity",
      incidentReference: "https://incident.example.test/details",
      reasonCode: "security_incident",
      tenantId: "tenant-1",
    })).toThrow(/opaque identifier/i);
    expect(() => validateTenantProductionStopCommand({
      commandId: "stop-command-3",
      expectedRevision: 9,
      gateId: "isolation_integrity",
      incidentReference: "incident:2026-0714",
      reasonCode: "unbounded_narrative",
      tenantId: "tenant-1",
    })).toThrow(/reason/i);
  });
});

describe("tenant readiness export contract", () => {
  it("accepts only a tenant UUID and an explicit portable format", () => {
    expect(validateTenantReadinessExportCommand({
      format: "json",
      tenantId: "11111111-1111-4111-8111-111111111111",
    })).toEqual({
      format: "json",
      tenantId: "11111111-1111-4111-8111-111111111111",
    });
    expect(() => validateTenantReadinessExportCommand({
      format: "pdf",
      tenantId: "11111111-1111-4111-8111-111111111111",
    })).toThrow(/format is unsupported/i);
    expect(() => validateTenantReadinessExportCommand({
      format: "html",
      tenantId: "tenant-1",
    })).toThrow(/tenantId must be a UUID/i);
    expect(() => validateTenantReadinessExportCommand({
      format: "html",
      tenantId: "11111111-1111-4111-8111-111111111111",
      includeSecrets: true,
    })).toThrow(/includeSecrets is unsupported/i);
  });
});

describe("integration binding contracts", () => {
  it("normalizes signed webhooks without exposing credentials in configuration", () => {
    const result = validateIntegrationBindingCommand({
      adapterId: "webhook",
      capability: "notification.delivery",
      config: { url: "https://events.example.test/vasi" },
      credentials: { secret: "s".repeat(48) },
      expectedRevision: 0,
      tenantId: "tenant-1",
    });
    expect(result.config).toEqual({ url: "https://events.example.test/vasi" });
    expect(result.credentials).toEqual({ secret: "s".repeat(48) });
    expect(JSON.stringify(result.config)).not.toContain("ssss");
  });

  it("rejects insecure webhooks and partial SMTP credentials", () => {
    expect(() => validateIntegrationBindingCommand({
      adapterId: "webhook",
      capability: "notification.delivery",
      config: { url: "http://events.example.test" },
      credentials: { secret: "s".repeat(48) },
      expectedRevision: 0,
      tenantId: "tenant-1",
    })).toThrow(/HTTPS/);
    expect(() => validateIntegrationBindingCommand({
      adapterId: "smtp",
      capability: "notification.delivery",
      config: { from: "VASI <no-reply@example.test>", host: "smtp.example.test", port: 587, secure: false, username: "user" },
      credentials: {},
      expectedRevision: 0,
      tenantId: "tenant-1",
    })).toThrow(/together/);
  });

  it("normalizes a write-only Microsoft Graph app binding", () => {
    const result = validateIntegrationBindingCommand({
      adapterId: "microsoft_graph",
      capability: "notification.delivery",
      config: {
        clientId: graphClientId.toUpperCase(),
        senderEmail: "Notifications@Example.Test",
        tenantId: graphTenantId.toUpperCase(),
      },
      credentials: { clientSecret: "graph-secret-value" },
      expectedRevision: 2,
      tenantId: "tenant-1",
    });
    expect(result.config).toEqual({
      clientId: graphClientId,
      senderEmail: "notifications@example.test",
      tenantId: graphTenantId,
    });
    expect(result.credentials).toEqual({ clientSecret: "graph-secret-value" });
    expect(JSON.stringify(result.config)).not.toContain("graph-secret-value");
  });

  it("rejects malformed or incomplete Microsoft Graph app configuration", () => {
    expect(() => validateIntegrationBindingCommand({
      adapterId: "microsoft_graph",
      capability: "notification.delivery",
      config: { clientId: "not-a-uuid", senderEmail: "sender@example.test", tenantId: graphTenantId },
      credentials: { clientSecret: "secret" },
      expectedRevision: 0,
      tenantId: "tenant-1",
    })).toThrow(/UUID/);
    expect(() => validateIntegrationBindingCommand({
      adapterId: "microsoft_graph",
      capability: "notification.delivery",
      config: { clientId: graphClientId, senderEmail: "sender@example.test", tenantId: graphTenantId },
      credentials: {},
      expectedRevision: 0,
      tenantId: "tenant-1",
    })).toThrow(/clientSecret/);
  });

  it("requires exact installation-approved outbound destinations", () => {
    const binding = validateIntegrationBindingCommand({
      adapterId: "webhook",
      capability: "notification.delivery",
      config: { url: "https://events.example.test/vasi" },
      credentials: { secret: "s".repeat(48) },
      expectedRevision: 1,
      tenantId: "tenant-1",
    });
    expect(integrationDestinationAllowed(defaultInstallationProfile(), binding)).toBe(false);
    expect(integrationDestinationAllowed({
      ...defaultInstallationProfile(),
      adapters: {
        ...defaultInstallationProfile().adapters,
        webhookAllowedHosts: ["events.example.test"],
      },
    }, binding)).toBe(true);

    const graphBinding = validateIntegrationBindingCommand({
      adapterId: "microsoft_graph",
      capability: "notification.delivery",
      config: { clientId: graphClientId, senderEmail: "sender@example.test", tenantId: graphTenantId },
      credentials: { clientSecret: "secret" },
      expectedRevision: 1,
      tenantId: "tenant-1",
    });
    expect(integrationDestinationAllowed(defaultInstallationProfile(), graphBinding)).toBe(false);
    expect(integrationDestinationAllowed({
      ...defaultInstallationProfile(),
      adapters: {
        ...defaultInstallationProfile().adapters,
        microsoftGraphAllowedClientIds: [graphClientId],
        microsoftGraphAllowedSenders: ["sender@example.test"],
        microsoftGraphAllowedTenantIds: [graphTenantId],
      },
    }, graphBinding)).toBe(true);
    expect(integrationDestinationAllowed({
      ...defaultInstallationProfile(),
      adapters: {
        ...defaultInstallationProfile().adapters,
        microsoftGraphAllowedClientIds: [graphClientId],
        microsoftGraphAllowedSenders: ["other@example.test"],
        microsoftGraphAllowedTenantIds: [graphTenantId],
      },
    }, graphBinding)).toBe(false);
  });

  it("normalizes a write-only HTTPS scanner and requires an exact approved host", () => {
    const binding = validateIntegrationBindingCommand({
      adapterId: "https_malware_scanner",
      capability: "document.malware_scan",
      config: { timeoutSeconds: 30, url: "https://scanner.example.test/v1/scan" },
      credentials: { secret: "m".repeat(48) },
      expectedRevision: 1,
      tenantId: "tenant-1",
    });
    expect(binding.config).toEqual({
      timeoutSeconds: 30,
      url: "https://scanner.example.test/v1/scan",
    });
    expect(binding.credentials).toEqual({ caCertificatePem: undefined, secret: "m".repeat(48) });
    expect(integrationDestinationAllowed(defaultInstallationProfile(), binding)).toBe(false);
    expect(integrationDestinationAllowed({
      ...defaultInstallationProfile(),
      adapters: {
        ...defaultInstallationProfile().adapters,
        malwareScannerAllowedHosts: ["scanner.example.test"],
      },
    }, binding)).toBe(true);
    expect(() => validateIntegrationBindingCommand({
      adapterId: "https_malware_scanner",
      capability: "document.malware_scan",
      config: { timeoutSeconds: 30, url: "http://scanner.example.test/v1/scan" },
      credentials: { secret: "m".repeat(48) },
      expectedRevision: 1,
      tenantId: "tenant-1",
    })).toThrow(/HTTPS/);
    expect(() => validateIntegrationBindingCommand({
      adapterId: "https_malware_scanner",
      capability: "document.malware_scan",
      config: { timeoutSeconds: 30, url: "https://scanner.example.test/v1/scan?token=visible-secret" },
      credentials: { secret: "m".repeat(48) },
      expectedRevision: 1,
      tenantId: "tenant-1",
    })).toThrow(/query/);
  });
});
