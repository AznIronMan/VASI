import { describe, expect, it } from "vitest";

import {
  BUILT_IN_ADAPTERS,
  defaultInstallationProfile,
  defaultTenantProfile,
  integrationDestinationAllowed,
  validateInstallationProfile,
  validateIntegrationBindingCommand,
  validateTenantProfile,
  validateTenantProvisionInput,
} from "./productization.mjs";

const graphTenantId = "11111111-1111-4111-8111-111111111111";
const graphClientId = "22222222-2222-4222-8222-222222222222";

describe("productized installation and tenant profiles", () => {
  it("normalizes product-neutral defaults", () => {
    expect(validateInstallationProfile(defaultInstallationProfile())).toMatchObject({
      deployment: { mode: "self_hosted", publicIngress: "gateway_only" },
      adapters: {
        microsoftGraphAllowedClientIds: [],
        microsoftGraphAllowedSenders: [],
        microsoftGraphAllowedTenantIds: [],
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
      "disabled", "microsoft_graph", "smtp", "webhook",
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
    expect(validateTenantProvisionInput({ name: "Example Company", slug: "example-company" })).toMatchObject({
      name: "Example Company",
      slug: "example-company",
    });
    expect(() => validateTenantProvisionInput({ name: "Example", slug: "UPPER CASE" })).toThrow(/slug/i);
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
});
