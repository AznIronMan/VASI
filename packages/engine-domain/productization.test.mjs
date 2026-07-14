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

describe("productized installation and tenant profiles", () => {
  it("normalizes product-neutral defaults", () => {
    expect(validateInstallationProfile(defaultInstallationProfile())).toMatchObject({
      deployment: { mode: "self_hosted", publicIngress: "gateway_only" },
      adapters: { smtpAllowedHosts: [], webhookAllowedHosts: [] },
      product: { organizationName: "VASI", productName: "V·Sign" },
    });
    expect(validateTenantProfile(defaultTenantProfile("Example Company"))).toMatchObject({
      branding: { displayName: "Example Company" },
      policies: { defaultRetentionProfile: "tenant_default" },
      quotas: { maxMembers: 100 },
    });
    expect(BUILT_IN_ADAPTERS.map((adapter) => adapter.id)).toEqual(["disabled", "smtp", "webhook"]);
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
  });
});
