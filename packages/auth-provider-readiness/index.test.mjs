import { describe, expect, it } from "vitest";

import {
  AUTH_PROVIDER_IDS,
  ZOHO_ACCOUNTS_ORIGINS,
  getAuthProviderReadiness,
  normalizeZohoAccountsOrigin,
  validateAuthProviderConfiguration,
} from "./index.mjs";

describe("identity-provider activation readiness", () => {
  it("reports every provider without exposing credentials", () => {
    const settings = {
      MICROSOFT_CLIENT_ID: "microsoft-client",
      MICROSOFT_CLIENT_SECRET: "microsoft-secret",
      GOOGLE_CLIENT_ID: "google-client",
      GOOGLE_CLIENT_SECRET: "google-secret",
      APPLE_LOGIN_ENABLED: "false",
      YAHOO_CLIENT_ID: "yahoo-client",
      YAHOO_CLIENT_SECRET: "yahoo-secret",
      ZOHO_CLIENT_ID: "zoho-client",
      ZOHO_CLIENT_SECRET: "zoho-secret",
      ZOHO_ACCOUNTS_ORIGIN: "https://accounts.zoho.com/",
    };
    const readiness = getAuthProviderReadiness(settings, {
      adminOrigin: "https://admin.example.test",
      publicOrigin: "https://login.example.test",
    });

    expect(readiness.map((provider) => provider.id)).toEqual(AUTH_PROVIDER_IDS);
    expect(readiness.find((provider) => provider.id === "microsoft")).toMatchObject({
      publicCallback: "https://login.example.test/api/auth/callback/microsoft",
      status: "ready",
      visible: true,
    });
    expect(readiness.find((provider) => provider.id === "yahoo")).toMatchObject({
      adminCallback: "https://admin.example.test/api/auth/oauth2/callback/yahoo",
      status: "ready",
    });
    expect(readiness.find((provider) => provider.id === "apple")).toMatchObject({
      configuration: "required",
      configured: false,
      status: "hidden",
      visible: false,
    });
    const serialized = JSON.stringify(readiness);
    for (const secret of ["microsoft-secret", "google-secret", "yahoo-secret", "zoho-secret"]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("distinguishes absent configuration from a dangerous partial tuple", () => {
    const readiness = getAuthProviderReadiness({ MICROSOFT_CLIENT_ID: "client-only" });
    expect(readiness.find((provider) => provider.id === "google")).toMatchObject({
      configuration: "required",
      reason: "not_configured",
      status: "configuration_required",
    });
    expect(readiness.find((provider) => provider.id === "microsoft")).toMatchObject({
      configuration: "invalid",
      reason: "partial_credentials",
      status: "invalid",
    });
    expect(() => validateAuthProviderConfiguration({ MICROSOFT_CLIENT_ID: "client-only" }))
      .toThrow("Microsoft (partial_credentials)");
  });

  it("requires a complete Apple credential route before public visibility", () => {
    expect(() => validateAuthProviderConfiguration({ APPLE_LOGIN_ENABLED: "true" }))
      .toThrow("Apple (visibility_requires_credentials)");
    expect(() => validateAuthProviderConfiguration({ APPLE_LOGIN_ENABLED: "sometimes" }))
      .toThrow("Apple (invalid_visibility_setting)");
    expect(() => validateAuthProviderConfiguration({
      APPLE_CLIENT_ID: "service-id",
      APPLE_CLIENT_SECRET: "signed-secret",
      APPLE_TEAM_ID: "partial-unused-route",
    })).toThrow("Apple (partial_credentials)");

    expect(validateAuthProviderConfiguration({
      APPLE_CLIENT_ID: "service-id",
      APPLE_LOGIN_ENABLED: "true",
      APPLE_TEAM_ID: "team-id",
      APPLE_KEY_ID: "key-id",
      APPLE_PRIVATE_KEY: "private-key-material",
    }).find((provider) => provider.id === "apple")).toMatchObject({
      configuration: "ready",
      status: "ready",
      visible: true,
    });
  });

  it("allows only Zoho's documented HTTPS account origins", () => {
    for (const origin of ZOHO_ACCOUNTS_ORIGINS) {
      expect(normalizeZohoAccountsOrigin(`${origin}/`)).toBe(origin);
      expect(validateAuthProviderConfiguration({
        ZOHO_ACCOUNTS_ORIGIN: origin,
        ZOHO_CLIENT_ID: "client",
        ZOHO_CLIENT_SECRET: "secret",
      }).find((provider) => provider.id === "zoho")?.configured).toBe(true);
    }
    for (const origin of [
      "http://accounts.zoho.com",
      "https://accounts.zoho.com/path",
      "https://accounts.zoho.com?redirect=1",
      "https://user@accounts.zoho.com",
      "https://accounts.zoho.example",
    ]) {
      expect(() => normalizeZohoAccountsOrigin(origin)).toThrow("unsupported");
      expect(() => validateAuthProviderConfiguration({
        ZOHO_ACCOUNTS_ORIGIN: origin,
        ZOHO_CLIENT_ID: "client",
        ZOHO_CLIENT_SECRET: "secret",
      })).toThrow("Zoho (unsupported_accounts_origin)");
      expect(() => validateAuthProviderConfiguration({ ZOHO_ACCOUNTS_ORIGIN: origin }))
        .toThrow("Zoho (unsupported_accounts_origin)");
    }
  });

  it("rejects callback origins that contain non-origin material", () => {
    for (const publicOrigin of [
      "https://user@login.example.test",
      "https://login.example.test/path",
      "https://login.example.test?query=1",
      "https://login.example.test#fragment",
    ]) {
      expect(() => getAuthProviderReadiness({}, { publicOrigin }))
        .toThrow("callback origin is invalid");
    }
  });
});
