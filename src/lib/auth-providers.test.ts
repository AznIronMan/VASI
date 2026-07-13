import { describe, expect, it } from "vitest";

import {
  getAuthProviderAvailability,
  isProviderConfigured,
} from "@/lib/auth-providers";

describe("authentication provider configuration", () => {
  it("keeps incomplete provider configuration disabled", () => {
    expect(
      isProviderConfigured("microsoft", {
        MICROSOFT_CLIENT_ID: "client-id",
      }),
    ).toBe(false);
  });

  it("enables providers only when their required credentials are present", () => {
    expect(
      isProviderConfigured("google", {
        GOOGLE_CLIENT_ID: "client-id",
        GOOGLE_CLIENT_SECRET: "client-secret",
      }),
    ).toBe(true);
  });

  it("supports generated Apple client secrets", () => {
    expect(
      isProviderConfigured("apple", {
        APPLE_CLIENT_ID: "service-id",
        APPLE_TEAM_ID: "team-id",
        APPLE_KEY_ID: "key-id",
        APPLE_PRIVATE_KEY: "private-key",
      }),
    ).toBe(true);
  });

  it("returns a stable public provider list without exposing secrets", () => {
    const providers = getAuthProviderAvailability({
      YAHOO_CLIENT_ID: "client-id",
      YAHOO_CLIENT_SECRET: "client-secret",
    });

    expect(providers).toEqual([
      { id: "microsoft", label: "Microsoft", configured: false },
      { id: "google", label: "Google", configured: false },
      { id: "apple", label: "Apple", configured: false },
      { id: "yahoo", label: "Yahoo", configured: true },
    ]);
    expect(JSON.stringify(providers)).not.toContain("client-secret");
  });
});
