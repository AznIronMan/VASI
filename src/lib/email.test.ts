import { describe, expect, it } from "vitest";

import { hasEmailConfiguration, resolveEmailProvider } from "@/lib/email";

describe("transactional email configuration", () => {
  it("requires a sender and SMTP host", () => {
    expect(hasEmailConfiguration({ SMTP_HOST: "smtp.example.com" })).toBe(false);
    expect(hasEmailConfiguration({ AUTH_EMAIL_FROM: "auth@example.com" })).toBe(false);
  });

  it("allows unauthenticated local SMTP relays", () => {
    expect(
      hasEmailConfiguration({
        SMTP_HOST: "smtp.internal",
        AUTH_EMAIL_FROM: "V Sign <auth@example.com>",
      }),
    ).toBe(true);
  });

  it("prefers a complete Graph configuration", () => {
    const environment = {
      GRAPH_TENANT_ID: "tenant-id",
      GRAPH_CLIENT_ID: "client-id",
      GRAPH_CLIENT_SECRET: "client-secret",
      GRAPH_SENDER_EMAIL: "server@example.com",
      SMTP_HOST: "smtp.internal",
      AUTH_EMAIL_FROM: "V Sign <auth@example.com>",
    };

    expect(hasEmailConfiguration(environment)).toBe(true);
    expect(resolveEmailProvider(environment)).toBe("graph");
  });

  it("honors an explicit email provider", () => {
    expect(
      resolveEmailProvider({
        AUTH_EMAIL_PROVIDER: "smtp",
        SMTP_HOST: "smtp.internal",
        AUTH_EMAIL_FROM: "V Sign <auth@example.com>",
      }),
    ).toBe("smtp");

    expect(resolveEmailProvider({ AUTH_EMAIL_PROVIDER: "graph" })).toBeUndefined();
  });
});
