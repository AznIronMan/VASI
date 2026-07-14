import { describe, expect, it } from "vitest";

import { integrationCommandFromForm } from "@/lib/integration-configuration";

describe("owner integration configuration", () => {
  it("builds the exact Microsoft Graph write-only command", () => {
    const data = new FormData();
    data.set("graphTenantId", "11111111-1111-4111-8111-111111111111");
    data.set("graphClientId", "22222222-2222-4222-8222-222222222222");
    data.set("graphSenderEmail", "sender@example.test");
    data.set("graphClientSecret", "write-only-secret");
    expect(integrationCommandFromForm("microsoft_graph", data)).toEqual({
      config: {
        clientId: "22222222-2222-4222-8222-222222222222",
        senderEmail: "sender@example.test",
        tenantId: "11111111-1111-4111-8111-111111111111",
      },
      credentials: { clientSecret: "write-only-secret" },
      status: "active",
    });
  });

  it("normalizes SMTP form values and disables delivery without residue", () => {
    const data = new FormData();
    data.set("smtpHost", "smtp.example.test");
    data.set("smtpPort", "587");
    data.set("smtpSecure", "false");
    data.set("smtpFrom", "sender@example.test");
    expect(integrationCommandFromForm("smtp", data)).toEqual({
      config: {
        from: "sender@example.test",
        host: "smtp.example.test",
        port: 587,
        secure: false,
        username: undefined,
      },
      credentials: { password: undefined },
      status: "active",
    });
    expect(integrationCommandFromForm("disabled", data)).toEqual({
      config: {},
      credentials: {},
      status: "disabled",
    });
  });
});
