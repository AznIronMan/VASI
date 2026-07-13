import { describe, expect, it } from "vitest";

import { hasEmailConfiguration } from "@/lib/email";

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
});
