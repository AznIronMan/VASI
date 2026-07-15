import { describe, expect, it, vi } from "vitest";

import {
  connectorAuthenticationProvenance,
  recordConnectorAuthentication,
} from "@/lib/connector-authentication-health";

describe("connector authentication health", () => {
  const federatedSession = {
    authenticationAccountId: "provider-account-17",
    authenticationMethod: "federated",
    authenticationProvider: "google",
    createdAt: new Date("2026-07-14T18:30:00Z"),
    userId: "user-42",
  };

  it("advances only the connector attributed by a completed federated session", async () => {
    const query = vi.fn().mockResolvedValue({ rowCount: 1 });

    await expect(recordConnectorAuthentication(federatedSession, query)).resolves.toBe("recorded");

    expect(query).toHaveBeenCalledTimes(1);
    const [sql, values] = query.mock.calls[0];
    expect(sql).toContain('"userId" = $1');
    expect(sql).toContain('"providerId" = $2');
    expect(sql).toContain('"accountId" = $3');
    expect(sql).toContain('"lastAuthenticatedAt"');
    expect(sql).not.toContain('set "updatedAt"');
    expect(values).toEqual([
      "user-42",
      "google",
      "provider-account-17",
      new Date("2026-07-14T18:30:00Z"),
      connectorAuthenticationProvenance.legacyAccountActivityEstimate,
      connectorAuthenticationProvenance.federatedSession,
    ]);
  });

  it.each([
    ["password", "credential"],
    ["email_verification", undefined],
    ["session_unspecified", undefined],
    ["federated", "unsupported-provider"],
  ])("does not advance a %s session", async (method, provider) => {
    const query = vi.fn();
    await expect(recordConnectorAuthentication({
      ...federatedSession,
      authenticationMethod: method,
      authenticationProvider: provider,
    }, query)).resolves.toBe("ignored");
    expect(query).not.toHaveBeenCalled();
  });

  it("rejects incomplete federated attribution without guessing an account", async () => {
    const query = vi.fn();
    await expect(recordConnectorAuthentication({
      ...federatedSession,
      authenticationAccountId: undefined,
    }, query)).resolves.toBe("incomplete_attribution");
    expect(query).not.toHaveBeenCalled();
  });

  it("reports a missing exact account without broadening the update", async () => {
    const query = vi.fn().mockResolvedValue({ rowCount: 0 });
    await expect(recordConnectorAuthentication(federatedSession, query)).resolves.toBe("account_not_found");
    expect(query).toHaveBeenCalledTimes(1);
  });
});
