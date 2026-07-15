import { describe, expect, it } from "vitest";

import {
  resolveAuthenticationEvidence,
  resolveConnectorHealth,
} from "@/lib/admin-users";
import { connectorAuthenticationProvenance } from "@/lib/connector-authentication-health";

describe("connector health", () => {
  const now = new Date("2026-07-13T12:00:00Z").getTime();

  it("uses gray for a connector that is not linked", () => {
    expect(
      resolveConnectorHealth({ configured: true, connected: false, now }),
    ).toBe("disconnected");
  });

  it("uses red when a linked connector is unavailable", () => {
    expect(
      resolveConnectorHealth({
        accountId: "provider-account",
        authenticationEvidence: "observed",
        configured: false,
        connected: true,
        lastAuthenticatedAt: new Date(now),
        now,
      }),
    ).toBe("error");
  });

  it("uses yellow after more than 90 days without authentication", () => {
    expect(
      resolveConnectorHealth({
        accountId: "provider-account",
        authenticationEvidence: "observed",
        configured: true,
        connected: true,
        lastAuthenticatedAt: new Date(now - 91 * 24 * 60 * 60 * 1_000),
        now,
      }),
    ).toBe("stale");
  });

  it("uses green for a recently used healthy connector", () => {
    expect(
      resolveConnectorHealth({
        accountId: "provider-account",
        authenticationEvidence: "observed",
        configured: true,
        connected: true,
        lastAuthenticatedAt: new Date(now - 12 * 24 * 60 * 60 * 1_000),
        now,
      }),
    ).toBe("active");
  });

  it("distinguishes observed authentication from legacy account activity", () => {
    expect(resolveAuthenticationEvidence(
      connectorAuthenticationProvenance.federatedSession,
    )).toBe("observed");
    expect(resolveAuthenticationEvidence(
      connectorAuthenticationProvenance.attributedSessionBackfill,
    )).toBe("attributed_history");
    expect(resolveAuthenticationEvidence(
      connectorAuthenticationProvenance.legacyAccountActivityEstimate,
    )).toBe("legacy_estimate");
    expect(resolveAuthenticationEvidence(null)).toBeNull();
  });

  it("never presents a legacy account-update estimate as active authentication", () => {
    expect(resolveConnectorHealth({
      accountId: "provider-account",
      authenticationEvidence: "legacy_estimate",
      configured: true,
      connected: true,
      lastAuthenticatedAt: new Date(now),
      now,
    })).toBe("error");
  });
});
