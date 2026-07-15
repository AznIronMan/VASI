import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { ADMIN_AUDIT_GENESIS_HASH } from "../packages/admin-audit/index.mjs";
import {
  buildGatewayOperationalSnapshot,
  parseGatewayOperationalArguments,
} from "./probe-gateway-operational-readiness.mjs";

describe("gateway operational-readiness probe", () => {
  it("builds a privacy-safe snapshot and verifies exact migration state", () => {
    const row = chainedEvent();
    const snapshot = buildGatewayOperationalSnapshot({
      chainRows: [row],
      commandRow: { ambiguous24Hours: "1", incomplete: "2", oldestIncompleteSeconds: "12" },
      expectedMigrations: new Map([["0001", "expected"]]),
      generatedAt: "2026-07-14T12:01:00.000Z",
      headRow: { lastHash: row.eventHash, lastSequence: "1" },
      migrationRows: [{ checksum: "expected", name: "0001" }],
      queryMilliseconds: 8,
    });
    expect(snapshot).toMatchObject({
      audit: { events: 1, failureCode: null, headMatches: true, lastSequence: 1, valid: true },
      commands: { ambiguous24Hours: 1, incomplete: 2, oldestIncompleteSeconds: 12 },
      database: { queryMilliseconds: 8 },
      migrations: { applied: 1, expected: 1, valid: true },
      schema: "vasi-gateway-operational-readiness/v1",
    });
    expect(JSON.stringify(snapshot)).not.toContain("actor@example.test");
    expect(JSON.stringify(snapshot)).not.toContain("192.0.2.10");
  });

  it("detects an exact migration checksum mismatch", () => {
    const snapshot = buildGatewayOperationalSnapshot({
      chainRows: [],
      commandRow: {},
      expectedMigrations: new Map([["0001", "expected"]]),
      generatedAt: "2026-07-14T12:01:00.000Z",
      headRow: { lastHash: ADMIN_AUDIT_GENESIS_HASH, lastSequence: 0 },
      migrationRows: [{ checksum: "changed", name: "0001" }],
      queryMilliseconds: 1,
    });
    expect(snapshot.migrations).toEqual({ applied: 1, expected: 1, valid: false });
  });

  it("rejects unbounded aggregate values", () => {
    expect(() => buildGatewayOperationalSnapshot({
      chainRows: [],
      commandRow: { incomplete: "9007199254740992" },
      expectedMigrations: new Map(),
      generatedAt: "2026-07-14T12:01:00.000Z",
      headRow: { lastHash: ADMIN_AUDIT_GENESIS_HASH, lastSequence: 0 },
      migrationRows: [],
      queryMilliseconds: 1,
    })).toThrow("incomplete command count is invalid");
  });

  it("accepts bounded overrides and rejects malformed options", () => {
    expect(parseGatewayOperationalArguments([
      "--maximum-database-ms", "50",
      "--maximum-incomplete-command-seconds", "120",
    ])).toEqual({
      maximumDatabaseQueryMilliseconds: 50,
      maximumIncompleteCommandSeconds: 120,
    });
    expect(() => parseGatewayOperationalArguments(["--maximum-database-ms"]))
      .toThrow("Invalid gateway operational-readiness option");
    expect(() => parseGatewayOperationalArguments(["--unknown", "1"]))
      .toThrow("Invalid gateway operational-readiness option");
  });
});

function chainedEvent() {
  const data = {
    action: "user.set_active",
    actorSessionId: "session-1",
    actorUserId: "actor-1",
    commandId: "command-1",
    createdAt: "2026-07-14T12:00:00.000Z",
    id: "event-1",
    ipAddress: "192.0.2.10",
    metadata: { desiredEnabled: false },
    phase: "started",
    requestId: "request-1",
    sequence: 1,
    targetUserId: "target-1",
    userAgent: "VASI test browser",
  };
  const canonicalPayload = JSON.stringify(data);
  return {
    ...data,
    canonicalPayload,
    eventHash: createHash("sha256").update(ADMIN_AUDIT_GENESIS_HASH + canonicalPayload).digest("hex"),
    previousHash: ADMIN_AUDIT_GENESIS_HASH,
  };
}
