import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  ADMIN_AUDIT_GENESIS_HASH,
  evaluateGatewayOperationalReadiness,
  verifyAdminAuditChain,
} from "./index.mjs";

describe("administrator audit chain", () => {
  it("recomputes an ordered chain and exact head", () => {
    const rows = chain([
      event({ id: "event-1", phase: "started", sequence: 1 }),
      event({ id: "event-2", phase: "succeeded", sequence: 2 }),
    ]);
    expect(verifyAdminAuditChain(rows, {
      lastHash: rows[1].eventHash,
      lastSequence: 2,
    })).toMatchObject({ count: 2, firstFailure: null, headMatches: true, valid: true });
  });

  it.each([
    ["sequence discontinuity", (rows) => { rows[1].sequence = 4; }, "sequence_discontinuity"],
    ["previous hash substitution", (rows) => { rows[1].previousHash = "f".repeat(64); }, "previous_hash_mismatch"],
    ["payload tampering", (rows) => { rows[1].canonicalPayload += " "; }, "event_hash_mismatch"],
    ["column substitution", (rows) => { rows[1].action = "user.disabled"; }, "canonical_payload_mismatch"],
    ["unsafe sequence", (rows) => { rows[1].sequence = Number.MAX_VALUE; }, "sequence_invalid"],
  ])("rejects %s", (_label, mutate, code) => {
    const rows = chain([
      event({ id: "event-1", phase: "started", sequence: 1 }),
      event({ id: "event-2", phase: "succeeded", sequence: 2 }),
    ]);
    mutate(rows);
    expect(verifyAdminAuditChain(rows, {
      lastHash: rows[1].eventHash,
      lastSequence: 2,
    }).firstFailure?.code).toBe(code);
  });

  it("fails readiness on drift, invalid audit, and stale incomplete commands", () => {
    expect(evaluateGatewayOperationalReadiness({
      audit: { failureCode: "event_hash_mismatch", valid: false },
      commands: { ambiguous24Hours: 1, incomplete: 1, oldestIncompleteSeconds: 301 },
      database: { queryMilliseconds: 2_001 },
      migrations: { applied: 6, expected: 7 },
    }, {
      maximumDatabaseQueryMilliseconds: 2_000,
      maximumIncompleteCommandSeconds: 300,
    })).toEqual({
      failures: [
        "database_query_threshold_exceeded",
        "event_hash_mismatch",
        "migration_drift",
        "stale_incomplete_admin_command",
      ],
      status: "fail",
      warnings: ["recent_ambiguous_admin_command"],
    });
  });

  it("fails readiness when migration names match but a checksum does not", () => {
    expect(evaluateGatewayOperationalReadiness({
      audit: { failureCode: null, valid: true },
      commands: { ambiguous24Hours: 0, incomplete: 0, oldestIncompleteSeconds: 0 },
      database: { queryMilliseconds: 1 },
      migrations: { applied: 7, expected: 7, valid: false },
    }, {
      maximumDatabaseQueryMilliseconds: 2_000,
      maximumIncompleteCommandSeconds: 300,
    }).failures).toEqual(["migration_drift"]);
  });
});

function event({ id, phase, sequence }) {
  const createdAt = `2026-07-14T12:00:0${sequence}.000Z`;
  const row = {
    action: "user.set_active",
    actorSessionId: "session-1",
    actorUserId: "actor-1",
    commandId: "command-1",
    createdAt,
    id,
    ipAddress: "192.0.2.10",
    metadata: { desiredEnabled: false },
    phase,
    requestId: "request-1",
    sequence,
    targetUserId: "target-1",
    userAgent: "VASI test browser",
  };
  return {
    ...row,
    canonicalPayload: JSON.stringify(row),
    eventHash: "",
    previousHash: "",
  };
}

function chain(rows) {
  let previousHash = ADMIN_AUDIT_GENESIS_HASH;
  for (const row of rows) {
    row.previousHash = previousHash;
    row.eventHash = createHash("sha256")
      .update(previousHash + row.canonicalPayload)
      .digest("hex");
    previousHash = row.eventHash;
  }
  return rows;
}
