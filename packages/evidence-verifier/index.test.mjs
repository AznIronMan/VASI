import { describe, expect, it } from "vitest";

import { sealedTestRecord } from "./test-fixture.mjs";
import { assertEvidenceRecord, verifyEvidenceRecord } from "./index.mjs";

describe("portable evidence record verification", () => {
  it("validates event identity, hash continuity, manifest binding, and the public seal", () => {
    const { record } = sealedTestRecord();
    expect(assertEvidenceRecord(record).verified).toBe(true);
    const altered = structuredClone(record);
    altered.events[1].eventData.actor.email = "attacker@example.test";
    const result = verifyEvidenceRecord(altered);
    expect(result.verified).toBe(false);
    expect(result.errors).toContain("event_2_hash_invalid");
  });

  it("recalculates generalized activity-interaction evidence and rejects sealed telemetry tampering", () => {
    const { record } = sealedTestRecord();
    expect(verifyEvidenceRecord(record).checks.activityInteraction).toBe(true);
    const altered = structuredClone(record);
    altered.manifest.activityInteraction.events[3].event.monotonicMs = 9_000;
    const result = verifyEvidenceRecord(altered);
    expect(result.verified).toBe(false);
    expect(result.errors).toContain("activity_interaction_summary_calculation_invalid");
  });
});
