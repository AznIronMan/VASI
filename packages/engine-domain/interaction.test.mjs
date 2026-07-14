import { describe, expect, it } from "vitest";

import {
  activityInteractionPolicy,
  calculateActivityInteractionSummary,
  validateActivityInteractionBatch,
} from "./interaction.mjs";

const policy = activityInteractionPolicy();
const startedAt = Date.parse("2026-01-01T00:00:00.000Z");

describe("general activity interaction evidence", () => {
  it("validates strict replay-safe batches without arbitrary interaction detail", () => {
    const result = validateActivityInteractionBatch(batch([
      event(1, 0, "presented"),
      event(2, 1, "visible"),
      event(3, 2, "focus"),
    ]));
    expect(result.events).toHaveLength(3);
    expect(() => validateActivityInteractionBatch(batch([{ ...event(1, 0, "interaction"), key: "secret" }])))
      .toThrow("unsupported fields");
    expect(() => validateActivityInteractionBatch(batch([
      event(2, 10, "heartbeat"),
      event(1, 20, "heartbeat"),
    ]))).toThrow("sequence and monotonic time");
    expect(() => validateActivityInteractionBatch(batch([event(1, 0, "keystroke")]))).toThrow("unsupported");
  });

  it("credits only bounded open, foreground-visible, and recently engaged intervals", () => {
    const rows = [
      row(1, 0, "presented"),
      row(2, 1_000, "visible"),
      row(3, 2_000, "focus"),
      row(4, 3_000, "interaction"),
      row(5, 13_000, "heartbeat"),
      row(6, 18_000, "hidden"),
      row(7, 19_000, "disconnect"),
    ];
    expect(calculateActivityInteractionSummary(policy, rows)).toMatchObject({
      confidence: { level: "medium" },
      events: { count: 7, heartbeatCount: 1, presentedCount: 1 },
      sessions: { count: 1, disconnectCount: 1, incompleteCount: 0 },
      timing: {
        backgroundOrHiddenMilliseconds: 3_000,
        engagedMilliseconds: 15_000,
        foregroundVisibleMilliseconds: 16_000,
        idleForegroundMilliseconds: 1_000,
        openMilliseconds: 19_000,
        uncreditedGapMilliseconds: 0,
      },
    });
  });

  it("excludes oversized gaps and labels incomplete low-confidence sessions", () => {
    const summary = calculateActivityInteractionSummary(policy, [
      row(1, 0, "presented"),
      row(2, 1_000, "visible"),
      row(3, 2_000, "focus"),
      row(4, 50_000, "heartbeat"),
    ]);
    expect(summary).toMatchObject({
      confidence: { level: "low" },
      sessions: { incompleteCount: 1 },
      timing: { openMilliseconds: 2_000, uncreditedGapMilliseconds: 48_000 },
    });
    expect(summary.confidence.limitations.join(" ")).toContain("missing or oversized");
  });

  it("bounds installation policy values", () => {
    expect(activityInteractionPolicy({ ENGINE_ACTIVITY_HEARTBEAT_SECONDS: "5" })).toMatchObject({
      heartbeatSeconds: 5,
    });
    expect(() => activityInteractionPolicy({ ENGINE_ACTIVITY_IDLE_SECONDS: "1" })).toThrow("ENGINE_ACTIVITY_IDLE_SECONDS");
  });
});

function batch(events) {
  return {
    activityId: "activity-1",
    batchId: "batch-1",
    events,
    handle: "h".repeat(43),
    interactionId: "interaction-1",
    telemetrySessionId: "telemetry-1",
  };
}

function event(sequence, monotonicMs, type) {
  return {
    clientOccurredAt: new Date(startedAt + monotonicMs).toISOString(),
    id: `event-${sequence}`,
    monotonicMs,
    sequence,
    type,
  };
}

function row(sequence, monotonicMs, eventType) {
  const value = event(sequence, monotonicMs, eventType);
  return {
    eventData: value,
    eventType,
    monotonicMs,
    receivedAt: new Date(startedAt + monotonicMs + 100),
    sequence,
    telemetrySessionId: "telemetry-1",
  };
}
