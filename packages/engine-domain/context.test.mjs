import { describe, expect, it } from "vitest";

import {
  participantContextPolicy,
  validateParticipantContextSubmission,
  validateStoredParticipantContextSnapshot,
  withParticipantContextProvenance,
} from "./context.mjs";

describe("participant context evidence", () => {
  it("normalizes only the fixed privacy-bounded browser context schema", () => {
    const validated = validateParticipantContextSubmission(submission());
    expect(validated.snapshot).toMatchObject({
      browser: { language: "en-US", online: true, timeZone: "America/Los_Angeles" },
      capabilities: { cookiesEnabled: true, localStorage: "available" },
      display: { viewportHeight: 900, viewportWidth: 1440 },
      purpose: "presentation",
      schema: "vasi-participant-context/v1",
    });
    expect(validateStoredParticipantContextSnapshot(
      withParticipantContextProvenance(validated.snapshot),
    )).toEqual(withParticipantContextProvenance(validated.snapshot));
  });

  it("rejects unapproved fingerprinting and arbitrary detail", () => {
    expect(() => validateParticipantContextSubmission(submission({
      plugins: ["example"],
    }))).toThrow("unsupported fields");
    expect(() => validateParticipantContextSubmission(submission({
      display: { ...submission().snapshot.display, canvasHash: "secret" },
    }))).toThrow("unsupported fields");
    expect(() => validateParticipantContextSubmission(submission({
      connection: { effectiveType: "satellite" },
    }))).toThrow("connection.effectiveType");
  });

  it("bounds arrays, display values, sequence, and installation limits", () => {
    expect(() => validateParticipantContextSubmission(submission({
      browser: { languages: Array.from({ length: 9 }, (_, index) => `x-${index}`) },
    }))).toThrow("languages");
    expect(() => validateParticipantContextSubmission(submission({
      display: { viewportHeight: 900, viewportWidth: 100_000 },
    }))).toThrow("viewportWidth");
    expect(() => validateParticipantContextSubmission(submission({ sequence: 65 })))
      .toThrow("snapshot.sequence");
    expect(participantContextPolicy({
      ENGINE_PARTICIPANT_CONTEXT_MAX_SNAPSHOTS_PER_ACTIVITY: "24",
    }).maxSnapshotsPerActivity).toBe(24);
    expect(() => participantContextPolicy({
      ENGINE_PARTICIPANT_CONTEXT_MAX_SNAPSHOTS_PER_ACTIVITY: "1",
    })).toThrow("ENGINE_PARTICIPANT_CONTEXT_MAX_SNAPSHOTS_PER_ACTIVITY");
  });

  it("publishes explicit exclusions and reliability limitations", () => {
    const policy = participantContextPolicy();
    expect(policy.reliabilityClass).toBe("browser_reported");
    expect(policy.excludedSignals.join(" ")).toContain("plugin_or_font_enumeration");
    expect(policy.excludedSignals.join(" ")).toContain("precise_geolocation");
    expect(policy.limitations.join(" ")).toContain("does not prove identity");
  });
});

function submission(overrides = {}) {
  const snapshot = {
    browser: {
      language: "en-US",
      languages: ["en-US", "en"],
      online: true,
      timeZone: "America/Los_Angeles",
    },
    capabilities: {
      cookiesEnabled: true,
      localStorage: "available",
      pdfViewerEnabled: true,
      sessionStorage: "available",
    },
    clientOccurredAt: "2026-07-14T12:00:00.000Z",
    connection: { downlinkMbps: 10, effectiveType: "4g", rttMs: 50, saveData: false },
    display: {
      availableHeight: 1040,
      availableWidth: 1920,
      colorDepth: 24,
      devicePixelRatio: 2,
      pixelDepth: 24,
      screenHeight: 1080,
      screenWidth: 1920,
      viewportHeight: 900,
      viewportWidth: 1440,
    },
    id: "snapshot-1",
    input: { maxTouchPoints: 0 },
    monotonicMs: 10,
    preferences: {
      colorScheme: "dark",
      contrast: "no-preference",
      forcedColors: false,
      reducedMotion: true,
    },
    purpose: "presentation",
    schema: "vasi-participant-context/v1",
    sequence: 1,
    ...overrides,
  };
  return {
    activityId: "activity-1",
    contextSessionId: "context-session-1",
    handle: "h".repeat(43),
    interactionId: "interaction-1",
    snapshot,
  };
}
