import { describe, expect, it } from "vitest";

import {
  calculateMediaSummary,
  normalizeExternalMediaContent,
  validateMediaEventBatch,
  validateMediaOriginPolicy,
} from "./media.mjs";

function youtubeContent(overrides = {}) {
  return normalizeExternalMediaContent({
    descriptor: {
      durationSeconds: 10,
      kind: "video",
      provider: "youtube",
      sourceUrl: "https://youtu.be/M7lc1UVf-VE",
      title: "Provider training",
    },
    prompt: "Watch the training and confirm completion.",
    ...overrides,
  });
}

describe("external media domain", () => {
  it("normalizes provider-owned embeds and never accepts raw markup", () => {
    const content = youtubeContent();
    expect(content.descriptor).toMatchObject({
      capability: "instrumented_player",
      embedUrl: "https://www.youtube-nocookie.com/embed/M7lc1UVf-VE?enablejsapi=1&rel=0&playsinline=1",
      itemId: "M7lc1UVf-VE",
      provider: "youtube",
    });
    expect(() => youtubeContent({ iframe: "<iframe>" })).toThrow(/unsupported/);
    expect(() => youtubeContent({ descriptor: {
      kind: "video",
      provider: "youtube",
      sourceUrl: "https://evil.example/watch?v=M7lc1UVf-VE",
      title: "Wrong host",
    } })).toThrow(/host/);
  });

  it("downgrades providers when playback or version evidence is unavailable", () => {
    const google = normalizeExternalMediaContent({
      descriptor: {
        kind: "video",
        provider: "google_drive",
        sourceUrl: "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/preview",
        title: "Drive-hosted training",
      },
      prompt: "Review the hosted training.",
    });
    const dropbox = normalizeExternalMediaContent({
      descriptor: {
        kind: "video",
        provider: "dropbox",
        sourceUrl: "https://www.dropbox.com/s/example/training.mp4?dl=0",
        title: "Dropbox-hosted training",
      },
      prompt: "Open the hosted training.",
    });
    expect(google.descriptor.capability).toBe("generic_embed");
    expect(dropbox.descriptor.capability).toBe("external_link");
    expect(() => normalizeExternalMediaContent({
      completionPolicy: { mode: "playback" },
      descriptor: {
        kind: "video",
        provider: "google_drive",
        sourceUrl: "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/preview",
        title: "Drive-hosted training",
      },
      prompt: "Invalid claim",
    })).toThrow(/cannot require playback/);
  });

  it("requires installation allowlisting for generic media origins", () => {
    const content = normalizeExternalMediaContent({
      descriptor: {
        embedUrl: "https://media.example.test/embed/42",
        kind: "presentation",
        provider: "generic",
        sourceUrl: "https://media.example.test/items/42",
        title: "Generic presentation",
      },
      prompt: "Review the presentation.",
    });
    expect(() => validateMediaOriginPolicy(content, [])).toThrow(/not enabled/);
    expect(validateMediaOriginPolicy(content, ["https://media.example.test"]).descriptor.capability)
      .toBe("generic_embed");
  });

  it("rejects player telemetry for a generic iframe", () => {
    const content = normalizeExternalMediaContent({
      descriptor: {
        kind: "video",
        provider: "google_drive",
        sourceUrl: "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/preview",
        title: "Drive video",
      },
      prompt: "Review this video.",
    });
    expect(() => validateMediaEventBatch({
      activityId: "media",
      batchId: "batch-1",
      events: [{ id: "event-1", monotonicMs: 1, sequence: 1, type: "play" }],
      handle: "h".repeat(43),
      interactionId: "interaction-1",
      telemetrySessionId: "telemetry-1",
    }, content)).toThrow(/capability/);
  });

  it("credits only plausible visible playback intervals and not seeks or gaps", () => {
    const content = youtubeContent({
      completionPolicy: { minimumUniqueSeconds: 5, mode: "playback", thresholdPercent: 50 },
      telemetryPolicy: { heartbeatSeconds: 2, idleSeconds: 10, maxCreditedGapSeconds: 5 },
    });
    const raw = [
      ["presented", 0, {}],
      ["visible", 1, {}],
      ["focus", 2, {}],
      ["interaction", 3, {}],
      ["play", 4, {}],
      ["position", 1_000, { durationSeconds: 10, positionSeconds: 0 }],
      ["position", 3_000, { durationSeconds: 10, positionSeconds: 2 }],
      ["seek", 3_100, { fromSeconds: 2, toSeconds: 8 }],
      ["position", 3_200, { durationSeconds: 10, positionSeconds: 8 }],
      ["position", 5_200, { durationSeconds: 10, positionSeconds: 10 }],
      ["ended", 5_300, { durationSeconds: 10, positionSeconds: 10 }],
    ];
    const events = raw.map(([type, monotonicMs, fields], index) => ({
      event: { id: `e-${index}`, monotonicMs, sequence: index + 1, type, ...fields },
      interactionId: "session-1",
    }));
    const summary = calculateMediaSummary(content, events);
    expect(summary.playback.uniqueMilliseconds).toBe(4_000);
    expect(summary.playback.percentBasisPoints).toBe(4_000);
    expect(summary.playback.completionMet).toBe(false);
    expect(summary.playback.seekCount).toBe(1);
    expect(summary.sessionIntegrity).toEqual({ disconnectCount: 0, incompleteSessionCount: 1 });

    events.splice(8, 0, {
      event: { id: "gap", monotonicMs: 20_000, positionSeconds: 9, sequence: 9, type: "position" },
      interactionId: "session-1",
    });
    const gapSummary = calculateMediaSummary(content, events);
    expect(gapSummary.gaps.count).toBeGreaterThan(0);
    expect(gapSummary.confidence.level).toBe("low");
  });

  it("keeps open, visible, engaged, and playback values distinct", () => {
    const content = youtubeContent();
    const summary = calculateMediaSummary(content, [
      { interactionId: "one", event: { id: "1", monotonicMs: 0, sequence: 1, type: "presented" } },
      { interactionId: "one", event: { id: "2", monotonicMs: 1_000, sequence: 2, type: "visible" } },
      { interactionId: "one", event: { id: "3", monotonicMs: 2_000, sequence: 3, type: "focus" } },
      { interactionId: "one", event: { id: "4", monotonicMs: 3_000, sequence: 4, type: "interaction" } },
      { interactionId: "one", event: { id: "5", monotonicMs: 5_000, sequence: 5, type: "heartbeat" } },
      { interactionId: "one", event: { id: "6", monotonicMs: 40_000, sequence: 6, type: "disconnect" } },
    ]);
    expect(summary.engagement.openMilliseconds).toBe(5_000);
    expect(summary.engagement.visibleMilliseconds).toBe(3_000);
    expect(summary.engagement.engagedMilliseconds).toBe(2_000);
    expect(summary.playback.uniqueMilliseconds).toBe(0);
    expect(summary.gaps.count).toBe(1);
    expect(summary.sessionIntegrity).toEqual({ disconnectCount: 1, incompleteSessionCount: 0 });
  });
});
