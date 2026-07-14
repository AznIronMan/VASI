import { describe, expect, it } from "vitest";

import {
  buildEvidenceManifest,
  validateIssueInput,
  validateParticipantResponse,
} from "./evidence.mjs";

describe("first evidence slice domain", () => {
  it("freezes a bounded issued request and exact content hash", () => {
    const value = validateIssueInput(
      {
        intendedEmail: "Person@Example.com",
        prompt: "Do you accept?",
        purpose: "Training acknowledgement",
        responseMode: "yes_no",
        tenantId: "tenant-1",
        terms: "These are the exact terms.",
        title: "Training terms",
      },
      new Date("2026-01-01T00:00:00Z"),
    );

    expect(value.intendedEmail).toBe("person@example.com");
    expect(value.contentHash).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(value)).toBe(true);
  });

  it("enforces the configured response vocabulary", () => {
    expect(validateParticipantResponse("acknowledgement", "acknowledged")).toBe(
      "acknowledged",
    );
    expect(() => validateParticipantResponse("yes_no", "maybe")).toThrow(
      "invalid",
    );
  });

  it("binds the manifest to the ordered evidence hashes", () => {
    const manifest = buildEvidenceManifest({
      assignment: {
        id: "assignment-1",
        manifestId: "manifest-1",
        participantEmail: "person@example.com",
        principalId: "principal-1",
      },
      completedAt: "2026-01-01T00:05:00.000Z",
      events: [
        { eventHash: "a".repeat(64), sequence: 1 },
        { eventHash: "b".repeat(64), sequence: 2 },
      ],
      issuedAt: "2026-01-01T00:00:00.000Z",
      request: { id: "request-1", purpose: "Purpose" },
      response: "yes",
      startedAt: "2026-01-01T00:04:00.000Z",
      tenant: { id: "tenant-1", name: "Example" },
      workflow: {
        content: { prompt: "Accept?", terms: "Terms" },
        contentHash: "c".repeat(64),
        id: "workflow-1",
        responseMode: "yes_no",
        revision: 1,
        title: "Terms",
      },
    });

    expect(manifest.evidence.headHash).toBe("b".repeat(64));
    expect(manifest.evidence.eventCount).toBe(2);
  });
});
