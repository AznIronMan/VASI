import { describe, expect, it } from "vitest";

import {
  normalizeActivityDefinition,
  participantActivityProjection,
  validateActivityResponse,
} from "./activities.mjs";

function activity(type, content, responseMode = type) {
  return normalizeActivityDefinition({
    content,
    id: "step_one",
    responseMode,
    title: "Step one",
    type,
  });
}

describe("electronic activity contracts", () => {
  it("validates choices and preserves exact presented labels", () => {
    const definition = activity("single_choice", {
      choices: [{ id: "a", label: "Alpha" }, { id: "b", label: "Beta" }],
      prompt: "Choose one.",
    });
    expect(validateActivityResponse(definition, "b")).toMatchObject({
      display: "Beta",
      outcome: "b",
      value: "b",
    });
    expect(() => validateActivityResponse(definition, "c")).toThrow(/presented choices/);
  });

  it("scores questionnaires only from the immutable answer key", () => {
    const definition = activity("questionnaire", {
      passingPercent: 75,
      questions: [
        {
          choices: [{ id: "a", label: "A" }, { id: "b", label: "B" }],
          correctChoiceIds: ["b"],
          id: "q_one",
          points: 3,
          prompt: "First?",
          type: "single_choice",
        },
        {
          choices: [{ id: "x", label: "X" }, { id: "y", label: "Y" }, { id: "z", label: "Z" }],
          correctChoiceIds: ["x", "z"],
          id: "q_two",
          points: 1,
          prompt: "Second?",
          type: "multiple_choice",
        },
      ],
    });
    const result = validateActivityResponse(definition, { q_one: "b", q_two: ["x"] });
    expect(result.result).toMatchObject({ earnedPoints: 3, passed: true, percent: 75, totalPoints: 4 });
    const participant = participantActivityProjection(definition);
    expect(participant.content.questions[0]).not.toHaveProperty("correctChoiceIds");
    expect(participant.content.questions[0]).not.toHaveProperty("points");
  });

  it("stores a bounded normalized vector rather than a raster signature image", () => {
    const definition = activity("electronic_signature", {
      consentText: "I intend this electronic mark to be my signature.",
      prompt: "Sign below.",
      statement: "I approve the statement above.",
    });
    const response = validateActivityResponse(definition, {
      consent: true,
      method: "drawn",
      strokes: [[{ t: 0, x: 0.1, y: 0.2 }, { t: 10, x: 0.8, y: 0.9 }]],
    });
    expect(response.outcome).toBe("signed");
    expect(response.result.representation).toBe("normalized-vector-strokes/v1");
    expect(() => validateActivityResponse(definition, {
      consent: true,
      method: "drawn",
      strokes: [[{ x: -1, y: 0 }, { x: 1, y: 1 }]],
    })).toThrow(/drawing bounds/);
  });

  it("rejects executable and undeclared definition fields", () => {
    expect(() => normalizeActivityDefinition({
      content: { prompt: "Choose.", choices: [{ id: "a", label: "A" }, { id: "b", label: "B" }] },
      id: "step_one",
      javascript: "return true",
      responseMode: "single_choice",
      title: "Choice",
      type: "single_choice",
    })).toThrow(/unsupported/);
  });
});
