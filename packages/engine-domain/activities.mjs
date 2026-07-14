import { normalizeExternalMediaContent } from "./media.mjs";

export const ACTIVITY_TYPES = Object.freeze([
  "terms_response",
  "approval",
  "single_choice",
  "multiple_choice",
  "free_form",
  "electronic_signature",
  "document_review",
  "questionnaire",
  "external_media",
]);

export function normalizeActivityDefinition(value, index = 0) {
  const input = strictObject(value, `activity ${index + 1}`, [
    "content", "contractVersion", "id", "instructions", "responseMode", "title", "transition", "type",
  ]);
  const type = boundedString(input.type, "activity.type", 1, 64);
  if (!ACTIVITY_TYPES.includes(type)) invalidDefinition(`Unsupported activity type: ${type}.`);
  const contractVersion = input.contractVersion ?? 1;
  if (contractVersion !== 1) invalidDefinition("The activity contract version is unsupported.");
  const expectedMode = responseModeForType(type, input.responseMode);
  const transitionInput = input.transition === undefined
    ? { cases: [] }
    : strictObject(input.transition, "activity.transition", ["cases", "defaultTo"]);
  const cases = transitionInput.cases ?? [];
  if (!Array.isArray(cases) || cases.length > 16) {
    invalidDefinition("An activity may define at most sixteen branches.");
  }
  return Object.freeze({
    content: normalizeContent(type, input.content),
    contractVersion,
    id: identifier(input.id, "activity.id"),
    instructions: optionalString(input.instructions, "activity.instructions", 2_000),
    responseMode: expectedMode,
    title: boundedString(input.title, "activity.title", 2, 160),
    transition: Object.freeze({
      cases: Object.freeze(cases.map((entry, branchIndex) => normalizeBranch(entry, branchIndex))),
      defaultTo: normalizeDestination(transitionInput.defaultTo),
    }),
    type,
  });
}

export function branchValuesForActivity(activity) {
  switch (activity.type) {
    case "terms_response":
      return activity.responseMode === "acknowledgement" ? ["acknowledged"] : ["yes", "no"];
    case "approval": return ["approved", "disapproved", "declined"];
    case "single_choice": return activity.content.choices.map((choice) => choice.id);
    case "electronic_signature": return ["signed"];
    case "document_review": return ["reviewed"];
    case "questionnaire": return ["passed", "failed"];
    case "external_media": return ["completed"];
    default: return [];
  }
}

export function validateActivityResponse(activity, response) {
  let value;
  let display;
  let outcome;
  let result;
  switch (activity.type) {
    case "terms_response": {
      const allowed = activity.responseMode === "acknowledgement" ? ["acknowledged"] : ["yes", "no"];
      value = oneOf(response, allowed, "response");
      display = activity.responseMode === "acknowledgement"
        ? activity.content.acknowledgementLabel || "I acknowledge these terms."
        : value === "yes" ? activity.content.yesLabel || "Yes" : activity.content.noLabel || "No";
      outcome = value;
      break;
    }
    case "approval": {
      value = oneOf(response, ["approved", "disapproved", "declined"], "response");
      display = activity.content.labels[value];
      outcome = value;
      break;
    }
    case "single_choice": {
      const choice = activity.content.choices.find((entry) => entry.id === response);
      if (!choice) invalidResponse("Select one of the presented choices.");
      value = choice.id;
      display = choice.label;
      outcome = value;
      break;
    }
    case "multiple_choice": {
      if (!Array.isArray(response)) invalidResponse("The response must be a list of choices.");
      const values = response.map((entry) => boundedResponseString(entry, 64));
      if (new Set(values).size !== values.length) invalidResponse("A choice cannot be selected more than once.");
      if (values.length < activity.content.minSelections || values.length > activity.content.maxSelections) {
        invalidResponse("The number of selected choices is outside the allowed range.");
      }
      const choices = values.map((entry) => activity.content.choices.find((choice) => choice.id === entry));
      if (choices.some((choice) => !choice)) invalidResponse("Select only presented choices.");
      value = Object.freeze(values);
      display = choices.map((choice) => choice.label).join("; ");
      outcome = "submitted";
      break;
    }
    case "free_form": {
      if (typeof response !== "string") invalidResponse("The response must be text.");
      if (response.length > activity.content.maxLength || response.trim().length < activity.content.minLength) {
        invalidResponse("The text response is outside the allowed length.");
      }
      if (/\u0000/.test(response)) invalidResponse("The text response contains an unsupported character.");
      value = response;
      display = response;
      outcome = "submitted";
      break;
    }
    case "electronic_signature": {
      const signature = strictResponseObject(response, "electronic signature", ["consent", "method", "name", "strokes"]);
      if (signature.consent !== true) invalidResponse("Electronic-signature consent is required.");
      if (!activity.content.methods.includes(signature.method)) {
        invalidResponse("The selected signature method is unavailable.");
      }
      if (signature.method === "typed") {
        value = Object.freeze({
          consent: true,
          method: "typed",
          name: boundedResponseString(signature.name, 160, 2),
        });
        display = `Typed electronic signature: ${value.name}`;
      } else {
        value = Object.freeze({
          consent: true,
          method: "drawn",
          strokes: normalizeStrokes(signature.strokes),
        });
        display = "Drawn electronic signature";
      }
      outcome = "signed";
      result = Object.freeze({
        consentText: activity.content.consentText,
        method: value.method,
        representation: value.method === "drawn" ? "normalized-vector-strokes/v1" : "typed-name/v1",
      });
      break;
    }
    case "document_review": {
      value = oneOf(response, ["reviewed"], "response");
      display = activity.content.responseLabel;
      outcome = "reviewed";
      break;
    }
    case "questionnaire": {
      const answers = strictResponseObject(response, "questionnaire response", activity.content.questions.map((q) => q.id));
      const normalizedAnswers = {};
      let earnedPoints = 0;
      let totalPoints = 0;
      const questionResults = [];
      for (const question of activity.content.questions) {
        const answer = answers[question.id];
        if (answer === undefined && question.required) invalidResponse(`An answer is required for ${question.id}.`);
        let normalized;
        let correct = false;
        if (question.type === "single_choice") {
          if (answer === undefined) normalized = undefined;
          else {
            normalized = boundedResponseString(answer, 64);
            if (!question.choices.some((choice) => choice.id === normalized)) {
              invalidResponse(`The answer for ${question.id} is unsupported.`);
            }
            correct = question.correctChoiceIds.includes(normalized);
          }
        } else {
          if (answer === undefined) normalized = undefined;
          else {
            if (!Array.isArray(answer)) invalidResponse(`The answer for ${question.id} must be a list.`);
            normalized = answer.map((entry) => boundedResponseString(entry, 64));
            if (new Set(normalized).size !== normalized.length ||
              normalized.some((entry) => !question.choices.some((choice) => choice.id === entry))) {
              invalidResponse(`The answer for ${question.id} is unsupported.`);
            }
            correct = sameSet(normalized, question.correctChoiceIds);
          }
        }
        if (normalized !== undefined) normalizedAnswers[question.id] = normalized;
        totalPoints += question.points;
        if (correct) earnedPoints += question.points;
        questionResults.push(Object.freeze({ correct, id: question.id, pointsEarned: correct ? question.points : 0 }));
      }
      const percent = totalPoints ? Math.round((earnedPoints / totalPoints) * 10_000) / 100 : 100;
      const passed = percent >= activity.content.passingPercent;
      value = Object.freeze(normalizedAnswers);
      display = `${earnedPoints} of ${totalPoints} points (${percent}%) — ${passed ? "passed" : "not passed"}`;
      outcome = passed ? "passed" : "failed";
      result = Object.freeze({
        earnedPoints,
        passed,
        passingPercent: activity.content.passingPercent,
        percent,
        questionResults: Object.freeze(questionResults),
        totalPoints,
      });
      break;
    }
    case "external_media": {
      const mediaResponse = strictResponseObject(response, "external media response", ["acknowledged", "method"]);
      const method = oneOf(mediaResponse.method, ["playback", "acknowledgement"], "media completion method");
      const mode = activity.content.completionPolicy.mode;
      if (method === "playback" && mode === "acknowledgement") {
        invalidResponse("This activity does not allow playback-based completion.");
      }
      if (method === "acknowledgement" && mode === "playback") {
        invalidResponse("This activity requires validated playback completion.");
      }
      if (method === "acknowledgement" && mediaResponse.acknowledged !== true) {
        invalidResponse("Media-review acknowledgement is required.");
      }
      value = Object.freeze({ acknowledged: method === "acknowledgement" ? true : undefined, method });
      display = method === "playback"
        ? `Playback met the configured ${activity.content.completionPolicy.thresholdPercent}% threshold.`
        : activity.content.acknowledgementLabel;
      outcome = "completed";
      result = Object.freeze({
        capability: activity.content.descriptor.capability,
        completionMethod: method,
        completionPolicy: activity.content.completionPolicy,
      });
      break;
    }
    default:
      invalidResponse("The activity response contract is unavailable.");
  }
  return Object.freeze({ display, outcome, result, value });
}

export function participantActivityProjection(activity) {
  const content = activity.type === "questionnaire"
    ? Object.freeze({
        instructions: activity.content.instructions,
        passingPercent: activity.content.passingPercent,
        questions: Object.freeze(activity.content.questions.map((question) => Object.freeze({
          choices: question.choices,
          id: question.id,
          prompt: question.prompt,
          required: question.required,
          type: question.type,
        }))),
        resultDisclosure: activity.content.resultDisclosure,
      })
    : activity.content;
  return Object.freeze({
    content,
    contentHash: activity.contentHash,
    contractVersion: activity.contractVersion,
    id: activity.id,
    instructions: activity.instructions,
    responseMode: activity.responseMode,
    title: activity.title,
    type: activity.type,
  });
}

function normalizeContent(type, value) {
  switch (type) {
    case "terms_response": return normalizeTerms(value);
    case "approval": return normalizeApproval(value);
    case "single_choice": return normalizeSingleChoice(value);
    case "multiple_choice": return normalizeMultipleChoice(value);
    case "free_form": return normalizeFreeForm(value);
    case "electronic_signature": return normalizeSignature(value);
    case "document_review": return normalizeDocument(value);
    case "questionnaire": return normalizeQuestionnaire(value);
    case "external_media": return normalizeExternalMediaContent(value);
    default: invalidDefinition("The activity content contract is unavailable.");
  }
}

function normalizeTerms(value) {
  const input = strictObject(value, "activity.content", [
    "acknowledgementLabel", "noLabel", "prompt", "terms", "yesLabel",
  ]);
  return Object.freeze({
    acknowledgementLabel: optionalString(input.acknowledgementLabel, "acknowledgementLabel", 160) || "I acknowledge these terms.",
    noLabel: optionalString(input.noLabel, "noLabel", 160) || "No",
    prompt: boundedString(input.prompt, "activity.content.prompt", 2, 1_000),
    terms: boundedString(input.terms, "activity.content.terms", 2, 50_000),
    yesLabel: optionalString(input.yesLabel, "yesLabel", 160) || "Yes",
  });
}

function normalizeApproval(value) {
  const input = strictObject(value, "activity.content", ["labels", "prompt", "statement"]);
  const labels = input.labels === undefined ? {} : strictObject(input.labels, "approval labels", [
    "approved", "declined", "disapproved",
  ]);
  return Object.freeze({
    labels: Object.freeze({
      approved: optionalString(labels.approved, "labels.approved", 160) || "Approve",
      declined: optionalString(labels.declined, "labels.declined", 160) || "Decline to decide",
      disapproved: optionalString(labels.disapproved, "labels.disapproved", 160) || "Disapprove",
    }),
    prompt: boundedString(input.prompt, "activity.content.prompt", 2, 1_000),
    statement: boundedString(input.statement, "activity.content.statement", 2, 50_000),
  });
}

function normalizeSingleChoice(value) {
  const input = strictObject(value, "activity.content", ["choices", "prompt"]);
  return Object.freeze({
    choices: normalizeChoices(input.choices),
    prompt: boundedString(input.prompt, "activity.content.prompt", 2, 2_000),
  });
}

function normalizeMultipleChoice(value) {
  const input = strictObject(value, "activity.content", ["choices", "maxSelections", "minSelections", "prompt"]);
  const choices = normalizeChoices(input.choices);
  const minSelections = safeInteger(input.minSelections ?? 1, "minSelections", 0, choices.length);
  const maxSelections = safeInteger(input.maxSelections ?? choices.length, "maxSelections", Math.max(1, minSelections), choices.length);
  return Object.freeze({ choices, maxSelections, minSelections, prompt: boundedString(input.prompt, "activity.content.prompt", 2, 2_000) });
}

function normalizeFreeForm(value) {
  const input = strictObject(value, "activity.content", ["maxLength", "minLength", "multiline", "prompt"]);
  const minLength = safeInteger(input.minLength ?? 1, "minLength", 0, 10_000);
  return Object.freeze({
    maxLength: safeInteger(input.maxLength ?? 2_000, "maxLength", Math.max(1, minLength), 10_000),
    minLength,
    multiline: input.multiline !== false,
    prompt: boundedString(input.prompt, "activity.content.prompt", 2, 2_000),
  });
}

function normalizeSignature(value) {
  const input = strictObject(value, "activity.content", [
    "consentText", "drawnSignatureLabel", "methods", "prompt", "statement", "typedNameLabel",
  ]);
  const methods = input.methods ?? ["typed", "drawn"];
  if (!Array.isArray(methods) || !methods.length || methods.length > 2 ||
      new Set(methods).size !== methods.length || methods.some((method) => !["typed", "drawn"].includes(method))) {
    invalidDefinition("Signature methods must contain typed, drawn, or both.");
  }
  return Object.freeze({
    consentText: boundedString(input.consentText, "activity.content.consentText", 10, 4_000),
    drawnSignatureLabel: optionalString(input.drawnSignatureLabel, "drawnSignatureLabel", 160) || "Draw your signature",
    methods: Object.freeze([...methods]),
    prompt: boundedString(input.prompt, "activity.content.prompt", 2, 1_000),
    statement: boundedString(input.statement, "activity.content.statement", 2, 50_000),
    typedNameLabel: optionalString(input.typedNameLabel, "typedNameLabel", 160) || "Type your full legal name",
  });
}

function normalizeDocument(value) {
  const input = strictObject(value, "activity.content", [
    "artifact", "artifactId", "displayName", "prompt", "responseLabel",
  ]);
  return Object.freeze({
    artifactId: boundedString(input.artifactId, "activity.content.artifactId", 1, 128),
    displayName: boundedString(input.displayName, "activity.content.displayName", 1, 255),
    prompt: boundedString(input.prompt, "activity.content.prompt", 2, 1_000),
    responseLabel: optionalString(input.responseLabel, "responseLabel", 160) || "I reviewed this document.",
  });
}

function normalizeQuestionnaire(value) {
  const input = strictObject(value, "activity.content", [
    "instructions", "passingPercent", "questions", "resultDisclosure",
  ]);
  if (!Array.isArray(input.questions) || !input.questions.length || input.questions.length > 50) {
    invalidDefinition("A questionnaire requires 1 to 50 questions.");
  }
  const questions = input.questions.map(normalizeQuestion);
  if (new Set(questions.map((question) => question.id)).size !== questions.length) {
    invalidDefinition("Question IDs must be unique.");
  }
  const resultDisclosure = input.resultDisclosure ?? "pass_fail_and_score";
  if (!['pass_fail', 'pass_fail_and_score'].includes(resultDisclosure)) {
    invalidDefinition("The questionnaire result-disclosure policy is unsupported.");
  }
  return Object.freeze({
    instructions: optionalString(input.instructions, "questionnaire.instructions", 4_000),
    passingPercent: safeInteger(input.passingPercent ?? 70, "passingPercent", 0, 100),
    questions: Object.freeze(questions),
    resultDisclosure,
  });
}

function normalizeQuestion(value, index) {
  const input = strictObject(value, `question ${index + 1}`, [
    "choices", "correctChoiceIds", "id", "points", "prompt", "required", "type",
  ]);
  const type = input.type ?? "single_choice";
  if (!['single_choice', 'multiple_choice'].includes(type)) invalidDefinition("The question type is unsupported.");
  const choices = normalizeChoices(input.choices, `question ${index + 1}`);
  const correctChoiceIds = input.correctChoiceIds;
  if (!Array.isArray(correctChoiceIds) || !correctChoiceIds.length ||
      new Set(correctChoiceIds).size !== correctChoiceIds.length ||
      correctChoiceIds.some((id) => !choices.some((choice) => choice.id === id)) ||
      (type === "single_choice" && correctChoiceIds.length !== 1)) {
    invalidDefinition("Each scored question requires valid correct choice IDs.");
  }
  return Object.freeze({
    choices,
    correctChoiceIds: Object.freeze([...correctChoiceIds]),
    id: identifier(input.id, "question.id"),
    points: safeInteger(input.points ?? 1, "question.points", 1, 1_000),
    prompt: boundedString(input.prompt, "question.prompt", 2, 2_000),
    required: input.required !== false,
    type,
  });
}

function normalizeChoices(value, name = "activity") {
  if (!Array.isArray(value) || value.length < 2 || value.length > 50) {
    invalidDefinition(`${name} requires 2 to 50 choices.`);
  }
  const choices = value.map((entry, index) => {
    const input = strictObject(entry, `choice ${index + 1}`, ["description", "id", "label"]);
    return Object.freeze({
      description: optionalString(input.description, "choice.description", 1_000),
      id: identifier(input.id, "choice.id"),
      label: boundedString(input.label, "choice.label", 1, 500),
    });
  });
  if (new Set(choices.map((choice) => choice.id)).size !== choices.length) {
    invalidDefinition("Choice IDs must be unique.");
  }
  return Object.freeze(choices);
}

function responseModeForType(type, supplied) {
  if (type === "terms_response") {
    const mode = boundedString(supplied, "activity.responseMode", 1, 32);
    if (!['acknowledgement', 'yes_no'].includes(mode)) invalidDefinition("The response mode is unsupported.");
    return mode;
  }
  const expected = type;
  if (supplied !== undefined && supplied !== expected) {
    invalidDefinition(`The response mode for ${type} must be ${expected}.`);
  }
  return expected;
}

function normalizeBranch(value, index) {
  const input = strictObject(value, `branch ${index + 1}`, ["to", "when"]);
  const when = strictObject(input.when, "branch.when", ["equals"]);
  return Object.freeze({
    to: normalizeDestination(input.to, true),
    when: Object.freeze({ equals: boundedString(when.equals, "branch.when.equals", 1, 64) }),
  });
}

function normalizeStrokes(value) {
  if (!Array.isArray(value) || !value.length || value.length > 50) {
    invalidResponse("A drawn signature requires 1 to 50 strokes.");
  }
  let pointCount = 0;
  const strokes = value.map((stroke) => {
    if (!Array.isArray(stroke) || stroke.length < 2 || stroke.length > 1_000) {
      invalidResponse("Each signature stroke requires 2 to 1000 points.");
    }
    pointCount += stroke.length;
    if (pointCount > 5_000) invalidResponse("The drawn signature contains too many points.");
    return Object.freeze(stroke.map((point) => {
      const input = strictResponseObject(point, "signature point", ["t", "x", "y"]);
      if (!Number.isFinite(input.x) || input.x < 0 || input.x > 1 ||
          !Number.isFinite(input.y) || input.y < 0 || input.y > 1 ||
          (input.t !== undefined && (!Number.isSafeInteger(input.t) || input.t < 0 || input.t > 86_400_000))) {
        invalidResponse("A signature point is outside the normalized drawing bounds.");
      }
      return Object.freeze({ t: input.t, x: roundCoordinate(input.x), y: roundCoordinate(input.y) });
    }));
  });
  return Object.freeze(strokes);
}

function sameSet(left, right) {
  return left.length === right.length && left.every((entry) => right.includes(entry));
}

function roundCoordinate(value) {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function oneOf(value, allowed, field) {
  if (typeof value !== "string" || !allowed.includes(value)) invalidResponse(`The ${field} is unsupported.`);
  return value;
}

function strictObject(value, name, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") invalidDefinition(`The ${name} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) invalidDefinition(`The ${name} field ${key} is unsupported.`);
  }
  return value;
}

function strictResponseObject(value, name, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") invalidResponse(`The ${name} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) invalidResponse(`The ${name} field ${key} is unsupported.`);
  }
  return value;
}

function identifier(value, field) {
  const result = boundedString(value, field, 1, 64);
  if (!/^[a-z][a-z0-9_-]{0,63}$/.test(result)) invalidDefinition(`${field} has an invalid format.`);
  return result;
}

function normalizeDestination(value, required = false) {
  if (value === null) return null;
  if (value === undefined && !required) return undefined;
  return identifier(value, "transition destination");
}

function safeInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalidDefinition(`${field} must be a whole number between ${minimum} and ${maximum}.`);
  }
  return value;
}

function boundedString(value, field, minimum, maximum) {
  if (typeof value !== "string") invalidDefinition(`${field} must be a string.`);
  const normalized = value.trim();
  if (normalized.length < minimum || normalized.length > maximum) {
    invalidDefinition(`${field} must contain ${minimum} to ${maximum} characters.`);
  }
  return normalized;
}

function optionalString(value, field, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  return boundedString(value, field, 1, maximum);
}

function boundedResponseString(value, maximum, minimum = 1) {
  if (typeof value !== "string" || value.length > maximum || value.trim().length < minimum) {
    invalidResponse("A response value is outside the allowed length.");
  }
  return value;
}

function invalidDefinition(message) {
  const error = new Error(message);
  error.code = "INVALID_WORKFLOW";
  throw error;
}

function invalidResponse(message) {
  const error = new Error(message);
  error.code = "INVALID_ACTIVITY_RESPONSE";
  throw error;
}
