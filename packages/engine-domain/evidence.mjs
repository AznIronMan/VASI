import { hashCanonicalJSON } from "../engine-crypto/index.mjs";

export const RESPONSE_MODES = Object.freeze(["acknowledgement", "yes_no"]);

export function validateTenantInput(value) {
  const input = object(value, "tenant");
  return Object.freeze({
    name: boundedString(input.name, "name", 2, 160),
    slug: boundedString(input.slug, "slug", 2, 64).toLowerCase(),
  });
}

export function validateIssueInput(value, now = new Date()) {
  const input = object(value, "request");
  const responseMode = boundedString(input.responseMode, "responseMode", 1, 32);
  if (!RESPONSE_MODES.includes(responseMode)) {
    throw new Error("The response mode is unsupported.");
  }
  const intendedEmail = boundedString(input.intendedEmail, "intendedEmail", 3, 320).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+$/.test(intendedEmail)) {
    throw new Error("The intended participant email is invalid.");
  }
  const expiresAt = input.expiresAt ? new Date(input.expiresAt) : new Date(now.getTime() + 7 * 86_400_000);
  if (
    Number.isNaN(expiresAt.getTime()) ||
    expiresAt <= now ||
    expiresAt.getTime() > now.getTime() + 365 * 86_400_000
  ) {
    throw new Error("The request expiration must be within one year.");
  }
  const content = Object.freeze({
    prompt: boundedString(input.prompt, "prompt", 2, 1_000),
    terms: boundedString(input.terms, "terms", 2, 50_000),
  });
  return Object.freeze({
    content,
    contentHash: hashCanonicalJSON(content),
    expiresAt,
    intendedEmail,
    purpose: boundedString(input.purpose, "purpose", 2, 1_000),
    responseMode,
    tenantId: boundedString(input.tenantId, "tenantId", 1, 128),
    title: boundedString(input.title, "title", 2, 160),
  });
}

export function validateParticipantResponse(responseMode, value) {
  if (responseMode === "acknowledgement" && value === "acknowledged") return value;
  if (responseMode === "yes_no" && (value === "yes" || value === "no")) return value;
  throw new Error("The participant response is invalid for this activity.");
}

export function buildEvidenceManifest({
  assignment,
  completedAt,
  events,
  issuedAt,
  request,
  response,
  startedAt,
  tenant,
  workflow,
}) {
  if (!events.length) throw new Error("A sealed manifest requires evidence events.");
  return Object.freeze({
    assignment: {
      id: assignment.id,
      participantEmail: assignment.participantEmail,
      principalId: assignment.principalId,
    },
    evidence: {
      eventCount: events.length,
      eventHashes: events.map((event) => event.eventHash),
      firstSequence: events[0].sequence,
      headHash: events.at(-1).eventHash,
      lastSequence: events.at(-1).sequence,
    },
    manifestId: assignment.manifestId,
    outcome: { response },
    request: { id: request.id, purpose: request.purpose },
    schema: "vasi-evidence-manifest/v1",
    tenant: {
      id: tenant.id,
      name: tenant.name,
      ...(tenant.profile ? {
        profile: tenant.profile,
        profileBindingProvenance: tenant.profileBindingProvenance,
        profileHash: tenant.profileHash,
        profileRevisionId: tenant.profileRevisionId,
      } : {}),
    },
    timestamps: { completedAt, issuedAt, startedAt },
    workflow: {
      content: workflow.content,
      contentHash: workflow.contentHash,
      id: workflow.id,
      responseMode: workflow.responseMode,
      revision: workflow.revision,
      title: workflow.title,
    },
  });
}

function object(value, name) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error(`The ${name} payload must be an object.`);
  }
  return value;
}

function boundedString(value, field, minimum, maximum) {
  if (typeof value !== "string") throw new Error(`${field} must be a string.`);
  const normalized = value.trim();
  if (normalized.length < minimum || normalized.length > maximum) {
    throw new Error(`${field} must contain ${minimum} to ${maximum} characters.`);
  }
  return normalized;
}
