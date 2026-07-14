export const REQUESTER_SNAPSHOT_SCHEMA = "vasi-requester-snapshot/v1";

const PROVENANCE = Object.freeze([
  "authenticated_actor_at_issuance",
  "evidence_event_backfill",
  "membership_backfill",
  "legacy_unavailable",
]);

export function requesterSnapshot(actor) {
  const principalId = boundedText(actor?.principalId, 512);
  const email = normalizedEmail(actor?.email);
  if (!principalId || !email) throw new Error("requester_identity_required");
  return Object.freeze({
    email,
    principalId,
    provenance: "authenticated_actor_at_issuance",
    relationship: "requesting_organization",
    schema: REQUESTER_SNAPSHOT_SCHEMA,
  });
}

export function validateRequesterSnapshot(value, expectedPrincipalId) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error("requester_snapshot_invalid");
  }
  const principalId = boundedText(value.principalId, 512);
  const email = value.email === null ? null : normalizedEmail(value.email);
  const keys = Object.keys(value).sort();
  if (
    JSON.stringify(keys) !== JSON.stringify([
      "email", "principalId", "provenance", "relationship", "schema",
    ]) ||
    value.schema !== REQUESTER_SNAPSHOT_SCHEMA ||
    value.relationship !== "requesting_organization" ||
    !principalId ||
    (expectedPrincipalId && principalId !== expectedPrincipalId) ||
    !PROVENANCE.includes(value.provenance) ||
    (value.provenance !== "legacy_unavailable" && !email)
  ) {
    throw new Error("requester_snapshot_invalid");
  }
  return Object.freeze({
    email,
    principalId,
    provenance: value.provenance,
    relationship: value.relationship,
    schema: value.schema,
  });
}

function normalizedEmail(value) {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized.length > 320 || !/^[^@\s]+@[^@\s]+$/.test(normalized)) return undefined;
  return normalized;
}

function boundedText(value, maximum) {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized && normalized.length <= maximum ? normalized : undefined;
}
