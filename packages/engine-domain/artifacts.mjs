export const DOCUMENT_ARTIFACT_ROLES = Object.freeze([
  "source_document",
  "derived_preview",
  "completed_document",
  "report",
  "manifest",
  "structured_export",
  "evidence_bundle",
]);

export const DOCUMENT_MEDIA_TYPES = Object.freeze([
  "application/pdf",
  "application/json",
  "application/xml",
  "application/vnd.oasis.opendocument.presentation",
  "application/vnd.oasis.opendocument.spreadsheet",
  "application/vnd.oasis.opendocument.text",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "text/csv",
  "text/markdown",
  "text/plain",
]);

export function validateArtifactCreateInput(value, limits) {
  const input = strictObject(value, "artifact", [
    "expectedByteLength", "mediaType", "originalFilename", "replacesArtifactId", "retentionPolicy",
    "role", "sourceArtifactId", "tenantId",
  ]);
  const expectedByteLength = safeInteger(
    input.expectedByteLength,
    "expectedByteLength",
    1,
    limits.maxBytes,
  );
  const mediaType = normalizedMediaType(input.mediaType);
  const role = input.role ?? "source_document";
  if (!DOCUMENT_ARTIFACT_ROLES.includes(role)) invalid("The artifact role is unsupported.");
  if (!["source_document", "derived_preview"].includes(role)) {
    invalid("Direct owner upload supports source documents and derived previews only.");
  }
  if (role === "derived_preview" && !input.sourceArtifactId) {
    invalid("A derived preview must identify its source artifact.");
  }
  const retentionInput = input.retentionPolicy === undefined
    ? {}
    : strictObject(input.retentionPolicy, "retention policy", ["profile"]);
  return Object.freeze({
    expectedByteLength,
    mediaType,
    originalFilename: filename(input.originalFilename),
    replacesArtifactId: optionalToken(input.replacesArtifactId, "replacesArtifactId"),
    retentionPolicy: Object.freeze({
      profile: optionalString(retentionInput.profile, "retentionPolicy.profile", 128) || "workflow_bound",
    }),
    role,
    sourceArtifactId: optionalToken(input.sourceArtifactId, "sourceArtifactId"),
    tenantId: token(input.tenantId, "tenantId"),
  });
}

export function validateArtifactChunkInput(value, limits) {
  const input = strictObject(value, "artifact chunk", ["artifactId", "data", "sequence", "tenantId"]);
  if (typeof input.data !== "string" || !input.data.length || input.data.length > Math.ceil(limits.chunkBytes / 3) * 4 + 8) {
    invalid("The artifact chunk is outside the transport limit.");
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(input.data)) {
    invalid("The artifact chunk encoding is invalid.");
  }
  return Object.freeze({
    artifactId: token(input.artifactId, "artifactId"),
    data: input.data,
    sequence: safeInteger(input.sequence, "sequence", 0, limits.maxChunks - 1),
    tenantId: token(input.tenantId, "tenantId"),
  });
}

export function validateArtifactReferenceInput(value, name = "artifact command") {
  const input = strictObject(value, name, ["artifactId", "disposition", "sequence", "tenantId"]);
  const disposition = input.disposition ?? "inline";
  if (!['inline', 'attachment'].includes(disposition)) invalid("The artifact disposition is unsupported.");
  return Object.freeze({
    artifactId: token(input.artifactId, "artifactId"),
    disposition,
    sequence: input.sequence === undefined ? undefined : safeInteger(input.sequence, "sequence", 0, 100_000),
    tenantId: token(input.tenantId, "tenantId"),
  });
}

export function validateArtifactListInput(value) {
  const input = strictObject(value, "artifact list", ["tenantId"]);
  return Object.freeze({ tenantId: token(input.tenantId, "tenantId") });
}

export function validateParticipantArtifactInput(value) {
  const input = strictObject(value, "participant artifact command", [
    "activityId", "artifactId", "disposition", "handle", "sequence",
  ]);
  const disposition = input.disposition ?? "inline";
  if (!['inline', 'attachment'].includes(disposition)) invalid("The artifact disposition is unsupported.");
  return Object.freeze({
    activityId: token(input.activityId, "activityId", 64),
    artifactId: token(input.artifactId, "artifactId"),
    disposition,
    handle: handle(input.handle),
    sequence: input.sequence === undefined ? undefined : safeInteger(input.sequence, "sequence", 0, 100_000),
  });
}

export function normalizedMediaType(value) {
  if (typeof value !== "string") invalid("The document media type is required.");
  const mediaType = value.split(";", 1)[0].trim().toLowerCase();
  if (!DOCUMENT_MEDIA_TYPES.includes(mediaType)) invalid("The document media type is unsupported.");
  return mediaType;
}

function filename(value) {
  if (typeof value !== "string") invalid("The original filename is required.");
  const normalized = value.normalize("NFC").trim();
  if (!normalized || normalized.length > 255 || /[\/\\\u0000-\u001f\u007f]/.test(normalized) || normalized === "." || normalized === "..") {
    invalid("The original filename is invalid.");
  }
  return normalized;
}

function handle(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) invalid("The participant handle is invalid.");
  return value;
}

function token(value, field, maximum = 128) {
  if (typeof value !== "string" || !value || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
    invalid(`The ${field} is invalid.`);
  }
  return value;
}

function optionalToken(value, field) {
  if (value === undefined || value === null || value === "") return undefined;
  return token(value, field);
}

function optionalString(value, field, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !value.trim() || value.trim().length > maximum) invalid(`The ${field} is invalid.`);
  return value.trim();
}

function safeInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`The ${field} must be a whole number between ${minimum} and ${maximum}.`);
  }
  return value;
}

function strictObject(value, name, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") invalid(`The ${name} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) invalid(`The ${name} field ${key} is unsupported.`);
  }
  return value;
}

function invalid(message) {
  const error = new Error(message);
  error.code = "INVALID_ARTIFACT";
  throw error;
}
