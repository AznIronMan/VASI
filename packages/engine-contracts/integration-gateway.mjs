import { canonicalJSON } from "../engine-crypto/index.mjs";

export const INTEGRATION_DELIVERY_SCHEMA = "vasi-integration-delivery/v1";
export const ARTIFACT_SCAN_SCHEMA = "vasi-artifact-scan/v1";

export function validateArtifactScanCommand(value) {
  const input = strictObject(value, "artifact scan", [
    "artifactId", "byteLength", "capability", "mediaType", "scanRequestId", "schema",
    "sha256", "tenantId",
  ]);
  if (input.schema !== ARTIFACT_SCAN_SCHEMA) invalidScan("The artifact scan schema is unsupported.");
  if (input.capability !== "document.malware_scan") {
    invalidScan("The artifact scan capability is unsupported.");
  }
  return Object.freeze({
    artifactId: token(input.artifactId, "artifactId", invalidScan),
    byteLength: safeInteger(input.byteLength, "byteLength", 1, 268_435_456, invalidScan),
    capability: "document.malware_scan",
    mediaType: mediaType(input.mediaType),
    scanRequestId: token(input.scanRequestId, "scanRequestId", invalidScan),
    schema: ARTIFACT_SCAN_SCHEMA,
    sha256: sha256(input.sha256),
    tenantId: token(input.tenantId, "tenantId", invalidScan),
  });
}

export function validateIntegrationDeliveryCommand(value) {
  const input = strictObject(value, "integration delivery", [
    "attempt", "capability", "idempotencyKey", "jobId", "payload", "schema", "tenantId",
  ]);
  if (input.schema !== INTEGRATION_DELIVERY_SCHEMA) invalid("The integration delivery schema is unsupported.");
  if (input.capability !== "notification.delivery") invalid("The integration capability is unsupported.");
  const payload = validateNotificationPayload(input.payload);
  if (Buffer.byteLength(canonicalJSON(payload), "utf8") > 32_768) {
    invalid("The integration payload is too large.");
  }
  return Object.freeze({
    attempt: safeInteger(input.attempt, "attempt", 1, 100),
    capability: "notification.delivery",
    idempotencyKey: token(input.idempotencyKey, "idempotencyKey"),
    jobId: token(input.jobId, "jobId"),
    payload,
    schema: INTEGRATION_DELIVERY_SCHEMA,
    tenantId: token(input.tenantId, "tenantId"),
  });
}

function validateNotificationPayload(value) {
  const input = strictObject(value, "notification payload", [
    "dueAt", "eventType", "participantPath", "recipient", "requestId", "tenant", "title",
  ]);
  if (!["request.completed", "request.issued", "request.reminder"].includes(input.eventType)) {
    invalid("The notification event type is unsupported.");
  }
  const tenant = strictObject(input.tenant, "notification tenant", ["id", "name"]);
  const participantPath = optionalString(input.participantPath, "participantPath", 2_048);
  if (participantPath && !/^\/r\/[A-Za-z0-9_-]{20,512}$/.test(participantPath)) {
    invalid("The participant path is invalid.");
  }
  return Object.freeze({
    dueAt: optionalDate(input.dueAt, "dueAt"),
    eventType: input.eventType,
    participantPath,
    recipient: email(input.recipient),
    requestId: token(input.requestId, "requestId"),
    tenant: Object.freeze({
      id: token(tenant.id, "tenant.id"),
      name: boundedString(tenant.name, "tenant.name", 1, 160),
    }),
    title: boundedString(input.title, "title", 1, 160),
  });
}

function strictObject(value, name, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") invalid(`The ${name} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) invalid(`The ${name} field ${key} is unsupported.`);
  }
  return value;
}

function boundedString(value, field, minimum, maximum, reject = invalid) {
  if (typeof value !== "string") reject(`${field} must be a string.`);
  const normalized = value.normalize("NFC").trim();
  if (normalized.length < minimum || normalized.length > maximum || /[\u0000-\u001f\u007f]/.test(normalized)) {
    reject(`${field} is invalid.`);
  }
  return normalized;
}

function optionalString(value, field, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  return boundedString(value, field, 1, maximum);
}

function optionalDate(value, field) {
  if (value === undefined || value === null || value === "") return undefined;
  const date = new Date(boundedString(value, field, 1, 64));
  if (Number.isNaN(date.getTime())) invalid(`${field} is invalid.`);
  return date.toISOString();
}

function email(value) {
  const normalized = boundedString(value, "recipient", 3, 320).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+$/.test(normalized)) invalid("The notification recipient is invalid.");
  return normalized;
}

function token(value, field, reject = invalid) {
  const normalized = boundedString(value, field, 1, 512, reject);
  if (!/^[A-Za-z0-9._:-]+$/.test(normalized)) reject(`${field} is invalid.`);
  return normalized;
}

function safeInteger(value, field, minimum, maximum, reject = invalid) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) reject(`${field} is invalid.`);
  return value;
}

function mediaType(value) {
  const normalized = boundedString(value, "mediaType", 1, 255, invalidScan).toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?:\s*;\s*[a-z0-9!#$&^_.+-]+=[a-z0-9!#$&^_.+:-]+)*$/.test(normalized)) {
    invalidScan("mediaType is invalid.");
  }
  return normalized;
}

function sha256(value) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    invalidScan("sha256 is invalid.");
  }
  return value;
}

function invalid(message) {
  const error = new Error(message);
  error.code = "INVALID_INTEGRATION_DELIVERY";
  throw error;
}

function invalidScan(message) {
  const error = new Error(message);
  error.code = "INVALID_ARTIFACT_SCAN";
  throw error;
}
