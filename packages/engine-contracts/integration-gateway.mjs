import { canonicalJSON } from "../engine-crypto/index.mjs";

export const INTEGRATION_DELIVERY_SCHEMA = "vasi-integration-delivery/v1";

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

function boundedString(value, field, minimum, maximum) {
  if (typeof value !== "string") invalid(`${field} must be a string.`);
  const normalized = value.normalize("NFC").trim();
  if (normalized.length < minimum || normalized.length > maximum || /[\u0000-\u001f\u007f]/.test(normalized)) {
    invalid(`${field} is invalid.`);
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

function token(value, field) {
  const normalized = boundedString(value, field, 1, 512);
  if (!/^[A-Za-z0-9._:-]+$/.test(normalized)) invalid(`${field} is invalid.`);
  return normalized;
}

function safeInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${field} is invalid.`);
  return value;
}

function invalid(message) {
  const error = new Error(message);
  error.code = "INVALID_INTEGRATION_DELIVERY";
  throw error;
}
