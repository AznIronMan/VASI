export const NOTIFICATION_TYPES = Object.freeze([
  "request.issued",
  "request.reminder",
  "request.completed",
  "participant_data.ready",
  "participant_data.denied",
  "participant_data.preparation_failed",
  "participant_data.expired",
]);

export const NOTIFICATION_JOB_LIMIT = 32;

export const NOTIFICATION_DELIVERY_LIMITATIONS = Object.freeze([
  "Provider acceptance means the configured adapter accepted the notification; it does not prove inbox delivery, receipt, reading, attention, or identity.",
  "This sealed snapshot includes only notification state and immutable attempts available when the evidence record was sealed.",
]);

const JOB_STATUSES = Object.freeze([
  "scheduled",
  "queued",
  "processing",
  "provider_accepted",
  "suppressed",
  "failed",
  "indeterminate",
]);
const ATTEMPT_OUTCOMES = Object.freeze(["provider_accepted", "suppressed", "failed"]);
const NOTIFICATION_ADAPTERS = Object.freeze([
  "disabled",
  "microsoft_graph",
  "notification",
  "smtp",
  "webhook",
]);

export function requireNotificationType(value) {
  if (!NOTIFICATION_TYPES.includes(value)) throw invalidNotification("notification_type_invalid");
  return value;
}

export function notificationOperationalStatus(job, now = new Date()) {
  const status = job?.status;
  // The job result is the authoritative current outcome. A sealed history may
  // contain earlier failed attempts before a later provider acceptance.
  const outcome = job?.resultOutcome || job?.attemptOutcome;
  if (["pending", "participant_pending"].includes(status)) {
    const availableAt = new Date(job.availableAt);
    return !Number.isNaN(availableAt.getTime()) && availableAt > now ? "scheduled" : "queued";
  }
  if (status === "running") return "processing";
  if (status === "failed") return "failed";
  if (status === "completed" && outcome === "delivered") return "provider_accepted";
  if (status === "completed" && outcome === "suppressed") return "suppressed";
  if (status === "completed" && outcome === "failed") return "failed";
  return "indeterminate";
}

export function notificationEvidenceOutcome(value) {
  if (value === "delivered") return "provider_accepted";
  if (value === "failed" || value === "suppressed") return value;
  throw invalidNotification("notification_attempt_outcome_invalid");
}

export function validateNotificationDeliveryEvidence(value, expectedCapturedAt) {
  strictObject(value, "notification delivery evidence", ["capturedAt", "jobs", "limitations", "schema"]);
  if (value.schema !== "vasi-notification-delivery-evidence/v1") {
    throw invalidNotification("notification_delivery_schema_invalid");
  }
  const capturedAt = canonicalTimestamp(value.capturedAt, "capturedAt");
  if (expectedCapturedAt !== undefined && capturedAt !== canonicalTimestamp(expectedCapturedAt, "expectedCapturedAt")) {
    throw invalidNotification("notification_delivery_capture_invalid");
  }
  if (!Array.isArray(value.limitations) ||
      JSON.stringify(value.limitations) !== JSON.stringify(NOTIFICATION_DELIVERY_LIMITATIONS)) {
    throw invalidNotification("notification_delivery_limitations_invalid");
  }
  if (!Array.isArray(value.jobs) || value.jobs.length > NOTIFICATION_JOB_LIMIT) {
    throw invalidNotification("notification_delivery_jobs_invalid");
  }
  const jobIds = new Set();
  const jobs = value.jobs.map((job) => validateJob(job, capturedAt, jobIds));
  return Object.freeze({
    capturedAt,
    jobs: Object.freeze(jobs),
    limitations: NOTIFICATION_DELIVERY_LIMITATIONS,
    schema: value.schema,
  });
}

function validateJob(value, capturedAt, jobIds) {
  strictObject(value, "notification job", [
    "attempts", "id", "notificationType", "queuedAt", "scheduledFor", "status",
  ]);
  const id = boundedToken(value.id, "notification job id", 128);
  if (jobIds.has(id)) throw invalidNotification("notification_delivery_job_duplicate");
  jobIds.add(id);
  const notificationType = requireNotificationType(value.notificationType);
  const queuedAt = canonicalTimestamp(value.queuedAt, "queuedAt");
  const scheduledFor = canonicalTimestamp(value.scheduledFor, "scheduledFor");
  if (Date.parse(queuedAt) > Date.parse(capturedAt)) {
    throw invalidNotification("notification_delivery_job_time_invalid");
  }
  if (!JOB_STATUSES.includes(value.status)) throw invalidNotification("notification_delivery_status_invalid");
  if (!Array.isArray(value.attempts) || value.attempts.length > 20) {
    throw invalidNotification("notification_delivery_attempts_invalid");
  }
  let previousAttempt = 0;
  const attempts = value.attempts.map((attempt) => {
    const validated = validateAttempt(attempt, capturedAt);
    if (validated.attempt <= previousAttempt) {
      throw invalidNotification("notification_delivery_attempt_order_invalid");
    }
    previousAttempt = validated.attempt;
    return validated;
  });
  const lastOutcome = attempts.at(-1)?.outcome;
  if (value.status === "provider_accepted" && lastOutcome !== "provider_accepted") {
    throw invalidNotification("notification_delivery_status_attempt_mismatch");
  }
  if (value.status === "failed" && attempts.length && lastOutcome !== "failed") {
    throw invalidNotification("notification_delivery_status_attempt_mismatch");
  }
  return Object.freeze({
    attempts: Object.freeze(attempts),
    id,
    notificationType,
    queuedAt,
    scheduledFor,
    status: value.status,
  });
}

function validateAttempt(value, capturedAt) {
  strictObject(value, "notification attempt", [
    "adapter", "attempt", "completedAt", "errorCode", "outcome", "startedAt",
  ]);
  const adapter = boundedToken(value.adapter, "notification adapter", 64);
  if (!NOTIFICATION_ADAPTERS.includes(adapter)) {
    throw invalidNotification("notification_delivery_adapter_invalid");
  }
  if (!Number.isSafeInteger(value.attempt) || value.attempt < 1 || value.attempt > 20) {
    throw invalidNotification("notification_delivery_attempt_number_invalid");
  }
  const startedAt = canonicalTimestamp(value.startedAt, "startedAt");
  const completedAt = canonicalTimestamp(value.completedAt, "completedAt");
  if (Date.parse(startedAt) > Date.parse(completedAt) || Date.parse(completedAt) > Date.parse(capturedAt)) {
    throw invalidNotification("notification_delivery_attempt_time_invalid");
  }
  if (!ATTEMPT_OUTCOMES.includes(value.outcome)) {
    throw invalidNotification("notification_delivery_attempt_outcome_invalid");
  }
  const errorCode = value.errorCode === undefined || value.errorCode === null
    ? undefined
    : boundedErrorCode(value.errorCode);
  if (value.outcome === "failed" && !errorCode) {
    throw invalidNotification("notification_delivery_attempt_error_missing");
  }
  if (value.outcome !== "failed" && errorCode) {
    throw invalidNotification("notification_delivery_attempt_error_unexpected");
  }
  return Object.freeze({
    adapter,
    attempt: value.attempt,
    completedAt,
    ...(errorCode ? { errorCode } : {}),
    outcome: value.outcome,
    startedAt,
  });
}

function boundedErrorCode(value) {
  if (typeof value !== "string" || !/^[a-z0-9_]{1,64}$/.test(value)) {
    throw invalidNotification("notification_error_code_invalid");
  }
  return value;
}

function strictObject(value, name, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw invalidNotification(`${name.replaceAll(" ", "_")}_invalid`);
  }
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) throw invalidNotification("notification_delivery_field_unsupported");
  }
  return value;
}

function boundedToken(value, name, maximum) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum ||
      !/^[A-Za-z0-9._:-]+$/.test(value)) {
    throw invalidNotification(`${name.replaceAll(" ", "_")}_invalid`);
  }
  return value;
}

function canonicalTimestamp(value, name) {
  if (typeof value !== "string") throw invalidNotification(`${name}_invalid`);
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) {
    throw invalidNotification(`${name}_invalid`);
  }
  return value;
}

function invalidNotification(code) {
  const error = new Error(code);
  error.code = "INVALID_NOTIFICATION_DELIVERY";
  return error;
}
