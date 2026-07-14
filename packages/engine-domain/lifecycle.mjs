import { hashCanonicalJSON } from "../engine-crypto/index.mjs";

export const RETENTION_POLICY_SCHEMA = "vasi-retention-policy/v1";
export const DATA_EXPORT_PROFILE = "vasi-participant-data-export/v1";

export const SYSTEM_RETENTION_POLICY = deepFreeze({
  contentAccess: { mode: "request_expiration" },
  evidence: { archiveAfterDays: 365, deleteAfterDays: null },
  participantHistory: { daysAfterTerminal: null },
  schema: RETENTION_POLICY_SCHEMA,
});

export function normalizeRetentionPolicy(value = SYSTEM_RETENTION_POLICY) {
  const input = strictObject(value, "retention policy", [
    "contentAccess", "evidence", "participantHistory", "schema",
  ]);
  if (input.schema !== undefined && input.schema !== RETENTION_POLICY_SCHEMA) {
    invalid("The retention policy schema is unsupported.");
  }
  const content = strictObject(input.contentAccess, "content access policy", [
    "daysAfterTerminal", "mode",
  ]);
  const mode = boundedString(content.mode, "contentAccess.mode", 1, 64);
  if (!["days_after_terminal", "indefinite", "request_expiration"].includes(mode)) {
    invalid("The content access mode is unsupported.");
  }
  const contentAccess = mode === "days_after_terminal"
    ? deepFreeze({
      daysAfterTerminal: boundedDays(content.daysAfterTerminal, "contentAccess.daysAfterTerminal"),
      mode,
    })
    : deepFreeze({ mode });
  if (mode !== "days_after_terminal" && content.daysAfterTerminal !== undefined) {
    invalid("Content access days are allowed only with days_after_terminal.");
  }

  const history = strictObject(input.participantHistory, "participant history policy", [
    "daysAfterTerminal",
  ]);
  const participantHistory = deepFreeze({
    daysAfterTerminal: nullableDays(
      history.daysAfterTerminal,
      "participantHistory.daysAfterTerminal",
    ),
  });

  const evidenceInput = strictObject(input.evidence, "evidence retention policy", [
    "archiveAfterDays", "deleteAfterDays",
  ]);
  const evidence = deepFreeze({
    archiveAfterDays: nullableDays(evidenceInput.archiveAfterDays, "evidence.archiveAfterDays"),
    deleteAfterDays: nullableDays(evidenceInput.deleteAfterDays, "evidence.deleteAfterDays"),
  });
  if (
    evidence.archiveAfterDays !== null &&
    evidence.deleteAfterDays !== null &&
    evidence.deleteAfterDays < evidence.archiveAfterDays
  ) {
    invalid("Evidence deletion cannot precede archival.");
  }
  return deepFreeze({ contentAccess, evidence, participantHistory, schema: RETENTION_POLICY_SCHEMA });
}

export function retentionPolicyHash(policy) {
  return hashCanonicalJSON(normalizeRetentionPolicy(policy));
}

export function calculateRetentionDeadlines(policyValue, dates) {
  const policy = normalizeRetentionPolicy(policyValue);
  const expiresAt = validDate(dates?.expiresAt, "expiresAt");
  const terminalAt = dates?.terminalAt === undefined || dates?.terminalAt === null
    ? expiresAt
    : validDate(dates.terminalAt, "terminalAt");
  const contentExpiresAt = policy.contentAccess.mode === "indefinite"
    ? null
    : policy.contentAccess.mode === "request_expiration"
      ? expiresAt
      : plusDays(terminalAt, policy.contentAccess.daysAfterTerminal);
  const historyExpiresAt = policy.participantHistory.daysAfterTerminal === null
    ? null
    : plusDays(terminalAt, policy.participantHistory.daysAfterTerminal);
  const archiveAt = policy.evidence.archiveAfterDays === null
    ? null
    : plusDays(terminalAt, policy.evidence.archiveAfterDays);
  const deleteAt = policy.evidence.deleteAfterDays === null
    ? null
    : plusDays(terminalAt, policy.evidence.deleteAfterDays);
  return deepFreeze({ archiveAt, contentExpiresAt, deleteAt, historyExpiresAt, terminalAt });
}

export function validateRetentionPolicyMutation(value) {
  const input = strictObject(value, "retention policy command", [
    "expectedRevision", "name", "policy", "tenantId",
  ]);
  const name = boundedString(input.name, "name", 1, 64).toLowerCase();
  if (!/^[a-z][a-z0-9_-]*$/.test(name)) invalid("The retention profile name is invalid.");
  return deepFreeze({
    expectedRevision: optionalInteger(input.expectedRevision, "expectedRevision", 0, 1_000_000),
    name,
    policy: normalizeRetentionPolicy(input.policy),
    tenantId: boundedString(input.tenantId, "tenantId", 1, 128),
  });
}

export function validateLifecycleListInput(value) {
  const input = strictObject(value, "lifecycle list", ["limit", "tenantId"]);
  return deepFreeze({
    limit: optionalInteger(input.limit, "limit", 1, 250) ?? 100,
    tenantId: boundedString(input.tenantId, "tenantId", 1, 128),
  });
}

export function validateLegalHoldCommand(value) {
  const input = strictObject(value, "legal hold command", [
    "action", "assignmentId", "caseReference", "commandId", "holdId", "reason", "tenantId",
  ]);
  const action = boundedString(input.action, "action", 1, 32);
  if (!['place', 'release'].includes(action)) invalid("The legal hold action is unsupported.");
  const command = {
    action,
    commandId: boundedString(input.commandId, "commandId", 1, 128),
    reason: boundedString(input.reason, "reason", 2, 1_000),
    tenantId: boundedString(input.tenantId, "tenantId", 1, 128),
  };
  if (action === "place") {
    return deepFreeze({
      ...command,
      assignmentId: boundedString(input.assignmentId, "assignmentId", 1, 128),
      caseReference: boundedString(input.caseReference, "caseReference", 1, 160),
    });
  }
  return deepFreeze({
    ...command,
    holdId: boundedString(input.holdId, "holdId", 1, 128),
  });
}

export function validateParticipantDataRequestCreate(value) {
  const input = strictObject(value, "participant data request", ["commandId"]);
  return deepFreeze({ commandId: boundedString(input.commandId, "commandId", 1, 128) });
}

export function validateParticipantDataRequestReview(value) {
  const input = strictObject(value, "participant data request review", [
    "commandId", "decision", "includeTechnicalTelemetry", "reason", "requestId", "tenantId",
  ]);
  const decision = boundedString(input.decision, "decision", 1, 32);
  if (!['approve', 'deny'].includes(decision)) invalid("The review decision is unsupported.");
  const reason = optionalString(input.reason, "reason", 1_000);
  if (decision === "deny" && !reason) invalid("A denial reason is required.");
  if (input.includeTechnicalTelemetry !== undefined && typeof input.includeTechnicalTelemetry !== "boolean") {
    invalid("includeTechnicalTelemetry must be boolean.");
  }
  return deepFreeze({
    commandId: boundedString(input.commandId, "commandId", 1, 128),
    decision,
    includeTechnicalTelemetry: input.includeTechnicalTelemetry !== false,
    reason,
    requestId: boundedString(input.requestId, "requestId", 1, 128),
    tenantId: boundedString(input.tenantId, "tenantId", 1, 128),
  });
}

export function validateParticipantDataExportOpen(value) {
  const input = strictObject(value, "participant data export", ["requestId"]);
  return deepFreeze({ requestId: boundedString(input.requestId, "requestId", 1, 128) });
}

export function participantMatches(actor, principalId, email) {
  return Boolean(
    actor?.principalId &&
    (actor.principalId === principalId || actor.email?.toLowerCase() === String(email || "").toLowerCase()),
  );
}

function nullableDays(value, name) {
  if (value === null) return null;
  return boundedDays(value, name);
}

function boundedDays(value, name) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 36_500) {
    invalid(`${name} must be an integer from 0 to 36500 or null.`);
  }
  return value;
}

function optionalInteger(value, name, minimum, maximum) {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${name} is invalid.`);
  }
  return value;
}

function plusDays(value, days) {
  return new Date(value.getTime() + days * 86_400_000);
}

function validDate(value, name) {
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (Number.isNaN(date.getTime())) invalid(`${name} must be a valid date.`);
  return date;
}

function optionalString(value, name, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  return boundedString(value, name, 1, maximum);
}

function boundedString(value, name, minimum, maximum) {
  if (typeof value !== "string") invalid(`${name} must be text.`);
  const normalized = value.trim();
  if (normalized.length < minimum || normalized.length > maximum) invalid(`${name} is invalid.`);
  return normalized;
}

function strictObject(value, name, keys) {
  if (!value || Array.isArray(value) || typeof value !== "object") invalid(`${name} must be an object.`);
  const extras = Object.keys(value).filter((key) => !keys.includes(key));
  if (extras.length) invalid(`${name} contains unsupported fields.`);
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function invalid(message) {
  const error = new Error(message);
  error.code = "INVALID_LIFECYCLE";
  throw error;
}
