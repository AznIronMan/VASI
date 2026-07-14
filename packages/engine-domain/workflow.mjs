import { hashCanonicalJSON } from "../engine-crypto/index.mjs";

export const TENANT_ROLES = Object.freeze(["owner", "manager", "author", "auditor"]);
export const ACTIVITY_TYPES = Object.freeze(["terms_response"]);
export const POST_COMPLETION_ACCESS = Object.freeze([
  "receipt_only",
  "content_until_expiration",
  "content_always",
]);

const ROLE_PERMISSIONS = Object.freeze({
  owner: Object.freeze(["member.manage", "record.read", "request.manage", "workflow.manage"]),
  manager: Object.freeze(["record.read", "request.manage", "workflow.manage"]),
  author: Object.freeze(["workflow.manage"]),
  auditor: Object.freeze(["record.read"]),
});

export function permissionsForRoles(roles = []) {
  return Object.freeze([...new Set(roles.flatMap((role) => ROLE_PERMISSIONS[role] || []))].sort());
}

export function hasTenantPermission(roles, permission) {
  return permissionsForRoles(roles).includes(permission);
}

export function validateWorkflowDraft(value) {
  const input = strictObject(value, "workflow", [
    "access", "activities", "assurance", "completion", "instructions", "notifications",
    "purpose", "retention", "schedule", "schema", "title",
  ]);
  if (input.schema !== undefined && input.schema !== "vasi-workflow/v1") {
    invalid("The workflow schema is unsupported.");
  }
  if (!Array.isArray(input.activities) || input.activities.length < 1 || input.activities.length > 50) {
    invalid("A workflow requires 1 to 50 activities.");
  }

  const activities = input.activities.map((activity, index) => normalizeActivity(activity, index));
  const activityIds = new Set(activities.map((activity) => activity.id));
  if (activityIds.size !== activities.length) invalid("Workflow activity IDs must be unique.");
  for (const [index, activity] of activities.entries()) {
    validateTransition(activity.transition, activity, index, activities, activityIds);
  }

  const document = Object.freeze({
    access: normalizeAccess(input.access),
    activities: Object.freeze(activities),
    assurance: normalizeNamedProfile(input.assurance, "assurance", "vasi-integrity-seal/v1"),
    completion: normalizeCompletion(input.completion),
    instructions: optionalString(input.instructions, "instructions", 4_000),
    notifications: normalizeNotifications(input.notifications),
    purpose: boundedString(input.purpose, "purpose", 2, 1_000),
    retention: normalizeNamedProfile(input.retention, "retention", "tenant_default"),
    schedule: normalizeSchedule(input.schedule),
    schema: "vasi-workflow/v1",
    title: boundedString(input.title, "title", 2, 160),
  });
  return Object.freeze({ document, documentHash: hashCanonicalJSON(document) });
}

export function evaluateNextActivity(workflow, currentActivityId, response) {
  const index = workflow.activities.findIndex((activity) => activity.id === currentActivityId);
  if (index < 0) invalid("The current workflow activity is unknown.");
  const activity = workflow.activities[index];
  const matched = activity.transition.cases.find((entry) => entry.when.equals === response);
  if (matched) return matched.to;
  if (activity.transition.defaultTo !== undefined) return activity.transition.defaultTo;
  return workflow.activities[index + 1]?.id ?? null;
}

export function participantActivityProjection(activity) {
  return Object.freeze({
    content: activity.content,
    contractVersion: activity.contractVersion,
    id: activity.id,
    instructions: activity.instructions,
    responseMode: activity.responseMode,
    title: activity.title,
    type: activity.type,
  });
}

export function validateMembershipInput(value) {
  const input = strictObject(value, "membership", ["email", "roles", "status", "tenantId"]);
  if (!Array.isArray(input.roles) || !input.roles.length || input.roles.length > TENANT_ROLES.length) {
    invalid("At least one supported company role is required.");
  }
  const roles = [...new Set(input.roles.map((role) => boundedString(role, "role", 1, 32)))].sort();
  if (roles.some((role) => !TENANT_ROLES.includes(role))) invalid("A company role is unsupported.");
  const status = input.status ?? "active";
  if (!['active', 'disabled'].includes(status)) invalid("The membership status is unsupported.");
  return Object.freeze({
    email: email(input.email),
    roles: Object.freeze(roles),
    status,
    tenantId: boundedString(input.tenantId, "tenantId", 1, 128),
  });
}

export function validateWorkflowMutation(value) {
  const input = strictObject(value, "workflow command", [
    "definitionId", "document", "expectedDraftVersion", "name", "tenantId",
  ]);
  return Object.freeze({
    definitionId: optionalString(input.definitionId, "definitionId", 128),
    document: input.document === undefined ? undefined : validateWorkflowDraft(input.document),
    expectedDraftVersion: optionalSafeInteger(input.expectedDraftVersion, "expectedDraftVersion", 1),
    name: optionalString(input.name, "name", 160),
    tenantId: boundedString(input.tenantId, "tenantId", 1, 128),
  });
}

export function validatePublishedIssueInput(value, now = new Date()) {
  const input = strictObject(value, "published request", [
    "dueAt", "expiresAt", "intendedEmail", "scheduledFor", "tenantId", "workflowRevisionId",
  ]);
  const scheduledFor = dateOrDefault(input.scheduledFor, now, "scheduledFor");
  const dueAt = optionalDate(input.dueAt, "dueAt");
  const expiresAt = optionalDate(input.expiresAt, "expiresAt");
  if (dueAt && dueAt <= scheduledFor) invalid("The due date must follow the scheduled date.");
  if (expiresAt && expiresAt <= scheduledFor) invalid("The expiration must follow the scheduled date.");
  if (dueAt && expiresAt && expiresAt < dueAt) invalid("The expiration cannot precede the due date.");
  if (scheduledFor.getTime() > now.getTime() + 365 * 86_400_000) {
    invalid("A request cannot be scheduled more than one year ahead.");
  }
  return Object.freeze({
    dueAt,
    expiresAt,
    intendedEmail: email(input.intendedEmail),
    scheduledFor,
    tenantId: boundedString(input.tenantId, "tenantId", 1, 128),
    workflowRevisionId: boundedString(input.workflowRevisionId, "workflowRevisionId", 1, 128),
  });
}

export function validateRequestAction(value) {
  const input = strictObject(value, "request action", ["action", "commandId", "requestId", "tenantId"]);
  const action = boundedString(input.action, "action", 1, 32);
  if (!['remind', 'reissue', 'revoke'].includes(action)) invalid("The request action is unsupported.");
  return Object.freeze({
    action,
    commandId: boundedString(input.commandId, "commandId", 1, 128),
    requestId: boundedString(input.requestId, "requestId", 1, 128),
    tenantId: boundedString(input.tenantId, "tenantId", 1, 128),
  });
}

function normalizeActivity(value, index) {
  const input = strictObject(value, `activity ${index + 1}`, [
    "content", "contractVersion", "id", "instructions", "responseMode", "title", "transition", "type",
  ]);
  const type = boundedString(input.type, "activity.type", 1, 64);
  if (!ACTIVITY_TYPES.includes(type)) invalid(`Unsupported activity type: ${type}.`);
  const contractVersion = input.contractVersion ?? 1;
  if (contractVersion !== 1) invalid("The activity contract version is unsupported.");
  const responseMode = boundedString(input.responseMode, "activity.responseMode", 1, 32);
  if (!['acknowledgement', 'yes_no'].includes(responseMode)) invalid("The response mode is unsupported.");
  const contentInput = strictObject(input.content, "activity.content", ["prompt", "terms"]);
  const transitionInput = input.transition === undefined
    ? { cases: [] }
    : strictObject(input.transition, "activity.transition", ["cases", "defaultTo"]);
  const cases = transitionInput.cases ?? [];
  if (!Array.isArray(cases) || cases.length > 8) invalid("An activity may define at most eight branches.");
  return Object.freeze({
    content: Object.freeze({
      prompt: boundedString(contentInput.prompt, "activity.content.prompt", 2, 1_000),
      terms: boundedString(contentInput.terms, "activity.content.terms", 2, 50_000),
    }),
    contractVersion,
    id: identifier(input.id, "activity.id"),
    instructions: optionalString(input.instructions, "activity.instructions", 2_000),
    responseMode,
    title: boundedString(input.title, "activity.title", 2, 160),
    transition: Object.freeze({
      cases: Object.freeze(cases.map((entry, branchIndex) => normalizeBranch(entry, branchIndex))),
      defaultTo: normalizeDestination(transitionInput.defaultTo),
    }),
    type,
  });
}

function normalizeBranch(value, index) {
  const input = strictObject(value, `branch ${index + 1}`, ["to", "when"]);
  const when = strictObject(input.when, "branch.when", ["equals"]);
  return Object.freeze({
    to: normalizeDestination(input.to, true),
    when: Object.freeze({ equals: boundedString(when.equals, "branch.when.equals", 1, 64) }),
  });
}

function validateTransition(transition, activity, index, activities, activityIds) {
  const allowedResponses = activity.responseMode === "acknowledgement"
    ? ["acknowledged"]
    : ["yes", "no"];
  const seen = new Set();
  for (const branch of transition.cases) {
    if (!allowedResponses.includes(branch.when.equals) || seen.has(branch.when.equals)) {
      invalid(`Activity ${activity.id} contains an invalid or duplicate branch response.`);
    }
    seen.add(branch.when.equals);
    validateForwardDestination(branch.to, index, activities, activityIds);
  }
  if (transition.defaultTo !== undefined && transition.defaultTo !== null) {
    validateForwardDestination(transition.defaultTo, index, activities, activityIds);
  }
}

function validateForwardDestination(destination, index, activities, activityIds) {
  if (destination === null) return;
  if (!activityIds.has(destination)) invalid(`Unknown workflow destination: ${destination}.`);
  const destinationIndex = activities.findIndex((activity) => activity.id === destination);
  if (destinationIndex <= index) invalid("Workflow branches must move forward and cannot form cycles.");
}

function normalizeAccess(value) {
  const input = value === undefined
    ? {}
    : strictObject(value, "access", ["authentication", "postCompletion"]);
  const authentication = input.authentication ?? "verified_email";
  const postCompletion = input.postCompletion ?? "receipt_only";
  if (authentication !== "verified_email") invalid("Only verified-email participant access is supported.");
  if (!POST_COMPLETION_ACCESS.includes(postCompletion)) invalid("The post-completion access policy is unsupported.");
  return Object.freeze({ authentication, postCompletion });
}

function normalizeCompletion(value) {
  const input = value === undefined ? {} : strictObject(value, "completion", ["mode"]);
  const mode = input.mode ?? "terminal_activity";
  if (mode !== "terminal_activity") invalid("The completion mode is unsupported.");
  return Object.freeze({ mode });
}

function normalizeSchedule(value) {
  const input = value === undefined
    ? {}
    : strictObject(value, "schedule", ["defaultDueDays", "defaultExpirationDays"]);
  const defaultDueDays = optionalSafeInteger(input.defaultDueDays, "defaultDueDays", 1, 365) ?? 7;
  const defaultExpirationDays = optionalSafeInteger(
    input.defaultExpirationDays,
    "defaultExpirationDays",
    defaultDueDays,
    365,
  ) ?? Math.max(defaultDueDays, 14);
  return Object.freeze({ defaultDueDays, defaultExpirationDays });
}

function normalizeNotifications(value) {
  const input = value === undefined
    ? {}
    : strictObject(value, "notifications", ["onCompletion", "onIssue", "reminderHoursBeforeDue"]);
  const offsets = input.reminderHoursBeforeDue ?? [24];
  if (!Array.isArray(offsets) || offsets.length > 8) invalid("Too many reminder offsets were supplied.");
  const reminderHoursBeforeDue = [...new Set(offsets.map((offset) => {
    if (!Number.isSafeInteger(offset) || offset < 1 || offset > 8_760) {
      invalid("Reminder offsets must be whole hours between 1 and 8760.");
    }
    return offset;
  }))].sort((a, b) => b - a);
  return Object.freeze({
    onCompletion: input.onCompletion !== false,
    onIssue: input.onIssue !== false,
    reminderHoursBeforeDue: Object.freeze(reminderHoursBeforeDue),
  });
}

function normalizeNamedProfile(value, name, fallback) {
  const input = value === undefined ? {} : strictObject(value, name, ["profile"]);
  return Object.freeze({ profile: optionalString(input.profile, `${name}.profile`, 128) ?? fallback });
}

function strictObject(value, name, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") invalid(`The ${name} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) invalid(`The ${name} field ${key} is unsupported.`);
  }
  return value;
}

function identifier(value, field) {
  const result = boundedString(value, field, 1, 64);
  if (!/^[a-z][a-z0-9_-]{0,63}$/.test(result)) invalid(`${field} has an invalid format.`);
  return result;
}

function email(value) {
  const result = boundedString(value, "email", 3, 320).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+$/.test(result)) invalid("The email address is invalid.");
  return result;
}

function normalizeDestination(value, required = false) {
  if (value === null) return null;
  if (value === undefined && !required) return undefined;
  return identifier(value, "transition destination");
}

function boundedString(value, field, minimum, maximum) {
  if (typeof value !== "string") invalid(`${field} must be a string.`);
  const normalized = value.trim();
  if (normalized.length < minimum || normalized.length > maximum) {
    invalid(`${field} must contain ${minimum} to ${maximum} characters.`);
  }
  return normalized;
}

function optionalString(value, field, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  return boundedString(value, field, 1, maximum);
}

function optionalSafeInteger(value, field, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (value === undefined || value === null) return undefined;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${field} must be a whole number between ${minimum} and ${maximum}.`);
  }
  return value;
}

function optionalDate(value, field) {
  if (value === undefined || value === null || value === "") return undefined;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) invalid(`${field} must be a valid date.`);
  return date;
}

function dateOrDefault(value, fallback, field) {
  return optionalDate(value, field) ?? new Date(fallback);
}

function invalid(message) {
  const error = new Error(message);
  error.code = "INVALID_WORKFLOW";
  throw error;
}
