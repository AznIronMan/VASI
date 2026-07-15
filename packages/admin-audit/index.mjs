import { createHash } from "node:crypto";

export const ADMIN_AUDIT_GENESIS_HASH = "0".repeat(64);

export function verifyAdminAuditChain(rows, head) {
  const ordered = [...(rows || [])].sort((left, right) => Number(left.sequence) - Number(right.sequence));
  let previousHash = ADMIN_AUDIT_GENESIS_HASH;
  let expectedSequence = 1;
  let firstFailure = null;

  for (const row of ordered) {
    const sequence = Number(row.sequence);
    const canonicalPayload = String(row.canonicalPayload || "");
    const eventHash = String(row.eventHash || "");
    const calculatedHash = sha256Hex(previousHash + canonicalPayload);
    let payload;
    try {
      payload = JSON.parse(canonicalPayload);
    } catch {
      payload = null;
    }

    const semanticMatch = Boolean(payload) &&
      payload.id === row.id &&
      payload.action === row.action &&
      payload.actorSessionId === nullish(row.actorSessionId) &&
      payload.actorUserId === nullish(row.actorUserId) &&
      payload.commandId === row.commandId &&
      payload.ipAddress === nullish(row.ipAddress) &&
      payload.phase === row.phase &&
      payload.requestId === row.requestId &&
      payload.targetUserId === nullish(row.targetUserId) &&
      payload.userAgent === nullish(row.userAgent) &&
      new Date(payload.createdAt).getTime() === new Date(row.createdAt).getTime() &&
      semanticJSON(payload.metadata) === semanticJSON(row.metadata || {});

    if (!firstFailure) {
      if (!Number.isSafeInteger(sequence) || sequence < 1) firstFailure = failure(0, "sequence_invalid");
      else if (sequence !== expectedSequence) firstFailure = failure(sequence, "sequence_discontinuity");
      else if (row.previousHash !== previousHash) firstFailure = failure(sequence, "previous_hash_mismatch");
      else if (eventHash !== calculatedHash) firstFailure = failure(sequence, "event_hash_mismatch");
      else if (!semanticMatch) firstFailure = failure(sequence, "canonical_payload_mismatch");
    }

    previousHash = eventHash;
    expectedSequence += 1;
  }

  const lastSequenceValue = ordered.length ? Number(ordered.at(-1).sequence) : 0;
  const lastSequence = Number.isSafeInteger(lastSequenceValue) && lastSequenceValue >= 0
    ? lastSequenceValue
    : 0;
  const lastHash = ordered.length ? String(ordered.at(-1).eventHash) : ADMIN_AUDIT_GENESIS_HASH;
  const headSequence = Number(head?.lastSequence);
  const headMatches = Number.isSafeInteger(headSequence) && headSequence >= 0 &&
    headSequence === lastSequence && String(head?.lastHash) === lastHash;
  if (!firstFailure && !headMatches) firstFailure = failure(lastSequence, "chain_head_mismatch");

  return Object.freeze({
    count: ordered.length,
    firstFailure,
    headMatches,
    lastHash,
    lastSequence,
    valid: !firstFailure,
  });
}

export function evaluateGatewayOperationalReadiness(snapshot, thresholds) {
  const failures = new Set();
  const warnings = new Set();
  if (
    snapshot.migrations.applied !== snapshot.migrations.expected ||
    snapshot.migrations.valid === false
  ) failures.add("migration_drift");
  if (!snapshot.audit.valid) failures.add(snapshot.audit.failureCode || "admin_audit_chain_invalid");
  if (snapshot.database.queryMilliseconds > thresholds.maximumDatabaseQueryMilliseconds) {
    failures.add("database_query_threshold_exceeded");
  }
  if (
    snapshot.commands.incomplete > 0 &&
    snapshot.commands.oldestIncompleteSeconds > thresholds.maximumIncompleteCommandSeconds
  ) failures.add("stale_incomplete_admin_command");
  else if (snapshot.commands.incomplete > 0) warnings.add("recent_incomplete_admin_command");
  if (snapshot.commands.ambiguous24Hours > 0) warnings.add("recent_ambiguous_admin_command");
  return Object.freeze({
    failures: Object.freeze([...failures].sort()),
    status: failures.size ? "fail" : "pass",
    warnings: Object.freeze([...warnings].sort()),
  });
}

function failure(sequence, code) {
  return Object.freeze({ code, sequence: Number(sequence) || 0 });
}

function sha256Hex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function nullish(value) {
  return value === undefined ? null : value;
}

function semanticJSON(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortValue(value[key])]));
  }
  return value;
}
