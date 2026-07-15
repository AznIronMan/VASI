import {
  hashCanonicalJSON,
  sha256Hex,
  verifyCertificateSeal,
  verifyDetachedIntegritySeal,
} from "../engine-crypto/index.mjs";
import { parseStoredZip } from "../evidence-bundle/index.mjs";
import { buildEvidenceReports, renderEvidenceReport } from "../evidence-reporting/index.mjs";
import { calculateActivityInteractionSummary } from "../engine-domain/interaction.mjs";
import {
  participantContextPolicy,
  validateStoredParticipantContextSnapshot,
} from "../engine-domain/context.mjs";
import { validateNotificationDeliveryEvidence } from "../engine-domain/notifications.mjs";
import { validateRequesterSnapshot } from "../engine-domain/requester.mjs";
import { validateTenantAdmission } from "../engine-domain/productization.mjs";
import {
  authenticationAssurancePolicy,
  evaluateAuthenticationAssurance,
} from "../engine-domain/workflow.mjs";

const GENESIS_HASH = "0".repeat(64);

export function verifyEvidenceRecord(record, options = {}) {
  const errors = [];
  const events = Array.isArray(record?.events) ? record.events : [];
  const manifest = record?.manifest;
  const seals = normalizedSeals(record);
  if (!events.length) errors.push("event_chain_missing");
  if (!manifest || typeof manifest !== "object") errors.push("manifest_missing");
  if (!seals.length) errors.push("seal_missing");

  let previousHash = GENESIS_HASH;
  const eventHashes = [];
  if (manifest) {
    for (const [index, event] of events.entries()) {
      const sequence = index + 1;
      if (event?.sequence !== sequence) errors.push(`event_${sequence}_sequence_invalid`);
      if (event?.previousHash !== previousHash || event?.eventData?.previousHash !== previousHash) {
        errors.push(`event_${sequence}_previous_hash_invalid`);
      }
      if (event?.eventData?.sequence !== event?.sequence) {
        errors.push(`event_${sequence}_embedded_sequence_invalid`);
      }
      if (event?.eventData?.assignmentId !== manifest.assignment?.id) {
        errors.push(`event_${sequence}_assignment_invalid`);
      }
      if (event?.eventData?.requestId !== manifest.request?.id) {
        errors.push(`event_${sequence}_request_invalid`);
      }
      if (event?.eventData?.tenantId !== manifest.tenant?.id) {
        errors.push(`event_${sequence}_tenant_invalid`);
      }
      try {
        if (hashCanonicalJSON(event?.eventData) !== event?.eventHash) {
          errors.push(`event_${sequence}_hash_invalid`);
        }
      } catch {
        errors.push(`event_${sequence}_canonical_invalid`);
      }
      if (typeof event?.eventHash === "string") {
        previousHash = event.eventHash;
        eventHashes.push(event.eventHash);
      }
    }

    const evidence = manifest.evidence;
    if (evidence?.eventCount !== events.length) errors.push("manifest_event_count_invalid");
    if (evidence?.firstSequence !== 1) errors.push("manifest_first_sequence_invalid");
    if (evidence?.lastSequence !== events.length) errors.push("manifest_last_sequence_invalid");
    if (evidence?.headHash !== previousHash) errors.push("manifest_head_hash_invalid");
    if (JSON.stringify(evidence?.eventHashes) !== JSON.stringify(eventHashes)) {
      errors.push("manifest_event_hashes_invalid");
    }
    if (["vasi-evidence-manifest/v5", "vasi-evidence-manifest/v6", "vasi-evidence-manifest/v7", "vasi-evidence-manifest/v8", "vasi-evidence-manifest/v9", "vasi-evidence-manifest/v10"].includes(manifest.schema)) {
      verifyActivityInteractionEvidence(manifest.activityInteraction, events, errors);
    }
    if (["vasi-evidence-manifest/v6", "vasi-evidence-manifest/v7", "vasi-evidence-manifest/v8", "vasi-evidence-manifest/v9", "vasi-evidence-manifest/v10"].includes(manifest.schema)) {
      verifyParticipantContextEvidence(manifest.participantContext, events, errors);
    }
    if (["vasi-evidence-manifest/v7", "vasi-evidence-manifest/v8", "vasi-evidence-manifest/v9", "vasi-evidence-manifest/v10"].includes(manifest.schema)) {
      verifyNotificationDeliveryEvidence(manifest.notificationDelivery, manifest.timestamps?.completedAt, errors);
    }
    if (["vasi-evidence-manifest/v8", "vasi-evidence-manifest/v9", "vasi-evidence-manifest/v10"].includes(manifest.schema)) {
      verifyRequesterEvidence(manifest.requester, events, errors);
    }
    if (["vasi-evidence-manifest/v9", "vasi-evidence-manifest/v10"].includes(manifest.schema)) {
      verifyTenantAdmissionEvidence(manifest.admission, events, errors);
    }
    if (manifest.schema === "vasi-evidence-manifest/v10") {
      verifyAuthenticationAssuranceEvidence(manifest.authenticationAssurance, manifest, events, errors);
    }
  }

  const sealResults = [];
  for (const seal of seals) {
    let verified = false;
    if (seal.profile === "vasi-certificate-seal/v1") {
      verified = verifyCertificateSeal(manifest, seal);
    } else {
      verified = verifyDetachedIntegritySeal(manifest, seal, ["vasi-integrity-seal/v1"]);
    }
    sealResults.push(Object.freeze({
      algorithm: seal.algorithm,
      keyId: seal.keyId,
      profile: seal.profile,
      role: seal.role || (seal.profile === "vasi-integrity-seal/v1" ? "vasi_integrity" : "certificate"),
      verified,
    }));
    if (!verified) errors.push(`seal_${seal.keyId || "unknown"}_invalid`);
  }

  const primary = seals.find((seal) => (seal.role || "vasi_integrity") === "vasi_integrity") || seals[0];
  if (!primary || primary.profile !== "vasi-integrity-seal/v1") errors.push("primary_seal_missing");
  if (options.expectedPublicJWK && primary) {
    try {
      if (hashCanonicalJSON(primary.publicJWK) !== hashCanonicalJSON(options.expectedPublicJWK)) {
        errors.push("primary_seal_key_unexpected");
      }
    } catch {
      errors.push("primary_seal_key_invalid");
    }
  }

  return Object.freeze({
    checks: Object.freeze({
      eventChain: !errors.some((error) => error.startsWith("event_") || error.startsWith("manifest_event") || error === "manifest_head_hash_invalid"),
      activityInteraction: !errors.some((error) => error.startsWith("activity_interaction_")),
      authenticationAssurance: !errors.some((error) => error.startsWith("authentication_assurance_")),
      notificationDelivery: !errors.some((error) => error.startsWith("notification_delivery_")),
      participantContext: !errors.some((error) => error.startsWith("participant_context_")),
      requester: !errors.some((error) => error.startsWith("requester_")),
      tenantAdmission: !errors.some((error) => error.startsWith("tenant_admission_")),
      manifest: Boolean(manifest) && !errors.includes("manifest_missing"),
      primarySeal: Boolean(primary) && !errors.includes("primary_seal_missing") && sealResults.some((seal) => seal.role === "vasi_integrity" && seal.verified),
    }),
    errors: Object.freeze(errors),
    seals: Object.freeze(sealResults),
    verified: errors.length === 0,
  });
}

const AUTHENTICATION_ASSURANCE_EVENT_TYPES = new Set([
  "activity.response.saved",
  "activity.response.submitted",
  "document.downloaded",
  "document.presented",
  "media.telemetry.recorded",
  "participant.opened",
  "participant.responded",
]);

function verifyAuthenticationAssuranceEvidence(value, manifest, events, errors) {
  if (!value || Array.isArray(value) || typeof value !== "object" ||
      value.schema !== "vasi-authentication-assurance-evidence/v1" ||
      !Array.isArray(value.evaluations) || value.evaluations.length > events.length) {
    errors.push("authentication_assurance_evidence_invalid");
    return;
  }
  let policy;
  try {
    policy = authenticationAssurancePolicy(manifest.request?.accessPolicy);
    const workflowPolicy = authenticationAssurancePolicy(manifest.workflow?.snapshot?.access);
    if (hashCanonicalJSON(policy) !== hashCanonicalJSON(workflowPolicy) ||
        hashCanonicalJSON(policy) !== hashCanonicalJSON(value.policy)) {
      errors.push("authentication_assurance_policy_binding_invalid");
    }
  } catch {
    errors.push("authentication_assurance_policy_invalid");
    return;
  }

  const materialEvents = events.filter((event) =>
    event?.eventData?.actor?.principalId === manifest.assignment?.principalId &&
    AUTHENTICATION_ASSURANCE_EVENT_TYPES.has(event?.eventData?.eventType)
  );
  const eventById = new Map(events.map((event) => [event?.eventData?.eventId, event]));
  const boundEvents = new Set();
  for (const entry of value.evaluations) {
    const eventId = boundedText(entry?.eventId, 128);
    const eventType = boundedText(entry?.eventType, 64);
    const event = eventById.get(eventId);
    if (!eventId || !eventType || !event || boundEvents.has(eventId) ||
        event.eventData?.eventType !== eventType ||
        !AUTHENTICATION_ASSURANCE_EVENT_TYPES.has(eventType) ||
        event.eventData?.actor?.principalId !== manifest.assignment?.principalId) {
      errors.push("authentication_assurance_event_binding_invalid");
      continue;
    }
    boundEvents.add(eventId);
    let expected;
    try {
      expected = evaluateAuthenticationAssurance(
        policy,
        event.eventData.actor,
        event.eventData.receivedAt,
      );
      if (!expected.satisfied) errors.push("authentication_assurance_unsatisfied_event");
      if (hashCanonicalJSON(expected) !== hashCanonicalJSON(entry.evaluation) ||
          hashCanonicalJSON(expected) !==
            hashCanonicalJSON(event.eventData?.payload?.authenticationAssurance)) {
        errors.push("authentication_assurance_evaluation_invalid");
      }
    } catch {
      errors.push("authentication_assurance_evaluation_invalid");
    }
  }
  if (materialEvents.length !== value.evaluations.length ||
      materialEvents.some((event) => !boundEvents.has(event.eventData.eventId))) {
    errors.push("authentication_assurance_material_event_missing");
  }
}

function verifyTenantAdmissionEvidence(value, events, errors) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    errors.push("tenant_admission_missing");
    return;
  }
  let admission;
  try {
    admission = validateTenantAdmission(value.admission);
  } catch {
    errors.push("tenant_admission_invalid");
    return;
  }
  if (admission.status !== "admitted") errors.push("tenant_admission_status_invalid");
  if (hashCanonicalJSON(admission) !== value.admissionHash) {
    errors.push("tenant_admission_hash_invalid");
  }
  if (
    value.bindingProvenance !== "issued" ||
    !boundedText(value.revisionId, 128) ||
    !Number.isSafeInteger(value.revision) || value.revision < 1
  ) {
    errors.push("tenant_admission_binding_invalid");
  }
  const issuance = events.find((event) =>
    ["request.issued", "request.scheduled"].includes(event?.eventData?.eventType),
  );
  if (!issuance) {
    errors.push("tenant_admission_issuance_event_missing");
    return;
  }
  try {
    if (hashCanonicalJSON(issuance.eventData?.payload?.admission) !== hashCanonicalJSON(value)) {
      errors.push("tenant_admission_issuance_binding_invalid");
    }
  } catch {
    errors.push("tenant_admission_issuance_binding_invalid");
  }
}

function verifyRequesterEvidence(value, events, errors) {
  let requester;
  try {
    requester = validateRequesterSnapshot(value);
  } catch {
    errors.push("requester_snapshot_invalid");
    return;
  }
  const issuance = events.find((event) =>
    ["request.issued", "request.scheduled"].includes(event?.eventData?.eventType),
  );
  if (!issuance) {
    errors.push("requester_issuance_event_missing");
    return;
  }
  const actor = issuance.eventData?.actor;
  if (actor?.principalId !== requester.principalId) {
    errors.push("requester_principal_binding_invalid");
  }
  if (requester.email && actor?.email?.toLowerCase() !== requester.email) {
    errors.push("requester_email_binding_invalid");
  }
}

function verifyNotificationDeliveryEvidence(value, completedAt, errors) {
  try {
    validateNotificationDeliveryEvidence(value, completedAt);
  } catch (error) {
    const code = typeof error?.message === "string" && error.message.startsWith("notification_")
      ? error.message
      : "notification_delivery_evidence_invalid";
    errors.push(code);
  }
}

function verifyActivityInteractionEvidence(value, evidenceEvents, errors) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !Array.isArray(value.batches) || !Array.isArray(value.events) ||
      !Array.isArray(value.summaries)) {
    errors.push("activity_interaction_evidence_invalid");
    return;
  }
  if (value.batches.length > 100_000 || value.events.length > 100_000 ||
      value.summaries.length > 100_000) {
    errors.push("activity_interaction_evidence_unbounded");
    return;
  }

  const eventIdentities = new Set();
  const sequenceIdentities = new Set();
  const activityEvents = new Map();
  const batchEvents = new Map();
  const sessionProgress = new Map();
  for (const event of value.events) {
    const activityId = boundedText(event?.activityId, 64);
    const batchId = boundedText(event?.batchId, 128);
    const eventId = boundedText(event?.id, 128);
    const interactionId = boundedText(event?.interactionId, 128);
    const sessionId = boundedText(event?.telemetrySessionId, 128);
    const type = boundedText(event?.type, 32);
    const sequence = event?.sequence;
    const monotonicMs = event?.event?.monotonicMs;
    if (!activityId || !batchId || !eventId || !interactionId || !sessionId ||
        !["presented", "visible", "hidden", "focus", "blur", "heartbeat", "interaction", "disconnect"].includes(type) ||
        !Number.isSafeInteger(sequence) || sequence < 1 || sequence > 100_000 ||
        !Number.isSafeInteger(monotonicMs) || monotonicMs < 0 || monotonicMs > 604_800_000 ||
        event?.event?.id !== eventId || event?.event?.sequence !== sequence ||
        event?.event?.type !== type || !canonicalTimestamp(event?.receivedAt) ||
        (event?.event?.clientOccurredAt !== undefined && !canonicalTimestamp(event.event.clientOccurredAt))) {
      errors.push("activity_interaction_event_invalid");
      continue;
    }
    const eventIdentity = `${activityId}\u0000${sessionId}\u0000${eventId}`;
    const sequenceIdentity = `${activityId}\u0000${sessionId}\u0000${sequence}`;
    if (eventIdentities.has(eventIdentity)) errors.push("activity_interaction_event_id_duplicate");
    if (sequenceIdentities.has(sequenceIdentity)) errors.push("activity_interaction_event_sequence_duplicate");
    eventIdentities.add(eventIdentity);
    sequenceIdentities.add(sequenceIdentity);
    const sessionIdentity = `${activityId}\u0000${sessionId}`;
    const previous = sessionProgress.get(sessionIdentity);
    if (previous && (sequence <= previous.sequence || monotonicMs < previous.monotonicMs)) {
      errors.push("activity_interaction_event_order_invalid");
    }
    sessionProgress.set(sessionIdentity, { monotonicMs, sequence });
    const events = activityEvents.get(activityId) || [];
    events.push(event);
    activityEvents.set(activityId, events);
    const groupedBatch = batchEvents.get(batchId) || [];
    groupedBatch.push(event);
    batchEvents.set(batchId, groupedBatch);
  }

  const batches = new Map();
  const chainLinks = new Map();
  const interactionChainEvents = evidenceEvents.filter((entry) =>
    entry?.eventData?.eventType === "activity.interaction.recorded"
  );
  for (const batch of value.batches) {
    const activityId = boundedText(batch?.activityId, 64);
    const actorPrincipalId = boundedText(batch?.actorPrincipalId, 128);
    const id = boundedText(batch?.id, 128);
    const interactionId = boundedText(batch?.interactionId, 128);
    const telemetrySessionId = boundedText(batch?.telemetrySessionId, 128);
    if (!activityId || !actorPrincipalId || !id || !interactionId || !telemetrySessionId ||
        !Number.isSafeInteger(batch?.eventCount) || batch.eventCount < 1 || batch.eventCount > 100 ||
        !/^[a-f0-9]{64}$/.test(batch?.payloadHash || "") || !canonicalTimestamp(batch?.receivedAt)) {
      errors.push("activity_interaction_batch_invalid");
      continue;
    }
    if (batches.has(id)) {
      errors.push("activity_interaction_batch_duplicate");
      continue;
    }
    batches.set(id, batch);
    const grouped = [...(batchEvents.get(id) || [])].sort((left, right) => left.sequence - right.sequence);
    if (grouped.length !== batch.eventCount || grouped.some((entry) =>
      entry.activityId !== activityId || entry.interactionId !== interactionId ||
      entry.telemetrySessionId !== telemetrySessionId
    )) {
      errors.push("activity_interaction_batch_event_binding_invalid");
    }
    try {
      const expectedHash = hashCanonicalJSON({
        activityId,
        batchId: id,
        events: grouped.map((entry) => entry.event),
        interactionId,
        telemetrySessionId,
      });
      if (expectedHash !== batch.payloadHash) errors.push("activity_interaction_batch_hash_invalid");
    } catch {
      errors.push("activity_interaction_batch_hash_invalid");
    }
    const links = interactionChainEvents.filter((entry) =>
      entry.eventData?.payload?.batch?.id === id
    );
    if (links.length !== 1 ||
        links[0].eventData?.payload?.activityId !== activityId ||
        links[0].eventData?.payload?.batch?.eventCount !== batch.eventCount ||
        links[0].eventData?.payload?.batch?.payloadHash !== batch.payloadHash ||
        links[0].eventData?.payload?.batch?.telemetrySessionId !== telemetrySessionId ||
        links[0].eventData?.actor?.principalId !== actorPrincipalId) {
      errors.push("activity_interaction_batch_chain_binding_invalid");
    } else {
      chainLinks.set(id, links[0].eventData.payload);
    }
  }
  for (const batchId of batchEvents.keys()) {
    if (!batches.has(batchId)) errors.push("activity_interaction_event_batch_missing");
  }
  if (interactionChainEvents.length !== batches.size) {
    errors.push("activity_interaction_batch_chain_count_invalid");
  }

  const summaryRevisions = new Set();
  const latestSummaries = new Map();
  const summariesByRevision = new Map();
  for (const summary of value.summaries) {
    const activityId = boundedText(summary?.activityId, 64);
    const revision = summary?.revision;
    if (!activityId || !boundedText(summary?.id, 128) ||
        !Number.isSafeInteger(revision) || revision < 1 ||
        !canonicalTimestamp(summary?.calculatedAt) ||
        !summary?.policy || typeof summary.policy !== "object" || Array.isArray(summary.policy) ||
        !summary?.summary || typeof summary.summary !== "object" || Array.isArray(summary.summary) ||
        !/^[a-f0-9]{64}$/.test(summary?.summaryHash || "")) {
      errors.push("activity_interaction_summary_invalid");
      continue;
    }
    const identity = `${activityId}\u0000${revision}`;
    if (summaryRevisions.has(identity)) errors.push("activity_interaction_summary_revision_duplicate");
    summaryRevisions.add(identity);
    try {
      if (hashCanonicalJSON(summary.summary) !== summary.summaryHash) {
        errors.push("activity_interaction_summary_hash_invalid");
      }
    } catch {
      errors.push("activity_interaction_summary_canonical_invalid");
    }
    const latest = latestSummaries.get(activityId);
    if (!latest || revision > latest.revision) latestSummaries.set(activityId, summary);
    summariesByRevision.set(identity, summary);
  }

  const linkedSummaryRevisions = new Set();
  for (const [batchId, link] of chainLinks) {
    const batch = batches.get(batchId);
    const summaryIdentity = `${batch.activityId}\u0000${link.summaryRevision}`;
    linkedSummaryRevisions.add(summaryIdentity);
    const summary = summariesByRevision.get(summaryIdentity);
    if (!summary || summary.summaryHash !== link.summaryHash) {
      errors.push("activity_interaction_summary_chain_binding_invalid");
    }
  }
  for (const identity of summariesByRevision.keys()) {
    if (!linkedSummaryRevisions.has(identity)) {
      errors.push("activity_interaction_summary_chain_missing");
    }
  }

  for (const [activityId, events] of activityEvents) {
    const latest = latestSummaries.get(activityId);
    if (!latest) {
      errors.push("activity_interaction_summary_missing");
      continue;
    }
    try {
      const calculated = calculateActivityInteractionSummary(latest.policy, events);
      if (hashCanonicalJSON(calculated) !== latest.summaryHash) {
        errors.push("activity_interaction_summary_calculation_invalid");
      }
    } catch {
      errors.push("activity_interaction_summary_calculation_invalid");
    }
  }
  for (const activityId of latestSummaries.keys()) {
    if (!activityEvents.has(activityId)) errors.push("activity_interaction_summary_orphaned");
  }
}

function verifyParticipantContextEvidence(value, evidenceEvents, errors) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !value.policy || typeof value.policy !== "object" || Array.isArray(value.policy) ||
      !Array.isArray(value.snapshots)) {
    errors.push("participant_context_evidence_invalid");
    return;
  }
  if (value.snapshots.length > 100_000) {
    errors.push("participant_context_evidence_unbounded");
    return;
  }
  const maximum = value.policy.maxSnapshotsPerActivity;
  if (!Number.isSafeInteger(maximum) || maximum < 2 || maximum > 64) {
    errors.push("participant_context_policy_invalid");
    return;
  }
  try {
    const expectedPolicy = participantContextPolicy({
      ENGINE_PARTICIPANT_CONTEXT_MAX_SNAPSHOTS_PER_ACTIVITY: maximum,
    });
    if (hashCanonicalJSON(value.policy) !== hashCanonicalJSON(expectedPolicy)) {
      errors.push("participant_context_policy_invalid");
    }
  } catch {
    errors.push("participant_context_policy_invalid");
  }

  const contextChainEvents = evidenceEvents.filter((entry) =>
    entry?.eventData?.eventType === "participant.context.recorded"
  );
  const snapshotIds = new Set();
  const sequenceIds = new Set();
  const sessionProgress = new Map();
  const activityCounts = new Map();
  for (const entry of value.snapshots) {
    const activityId = boundedText(entry?.activityId, 64);
    const actorPrincipalId = boundedText(entry?.actorPrincipalId, 512);
    const contextSessionId = boundedText(entry?.contextSessionId, 128);
    const gatewaySessionId = boundedText(entry?.gatewaySessionId, 512);
    const id = boundedText(entry?.id, 128);
    const interactionId = boundedText(entry?.interactionId, 128);
    const sequence = entry?.sequence;
    if (!activityId || !actorPrincipalId || !contextSessionId || !gatewaySessionId || !id ||
        !interactionId || !Number.isSafeInteger(sequence) || sequence < 1 || sequence > 64 ||
        !["presentation", "save", "submission"].includes(entry?.purpose) ||
        entry?.schema !== "vasi-participant-context/v1" ||
        !/^[a-f0-9]{64}$/.test(entry?.payloadHash || "") ||
        !canonicalTimestamp(entry?.receivedAt) || !validRequestContext(entry?.requestContext)) {
      errors.push("participant_context_snapshot_invalid");
      continue;
    }
    let snapshot;
    try {
      snapshot = validateStoredParticipantContextSnapshot(entry.snapshot);
      if (hashCanonicalJSON(snapshot) !== hashCanonicalJSON(entry.snapshot) ||
          snapshot.id !== id || snapshot.sequence !== sequence ||
          snapshot.purpose !== entry.purpose || snapshot.schema !== entry.schema) {
        errors.push("participant_context_snapshot_invalid");
        continue;
      }
    } catch {
      errors.push("participant_context_snapshot_invalid");
      continue;
    }
    if (snapshotIds.has(id)) errors.push("participant_context_snapshot_duplicate");
    snapshotIds.add(id);
    const sequenceId = `${activityId}\u0000${contextSessionId}\u0000${sequence}`;
    if (sequenceIds.has(sequenceId)) errors.push("participant_context_sequence_duplicate");
    sequenceIds.add(sequenceId);
    const sessionId = `${activityId}\u0000${contextSessionId}`;
    const previous = sessionProgress.get(sessionId);
    if (!previous && (sequence !== 1 || entry.purpose !== "presentation")) {
      errors.push("participant_context_sequence_invalid");
    }
    if (previous && (sequence <= previous.sequence || snapshot.monotonicMs < previous.monotonicMs)) {
      errors.push("participant_context_sequence_invalid");
    }
    sessionProgress.set(sessionId, { monotonicMs: snapshot.monotonicMs, sequence });
    const activityCount = Number(activityCounts.get(activityId) || 0) + 1;
    activityCounts.set(activityId, activityCount);
    if (activityCount > maximum) errors.push("participant_context_activity_limit_invalid");

    try {
      const expectedHash = hashCanonicalJSON({
        activityId,
        contextSessionId,
        interactionId,
        snapshot,
      });
      if (expectedHash !== entry.payloadHash) errors.push("participant_context_snapshot_hash_invalid");
    } catch {
      errors.push("participant_context_snapshot_hash_invalid");
    }

    const links = contextChainEvents.filter((event) =>
      event?.eventData?.payload?.snapshot?.id === id
    );
    const link = links[0];
    if (links.length !== 1 ||
        link?.eventData?.payload?.activityId !== activityId ||
        link?.eventData?.payload?.contextSessionId !== contextSessionId ||
        link?.eventData?.payload?.interactionId !== interactionId ||
        link?.eventData?.payload?.snapshot?.payloadHash !== entry.payloadHash ||
        link?.eventData?.payload?.snapshot?.purpose !== entry.purpose ||
        link?.eventData?.payload?.snapshot?.schema !== entry.schema ||
        link?.eventData?.payload?.snapshot?.sequence !== sequence ||
        link?.eventData?.actor?.principalId !== actorPrincipalId ||
        link?.eventData?.actor?.gatewaySessionId !== gatewaySessionId ||
        !sameCanonicalValue(link?.eventData?.actor?.requestContext, entry.requestContext)) {
      errors.push("participant_context_snapshot_chain_binding_invalid");
    }
  }
  for (const event of contextChainEvents) {
    const id = event?.eventData?.payload?.snapshot?.id;
    if (!snapshotIds.has(id)) errors.push("participant_context_snapshot_missing");
  }
  if (contextChainEvents.length !== value.snapshots.length) {
    errors.push("participant_context_snapshot_chain_count_invalid");
  }
}

function validRequestContext(value) {
  if (value === undefined || value === null) return true;
  if (typeof value !== "object" || Array.isArray(value)) return false;
  const allowed = new Set(["acceptLanguage", "clientHints", "ipAddress", "userAgent"]);
  return Object.entries(value).every(([key, entry]) =>
    allowed.has(key) && typeof entry === "string" && entry.length > 0 && entry.length <= 512 &&
    !/[\u0000-\u001f\u007f]/.test(entry)
  );
}

function sameCanonicalValue(left, right) {
  try {
    return hashCanonicalJSON(left ?? null) === hashCanonicalJSON(right ?? null);
  } catch {
    return false;
  }
}

function boundedText(value, maximum) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum &&
    !/[\u0000-\u001f\u007f]/.test(value) ? value : undefined;
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

export function assertEvidenceRecord(record, options = {}) {
  const result = verifyEvidenceRecord(record, options);
  if (!result.verified) {
    const error = new Error(`VASI evidence verification failed: ${result.errors.join(", ")}`);
    error.code = "VASI_EVIDENCE_INVALID";
    error.result = result;
    throw error;
  }
  return result;
}

export function verifyEvidenceBundle(value, limits = {}) {
  const errors = [];
  let entries;
  try {
    entries = parseStoredZip(value, limits);
  } catch (error) {
    return bundleResult([`zip_invalid:${error instanceof Error ? error.message : "unknown"}`]);
  }
  const index = parseJSONEntry(entries, "bundle-index.json", errors);
  const sealDocument = parseJSONEntry(entries, "bundle-seals.json", errors);
  const record = parseJSONEntry(entries, "record.json", errors);
  if (!index || index.schema !== "vasi-evidence-bundle/v1") errors.push("bundle_index_profile_invalid");
  if (!sealDocument || sealDocument.schema !== "vasi-bundle-seals/v1" || !Array.isArray(sealDocument.seals)) {
    errors.push("bundle_seals_invalid");
  }
  if (index?.entries) {
    let rootHashValid = false;
    try {
      rootHashValid = Array.isArray(index.entries) && hashCanonicalJSON(index.entries) === index.rootHash;
    } catch {
      rootHashValid = false;
    }
    if (!rootHashValid) {
      errors.push("bundle_root_hash_invalid");
    } else {
      const declared = new Set(["bundle-index.json", "bundle-seals.json"]);
      for (const descriptor of index.entries) {
        if (!descriptor || typeof descriptor.path !== "string" || declared.has(descriptor.path)) {
          errors.push("bundle_entry_descriptor_invalid");
          continue;
        }
        declared.add(descriptor.path);
        const bytes = entries.get(descriptor.path);
        if (!bytes) errors.push(`bundle_entry_missing:${descriptor.path}`);
        else if (bytes.length !== descriptor.byteLength || sha256Hex(bytes) !== descriptor.sha256) {
          errors.push(`bundle_entry_hash_invalid:${descriptor.path}`);
        }
      }
      for (const path of entries.keys()) {
        if (!declared.has(path)) errors.push(`bundle_entry_undeclared:${path}`);
      }
    }
  }
  const sealResults = [];
  for (const seal of sealDocument?.seals || []) {
    const verified = seal.profile === "vasi-certificate-seal/v1"
      ? verifyCertificateSeal(index, seal)
      : verifyDetachedIntegritySeal(index, seal, ["vasi-bundle-seal/v1"]);
    sealResults.push({ keyId: seal.keyId, profile: seal.profile, verified });
    if (!verified) errors.push(`bundle_seal_invalid:${seal.keyId || "unknown"}`);
  }
  if (!sealResults.some((seal) => seal.profile === "vasi-bundle-seal/v1" && seal.verified)) {
    errors.push("bundle_primary_seal_missing");
  }
  const recordResult = record ? verifyEvidenceRecord(record) : undefined;
  if (!recordResult?.verified) errors.push(...(recordResult?.errors || ["record_invalid"]).map((error) => `record:${error}`));
  const primaryRecordSeal = normalizedSeals(record).find((seal) => (seal.role || "vasi_integrity") === "vasi_integrity");
  if (index && primaryRecordSeal?.manifestHash !== index.sourceManifestHash) {
    errors.push("bundle_source_manifest_hash_invalid");
  }
  if (record) verifyRegeneratedReports(entries, record, errors);
  return bundleResult(errors, { index, record: recordResult, seals: sealResults });
}

export function assertEvidenceBundle(value, limits = {}) {
  const result = verifyEvidenceBundle(value, limits);
  if (!result.verified) {
    const error = new Error(`VASI bundle verification failed: ${result.errors.join(", ")}`);
    error.code = "VASI_BUNDLE_INVALID";
    error.result = result;
    throw error;
  }
  return result;
}

function normalizedSeals(record) {
  if (Array.isArray(record?.seals) && record.seals.length) return record.seals;
  return record?.seal ? [record.seal] : [];
}

function parseJSONEntry(entries, path, errors) {
  const bytes = entries.get(path);
  if (!bytes) {
    errors.push(`bundle_control_missing:${path}`);
    return undefined;
  }
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    errors.push(`bundle_json_invalid:${path}`);
    return undefined;
  }
}

function verifyRegeneratedReports(entries, record, errors) {
  try {
    const reports = buildEvidenceReports(record);
    for (const [profile, report] of Object.entries(reports)) {
      for (const format of ["json", "text", "html"]) {
        const extension = format === "text" ? "txt" : format;
        const path = `reports/${profile}.${extension}`;
        const actual = entries.get(path);
        const expected = renderEvidenceReport(report, format);
        if (!actual || !actual.equals(expected)) errors.push(`bundle_report_invalid:${path}`);
      }
    }
  } catch {
    errors.push("bundle_report_regeneration_failed");
  }
}

function bundleResult(errors, detail = {}) {
  return Object.freeze({
    errors: Object.freeze(errors),
    ...detail,
    verified: errors.length === 0,
  });
}
