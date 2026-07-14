import {
  hashCanonicalJSON,
  sha256Hex,
  verifyCertificateSeal,
  verifyDetachedIntegritySeal,
} from "../engine-crypto/index.mjs";
import { parseStoredZip } from "../evidence-bundle/index.mjs";
import { buildEvidenceReports, renderEvidenceReport } from "../evidence-reporting/index.mjs";
import { calculateActivityInteractionSummary } from "../engine-domain/interaction.mjs";

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
    if (manifest.schema === "vasi-evidence-manifest/v5") {
      verifyActivityInteractionEvidence(manifest.activityInteraction, events, errors);
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
      manifest: Boolean(manifest) && !errors.includes("manifest_missing"),
      primarySeal: Boolean(primary) && !errors.includes("primary_seal_missing") && sealResults.some((seal) => seal.role === "vasi_integrity" && seal.verified),
    }),
    errors: Object.freeze(errors),
    seals: Object.freeze(sealResults),
    verified: errors.length === 0,
  });
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
