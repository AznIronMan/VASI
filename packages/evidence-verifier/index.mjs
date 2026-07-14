import {
  hashCanonicalJSON,
  sha256Hex,
  verifyCertificateSeal,
  verifyDetachedIntegritySeal,
} from "../engine-crypto/index.mjs";
import { parseStoredZip } from "../evidence-bundle/index.mjs";
import { buildEvidenceReports, renderEvidenceReport } from "../evidence-reporting/index.mjs";

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
      manifest: Boolean(manifest) && !errors.includes("manifest_missing"),
      primarySeal: Boolean(primary) && !errors.includes("primary_seal_missing") && sealResults.some((seal) => seal.role === "vasi_integrity" && seal.verified),
    }),
    errors: Object.freeze(errors),
    seals: Object.freeze(sealResults),
    verified: errors.length === 0,
  });
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
