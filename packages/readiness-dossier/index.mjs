import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { TextDecoder } from "node:util";

import {
  hashCanonicalJSON,
  verifyCertificateSeal,
  verifyDetachedIntegritySeal,
} from "../engine-crypto/index.mjs";
import {
  BUILT_IN_ADAPTERS,
  TENANT_ADMISSION_GATES,
  TENANT_PRODUCTION_STOP_REASONS,
  validateTenantAdmission,
} from "../engine-domain/productization.mjs";

export const MAXIMUM_READINESS_DOSSIER_BYTES = 2_097_152;
export const READINESS_ATTESTATION_SCHEMA = "vasi-tenant-readiness-attestation/v1";
export const READINESS_DOSSIER_SEAL_PROFILE = "vasi-readiness-dossier-seal/v1";
export const READINESS_DOSSIER_VERIFICATION_SCHEMA = "vasi-readiness-dossier-verification/v2";
export const SIGNED_READINESS_EXPORT_SCHEMA = "vasi-tenant-readiness-export/v2";
export const READINESS_DOSSIER_LIMITATIONS = Object.freeze([
  "This dossier reports the VASI engine state observed at export; it is not a certification, legal opinion, or independent assessment.",
  "Recorded gate approvals identify evidence and reviewers but do not establish that the underlying review was sufficient or correct.",
  "Secrets, credentials, personal contact data, raw integration configuration, and destination allowlist values are deliberately omitted.",
  "The dossier SHA-256 detects changes to these exported facts; it is not a digital signature or a certificate seal.",
  "External identity, delivery, custody, recovery, accessibility, legal, security, capacity, and support controls remain installation and customer responsibilities.",
]);

const LEGACY_EXPORT_SCHEMA = "vasi-tenant-readiness-export/v1";
const DOSSIER_SCHEMA = "vasi-tenant-readiness-dossier/v1";
const SUPPORTED_ADAPTERS = new Map(BUILT_IN_ADAPTERS.map((adapter) => [adapter.id, adapter]));
const SUPPORTED_CAPABILITIES = new Set(BUILT_IN_ADAPTERS.flatMap((adapter) => adapter.capabilities));
const RESOURCE_QUOTAS = Object.freeze({
  activeRequests: "maxActiveRequests",
  artifactBytes: "maxArtifactBytes",
  integrations: "maxIntegrations",
  members: "maxMembers",
  workflows: "maxWorkflows",
});
const QUOTA_LIMITS = Object.freeze({
  maxActiveRequests: [1, 1_000_000],
  maxArtifactBytes: [1_048_576, 10_995_116_277_760],
  maxArtifactBytesPerArtifact: [1_024, 1_073_741_824],
  maxIntegrations: [0, 100],
  maxMembers: [1, 100_000],
  maxWorkflows: [1, 100_000],
});
const gateLabels = Object.freeze({
  exact_release: "Exact release",
  isolation_integrity: "Isolation and integrity",
  identity_delivery: "Identity and delivery",
  privacy_legal: "Privacy and legal",
  accessibility: "Accessibility",
  malware_content: "Malware and content safety",
  recovery_custody: "Recovery and custody",
  capacity_support: "Capacity and support",
});

export class ReadinessDossierVerificationError extends Error {
  constructor(code) {
    super("VASI readiness dossier verification failed.");
    this.code = code;
    this.name = "ReadinessDossierVerificationError";
  }
}

export function validateReadinessExport(value) {
  const schema = value && !Array.isArray(value) && typeof value === "object"
    ? value.schema
    : undefined;
  const keys = schema === LEGACY_EXPORT_SCHEMA
    ? ["auditEventHash", "capturedAt", "dossier", "dossierHash", "format", "schema"]
    : schema === SIGNED_READINESS_EXPORT_SCHEMA
      ? [
          "attestation", "auditEventHash", "capturedAt", "dossier", "dossierHash",
          "format", "schema", "seals",
        ]
      : null;
  if (!keys) fail("unsupported_export_schema");
  const exported = exactObject(value, "export", keys);
  hash(exported.auditEventHash, "audit_event_hash");
  canonicalTimestamp(exported.capturedAt, "captured_at");
  hash(exported.dossierHash, "dossier_hash");
  if (exported.format !== "html" && exported.format !== "json") fail("unsupported_export_format");
  validateDossier(exported.dossier);
  if (hashCanonicalJSON(exported.dossier) !== exported.dossierHash) fail("dossier_hash_mismatch");
  if (schema === SIGNED_READINESS_EXPORT_SCHEMA) {
    const attestation = validateReadinessAttestation(exported.attestation);
    if (
      attestation.auditEventHash !== exported.auditEventHash ||
      attestation.capturedAt !== exported.capturedAt ||
      attestation.dossierHash !== exported.dossierHash ||
      attestation.dossierSchema !== exported.dossier.schema ||
      attestation.exportSchema !== exported.schema ||
      attestation.format !== exported.format
    ) fail("attestation_binding_mismatch");
    validateReadinessSeals(attestation, exported.seals);
  }
  return exported;
}

export function createReadinessAttestation({
  auditEventHash,
  capturedAt,
  dossierHash,
  format,
  signingKeys,
}) {
  const attestation = {
    auditEventHash,
    capturedAt,
    dossierHash,
    dossierSchema: DOSSIER_SCHEMA,
    exportSchema: SIGNED_READINESS_EXPORT_SCHEMA,
    format,
    schema: READINESS_ATTESTATION_SCHEMA,
    signingKeys,
  };
  validateReadinessAttestation(attestation);
  return Object.freeze({
    ...attestation,
    signingKeys: Object.freeze(attestation.signingKeys.map((key) => Object.freeze({ ...key }))),
  });
}

export function hashReadinessDossier(value) {
  validateDossier(value);
  return hashCanonicalJSON(value);
}

export function readinessExportJSON(value) {
  const exported = validateReadinessExport(value);
  if (exported.format !== "json") fail("json_format_mismatch");
  return `${JSON.stringify(exported, null, 2)}\n`;
}

export function renderReadinessDossierHTML(value) {
  const exported = validateReadinessExport(value);
  if (exported.format !== "html") fail("html_format_mismatch");
  return exported.schema === SIGNED_READINESS_EXPORT_SCHEMA
    ? renderSignedReadinessDossierHTML(exported)
    : renderLegacyReadinessDossierHTML(exported);
}

function renderLegacyReadinessDossierHTML(exported) {
  const dossier = exported.dossier;
  const usage = dossier.tenant.usage.resources;
  const allowlistCounts = dossier.installation.adapterPolicy.destinationAllowlistCounts;
  const embeddedExport = embeddedJSON(exported);
  const embeddedDossier = embeddedJSON(dossier);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>VASI pilot readiness dossier — ${h(dossier.tenant.name)}</title>
<style>${reportCSS}</style>
</head>
<body>
<main>
  <header>
    <p class="eyebrow">VASI PILOT READINESS DOSSIER</p>
    <h1>${h(dossier.tenant.name)}</h1>
    <p class="lede">A privacy-bounded technical snapshot for accountable pilot review. Recorded approvals are evidence references, not certification or legal conclusions.</p>
    <dl class="summary">
      ${pair("Technical admission", title(dossier.readiness.technicalAdmissionStatus))}
      ${pair("Captured", exported.capturedAt)}
      ${pair("Engine release", dossier.installation.engineVersion)}
      ${pair("Dossier SHA-256", exported.dossierHash, true)}
      ${pair("Immutable export event", exported.auditEventHash, true)}
    </dl>
  </header>

  <section>
    <h2>Readiness decision record</h2>
    <p>${dossier.readiness.pendingGateIds.length
      ? `${dossier.readiness.pendingGateIds.length} gate(s) remain pending. Production admission remains closed.`
      : "All required gates have recorded approvals. This reports VASI's technical admission state only."}</p>
    <table>
      <thead><tr><th>Gate</th><th>State</th><th>Reviewer / evidence</th><th>Evidence SHA-256</th><th>Recorded</th></tr></thead>
      <tbody>${dossier.admission.gates.map((gate) => `<tr>
        <td>${h(gateLabels[gate.id])}</td>
        <td><span class="state state--${h(gate.state)}">${h(title(gate.state))}</span></td>
        <td>${gate.state === "approved" ? `${h(gate.reviewerReference)}<br>${h(gate.evidenceReference)}` : "—"}</td>
        <td class="mono">${gate.evidenceDigest ? h(gate.evidenceDigest) : "—"}</td>
        <td>${gate.decidedAt ? h(gate.decidedAt) : "—"}</td>
      </tr>`).join("")}</tbody>
    </table>
    <p class="fingerprint">Admission revision ${h(dossier.admission.revision)} · <span class="mono">${h(dossier.admission.admissionHash)}</span></p>
  </section>

  <section>
    <h2>Bound installation and company configuration</h2>
    <div class="columns">
      <dl>
        ${pair("Product", `${dossier.installation.productName} / ${dossier.installation.organizationName}`)}
        ${pair("Deployment", dossier.installation.deployment.mode)}
        ${pair("Public ingress", dossier.installation.deployment.publicIngress)}
        ${pair("Engine database", dossier.installation.deployment.engineDatabaseBoundary)}
        ${pair("Installation profile", `revision ${dossier.installation.revision}`)}
        ${pair("Installation SHA-256", dossier.installation.profileHash, true)}
      </dl>
      <dl>
        ${pair("Tenant identifier", dossier.tenant.id, true)}
        ${pair("Tenant status", dossier.tenant.status)}
        ${pair("Tenant profile", `revision ${dossier.tenant.profile.revision}`)}
        ${pair("Tenant profile SHA-256", dossier.tenant.profile.profileHash, true)}
        ${pair("Retention profile", dossier.tenant.profile.defaultRetentionProfile)}
        ${pair("Provisioning", dossier.installation.provisioning.mode)}
      </dl>
    </div>
  </section>

  <section>
    <h2>Capacity snapshot</h2>
    <table>
      <thead><tr><th>Resource</th><th>Used</th><th>Limit</th><th>Available</th></tr></thead>
      <tbody>${Object.entries(usage).map(([resource, quota]) => `<tr><td>${h(resourceLabel(resource))}</td><td>${h(quota.used)}</td><td>${h(quota.limit)}</td><td>${h(quota.available)}</td></tr>`).join("")}</tbody>
    </table>
  </section>

  <section>
    <h2>Integration bindings</h2>
    <p>Configuration and credential values are withheld. Hashes bind the active configuration revisions.</p>
    <table>
      <thead><tr><th>Capability</th><th>Adapter</th><th>Status</th><th>Revision</th><th>Configuration SHA-256</th></tr></thead>
      <tbody>${dossier.integrations.map((integration) => `<tr><td>${h(integration.capability)}</td><td>${h(integration.adapterId)} v${h(integration.adapterVersion)}</td><td>${h(title(integration.status))}</td><td>${h(integration.revision)}</td><td class="mono">${h(integration.configHash)}</td></tr>`).join("")}</tbody>
    </table>
    <p>Permitted adapters: ${dossier.installation.adapterPolicy.allowedAdapterIds.map(h).join(", ")}.</p>
    <p>Destination allowlist entry counts: scanner ${h(allowlistCounts.malwareScannerHosts)}; Graph clients ${h(allowlistCounts.microsoftGraphClientIds)}, senders ${h(allowlistCounts.microsoftGraphSenders)}, tenants ${h(allowlistCounts.microsoftGraphTenantIds)}; SMTP ${h(allowlistCounts.smtpHosts)}; webhook ${h(allowlistCounts.webhookHosts)}. Values are withheld.</p>
  </section>

  ${renderProductionStop(dossier)}

  <section>
    <h2>Interpretation limits</h2>
    <ul>${dossier.limitations.map((limitation) => `<li>${h(limitation)}</li>`).join("")}</ul>
  </section>

  <footer>
    <p>Schema ${h(dossier.schema)} · classification ${h(dossier.readiness.classification)}</p>
    <p>The exact export wrapper and dossier used for this report are embedded below as inert JSON. Use the VASI offline verifier and compare its SHA-256 with <span class="mono">${h(exported.dossierHash)}</span>.</p>
  </footer>
</main>
<script type="application/json" id="vasi-readiness-export">${embeddedExport}</script>
<script type="application/json" id="vasi-readiness-dossier">${embeddedDossier}</script>
</body>
</html>\n`;
}

function renderSignedReadinessDossierHTML(exported) {
  const legacyExport = {
    auditEventHash: exported.auditEventHash,
    capturedAt: exported.capturedAt,
    dossier: exported.dossier,
    dossierHash: exported.dossierHash,
    format: exported.format,
    schema: LEGACY_EXPORT_SCHEMA,
  };
  const integritySeal = exported.seals.find((seal) => seal.role === "vasi_integrity");
  const integrityKey = exported.attestation.signingKeys.find((key) => key.role === "vasi_integrity");
  const certificateSeal = exported.seals.find((seal) => seal.role === "certificate");
  const certificateKey = exported.attestation.signingKeys.find((key) => key.role === "certificate");
  const sealSection = `  <section>
    <h2>Export integrity seals</h2>
    <p>The immutable export event, capture time, dossier digest, output format, and signing-key identities are covered by the VASI integrity signature.</p>
    <dl class="summary">
      ${pair("VASI integrity key", integritySeal.keyId)}
      ${pair("Integrity key SHA-256", integrityKey.fingerprint, true)}
      ${pair("Integrity algorithm", integritySeal.algorithm)}
      ${pair("Certificate seal", certificateSeal ? `${certificateSeal.keyId} / ${certificateSeal.algorithm}` : "Not configured")}
      ${pair("Certificate key SHA-256", certificateKey?.fingerprint || "Not configured", Boolean(certificateKey))}
      ${pair("Offline trust check", "Compare the integrity-key SHA-256 with an independently trusted value")}
    </dl>
    <p>An embedded key proves signature consistency, not who controls that key. A certificate seal proves the leaf signature and key match only; chain trust, revocation, policy, and trusted time require independent validation.</p>
  </section>`;
  const legacyFooter = `    <p>The exact export wrapper and dossier used for this report are embedded below as inert JSON. Use the VASI offline verifier and compare its SHA-256 with <span class="mono">${h(exported.dossierHash)}</span>.</p>`;
  const signedFooter = `    <p>The exact signed export wrapper and dossier used for this report are embedded below as inert JSON. Use the VASI offline verifier, compare its dossier SHA-256 with <span class="mono">${h(exported.dossierHash)}</span>, and pin integrity key <span class="mono">${h(integrityKey.fingerprint)}</span> through an independent channel.</p>`;
  let rendered = renderLegacyReadinessDossierHTML(legacyExport);
  rendered = replaceOnce(
    rendered,
    `  <section>\n    <h2>Interpretation limits</h2>`,
    `${sealSection}\n\n  <section>\n    <h2>Interpretation limits</h2>`,
  );
  rendered = replaceOnce(rendered, legacyFooter, signedFooter);
  rendered = replaceOnce(
    rendered,
    `<script type="application/json" id="vasi-readiness-export">${embeddedJSON(legacyExport)}</script>`,
    `<script type="application/json" id="vasi-readiness-export">${embeddedJSON(exported)}</script>`,
  );
  return rendered;
}

export function verifyReadinessDossierBytes(value, { expectedDigest, expectedKeyFingerprint } = {}) {
  const bytes = Buffer.isBuffer(value)
    ? value
    : value instanceof Uint8Array ? Buffer.from(value) : null;
  if (!bytes || !bytes.length || bytes.length > MAXIMUM_READINESS_DOSSIER_BYTES) {
    fail("invalid_file_size");
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("invalid_utf8");
  }
  if (text.includes("\0")) fail("invalid_text");

  let exported;
  let format;
  let presentation;
  if (text.startsWith("{\n")) {
    exported = parseJSON(text, "invalid_json_export");
    validateReadinessExport(exported);
    if (exported.format !== "json" || `${JSON.stringify(exported, null, 2)}\n` !== text) {
      fail("noncanonical_json_export");
    }
    format = "json";
    presentation = "not_applicable";
  } else if (text.startsWith("<!doctype html>\n")) {
    const matches = [...text.matchAll(
      /<script type="application\/json" id="vasi-readiness-export">([^<]*)<\/script>/g,
    )];
    if (matches.length !== 1) fail("invalid_html_embedding");
    exported = parseJSON(matches[0][1], "invalid_html_export");
    validateReadinessExport(exported);
    if (exported.format !== "html" || renderReadinessDossierHTML(exported) !== text) {
      fail("html_presentation_mismatch");
    }
    format = "html";
    presentation = "exact";
  } else {
    fail("unsupported_file_format");
  }

  const expected = expectedDigest === undefined ? undefined : hash(expectedDigest, "expected_digest");
  if (expected && expected !== exported.dossierHash) fail("expected_digest_mismatch");
  const seals = readinessSealSummary(exported);
  const expectedKey = expectedKeyFingerprint === undefined
    ? undefined
    : hash(expectedKeyFingerprint, "expected_key_fingerprint");
  if (expectedKey && !seals.integrityKeyFingerprint) fail("expected_key_unavailable");
  if (expectedKey && expectedKey !== seals.integrityKeyFingerprint) fail("expected_key_mismatch");
  return Object.freeze({
    certificateSeal: seals.certificateSeal,
    dossierSha256: exported.dossierHash,
    expectedDigest: expected ? "matched" : "not_supplied",
    expectedKeyFingerprint: expectedKey ? "matched" : "not_supplied",
    format,
    integrityKeyFingerprint: seals.integrityKeyFingerprint,
    integritySeal: seals.integritySeal,
    presentation,
    schema: READINESS_DOSSIER_VERIFICATION_SCHEMA,
    status: "pass",
  });
}

export async function verifyReadinessDossierFile(filename, options = {}) {
  if (
    typeof filename !== "string" || !filename || Buffer.byteLength(filename) > 4_096 ||
    filename.includes("\0")
  ) fail("invalid_path");
  let handle;
  try {
    handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > MAXIMUM_READINESS_DOSSIER_BYTES) {
      fail("invalid_file");
    }
    const bytes = await handle.readFile();
    if (bytes.length !== stat.size) fail("file_changed");
    return verifyReadinessDossierBytes(bytes, options);
  } catch (error) {
    if (error instanceof ReadinessDossierVerificationError) throw error;
    fail("file_unavailable");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function validateDossier(value) {
  const dossier = exactObject(value, "dossier", [
    "admission", "installation", "integrations", "lastProductionStop",
    "limitations", "readiness", "schema", "tenant",
  ]);
  if (dossier.schema !== DOSSIER_SCHEMA) fail("unsupported_dossier_schema");
  const admission = validateAdmission(dossier.admission);
  validateInstallation(dossier.installation);
  validateIntegrations(dossier.integrations, dossier.installation.adapterPolicy.allowedAdapterIds);
  validateProductionStop(dossier.lastProductionStop);
  if (!sameArray(dossier.limitations, READINESS_DOSSIER_LIMITATIONS)) fail("invalid_limitations");
  validateReadiness(dossier.readiness, admission);
  validateTenant(dossier.tenant);
  return dossier;
}

function validateReadinessAttestation(value) {
  const attestation = exactObject(value, "attestation", [
    "auditEventHash", "capturedAt", "dossierHash", "dossierSchema", "exportSchema",
    "format", "schema", "signingKeys",
  ]);
  if (
    attestation.schema !== READINESS_ATTESTATION_SCHEMA ||
    attestation.dossierSchema !== DOSSIER_SCHEMA ||
    attestation.exportSchema !== SIGNED_READINESS_EXPORT_SCHEMA ||
    !["html", "json"].includes(attestation.format)
  ) fail("invalid_attestation_contract");
  hash(attestation.auditEventHash, "attestation_audit_event_hash");
  canonicalTimestamp(attestation.capturedAt, "attestation_captured_at");
  hash(attestation.dossierHash, "attestation_dossier_hash");
  if (!Array.isArray(attestation.signingKeys) ||
      attestation.signingKeys.length < 1 || attestation.signingKeys.length > 2) {
    fail("invalid_attestation_signing_keys");
  }
  const roles = new Set();
  const keyIds = new Set();
  for (const [index, entry] of attestation.signingKeys.entries()) {
    const key = exactObject(entry, "attestation_signing_key", ["fingerprint", "keyId", "role"]);
    hash(key.fingerprint, "attestation_key_fingerprint");
    safeToken(key.keyId, "attestation_key_id", 1, 128);
    if (!["vasi_integrity", "certificate"].includes(key.role) ||
        roles.has(key.role) || keyIds.has(key.keyId) ||
        (index === 0 && key.role !== "vasi_integrity")) {
      fail("invalid_attestation_signing_key");
    }
    roles.add(key.role);
    keyIds.add(key.keyId);
  }
  if (!roles.has("vasi_integrity")) fail("missing_integrity_signing_key");
  return attestation;
}

function validateReadinessSeals(attestation, value) {
  if (!Array.isArray(value) || value.length !== attestation.signingKeys.length) {
    fail("invalid_readiness_seals");
  }
  for (const [index, rawSeal] of value.entries()) {
    const expected = attestation.signingKeys[index];
    const seal = expected.role === "vasi_integrity"
      ? validateReadinessIntegritySeal(attestation, rawSeal)
      : validateReadinessCertificateSeal(attestation, rawSeal);
    if (
      seal.role !== expected.role || seal.keyId !== expected.keyId ||
      readinessSealFingerprint(seal) !== expected.fingerprint
    ) fail("readiness_seal_key_mismatch");
  }
}

function validateReadinessIntegritySeal(attestation, value) {
  const seal = exactObject(value, "integrity_seal", [
    "algorithm", "keyId", "manifestHash", "profile", "publicJWK", "role", "signature",
  ]);
  if (
    seal.algorithm !== "Ed25519" || seal.profile !== READINESS_DOSSIER_SEAL_PROFILE ||
    seal.role !== "vasi_integrity"
  ) fail("invalid_integrity_seal_contract");
  safeToken(seal.keyId, "integrity_seal_key_id", 1, 128);
  hash(seal.manifestHash, "integrity_seal_manifest_hash");
  validatePublicJWK(seal.publicJWK, "integrity_seal_public_key");
  if (seal.publicJWK.kty !== "OKP" || seal.publicJWK.crv !== "Ed25519") {
    fail("invalid_integrity_seal_public_key");
  }
  base64url(seal.signature, "integrity_seal_signature", 86, 86);
  if (!verifyDetachedIntegritySeal(attestation, seal, [READINESS_DOSSIER_SEAL_PROFILE])) {
    fail("invalid_integrity_seal_signature");
  }
  return seal;
}

function validateReadinessCertificateSeal(attestation, value) {
  const seal = exactObject(value, "certificate_seal", [
    "algorithm", "certificate", "certificateChain", "keyId", "manifestHash", "profile",
    "publicJWK", "role", "signature", "validationScope",
  ]);
  if (
    !["Ed25519", "ECDSA-SHA256", "RSA-SHA256"].includes(seal.algorithm) ||
    seal.profile !== "vasi-certificate-seal/v1" || seal.role !== "certificate" ||
    seal.validationScope !== "leaf_signature_and_key_match"
  ) fail("invalid_certificate_seal_contract");
  safeToken(seal.keyId, "certificate_seal_key_id", 1, 128);
  hash(seal.manifestHash, "certificate_seal_manifest_hash");
  validatePublicJWK(seal.publicJWK, "certificate_seal_public_key");
  base64url(seal.signature, "certificate_seal_signature", 64, 2_048);
  const certificate = exactObject(seal.certificate, "certificate_metadata", [
    "fingerprint256", "issuer", "serialNumber", "subject", "validFrom", "validTo",
  ]);
  hash(certificate.fingerprint256, "certificate_fingerprint");
  boundedCertificateText(certificate.issuer, "certificate_issuer");
  boundedCertificateText(certificate.subject, "certificate_subject");
  if (typeof certificate.serialNumber !== "string" ||
      !/^[A-Fa-f0-9]{1,256}$/.test(certificate.serialNumber)) fail("invalid_certificate_serial");
  canonicalTimestamp(certificate.validFrom, "certificate_valid_from");
  canonicalTimestamp(certificate.validTo, "certificate_valid_to");
  if (!Array.isArray(seal.certificateChain) ||
      seal.certificateChain.length < 1 || seal.certificateChain.length > 10) {
    fail("invalid_certificate_chain");
  }
  let chainBytes = 0;
  for (const pem of seal.certificateChain) {
    if (typeof pem !== "string" || pem.length > 100_000 ||
        !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----$/.test(pem)) {
      fail("invalid_certificate_chain");
    }
    chainBytes += Buffer.byteLength(pem);
  }
  if (chainBytes > 1_000_000 || !verifyCertificateSeal(attestation, seal)) {
    fail("invalid_certificate_seal_signature");
  }
  return seal;
}

function readinessSealSummary(exported) {
  if (exported.schema === LEGACY_EXPORT_SCHEMA) {
    return Object.freeze({
      certificateSeal: "not_present",
      integrityKeyFingerprint: null,
      integritySeal: "not_present",
    });
  }
  const integrityKey = exported.attestation.signingKeys.find((key) => key.role === "vasi_integrity");
  const certificate = exported.seals.some((seal) => seal.role === "certificate");
  return Object.freeze({
    certificateSeal: certificate ? "verified" : "not_present",
    integrityKeyFingerprint: integrityKey.fingerprint,
    integritySeal: "verified",
  });
}

function readinessSealFingerprint(seal) {
  return hashCanonicalJSON({
    certificateChain: seal.role === "certificate" ? seal.certificateChain : undefined,
    publicJWK: seal.publicJWK,
  });
}

function validatePublicJWK(value, name) {
  if (!value || Array.isArray(value) || typeof value !== "object" ||
      Buffer.byteLength(JSON.stringify(value)) > 4_096) fail(`invalid_${name}`);
  if (value.kty === "OKP") {
    exactObject(value, name, ["crv", "kty", "x"]);
    if (value.crv !== "Ed25519") fail(`invalid_${name}`);
    base64url(value.x, name, 43, 43);
  } else if (value.kty === "EC") {
    exactObject(value, name, ["crv", "kty", "x", "y"]);
    if (!['P-256', 'P-384', 'P-521'].includes(value.crv)) fail(`invalid_${name}`);
    base64url(value.x, name, 40, 100);
    base64url(value.y, name, 40, 100);
  } else if (value.kty === "RSA") {
    exactObject(value, name, ["e", "kty", "n"]);
    base64url(value.e, name, 2, 16);
    base64url(value.n, name, 128, 1_024);
  } else {
    fail(`invalid_${name}`);
  }
  return value;
}

function validateAdmission(value) {
  const admission = exactObject(value, "admission", [
    "admissionHash", "gates", "revision", "revisionCreatedAt", "schema", "status",
  ]);
  hash(admission.admissionHash, "admission_hash");
  positiveInteger(admission.revision, "admission_revision");
  canonicalTimestamp(admission.revisionCreatedAt, "admission_revision_created_at");
  let normalized;
  try {
    normalized = validateTenantAdmission({
      gates: admission.gates,
      schema: admission.schema,
      status: admission.status,
    });
  } catch {
    fail("invalid_admission");
  }
  if (hashCanonicalJSON(normalized) !== admission.admissionHash) fail("admission_hash_mismatch");
  return normalized;
}

function validateInstallation(value) {
  const installation = exactObject(value, "installation", [
    "adapterPolicy", "deployment", "engineVersion", "organizationName", "productName",
    "profileHash", "provisioning", "revision",
  ]);
  hash(installation.profileHash, "installation_profile_hash");
  positiveInteger(installation.revision, "installation_revision");
  safeString(installation.organizationName, "organization_name", 2, 120);
  safeString(installation.productName, "product_name", 2, 80);
  if (typeof installation.engineVersion !== "string" ||
      !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(installation.engineVersion) ||
      installation.engineVersion.length > 64) fail("invalid_engine_version");
  const deployment = exactObject(installation.deployment, "deployment", [
    "engineDatabaseBoundary", "mode", "publicIngress",
  ]);
  if (
    deployment.engineDatabaseBoundary !== "dedicated" ||
    !["saas", "self_hosted"].includes(deployment.mode) ||
    deployment.publicIngress !== "gateway_only"
  ) fail("invalid_deployment");
  const provisioning = exactObject(installation.provisioning, "provisioning", ["maxTenants", "mode"]);
  if (provisioning.mode !== "administrators_only") fail("invalid_provisioning");
  boundedInteger(provisioning.maxTenants, "maximum_tenants", 1, 1_000_000);
  const policy = exactObject(installation.adapterPolicy, "adapter_policy", [
    "allowedAdapterIds", "destinationAllowlistCounts",
  ]);
  if (!Array.isArray(policy.allowedAdapterIds) || !policy.allowedAdapterIds.length ||
      policy.allowedAdapterIds.length > SUPPORTED_ADAPTERS.size ||
      new Set(policy.allowedAdapterIds).size !== policy.allowedAdapterIds.length ||
      policy.allowedAdapterIds.some((id) => !SUPPORTED_ADAPTERS.has(id))) {
    fail("invalid_adapter_policy");
  }
  const counts = exactObject(policy.destinationAllowlistCounts, "allowlist_counts", [
    "malwareScannerHosts", "microsoftGraphClientIds", "microsoftGraphSenders",
    "microsoftGraphTenantIds", "smtpHosts", "webhookHosts",
  ]);
  for (const count of Object.values(counts)) boundedInteger(count, "allowlist_count", 0, 1_000_000);
}

function validateIntegrations(value, allowedAdapterIds) {
  if (!Array.isArray(value) || value.length > SUPPORTED_CAPABILITIES.size) fail("invalid_integrations");
  const capabilities = new Set();
  for (const entry of value) {
    const integration = exactObject(entry, "integration", [
      "adapterId", "adapterVersion", "capability", "configHash", "configurationWithheld",
      "revision", "revisionCreatedAt", "status",
    ]);
    const adapter = SUPPORTED_ADAPTERS.get(integration.adapterId);
    if (!adapter || !allowedAdapterIds.includes(integration.adapterId) ||
        !adapter.capabilities.includes(integration.capability) ||
        capabilities.has(integration.capability)) fail("invalid_integration_binding");
    capabilities.add(integration.capability);
    safeToken(integration.adapterVersion, "adapter_version", 1, 64);
    hash(integration.configHash, "integration_config_hash");
    if (integration.configurationWithheld !== true || !["active", "disabled"].includes(integration.status)) {
      fail("invalid_integration_state");
    }
    positiveInteger(integration.revision, "integration_revision");
    canonicalTimestamp(integration.revisionCreatedAt, "integration_revision_created_at");
  }
}

function validateProductionStop(value) {
  if (value === null) return;
  const stop = exactObject(value, "production_stop", [
    "effects", "eventHash", "gateId", "reasonCode", "resultingAdmissionRevision",
    "resultingAdmissionStatus", "stoppedAt",
  ]);
  hash(stop.eventHash, "production_stop_event_hash");
  if (!TENANT_ADMISSION_GATES.includes(stop.gateId) ||
      !TENANT_PRODUCTION_STOP_REASONS.includes(stop.reasonCode) ||
      !["admitted", "pending"].includes(stop.resultingAdmissionStatus)) {
    fail("invalid_production_stop");
  }
  positiveInteger(stop.resultingAdmissionRevision, "production_stop_admission_revision");
  canonicalTimestamp(stop.stoppedAt, "production_stop_timestamp");
  const effects = exactObject(stop.effects, "production_stop_effects", [
    "revokedAssignmentCount", "revokedRequestCount", "suppressedNotificationCount",
  ]);
  for (const count of Object.values(effects)) boundedInteger(count, "production_stop_count", 0, 1_000_000_000);
}

function validateReadiness(value, admission) {
  const readiness = exactObject(value, "readiness", [
    "approvedGateIds", "classification", "externalReviewRequired", "pendingGateIds",
    "technicalAdmissionStatus",
  ]);
  if (
    readiness.classification !== "recorded_evidence_not_certification" ||
    readiness.externalReviewRequired !== true ||
    readiness.technicalAdmissionStatus !== admission.status
  ) fail("invalid_readiness_state");
  const approved = admission.gates.filter((gate) => gate.state === "approved").map((gate) => gate.id);
  const pending = admission.gates.filter((gate) => gate.state === "pending").map((gate) => gate.id);
  if (!sameArray(readiness.approvedGateIds, approved) || !sameArray(readiness.pendingGateIds, pending)) {
    fail("inconsistent_readiness_gates");
  }
}

function validateTenant(value) {
  const tenant = exactObject(value, "tenant", ["id", "name", "profile", "slug", "status", "usage"]);
  uuid(tenant.id, "tenant_id");
  safeString(tenant.name, "tenant_name", 2, 160);
  if (typeof tenant.slug !== "string" || !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(tenant.slug)) {
    fail("invalid_tenant_slug");
  }
  if (!['active', 'disabled'].includes(tenant.status)) fail("invalid_tenant_status");
  const profile = exactObject(tenant.profile, "tenant_profile", [
    "defaultRetentionProfile", "profileHash", "quotas", "revision",
  ]);
  safeToken(profile.defaultRetentionProfile, "retention_profile", 1, 128);
  hash(profile.profileHash, "tenant_profile_hash");
  positiveInteger(profile.revision, "tenant_profile_revision");
  const quotas = exactObject(profile.quotas, "tenant_quotas", Object.keys(QUOTA_LIMITS));
  for (const [name, [minimum, maximum]] of Object.entries(QUOTA_LIMITS)) {
    boundedInteger(quotas[name], name, minimum, maximum);
  }
  if (quotas.maxArtifactBytesPerArtifact > quotas.maxArtifactBytes) fail("invalid_artifact_quota");
  const usage = exactObject(tenant.usage, "tenant_usage", [
    "profileHash", "profileRevision", "resources", "tenantId",
  ]);
  if (
    usage.profileHash !== profile.profileHash || usage.profileRevision !== profile.revision ||
    usage.tenantId !== tenant.id
  ) fail("tenant_usage_binding_mismatch");
  const resources = exactObject(usage.resources, "tenant_resources", Object.keys(RESOURCE_QUOTAS));
  for (const [resource, quotaName] of Object.entries(RESOURCE_QUOTAS)) {
    const measure = exactObject(resources[resource], "tenant_resource", ["available", "limit", "used"]);
    boundedInteger(measure.used, "resource_used", 0, Number.MAX_SAFE_INTEGER);
    if (measure.limit !== quotas[quotaName] || measure.available !== Math.max(0, measure.limit - measure.used)) {
      fail("tenant_resource_mismatch");
    }
  }
}

function renderProductionStop(dossier) {
  const stop = dossier.lastProductionStop;
  if (!stop) return `<section><h2>Production-stop history</h2><p>No tenant production-stop event is present in the current snapshot.</p></section>`;
  return `<section>
    <h2>Latest production stop</h2>
    <dl class="summary">
      ${pair("Stopped", stop.stoppedAt)}
      ${pair("Reason", stop.reasonCode)}
      ${pair("Gate", gateLabels[stop.gateId])}
      ${pair("Result", `${stop.resultingAdmissionStatus}, revision ${stop.resultingAdmissionRevision}`)}
      ${pair("Effects", `${stop.effects.revokedRequestCount} request(s), ${stop.effects.revokedAssignmentCount} assignment(s), ${stop.effects.suppressedNotificationCount} notification(s)`)}
      ${pair("Event SHA-256", stop.eventHash, true)}
    </dl>
  </section>`;
}

function parseJSON(value, code) {
  try {
    return JSON.parse(value);
  } catch {
    fail(code);
  }
}

function embeddedJSON(value) {
  return JSON.stringify(value).replace(/[<>&]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
  );
}

function pair(label, value, mono = false) {
  return `<div><dt>${h(label)}</dt><dd${mono ? ' class="mono"' : ""}>${h(value)}</dd></div>`;
}

function resourceLabel(value) {
  return value.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, (character) => character.toUpperCase());
}

function title(value) {
  return value.replaceAll("_", " ").replace(/^./, (character) => character.toUpperCase());
}

function h(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function exactObject(value, name, keys) {
  if (!value || Array.isArray(value) || typeof value !== "object") fail(`invalid_${name}`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (!sameArray(actual, expected)) fail(`invalid_${name}_fields`);
  return value;
}

function sameArray(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length &&
    actual.every((entry, index) => entry === expected[index]);
}

function safeString(value, name, minimum, maximum) {
  if (
    typeof value !== "string" || value !== value.normalize("NFC") || value !== value.trim() ||
    value.length < minimum || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)
  ) fail(`invalid_${name}`);
  return value;
}

function safeToken(value, name, minimum, maximum) {
  safeString(value, name, minimum, maximum);
  if (!/^[A-Za-z0-9._:-]+$/.test(value)) fail(`invalid_${name}`);
  return value;
}

function base64url(value, name, minimum, maximum) {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum ||
      !/^[A-Za-z0-9_-]+$/.test(value)) fail(`invalid_${name}`);
  return value;
}

function boundedCertificateText(value, name) {
  if (typeof value !== "string" || !value.length || value.length > 4_096 || value.includes("\0")) {
    fail(`invalid_${name}`);
  }
  return value;
}

function replaceOnce(value, search, replacement) {
  const index = value.indexOf(search);
  if (index < 0 || value.indexOf(search, index + search.length) >= 0) fail("html_renderer_state");
  return `${value.slice(0, index)}${replacement}${value.slice(index + search.length)}`;
}

function hash(value, name) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) fail(`invalid_${name}`);
  return value;
}

function uuid(value, name) {
  if (typeof value !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    fail(`invalid_${name}`);
  }
}

function canonicalTimestamp(value, name) {
  if (typeof value !== "string") fail(`invalid_${name}`);
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) fail(`invalid_${name}`);
}

function positiveInteger(value, name) {
  return boundedInteger(value, name, 1, Number.MAX_SAFE_INTEGER);
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(`invalid_${name}`);
  return value;
}

function fail(code) {
  throw new ReadinessDossierVerificationError(code);
}

const reportCSS = `
:root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #17231f; background: #f3f6f4; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px; background: #f3f6f4; }
main { max-width: 1080px; margin: 0 auto; background: #fff; border: 1px solid #d7dfdb; border-radius: 18px; overflow: hidden; box-shadow: 0 18px 48px rgba(20, 55, 46, .08); }
header, section, footer { padding: 28px 36px; border-bottom: 1px solid #e2e8e5; }
footer { border-bottom: 0; background: #f7f9f8; }
h1, h2 { color: #15372e; margin: 0 0 14px; }
h1 { font-size: 34px; }
h2 { font-size: 22px; }
p, li, dd, dt, td, th { line-height: 1.5; }
.eyebrow { color: #28745f; font-size: 12px; font-weight: 800; letter-spacing: .12em; }
.lede { max-width: 780px; color: #4e5e58; }
.summary, .columns dl { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0; margin: 22px 0 0; border: 1px solid #dce4e0; border-radius: 10px; overflow: hidden; }
.summary div, .columns dl div { padding: 12px 14px; border-bottom: 1px solid #e3e9e6; }
.summary div:nth-last-child(-n+2), .columns dl div:nth-last-child(-n+2) { border-bottom: 0; }
dt { color: #596861; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
dd { margin: 3px 0 0; overflow-wrap: anywhere; }
.columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; color: #4b5e56; background: #f2f6f4; }
th, td { padding: 10px; border: 1px solid #dce4e0; vertical-align: top; overflow-wrap: anywhere; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; overflow-wrap: anywhere; }
.state { display: inline-block; border-radius: 999px; padding: 3px 8px; font-weight: 700; }
.state--approved { color: #175c47; background: #dff2ea; }
.state--pending { color: #795b00; background: #fff2c7; }
.fingerprint { color: #5b6964; }
ul { padding-left: 22px; }
@media print { body { padding: 0; background: #fff; } main { max-width: none; border: 0; border-radius: 0; box-shadow: none; } section, header, footer { break-inside: avoid; } }
@media (max-width: 720px) { body { padding: 0; } main { border: 0; border-radius: 0; } header, section, footer { padding: 22px 18px; } .summary, .columns { grid-template-columns: 1fr; } table { display: block; overflow-x: auto; } }
`;
