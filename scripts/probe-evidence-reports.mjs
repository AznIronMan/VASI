import { createHash, randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { assertEvidenceBundle } from "../packages/evidence-verifier/index.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";

const settings = await readRuntimeSettings({ scope: "gateway" });
const expectCertificate = process.env.VASI_EXPECT_CERTIFICATE_SEAL === "1";
const now = Math.floor(Date.now() / 1000);
const owner = actor("report-owner", "report-owner@example.test", ["admin"]);
const outsider = actor("report-outsider", "report-outsider@example.test", ["admin"]);
const participant = actor("report-participant", "report-participant@example.test", ["user"]);
const verifier = actor("public-verifier", undefined, ["verification"]);

const tenant = await call(owner, "/v1/owner/tenants", {
  name: "VASI Report Proof",
  slug: `report-${randomUUID()}`,
});
expectStatus(tenant, 200, "report tenant creation");
await call(outsider, "/v1/owner/tenants", {
  name: "VASI Report Isolation",
  slug: `report-isolation-${randomUUID()}`,
});

const issued = await call(owner, "/v1/owner/requests", {
  intendedEmail: participant.email,
  prompt: "Do you confirm the report proof?",
  purpose: "Deterministic evidence export conformance",
  responseMode: "yes_no",
  tenantId: tenant.body.id,
  terms: "These are the immutable report conformance terms.",
  title: "Evidence report proof",
});
expectStatus(issued, 200, "report request issue");
const handle = issued.body.participantPath.split("/").at(-1);
const opened = await call(participant, "/v1/participant/open", { handle });
expectStatus(opened, 200, "report participant open");
const completed = await call(participant, "/v1/participant/respond", {
  commandId: randomUUID(),
  handle,
  interactionId: opened.body.interaction.id,
  response: "yes",
});
expectStatus(completed, 200, "report participant completion");
const manifestHash = completed.body.integrity.manifestHash;

for (const [profile, format] of [
  ["participant", "html"],
  ["nontechnical", "text"],
  ["technical", "json"],
  ["structured", "json"],
]) {
  const payload = {
    assignmentId: issued.body.assignmentId,
    format,
    kind: "report",
    profile,
    tenantId: tenant.body.id,
  };
  const first = await call(owner, "/v1/owner/evidence-exports", payload);
  const second = await call(owner, "/v1/owner/evidence-exports", payload);
  expectStatus(first, 200, `${profile} report open`);
  expectStatus(second, 200, `${profile} report deterministic reopen`);
  if (first.body.id !== second.body.id || first.body.sha256 !== second.body.sha256) {
    throw new Error(`${profile} report was not deterministically reused.`);
  }
  const bytes = await exportBytes(owner, first.body, "/v1/owner/evidence-export-chunks");
  if (!bytes.includes(Buffer.from(manifestHash, "utf8"))) {
    throw new Error(`${profile} report does not trace to the manifest fingerprint.`);
  }
}

const participantReport = await call(participant, "/v1/participant/reports", {
  format: "html",
  handle,
});
expectStatus(participantReport, 200, "participant report open");
const participantBytes = await exportBytes(
  participant,
  participantReport.body,
  "/v1/participant/report-chunks",
);
if (participantBytes.includes(Buffer.from("192.0.2.1", "utf8"))) {
  throw new Error("The participant report exposed forensic request context.");
}

const bundleOpen = await call(owner, "/v1/owner/evidence-exports", {
  assignmentId: issued.body.assignmentId,
  format: "zip",
  kind: "bundle",
  profile: "full",
  tenantId: tenant.body.id,
});
expectStatus(bundleOpen, 200, "portable bundle open");
const bundleBytes = await exportBytes(owner, bundleOpen.body, "/v1/owner/evidence-export-chunks");
const bundleVerification = assertEvidenceBundle(bundleBytes);
if (
  !bundleVerification.verified ||
  (expectCertificate &&
    !bundleVerification.seals.some((seal) => seal.profile === "vasi-certificate-seal/v1" && seal.verified))
) throw new Error("The exported bundle did not preserve its optional certificate seal.");
const tampered = Buffer.from(bundleBytes);
tampered[80] ^= 1;
if (assertionSucceeds(() => assertEvidenceBundle(tampered))) {
  throw new Error("The offline bundle verifier accepted tampered bytes.");
}

const isolated = await call(outsider, "/v1/owner/evidence-exports", {
  assignmentId: issued.body.assignmentId,
  format: "html",
  kind: "report",
  profile: "nontechnical",
  tenantId: tenant.body.id,
});
expectStatus(isolated, 403, "cross-tenant report isolation");

const known = await call(verifier, "/v1/public/verification", { fingerprint: manifestHash });
expectStatus(known, 200, "known fingerprint verification");
if (
  !known.body.known || !known.body.verified || JSON.stringify(known.body).includes(participant.email) ||
  (expectCertificate && !known.body.seals.some((seal) => seal.role === "certificate" && seal.verified))
) {
  throw new Error("The public fingerprint result was invalid or exposed participant identity.");
}
const unknown = await call(verifier, "/v1/public/verification", { fingerprint: "f".repeat(64) });
expectStatus(unknown, 200, "unknown fingerprint verification");
if (unknown.body.known !== false || JSON.stringify(unknown.body).includes("tenant")) {
  throw new Error("The unknown public fingerprint result exposed record context.");
}

console.info("VASI reports, deterministic exports, portable bundle, public verification, isolation, and tamper checks passed.");

function actor(id, email, roles) {
  return {
    authenticatedAt: email ? now - 30 : undefined,
    authentication: { method: "integration-proof", provider: email ? "vsign" : undefined },
    email,
    gatewaySessionId: `session-${id}`,
    principalId: `principal-${id}`,
    requestContext: { ipAddress: "192.0.2.1", userAgent: "VASI report integration proof" },
    roles,
    subject: `principal-${id}`,
  };
}

async function call(actorContext, path, body) {
  const token = await createActorAssertion(settings, actorContext);
  return requestEngine(settings, { body, method: "POST", path, token });
}

async function exportBytes(actorContext, metadata, path) {
  const chunks = [];
  for (let sequence = 0; sequence < metadata.chunkCount; sequence += 1) {
    const result = await call(actorContext, path, { exportArtifactId: metadata.id, sequence });
    expectStatus(result, 200, `export chunk ${sequence}`);
    const bytes = Buffer.from(result.body.data, "base64");
    if (
      bytes.length !== result.body.byteLength ||
      createHash("sha256").update(bytes).digest("hex") !== result.body.sha256
    ) throw new Error(`Export chunk ${sequence} failed its gateway integrity check.`);
    chunks.push(bytes);
  }
  const bytes = Buffer.concat(chunks);
  if (bytes.length !== metadata.byteLength || createHash("sha256").update(bytes).digest("hex") !== metadata.sha256) {
    throw new Error("The assembled export failed its integrity check.");
  }
  return bytes;
}

function assertionSucceeds(callback) {
  try {
    callback();
    return true;
  } catch {
    return false;
  }
}

function expectStatus(result, status, label) {
  if (result.status !== status) {
    throw new Error(`${label} returned ${result.status}; expected ${status}.`);
  }
}
