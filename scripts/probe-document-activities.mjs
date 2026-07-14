import { createHash, randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { verifyEvidenceRecord } from "../services/engine/evidence-store.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";
import { admitConformanceTenant } from "./probe-tenant-admission.mjs";

const settings = await readRuntimeSettings({ scope: "gateway" });
const now = Math.floor(Date.now() / 1_000);
const owner = actor("document-owner", "document-owner@example.test", ["admin"]);
const participant = actor("document-participant", "document-participant@example.test", ["user"]);
const intruder = actor("document-intruder", "document-intruder@example.test", ["user"]);

const tenant = await call(owner, "POST", "/v1/owner/tenants", {
  name: "VASI Document Proof",
  slug: `documents-${randomUUID()}`,
});
expectStatus(tenant, 200, "document tenant creation");
await admitConformanceTenant(call, owner, tenant.body.id);

const bytes = Buffer.from(`${"Bounded PostgreSQL artifact proof.\n".repeat(10_000)}Final line.`, "utf8");
const artifact = await uploadArtifact(owner, tenant.body.id, bytes, {
  mediaType: "text/plain",
  originalFilename: "training-policy.txt",
});
if (artifact.status !== "published" || artifact.chunkCount < 2 || artifact.sha256 !== sha256(bytes)) {
  throw new Error("The bounded immutable artifact publication proof failed.");
}

const replacementBytes = Buffer.from("Replacement document revision.\n", "utf8");
const replacement = await uploadArtifact(owner, tenant.body.id, replacementBytes, {
  mediaType: "text/plain",
  originalFilename: "training-policy.txt",
  replacesArtifactId: artifact.id,
});
if (replacement.familyId !== artifact.familyId || replacement.revision !== 2 || replacement.sha256 === artifact.sha256) {
  throw new Error("The artifact replacement revision proof failed.");
}

const rejected = await beginArtifact(owner, tenant.body.id, Buffer.from("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"), {
  mediaType: "text/plain",
  originalFilename: "inspection-test.txt",
});
await expectCall(owner, "POST", "/v1/owner/artifact-chunks", {
  artifactId: rejected.id,
  data: Buffer.from("EICAR-STANDARD-ANTIVIRUS-TEST-FILE").toString("base64"),
  sequence: 1,
  tenantId: tenant.body.id,
}, 409, "out-of-order chunk rejection");
await appendArtifact(owner, tenant.body.id, rejected.id, Buffer.from("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"));
await expectCall(owner, "POST", "/v1/owner/artifact-finalizations", {
  artifactId: rejected.id,
  tenantId: tenant.body.id,
}, 422, "bounded inspection rejection");

const listed = await call(owner, "POST", "/v1/owner/artifact-list", { tenantId: tenant.body.id });
expectStatus(listed, 200, "artifact list");
if (!listed.body.some((entry) => entry.id === rejected.id && entry.status === "rejected")) {
  throw new Error("The retained rejected-artifact inspection record proof failed.");
}

const ownerOpened = await call(owner, "POST", "/v1/owner/artifact-open", {
  artifactId: artifact.id,
  disposition: "inline",
  tenantId: tenant.body.id,
});
expectStatus(ownerOpened, 200, "owner artifact open");
const ownerBytes = await readAllChunks(owner, "/v1/owner/artifact-read", {
  artifactId: artifact.id,
  tenantId: tenant.body.id,
}, artifact.chunkCount);
if (!ownerBytes.equals(bytes)) throw new Error("The authorized owner streaming proof failed.");

const created = await call(owner, "POST", "/v1/owner/workflows", {
  document: workflowDocument(artifact),
  name: "Document and electronic activity proof",
  tenantId: tenant.body.id,
});
expectStatus(created, 200, "rich workflow creation");
const publication = await call(owner, "POST", "/v1/owner/workflow-publications", {
  definitionId: created.body.definitionId,
  expectedDraftVersion: created.body.draftVersion,
  tenantId: tenant.body.id,
});
expectStatus(publication, 200, "rich workflow publication");
if (publication.body.snapshotHash === created.body.documentHash) {
  throw new Error("The publication-time exact artifact-binding hash proof failed.");
}

const issued = await call(owner, "POST", "/v1/owner/requests", {
  intendedEmail: participant.email,
  tenantId: tenant.body.id,
  workflowRevisionId: publication.body.revisionId,
});
expectStatus(issued, 200, "rich request issue");
const handle = issued.body.participantPath.split("/").at(-1);

let opened = await open(participant, handle, "document");
if (opened.body.content.artifact.sha256 !== artifact.sha256) {
  throw new Error("The participant exact artifact binding projection failed.");
}
await expectCall(participant, "POST", "/v1/participant/respond", responseCommand(handle, opened.body, "reviewed"), 409, "document presentation gate");
await expectCall(intruder, "POST", "/v1/participant/artifact-open", {
  activityId: "document",
  artifactId: artifact.id,
  handle,
}, 404, "wrong participant artifact denial");
const participantArtifact = await call(participant, "POST", "/v1/participant/artifact-open", {
  activityId: "document",
  artifactId: artifact.id,
  disposition: "inline",
  handle,
});
expectStatus(participantArtifact, 200, "participant artifact presentation");
const participantBytes = await readAllChunks(participant, "/v1/participant/artifact-read", {
  activityId: "document",
  artifactId: artifact.id,
  handle,
}, artifact.chunkCount);
if (!participantBytes.equals(bytes)) throw new Error("The participant bounded streaming proof failed.");
await save(participant, handle, opened.body, "reviewed");
await submit(participant, handle, opened.body, "reviewed");

opened = await open(participant, handle, "approval");
await save(participant, handle, opened.body, "disapproved");
await submit(participant, handle, opened.body, "approved");

opened = await open(participant, handle, "single");
await submit(participant, handle, opened.body, "green");

opened = await open(participant, handle, "multiple");
await submit(participant, handle, opened.body, ["email", "sms"]);

opened = await open(participant, handle, "freeform");
await save(participant, handle, opened.body, "First saved answer.");
await save(participant, handle, opened.body, "Second saved answer.");
await submit(participant, handle, opened.body, "Final submitted answer.");

opened = await open(participant, handle, "signature");
await submit(participant, handle, opened.body, {
  consent: true,
  method: "typed",
  name: "Document Participant",
});

opened = await open(participant, handle, "test");
if ("correctChoiceIds" in opened.body.content.questions[0]) {
  throw new Error("The participant answer-key redaction proof failed.");
}
const completed = await submit(participant, handle, opened.body, {
  q_one: "b",
  q_two: ["x", "z"],
});
if (!completed.body.integrity?.verified) throw new Error("The rich workflow seal proof failed.");

const record = await call(owner, "POST", "/v1/owner/records", {
  assignmentId: issued.body.assignmentId,
  tenantId: tenant.body.id,
});
expectStatus(record, 200, "rich owner record");
const outcomes = record.body.manifest.outcome.activities;
const approval = outcomes.find((entry) => entry.activityId === "approval");
const freeform = outcomes.find((entry) => entry.activityId === "freeform");
const test = outcomes.find((entry) => entry.activityId === "test");
if (
  record.body.manifest.schema !== "vasi-evidence-manifest/v9" ||
  record.body.manifest.workflow.snapshot.activities[0].content.artifact.sha256 !== artifact.sha256 ||
  outcomes.length !== 7 || approval.revisions.length !== 2 || freeform.revisions.length !== 3 ||
  !test.result?.passed || !verifyEvidenceRecord(record.body)
) {
  throw new Error("The exact material, response-revision, scoring, and sealed-record proof failed.");
}

console.info("VASI PostgreSQL artifact, inspection, streaming, rich activity, response revision, scoring, and seal checks passed.");
await import("./probe-document-malware-scanning.mjs");

async function beginArtifact(actorContext, tenantId, content, metadata) {
  const createdArtifact = await call(actorContext, "POST", "/v1/owner/artifacts", {
    expectedByteLength: content.length,
    ...metadata,
    tenantId,
  });
  expectStatus(createdArtifact, 200, "artifact quarantine creation");
  return createdArtifact.body;
}

async function appendArtifact(actorContext, tenantId, artifactId, content) {
  const size = 262_144;
  for (let sequence = 0, offset = 0; offset < content.length; sequence += 1, offset += size) {
    const appended = await call(actorContext, "POST", "/v1/owner/artifact-chunks", {
      artifactId,
      data: content.subarray(offset, Math.min(offset + size, content.length)).toString("base64"),
      sequence,
      tenantId,
    });
    expectStatus(appended, 200, `artifact chunk ${sequence}`);
  }
}

async function uploadArtifact(actorContext, tenantId, content, metadata) {
  const createdArtifact = await beginArtifact(actorContext, tenantId, content, metadata);
  await appendArtifact(actorContext, tenantId, createdArtifact.id, content);
  const finalized = await call(actorContext, "POST", "/v1/owner/artifact-finalizations", {
    artifactId: createdArtifact.id,
    tenantId,
  });
  expectStatus(finalized, 200, "artifact finalization");
  return finalized.body;
}

async function readAllChunks(actorContext, path, body, count) {
  const chunks = [];
  for (let sequence = 0; sequence < count; sequence += 1) {
    const chunk = await call(actorContext, "POST", path, { ...body, sequence });
    expectStatus(chunk, 200, `artifact read chunk ${sequence}`);
    const bytes = Buffer.from(chunk.body.data, "base64");
    if (sha256(bytes) !== chunk.body.sha256) throw new Error("An artifact read chunk failed verification.");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function workflowDocument(artifact) {
  return {
    access: { authentication: "verified_email", postCompletion: "content_always" },
    activities: [
      { content: { artifactId: artifact.id, displayName: "Training policy", prompt: "Review this document." }, id: "document", responseMode: "document_review", title: "Document review", type: "document_review" },
      { content: { prompt: "Approve this policy?", statement: "I approve the training policy." }, id: "approval", responseMode: "approval", title: "Approval", type: "approval" },
      { content: { choices: [{ id: "green", label: "Green" }, { id: "blue", label: "Blue" }], prompt: "Choose a color." }, id: "single", responseMode: "single_choice", title: "Single choice", type: "single_choice" },
      { content: { choices: [{ id: "email", label: "Email" }, { id: "sms", label: "SMS" }, { id: "phone", label: "Phone" }], maxSelections: 2, minSelections: 1, prompt: "Choose contact methods." }, id: "multiple", responseMode: "multiple_choice", title: "Multiple choice", type: "multiple_choice" },
      { content: { maxLength: 500, minLength: 2, multiline: true, prompt: "Provide a comment." }, id: "freeform", responseMode: "free_form", title: "Comment", type: "free_form" },
      { content: { consentText: "I intend this electronic mark to be my signature.", methods: ["typed", "drawn"], prompt: "Sign the policy.", statement: "I electronically sign the training policy." }, id: "signature", responseMode: "electronic_signature", title: "Electronic signature", type: "electronic_signature" },
      { content: { instructions: "Complete the scored knowledge check.", passingPercent: 75, questions: [{ choices: [{ id: "a", label: "A" }, { id: "b", label: "B" }], correctChoiceIds: ["b"], id: "q_one", points: 3, prompt: "Choose B.", type: "single_choice" }, { choices: [{ id: "x", label: "X" }, { id: "y", label: "Y" }, { id: "z", label: "Z" }], correctChoiceIds: ["x", "z"], id: "q_two", points: 1, prompt: "Choose X and Z.", type: "multiple_choice" }] }, id: "test", responseMode: "questionnaire", title: "Knowledge check", type: "questionnaire" },
    ],
    notifications: { onCompletion: true, onIssue: true, reminderHoursBeforeDue: [24] },
    purpose: "Document and electronic activity conformance proof",
    schedule: { defaultDueDays: 7, defaultExpirationDays: 14 },
    schema: "vasi-workflow/v1",
    title: "Document and electronic activity proof",
  };
}

function responseCommand(handle, assignment, response, intent = "submit") {
  return {
    activityId: assignment.activityId,
    clientContext: { clientStartedAt: new Date().toISOString(), clientSubmittedAt: new Date().toISOString(), timezone: "Etc/UTC" },
    commandId: randomUUID(),
    handle,
    intent,
    interactionId: assignment.interaction.id,
    response,
  };
}

function save(actorContext, handle, assignment, response) {
  return expectCall(actorContext, "POST", "/v1/participant/respond", responseCommand(handle, assignment, response, "save"), 200, `save ${assignment.activityId}`);
}

function submit(actorContext, handle, assignment, response) {
  return expectCall(actorContext, "POST", "/v1/participant/respond", responseCommand(handle, assignment, response), 200, `submit ${assignment.activityId}`);
}

async function open(actorContext, handle, expectedActivityId) {
  const result = await call(actorContext, "POST", "/v1/participant/open", { handle });
  expectStatus(result, 200, `open ${expectedActivityId}`);
  if (result.body.activityId !== expectedActivityId) throw new Error(`Expected ${expectedActivityId}; received ${result.body.activityId}.`);
  return result;
}

function actor(id, email, roles) {
  return {
    authenticatedAt: now - 30,
    authentication: { method: "integration-proof", provider: "vsign" },
    email,
    gatewaySessionId: `session-${id}`,
    principalId: `principal-${id}`,
    requestContext: { ipAddress: "192.0.2.10", userAgent: "VASI document proof" },
    roles,
    subject: `principal-${id}`,
  };
}

async function expectCall(actorContext, method, path, body, status, label) {
  const result = await call(actorContext, method, path, body);
  expectStatus(result, status, label);
  return result;
}

async function call(actorContext, method, path, body) {
  const token = await createActorAssertion(settings, actorContext);
  return requestEngine(settings, { body, method, path, token });
}

function expectStatus(result, status, label) {
  if (result.status !== status) throw new Error(`${label} returned ${result.status} (${result.body?.error}); expected ${status}.`);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
