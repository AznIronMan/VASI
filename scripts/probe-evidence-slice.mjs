import { randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { verifyEvidenceRecord } from "../services/engine/evidence-store.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";
import { admitConformanceTenant } from "./probe-tenant-admission.mjs";

const settings = await readRuntimeSettings({ scope: "gateway" });
const now = Math.floor(Date.now() / 1000);
const owner = actor("owner", "owner@example.test", ["admin"]);
const outsider = actor("outsider", "outsider@example.test", ["admin"]);
const participant = actor("participant", "participant@example.test", ["user"]);
const wrongParticipant = actor("wrong-participant", "wrong@example.test", ["user"]);

const tenant = await call(owner, "POST", "/v1/owner/tenants", {
  name: "VASI Evidence Proof",
  slug: `proof-${randomUUID()}`,
});
expectStatus(tenant, 200, "tenant creation");
await admitConformanceTenant(call, owner, tenant.body.id);

const outsiderTenant = await call(outsider, "POST", "/v1/owner/tenants", {
  name: "VASI Isolation Proof",
  slug: `isolation-${randomUUID()}`,
});
expectStatus(outsiderTenant, 200, "isolation tenant creation");

const issued = await call(owner, "POST", "/v1/owner/requests", {
  intendedEmail: participant.email,
  prompt: "Do you agree to these exact proof terms?",
  purpose: "Automated sealed evidence conformance proof",
  responseMode: "yes_no",
  tenantId: tenant.body.id,
  terms: "This immutable text exists only in the disposable VASI integration database.",
  title: "Sealed evidence proof",
});
expectStatus(issued, 200, "request issue");
const handle = issued.body.participantPath.split("/").at(-1);

const wrongOpen = await call(wrongParticipant, "POST", "/v1/participant/open", { handle });
expectStatus(wrongOpen, 404, "cross-participant isolation");

const opened = await call(participant, "POST", "/v1/participant/open", { handle });
expectStatus(opened, 200, "participant open");
if (opened.body.content?.terms !== "This immutable text exists only in the disposable VASI integration database.") {
  throw new Error("The exact participant content proof failed.");
}

const completed = await call(participant, "POST", "/v1/participant/respond", {
  clientContext: {
    clientStartedAt: new Date().toISOString(),
    clientSubmittedAt: new Date().toISOString(),
    timezone: "Etc/UTC",
  },
  commandId: randomUUID(),
  handle,
  interactionId: opened.body.interaction.id,
  response: "yes",
});
expectStatus(completed, 200, "participant completion");
if (!completed.body.integrity?.verified) throw new Error("The participant receipt seal proof failed.");

const replay = await call(participant, "POST", "/v1/participant/respond", {
  commandId: randomUUID(),
  handle,
  interactionId: opened.body.interaction.id,
  response: "yes",
});
expectStatus(replay, 409, "response replay rejection");

const receipt = await call(participant, "POST", "/v1/participant/receipt", { handle });
expectStatus(receipt, 200, "participant receipt");

const record = await call(owner, "POST", "/v1/owner/records", {
  assignmentId: issued.body.assignmentId,
  tenantId: tenant.body.id,
});
expectStatus(record, 200, "owner structured record");
if (record.body.events?.length !== 3 || !verifyEvidenceRecord(record.body)) {
  throw new Error("The structured evidence chain proof failed.");
}

const crossTenant = await call(outsider, "POST", "/v1/owner/records", {
  assignmentId: issued.body.assignmentId,
  tenantId: tenant.body.id,
});
expectStatus(crossTenant, 403, "cross-tenant isolation");

const tampered = structuredClone(record.body);
tampered.events[2].eventData.payload.response = "no";
let tamperRejected = false;
try {
  verifyEvidenceRecord(tampered);
} catch {
  tamperRejected = true;
}
if (!tamperRejected) throw new Error("The evidence tamper proof failed.");

console.info("VASI sealed evidence issue, access, response, receipt, isolation, replay, and tamper checks passed.");

function actor(id, email, roles) {
  return {
    authenticatedAt: now - 30,
    authentication: { method: "integration-proof", provider: "vsign" },
    email,
    gatewaySessionId: `session-${id}`,
    principalId: `principal-${id}`,
    requestContext: { ipAddress: "192.0.2.1", userAgent: "VASI integration proof" },
    roles,
    subject: `principal-${id}`,
  };
}

async function call(actorContext, method, path, body) {
  const token = await createActorAssertion(settings, actorContext);
  return await requestEngine(settings, { body, method, path, token });
}

function expectStatus(result, status, label) {
  if (result.status !== status) {
    throw new Error(`${label} returned ${result.status}; expected ${status}.`);
  }
}
