import { randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { verifyEvidenceRecord } from "../services/engine/evidence-store.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";

const settings = await readRuntimeSettings({ scope: "gateway" });
const now = Math.floor(Date.now() / 1_000);
const owner = actor("owner", "workflow-owner@example.test", ["admin"]);
const manager = actor("manager", "workflow-manager@example.test", ["user"]);
const auditor = actor("auditor", "workflow-auditor@example.test", ["user"]);
const participant = actor("participant", "workflow-participant@example.test", ["user"]);

const tenant = await call(owner, "POST", "/v1/owner/tenants", {
  name: "VASI Workflow Proof",
  slug: `workflow-${randomUUID()}`,
});
expectStatus(tenant, 200, "workflow tenant creation");

await expectCall(owner, "POST", "/v1/owner/members", {
  email: manager.email,
  roles: ["manager"],
  status: "active",
  tenantId: tenant.body.id,
}, 200, "manager grant");
await expectCall(owner, "POST", "/v1/owner/members", {
  email: auditor.email,
  roles: ["auditor"],
  status: "active",
  tenantId: tenant.body.id,
}, 200, "auditor grant");

const managerTenants = await call(manager, "GET", "/v1/owner/tenants");
expectStatus(managerTenants, 200, "email grant claim");
if (!managerTenants.body[0]?.permissions?.includes("workflow.manage")) {
  throw new Error("The engine-owned manager permission proof failed.");
}
await expectCall(auditor, "GET", "/v1/owner/tenants", undefined, 200, "auditor claim");

const firstDocument = workflowDocument("Published revision one");
const created = await call(manager, "POST", "/v1/owner/workflows", {
  document: firstDocument,
  name: "Conditional safety workflow",
  tenantId: tenant.body.id,
});
expectStatus(created, 200, "workflow draft creation");
const publicationOne = await call(manager, "POST", "/v1/owner/workflow-publications", {
  definitionId: created.body.definitionId,
  expectedDraftVersion: created.body.draftVersion,
  tenantId: tenant.body.id,
});
expectStatus(publicationOne, 200, "workflow revision one publication");

const updated = await call(manager, "POST", "/v1/owner/workflow-drafts", {
  definitionId: created.body.definitionId,
  document: workflowDocument("Published revision two"),
  expectedDraftVersion: created.body.draftVersion,
  tenantId: tenant.body.id,
});
expectStatus(updated, 200, "workflow draft update");
const publicationTwo = await call(manager, "POST", "/v1/owner/workflow-publications", {
  definitionId: created.body.definitionId,
  expectedDraftVersion: updated.body.draftVersion,
  tenantId: tenant.body.id,
});
expectStatus(publicationTwo, 200, "workflow revision two publication");
if (publicationTwo.body.revision !== 2 || publicationOne.body.snapshotHash === publicationTwo.body.snapshotHash) {
  throw new Error("The immutable workflow revision proof failed.");
}

const issued = await issue(manager, tenant.body.id, publicationOne.body.revisionId);
const handle = issued.body.participantPath.split("/").at(-1);
let opened = await call(participant, "POST", "/v1/participant/open", { handle });
expectStatus(opened, 200, "first activity open");
if (opened.body.activityId !== "decision" || opened.body.progress?.total !== 2) {
  throw new Error("The ordered activity projection proof failed.");
}
const firstResponse = await respond(participant, handle, opened.body, "yes");
expectStatus(firstResponse, 200, "first activity response");
if (firstResponse.body.completed !== false) throw new Error("The workflow continued-state proof failed.");
opened = await call(participant, "POST", "/v1/participant/open", { handle });
expectStatus(opened, 200, "second activity open");
if (opened.body.activityId !== "acknowledge") throw new Error("The workflow transition proof failed.");
const completion = await respond(participant, handle, opened.body, "acknowledged");
expectStatus(completion, 200, "workflow completion");
if (!completion.body.integrity?.verified) throw new Error("The workflow completion seal proof failed.");

const record = await call(auditor, "POST", "/v1/owner/records", {
  assignmentId: issued.body.assignmentId,
  tenantId: tenant.body.id,
});
expectStatus(record, 200, "auditor record access");
if (
  record.body.manifest?.schema !== "vasi-evidence-manifest/v4" ||
  record.body.manifest.workflow.snapshot.title !== "Published revision one" ||
  record.body.manifest.outcome.activities.length !== 2 ||
  !verifyEvidenceRecord(record.body)
) {
  throw new Error("The revision-bound structured record proof failed.");
}

const branched = await issue(manager, tenant.body.id, publicationOne.body.revisionId);
const branchHandle = branched.body.participantPath.split("/").at(-1);
const branchOpen = await call(participant, "POST", "/v1/participant/open", { handle: branchHandle });
expectStatus(branchOpen, 200, "branch activity open");
const branchComplete = await respond(participant, branchHandle, branchOpen.body, "no");
expectStatus(branchComplete, 200, "terminal branch completion");
if (!branchComplete.body.integrity?.verified) throw new Error("The terminal branch seal proof failed.");

const forbiddenIssue = await issue(auditor, tenant.body.id, publicationOne.body.revisionId);
expectStatus(forbiddenIssue, 403, "auditor issue denial");

const activates = await call(manager, "POST", "/v1/owner/requests", {
  intendedEmail: participant.email,
  scheduledFor: new Date(Date.now() + 2_000).toISOString(),
  tenantId: tenant.body.id,
  workflowRevisionId: publicationTwo.body.revisionId,
});
expectStatus(activates, 200, "near-term scheduled request");
await waitForRequestStatus(manager, tenant.body.id, activates.body.requestId, "issued", 15_000);

const expires = await call(manager, "POST", "/v1/owner/requests", {
  dueAt: new Date(Date.now() + 2_000).toISOString(),
  expiresAt: new Date(Date.now() + 4_000).toISOString(),
  intendedEmail: participant.email,
  tenantId: tenant.body.id,
  workflowRevisionId: publicationTwo.body.revisionId,
});
expectStatus(expires, 200, "near-term expiring request");
await waitForRequestStatus(manager, tenant.body.id, expires.body.requestId, "expired", 15_000);

const scheduled = await call(manager, "POST", "/v1/owner/requests", {
  intendedEmail: participant.email,
  scheduledFor: new Date(Date.now() + 3_600_000).toISOString(),
  tenantId: tenant.body.id,
  workflowRevisionId: publicationTwo.body.revisionId,
});
expectStatus(scheduled, 200, "scheduled request");
const scheduledHandle = scheduled.body.participantPath.split("/").at(-1);
await expectCall(participant, "POST", "/v1/participant/open", { handle: scheduledHandle }, 425, "schedule gate");
const reminderCommand = randomUUID();
await expectCall(manager, "POST", "/v1/owner/request-actions", {
  action: "remind",
  commandId: reminderCommand,
  requestId: scheduled.body.requestId,
  tenantId: tenant.body.id,
}, 200, "manual reminder queue");
await expectCall(manager, "POST", "/v1/owner/request-actions", {
  action: "remind",
  commandId: reminderCommand,
  requestId: scheduled.body.requestId,
  tenantId: tenant.body.id,
}, 409, "lifecycle command replay");
const reissued = await call(manager, "POST", "/v1/owner/request-actions", {
  action: "reissue",
  commandId: randomUUID(),
  requestId: scheduled.body.requestId,
  tenantId: tenant.body.id,
});
expectStatus(reissued, 200, "request reissue");
if (!reissued.body.participantPath) throw new Error("The one-time reissue link proof failed.");

await expectCall(owner, "POST", "/v1/owner/members", {
  email: owner.email,
  roles: ["manager"],
  status: "disabled",
  tenantId: tenant.body.id,
}, 409, "last owner protection");

const requestList = await call(manager, "POST", "/v1/owner/request-list", { tenantId: tenant.body.id });
expectStatus(requestList, 200, "request status list");
if (requestList.body.length < 4) throw new Error("The request lifecycle projection proof failed.");

console.info("VASI workflow draft, publication, role, branch, lifecycle, access, outbox, and seal checks passed.");

function workflowDocument(title) {
  return {
    access: { authentication: "verified_email", postCompletion: "content_until_expiration" },
    activities: [
      {
        content: { prompt: "Do you agree?", terms: "Exact decision terms." },
        id: "decision",
        responseMode: "yes_no",
        title: "Decision",
        transition: { cases: [{ to: null, when: { equals: "no" } }] },
        type: "terms_response",
      },
      {
        content: { prompt: "Please acknowledge.", terms: "Exact acknowledgement terms." },
        id: "acknowledge",
        responseMode: "acknowledgement",
        title: "Acknowledgement",
        type: "terms_response",
      },
    ],
    notifications: { onCompletion: true, onIssue: true, reminderHoursBeforeDue: [24] },
    purpose: "Workflow conformance proof",
    schedule: { defaultDueDays: 7, defaultExpirationDays: 14 },
    schema: "vasi-workflow/v1",
    title,
  };
}

function actor(id, email, roles) {
  return {
    authenticatedAt: now - 30,
    authentication: { method: "integration-proof", provider: "vsign" },
    email,
    gatewaySessionId: `session-${id}`,
    principalId: `principal-${id}`,
    requestContext: { ipAddress: "192.0.2.1", userAgent: "VASI workflow proof" },
    roles,
    subject: `principal-${id}`,
  };
}

function issue(actorContext, tenantId, workflowRevisionId) {
  return call(actorContext, "POST", "/v1/owner/requests", {
    intendedEmail: participant.email,
    tenantId,
    workflowRevisionId,
  });
}

function respond(actorContext, handle, assignment, response) {
  return call(actorContext, "POST", "/v1/participant/respond", {
    activityId: assignment.activityId,
    clientContext: {
      clientStartedAt: new Date().toISOString(),
      clientSubmittedAt: new Date().toISOString(),
      timezone: "Etc/UTC",
    },
    commandId: randomUUID(),
    handle,
    interactionId: assignment.interaction.id,
    response,
  });
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

async function waitForRequestStatus(actorContext, tenantId, requestId, status, timeoutMilliseconds) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    const list = await call(actorContext, "POST", "/v1/owner/request-list", { tenantId });
    expectStatus(list, 200, `request ${status} poll`);
    if (list.body.find((request) => request.requestId === requestId)?.status === status) return;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`The worker did not transition request ${requestId} to ${status}.`);
}

function expectStatus(result, status, label) {
  if (result.status !== status) {
    throw new Error(`${label} returned ${result.status} (${result.body?.error}); expected ${status}.`);
  }
}
