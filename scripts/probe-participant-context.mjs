import { randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { buildEvidenceReports } from "../packages/evidence-reporting/index.mjs";
import { verifyEvidenceRecord } from "../services/engine/evidence-store.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";

const settings = await readRuntimeSettings({ scope: "gateway" });
const now = Math.floor(Date.now() / 1_000);
const owner = actor("context-owner", "context-owner@example.test", ["admin"]);
const participant = actor("context-participant", "context-participant@example.test", ["user"]);
const intruder = actor("context-intruder", "context-intruder@example.test", ["user"]);

const tenant = await call(owner, "POST", "/v1/owner/tenants", {
  name: "VASI Participant Context Proof",
  slug: `context-${randomUUID()}`,
});
expectStatus(tenant, 200, "context tenant creation");
const created = await call(owner, "POST", "/v1/owner/workflows", {
  document: workflowDocument(),
  name: "Participant context proof",
  tenantId: tenant.body.id,
});
expectStatus(created, 200, "context workflow creation");
const published = await call(owner, "POST", "/v1/owner/workflow-publications", {
  definitionId: created.body.definitionId,
  expectedDraftVersion: created.body.draftVersion,
  tenantId: tenant.body.id,
});
expectStatus(published, 200, "context workflow publication");
const issued = await call(owner, "POST", "/v1/owner/requests", {
  intendedEmail: participant.email,
  tenantId: tenant.body.id,
  workflowRevisionId: published.body.revisionId,
});
expectStatus(issued, 200, "context request issue");
const handle = issued.body.participantPath.split("/").at(-1);
const opened = await call(participant, "POST", "/v1/participant/open", { handle });
expectStatus(opened, 200, "context participant open");

const contextSessionId = randomUUID();
const presentation = submission(handle, opened.body, contextSessionId, snapshot(1, "presentation", 0));
await expectCall(intruder, "POST", "/v1/participant/context-snapshots", presentation, 404, "wrong-participant context denial");
await expectCall(participant, "POST", "/v1/participant/context-snapshots", {
  ...presentation,
  snapshot: { ...presentation.snapshot, plugins: ["forbidden"] },
}, 400, "plugin-enumeration context denial");
const accepted = await call(participant, "POST", "/v1/participant/context-snapshots", presentation);
expectStatus(accepted, 200, "presentation context snapshot");
if (!accepted.body.accepted || accepted.body.duplicate || !accepted.body.payloadHash) {
  throw new Error("The participant-context acceptance proof failed.");
}
const duplicate = await call(participant, "POST", "/v1/participant/context-snapshots", presentation);
expectStatus(duplicate, 200, "context snapshot idempotency");
if (!duplicate.body.duplicate || duplicate.body.accepted) {
  throw new Error("The participant-context idempotency proof failed.");
}
await expectCall(participant, "POST", "/v1/participant/context-snapshots", {
  ...presentation,
  snapshot: {
    ...presentation.snapshot,
    display: { ...presentation.snapshot.display, viewportWidth: 1280 },
  },
}, 409, "changed context replay denial");
await expectCall(participant, "POST", "/v1/participant/context-snapshots", submission(
  handle,
  opened.body,
  contextSessionId,
  snapshot(1, "save", 1_000),
), 409, "context sequence replay denial");

const responseContext = submission(
  handle,
  opened.body,
  contextSessionId,
  snapshot(2, "submission", 5_000),
);
expectStatus(
  await call(participant, "POST", "/v1/participant/context-snapshots", responseContext),
  200,
  "submission context snapshot",
);
const completed = await call(participant, "POST", "/v1/participant/respond", {
  activityId: opened.body.activityId,
  clientContext: {
    clientStartedAt: new Date().toISOString(),
    clientSubmittedAt: new Date().toISOString(),
    timezone: "Etc/UTC",
  },
  commandId: randomUUID(),
  handle,
  interactionId: opened.body.interaction.id,
  response: "acknowledged",
});
expectStatus(completed, 200, "context-qualified activity completion");

const record = await call(owner, "POST", "/v1/owner/records", {
  assignmentId: issued.body.assignmentId,
  tenantId: tenant.body.id,
});
expectStatus(record, 200, "context owner record");
const evidence = record.body.manifest.participantContext;
if (
  record.body.manifest.schema !== "vasi-evidence-manifest/v6" ||
  evidence.policy.version !== "vasi-participant-context-policy/v1" ||
  evidence.policy.reliabilityClass !== "browser_reported" ||
  evidence.snapshots.length !== 2 ||
  evidence.snapshots.some((entry) => entry.snapshot.provenance.source !== "browser_api") ||
  record.body.events.filter((entry) =>
    entry.eventData?.eventType === "participant.context.recorded"
  ).length !== 2 ||
  !verifyEvidenceRecord(record.body)
) throw new Error("The sealed participant-context evidence proof failed.");

const reports = buildEvidenceReports(record.body);
if (reports.participant.contextEvidence.snapshotCount !== 2 ||
    JSON.stringify(reports.participant).includes("viewportWidth") ||
    !JSON.stringify(reports.technical).includes("viewportWidth")) {
  throw new Error("The participant-context report audience proof failed.");
}

const tampered = structuredClone(record.body);
tampered.manifest.participantContext.snapshots[0].snapshot.display.viewportWidth = 1279;
let tamperRejected = false;
try {
  verifyEvidenceRecord(tampered);
} catch {
  tamperRejected = true;
}
if (!tamperRejected) throw new Error("The offline participant-context hash proof failed.");

console.info("VASI participant-context privacy, isolation, replay, sealing, report, and tamper checks passed.");

function submission(handle, assignment, contextSessionId, contextSnapshot) {
  return {
    activityId: assignment.activityId,
    contextSessionId,
    handle,
    interactionId: assignment.interaction.id,
    snapshot: contextSnapshot,
  };
}

function snapshot(sequence, purpose, monotonicMs) {
  return {
    browser: {
      language: "en-US",
      languages: ["en-US", "en"],
      online: true,
      timeZone: "America/Los_Angeles",
    },
    capabilities: {
      cookiesEnabled: true,
      localStorage: "available",
      pdfViewerEnabled: true,
      sessionStorage: "available",
    },
    clientOccurredAt: new Date(Date.now() + sequence).toISOString(),
    connection: { downlinkMbps: 10, effectiveType: "4g", rttMs: 50, saveData: false },
    display: {
      availableHeight: 1040,
      availableWidth: 1920,
      colorDepth: 24,
      devicePixelRatio: 2,
      pixelDepth: 24,
      screenHeight: 1080,
      screenWidth: 1920,
      viewportHeight: 900,
      viewportWidth: 1440,
    },
    id: randomUUID(),
    input: { maxTouchPoints: 0 },
    monotonicMs,
    preferences: {
      colorScheme: "dark",
      contrast: "no-preference",
      forcedColors: false,
      reducedMotion: true,
    },
    purpose,
    schema: "vasi-participant-context/v1",
    sequence,
  };
}

function workflowDocument() {
  return {
    access: { authentication: "verified_email", postCompletion: "receipt_only" },
    activities: [{
      content: {
        acknowledgementLabel: "I acknowledge the participant-context proof terms.",
        prompt: "Acknowledge the proof terms.",
        terms: "This exact text is used to prove privacy-bounded participant context evidence.",
      },
      id: "terms",
      responseMode: "acknowledgement",
      title: "Participant context",
      type: "terms_response",
    }],
    notifications: { onCompletion: true, onIssue: true, reminderHoursBeforeDue: [] },
    purpose: "Participant context conformance proof",
    schedule: { defaultDueDays: 7, defaultExpirationDays: 14 },
    schema: "vasi-workflow/v1",
    title: "Participant context proof",
  };
}

function actor(id, email, roles) {
  return {
    authenticatedAt: now - 30,
    authentication: { method: "integration-proof", provider: "vsign" },
    email,
    gatewaySessionId: `session-${id}`,
    principalId: `principal-${id}`,
    requestContext: {
      acceptLanguage: "en-US,en;q=0.9",
      clientHints: 'brands="Proof";mobile=?0;platform="Test"',
      ipAddress: "192.0.2.42",
      userAgent: "VASI participant context proof",
    },
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

function expectStatus(result, expected, label) {
  if (result.status !== expected) {
    throw new Error(`${label} returned ${result.status}: ${JSON.stringify(result.body)}`);
  }
}
