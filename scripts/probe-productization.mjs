import { randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { hashCanonicalJSON } from "../packages/engine-crypto/index.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";
import { admitConformanceTenant } from "./probe-tenant-admission.mjs";

const settings = await readRuntimeSettings({ scope: "gateway" });
const now = Math.floor(Date.now() / 1_000);
const owner = actor("product-owner", "product-owner@example.test", ["admin"]);
const otherOwner = actor("other-owner", "other-owner@example.test", ["admin"]);
const member = actor("product-member", "product-member@example.test", ["user"]);
const graphTenantId = "11111111-1111-4111-8111-111111111111";
const graphClientId = "22222222-2222-4222-8222-222222222222";
const graphSenderEmail = "notifications@example.test";

const installation = await expectCall(owner, "GET", "/v1/admin/installation-profile", undefined, 200, "installation profile read");
const installationUpdate = await expectCall(owner, "POST", "/v1/admin/installation-profile", {
  expectedRevision: installation.body.revision,
  profile: {
    ...installation.body.profile,
    adapters: {
      ...installation.body.profile.adapters,
      allow: [...new Set([
        ...installation.body.profile.adapters.allow,
        "https_malware_scanner",
        "scan_disabled",
      ])],
      malwareScannerAllowedHosts: ["scanner.example.test"],
      microsoftGraphAllowedClientIds: [graphClientId],
      microsoftGraphAllowedSenders: [graphSenderEmail],
      microsoftGraphAllowedTenantIds: [graphTenantId],
      webhookAllowedHosts: ["events.example.test"],
    },
  },
}, 200, "installation allowlist revision");
if (installationUpdate.body.revision !== installation.body.revision + 1) {
  throw new Error("The installation profile revision did not advance.");
}

const tenantProvisionCommandId = randomUUID();
const tenantProvisionCommand = {
  commandId: tenantProvisionCommandId,
  name: "Productized Tenant Proof",
  ownerEmail: member.email,
  slug: `product-${randomUUID()}`,
};
const tenant = await expectCall(owner, "POST", "/v1/owner/tenants", tenantProvisionCommand, 200, "tenant provisioning");
if (tenant.body.owner?.email !== member.email || tenant.body.owner?.grantCreated !== true) {
  throw new Error("Tenant provisioning did not report the requested durable owner grant.");
}
const replayedTenant = await expectCall(
  owner,
  "POST",
  "/v1/owner/tenants",
  tenantProvisionCommand,
  200,
  "tenant provisioning safe replay",
);
if (hashCanonicalJSON(replayedTenant.body) !== hashCanonicalJSON(tenant.body)) {
  throw new Error("Tenant provisioning replay did not return the exact committed result.");
}
const changedProvision = await expectCall(owner, "POST", "/v1/owner/tenants", {
  ...tenantProvisionCommand,
  name: "Changed Productized Tenant Proof",
}, 409, "tenant provisioning changed-command denial");
if (changedProvision.body.error !== "tenant_provision_command_conflict") {
  throw new Error("Changed tenant provisioning command reuse was not identified.");
}
const ownerHandoff = await expectCall(member, "GET", "/v1/owner/tenants", undefined, 200, "initial owner grant claim");
const handedOffTenant = ownerHandoff.body.find((entry) => entry.id === tenant.body.id);
if (!handedOffTenant?.roles?.includes("owner")) {
  throw new Error("The initial owner grant was not claimed as an engine-owned membership.");
}
const otherTenant = await expectCall(otherOwner, "POST", "/v1/owner/tenants", {
  name: "Isolated Product Tenant",
  ownerEmail: otherOwner.email,
  slug: `product-isolated-${randomUUID()}`,
}, 200, "isolated tenant provisioning");
await expectCall(owner, "POST", "/v1/owner/tenant-profile-read", {
  tenantId: otherTenant.body.id,
}, 403, "tenant profile isolation");
await expectCall(member, "GET", "/v1/admin/installation-profile", undefined, 403, "installation administrator denial");

const profile = await expectCall(owner, "POST", "/v1/owner/tenant-profile-read", {
  tenantId: tenant.body.id,
}, 200, "tenant profile read");
const profileUpdate = await expectCall(owner, "POST", "/v1/owner/tenant-profiles", {
  expectedRevision: profile.body.revision,
  profile: {
    ...profile.body.profile,
    branding: {
      ...profile.body.profile.branding,
      displayName: "Productized Tenant Proof",
      shortName: "Product Proof",
    },
    quotas: {
      ...profile.body.profile.quotas,
      maxActiveRequests: 1,
      maxMembers: 2,
      maxWorkflows: 1,
    },
  },
  tenantId: tenant.body.id,
}, 200, "tenant profile revision");
await expectCall(owner, "POST", "/v1/owner/tenant-profiles", {
  expectedRevision: profile.body.revision,
  profile: profileUpdate.body.profile,
  tenantId: tenant.body.id,
}, 409, "tenant profile optimistic conflict");

await expectCall(owner, "POST", "/v1/owner/members", {
  email: member.email,
  roles: ["auditor"],
  status: "active",
  tenantId: tenant.body.id,
}, 200, "quota member grant");
await expectCall(owner, "POST", "/v1/owner/members", {
  email: "third-member@example.test",
  roles: ["auditor"],
  status: "active",
  tenantId: tenant.body.id,
}, 409, "member quota denial");

const workflow = await expectCall(owner, "POST", "/v1/owner/workflows", {
  document: workflowDocument(),
  name: "Profile-bound workflow",
  tenantId: tenant.body.id,
}, 200, "workflow quota first allocation");
await expectCall(owner, "POST", "/v1/owner/workflows", {
  document: workflowDocument(),
  name: "Excess workflow",
  tenantId: tenant.body.id,
}, 409, "workflow quota denial");
const publication = await expectCall(owner, "POST", "/v1/owner/workflow-publications", {
  definitionId: workflow.body.definitionId,
  expectedDraftVersion: workflow.body.draftVersion,
  tenantId: tenant.body.id,
}, 200, "profile-bound publication");

const integrations = await expectCall(owner, "POST", "/v1/owner/integration-list", {
  tenantId: tenant.body.id,
}, 200, "integration list");
const initialBinding = integrations.body.find((entry) => entry.capability === "notification.delivery");
const initialScannerBinding = integrations.body.find((entry) => entry.capability === "document.malware_scan");
if (!initialBinding || !initialScannerBinding || initialScannerBinding.adapterId !== "scan_disabled") {
  throw new Error("The initial governed integration bindings are incomplete.");
}
const initialAdmissionDenial = await expectCall(owner, "POST", "/v1/owner/requests", {
  intendedEmail: member.email,
  tenantId: tenant.body.id,
  workflowRevisionId: publication.body.revisionId,
}, 409, "pending-admission request denial");
if (initialAdmissionDenial.body.error !== "tenant_not_admitted") {
  throw new Error("A pending tenant was not denied by the admission gate.");
}
await expectCall(owner, "POST", "/v1/owner/integrations", {
  adapterId: "webhook",
  capability: "notification.delivery",
  config: { url: "https://events.example.test/vasi" },
  credentials: { secret: "p".repeat(48) },
  expectedRevision: initialBinding.revision,
  tenantId: tenant.body.id,
}, 409, "pending-admission integration denial");
await expectCall(member, "GET", "/v1/admin/tenant-admissions", undefined, 403, "admission administrator denial");
await expectCall(member, "POST", "/v1/admin/tenant-production-stops", {
  commandId: randomUUID(),
  expectedRevision: 1,
  gateId: "capacity_support",
  incidentReference: "conformance:unauthorized",
  reasonCode: "operator_decision",
  tenantId: tenant.body.id,
}, 403, "production-stop administrator denial");
let admission = await admitConformanceTenant(call, owner, tenant.body.id);
await expectCall(owner, "POST", "/v1/admin/tenant-admissions", {
  decision: "pending",
  expectedRevision: 1,
  gateId: "exact_release",
  tenantId: tenant.body.id,
}, 409, "admission optimistic conflict");
await expectCall(owner, "POST", "/v1/owner/integrations", {
  adapterId: "webhook",
  capability: "notification.delivery",
  config: { url: "https://blocked.example.test/vasi" },
  credentials: { secret: "b".repeat(48) },
  expectedRevision: initialBinding.revision,
  tenantId: tenant.body.id,
}, 403, "integration destination denial");
const secret = `proof-${"s".repeat(48)}`;
const activeBinding = await expectCall(owner, "POST", "/v1/owner/integrations", {
  adapterId: "webhook",
  capability: "notification.delivery",
  config: { url: "https://events.example.test/vasi" },
  credentials: { secret },
  expectedRevision: initialBinding.revision,
  tenantId: tenant.body.id,
}, 200, "allowlisted integration activation");
if (JSON.stringify(activeBinding.body).includes(secret) || !activeBinding.body.configuredCredentials) {
  throw new Error("The integration credential redaction proof failed.");
}
const listedBindings = await expectCall(owner, "POST", "/v1/owner/integration-list", {
  tenantId: tenant.body.id,
}, 200, "redacted integration readback");
if (JSON.stringify(listedBindings.body).includes(secret) || JSON.stringify(listedBindings.body).includes("credentialEnvelope")) {
  throw new Error("The integration list exposed credential material.");
}
const queuedBeforeRevocation = await expectCall(owner, "POST", "/v1/owner/requests", {
  intendedEmail: member.email,
  scheduledFor: new Date(Date.now() + 60_000).toISOString(),
  tenantId: tenant.body.id,
  workflowRevisionId: publication.body.revisionId,
}, 200, "pre-stop scheduled request");
const releaseApproval = admission.admission.gates.find((gate) => gate.id === "exact_release");
const stopCommandId = randomUUID();
const stoppedAdmission = await expectCall(owner, "POST", "/v1/admin/tenant-production-stops", {
  commandId: stopCommandId,
  expectedRevision: admission.revision,
  gateId: "exact_release",
  incidentReference: "conformance:production-stop",
  reasonCode: "operator_decision",
  tenantId: tenant.body.id,
}, 200, "atomic tenant production stop");
if (
  stoppedAdmission.body.status !== "pending" ||
  stoppedAdmission.body.lastProductionStop?.revokedRequestCount !== 1 ||
  stoppedAdmission.body.lastProductionStop?.revokedAssignmentCount !== 1 ||
  stoppedAdmission.body.lastProductionStop?.suppressedNotificationCount !== 1 ||
  stoppedAdmission.body.lastProductionStop?.commandId !== stopCommandId ||
  stoppedAdmission.body.lastProductionStop?.resultingAdmissionRevision !== stoppedAdmission.body.revision
) throw new Error("The tenant production stop did not return its bounded atomic outcome.");
await expectCall(owner, "POST", "/v1/admin/tenant-production-stops", {
  commandId: stopCommandId,
  expectedRevision: admission.revision,
  gateId: "exact_release",
  incidentReference: "conformance:production-stop",
  reasonCode: "operator_decision",
  tenantId: tenant.body.id,
}, 409, "production-stop replay denial");
const postRevocationDenial = await expectCall(owner, "POST", "/v1/owner/requests", {
  intendedEmail: member.email,
  tenantId: tenant.body.id,
  workflowRevisionId: publication.body.revisionId,
}, 409, "post-revocation request denial");
if (postRevocationDenial.body.error !== "tenant_not_admitted") {
  throw new Error("Request issuance did not identify the revoked admission gate.");
}
const suppressed = await waitForDeliveryStatus(
  owner,
  tenant.body.id,
  queuedBeforeRevocation.body.requestId,
  "invitation",
  "suppressed",
  15_000,
);
if (suppressed.status !== "suppressed") throw new Error("The gateway did not suppress queued work after revocation.");
const stoppedRequests = await expectCall(owner, "POST", "/v1/owner/request-list", {
  tenantId: tenant.body.id,
}, 200, "production-stop request state");
if (stoppedRequests.body.find((request) => request.requestId === queuedBeforeRevocation.body.requestId)?.status !== "revoked") {
  throw new Error("The tenant production stop did not revoke the scheduled request.");
}
const stoppedHandle = queuedBeforeRevocation.body.participantPath.split("/").at(-1);
const stoppedOpen = await expectCall(member, "POST", "/v1/participant/open", {
  handle: stoppedHandle,
}, 410, "production-stop participant denial");
if (stoppedOpen.body.error !== "assignment_revoked") {
  throw new Error("A production-stopped participant handle remained available.");
}
const listedStoppedAdmission = await expectCall(owner, "GET", "/v1/admin/tenant-admissions", undefined, 200, "production-stop audit readback");
const listedStop = listedStoppedAdmission.body.find((candidate) => candidate.tenant?.id === tenant.body.id)?.lastProductionStop;
if (listedStop?.commandId !== stopCommandId || !/^[a-f0-9]{64}$/.test(listedStop?.eventHash || "")) {
  throw new Error("The tenant production-stop configuration-chain event was not readable.");
}
const restoredAdmission = await expectCall(owner, "POST", "/v1/admin/tenant-admissions", {
  decision: "approved",
  evidenceDigest: releaseApproval.evidenceDigest,
  evidenceReference: releaseApproval.evidenceReference,
  expectedRevision: stoppedAdmission.body.revision,
  gateId: "exact_release",
  reviewerReference: releaseApproval.reviewerReference,
  tenantId: tenant.body.id,
}, 200, "admission restoration");
admission = restoredAdmission.body;
const graphSecret = `graph-${"g".repeat(48)}`;
const graphBinding = await expectCall(owner, "POST", "/v1/owner/integrations", {
  adapterId: "microsoft_graph",
  capability: "notification.delivery",
  config: {
    clientId: graphClientId,
    senderEmail: graphSenderEmail,
    tenantId: graphTenantId,
  },
  credentials: { clientSecret: graphSecret },
  expectedRevision: activeBinding.body.revision,
  tenantId: tenant.body.id,
}, 200, "allowlisted Microsoft Graph integration activation");
if (
  JSON.stringify(graphBinding.body).includes(graphSecret) ||
  !graphBinding.body.configuredCredentials ||
  graphBinding.body.config.senderEmail !== graphSenderEmail
) throw new Error("The Microsoft Graph integration redaction proof failed.");
await expectCall(owner, "POST", "/v1/owner/integrations", {
  adapterId: "disabled",
  capability: "notification.delivery",
  config: {},
  credentials: {},
  expectedRevision: graphBinding.body.revision,
  status: "disabled",
  tenantId: tenant.body.id,
}, 200, "integration kill switch");
const scannerSecret = `scanner-${"m".repeat(48)}`;
const scannerBinding = await expectCall(owner, "POST", "/v1/owner/integrations", {
  adapterId: "https_malware_scanner",
  capability: "document.malware_scan",
  config: { timeoutSeconds: 30, url: "https://scanner.example.test/v1/scan" },
  credentials: { secret: scannerSecret },
  expectedRevision: initialScannerBinding.revision,
  tenantId: tenant.body.id,
}, 200, "allowlisted malware scanner activation");
if (JSON.stringify(scannerBinding.body).includes(scannerSecret) || !scannerBinding.body.configuredCredentials) {
  throw new Error("The scanner credential redaction proof failed.");
}
await expectCall(owner, "POST", "/v1/owner/integrations", {
  adapterId: "scan_disabled",
  capability: "document.malware_scan",
  config: {},
  credentials: {},
  expectedRevision: scannerBinding.body.revision,
  status: "disabled",
  tenantId: tenant.body.id,
}, 200, "scanner kill switch");

const issued = await expectCall(owner, "POST", "/v1/owner/requests", {
  intendedEmail: member.email,
  tenantId: tenant.body.id,
  workflowRevisionId: publication.body.revisionId,
}, 200, "profile-bound request");
await expectCall(owner, "POST", "/v1/owner/requests", {
  intendedEmail: member.email,
  tenantId: tenant.body.id,
  workflowRevisionId: publication.body.revisionId,
}, 409, "active request quota denial");
const usage = await expectCall(owner, "POST", "/v1/owner/tenant-usage", {
  tenantId: tenant.body.id,
}, 200, "tenant usage read");
if (
  usage.body.resources.members.used !== 2 ||
  usage.body.resources.workflows.used !== 1 ||
  usage.body.resources.activeRequests.used !== 1
) throw new Error("The tenant quota usage proof failed.");

const handle = issued.body.participantPath.split("/").at(-1);
const opened = await expectCall(member, "POST", "/v1/participant/open", { handle }, 200, "profile-bound participant open");
if (
  opened.body.tenant.branding.displayName !== "Productized Tenant Proof" ||
  opened.body.tenant.branding.shortName !== "Product Proof"
) throw new Error("The participant did not receive the issuance-time tenant branding snapshot.");
await expectCall(member, "POST", "/v1/participant/respond", {
  activityId: opened.body.activityId,
  clientContext: { visibility: "visible" },
  commandId: randomUUID(),
  handle,
  interactionId: opened.body.interaction.id,
  response: "acknowledged",
}, 200, "profile-bound participant completion");
const record = await expectCall(owner, "POST", "/v1/owner/records", {
  assignmentId: issued.body.assignmentId,
  tenantId: tenant.body.id,
}, 200, "profile-bound evidence read");
if (
  record.body.manifest.admission?.admissionHash !== admission.admissionHash ||
  record.body.manifest.admission?.admission?.status !== "admitted" ||
  record.body.manifest.admission?.revision !== admission.revision ||
  record.body.manifest.tenant.profileHash !== profileUpdate.body.profileHash ||
  record.body.manifest.tenant.profileBindingProvenance !== "issued" ||
  record.body.manifest.tenant.profile.branding.shortName !== "Product Proof"
) throw new Error("The immutable tenant-profile evidence binding proof failed.");

console.info("VASI installation, tenant profile, quota, integration redaction/allowlist, atomic production-stop, isolation, and evidence-binding checks passed.");

function workflowDocument() {
  return {
    access: { authentication: "verified_email", postCompletion: "receipt_only" },
    activities: [{
      content: { prompt: "Acknowledge the productization proof.", terms: "Immutable proof terms." },
      id: "acknowledge",
      responseMode: "acknowledgement",
      title: "Acknowledgement",
      type: "terms_response",
    }],
    notifications: { onCompletion: false, onIssue: true, reminderHoursBeforeDue: [] },
    purpose: "Productization conformance",
    retention: { profile: "tenant_default" },
    schedule: { defaultDueDays: 7, defaultExpirationDays: 14 },
    schema: "vasi-workflow/v1",
    title: "Productization proof",
  };
}

function actor(id, email, roles) {
  return {
    authenticatedAt: now - 30,
    authentication: { method: "integration-proof", provider: "vsign" },
    email,
    gatewaySessionId: `session-${id}`,
    principalId: `principal-${id}`,
    requestContext: { ipAddress: "192.0.2.1", userAgent: "VASI productization proof" },
    roles,
    subject: `principal-${id}`,
  };
}

async function call(actorContext, method, path, body) {
  const token = await createActorAssertion(settings, actorContext);
  return requestEngine(settings, { body, method, path, token });
}

async function expectCall(actorContext, method, path, body, status, label) {
  const result = await call(actorContext, method, path, body);
  if (result.status !== status) {
    throw new Error(`${label} returned ${result.status} instead of ${status}: ${JSON.stringify(result.body)}`);
  }
  return result;
}

async function waitForDeliveryStatus(
  actorContext,
  tenantId,
  requestId,
  kind,
  status,
  timeoutMilliseconds,
) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    const result = await call(actorContext, "POST", "/v1/owner/request-list", { tenantId });
    if (result.status !== 200) throw new Error(`Delivery-state polling returned ${result.status}.`);
    const state = result.body.find((request) => request.requestId === requestId)
      ?.notificationDelivery?.[kind];
    if (state?.status === status) return state;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`Delivery for ${requestId} did not reach ${status}.`);
}
