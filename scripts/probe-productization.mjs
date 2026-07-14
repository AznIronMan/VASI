import { randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";

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

const tenant = await expectCall(owner, "POST", "/v1/owner/tenants", {
  name: "Productized Tenant Proof",
  slug: `product-${randomUUID()}`,
}, 200, "tenant provisioning");
const otherTenant = await expectCall(otherOwner, "POST", "/v1/owner/tenants", {
  name: "Isolated Product Tenant",
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
  record.body.manifest.tenant.profileHash !== profileUpdate.body.profileHash ||
  record.body.manifest.tenant.profileBindingProvenance !== "issued" ||
  record.body.manifest.tenant.profile.branding.shortName !== "Product Proof"
) throw new Error("The immutable tenant-profile evidence binding proof failed.");

console.info("VASI installation, tenant profile, quota, integration redaction/allowlist, isolation, and evidence-binding checks passed.");

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
