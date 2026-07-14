import { createServer } from "node:http";

import { importJWK, jwtVerify } from "jose";

import {
  resolveEngineRoute,
  validateActorAssertionClaims,
} from "../../packages/engine-contracts/index.mjs";
import { verifyServiceRequest } from "../../packages/engine-crypto/index.mjs";
import { authorizeServiceAction } from "../../packages/engine-domain/index.mjs";
import {
  createSettingsPool,
  loadBootstrapSettings,
  readRuntimeSettings,
} from "../../scripts/settings-core.mjs";
import { readRequestBody, sendJSON } from "../shared/http.mjs";
import { createArtifactStore } from "./artifact-store.mjs";
import { createEvidenceStore, EvidenceStoreError } from "./evidence-store.mjs";
import { EngineStoreError } from "./errors.mjs";
import { createLifecycleStore } from "./lifecycle-store.mjs";
import { createInteractionStore } from "./interaction-store.mjs";
import { createMediaStore } from "./media-store.mjs";
import { createOperationsStore } from "./operations-store.mjs";
import { createProductStore } from "./product-store.mjs";
import { createReportStore } from "./report-store.mjs";
import { initializeSigningKeys } from "./signing-provider.mjs";
import { createWorkflowStore } from "./workflow-store.mjs";

const ENGINE_VERSION = "0.17.0";
const SERVICE_REQUEST_WINDOW_SECONDS = 30;
const bootstrap = loadBootstrapSettings();
const settings = await readRuntimeSettings({ bootstrap, scope: "engine" });
const assertionPublicKey = await importJWK(
  JSON.parse(settings.ENGINE_ASSERTION_PUBLIC_JWK),
  "EdDSA",
);
const database = createSettingsPool(bootstrap);
const evidence = createEvidenceStore(database, settings);
const artifacts = createArtifactStore(database, settings);
const interactions = createInteractionStore(database, settings);
const media = createMediaStore(database, settings);
const lifecycle = createLifecycleStore(database, settings);
const reports = createReportStore(database, settings);
const workflows = createWorkflowStore(database, settings);
const product = createProductStore(database, settings, bootstrap.installationId);
const operations = createOperationsStore(database, { engineVersion: ENGINE_VERSION });
await initializeSigningKeys(database, settings);
await product.initialize();
const seenServiceRequests = new Map();

const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url || "/", "http://engine.internal").pathname;
    const route = resolveEngineRoute(request.method || "GET", path);
    if (!route) return sendJSON(response, 404, { error: "not_found" });
    const body = await readRequestBody(
      request,
      route.action === "artifact.chunk.append" ? 524_288 : 65_536,
    );
    const service = authenticateServiceRequest(request, body, path, route.action);

    if (request.method === "GET" && path === "/healthz") {
      return sendJSON(response, 200, {
        service: "vasi-engine",
        status: "ok",
        version: ENGINE_VERSION,
      });
    }

    if (request.method === "POST" && path === "/v1/whoami") {
      const actor = await verifyActor(request);
      return sendJSON(response, 200, {
        actor: {
          assertionId: actor.assertionId,
          authentication: actor.authentication,
          principalId: actor.principalId,
          roles: actor.roles,
          tenantId: actor.tenantId,
        },
        service: service.serviceId,
      });
    }

    const actor = await verifyActor(request);
    const payload = parseJSONBody(body);
    const result = await dispatchEvidence(route.action, actor, payload);
    return sendJSON(response, 200, result);
  } catch (error) {
    const status = errorStatus(error);
    console.error("VASI engine request rejected", errorCode(error), internalErrorContext(error));
    return sendJSON(response, status, { error: publicErrorCode(error, status) });
  }
});

server.listen(8080, "0.0.0.0", () => {
  console.info(`VASI engine ${ENGINE_VERSION} listening on its private container network.`);
});

function authenticateServiceRequest(request, body, path, action) {
  const serviceId = singleHeader(request.headers["x-vasi-service"]);
  const requestId = singleHeader(request.headers["x-vasi-request-id"]);
  const signature = singleHeader(request.headers["x-vasi-signature"]);
  const timestamp = Number(singleHeader(request.headers["x-vasi-timestamp"]));
  if (
    serviceId !== settings.ENGINE_INGRESS_SERVICE_ID ||
    !requestId ||
    requestId.length > 128 ||
    !Number.isSafeInteger(timestamp)
  ) {
    throw authorizationFailure("Invalid service request metadata.");
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > SERVICE_REQUEST_WINDOW_SECONDS) {
    throw authorizationFailure("Expired service request.");
  }
  pruneServiceReplayCache(now);
  if (seenServiceRequests.has(requestId)) throw authorizationFailure("Replayed service request.");
  const valid = verifyServiceRequest(
    {
      body,
      method: request.method || "GET",
      path,
      requestId,
      serviceId,
      timestamp,
    },
    settings.ENGINE_INTERNAL_HMAC_SECRET,
    signature,
  );
  if (!valid) throw authorizationFailure("Invalid service request signature.");
  seenServiceRequests.set(requestId, now + SERVICE_REQUEST_WINDOW_SECONDS);
  try {
    return authorizeServiceAction(serviceId, action);
  } catch {
    throw authorizationFailure("The service action is unauthorized.");
  }
}

function pruneServiceReplayCache(now) {
  for (const [requestId, expiresAt] of seenServiceRequests) {
    if (expiresAt <= now) seenServiceRequests.delete(requestId);
  }
}

function bearerToken(header) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    throw authorizationFailure("An actor assertion is required.");
  }
  return header.slice("Bearer ".length);
}

async function verifyActor(request) {
  const token = bearerToken(request.headers.authorization);
  let actor;
  try {
    const verified = await jwtVerify(token, assertionPublicKey, {
      algorithms: ["EdDSA"],
      audience: settings.ENGINE_ASSERTION_AUDIENCE,
      clockTolerance: 5,
      issuer: settings.ENGINE_ASSERTION_ISSUER,
      maxTokenAge: "2 minutes",
    });
    actor = validateActorAssertionClaims(verified.payload);
  } catch (error) {
    if (typeof error?.code === "string" && error.code.startsWith("ERR_JWT")) throw error;
    throw authorizationFailure("The actor assertion is invalid.");
  }
  const replay = await database.query(
    `insert into "vasi_engine"."actor_assertion_replay"
      ("jti", "issuer", "subject", "expiresAt")
     values ($1, $2, $3, $4)
     on conflict ("jti") do nothing
     returning "jti"`,
    [
      actor.assertionId,
      settings.ENGINE_ASSERTION_ISSUER,
      actor.subject,
      new Date(actor.expiresAt * 1000),
    ],
  );
  if (!replay.rowCount) throw new EvidenceStoreError("assertion_replayed", 409);
  return actor;
}

function parseJSONBody(body) {
  if (!body.length) return {};
  try {
    const value = JSON.parse(body.toString("utf8"));
    if (!value || Array.isArray(value) || typeof value !== "object") throw new Error();
    return value;
  } catch {
    const error = new Error("The request body is invalid.");
    error.code = "INVALID_JSON";
    throw error;
  }
}

function dispatchEvidence(action, actor, payload) {
  switch (action) {
    case "tenant.list": return workflows.listTenants(actor);
    case "tenant.create": return product.provisionTenant(actor, payload);
    case "tenant.profile.read": return product.getTenantProfile(actor, payload);
    case "tenant.profile.update": return product.updateTenantProfile(actor, payload);
    case "tenant.usage.read": return product.getTenantUsage(actor, payload);
    case "integration.list": return product.listIntegrations(actor, payload);
    case "integration.update": return product.updateIntegration(actor, payload);
    case "installation.profile.read": return product.getInstallationProfile(actor);
    case "installation.profile.update": return product.updateInstallationProfile(actor, payload);
    case "operations.read": return operations.snapshot(actor);
    case "membership.list": return workflows.listMembers(actor, payload);
    case "membership.update": return workflows.setMember(actor, payload);
    case "lifecycle.policy.list": return lifecycle.listPolicies(actor, payload);
    case "lifecycle.policy.update": return lifecycle.updatePolicy(actor, payload);
    case "lifecycle.record.list": return lifecycle.listRecords(actor, payload);
    case "lifecycle.hold.command": return lifecycle.commandHold(actor, payload);
    case "data_request.review.list": return lifecycle.listDataRequestReviews(actor, payload);
    case "data_request.review": return lifecycle.reviewDataRequest(actor, payload);
    case "artifact.list": return artifacts.listArtifacts(actor, payload);
    case "artifact.create": return artifacts.createArtifact(actor, payload);
    case "artifact.chunk.append": return artifacts.appendChunk(actor, payload);
    case "artifact.finalize": return artifacts.finalizeArtifact(actor, payload);
    case "artifact.abort": return artifacts.abortArtifact(actor, payload);
    case "artifact.owner.open": return artifacts.openOwnerArtifact(actor, payload);
    case "artifact.owner.read": return artifacts.readOwnerChunk(actor, payload);
    case "artifact.participant.open": return evidence.openParticipantArtifact(actor, payload);
    case "artifact.participant.read": return evidence.readParticipantArtifactChunk(actor, payload);
    case "workflow.list": return workflows.listWorkflows(actor, payload);
    case "workflow.create": return workflows.createWorkflow(actor, payload);
    case "workflow.draft.update": return workflows.updateDraft(actor, payload);
    case "workflow.publish": return workflows.publishWorkflow(actor, payload);
    case "request.issue": return evidence.issueRequest(actor, payload);
    case "request.list": return evidence.listRequests(actor, payload);
    case "request.action": return evidence.requestAction(actor, payload);
    case "record.read": return evidence.ownerRecord(actor, payload);
    case "record.export.open": return reports.openOwnerExport(actor, payload);
    case "record.export.read": return reports.readOwnerExportChunk(actor, payload);
    case "participant.open": return evidence.openAssignment(actor, payload);
    case "participant.history.list": return lifecycle.listParticipantHistory(actor);
    case "participant.data_request.list": return lifecycle.listParticipantDataRequests(actor);
    case "participant.data_request.create": return lifecycle.createParticipantDataRequest(actor, payload);
    case "participant.data_export.open": return lifecycle.openParticipantDataExport(actor, payload);
    case "participant.data_export.read": return lifecycle.readParticipantDataExportChunk(actor, payload);
    case "participant.respond": return evidence.respond(actor, payload);
    case "participant.interaction.events": return interactions.recordParticipantEvents(actor, payload);
    case "participant.media.open": return media.openParticipantMedia(actor, payload);
    case "participant.media.events": return media.recordParticipantEvents(actor, payload);
    case "participant.receipt": return evidence.participantReceipt(actor, payload);
    case "participant.report.open": return reports.openParticipantReport(actor, payload);
    case "participant.report.read": return reports.readParticipantExportChunk(actor, payload);
    case "verification.lookup": return reports.verifyFingerprint(actor, payload);
    default: throw new EvidenceStoreError("not_found", 404);
  }
}

function singleHeader(value) {
  return Array.isArray(value) ? undefined : value;
}

function errorCode(error) {
  if (error?.code === "ERR_JWT_EXPIRED") return "actor_expired";
  if (error?.code === "BODY_LIMIT") return "body_limit";
  if (error instanceof EngineStoreError) return error.code;
  if (error?.code === "INVALID_JSON") return "invalid_json";
  if (error?.code === "INVALID_WORKFLOW") return "invalid_workflow";
  if (error?.code === "INVALID_ARTIFACT") return "invalid_artifact";
  if (error?.code === "INVALID_ACTIVITY_RESPONSE") return "invalid_activity_response";
  if (error?.code === "INVALID_ACTIVITY_INTERACTION") return "invalid_activity_interaction";
  if (error?.code === "INVALID_MEDIA_TELEMETRY") return "invalid_media_telemetry";
  if (error?.code === "INVALID_LIFECYCLE") return "invalid_lifecycle";
  if (error?.code === "INVALID_PRODUCT_CONFIGURATION") return "invalid_product_configuration";
  if (error?.code === "AUTHORIZATION_FAILED" || String(error?.code || "").startsWith("ERR_JWT")) {
    return "authorization_failed";
  }
  return "internal_failure";
}

function internalErrorContext(error) {
  if (error instanceof EngineStoreError) return undefined;
  return {
    constraint: boundedDiagnostic(error?.constraint),
    sourceCode: boundedDiagnostic(error?.code),
    table: boundedDiagnostic(error?.table),
    type: boundedDiagnostic(error?.name),
  };
}

function boundedDiagnostic(value) {
  return typeof value === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(value) ? value : undefined;
}

function errorStatus(error) {
  if (error?.code === "BODY_LIMIT") return 413;
  if (error?.code === "INVALID_JSON") return 400;
  if (error?.code === "INVALID_WORKFLOW") return 400;
  if (error?.code === "INVALID_ARTIFACT") return 400;
  if (error?.code === "INVALID_ACTIVITY_RESPONSE") return 400;
  if (error?.code === "INVALID_ACTIVITY_INTERACTION") return 400;
  if (error?.code === "INVALID_MEDIA_TELEMETRY") return 400;
  if (error?.code === "INVALID_LIFECYCLE") return 400;
  if (error?.code === "INVALID_PRODUCT_CONFIGURATION") return 400;
  if (error instanceof EngineStoreError) return error.status;
  if (error?.code === "AUTHORIZATION_FAILED" || String(error?.code || "").startsWith("ERR_JWT")) return 401;
  return 500;
}

function publicErrorCode(error, status) {
  if (error instanceof EngineStoreError) return error.code;
  if (error?.code === "INVALID_ARTIFACT") return "invalid_artifact";
  if (error?.code === "INVALID_ACTIVITY_RESPONSE") return "invalid_activity_response";
  if (error?.code === "INVALID_ACTIVITY_INTERACTION") return "invalid_activity_interaction";
  if (error?.code === "INVALID_MEDIA_TELEMETRY") return "invalid_media_telemetry";
  if (error?.code === "INVALID_LIFECYCLE") return "invalid_lifecycle";
  if (error?.code === "INVALID_PRODUCT_CONFIGURATION") return "invalid_product_configuration";
  if (error?.code === "INVALID_WORKFLOW") return "invalid_workflow";
  if (status === 413) return "request_too_large";
  if (status === 400) return "invalid_request";
  if (status === 401) return "unauthorized";
  return "internal_error";
}

function authorizationFailure(message) {
  const error = new Error(message);
  error.code = "AUTHORIZATION_FAILED";
  return error;
}

async function shutDown() {
  server.close();
  await database.end();
  process.exit(0);
}

process.on("SIGINT", shutDown);
process.on("SIGTERM", shutDown);
