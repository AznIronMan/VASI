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
import { createEvidenceStore, EvidenceStoreError } from "./evidence-store.mjs";

const ENGINE_VERSION = "0.5.0";
const SERVICE_REQUEST_WINDOW_SECONDS = 30;
const bootstrap = loadBootstrapSettings();
const settings = await readRuntimeSettings({ bootstrap, scope: "engine" });
const assertionPublicKey = await importJWK(
  JSON.parse(settings.ENGINE_ASSERTION_PUBLIC_JWK),
  "EdDSA",
);
const database = createSettingsPool(bootstrap);
const evidence = createEvidenceStore(database, settings);
const seenServiceRequests = new Map();

const server = createServer(async (request, response) => {
  try {
    const body = await readRequestBody(request);
    const path = new URL(request.url || "/", "http://engine.internal").pathname;
    const route = resolveEngineRoute(request.method || "GET", path);
    if (!route) return sendJSON(response, 404, { error: "not_found" });
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
    console.error("VASI engine request rejected", errorCode(error));
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
    throw new Error("Invalid service request metadata.");
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > SERVICE_REQUEST_WINDOW_SECONDS) {
    throw new Error("Expired service request.");
  }
  pruneServiceReplayCache(now);
  if (seenServiceRequests.has(requestId)) throw new Error("Replayed service request.");
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
  if (!valid) throw new Error("Invalid service request signature.");
  seenServiceRequests.set(requestId, now + SERVICE_REQUEST_WINDOW_SECONDS);
  return authorizeServiceAction(serviceId, action);
}

function pruneServiceReplayCache(now) {
  for (const [requestId, expiresAt] of seenServiceRequests) {
    if (expiresAt <= now) seenServiceRequests.delete(requestId);
  }
}

function bearerToken(header) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    throw new Error("An actor assertion is required.");
  }
  return header.slice("Bearer ".length);
}

async function verifyActor(request) {
  const token = bearerToken(request.headers.authorization);
  const verified = await jwtVerify(token, assertionPublicKey, {
    algorithms: ["EdDSA"],
    audience: settings.ENGINE_ASSERTION_AUDIENCE,
    clockTolerance: 5,
    issuer: settings.ENGINE_ASSERTION_ISSUER,
    maxTokenAge: "2 minutes",
  });
  const actor = validateActorAssertionClaims(verified.payload);
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
    case "tenant.list": return evidence.listTenants(actor);
    case "tenant.create": return evidence.createTenant(actor, payload);
    case "request.issue": return evidence.issueRequest(actor, payload);
    case "record.read": return evidence.ownerRecord(actor, payload);
    case "participant.open": return evidence.openAssignment(actor, payload);
    case "participant.respond": return evidence.respond(actor, payload);
    case "participant.receipt": return evidence.participantReceipt(actor, payload);
    default: throw new EvidenceStoreError("not_found", 404);
  }
}

function singleHeader(value) {
  return Array.isArray(value) ? undefined : value;
}

function errorCode(error) {
  if (error?.code === "ERR_JWT_EXPIRED") return "actor_expired";
  if (error?.code === "BODY_LIMIT") return "body_limit";
  if (error instanceof EvidenceStoreError) return error.code;
  if (error?.code === "INVALID_JSON") return "invalid_json";
  return "authorization_failed";
}

function errorStatus(error) {
  if (error?.code === "BODY_LIMIT") return 413;
  if (error?.code === "INVALID_JSON") return 400;
  if (error instanceof EvidenceStoreError) return error.status;
  return 401;
}

function publicErrorCode(error, status) {
  if (error instanceof EvidenceStoreError) return error.code;
  if (status === 413) return "request_too_large";
  if (status === 400) return "invalid_request";
  return "unauthorized";
}

async function shutDown() {
  server.close();
  await database.end();
  process.exit(0);
}

process.on("SIGINT", shutDown);
process.on("SIGTERM", shutDown);
