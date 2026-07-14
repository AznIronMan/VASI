import { createServer } from "node:http";

import { importJWK, jwtVerify } from "jose";

import { validateActorAssertionClaims } from "../../packages/engine-contracts/index.mjs";
import { verifyServiceRequest } from "../../packages/engine-crypto/index.mjs";
import { authorizeServiceAction } from "../../packages/engine-domain/index.mjs";
import {
  createSettingsPool,
  loadBootstrapSettings,
  readRuntimeSettings,
} from "../../scripts/settings-core.mjs";
import { readRequestBody, sendJSON } from "../shared/http.mjs";

const ENGINE_VERSION = "0.4.0";
const SERVICE_REQUEST_WINDOW_SECONDS = 30;
const bootstrap = loadBootstrapSettings();
const settings = await readRuntimeSettings({ bootstrap, scope: "engine" });
const assertionPublicKey = await importJWK(
  JSON.parse(settings.ENGINE_ASSERTION_PUBLIC_JWK),
  "EdDSA",
);
const database = createSettingsPool(bootstrap);
const seenServiceRequests = new Map();

const server = createServer(async (request, response) => {
  try {
    const body = await readRequestBody(request);
    const path = new URL(request.url || "/", "http://engine.internal").pathname;
    const action = path === "/healthz" ? "engine.health" : "actor.identity";
    const service = authenticateServiceRequest(request, body, path, action);

    if (request.method === "GET" && path === "/healthz") {
      return sendJSON(response, 200, {
        service: "vasi-engine",
        status: "ok",
        version: ENGINE_VERSION,
      });
    }

    if (request.method === "POST" && path === "/v1/whoami") {
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
      if (!replay.rowCount) return sendJSON(response, 409, { error: "assertion_replayed" });

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

    return sendJSON(response, 404, { error: "not_found" });
  } catch (error) {
    const status = error?.code === "BODY_LIMIT" ? 413 : 401;
    console.error("VASI engine request rejected", errorCode(error));
    return sendJSON(response, status, { error: status === 413 ? "request_too_large" : "unauthorized" });
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

function singleHeader(value) {
  return Array.isArray(value) ? undefined : value;
}

function errorCode(error) {
  if (error?.code === "ERR_JWT_EXPIRED") return "actor_expired";
  if (error?.code === "BODY_LIMIT") return "body_limit";
  return "authorization_failed";
}

async function shutDown() {
  server.close();
  await database.end();
  process.exit(0);
}

process.on("SIGINT", shutDown);
process.on("SIGTERM", shutDown);
