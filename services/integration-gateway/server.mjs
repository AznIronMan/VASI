import { createServer } from "node:http";

import { validateIntegrationDeliveryCommand } from "../../packages/engine-contracts/integration-gateway.mjs";
import { verifyServiceRequest } from "../../packages/engine-crypto/index.mjs";
import {
  createSettingsPool,
  loadBootstrapSettings,
  readRuntimeSettings,
} from "../../scripts/settings-core.mjs";
import { readRequestBody, sendJSON } from "../shared/http.mjs";
import { createIntegrationGatewayStore } from "./store.mjs";

const VERSION = "0.15.0";
const REQUEST_WINDOW_SECONDS = 30;
const bootstrap = loadBootstrapSettings();
const settings = await readRuntimeSettings({ bootstrap, scope: "engine" });
const gatewayHmacSecret = strongSecret(settings.ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET);
const database = createSettingsPool(bootstrap);
const gateway = createIntegrationGatewayStore(database, settings, bootstrap.installationId);
const seenRequests = new Map();

const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url || "/", "http://integration-gateway.internal").pathname;
    if (request.method === "GET" && path === "/healthz") {
      return sendJSON(response, 200, { service: "vasi-integration-gateway", status: "ok", version: VERSION });
    }
    if (request.method !== "POST" || path !== "/v1/deliver") {
      return sendJSON(response, 404, { error: "not_found" });
    }
    const body = await readRequestBody(request, 65_536);
    authenticateWorker(request, body, path);
    const command = validateIntegrationDeliveryCommand(parseJSON(body));
    return sendJSON(response, 200, await gateway.deliver(command));
  } catch (error) {
    const code = publicErrorCode(error);
    console.error("VASI integration delivery rejected", boundedDiagnostic(error?.code) || "internal_failure");
    return sendJSON(response, code.status, { error: code.error });
  }
});

server.listen(8090, "0.0.0.0", () => {
  console.info(`VASI integration gateway ${VERSION} listening on its isolated container network.`);
});

function authenticateWorker(request, body, path) {
  const serviceId = singleHeader(request.headers["x-vasi-service"]);
  const requestId = singleHeader(request.headers["x-vasi-request-id"]);
  const signature = singleHeader(request.headers["x-vasi-signature"]);
  const timestamp = Number(singleHeader(request.headers["x-vasi-timestamp"]));
  if (serviceId !== "vasi-worker" || !requestId || requestId.length > 128 || !Number.isSafeInteger(timestamp)) {
    throw authorizationError();
  }
  const now = Math.floor(Date.now() / 1_000);
  if (Math.abs(now - timestamp) > REQUEST_WINDOW_SECONDS) throw authorizationError();
  pruneReplayCache(now);
  if (seenRequests.has(requestId)) throw authorizationError();
  if (!verifyServiceRequest({
    body,
    method: request.method || "POST",
    path,
    requestId,
    serviceId,
    timestamp,
  }, gatewayHmacSecret, signature)) {
    throw authorizationError();
  }
  seenRequests.set(requestId, now + REQUEST_WINDOW_SECONDS);
}

function parseJSON(body) {
  try {
    const value = JSON.parse(body.toString("utf8"));
    if (!value || Array.isArray(value) || typeof value !== "object") throw new Error();
    return value;
  } catch {
    const error = new Error("invalid_json");
    error.code = "INVALID_JSON";
    throw error;
  }
}

function publicErrorCode(error) {
  if (error?.code === "AUTHORIZATION_FAILED") return { error: "unauthorized", status: 401 };
  if (error?.code === "INVALID_JSON" || error?.code === "INVALID_INTEGRATION_DELIVERY") {
    return { error: "invalid_request", status: 400 };
  }
  if (error?.code === "BODY_LIMIT") return { error: "request_too_large", status: 413 };
  if (error?.code === "integration_attempt_conflict") return { error: "integration_attempt_conflict", status: 409 };
  return { error: "internal_error", status: 500 };
}

function authorizationError() {
  const error = new Error("authorization_failed");
  error.code = "AUTHORIZATION_FAILED";
  return error;
}

function pruneReplayCache(now) {
  for (const [requestId, expiresAt] of seenRequests) {
    if (expiresAt <= now) seenRequests.delete(requestId);
  }
}

function singleHeader(value) {
  return Array.isArray(value) ? undefined : value;
}

function boundedDiagnostic(value) {
  return typeof value === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(value) ? value : undefined;
}

function strongSecret(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 32) {
    throw new Error("ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET must contain at least 32 bytes.");
  }
  return value;
}

async function shutDown() {
  server.close();
  await database.end();
  process.exit(0);
}

process.on("SIGINT", shutDown);
process.on("SIGTERM", shutDown);
