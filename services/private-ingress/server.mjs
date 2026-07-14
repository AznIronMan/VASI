import { randomUUID } from "node:crypto";
import { request as httpRequest } from "node:http";
import { createServer } from "node:https";

import { signServiceRequest } from "../../packages/engine-crypto/index.mjs";
import { resolveEngineRoute } from "../../packages/engine-contracts/index.mjs";
import { loadBootstrapSettings, readRuntimeSettings } from "../../scripts/settings-core.mjs";
import { readRequestBody, sendJSON } from "../shared/http.mjs";

const ENGINE_VERSION = "0.15.0";
const bootstrap = loadBootstrapSettings();
const settings = await readRuntimeSettings({ bootstrap, scope: "engine" });

const server = createServer(
  {
    ca: pem("ENGINE_AUTHORIZED_CLIENT_CA_CERT"),
    cert: pem("ENGINE_INGRESS_TLS_CERT"),
    key: pem("ENGINE_INGRESS_TLS_KEY"),
    minVersion: "TLSv1.3",
    rejectUnauthorized: true,
    requestCert: true,
  },
  async (request, response) => {
    try {
      if (!request.socket.authorized || !hasExpectedClientCertificate(request.socket)) {
        return sendJSON(response, 401, { error: "unauthorized" });
      }
      const path = new URL(request.url || "/", "https://engine.internal").pathname;
      const route = resolveEngineRoute(request.method || "GET", path);
      if (!route) {
        return sendJSON(response, 404, { error: "not_found" });
      }
      const body = await readRequestBody(
        request,
        route.action === "artifact.chunk.append" ? 524_288 : 65_536,
      );
      const requestId = randomUUID();
      const timestamp = Math.floor(Date.now() / 1000);
      const serviceId = settings.ENGINE_INGRESS_SERVICE_ID;
      const signature = signServiceRequest(
        { body, method: request.method, path, requestId, serviceId, timestamp },
        settings.ENGINE_INTERNAL_HMAC_SECRET,
      );
      return proxyToEngine({ body, path, request, requestId, response, serviceId, signature, timestamp });
    } catch (error) {
      console.error("VASI private ingress rejected a request", error?.code || "request_failed");
      return sendJSON(response, error?.code === "BODY_LIMIT" ? 413 : 502, {
        error: error?.code === "BODY_LIMIT" ? "request_too_large" : "private_engine_unavailable",
      });
    }
  },
);

server.listen(8443, "0.0.0.0", () => {
  console.info(`VASI private ingress ${ENGINE_VERSION} is ready for authenticated service traffic.`);
});

function hasExpectedClientCertificate(socket) {
  const fingerprint = socket.getPeerCertificate()?.fingerprint256;
  return normalizeFingerprint(fingerprint) ===
    normalizeFingerprint(settings.ENGINE_AUTHORIZED_CLIENT_FINGERPRINT_SHA256);
}

function normalizeFingerprint(value) {
  return String(value || "").replaceAll(":", "").toLowerCase();
}

function proxyToEngine({
  body,
  path,
  request,
  requestId,
  response,
  serviceId,
  signature,
  timestamp,
}) {
  return new Promise((resolve, reject) => {
    const upstream = httpRequest(
      {
        headers: {
          authorization: request.headers.authorization || "",
          "content-length": body.length,
          "content-type": request.headers["content-type"] || "application/json",
          "x-vasi-request-id": requestId,
          "x-vasi-service": serviceId,
          "x-vasi-signature": signature,
          "x-vasi-timestamp": String(timestamp),
        },
        host: "engine",
        method: request.method,
        path,
        port: 8080,
        timeout: 5_000,
      },
      (upstreamResponse) => {
        const chunks = [];
        upstreamResponse.on("data", (chunk) => chunks.push(chunk));
        upstreamResponse.on("end", () => {
          const upstreamBody = Buffer.concat(chunks);
          response.writeHead(upstreamResponse.statusCode || 502, {
            "cache-control": "no-store",
            "content-length": upstreamBody.length,
            "content-type": "application/json; charset=utf-8",
            "x-content-type-options": "nosniff",
          });
          response.end(upstreamBody);
          resolve();
        });
      },
    );
    upstream.on("error", reject);
    upstream.on("timeout", () => upstream.destroy(new Error("Engine request timed out.")));
    upstream.end(body);
  });
}

process.on("SIGINT", () => server.close(() => process.exit(0)));
process.on("SIGTERM", () => server.close(() => process.exit(0)));

function pem(name) {
  return settings[name].replaceAll("\\n", "\n");
}
