import { randomUUID } from "node:crypto";
import { request as httpsRequest } from "node:https";

import { importJWK, SignJWT } from "jose";

export async function createActorAssertion(settings, actor, now = Math.floor(Date.now() / 1000)) {
  const privateKey = await importJWK(
    JSON.parse(required(settings, "ENGINE_ASSERTION_PRIVATE_JWK")),
    "EdDSA",
  );
  return new SignJWT({
    authenticated_at: actor.authenticatedAt,
    authentication: {
      method: actor.authentication.method,
      provenance: actor.authentication.provenance,
      provider: actor.authentication.provider,
      provider_subject: actor.authentication.providerSubject,
      linked_provider: actor.authentication.linkedProvider,
      linked_provider_subject: actor.authentication.linkedProviderSubject,
    },
    email: actor.email,
    gateway_session_id: actor.gatewaySessionId,
    request_context: actor.requestContext && {
      accept_language: actor.requestContext.acceptLanguage,
      client_hints: actor.requestContext.clientHints,
      ip_address: actor.requestContext.ipAddress,
      user_agent: actor.requestContext.userAgent,
    },
    roles: actor.roles || [],
    tenant_id: actor.tenantId,
    vasi_principal_id: actor.principalId,
  })
    .setProtectedHeader({
      alg: "EdDSA",
      kid: required(settings, "ENGINE_ASSERTION_KEY_ID"),
      typ: "JWT",
    })
    .setIssuer(required(settings, "ENGINE_ASSERTION_ISSUER"))
    .setAudience(required(settings, "ENGINE_ASSERTION_AUDIENCE"))
    .setSubject(actor.subject)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setNotBefore(now - 5)
    .setExpirationTime(now + 60)
    .sign(privateKey);
}

export function requestEngine(settings, { body, method, path, token }) {
  const origin = new URL(required(settings, "ENGINE_ORIGIN"));
  if (origin.protocol !== "https:" || origin.pathname !== "/") {
    throw new Error("ENGINE_ORIGIN must be an HTTPS origin without a path.");
  }
  return new Promise((resolve, reject) => {
    const requestBody = body === undefined
      ? Buffer.alloc(0)
      : Buffer.from(JSON.stringify(body), "utf8");
    const timeoutMilliseconds = path === "/v1/owner/artifact-finalizations"
      ? 310_000
      : 7_500;
    const request = httpsRequest(
      new URL(path, origin),
      {
        ca: pem(settings, "ENGINE_CA_CERT"),
        cert: pem(settings, "ENGINE_CLIENT_CERT"),
        headers: {
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          ...(requestBody.length
            ? { "content-length": requestBody.length, "content-type": "application/json" }
            : {}),
        },
        key: pem(settings, "ENGINE_CLIENT_KEY"),
        method,
        minVersion: "TLSv1.3",
        rejectUnauthorized: true,
        servername: origin.hostname,
        timeout: timeoutMilliseconds,
      },
      (response) => {
        const chunks = [];
        let length = 0;
        response.on("data", (chunk) => {
          length += chunk.length;
          if (length > 1_048_576) {
            response.destroy(new Error("The private VASI engine response was too large."));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", reject);
        response.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          let json;
          try {
            json = JSON.parse(body);
          } catch {
            json = undefined;
          }
          resolve({ body: json, status: response.statusCode || 0 });
        });
      },
    );
    request.on("error", reject);
    request.on("timeout", () => request.destroy(new Error("VASI engine request timed out.")));
    request.end(requestBody);
  });
}

function required(settings, name) {
  const value = settings[name];
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Required VASI gateway setting ${name} is missing.`);
  }
  return value;
}

function pem(settings, name) {
  return required(settings, name).replaceAll("\\n", "\n");
}
