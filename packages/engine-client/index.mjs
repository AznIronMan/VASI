import { randomUUID } from "node:crypto";
import { request as httpsRequest } from "node:https";

import { importJWK, SignJWT } from "jose";

export async function createActorAssertion(settings, actor, now = Math.floor(Date.now() / 1000)) {
  const privateKey = await importJWK(
    JSON.parse(required(settings, "ENGINE_ASSERTION_PRIVATE_JWK")),
    "EdDSA",
  );
  return new SignJWT({
    authentication: actor.authentication,
    gateway_session_id: actor.gatewaySessionId,
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

export function requestEngine(settings, { method, path, token }) {
  const origin = new URL(required(settings, "ENGINE_ORIGIN"));
  if (origin.protocol !== "https:" || origin.pathname !== "/") {
    throw new Error("ENGINE_ORIGIN must be an HTTPS origin without a path.");
  }
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      new URL(path, origin),
      {
        ca: pem(settings, "ENGINE_CA_CERT"),
        cert: pem(settings, "ENGINE_CLIENT_CERT"),
        headers: token ? { authorization: `Bearer ${token}` } : undefined,
        key: pem(settings, "ENGINE_CLIENT_KEY"),
        method,
        minVersion: "TLSv1.3",
        rejectUnauthorized: true,
        servername: origin.hostname,
        timeout: 7_500,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
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
    request.end();
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
