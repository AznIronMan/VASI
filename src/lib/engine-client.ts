import { randomUUID } from "node:crypto";
import { request as httpsRequest } from "node:https";

import { importJWK, SignJWT } from "jose";

import { getRuntimeSettings, type RuntimeSettings } from "@/lib/runtime-settings";

export type EngineActor = {
  authenticatedAt?: number;
  authentication: {
    linkedProvider?: string;
    linkedProviderSubject?: string;
    method: string;
    provenance?: string;
    provider?: string;
    providerSubject?: string;
  };
  email?: string;
  gatewaySessionId: string;
  principalId: string;
  roles: string[];
  subject: string;
  tenantId?: string;
  requestContext?: {
    acceptLanguage?: string;
    clientHints?: string;
    ipAddress?: string;
    userAgent?: string;
  };
};

export async function createEngineActorAssertion(
  settings: RuntimeSettings,
  actor: EngineActor,
  now = Math.floor(Date.now() / 1000),
) {
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
    roles: actor.roles,
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

export async function requestEngineIdentity(actor: EngineActor) {
  const result = await requestEngineAction(actor, { method: "POST", path: "/v1/whoami" });
  if (result.status !== 200 || !result.body) {
    throw new Error("The private VASI engine identity check failed.");
  }
  return result.body;
}

export async function requestEngineAction<T>(
  actor: EngineActor,
  request: { body?: unknown; method: "GET" | "POST"; path: string },
) {
  const settings = await getRuntimeSettings();
  const assertion = await createEngineActorAssertion(settings, actor);
  return await requestJSON<T>(settings, request, assertion);
}

function requestJSON<T>(
  settings: RuntimeSettings,
  engineRequest: { body?: unknown; method: "GET" | "POST"; path: string },
  assertion: string,
) {
  const origin = new URL(required(settings, "ENGINE_ORIGIN"));
  if (origin.protocol !== "https:" || origin.pathname !== "/") {
    throw new Error("ENGINE_ORIGIN must be an HTTPS origin without a path.");
  }

  const requestBody = engineRequest.body === undefined
    ? Buffer.alloc(0)
    : Buffer.from(JSON.stringify(engineRequest.body), "utf8");
  return new Promise<{ body?: T; status: number }>((resolve, reject) => {
    const request = httpsRequest(
      new URL(engineRequest.path, origin),
      {
        ca: pem(settings, "ENGINE_CA_CERT"),
        cert: pem(settings, "ENGINE_CLIENT_CERT"),
        headers: {
          authorization: `Bearer ${assertion}`,
          ...(requestBody.length
            ? { "content-length": requestBody.length, "content-type": "application/json" }
            : {}),
        },
        key: pem(settings, "ENGINE_CLIENT_KEY"),
        method: engineRequest.method,
        minVersion: "TLSv1.3",
        rejectUnauthorized: true,
        servername: origin.hostname,
        timeout: 7_500,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let length = 0;
        response.on("data", (chunk: Buffer) => {
          length += chunk.length;
          if (length > 1_048_576) {
            response.destroy(new Error("The private VASI engine response was too large."));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", reject);
        response.on("end", () => {
          try {
            resolve({
              body: JSON.parse(Buffer.concat(chunks).toString("utf8")) as T,
              status: response.statusCode || 0,
            });
          } catch {
            resolve({ status: response.statusCode || 0 });
          }
        });
      },
    );
    request.on("error", reject);
    request.on("timeout", () => request.destroy(new Error("The private VASI engine timed out.")));
    request.end(requestBody);
  });
}

function required(settings: RuntimeSettings, name: string) {
  const value = settings[name];
  if (!value?.trim()) throw new Error(`Required VASI gateway setting ${name} is missing.`);
  return value;
}

function pem(settings: RuntimeSettings, name: string) {
  return required(settings, name).replaceAll("\\n", "\n");
}
