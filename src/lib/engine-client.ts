import { randomUUID } from "node:crypto";
import { request as httpsRequest } from "node:https";

import { importJWK, SignJWT } from "jose";

import { getRuntimeSettings, type RuntimeSettings } from "@/lib/runtime-settings";

export type EngineActor = {
  authentication: {
    method: string;
    provider?: string;
  };
  gatewaySessionId: string;
  principalId: string;
  roles: string[];
  subject: string;
  tenantId?: string;
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
    authentication: actor.authentication,
    gateway_session_id: actor.gatewaySessionId,
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
  const settings = await getRuntimeSettings();
  const assertion = await createEngineActorAssertion(settings, actor);
  const result = await requestJSON(settings, "/v1/whoami", assertion);
  if (result.status !== 200 || !result.body) {
    throw new Error("The private VASI engine identity check failed.");
  }
  return result.body;
}

function requestJSON(settings: RuntimeSettings, path: string, assertion: string) {
  const origin = new URL(required(settings, "ENGINE_ORIGIN"));
  if (origin.protocol !== "https:" || origin.pathname !== "/") {
    throw new Error("ENGINE_ORIGIN must be an HTTPS origin without a path.");
  }

  return new Promise<{ body?: unknown; status: number }>((resolve, reject) => {
    const request = httpsRequest(
      new URL(path, origin),
      {
        ca: pem(settings, "ENGINE_CA_CERT"),
        cert: pem(settings, "ENGINE_CLIENT_CERT"),
        headers: { authorization: `Bearer ${assertion}` },
        key: pem(settings, "ENGINE_CLIENT_KEY"),
        method: "POST",
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
          if (length > 65_536) {
            response.destroy(new Error("The private VASI engine response was too large."));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", reject);
        response.on("end", () => {
          try {
            resolve({
              body: JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown,
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
    request.end();
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
