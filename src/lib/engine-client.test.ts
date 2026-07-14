import { exportJWK, generateKeyPair, importJWK, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";

import { createEngineActorAssertion } from "@/lib/engine-client";

describe("gateway engine client", () => {
  it("binds a short-lived assertion to the gateway session and principal", async () => {
    const keys = await generateKeyPair("EdDSA", { extractable: true });
    const privateJWK = await exportJWK(keys.privateKey);
    const publicJWK = await exportJWK(keys.publicKey);
    const token = await createEngineActorAssertion(
      {
        ENGINE_ASSERTION_AUDIENCE: "vasi-engine",
        ENGINE_ASSERTION_ISSUER: "vsign-gateway",
        ENGINE_ASSERTION_KEY_ID: "test-key",
        ENGINE_ASSERTION_PRIVATE_JWK: JSON.stringify(privateJWK),
      },
      {
        authentication: { method: "google", provider: "google" },
        gatewaySessionId: "session-1",
        principalId: "principal-1",
        roles: ["admin"],
        subject: "user-1",
      },
      1_700_000_000,
    );
    const verified = await jwtVerify(token, await importJWK(publicJWK, "EdDSA"), {
      audience: "vasi-engine",
      currentDate: new Date(1_700_000_010_000),
      issuer: "vsign-gateway",
    });
    expect(verified.payload).toMatchObject({
      exp: 1_700_000_060,
      gateway_session_id: "session-1",
      vasi_principal_id: "principal-1",
    });
  });
});
