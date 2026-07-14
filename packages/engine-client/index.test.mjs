import { generateKeyPair, exportJWK, importJWK, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";

import { createActorAssertion } from "./index.mjs";

describe("gateway actor assertions", () => {
  it("creates a short-lived EdDSA assertion with engine context", async () => {
    const keys = await generateKeyPair("EdDSA", { extractable: true });
    const privateJWK = await exportJWK(keys.privateKey);
    const publicJWK = await exportJWK(keys.publicKey);
    const token = await createActorAssertion(
      {
        ENGINE_ASSERTION_AUDIENCE: "vasi-engine",
        ENGINE_ASSERTION_ISSUER: "vsign-gateway",
        ENGINE_ASSERTION_KEY_ID: "test-key",
        ENGINE_ASSERTION_PRIVATE_JWK: JSON.stringify(privateJWK),
      },
      {
        authentication: { method: "microsoft", provider: "microsoft" },
        gatewaySessionId: "session-1",
        principalId: "principal-1",
        roles: ["participant"],
        subject: "user-1",
        tenantId: "tenant-1",
      },
      1_700_000_000,
    );
    const verified = await jwtVerify(token, await importJWK(publicJWK, "EdDSA"), {
      audience: "vasi-engine",
      clockTolerance: 10,
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
