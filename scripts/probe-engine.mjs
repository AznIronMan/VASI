import { randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";

const settings = await readRuntimeSettings({ scope: "gateway" });
const health = await requestEngine(settings, { method: "GET", path: "/healthz" });
if (health.status !== 200 || health.body?.status !== "ok") {
  throw new Error("The private VASI engine health proof failed.");
}

const principalId = `probe-${randomUUID()}`;
const token = await createActorAssertion(settings, {
  authentication: { method: "service-proof", provider: "vsign" },
  gatewaySessionId: `probe-${randomUUID()}`,
  principalId,
  roles: ["gateway-probe"],
  subject: principalId,
  tenantId: "system-proof",
});
const identity = await requestEngine(settings, {
  method: "POST",
  path: "/v1/whoami",
  token,
});
if (identity.status !== 200 || identity.body?.actor?.principalId !== principalId) {
  throw new Error("The private VASI engine actor-identity proof failed.");
}

const replay = await requestEngine(settings, {
  method: "GET",
  path: "/v1/owner/tenants",
  token,
});
if (replay.status !== 409 || replay.body?.error !== "assertion_replayed") {
  throw new Error("The private VASI engine replay proof failed.");
}

console.info("VASI private-engine mTLS, actor assertion, and replay checks passed.");
