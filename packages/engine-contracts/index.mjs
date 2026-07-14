export const ACTOR_ASSERTION_ALGORITHM = "EdDSA";
export const ACTOR_ASSERTION_MAX_LIFETIME_SECONDS = 120;

export function validateActorAssertionClaims(payload, now = Math.floor(Date.now() / 1000)) {
  const subject = requiredString(payload.sub, "sub");
  const assertionId = requiredString(payload.jti, "jti");
  const principalId = requiredString(payload.vasi_principal_id, "vasi_principal_id");
  const gatewaySessionId = requiredString(payload.gateway_session_id, "gateway_session_id");
  const issuedAt = requiredInteger(payload.iat, "iat");
  const expiresAt = requiredInteger(payload.exp, "exp");
  if (expiresAt <= now || issuedAt > now + 15) {
    throw new Error("The actor assertion is outside its accepted time window.");
  }
  if (expiresAt - issuedAt > ACTOR_ASSERTION_MAX_LIFETIME_SECONDS) {
    throw new Error("The actor assertion lifetime is too long.");
  }

  const authentication = payload.authentication;
  if (!authentication || typeof authentication !== "object" || Array.isArray(authentication)) {
    throw new Error("The actor assertion authentication context is required.");
  }
  const method = requiredString(authentication.method, "authentication.method");
  const provider = optionalString(authentication.provider, "authentication.provider");
  const roles = Array.isArray(payload.roles)
    ? payload.roles.map((role) => requiredString(role, "roles[]"))
    : [];
  if (roles.length > 32) throw new Error("The actor assertion contains too many roles.");

  return Object.freeze({
    assertionId,
    authentication: Object.freeze({ method, provider }),
    expiresAt,
    gatewaySessionId,
    issuedAt,
    principalId,
    roles: Object.freeze(roles),
    subject,
    tenantId: optionalString(payload.tenant_id, "tenant_id"),
  });
}

function requiredString(value, field) {
  if (typeof value !== "string" || !value.trim() || value.length > 512) {
    throw new Error(`The actor assertion ${field} claim is invalid.`);
  }
  return value;
}

function optionalString(value, field) {
  if (value === undefined || value === null) return undefined;
  return requiredString(value, field);
}

function requiredInteger(value, field) {
  if (!Number.isSafeInteger(value)) {
    throw new Error(`The actor assertion ${field} claim is invalid.`);
  }
  return value;
}
