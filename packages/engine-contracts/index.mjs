export const ACTOR_ASSERTION_ALGORITHM = "EdDSA";
export const ACTOR_ASSERTION_MAX_LIFETIME_SECONDS = 120;

const engineRoutes = Object.freeze([
  { action: "engine.health", method: "GET", path: "/healthz" },
  { action: "actor.identity", method: "POST", path: "/v1/whoami" },
  { action: "tenant.list", method: "GET", path: "/v1/owner/tenants" },
  { action: "tenant.create", method: "POST", path: "/v1/owner/tenants" },
  { action: "membership.list", method: "POST", path: "/v1/owner/member-list" },
  { action: "membership.update", method: "POST", path: "/v1/owner/members" },
  { action: "workflow.list", method: "POST", path: "/v1/owner/workflow-list" },
  { action: "workflow.create", method: "POST", path: "/v1/owner/workflows" },
  { action: "workflow.draft.update", method: "POST", path: "/v1/owner/workflow-drafts" },
  { action: "workflow.publish", method: "POST", path: "/v1/owner/workflow-publications" },
  { action: "request.issue", method: "POST", path: "/v1/owner/requests" },
  { action: "request.list", method: "POST", path: "/v1/owner/request-list" },
  { action: "request.action", method: "POST", path: "/v1/owner/request-actions" },
  { action: "record.read", method: "POST", path: "/v1/owner/records" },
  { action: "participant.open", method: "POST", path: "/v1/participant/open" },
  { action: "participant.respond", method: "POST", path: "/v1/participant/respond" },
  { action: "participant.receipt", method: "POST", path: "/v1/participant/receipt" },
]);

export function resolveEngineRoute(method, path) {
  return engineRoutes.find((route) => route.method === method && route.path === path);
}

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
  const provenance = optionalString(authentication.provenance, "authentication.provenance");
  const provider = optionalString(authentication.provider, "authentication.provider");
  const providerSubject = optionalString(
    authentication.provider_subject,
    "authentication.provider_subject",
  );
  const linkedProvider = optionalString(
    authentication.linked_provider,
    "authentication.linked_provider",
  );
  const linkedProviderSubject = optionalString(
    authentication.linked_provider_subject,
    "authentication.linked_provider_subject",
  );
  const roles = Array.isArray(payload.roles)
    ? payload.roles.map((role) => requiredString(role, "roles[]"))
    : [];
  if (roles.length > 32) throw new Error("The actor assertion contains too many roles.");

  return Object.freeze({
    assertionId,
    authenticatedAt: optionalInteger(payload.authenticated_at, "authenticated_at"),
    authentication: Object.freeze({
      linkedProvider,
      linkedProviderSubject,
      method,
      provenance,
      provider,
      providerSubject,
    }),
    email: optionalEmail(payload.email),
    expiresAt,
    gatewaySessionId,
    issuedAt,
    principalId,
    requestContext: validateRequestContext(payload.request_context),
    roles: Object.freeze(roles),
    subject,
    tenantId: optionalString(payload.tenant_id, "tenant_id"),
  });
}

function optionalEmail(value) {
  if (value === undefined || value === null) return undefined;
  const email = requiredString(value, "email").toLowerCase();
  if (email.length > 320 || !/^[^@\s]+@[^@\s]+$/.test(email)) {
    throw new Error("The actor assertion email claim is invalid.");
  }
  return email;
}

function validateRequestContext(value) {
  if (value === undefined || value === null) return undefined;
  if (Array.isArray(value) || typeof value !== "object") {
    throw new Error("The actor assertion request context is invalid.");
  }
  return Object.freeze({
    acceptLanguage: optionalString(value.accept_language, "request_context.accept_language"),
    clientHints: optionalString(value.client_hints, "request_context.client_hints"),
    ipAddress: optionalString(value.ip_address, "request_context.ip_address"),
    userAgent: optionalString(value.user_agent, "request_context.user_agent"),
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

function optionalInteger(value, field) {
  if (value === undefined || value === null) return undefined;
  return requiredInteger(value, field);
}
