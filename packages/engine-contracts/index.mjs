export const ACTOR_ASSERTION_ALGORITHM = "EdDSA";
export const ACTOR_ASSERTION_MAX_LIFETIME_SECONDS = 120;

const engineRoutes = Object.freeze([
  { action: "engine.health", method: "GET", path: "/healthz" },
  { action: "actor.identity", method: "POST", path: "/v1/whoami" },
  { action: "tenant.list", method: "GET", path: "/v1/owner/tenants" },
  { action: "tenant.create", method: "POST", path: "/v1/owner/tenants" },
  { action: "tenant.profile.read", method: "POST", path: "/v1/owner/tenant-profile-read" },
  { action: "tenant.profile.update", method: "POST", path: "/v1/owner/tenant-profiles" },
  { action: "tenant.usage.read", method: "POST", path: "/v1/owner/tenant-usage" },
  { action: "integration.list", method: "POST", path: "/v1/owner/integration-list" },
  { action: "integration.update", method: "POST", path: "/v1/owner/integrations" },
  { action: "installation.profile.read", method: "GET", path: "/v1/admin/installation-profile" },
  { action: "installation.profile.update", method: "POST", path: "/v1/admin/installation-profile" },
  { action: "membership.list", method: "POST", path: "/v1/owner/member-list" },
  { action: "membership.update", method: "POST", path: "/v1/owner/members" },
  { action: "lifecycle.policy.list", method: "POST", path: "/v1/owner/retention-policy-list" },
  { action: "lifecycle.policy.update", method: "POST", path: "/v1/owner/retention-policies" },
  { action: "lifecycle.record.list", method: "POST", path: "/v1/owner/lifecycle-record-list" },
  { action: "lifecycle.hold.command", method: "POST", path: "/v1/owner/legal-holds" },
  { action: "data_request.review.list", method: "POST", path: "/v1/owner/data-request-review-list" },
  { action: "data_request.review", method: "POST", path: "/v1/owner/data-request-reviews" },
  { action: "artifact.list", method: "POST", path: "/v1/owner/artifact-list" },
  { action: "artifact.create", method: "POST", path: "/v1/owner/artifacts" },
  { action: "artifact.chunk.append", method: "POST", path: "/v1/owner/artifact-chunks" },
  { action: "artifact.finalize", method: "POST", path: "/v1/owner/artifact-finalizations" },
  { action: "artifact.abort", method: "POST", path: "/v1/owner/artifact-aborts" },
  { action: "artifact.owner.open", method: "POST", path: "/v1/owner/artifact-open" },
  { action: "artifact.owner.read", method: "POST", path: "/v1/owner/artifact-read" },
  { action: "workflow.list", method: "POST", path: "/v1/owner/workflow-list" },
  { action: "workflow.create", method: "POST", path: "/v1/owner/workflows" },
  { action: "workflow.draft.update", method: "POST", path: "/v1/owner/workflow-drafts" },
  { action: "workflow.publish", method: "POST", path: "/v1/owner/workflow-publications" },
  { action: "request.issue", method: "POST", path: "/v1/owner/requests" },
  { action: "request.list", method: "POST", path: "/v1/owner/request-list" },
  { action: "request.action", method: "POST", path: "/v1/owner/request-actions" },
  { action: "record.read", method: "POST", path: "/v1/owner/records" },
  { action: "record.export.open", method: "POST", path: "/v1/owner/evidence-exports" },
  { action: "record.export.read", method: "POST", path: "/v1/owner/evidence-export-chunks" },
  { action: "participant.open", method: "POST", path: "/v1/participant/open" },
  { action: "participant.history.list", method: "GET", path: "/v1/participant/history" },
  { action: "participant.data_request.list", method: "GET", path: "/v1/participant/data-requests" },
  { action: "participant.data_request.create", method: "POST", path: "/v1/participant/data-requests" },
  { action: "participant.data_export.open", method: "POST", path: "/v1/participant/data-exports" },
  { action: "participant.data_export.read", method: "POST", path: "/v1/participant/data-export-chunks" },
  { action: "participant.respond", method: "POST", path: "/v1/participant/respond" },
  { action: "participant.media.open", method: "POST", path: "/v1/participant/media-open" },
  { action: "participant.media.events", method: "POST", path: "/v1/participant/media-events" },
  { action: "participant.receipt", method: "POST", path: "/v1/participant/receipt" },
  { action: "participant.report.open", method: "POST", path: "/v1/participant/reports" },
  { action: "participant.report.read", method: "POST", path: "/v1/participant/report-chunks" },
  { action: "artifact.participant.open", method: "POST", path: "/v1/participant/artifact-open" },
  { action: "artifact.participant.read", method: "POST", path: "/v1/participant/artifact-read" },
  { action: "verification.lookup", method: "POST", path: "/v1/public/verification" },
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
