const serviceActions = Object.freeze({
  "vasi-private-ingress": new Set([
    "actor.identity",
    "engine.health",
    "participant.open",
    "participant.receipt",
    "participant.respond",
    "record.read",
    "request.issue",
    "tenant.create",
    "tenant.list",
  ]),
});

export function authorizeServiceAction(serviceId, action) {
  const actions = serviceActions[serviceId];
  if (!actions?.has(action)) {
    throw new Error("The service principal is not authorized for this engine action.");
  }
  return Object.freeze({ action, serviceId });
}
