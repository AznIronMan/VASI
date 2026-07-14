const serviceActions = Object.freeze({
  "vasi-private-ingress": new Set(["engine.health", "actor.identity"]),
});

export function authorizeServiceAction(serviceId, action) {
  const actions = serviceActions[serviceId];
  if (!actions?.has(action)) {
    throw new Error("The service principal is not authorized for this engine action.");
  }
  return Object.freeze({ action, serviceId });
}
