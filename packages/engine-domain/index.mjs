const serviceActions = Object.freeze({
  "vasi-private-ingress": new Set([
    "actor.identity",
    "artifact.abort",
    "artifact.chunk.append",
    "artifact.create",
    "artifact.finalize",
    "artifact.list",
    "artifact.owner.open",
    "artifact.owner.read",
    "artifact.participant.open",
    "artifact.participant.read",
    "engine.health",
    "membership.list",
    "membership.update",
    "participant.open",
    "participant.receipt",
    "participant.respond",
    "record.read",
    "request.issue",
    "request.list",
    "request.action",
    "tenant.create",
    "tenant.list",
    "workflow.create",
    "workflow.draft.update",
    "workflow.list",
    "workflow.publish",
  ]),
});

export function authorizeServiceAction(serviceId, action) {
  const actions = serviceActions[serviceId];
  if (!actions?.has(action)) {
    throw new Error("The service principal is not authorized for this engine action.");
  }
  return Object.freeze({ action, serviceId });
}
