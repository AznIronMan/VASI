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
    "installation.profile.read",
    "installation.profile.update",
    "integration.list",
    "integration.update",
    "membership.list",
    "membership.update",
    "operations.read",
    "lifecycle.hold.command",
    "lifecycle.policy.list",
    "lifecycle.policy.update",
    "lifecycle.record.list",
    "data_request.review",
    "data_request.review.list",
    "participant.open",
    "participant.history.list",
    "participant.data_request.create",
    "participant.data_request.list",
    "participant.data_export.open",
    "participant.data_export.read",
    "participant.media.open",
    "participant.receipt",
    "participant.report.open",
    "participant.report.read",
    "participant.respond",
    "participant.media.events",
    "record.read",
    "record.export.open",
    "record.export.read",
    "request.issue",
    "request.list",
    "request.action",
    "tenant.create",
    "tenant.list",
    "tenant.profile.read",
    "tenant.profile.update",
    "tenant.usage.read",
    "workflow.create",
    "workflow.draft.update",
    "workflow.list",
    "workflow.publish",
    "verification.lookup",
  ]),
});

export function authorizeServiceAction(serviceId, action) {
  const actions = serviceActions[serviceId];
  if (!actions?.has(action)) {
    throw new Error("The service principal is not authorized for this engine action.");
  }
  return Object.freeze({ action, serviceId });
}

export * from "./media.mjs";
export * from "./lifecycle.mjs";
export * from "./productization.mjs";
