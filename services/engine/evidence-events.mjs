import { randomUUID } from "node:crypto";

import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import { EngineStoreError } from "./errors.mjs";

const ENGINE_VERSION = "0.21.3";

export async function appendEvent(client, {
  actor,
  assignmentId,
  eventType,
  payload,
  receivedAt,
  requestId,
  tenantId,
}) {
  const head = await client.query(
    `select "lastSequence", "lastHash" from "vasi_engine"."evidence_chain_head"
     where "assignmentId" = $1 for update`,
    [assignmentId],
  );
  if (!head.rowCount) throw new EngineStoreError("evidence_chain_missing", 500);
  const sequence = Number(head.rows[0].lastSequence) + 1;
  const previousHash = head.rows[0].lastHash;
  const eventId = randomUUID();
  const eventData = {
    actor: actorSnapshot(actor),
    assignmentId,
    engineVersion: ENGINE_VERSION,
    eventId,
    eventType,
    payload,
    previousHash,
    receivedAt: receivedAt.toISOString(),
    requestId,
    schema: "vasi-evidence-event/v1",
    sequence,
    tenantId,
  };
  const eventHash = hashCanonicalJSON(eventData);
  await client.query(
    `insert into "vasi_engine"."evidence_event"
      ("id", "tenantId", "requestId", "assignmentId", "sequence", "eventType",
       "actorPrincipalId", "eventData", "previousHash", "eventHash", "receivedAt", "engineVersion")
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [
      eventId,
      tenantId,
      requestId,
      assignmentId,
      sequence,
      eventType,
      actor.principalId,
      eventData,
      previousHash,
      eventHash,
      receivedAt,
      ENGINE_VERSION,
    ],
  );
  await client.query(
    `update "vasi_engine"."evidence_chain_head"
     set "lastSequence" = $2, "lastHash" = $3 where "assignmentId" = $1`,
    [assignmentId, sequence, eventHash],
  );
  return { eventData, eventHash, previousHash, sequence };
}

function actorSnapshot(actor) {
  return {
    authenticatedAt: actor.authenticatedAt,
    authentication: actor.authentication,
    email: actor.email,
    gatewaySessionId: actor.gatewaySessionId,
    principalId: actor.principalId,
    requestContext: actor.requestContext,
    roles: actor.roles,
  };
}
