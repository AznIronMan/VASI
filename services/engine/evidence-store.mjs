import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  buildEvidenceManifest,
  validateIssueInput,
  validateParticipantResponse,
  validateTenantInput,
} from "../../packages/engine-domain/evidence.mjs";
import {
  createIntegritySeal,
  hashCanonicalJSON,
  verifyIntegritySeal,
} from "../../packages/engine-crypto/index.mjs";

const ENGINE_VERSION = "0.5.0";
const GENESIS_HASH = "0".repeat(64);

export class EvidenceStoreError extends Error {
  constructor(code, status, message = code) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function createEvidenceStore(database, settings) {
  const sealPrivateJWK = parseJWK(settings.EVIDENCE_SEAL_PRIVATE_JWK, "private");
  const sealPublicJWK = parseJWK(settings.EVIDENCE_SEAL_PUBLIC_JWK, "public");
  const sealKeyId = requiredSetting(settings, "EVIDENCE_SEAL_KEY_ID");
  const keyProof = createIntegritySeal({
    keyId: sealKeyId,
    manifest: { keyId: sealKeyId, schema: "vasi-seal-key-check/v1" },
    privateJWK: sealPrivateJWK,
  });
  if (hashCanonicalJSON(keyProof.publicJWK) !== hashCanonicalJSON(sealPublicJWK)) {
    throw new Error("The VASI evidence seal private and public keys do not match.");
  }

  return Object.freeze({
    async createTenant(actor, payload) {
      requireActor(actor);
      if (!actor.roles.includes("admin")) deny();
      const input = validateTenantInput(payload);
      if (!/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(input.slug)) {
        throw new EvidenceStoreError("invalid_tenant_slug", 400);
      }
      return transaction(database, async (client) => {
        const tenantId = randomUUID();
        try {
          await client.query(
            `insert into "vasi_engine"."tenant" ("id", "slug", "name")
             values ($1, $2, $3)`,
            [tenantId, input.slug, input.name],
          );
        } catch (error) {
          if (error?.code === "23505") {
            throw new EvidenceStoreError("tenant_slug_exists", 409);
          }
          throw error;
        }
        await client.query(
          `insert into "vasi_engine"."tenant_membership"
            ("tenantId", "principalId", "roles") values ($1, $2, $3)`,
          [tenantId, actor.principalId, ["owner"]],
        );
        return { id: tenantId, name: input.name, roles: ["owner"], slug: input.slug };
      });
    },

    async listTenants(actor) {
      requireActor(actor);
      const result = await database.query(
        `select t."id", t."name", t."slug", m."roles"
         from "vasi_engine"."tenant_membership" m
         join "vasi_engine"."tenant" t on t."id" = m."tenantId"
         where m."principalId" = $1 and m."status" = 'active' and t."status" = 'active'
         order by t."name", t."id"`,
        [actor.principalId],
      );
      return result.rows;
    },

    async issueRequest(actor, payload) {
      requireActor(actor);
      const input = validateIssueInput(payload);
      return transaction(database, async (client) => {
        await requireTenantRole(client, actor.principalId, input.tenantId, "owner");
        const tenant = await tenantById(client, input.tenantId);
        const issuedAt = new Date();
        const workflowId = randomUUID();
        const requestId = randomUUID();
        const assignmentId = randomUUID();
        const handle = randomBytes(32).toString("base64url");
        const handleDigest = createHash("sha256").update(handle, "utf8").digest();

        await client.query(
          `insert into "vasi_engine"."workflow_revision"
            ("id", "tenantId", "revision", "title", "purpose", "activityType",
             "responseMode", "content", "contentHash", "publishedByPrincipalId", "publishedAt")
           values ($1, $2, 1, $3, $4, 'terms_response', $5, $6, $7, $8, $9)`,
          [
            workflowId,
            input.tenantId,
            input.title,
            input.purpose,
            input.responseMode,
            input.content,
            input.contentHash,
            actor.principalId,
            issuedAt,
          ],
        );
        await client.query(
          `insert into "vasi_engine"."request_instance"
            ("id", "tenantId", "workflowRevisionId", "createdByPrincipalId",
             "purpose", "status", "issuedAt", "expiresAt")
           values ($1, $2, $3, $4, $5, 'issued', $6, $7)`,
          [requestId, input.tenantId, workflowId, actor.principalId, input.purpose, issuedAt, input.expiresAt],
        );
        await client.query(
          `insert into "vasi_engine"."participant_assignment"
            ("id", "tenantId", "requestId", "handleDigest", "intendedEmail", "status", "issuedAt")
           values ($1, $2, $3, $4, $5, 'issued', $6)`,
          [assignmentId, input.tenantId, requestId, handleDigest, input.intendedEmail, issuedAt],
        );
        await client.query(
          `insert into "vasi_engine"."evidence_chain_head"
            ("assignmentId", "lastSequence", "lastHash") values ($1, 0, $2)`,
          [assignmentId, GENESIS_HASH],
        );
        await appendEvent(client, {
          actor,
          assignmentId,
          eventType: "request.issued",
          payload: {
            expiresAt: input.expiresAt.toISOString(),
            intendedEmail: input.intendedEmail,
            tenant: { id: tenant.id, name: tenant.name },
            workflow: {
              content: input.content,
              contentHash: input.contentHash,
              id: workflowId,
              responseMode: input.responseMode,
              revision: 1,
              title: input.title,
            },
          },
          receivedAt: issuedAt,
          requestId,
          tenantId: input.tenantId,
        });
        return {
          assignmentId,
          expiresAt: input.expiresAt.toISOString(),
          participantPath: `/r/${handle}`,
          requestId,
          tenantId: input.tenantId,
        };
      });
    },

    async openAssignment(actor, payload) {
      requireParticipant(actor);
      const handleDigest = digestHandle(payload?.handle);
      return transaction(database, async (client) => {
        const record = await assignmentForHandle(client, handleDigest, true);
        authorizeParticipant(record, actor);
        const now = new Date();
        if (record.status === "completed") {
          return { completed: true, receiptAvailable: true };
        }
        assertAssignmentAvailable(record, now);

        if (!record.principalId) {
          await client.query(
            `update "vasi_engine"."participant_assignment"
             set "principalId" = $2, "participantEmail" = $3, "status" = 'in_progress',
                 "firstOpenedAt" = coalesce("firstOpenedAt", $4)
             where "id" = $1`,
            [record.assignmentId, actor.principalId, actor.email, now],
          );
          record.principalId = actor.principalId;
          record.participantEmail = actor.email;
          record.status = "in_progress";
          record.firstOpenedAt ||= now;
        }

        let interaction = await client.query(
          `select "id", "startedAt" from "vasi_engine"."interaction_session"
           where "assignmentId" = $1 and "principalId" = $2 and "completedAt" is null
           limit 1`,
          [record.assignmentId, actor.principalId],
        );
        if (!interaction.rowCount) {
          const interactionId = randomUUID();
          await client.query(
            `insert into "vasi_engine"."interaction_session"
              ("id", "assignmentId", "principalId", "gatewaySessionId", "authentication",
               "requestContext", "startedAt")
             values ($1, $2, $3, $4, $5, $6, $7)`,
            [
              interactionId,
              record.assignmentId,
              actor.principalId,
              actor.gatewaySessionId,
              actor.authentication,
              actor.requestContext || null,
              now,
            ],
          );
          await appendEvent(client, {
            actor,
            assignmentId: record.assignmentId,
            eventType: "participant.opened",
            payload: {
              authentication: actor.authentication,
              authenticatedAt: actor.authenticatedAt,
              contentHash: record.contentHash,
              interactionId,
              requestContext: actor.requestContext,
            },
            receivedAt: now,
            requestId: record.requestId,
            tenantId: record.tenantId,
          });
          interaction = { rows: [{ id: interactionId, startedAt: now }] };
        }

        return participantProjection(record, interaction.rows[0]);
      });
    },

    async respond(actor, payload) {
      requireParticipant(actor);
      const handleDigest = digestHandle(payload?.handle);
      const commandId = boundedToken(payload?.commandId, "commandId", 128);
      const interactionId = boundedToken(payload?.interactionId, "interactionId", 128);
      const clientContext = sanitizeClientContext(payload?.clientContext);

      return transaction(database, async (client) => {
        const record = await assignmentForHandle(client, handleDigest, true);
        authorizeParticipant(record, actor);
        assertAssignmentAvailable(record, new Date());
        if (record.status === "completed") {
          throw new EvidenceStoreError("response_replayed", 409);
        }
        const response = validateParticipantResponse(record.responseMode, payload?.response);
        const interaction = await client.query(
          `select "id", "startedAt" from "vasi_engine"."interaction_session"
           where "id" = $1 and "assignmentId" = $2 and "principalId" = $3
             and "completedAt" is null
           for update`,
          [interactionId, record.assignmentId, actor.principalId],
        );
        if (!interaction.rowCount) throw new EvidenceStoreError("interaction_unavailable", 409);
        const completedAt = new Date();
        const responseId = randomUUID();
        try {
          await client.query(
            `insert into "vasi_engine"."participant_response"
              ("id", "assignmentId", "interactionId", "commandId", "responseMode",
               "responseValue", "respondedAt", "clientContext")
             values ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [
              responseId,
              record.assignmentId,
              interactionId,
              commandId,
              record.responseMode,
              response,
              completedAt,
              clientContext,
            ],
          );
        } catch (error) {
          if (error?.code === "23505") throw new EvidenceStoreError("response_replayed", 409);
          throw error;
        }
        const startedAt = new Date(interaction.rows[0].startedAt);
        await appendEvent(client, {
          actor,
          assignmentId: record.assignmentId,
          eventType: "participant.responded",
          payload: {
            clientContext,
            interactionId,
            response,
            responseId,
            serverDurationMilliseconds: Math.max(0, completedAt.getTime() - startedAt.getTime()),
          },
          receivedAt: completedAt,
          requestId: record.requestId,
          tenantId: record.tenantId,
        });
        await client.query(
          `update "vasi_engine"."interaction_session" set "completedAt" = $2 where "id" = $1`,
          [interactionId, completedAt],
        );
        await client.query(
          `update "vasi_engine"."participant_assignment"
           set "status" = 'completed', "completedAt" = $2 where "id" = $1`,
          [record.assignmentId, completedAt],
        );
        await client.query(
          `update "vasi_engine"."request_instance"
           set "status" = 'completed', "completedAt" = $2 where "id" = $1`,
          [record.requestId, completedAt],
        );

        const events = await evidenceEvents(client, record.assignmentId);
        const manifestId = randomUUID();
        const manifest = buildEvidenceManifest({
          assignment: {
            id: record.assignmentId,
            manifestId,
            participantEmail: actor.email,
            principalId: actor.principalId,
          },
          completedAt: completedAt.toISOString(),
          events,
          issuedAt: new Date(record.issuedAt).toISOString(),
          request: { id: record.requestId, purpose: record.purpose },
          response,
          startedAt: startedAt.toISOString(),
          tenant: { id: record.tenantId, name: record.tenantName },
          workflow: {
            content: record.content,
            contentHash: record.contentHash,
            id: record.workflowId,
            responseMode: record.responseMode,
            revision: record.revision,
            title: record.title,
          },
        });
        const seal = createIntegritySeal({ keyId: sealKeyId, manifest, privateJWK: sealPrivateJWK });
        if (hashCanonicalJSON(seal.publicJWK) !== hashCanonicalJSON(sealPublicJWK)) {
          throw new EvidenceStoreError("seal_key_mismatch", 500);
        }
        await client.query(
          `insert into "vasi_engine"."evidence_manifest"
            ("id", "tenantId", "requestId", "assignmentId", "manifest", "manifestHash", "createdAt")
           values ($1, $2, $3, $4, $5, $6, $7)`,
          [manifestId, record.tenantId, record.requestId, record.assignmentId, manifest, seal.manifestHash, completedAt],
        );
        await client.query(
          `insert into "vasi_engine"."evidence_seal"
            ("id", "manifestId", "profile", "algorithm", "keyId", "publicJwk", "signature", "createdAt")
           values ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [
            randomUUID(),
            manifestId,
            seal.profile,
            seal.algorithm,
            seal.keyId,
            seal.publicJWK,
            seal.signature,
            completedAt,
          ],
        );

        const sealedRecord = { events, manifest, seal: { ...seal, createdAt: completedAt.toISOString() } };
        verifyEvidenceRecord(sealedRecord, sealPublicJWK);
        return participantReceipt(sealedRecord);
      });
    },

    async participantReceipt(actor, payload) {
      requireParticipant(actor);
      const handleDigest = digestHandle(payload?.handle);
      const client = await database.connect();
      try {
        const assignment = await assignmentForHandle(client, handleDigest, false);
        authorizeParticipant(assignment, actor);
        const record = await loadEvidenceRecord(client, assignment.assignmentId, sealPublicJWK);
        return participantReceipt(record);
      } finally {
        client.release();
      }
    },

    async ownerRecord(actor, payload) {
      requireActor(actor);
      const tenantId = boundedToken(payload?.tenantId, "tenantId", 128);
      const assignmentId = boundedToken(payload?.assignmentId, "assignmentId", 128);
      const client = await database.connect();
      try {
        await requireTenantRole(client, actor.principalId, tenantId, "owner");
        const assignment = await client.query(
          `select "id" from "vasi_engine"."participant_assignment"
           where "id" = $1 and "tenantId" = $2`,
          [assignmentId, tenantId],
        );
        if (!assignment.rowCount) notFound();
        return await loadEvidenceRecord(client, assignmentId, sealPublicJWK);
      } finally {
        client.release();
      }
    },
  });
}

export function verifyEvidenceRecord(record, expectedPublicJWK) {
  if (!record?.events?.length || !record.manifest || !record.seal) integrityFailure();
  let previousHash = GENESIS_HASH;
  for (const [index, event] of record.events.entries()) {
    if (
      event.sequence !== index + 1 ||
      event.previousHash !== previousHash ||
      event.eventData?.previousHash !== previousHash ||
      event.eventData?.sequence !== event.sequence ||
      hashCanonicalJSON(event.eventData) !== event.eventHash
    ) {
      integrityFailure();
    }
    previousHash = event.eventHash;
  }
  const hashes = record.events.map((event) => event.eventHash);
  if (
    record.manifest.evidence?.eventCount !== record.events.length ||
    record.manifest.evidence?.firstSequence !== 1 ||
    record.manifest.evidence?.lastSequence !== record.events.length ||
    record.manifest.evidence?.headHash !== previousHash ||
    JSON.stringify(record.manifest.evidence?.eventHashes) !== JSON.stringify(hashes) ||
    (expectedPublicJWK &&
      hashCanonicalJSON(record.seal.publicJWK) !== hashCanonicalJSON(expectedPublicJWK)) ||
    !verifyIntegritySeal(record.manifest, record.seal)
  ) {
    integrityFailure();
  }
  return true;
}

async function appendEvent(client, {
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
  if (!head.rowCount) throw new EvidenceStoreError("evidence_chain_missing", 500);
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

async function evidenceEvents(client, assignmentId) {
  const result = await client.query(
    `select "sequence", "eventData", "previousHash", "eventHash"
     from "vasi_engine"."evidence_event" where "assignmentId" = $1 order by "sequence"`,
    [assignmentId],
  );
  return result.rows.map((row) => ({ ...row, sequence: Number(row.sequence) }));
}

async function loadEvidenceRecord(client, assignmentId, expectedPublicJWK) {
  const result = await client.query(
    `select m."manifest", m."manifestHash", m."createdAt",
            s."profile", s."algorithm", s."keyId", s."publicJwk", s."signature", s."createdAt" as "sealedAt"
     from "vasi_engine"."evidence_manifest" m
     join "vasi_engine"."evidence_seal" s on s."manifestId" = m."id"
     where m."assignmentId" = $1`,
    [assignmentId],
  );
  if (!result.rowCount) throw new EvidenceStoreError("receipt_unavailable", 409);
  const row = result.rows[0];
  const record = {
    events: await evidenceEvents(client, assignmentId),
    manifest: row.manifest,
    seal: {
      algorithm: row.algorithm,
      createdAt: new Date(row.sealedAt).toISOString(),
      keyId: row.keyId,
      manifestHash: row.manifestHash,
      profile: row.profile,
      publicJWK: row.publicJwk,
      signature: row.signature,
    },
  };
  verifyEvidenceRecord(record, expectedPublicJWK);
  return record;
}

function participantReceipt(record) {
  const manifest = record.manifest;
  return {
    assignmentId: manifest.assignment.id,
    completedAt: manifest.timestamps.completedAt,
    integrity: {
      algorithm: record.seal.algorithm,
      keyId: record.seal.keyId,
      manifestHash: record.seal.manifestHash,
      profile: record.seal.profile,
      verified: true,
    },
    issuedAt: manifest.timestamps.issuedAt,
    request: {
      purpose: manifest.request.purpose,
      response: manifest.outcome.response,
      title: manifest.workflow.title,
    },
    tenant: manifest.tenant,
  };
}

async function assignmentForHandle(client, handleDigest, lock) {
  const result = await client.query(
    `select a."id" as "assignmentId", a."tenantId", a."requestId", a."intendedEmail",
            a."principalId", a."participantEmail", a."status", a."issuedAt", a."firstOpenedAt",
            r."purpose", r."expiresAt", r."status" as "requestStatus",
            w."id" as "workflowId", w."revision", w."title", w."responseMode",
            w."content", w."contentHash", t."name" as "tenantName"
     from "vasi_engine"."participant_assignment" a
     join "vasi_engine"."request_instance" r on r."id" = a."requestId"
     join "vasi_engine"."workflow_revision" w on w."id" = r."workflowRevisionId"
     join "vasi_engine"."tenant" t on t."id" = a."tenantId"
     where a."handleDigest" = $1${lock ? " for update of a, r" : ""}`,
    [handleDigest],
  );
  if (!result.rowCount) notFound();
  return result.rows[0];
}

function participantProjection(record, interaction) {
  return {
    assignmentId: record.assignmentId,
    completed: false,
    content: record.content,
    contentHash: record.contentHash,
    expiresAt: new Date(record.expiresAt).toISOString(),
    interaction: {
      id: interaction.id,
      startedAt: new Date(interaction.startedAt).toISOString(),
    },
    purpose: record.purpose,
    responseMode: record.responseMode,
    tenant: { id: record.tenantId, name: record.tenantName },
    title: record.title,
  };
}

function authorizeParticipant(record, actor) {
  if (
    record.intendedEmail.toLowerCase() !== actor.email ||
    (record.principalId && record.principalId !== actor.principalId)
  ) {
    notFound();
  }
}

function assertAssignmentAvailable(record, now) {
  if (record.status === "revoked" || record.requestStatus === "revoked") {
    throw new EvidenceStoreError("assignment_revoked", 410);
  }
  if (new Date(record.expiresAt) <= now || record.status === "expired" || record.requestStatus === "expired") {
    throw new EvidenceStoreError("assignment_expired", 410);
  }
}

async function requireTenantRole(client, principalId, tenantId, role) {
  const membership = await client.query(
    `select "roles" from "vasi_engine"."tenant_membership"
     where "tenantId" = $1 and "principalId" = $2 and "status" = 'active'`,
    [tenantId, principalId],
  );
  if (!membership.rowCount || !membership.rows[0].roles.includes(role)) deny();
}

async function tenantById(client, tenantId) {
  const result = await client.query(
    `select "id", "name" from "vasi_engine"."tenant" where "id" = $1 and "status" = 'active'`,
    [tenantId],
  );
  if (!result.rowCount) notFound();
  return result.rows[0];
}

async function transaction(database, callback) {
  const client = await database.connect();
  try {
    await client.query("begin");
    const value = await callback(client);
    await client.query("commit");
    return value;
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function digestHandle(value) {
  const handle = boundedToken(value, "handle", 64);
  if (!/^[A-Za-z0-9_-]{43}$/.test(handle)) notFound();
  return createHash("sha256").update(handle, "utf8").digest();
}

function boundedToken(value, name, maximum) {
  if (typeof value !== "string" || !value || value.length > maximum) {
    throw new EvidenceStoreError(`invalid_${name}`, 400);
  }
  return value;
}

function sanitizeClientContext(value) {
  if (value === undefined || value === null) return undefined;
  if (Array.isArray(value) || typeof value !== "object") {
    throw new EvidenceStoreError("invalid_client_context", 400);
  }
  return {
    clientStartedAt: optionalBounded(value.clientStartedAt, 64),
    clientSubmittedAt: optionalBounded(value.clientSubmittedAt, 64),
    timezone: optionalBounded(value.timezone, 100),
  };
}

function optionalBounded(value, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || value.length > maximum) {
    throw new EvidenceStoreError("invalid_client_context", 400);
  }
  return value;
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

function requireActor(actor) {
  if (!actor?.principalId || !actor.gatewaySessionId) deny();
}

function requireParticipant(actor) {
  requireActor(actor);
  if (!actor.email || !actor.authenticatedAt) deny();
}

function deny() {
  throw new EvidenceStoreError("forbidden", 403);
}

function notFound() {
  throw new EvidenceStoreError("not_found", 404);
}

function integrityFailure() {
  throw new EvidenceStoreError("integrity_check_failed", 500);
}

function requiredSetting(settings, name) {
  const value = settings[name];
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Required VASI engine setting ${name} is missing.`);
  }
  return value;
}

function parseJWK(value, type) {
  try {
    const jwk = JSON.parse(value);
    if (!jwk || typeof jwk !== "object" || jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
      throw new Error();
    }
    if (type === "private" && !jwk.d) throw new Error();
    if (type === "public" && jwk.d) throw new Error();
    return jwk;
  } catch {
    throw new Error(`The VASI evidence seal ${type} JWK is invalid.`);
  }
}
