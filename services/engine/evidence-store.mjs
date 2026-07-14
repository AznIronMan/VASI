import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  buildEvidenceManifest,
  validateIssueInput,
  validateParticipantResponse,
  validateTenantInput,
} from "../../packages/engine-domain/evidence.mjs";
import {
  createIntegritySeal,
  encryptJSONEnvelope,
  hashCanonicalJSON,
  verifyIntegritySeal,
} from "../../packages/engine-crypto/index.mjs";
import {
  evaluateNextActivity,
  hasTenantPermission,
  participantActivityProjection,
  validatePublishedIssueInput,
  validateRequestAction,
} from "../../packages/engine-domain/workflow.mjs";
import { validateActivityResponse } from "../../packages/engine-domain/activities.mjs";
import { validateParticipantArtifactInput } from "../../packages/engine-domain/artifacts.mjs";
import { readArtifactChunk } from "./artifact-store.mjs";
import { appendEvent } from "./evidence-events.mjs";
import { EngineStoreError } from "./errors.mjs";
import {
  assertMediaCompletion,
  loadMediaEvidence,
  persistIssueMediaSnapshots,
} from "./media-store.mjs";

const GENESIS_HASH = "0".repeat(64);

export class EvidenceStoreError extends EngineStoreError {}

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
  const outboxEncryptionSecret = requiredSetting(settings, "ENGINE_OUTBOX_ENCRYPTION_SECRET");

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
            ("tenantId", "principalId", "roles", "email", "source")
           values ($1, $2, $3, $4, 'identity_admin_bootstrap')`,
          [tenantId, actor.principalId, ["owner"], actor.email || null],
        );
        return {
          id: tenantId,
          name: input.name,
          permissions: ["member.manage", "record.read", "request.manage", "workflow.manage"],
          roles: ["owner"],
          slug: input.slug,
        };
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
      if (payload?.workflowRevisionId) {
        const input = validatePublishedIssueInput(payload);
        return transaction(database, async (client) =>
          issuePublishedRequest(client, actor, input, outboxEncryptionSecret),
        );
      }
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

        if (record.requestStatus === "scheduled") {
          await client.query(
            `update "vasi_engine"."request_instance" set "status" = 'issued' where "id" = $1`,
            [record.requestId],
          );
          await client.query(
            `update "vasi_engine"."participant_assignment" set "status" = 'issued' where "id" = $1`,
            [record.assignmentId],
          );
          record.requestStatus = "issued";
          record.status = "issued";
        }

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
          await client.query(
            `update "vasi_engine"."request_instance"
             set "status" = 'in_progress' where "id" = $1 and "status" in ('issued', 'scheduled')`,
            [record.requestId],
          );
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

        if (record.snapshot) {
          const activity = await currentActivity(client, record.assignmentId, now);
          return workflowParticipantProjection(record, interaction.rows[0], activity);
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
        if (record.snapshot) {
          return respondToWorkflowActivity({
            actor,
            client,
            clientContext,
            commandId,
            interactionId,
            payload,
            record,
            sealKeyId,
            sealPrivateJWK,
            sealPublicJWK,
            outboxEncryptionSecret,
          });
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
        await requireTenantPermission(client, actor.principalId, tenantId, "record.read");
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

    async openParticipantArtifact(actor, payload) {
      requireParticipant(actor);
      const input = validateParticipantArtifactInput(payload);
      const handleDigest = digestHandle(input.handle);
      return transaction(database, async (client) => {
        const record = await participantArtifactRecord(client, handleDigest, input, true);
        authorizeParticipant(record, actor);
        assertParticipantContentAccess(record, new Date());
        const accessType = input.disposition === "attachment"
          ? "participant_download"
          : "participant_presentation";
        const accessedAt = new Date();
        const accessId = randomUUID();
        await client.query(
          `insert into "vasi_engine"."document_artifact_access_event"
            ("id", "tenantId", "artifactId", "requestId", "assignmentId", "activityInstanceId",
             "actorPrincipalId", "accessType", "disposition", "metadata", "createdAt")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [
            accessId,
            record.tenantId,
            record.artifactId,
            record.requestId,
            record.assignmentId,
            record.activityInstanceId,
            actor.principalId,
            accessType,
            input.disposition,
            { gatewayObserved: true, limitation: "Route access does not by itself prove that every page was read." },
            accessedAt,
          ],
        );
        if (record.status !== "completed") {
          await appendEvent(client, {
            actor,
            assignmentId: record.assignmentId,
            eventType: accessType === "participant_download" ? "document.downloaded" : "document.presented",
            payload: {
              accessId,
              activityId: record.activityId,
              artifact: participantArtifactProjection(record),
              disposition: input.disposition,
              limitation: "Authorized route access does not prove that every page was read.",
            },
            receivedAt: accessedAt,
            requestId: record.requestId,
            tenantId: record.tenantId,
          });
        }
        return participantArtifactProjection(record);
      });
    },

    async readParticipantArtifactChunk(actor, payload) {
      requireParticipant(actor);
      const input = validateParticipantArtifactInput(payload);
      if (input.sequence === undefined) throw new EvidenceStoreError("invalid_artifact_sequence", 400);
      const handleDigest = digestHandle(input.handle);
      const client = await database.connect();
      try {
        const record = await participantArtifactRecord(client, handleDigest, input, false);
        authorizeParticipant(record, actor);
        assertParticipantContentAccess(record, new Date());
        return readArtifactChunk(client, input.artifactId, input.sequence);
      } finally {
        client.release();
      }
    },

    async listRequests(actor, payload) {
      requireActor(actor);
      const tenantId = boundedToken(payload?.tenantId, "tenantId", 128);
      const client = await database.connect();
      try {
        await requireTenantPermission(client, actor.principalId, tenantId, "request.manage");
        const result = await client.query(
          `select r."id" as "requestId", r."status", r."issuedAt", r."scheduledFor", r."dueAt",
                  r."expiresAt", r."completedAt", r."reissuedFromRequestId",
                  a."id" as "assignmentId", a."intendedEmail", a."status" as "assignmentStatus",
                  w."id" as "workflowRevisionId", w."revision", w."title", w."snapshotHash"
           from "vasi_engine"."request_instance" r
           join "vasi_engine"."participant_assignment" a on a."requestId" = r."id"
           join "vasi_engine"."workflow_revision" w on w."id" = r."workflowRevisionId"
           where r."tenantId" = $1 order by r."issuedAt" desc, r."id" limit 250`,
          [tenantId],
        );
        return result.rows.map((row) => ({
          ...row,
          revision: Number(row.revision),
        }));
      } finally {
        client.release();
      }
    },

    async requestAction(actor, payload) {
      requireActor(actor);
      const input = validateRequestAction(payload);
      return transaction(database, async (client) => {
        await requireTenantPermission(client, actor.principalId, input.tenantId, "request.manage");
        return applyRequestAction(client, actor, input, outboxEncryptionSecret);
      });
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

async function issuePublishedRequest(client, actor, input, outboxEncryptionSecret) {
  await requireTenantPermission(client, actor.principalId, input.tenantId, "request.manage");
  const revisionResult = await client.query(
    `select w."id", w."definitionId", w."revision", w."title", w."purpose", w."snapshot",
            w."snapshotHash", t."name" as "tenantName"
     from "vasi_engine"."workflow_revision" w
     join "vasi_engine"."tenant" t on t."id" = w."tenantId" and t."status" = 'active'
     join "vasi_engine"."workflow_definition" d on d."id" = w."definitionId" and d."status" = 'active'
     where w."id" = $1 and w."tenantId" = $2 and w."snapshot" is not null`,
    [input.workflowRevisionId, input.tenantId],
  );
  if (!revisionResult.rowCount) notFound();
  const revision = revisionResult.rows[0];
  const now = new Date();
  const scheduledFor = input.scheduledFor;
  const dueAt = input.dueAt ?? new Date(
    scheduledFor.getTime() + revision.snapshot.schedule.defaultDueDays * 86_400_000,
  );
  const expiresAt = input.expiresAt ?? new Date(
    scheduledFor.getTime() + revision.snapshot.schedule.defaultExpirationDays * 86_400_000,
  );
  if (expiresAt < dueAt || expiresAt.getTime() > scheduledFor.getTime() + 365 * 86_400_000) {
    throw new EvidenceStoreError("invalid_request_schedule", 400);
  }
  const requestId = randomUUID();
  const assignmentId = randomUUID();
  const handle = randomBytes(32).toString("base64url");
  const handleDigest = createHash("sha256").update(handle, "utf8").digest();
  const scheduled = scheduledFor.getTime() > now.getTime() + 1_000;
  const status = scheduled ? "scheduled" : "issued";

  await client.query(
    `insert into "vasi_engine"."request_instance"
      ("id", "tenantId", "workflowRevisionId", "createdByPrincipalId", "purpose", "status",
       "issuedAt", "scheduledFor", "dueAt", "expiresAt", "accessPolicy", "notificationPolicy")
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [
      requestId,
      input.tenantId,
      revision.id,
      actor.principalId,
      revision.purpose,
      status,
      now,
      scheduledFor,
      dueAt,
      expiresAt,
      revision.snapshot.access,
      revision.snapshot.notifications,
    ],
  );
  await client.query(
    `insert into "vasi_engine"."participant_assignment"
      ("id", "tenantId", "requestId", "handleDigest", "intendedEmail", "status", "issuedAt")
     values ($1, $2, $3, $4, $5, $6, $7)`,
    [assignmentId, input.tenantId, requestId, handleDigest, input.intendedEmail, status, now],
  );
  await client.query(
    `insert into "vasi_engine"."evidence_chain_head"
      ("assignmentId", "lastSequence", "lastHash") values ($1, 0, $2)`,
    [assignmentId, GENESIS_HASH],
  );
  for (const [ordinal, activity] of revision.snapshot.activities.entries()) {
    await client.query(
      `insert into "vasi_engine"."activity_instance"
        ("id", "tenantId", "requestId", "assignmentId", "activityId", "ordinal", "activityType",
         "contractVersion", "definition", "definitionHash", "status", "availableAt")
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        randomUUID(),
        input.tenantId,
        requestId,
        assignmentId,
        activity.id,
        ordinal,
        activity.type,
        activity.contractVersion,
        activity,
        hashCanonicalJSON(activity),
        ordinal === 0 ? "available" : "pending",
        ordinal === 0 ? scheduledFor : null,
      ],
    );
  }
  await persistIssueMediaSnapshots(client, {
    assignmentId,
    issuedAt: now,
    requestId,
    tenantId: input.tenantId,
    workflowRevisionId: revision.id,
  });
  await appendEvent(client, {
    actor,
    assignmentId,
    eventType: scheduled ? "request.scheduled" : "request.issued",
    payload: {
      accessPolicy: revision.snapshot.access,
      dueAt: dueAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      intendedEmail: input.intendedEmail,
      notificationPolicy: revision.snapshot.notifications,
      scheduledFor: scheduledFor.toISOString(),
      tenant: { id: input.tenantId, name: revision.tenantName },
      workflow: {
        definitionId: revision.definitionId,
        id: revision.id,
        revision: Number(revision.revision),
        snapshotHash: revision.snapshotHash,
        title: revision.title,
      },
    },
    receivedAt: now,
    requestId,
    tenantId: input.tenantId,
  });
  if (revision.snapshot.notifications.onIssue) {
    await queueNotification(client, {
      availableAt: scheduledFor,
      idempotencyKey: `${requestId}:issued`,
      outboxEncryptionSecret,
      payload: {
        eventType: "request.issued",
        participantPath: `/r/${handle}`,
        recipient: input.intendedEmail,
        requestId,
        tenant: { id: input.tenantId, name: revision.tenantName },
        title: revision.title,
      },
      requestId,
      tenantId: input.tenantId,
    });
  }
  for (const hoursBeforeDue of revision.snapshot.notifications.reminderHoursBeforeDue) {
    const availableAt = new Date(dueAt.getTime() - hoursBeforeDue * 3_600_000);
    if (availableAt <= now) continue;
    await queueNotification(client, {
      availableAt,
      idempotencyKey: `${requestId}:reminder:${hoursBeforeDue}`,
      outboxEncryptionSecret,
      payload: {
        dueAt: dueAt.toISOString(),
        eventType: "request.reminder",
        participantPath: `/r/${handle}`,
        recipient: input.intendedEmail,
        requestId,
        tenant: { id: input.tenantId, name: revision.tenantName },
        title: revision.title,
      },
      requestId,
      tenantId: input.tenantId,
    });
  }
  return {
    assignmentId,
    dueAt: dueAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    participantPath: `/r/${handle}`,
    requestId,
    scheduledFor: scheduledFor.toISOString(),
    status,
    tenantId: input.tenantId,
    workflowRevisionId: revision.id,
  };
}

async function currentActivity(client, assignmentId, now) {
  const result = await client.query(
    `select i."id", i."activityId", i."ordinal", i."definition", i."definitionHash", i."openedAt",
            saved."responseValue" as "savedResponse", saved."responseLabel" as "savedResponseLabel",
            media."summary" as "mediaSummary"
     from "vasi_engine"."activity_instance" i
     left join lateral (
       select "responseValue", "responseLabel"
       from "vasi_engine"."activity_response_revision"
       where "activityInstanceId" = i."id" and "state" = 'saved'
       order by "revision" desc limit 1
     ) saved on true
     left join lateral (
       select "summary" from "vasi_engine"."media_activity_summary_revision"
       where "activityInstanceId" = i."id" order by "revision" desc limit 1
     ) media on true
     where i."assignmentId" = $1 and i."status" = 'available'
     order by i."ordinal" limit 1 for update of i`,
    [assignmentId],
  );
  if (!result.rowCount) throw new EvidenceStoreError("activity_unavailable", 409);
  if (!result.rows[0].openedAt) {
    await client.query(
      `update "vasi_engine"."activity_instance" set "openedAt" = $2 where "id" = $1`,
      [result.rows[0].id, now],
    );
    result.rows[0].openedAt = now;
  }
  return result.rows[0];
}

function workflowParticipantProjection(record, interaction, activity) {
  const projection = participantActivityProjection(activity.definition);
  return {
    activityId: activity.activityId,
    assignmentId: record.assignmentId,
    completed: false,
    content: projection.content,
    contentHash: activity.definitionHash,
    contractVersion: projection.contractVersion,
    expiresAt: new Date(record.expiresAt).toISOString(),
    instructions: projection.instructions,
    interaction: {
      id: interaction.id,
      startedAt: new Date(interaction.startedAt).toISOString(),
    },
    progress: {
      current: Number(activity.ordinal) + 1,
      total: record.snapshot.activities.length,
    },
    purpose: record.purpose,
    responseMode: projection.responseMode,
    mediaSummary: activity.mediaSummary,
    savedResponse: activity.savedResponse,
    savedResponseLabel: activity.savedResponseLabel,
    tenant: { id: record.tenantId, name: record.tenantName },
    title: projection.title,
    type: projection.type,
    workflowTitle: record.title,
  };
}

async function respondToWorkflowActivity({
  actor,
  client,
  clientContext,
  commandId,
  interactionId,
  payload,
  record,
  sealKeyId,
  sealPrivateJWK,
  sealPublicJWK,
  outboxEncryptionSecret,
}) {
  const interaction = await client.query(
    `select "id", "startedAt" from "vasi_engine"."interaction_session"
     where "id" = $1 and "assignmentId" = $2 and "principalId" = $3
       and "completedAt" is null for update`,
    [interactionId, record.assignmentId, actor.principalId],
  );
  if (!interaction.rowCount) throw new EvidenceStoreError("interaction_unavailable", 409);
  const activity = await currentActivity(client, record.assignmentId, new Date());
  if (payload?.activityId && payload.activityId !== activity.activityId) {
    throw new EvidenceStoreError("activity_state_conflict", 409);
  }
  const intent = payload?.intent ?? "submit";
  if (!['save', 'submit'].includes(intent)) throw new EvidenceStoreError("invalid_response_intent", 400);
  let response = validateActivityResponse(activity.definition, payload?.response);
  if (intent === "submit" && activity.definition.type === "document_review") {
    const presented = await client.query(
      `select 1 from "vasi_engine"."document_artifact_access_event"
       where "assignmentId" = $1 and "activityInstanceId" = $2
         and "actorPrincipalId" = $3
         and "accessType" in ('participant_presentation', 'participant_download') limit 1`,
      [record.assignmentId, activity.id, actor.principalId],
    );
    if (!presented.rowCount) throw new EvidenceStoreError("document_not_presented", 409);
  }
  const completedAt = new Date();
  if (intent === "submit") {
    response = await assertMediaCompletion(client, record, activity, response, completedAt);
  }
  const revisionResult = await client.query(
    `select coalesce(max("revision"), 0) + 1 as "revision"
     from "vasi_engine"."activity_response_revision" where "activityInstanceId" = $1`,
    [activity.id],
  );
  const responseRevision = Number(revisionResult.rows[0].revision);
  const responseRevisionId = randomUUID();
  try {
    await client.query(
      `insert into "vasi_engine"."activity_response_revision"
        ("id", "tenantId", "requestId", "assignmentId", "activityInstanceId", "interactionId",
         "revision", "commandId", "state", "responseValue", "responseLabel", "outcome", "result",
         "clientContext", "recordedAt")
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        responseRevisionId,
        record.tenantId,
        record.requestId,
        record.assignmentId,
        activity.id,
        interactionId,
        responseRevision,
        commandId,
        intent === "save" ? "saved" : "submitted",
        JSON.stringify(response.value),
        response.display,
        response.outcome,
        response.result || null,
        clientContext,
        completedAt,
      ],
    );
  } catch (error) {
    if (error?.code === "23505") throw new EvidenceStoreError("response_replayed", 409);
    throw error;
  }
  await appendEvent(client, {
    actor,
    assignmentId: record.assignmentId,
    eventType: intent === "save" ? "activity.response.saved" : "activity.response.submitted",
    payload: {
      activity: {
        definitionHash: activity.definitionHash,
        id: activity.activityId,
        ordinal: Number(activity.ordinal),
        type: activity.definition.type,
      },
      clientContext,
      interactionId,
      response: {
        display: response.display,
        outcome: response.outcome,
        result: response.result,
        value: response.value,
      },
      responseRevision,
      responseRevisionId,
    },
    receivedAt: completedAt,
    requestId: record.requestId,
    tenantId: record.tenantId,
  });
  if (intent === "save") {
    activity.savedResponse = response.value;
    activity.savedResponseLabel = response.display;
    return {
      assignment: workflowParticipantProjection(record, interaction.rows[0], activity),
      completed: false,
      saved: true,
    };
  }
  const responseId = randomUUID();
  try {
    await client.query(
      `insert into "vasi_engine"."activity_response"
        ("id", "tenantId", "requestId", "assignmentId", "activityInstanceId", "interactionId",
         "commandId", "responseValue", "responseRevisionId", "responseLabel", "outcome", "result",
         "clientContext", "respondedAt")
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      [
        responseId,
        record.tenantId,
        record.requestId,
        record.assignmentId,
        activity.id,
        interactionId,
        commandId,
        JSON.stringify(response.value),
        responseRevisionId,
        response.display,
        response.outcome,
        response.result || null,
        clientContext,
        completedAt,
      ],
    );
  } catch (error) {
    if (error?.code === "23505") throw new EvidenceStoreError("response_replayed", 409);
    throw error;
  }
  await client.query(
    `update "vasi_engine"."activity_instance"
     set "status" = 'completed', "completedAt" = $2 where "id" = $1`,
    [activity.id, completedAt],
  );
  const nextActivityId = evaluateNextActivity(record.snapshot, activity.activityId, response);
  let nextActivity;
  if (nextActivityId) {
    const target = record.snapshot.activities.findIndex((entry) => entry.id === nextActivityId);
    await client.query(
      `update "vasi_engine"."activity_instance"
       set "status" = 'skipped', "completedAt" = $3
       where "assignmentId" = $1 and "status" = 'pending' and "ordinal" < $2`,
      [record.assignmentId, target, completedAt],
    );
    const activated = await client.query(
      `update "vasi_engine"."activity_instance"
       set "status" = 'available', "availableAt" = $3
       where "assignmentId" = $1 and "activityId" = $2 and "status" = 'pending'
       returning "id", "activityId", "ordinal", "definition", "definitionHash", "openedAt"`,
      [record.assignmentId, nextActivityId, completedAt],
    );
    if (!activated.rowCount) throw new EvidenceStoreError("activity_state_conflict", 409);
    nextActivity = activated.rows[0];
  } else {
    await client.query(
      `update "vasi_engine"."activity_instance"
       set "status" = 'skipped', "completedAt" = $2
       where "assignmentId" = $1 and "status" = 'pending'`,
      [record.assignmentId, completedAt],
    );
  }
  await appendEvent(client, {
    actor,
    assignmentId: record.assignmentId,
    eventType: "activity.completed",
    payload: {
      activity: {
        definitionHash: activity.definitionHash,
        id: activity.activityId,
        ordinal: Number(activity.ordinal),
        type: activity.definition.type,
      },
      clientContext,
      interactionId,
      nextActivityId,
      response: {
        display: response.display,
        outcome: response.outcome,
        result: response.result,
        value: response.value,
      },
      responseId,
      responseRevision,
      responseRevisionId,
      serverDurationMilliseconds: Math.max(
        0,
        completedAt.getTime() - new Date(activity.openedAt).getTime(),
      ),
    },
    receivedAt: completedAt,
    requestId: record.requestId,
    tenantId: record.tenantId,
  });

  if (nextActivity) {
    return {
      assignment: workflowParticipantProjection(record, interaction.rows[0], nextActivity),
      completed: false,
    };
  }

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
  const responses = await client.query(
    `select i."activityId", i."ordinal", i."definitionHash", r."responseValue", r."responseLabel",
            r."outcome", r."result", r."respondedAt",
            coalesce(revisions."items", '[]'::jsonb) as "revisions"
     from "vasi_engine"."activity_response" r
     join "vasi_engine"."activity_instance" i on i."id" = r."activityInstanceId"
     left join lateral (
       select jsonb_agg(jsonb_build_object(
         'id', rr."id", 'revision', rr."revision", 'state', rr."state",
         'response', rr."responseValue", 'responseLabel', rr."responseLabel",
         'outcome', rr."outcome", 'result', rr."result", 'recordedAt', rr."recordedAt"
       ) order by rr."revision") as "items"
       from "vasi_engine"."activity_response_revision" rr
       where rr."activityInstanceId" = i."id"
     ) revisions on true
     where r."assignmentId" = $1 order by i."ordinal"`,
    [record.assignmentId],
  );
  const events = await evidenceEvents(client, record.assignmentId);
  const media = await loadMediaEvidence(client, record.assignmentId);
  const manifestId = randomUUID();
  const manifest = buildWorkflowManifest({
    actor,
    completedAt,
    events,
    interaction: interaction.rows[0],
    manifestId,
    record,
    responses: responses.rows,
    media,
  });
  const sealedRecord = await persistSeal(client, {
    completedAt,
    events,
    manifest,
    manifestId,
    record,
    sealKeyId,
    sealPrivateJWK,
    sealPublicJWK,
  });
  if (record.notificationPolicy?.onCompletion) {
    await queueNotification(client, {
      availableAt: completedAt,
      idempotencyKey: `${record.requestId}:completed`,
      outboxEncryptionSecret,
      payload: {
        eventType: "request.completed",
        recipient: actor.email,
        requestId: record.requestId,
        tenant: { id: record.tenantId, name: record.tenantName },
        title: record.title,
      },
      requestId: record.requestId,
      tenantId: record.tenantId,
    });
  }
  return participantReceipt(sealedRecord);
}

function buildWorkflowManifest({ actor, completedAt, events, interaction, manifestId, media, record, responses }) {
  return {
    assignment: {
      id: record.assignmentId,
      participantEmail: actor.email,
      principalId: actor.principalId,
    },
    evidence: {
      eventCount: events.length,
      eventHashes: events.map((event) => event.eventHash),
      firstSequence: events[0].sequence,
      headHash: events.at(-1).eventHash,
      lastSequence: events.at(-1).sequence,
    },
    manifestId,
    media,
    outcome: {
      activities: responses.map((row) => ({
        activityId: row.activityId,
        definitionHash: row.definitionHash,
        ordinal: Number(row.ordinal),
        respondedAt: new Date(row.respondedAt).toISOString(),
        response: row.responseValue,
        responseLabel: row.responseLabel,
        outcome: row.outcome,
        result: row.result,
        revisions: row.revisions,
      })),
      status: "completed",
    },
    request: {
      accessPolicy: record.accessPolicy,
      dueAt: record.dueAt ? new Date(record.dueAt).toISOString() : undefined,
      expiresAt: new Date(record.expiresAt).toISOString(),
      id: record.requestId,
      purpose: record.purpose,
      scheduledFor: record.scheduledFor ? new Date(record.scheduledFor).toISOString() : undefined,
    },
    schema: "vasi-evidence-manifest/v4",
    tenant: { id: record.tenantId, name: record.tenantName },
    timestamps: {
      completedAt: completedAt.toISOString(),
      issuedAt: new Date(record.issuedAt).toISOString(),
      startedAt: new Date(interaction.startedAt).toISOString(),
    },
    workflow: {
      definitionId: record.definitionId,
      id: record.workflowId,
      revision: Number(record.revision),
      snapshot: record.snapshot,
      snapshotHash: record.snapshotHash,
      title: record.title,
    },
  };
}

async function persistSeal(client, {
  completedAt,
  events,
  manifest,
  manifestId,
  record,
  sealKeyId,
  sealPrivateJWK,
  sealPublicJWK,
}) {
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
    [randomUUID(), manifestId, seal.profile, seal.algorithm, seal.keyId, seal.publicJWK, seal.signature, completedAt],
  );
  const sealedRecord = { events, manifest, seal: { ...seal, createdAt: completedAt.toISOString() } };
  verifyEvidenceRecord(sealedRecord, sealPublicJWK);
  return sealedRecord;
}

async function applyRequestAction(client, actor, input, outboxEncryptionSecret) {
  const replay = await client.query(
    `select "eventData" from "vasi_engine"."request_lifecycle_event" where "idempotencyKey" = $1`,
    [input.commandId],
  );
  if (replay.rowCount) throw new EvidenceStoreError("action_replayed", 409);
  const result = await client.query(
    `select r."id", r."status", r."workflowRevisionId", r."scheduledFor", r."dueAt", r."expiresAt",
            a."id" as "assignmentId", a."intendedEmail"
     from "vasi_engine"."request_instance" r
     join "vasi_engine"."participant_assignment" a on a."requestId" = r."id"
     where r."id" = $1 and r."tenantId" = $2 for update of r, a`,
    [input.requestId, input.tenantId],
  );
  if (!result.rowCount) notFound();
  const request = result.rows[0];
  if (["completed", "expired"].includes(request.status)) {
    throw new EvidenceStoreError("request_state_conflict", 409);
  }
  const now = new Date();
  let actionResult = { action: input.action, requestId: input.requestId, status: request.status };
  if (input.action === "revoke" || input.action === "reissue") {
    if (request.status === "revoked") throw new EvidenceStoreError("request_state_conflict", 409);
    await client.query(
      `update "vasi_engine"."request_instance" set "status" = 'revoked' where "id" = $1`,
      [input.requestId],
    );
    await client.query(
      `update "vasi_engine"."participant_assignment" set "status" = 'revoked' where "id" = $1`,
      [request.assignmentId],
    );
    await appendEvent(client, {
      actor,
      assignmentId: request.assignmentId,
      eventType: input.action === "reissue" ? "request.reissued" : "request.revoked",
      payload: { commandId: input.commandId, previousStatus: request.status },
      receivedAt: now,
      requestId: input.requestId,
      tenantId: input.tenantId,
    });
    actionResult = { ...actionResult, status: "revoked" };
  }
  if (input.action === "reissue") {
    const reissued = await issuePublishedRequest(client, actor, {
      dueAt: undefined,
      expiresAt: undefined,
      intendedEmail: request.intendedEmail,
      scheduledFor: now,
      tenantId: input.tenantId,
      workflowRevisionId: request.workflowRevisionId,
    }, outboxEncryptionSecret);
    await client.query(
      `update "vasi_engine"."request_instance"
       set "reissuedFromRequestId" = $2 where "id" = $1`,
      [reissued.requestId, input.requestId],
    );
    actionResult = { ...reissued, action: input.action };
  }
  if (input.action === "remind") {
    await queueNotification(client, {
      availableAt: now,
      idempotencyKey: `${input.requestId}:manual-reminder:${input.commandId}`,
      outboxEncryptionSecret,
      payload: {
        eventType: "request.reminder",
        recipient: request.intendedEmail,
        requestId: input.requestId,
      },
      requestId: input.requestId,
      tenantId: input.tenantId,
    });
    actionResult = { ...actionResult, queued: true };
  }
  await client.query(
    `insert into "vasi_engine"."request_lifecycle_event"
      ("id", "tenantId", "requestId", "eventType", "actorPrincipalId", "idempotencyKey", "eventData", "createdAt")
     values ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      randomUUID(),
      input.tenantId,
      input.requestId,
      `request.${input.action}`,
      actor.principalId,
      input.commandId,
      { action: input.action, resultingStatus: actionResult.status || "issued" },
      now,
    ],
  );
  return actionResult;
}

async function queueNotification(client, {
  availableAt,
  idempotencyKey,
  outboxEncryptionSecret,
  payload,
  requestId,
  tenantId,
}) {
  const envelope = encryptJSONEnvelope(payload, outboxEncryptionSecret);
  await client.query(
    `insert into "vasi_engine"."outbox_job"
      ("id", "jobType", "tenantId", "requestId", "idempotencyKey", "payload", "payloadHash",
       "status", "availableAt")
     values ($1, 'notification', $2, $3, $4, $5, $6, 'pending', $7)
     on conflict ("idempotencyKey") where "idempotencyKey" is not null do nothing`,
    [randomUUID(), tenantId, requestId, idempotencyKey, { envelope }, hashCanonicalJSON(payload), availableAt],
  );
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
  const activityOutcomes = manifest.outcome.activities;
  const response = activityOutcomes
    ? activityOutcomes.map((activity) => `${activity.activityId}: ${activity.responseLabel || formatResponse(activity.response)}`).join("; ")
    : manifest.outcome.response;
  const postCompletion = manifest.request.accessPolicy?.postCompletion || "receipt_only";
  const contentAvailable = postCompletion === "content_always" || (
    postCompletion === "content_until_expiration" &&
    manifest.request.expiresAt && new Date(manifest.request.expiresAt) > new Date()
  );
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
      activities: contentAvailable
        ? manifest.workflow.snapshot?.activities.map(participantActivityProjection)
        : undefined,
      contentAccess: { available: Boolean(contentAvailable), policy: postCompletion },
      purpose: manifest.request.purpose,
      response,
      responses: activityOutcomes,
      title: manifest.workflow.title,
    },
    tenant: manifest.tenant,
  };
}

function formatResponse(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.join(", ");
  return JSON.stringify(value);
}

async function assignmentForHandle(client, handleDigest, lock) {
  const result = await client.query(
    `select a."id" as "assignmentId", a."tenantId", a."requestId", a."intendedEmail",
            a."principalId", a."participantEmail", a."status", a."issuedAt", a."firstOpenedAt",
            r."purpose", r."scheduledFor", r."dueAt", r."expiresAt", r."accessPolicy",
            r."notificationPolicy", r."status" as "requestStatus",
            w."id" as "workflowId", w."revision", w."title", w."responseMode",
            w."content", w."contentHash", w."definitionId", w."schemaVersion", w."snapshot",
            w."snapshotHash", t."name" as "tenantName"
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

async function participantArtifactRecord(client, handleDigest, input, lock) {
  const result = await client.query(
    `select a."id" as "assignmentId", a."tenantId", a."requestId", a."intendedEmail",
            a."principalId", a."participantEmail", a."status", r."status" as "requestStatus",
            r."expiresAt", r."scheduledFor", r."accessPolicy",
            i."id" as "activityInstanceId", i."activityId", i."status" as "activityStatus",
            d."id" as "artifactId", d."familyId", d."revision" as "artifactRevision",
            d."role" as "artifactRole", d."originalFilename", d."mediaType", d."byteLength",
            d."chunkCount", d."sha256", d."inspectionProfile"
     from "vasi_engine"."participant_assignment" a
     join "vasi_engine"."request_instance" r on r."id" = a."requestId"
     join "vasi_engine"."activity_instance" i
       on i."assignmentId" = a."id" and i."activityId" = $2
     join "vasi_engine"."workflow_artifact_binding" b
       on b."workflowRevisionId" = r."workflowRevisionId"
      and b."activityId" = i."activityId" and b."artifactId" = $3
     join "vasi_engine"."document_artifact" d
       on d."id" = b."artifactId" and d."tenantId" = a."tenantId" and d."status" = 'published'
     where a."handleDigest" = $1${lock ? " for update of a, r, i" : ""}`,
    [handleDigest, input.activityId, input.artifactId],
  );
  if (!result.rowCount) notFound();
  return result.rows[0];
}

function assertParticipantContentAccess(record, now) {
  const completed = record.status === "completed" || record.requestStatus === "completed";
  if (completed) {
    const policy = record.accessPolicy?.postCompletion || "receipt_only";
    const available = policy === "content_always" ||
      (policy === "content_until_expiration" && new Date(record.expiresAt) > now);
    if (!available) throw new EvidenceStoreError("content_unavailable", 410);
    return;
  }
  assertAssignmentAvailable(record, now);
  if (!["available", "completed"].includes(record.activityStatus)) notFound();
}

function participantArtifactProjection(record) {
  return {
    activityId: record.activityId,
    byteLength: Number(record.byteLength),
    chunkCount: Number(record.chunkCount),
    familyId: record.familyId,
    id: record.artifactId,
    inspectionProfile: record.inspectionProfile,
    mediaType: record.mediaType,
    originalFilename: record.originalFilename,
    revision: Number(record.artifactRevision),
    role: record.artifactRole,
    sha256: record.sha256,
  };
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
  if (record.scheduledFor && new Date(record.scheduledFor) > now) {
    throw new EvidenceStoreError("assignment_not_yet_available", 425);
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

async function requireTenantPermission(client, principalId, tenantId, permission) {
  const membership = await client.query(
    `select "roles" from "vasi_engine"."tenant_membership"
     where "tenantId" = $1 and "principalId" = $2 and "status" = 'active'
       and "validFrom" <= CURRENT_TIMESTAMP
       and ("expiresAt" is null or "expiresAt" > CURRENT_TIMESTAMP)`,
    [tenantId, principalId],
  );
  if (!membership.rowCount || !hasTenantPermission(membership.rows[0].roles, permission)) deny();
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
