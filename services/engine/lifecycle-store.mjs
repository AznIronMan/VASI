import { randomUUID } from "node:crypto";

import {
  canonicalJSON,
  hashCanonicalJSON,
  sha256Hex,
} from "../../packages/engine-crypto/index.mjs";
import {
  DATA_EXPORT_PROFILE,
  SYSTEM_RETENTION_POLICY,
  calculateRetentionDeadlines,
  normalizeRetentionPolicy,
  participantMatches,
  retentionPolicyHash,
  validateLegalHoldCommand,
  validateLifecycleListInput,
  validateParticipantDataExportOpen,
  validateParticipantDataRequestCreate,
  validateParticipantDataRequestReview,
  validateRetentionPolicyMutation,
} from "../../packages/engine-domain/lifecycle.mjs";
import { participantContextPolicy } from "../../packages/engine-domain/context.mjs";
import { notificationOperationalStatus } from "../../packages/engine-domain/notifications.mjs";
import { hasTenantPermission } from "../../packages/engine-domain/workflow.mjs";
import { EngineStoreError } from "./errors.mjs";
import { requireRecentParticipantDataAuthentication } from "./authentication-assurance.mjs";
import { createSigningProvider } from "./signing-provider.mjs";

const ENGINE_VERSION = "0.54.1";
const GENESIS_HASH = "0".repeat(64);
const DATA_EXPORT_SCHEMA = "vasi-participant-data-export/v1";

export function createLifecycleStore(database, settings) {
  const reviewDays = boundedSetting(
    settings.ENGINE_DATA_REQUEST_REVIEW_DAYS,
    30,
    1,
    90,
    "ENGINE_DATA_REQUEST_REVIEW_DAYS",
  );
  return Object.freeze({
    async listPolicies(actor, payload) {
      requireActor(actor);
      const input = validateLifecycleListInput(payload);
      const client = await database.connect();
      try {
        await requirePermission(client, actor, input.tenantId, "lifecycle.read");
        const result = await client.query(
          `select r."id", r."name", r."revision", r."policy", r."policyHash",
                  r."createdByPrincipalId", r."createdAt"
           from "vasi_engine"."retention_policy_pointer" p
           join "vasi_engine"."retention_policy_revision" r on r."id" = p."activeRevisionId"
           where p."tenantId" = $1 order by r."name" limit $2`,
          [input.tenantId, input.limit],
        );
        return [
          {
            id: null,
            name: "tenant_default",
            policy: SYSTEM_RETENTION_POLICY,
            policyHash: retentionPolicyHash(SYSTEM_RETENTION_POLICY),
            revision: 0,
            source: "system_default",
          },
          ...result.rows.map((row) => ({ ...row, revision: Number(row.revision), source: "tenant" })),
        ];
      } finally {
        client.release();
      }
    },

    async updatePolicy(actor, payload) {
      requireActor(actor);
      const input = validateRetentionPolicyMutation(payload);
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "lifecycle.manage");
        const current = await client.query(
          `select "revision" from "vasi_engine"."retention_policy_pointer"
           where "tenantId" = $1 and "name" = $2 for update`,
          [input.tenantId, input.name],
        );
        const currentRevision = Number(current.rows[0]?.revision || 0);
        if (input.expectedRevision !== undefined && input.expectedRevision !== currentRevision) {
          throw new EngineStoreError("retention_policy_version_conflict", 409);
        }
        const revision = currentRevision + 1;
        const id = randomUUID();
        const policyHash = retentionPolicyHash(input.policy);
        const now = new Date();
        await client.query(
          `insert into "vasi_engine"."retention_policy_revision"
            ("id", "tenantId", "name", "revision", "policy", "policyHash",
             "createdByPrincipalId", "createdAt")
           values ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [id, input.tenantId, input.name, revision, input.policy, policyHash, actor.principalId, now],
        );
        await client.query(
          `insert into "vasi_engine"."retention_policy_pointer"
            ("tenantId", "name", "activeRevisionId", "revision", "updatedByPrincipalId", "updatedAt")
           values ($1, $2, $3, $4, $5, $6)
           on conflict ("tenantId", "name") do update
             set "activeRevisionId" = excluded."activeRevisionId", "revision" = excluded."revision",
                 "updatedByPrincipalId" = excluded."updatedByPrincipalId", "updatedAt" = excluded."updatedAt"`,
          [input.tenantId, input.name, id, revision, actor.principalId, now],
        );
        return { id, name: input.name, policy: input.policy, policyHash, revision, source: "tenant" };
      });
    },

    async listRecords(actor, payload) {
      requireActor(actor);
      const input = validateLifecycleListInput(payload);
      const client = await database.connect();
      try {
        await requirePermission(client, actor, input.tenantId, "lifecycle.read");
        const result = await client.query(
          `select l.*, a."intendedEmail", a."participantEmail", a."status" as "assignmentStatus",
                  r."status" as "requestStatus", r."issuedAt", r."completedAt", w."title",
                  coalesce(holds."items", '[]'::jsonb) as "holds"
           from "vasi_engine"."record_lifecycle_state" l
           join "vasi_engine"."participant_assignment" a on a."id" = l."assignmentId"
           join "vasi_engine"."request_instance" r on r."id" = l."requestId"
           join "vasi_engine"."workflow_revision" w on w."id" = r."workflowRevisionId"
           left join lateral (
             select jsonb_agg(jsonb_build_object(
               'id', h."id", 'caseReference', h."caseReference", 'reason', h."reason",
               'placedAt', h."placedAt", 'placedByPrincipalId', h."placedByPrincipalId",
               'releasedAt', rel."releasedAt", 'releaseReason', rel."reason"
             ) order by h."placedAt" desc) as "items"
             from "vasi_engine"."legal_hold" h
             left join "vasi_engine"."legal_hold_release" rel on rel."holdId" = h."id"
             where h."assignmentId" = l."assignmentId" and h."tenantId" = l."tenantId"
           ) holds on true
           where l."tenantId" = $1
           order by coalesce(r."completedAt", r."issuedAt") desc, l."assignmentId"
           limit $2`,
          [input.tenantId, input.limit],
        );
        return result.rows.map(lifecycleProjection);
      } finally {
        client.release();
      }
    },

    async commandHold(actor, payload) {
      requireActor(actor);
      const input = validateLegalHoldCommand(payload);
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "lifecycle.manage");
        const replay = await replayedHoldCommand(client, input.commandId, input.tenantId);
        if (replay) return replay;
        const now = new Date();
        if (input.action === "place") {
          const record = await lifecycleRecord(client, input.tenantId, input.assignmentId, true);
          const id = randomUUID();
          await client.query(
            `insert into "vasi_engine"."legal_hold"
              ("id", "tenantId", "requestId", "assignmentId", "caseReference", "reason",
               "placedByPrincipalId", "placementCommandId", "placedAt")
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
              id,
              input.tenantId,
              record.requestId,
              input.assignmentId,
              input.caseReference,
              input.reason,
              actor.principalId,
              input.commandId,
              now,
            ],
          );
          await appendLifecycleEvent(client, {
            actor,
            assignmentId: input.assignmentId,
            commandId: input.commandId,
            eventType: "hold.placed",
            payload: { caseReference: input.caseReference, holdId: id, reason: input.reason },
            requestId: record.requestId,
            source: "owner",
            tenantId: input.tenantId,
            createdAt: now,
          });
          return holdProjection({
            assignmentId: input.assignmentId,
            caseReference: input.caseReference,
            id,
            placedAt: now,
            reason: input.reason,
            requestId: record.requestId,
            tenantId: input.tenantId,
          });
        }

        const holdResult = await client.query(
          `select h.*, rel."releasedAt"
           from "vasi_engine"."legal_hold" h
           left join "vasi_engine"."legal_hold_release" rel on rel."holdId" = h."id"
           where h."id" = $1 and h."tenantId" = $2 for update of h`,
          [input.holdId, input.tenantId],
        );
        if (!holdResult.rowCount) notFound();
        const hold = holdResult.rows[0];
        if (hold.releasedAt) throw new EngineStoreError("legal_hold_already_released", 409);
        const releaseId = randomUUID();
        await client.query(
          `insert into "vasi_engine"."legal_hold_release"
            ("id", "holdId", "reason", "releasedByPrincipalId", "releaseCommandId", "releasedAt")
           values ($1, $2, $3, $4, $5, $6)`,
          [releaseId, hold.id, input.reason, actor.principalId, input.commandId, now],
        );
        await appendLifecycleEvent(client, {
          actor,
          assignmentId: hold.assignmentId,
          commandId: input.commandId,
          eventType: "hold.released",
          payload: { holdId: hold.id, reason: input.reason, releaseId },
          requestId: hold.requestId,
          source: "owner",
          tenantId: input.tenantId,
          createdAt: now,
        });
        return holdProjection({ ...hold, releaseReason: input.reason, releasedAt: now });
      });
    },

    async listParticipantHistory(actor) {
      requireParticipant(actor);
      const result = await database.query(
        `select a."id" as "assignmentId", a."requestId", a."status", a."issuedAt",
                a."firstOpenedAt", a."completedAt", a."intendedEmail", a."participantEmail",
                r."purpose", r."scheduledFor", r."dueAt", r."expiresAt", r."requesterSnapshot",
                r."accessPolicy",
                w."id" as "workflowRevisionId", w."revision", w."title", w."snapshotHash",
                t."id" as "tenantId", t."name" as "tenantName",
                m."manifestHash", l."contentStatus", l."historyStatus", l."evidenceStatus",
                l."contentExpiresAt", l."historyExpiresAt", l."archiveAt", l."deleteAt",
                auth."authentication", auth."authenticatedAt", auth."authenticationObservedAt",
                activity."activityCount", activity."resolvedActivityCount",
                activity."lastActivityAt", activity."responses",
                legacy."legacyResponseMode", legacy."legacyResponseValue", legacy."legacyRespondedAt",
                status_event."statusChangedAt",
                invitation."invitationJobStatus", invitation."invitationQueuedAt",
                invitation."invitationAvailableAt", invitation."invitationCompletedAt",
                invitation."invitationResultOutcome",
                invitation."invitationResultAdapter", invitation."invitationAttemptOutcome",
                invitation."invitationAttemptAdapter", invitation."invitationAttemptCompletedAt"
         from "vasi_engine"."participant_assignment" a
         join "vasi_engine"."request_instance" r on r."id" = a."requestId"
         join "vasi_engine"."workflow_revision" w on w."id" = r."workflowRevisionId"
         join "vasi_engine"."tenant" t on t."id" = a."tenantId"
         join "vasi_engine"."record_lifecycle_state" l on l."assignmentId" = a."id"
         left join "vasi_engine"."evidence_manifest" m on m."assignmentId" = a."id"
         left join lateral (
           select e."eventData" #> '{actor,authentication}' as "authentication",
                  e."eventData" #>> '{actor,authenticatedAt}' as "authenticatedAt",
                  e."receivedAt" as "authenticationObservedAt"
           from "vasi_engine"."evidence_event" e
           where e."assignmentId" = a."id" and e."eventType" = 'participant.opened'
           order by e."sequence" limit 1
         ) auth on true
         left join lateral (
           select count(i."id")::integer as "activityCount",
                  (count(i."id") filter (where i."status" in ('completed', 'skipped')))::integer
                    as "resolvedActivityCount",
                  max(coalesce(response."respondedAt", i."completedAt", i."openedAt", i."availableAt"))
                    as "lastActivityAt",
                  coalesce(jsonb_agg(jsonb_build_object(
                    'activityId', i."activityId",
                    'activityTitle', i."definition"->>'title',
                    'outcome', response."outcome",
                    'respondedAt', response."respondedAt",
                    'responseLabel', response."responseLabel"
                  ) order by i."ordinal") filter (where response."id" is not null), '[]'::jsonb)
                    as "responses"
           from "vasi_engine"."activity_instance" i
           left join "vasi_engine"."activity_response" response
             on response."activityInstanceId" = i."id"
           where i."assignmentId" = a."id"
         ) activity on true
         left join lateral (
           select response."responseMode" as "legacyResponseMode",
                  response."responseValue" as "legacyResponseValue",
                  response."respondedAt" as "legacyRespondedAt"
           from "vasi_engine"."participant_response" response
           where response."assignmentId" = a."id"
         ) legacy on true
         left join lateral (
           select event."createdAt" as "statusChangedAt"
           from "vasi_engine"."request_lifecycle_event" event
           where event."requestId" = a."requestId"
             and event."eventType" = ('request.' || a."status")
           order by event."createdAt" desc, event."id" desc limit 1
         ) status_event on true
         left join lateral (
           select job."status" as "invitationJobStatus",
                  job."createdAt" as "invitationQueuedAt",
                  job."availableAt" as "invitationAvailableAt",
                  job."completedAt" as "invitationCompletedAt",
                  job."result"->>'outcome' as "invitationResultOutcome",
                  job."result"->>'adapter' as "invitationResultAdapter",
                  attempt."outcome" as "invitationAttemptOutcome",
                  attempt."adapter" as "invitationAttemptAdapter",
                  attempt."completedAt" as "invitationAttemptCompletedAt"
           from "vasi_engine"."outbox_job" job
           left join lateral (
             select delivery."outcome", delivery."adapter", delivery."completedAt"
             from "vasi_engine"."notification_delivery_attempt" delivery
             where delivery."jobId" = job."id"
             order by delivery."attempt" desc limit 1
           ) attempt on true
           where job."requestId" = a."requestId"
             and job."jobType" = 'notification'
             and job."notificationType" = 'request.issued'
           order by job."createdAt" desc, job."id" desc limit 1
         ) invitation on true
         where (a."principalId" = $1 or lower(coalesce(a."participantEmail", a."intendedEmail")) = $2)
           and l."historyStatus" = 'active'
           and (l."historyExpiresAt" is null or l."historyExpiresAt" > CURRENT_TIMESTAMP)
         order by coalesce(a."completedAt", a."firstOpenedAt", a."issuedAt") desc, a."id"
         limit 250`,
        [actor.principalId, actor.email.toLowerCase()],
      );
      return result.rows.map(participantHistoryProjection);
    },

    async createParticipantDataRequest(actor, payload) {
      requireParticipant(actor);
      const now = new Date();
      const authenticationAssurance = requireRecentParticipantDataAuthentication(actor, now);
      const input = validateParticipantDataRequestCreate(payload);
      return transaction(database, async (client) => {
        const replay = await client.query(
          `select "id" from "vasi_engine"."participant_data_request" where "commandId" = $1`,
          [input.commandId],
        );
        if (replay.rowCount) return loadDataRequestProjection(client, replay.rows[0].id, actor);
        const assignments = await client.query(
          `select a."id" as "assignmentId", a."tenantId"
           from "vasi_engine"."participant_assignment" a
           join "vasi_engine"."record_lifecycle_state" l on l."assignmentId" = a."id"
           where a."principalId" = $1
              or lower(coalesce(a."participantEmail", a."intendedEmail")) = $2
           order by a."tenantId", a."id"`,
          [actor.principalId, actor.email.toLowerCase()],
        );
        const scopes = groupAssignments(assignments.rows);
        const requestId = randomUUID();
        const status = scopes.length ? "pending_review" : "approved";
        const expiresAt = plusDays(now, reviewDays);
        await client.query(
          `insert into "vasi_engine"."participant_data_request"
            ("id", "requesterPrincipalId", "requesterEmail", "status", "commandId",
             "requestedAt", "expiresAt", "updatedAt")
           values ($1, $2, $3, $4, $5, $6, $7, $6)`,
          [requestId, actor.principalId, actor.email.toLowerCase(), status, input.commandId, now, expiresAt],
        );
        await client.query(
          `insert into "vasi_engine"."participant_data_request_chain_head"
            ("requestId", "lastSequence", "lastHash") values ($1, 0, $2)`,
          [requestId, GENESIS_HASH],
        );
        for (const scope of scopes) {
          await client.query(
            `insert into "vasi_engine"."participant_data_request_scope"
              ("requestId", "tenantId", "matchedAssignmentIds") values ($1, $2, $3)`,
            [requestId, scope.tenantId, scope.assignmentIds],
          );
        }
        await appendDataRequestEvent(client, {
          actor,
          commandId: input.commandId,
          eventType: "request.created",
          payload: {
            authenticationAssurance,
            matchedRecordCount: assignments.rowCount,
            reviewExpiresAt: expiresAt.toISOString(),
            tenantScopeCount: scopes.length,
          },
          requestId,
          createdAt: now,
        });
        return loadDataRequestProjection(client, requestId, actor);
      });
    },

    async listParticipantDataRequests(actor) {
      requireParticipant(actor);
      const result = await database.query(
        `select "id" from "vasi_engine"."participant_data_request"
         where "requesterPrincipalId" = $1 or lower("requesterEmail") = $2
         order by "requestedAt" desc limit 50`,
        [actor.principalId, actor.email.toLowerCase()],
      );
      const requests = [];
      for (const row of result.rows) requests.push(await loadDataRequestProjection(database, row.id, actor));
      return requests;
    },

    async listDataRequestReviews(actor, payload) {
      requireActor(actor);
      const input = validateLifecycleListInput(payload);
      const client = await database.connect();
      try {
        await requirePermission(client, actor, input.tenantId, "data_request.review");
        const result = await client.query(
          `select s."requestId", s."tenantId", s."status", s."matchedAssignmentIds",
                  s."reviewPolicy", s."reviewedByPrincipalId", s."reviewReason", s."reviewedAt",
                  r."requesterEmail", r."status" as "requestStatus", r."requestedAt", r."expiresAt"
           from "vasi_engine"."participant_data_request_scope" s
           join "vasi_engine"."participant_data_request" r on r."id" = s."requestId"
           where s."tenantId" = $1
           order by case when s."status" = 'pending_review' then 0 else 1 end,
                    r."requestedAt" desc, s."requestId" limit $2`,
          [input.tenantId, input.limit],
        );
        return result.rows.map(dataReviewProjection);
      } finally {
        client.release();
      }
    },

    async reviewDataRequest(actor, payload) {
      requireActor(actor);
      const input = validateParticipantDataRequestReview(payload);
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "data_request.review");
        const replay = await client.query(
          `select "requestId" from "vasi_engine"."participant_data_request_scope"
           where "reviewCommandId" = $1 and "tenantId" = $2`,
          [input.commandId, input.tenantId],
        );
        if (replay.rowCount) return loadDataRequestProjection(client, replay.rows[0].requestId);
        const scopeResult = await client.query(
          `select s.*, r."expiresAt", r."status" as "requestStatus"
           from "vasi_engine"."participant_data_request_scope" s
           join "vasi_engine"."participant_data_request" r on r."id" = s."requestId"
           where s."requestId" = $1 and s."tenantId" = $2 for update of s, r`,
          [input.requestId, input.tenantId],
        );
        if (!scopeResult.rowCount) notFound();
        const scope = scopeResult.rows[0];
        if (scope.status !== "pending_review") throw new EngineStoreError("data_request_already_reviewed", 409);
        const now = new Date();
        if (new Date(scope.expiresAt) <= now || scope.requestStatus === "expired") {
          throw new EngineStoreError("data_request_expired", 410);
        }
        const reviewPolicy = input.decision === "approve" ? {
          excludeRequestingOrganizationInternalMetadata: true,
          excludeSecrets: true,
          excludeThirdPartyPersonalData: true,
          includeAuthenticationProvenance: true,
          includeTechnicalTelemetry: input.includeTechnicalTelemetry,
          schema: "vasi-participant-data-redaction/v1",
        } : null;
        await client.query(
          `update "vasi_engine"."participant_data_request_scope"
           set "status" = $3, "reviewPolicy" = $4, "reviewedByPrincipalId" = $5,
               "reviewCommandId" = $6, "reviewReason" = $7, "reviewedAt" = $8
           where "requestId" = $1 and "tenantId" = $2`,
          [
            input.requestId,
            input.tenantId,
            input.decision === "approve" ? "approved" : "denied",
            reviewPolicy,
            actor.principalId,
            input.commandId,
            input.reason || null,
            now,
          ],
        );
        const countsResult = await client.query(
          `select count(*) filter (where "status" = 'pending_review') as "pending",
                  count(*) filter (where "status" = 'approved') as "approved",
                  count(*) filter (where "status" = 'denied') as "denied"
           from "vasi_engine"."participant_data_request_scope" where "requestId" = $1`,
          [input.requestId],
        );
        const counts = countsResult.rows[0];
        const pending = Number(counts.pending);
        const approved = Number(counts.approved);
        const denied = Number(counts.denied);
        const requestStatus = pending
          ? "pending_review"
          : approved && denied
            ? "partially_approved"
            : approved
              ? "approved"
              : "denied";
        await client.query(
          `update "vasi_engine"."participant_data_request"
           set "status" = $2,
               "reviewCompletedAt" = case when $3 then $4::timestamptz else null end,
               "updatedAt" = $4::timestamptz where "id" = $1`,
          [input.requestId, requestStatus, pending === 0, now],
        );
        await appendDataRequestEvent(client, {
          actor,
          commandId: input.commandId,
          eventType: input.decision === "approve" ? "scope.approved" : "scope.denied",
          payload: {
            decision: input.decision,
            includeTechnicalTelemetry: reviewPolicy?.includeTechnicalTelemetry,
            reason: input.reason,
            resultingRequestStatus: requestStatus,
          },
          requestId: input.requestId,
          tenantId: input.tenantId,
          createdAt: now,
        });
        return loadDataRequestProjection(client, input.requestId);
      });
    },

    async openParticipantDataExport(actor, payload) {
      requireParticipant(actor);
      const now = new Date();
      const authenticationAssurance = requireRecentParticipantDataAuthentication(actor, now);
      const input = validateParticipantDataExportOpen(payload);
      return transaction(database, async (client) => {
        const request = await participantDataRequest(client, input.requestId, actor, true);
        assertDataRequestExportable(request, now);
        const artifact = await participantDataExport(client, request.id);
        if (!artifact) throw new EngineStoreError("participant_data_export_unavailable", 503);
        if (artifact.contentDeletedAt || new Date(artifact.expiresAt) <= now) {
          throw new EngineStoreError("participant_data_export_expired", 410);
        }
        await recordDataExportAccess(client, actor, artifact, "metadata");
        await appendDataRequestEvent(client, {
          actor,
          eventType: "export.opened",
          payload: { authenticationAssurance, exportId: artifact.id },
          requestId: request.id,
          createdAt: now,
        });
        return participantDataExportProjection(artifact);
      });
    },

    async readParticipantDataExportChunk(actor, payload) {
      requireParticipant(actor);
      const now = new Date();
      const authenticationAssurance = requireRecentParticipantDataAuthentication(actor, now);
      const input = validateParticipantDataExportOpen({ requestId: payload?.requestId });
      const exportId = token(payload?.exportId, "exportId");
      const sequence = integer(payload?.sequence, "sequence", 0, 100_000);
      return transaction(database, async (client) => {
        const request = await participantDataRequest(client, input.requestId, actor, false);
        const artifact = await participantDataExport(client, request.id, exportId);
        if (!artifact) notFound();
        if (artifact.contentDeletedAt || new Date(artifact.expiresAt) <= now) {
          throw new EngineStoreError("participant_data_export_expired", 410);
        }
        if (sequence >= Number(artifact.chunkCount)) notFound();
        const result = await client.query(
          `select "sequence", "byteLength", "sha256", "bytes"
           from "vasi_engine"."participant_data_export_chunk"
           where "exportId" = $1 and "sequence" = $2`,
          [artifact.id, sequence],
        );
        if (!result.rowCount) notFound();
        const chunk = result.rows[0];
        if (Number(chunk.byteLength) !== chunk.bytes.length || sha256Hex(chunk.bytes) !== chunk.sha256) {
          throw new EngineStoreError("integrity_check_failed", 500);
        }
        await recordDataExportAccess(client, actor, artifact, "chunk", sequence);
        if (sequence === Number(artifact.chunkCount) - 1) {
          await appendDataRequestEvent(client, {
            actor,
            eventType: "export.downloaded",
            payload: { authenticationAssurance, exportId: artifact.id, finalSequence: sequence },
            requestId: request.id,
            createdAt: now,
          });
        }
        return {
          byteLength: Number(chunk.byteLength),
          data: chunk.bytes.toString("base64"),
          sequence: Number(chunk.sequence),
          sha256: chunk.sha256,
        };
      });
    },
  });
}

export function createParticipantDataExportWorker(database, settings) {
  const signingProvider = createSigningProvider(settings);
  const contextEvidencePolicy = participantContextPolicy(settings);
  const chunkBytes = boundedSetting(
    settings.ENGINE_EXPORT_CHUNK_BYTES,
    262_144,
    65_536,
    524_288,
    "ENGINE_EXPORT_CHUNK_BYTES",
  );
  const maxBytes = boundedSetting(
    settings.ENGINE_PARTICIPANT_DATA_EXPORT_MAX_BYTES,
    67_108_864,
    1_048_576,
    536_870_912,
    "ENGINE_PARTICIPANT_DATA_EXPORT_MAX_BYTES",
  );
  const deliveryDays = boundedSetting(
    settings.ENGINE_DATA_EXPORT_DELIVERY_DAYS,
    7,
    1,
    30,
    "ENGINE_DATA_EXPORT_DELIVERY_DAYS",
  );

  return Object.freeze({
    async prepareOne(now = new Date()) {
      return transaction(database, async (client) => {
        const result = await client.query(
          `select r.* from "vasi_engine"."participant_data_request" r
           where r."status" in ('approved', 'partially_approved')
             and r."expiresAt" > $1
             and not exists (
               select 1 from "vasi_engine"."participant_data_export" e
               where e."requestId" = r."id"
             )
           order by coalesce(r."reviewCompletedAt", r."requestedAt"), r."id"
           limit 1 for update of r skip locked`,
          [now],
        );
        if (!result.rowCount) return null;
        const request = result.rows[0];
        const generated = await buildParticipantDataExport(
          client,
          request,
          participantExportActor(request),
          now,
          contextEvidencePolicy,
        );
        if (!generated.bytes.length || generated.bytes.length > maxBytes) {
          await client.query(
            `update "vasi_engine"."participant_data_request"
             set "status" = 'preparation_failed', "updatedAt" = $2 where "id" = $1`,
            [request.id, now],
          );
          await appendDataRequestEvent(client, {
            actor: serviceActor("vasi-worker"),
            createdAt: now,
            eventType: "export.preparation_failed",
            payload: {
              errorCode: "participant_data_export_too_large",
              maximumBytes: maxBytes,
              observedBytes: generated.bytes.length,
            },
            requestId: request.id,
          });
          return Object.freeze({ action: "export.preparation_failed", requestId: request.id });
        }
        const artifact = await persistParticipantDataExport(client, {
          bytes: generated.bytes,
          chunkBytes,
          deliveryDays,
          payload: generated.payload,
          request,
          signingProvider,
          now,
        });
        await client.query(
          `update "vasi_engine"."participant_data_request"
           set "status" = 'ready', "updatedAt" = $2 where "id" = $1`,
          [request.id, now],
        );
        await appendDataRequestEvent(client, {
          actor: serviceActor("vasi-worker"),
          createdAt: now,
          eventType: "export.created",
          payload: {
            byteLength: Number(artifact.byteLength),
            exportId: artifact.id,
            expiresAt: new Date(artifact.expiresAt).toISOString(),
            sha256: artifact.sha256,
          },
          requestId: request.id,
        });
        return Object.freeze({
          action: "export.created",
          exportId: artifact.id,
          requestId: request.id,
        });
      });
    },
  });
}

export async function bindRecordLifecycle(client, {
  actor,
  assignmentId,
  expiresAt,
  profileName = "tenant_default",
  requestId,
  tenantId,
}) {
  const resolved = await resolveRetentionPolicy(client, tenantId, profileName);
  const deadlines = calculateRetentionDeadlines(resolved.policy, { expiresAt });
  await client.query(
    `insert into "vasi_engine"."record_lifecycle_state"
      ("assignmentId", "tenantId", "requestId", "policyRevisionId", "policySnapshot", "policyHash",
       "terminalAt", "contentExpiresAt", "historyExpiresAt", "archiveAt", "deleteAt")
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      assignmentId,
      tenantId,
      requestId,
      resolved.id,
      resolved.policy,
      resolved.policyHash,
      deadlines.terminalAt,
      deadlines.contentExpiresAt,
      deadlines.historyExpiresAt,
      deadlines.archiveAt,
      deadlines.deleteAt,
    ],
  );
  await client.query(
    `insert into "vasi_engine"."record_lifecycle_chain_head"
      ("assignmentId", "lastSequence", "lastHash") values ($1, 0, $2)`,
    [assignmentId, GENESIS_HASH],
  );
  await appendLifecycleEvent(client, {
    actor,
    assignmentId,
    eventType: "policy.bound",
    payload: {
      deadlines: isoDeadlines(deadlines),
      policyHash: resolved.policyHash,
      policyRevisionId: resolved.id,
      profileName,
    },
    requestId,
    source: "engine",
    tenantId,
    createdAt: new Date(),
  });
  return { ...resolved, deadlines };
}

export async function anchorRecordLifecycle(client, {
  actor,
  assignmentId,
  completedAt,
  requestId,
  tenantId,
}) {
  const result = await client.query(
    `select * from "vasi_engine"."record_lifecycle_state" where "assignmentId" = $1 for update`,
    [assignmentId],
  );
  if (!result.rowCount) throw new EngineStoreError("record_lifecycle_missing", 500);
  const row = result.rows[0];
  const deadlines = calculateRetentionDeadlines(row.policySnapshot, {
    expiresAt: row.contentExpiresAt || completedAt,
    terminalAt: completedAt,
  });
  await client.query(
    `update "vasi_engine"."record_lifecycle_state"
     set "terminalAt" = $2, "contentExpiresAt" = $3, "historyExpiresAt" = $4,
         "archiveAt" = $5, "deleteAt" = $6, "updatedAt" = $2
     where "assignmentId" = $1`,
    [
      assignmentId,
      deadlines.terminalAt,
      deadlines.contentExpiresAt,
      deadlines.historyExpiresAt,
      deadlines.archiveAt,
      deadlines.deleteAt,
    ],
  );
  await appendLifecycleEvent(client, {
    actor,
    assignmentId,
    eventType: "terminal.anchored",
    payload: { deadlines: isoDeadlines(deadlines), policyHash: row.policyHash },
    requestId,
    source: "engine",
    tenantId,
    createdAt: completedAt,
  });
  return deadlines;
}

export async function assertLifecycleContentAvailable(client, assignmentId, now = new Date()) {
  const result = await client.query(
    `select "contentStatus", "contentExpiresAt" from "vasi_engine"."record_lifecycle_state"
     where "assignmentId" = $1`,
    [assignmentId],
  );
  if (!result.rowCount) throw new EngineStoreError("record_lifecycle_missing", 500);
  const row = result.rows[0];
  if (row.contentStatus === "expired" || (row.contentExpiresAt && new Date(row.contentExpiresAt) <= now)) {
    throw new EngineStoreError("content_unavailable", 410);
  }
}

export async function assertLifecycleHistoryAvailable(client, assignmentId, now = new Date()) {
  const result = await client.query(
    `select "historyStatus", "historyExpiresAt" from "vasi_engine"."record_lifecycle_state"
     where "assignmentId" = $1`,
    [assignmentId],
  );
  if (!result.rowCount) throw new EngineStoreError("record_lifecycle_missing", 500);
  const row = result.rows[0];
  if (row.historyStatus === "expired" || (row.historyExpiresAt && new Date(row.historyExpiresAt) <= now)) {
    throw new EngineStoreError("participant_history_unavailable", 410);
  }
}

export async function appendLifecycleEvent(client, {
  actor,
  assignmentId,
  commandId,
  createdAt,
  eventType,
  payload,
  requestId,
  source,
  tenantId,
}) {
  const head = await client.query(
    `select "lastSequence", "lastHash" from "vasi_engine"."record_lifecycle_chain_head"
     where "assignmentId" = $1 for update`,
    [assignmentId],
  );
  if (!head.rowCount) throw new EngineStoreError("record_lifecycle_chain_missing", 500);
  const sequence = Number(head.rows[0].lastSequence) + 1;
  const previousHash = head.rows[0].lastHash;
  const eventId = randomUUID();
  const eventData = {
    actor: lifecycleActorSnapshot(actor),
    assignmentId,
    createdAt: createdAt.toISOString(),
    engineVersion: ENGINE_VERSION,
    eventId,
    eventType,
    payload,
    previousHash,
    requestId,
    schema: "vasi-record-lifecycle-event/v1",
    sequence,
    source,
    tenantId,
  };
  const eventHash = hashCanonicalJSON(eventData);
  await client.query(
    `insert into "vasi_engine"."record_lifecycle_event"
      ("id", "tenantId", "requestId", "assignmentId", "sequence", "eventType",
       "actorPrincipalId", "source", "commandId", "eventData", "previousHash", "eventHash", "createdAt")
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
    [
      eventId,
      tenantId,
      requestId,
      assignmentId,
      sequence,
      eventType,
      actor.principalId,
      source,
      commandId || null,
      eventData,
      previousHash,
      eventHash,
      createdAt,
    ],
  );
  await client.query(
    `update "vasi_engine"."record_lifecycle_chain_head"
     set "lastSequence" = $2, "lastHash" = $3 where "assignmentId" = $1`,
    [assignmentId, sequence, eventHash],
  );
  return { eventHash, eventId, sequence };
}

async function resolveRetentionPolicy(client, tenantId, profileName) {
  const result = await client.query(
    `select r."id", r."policy", r."policyHash", r."revision"
     from "vasi_engine"."retention_policy_pointer" p
     join "vasi_engine"."retention_policy_revision" r on r."id" = p."activeRevisionId"
     where p."tenantId" = $1 and p."name" = $2`,
    [tenantId, profileName],
  );
  if (!result.rowCount) {
    if (profileName !== "tenant_default") {
      throw new EngineStoreError("retention_policy_not_found", 409);
    }
    return {
      id: null,
      policy: SYSTEM_RETENTION_POLICY,
      policyHash: retentionPolicyHash(SYSTEM_RETENTION_POLICY),
      revision: 0,
    };
  }
  const row = result.rows[0];
  const policy = normalizeRetentionPolicy(row.policy);
  if (retentionPolicyHash(policy) !== row.policyHash) {
    throw new EngineStoreError("retention_policy_integrity_failed", 500);
  }
  return { id: row.id, policy, policyHash: row.policyHash, revision: Number(row.revision) };
}

async function buildParticipantDataExport(
  client,
  request,
  actor,
  generatedAt,
  contextEvidencePolicy,
) {
  const scopesResult = await client.query(
    `select s."tenantId", s."matchedAssignmentIds", s."reviewPolicy", s."reviewedAt",
            t."name" as "tenantName"
     from "vasi_engine"."participant_data_request_scope" s
     join "vasi_engine"."tenant" t on t."id" = s."tenantId"
     where s."requestId" = $1 and s."status" = 'approved'
     order by s."tenantId"`,
    [request.id],
  );
  const scopes = [];
  for (const scope of scopesResult.rows) {
    const records = [];
    for (const assignmentId of [...scope.matchedAssignmentIds].sort()) {
      records.push(await loadParticipantDataRecord(client, {
        actor,
        assignmentId,
        contextEvidencePolicy,
        includeTechnicalTelemetry: scope.reviewPolicy?.includeTechnicalTelemetry !== false,
        tenantId: scope.tenantId,
      }));
    }
    scopes.push({
      records,
      review: {
        policy: scope.reviewPolicy,
        reviewedAt: new Date(scope.reviewedAt).toISOString(),
      },
      tenant: { id: scope.tenantId, name: scope.tenantName },
    });
  }
  const payload = {
    generatedAt: generatedAt.toISOString(),
    limitations: [
      "This export contains VASI engine data approved for the requesting participant.",
      "Requesting-organization secrets, internal-only metadata, and unrelated third-party personal data are excluded.",
      "Provider-hosted source media is referenced by recorded metadata; VASI does not reproduce provider content here.",
    ],
    profile: DATA_EXPORT_PROFILE,
    request: {
      id: request.id,
      requestedAt: new Date(request.requestedAt).toISOString(),
      requester: { email: request.requesterEmail, principalId: request.requesterPrincipalId },
    },
    schema: DATA_EXPORT_SCHEMA,
    scopes,
  };
  return { bytes: Buffer.from(canonicalJSON(payload), "utf8"), payload };
}

async function loadParticipantDataRecord(client, {
  actor,
  assignmentId,
  contextEvidencePolicy,
  includeTechnicalTelemetry,
  tenantId,
}) {
  const result = await client.query(
    `select a."id" as "assignmentId", a."requestId", a."principalId", a."intendedEmail",
            a."participantEmail", a."status" as "assignmentStatus", a."issuedAt", a."firstOpenedAt",
            a."completedAt", r."status" as "requestStatus", r."purpose", r."scheduledFor",
            r."dueAt", r."expiresAt", r."requesterSnapshot", w."id" as "workflowRevisionId",
            w."revision", w."title", w."contentHash", w."snapshotHash", t."id" as "tenantId",
            t."name" as "tenantName", m."manifestHash",
            l."policySnapshot", l."policyHash", l."contentStatus", l."historyStatus",
            l."evidenceStatus", l."contentExpiresAt", l."historyExpiresAt", l."archiveAt", l."deleteAt"
     from "vasi_engine"."participant_assignment" a
     join "vasi_engine"."request_instance" r on r."id" = a."requestId"
     join "vasi_engine"."workflow_revision" w on w."id" = r."workflowRevisionId"
     join "vasi_engine"."tenant" t on t."id" = a."tenantId"
     join "vasi_engine"."record_lifecycle_state" l on l."assignmentId" = a."id"
     left join "vasi_engine"."evidence_manifest" m on m."assignmentId" = a."id"
     where a."id" = $1 and a."tenantId" = $2
       and (a."principalId" = $3 or lower(coalesce(a."participantEmail", a."intendedEmail")) = $4)`,
    [assignmentId, tenantId, actor.principalId, actor.email.toLowerCase()],
  );
  if (!result.rowCount) notFound();
  const row = result.rows[0];
  const eventsResult = await client.query(
    `select "id", "sequence", "eventType", "actorPrincipalId", "eventData",
            "previousHash", "eventHash", "receivedAt"
     from "vasi_engine"."evidence_event" where "assignmentId" = $1 order by "sequence"`,
    [assignmentId],
  );
  const responsesResult = await client.query(
    `select i."activityId", i."activityType", rr."revision", rr."state", rr."responseValue",
            rr."responseLabel", rr."outcome", rr."result", rr."clientContext", rr."recordedAt"
     from "vasi_engine"."activity_response_revision" rr
     join "vasi_engine"."activity_instance" i on i."id" = rr."activityInstanceId"
     where rr."assignmentId" = $1 order by i."ordinal", rr."revision"`,
    [assignmentId],
  );
  const legacyResponse = await client.query(
    `select "responseMode", "responseValue", "respondedAt", "clientContext"
     from "vasi_engine"."participant_response" where "assignmentId" = $1`,
    [assignmentId],
  );
  const accessResult = await client.query(
    `select 'document' as "category", "accessType", "disposition", "metadata", "createdAt"
     from "vasi_engine"."document_artifact_access_event"
     where "assignmentId" = $1 and "actorPrincipalId" = any($2::text[])
     union all
     select 'evidence' as "category", "accessType", null as "disposition", "metadata", "createdAt"
     from "vasi_engine"."evidence_access_event"
     where "assignmentId" = $1 and "actorPrincipalId" = any($2::text[])
     order by "createdAt"`,
    [assignmentId, [...new Set([actor.principalId, row.principalId].filter(Boolean))]],
  );
  const sealsResult = await client.query(
    `select s."sealRole", s."profile", s."algorithm", s."keyId", s."publicJwk",
            s."signature", s."certificateChain", s."metadata", s."createdAt"
     from "vasi_engine"."evidence_manifest" m
     join "vasi_engine"."evidence_seal" s on s."manifestId" = m."id"
     where m."assignmentId" = $1 order by s."sealRole", s."keyId"`,
    [assignmentId],
  );
  const interactionSummariesResult = await client.query(
    `select i."activityId", s."revision", s."policy", s."summary", s."summaryHash", s."calculatedAt"
     from "vasi_engine"."activity_interaction_summary_revision" s
     join "vasi_engine"."activity_instance" i on i."id" = s."activityInstanceId"
     where s."assignmentId" = $1 order by i."ordinal", s."revision"`,
    [assignmentId],
  );
  let activityInteractionBatches = [];
  let activityInteractionEvents = [];
  let participantContextSnapshots = [];
  let media = [];
  if (includeTechnicalTelemetry) {
    const interactionBatchResult = await client.query(
      `select i."activityId", b."id", b."interactionId", b."telemetrySessionId",
              b."actorPrincipalId", b."eventCount", b."payloadHash", b."receivedAt"
       from "vasi_engine"."activity_interaction_event_batch" b
       join "vasi_engine"."activity_instance" i on i."id" = b."activityInstanceId"
       where b."assignmentId" = $1 order by i."ordinal", b."receivedAt", b."id"`,
      [assignmentId],
    );
    activityInteractionBatches = interactionBatchResult.rows.map((entry) => ({
      ...entry,
      eventCount: Number(entry.eventCount),
      receivedAt: new Date(entry.receivedAt).toISOString(),
    }));
    const interactionResult = await client.query(
      `select i."activityId", e."id", e."telemetrySessionId", e."sequence",
              e."eventType", e."monotonicMs", e."eventData", e."receivedAt"
       from "vasi_engine"."activity_interaction_event" e
       join "vasi_engine"."activity_instance" i on i."id" = e."activityInstanceId"
       where e."assignmentId" = $1
       order by i."ordinal", e."telemetrySessionId", e."sequence"`,
      [assignmentId],
    );
    activityInteractionEvents = interactionResult.rows.map((entry) => ({
      ...entry,
      monotonicMs: Number(entry.monotonicMs),
      receivedAt: new Date(entry.receivedAt).toISOString(),
      sequence: Number(entry.sequence),
    }));
    const contextResult = await client.query(
      `select i."activityId", s."id", s."interactionId", s."contextSessionId",
              s."sequence", s."purpose", s."schema", s."actorPrincipalId",
              s."gatewaySessionId", s."snapshot", s."requestContext", s."payloadHash",
              s."receivedAt"
       from "vasi_engine"."participant_context_snapshot" s
       join "vasi_engine"."activity_instance" i on i."id" = s."activityInstanceId"
       where s."assignmentId" = $1
       order by i."ordinal", s."contextSessionId", s."sequence"`,
      [assignmentId],
    );
    participantContextSnapshots = contextResult.rows.map((entry) => ({
      activityId: entry.activityId,
      actorPrincipalId: entry.actorPrincipalId,
      context: entry.snapshot,
      contextSessionId: entry.contextSessionId,
      gatewaySessionId: entry.gatewaySessionId,
      id: entry.id,
      interactionId: entry.interactionId,
      payloadHash: entry.payloadHash,
      purpose: entry.purpose,
      receivedAt: new Date(entry.receivedAt).toISOString(),
      requestContext: entry.requestContext,
      schema: entry.schema,
      sequence: Number(entry.sequence),
    }));
    const mediaResult = await client.query(
      `select e."id", e."activityInstanceId", e."telemetrySessionId", e."sequence",
              e."eventType", e."monotonicMs", e."eventData", e."receivedAt"
       from "vasi_engine"."media_event" e where e."assignmentId" = $1
       order by e."activityInstanceId", e."telemetrySessionId", e."sequence"`,
      [assignmentId],
    );
    media = mediaResult.rows.map((entry) => ({
      ...entry,
      monotonicMs: Number(entry.monotonicMs),
      receivedAt: new Date(entry.receivedAt).toISOString(),
      sequence: Number(entry.sequence),
    }));
  }
  const participantPrincipalId = row.principalId || actor.principalId;
  return {
    accessEvents: accessResult.rows.map((entry) => ({
      ...entry,
      createdAt: new Date(entry.createdAt).toISOString(),
    })),
    assignment: {
      completedAt: iso(row.completedAt),
      firstOpenedAt: iso(row.firstOpenedAt),
      id: row.assignmentId,
      intendedEmail: row.intendedEmail,
      issuedAt: iso(row.issuedAt),
      participantEmail: row.participantEmail,
      principalId: row.principalId,
      status: row.assignmentStatus,
    },
    activityInteractionEvidence: {
      batches: activityInteractionBatches,
      events: activityInteractionEvents,
      summaries: interactionSummariesResult.rows.map((entry) => ({
        ...entry,
        calculatedAt: new Date(entry.calculatedAt).toISOString(),
        revision: Number(entry.revision),
      })),
      telemetryIncluded: includeTechnicalTelemetry,
    },
    evidence: {
      eventCount: eventsResult.rowCount,
      manifestHash: row.manifestHash,
      seals: sealsResult.rows.map((seal) => ({
        algorithm: seal.algorithm,
        certificateChain: seal.certificateChain,
        createdAt: iso(seal.createdAt),
        keyId: seal.keyId,
        metadata: seal.metadata,
        profile: seal.profile,
        publicJWK: seal.publicJwk,
        role: seal.sealRole,
        signature: seal.signature,
      })),
    },
    events: eventsResult.rows.map((entry) => participantDataEvent(
      entry,
      participantPrincipalId,
      includeTechnicalTelemetry,
    )),
    lifecycle: {
      archiveAt: iso(row.archiveAt),
      contentExpiresAt: iso(row.contentExpiresAt),
      contentStatus: row.contentStatus,
      deleteAt: iso(row.deleteAt),
      evidenceStatus: row.evidenceStatus,
      historyExpiresAt: iso(row.historyExpiresAt),
      historyStatus: row.historyStatus,
      policy: row.policySnapshot,
      policyHash: row.policyHash,
    },
    mediaTelemetry: media,
    participantContextEvidence: {
      policy: includeTechnicalTelemetry ? contextEvidencePolicy : undefined,
      snapshots: participantContextSnapshots,
      telemetryIncluded: includeTechnicalTelemetry,
    },
    request: {
      completedAt: iso(row.completedAt),
      dueAt: iso(row.dueAt),
      expiresAt: iso(row.expiresAt),
      id: row.requestId,
      purpose: row.purpose,
      scheduledFor: iso(row.scheduledFor),
      sender: { email: row.requesterSnapshot?.email || null, relationship: "requesting_organization" },
      status: row.requestStatus,
    },
    responses: [
      ...responsesResult.rows.map((response) => ({
        activityId: response.activityId,
        activityType: response.activityType,
        clientContext: includeTechnicalTelemetry ? response.clientContext : undefined,
        outcome: response.outcome,
        recordedAt: iso(response.recordedAt),
        responseLabel: response.responseLabel,
        result: response.result,
        revision: Number(response.revision),
        state: response.state,
        value: response.responseValue,
      })),
      ...legacyResponse.rows.map((response) => ({
        clientContext: includeTechnicalTelemetry ? response.clientContext : undefined,
        recordedAt: iso(response.respondedAt),
        responseMode: response.responseMode,
        value: response.responseValue,
      })),
    ],
    tenant: { id: row.tenantId, name: row.tenantName },
    workflow: {
      contentHash: row.contentHash,
      id: row.workflowRevisionId,
      revision: Number(row.revision),
      snapshotHash: row.snapshotHash,
      title: row.title,
    },
  };
}

function participantDataEvent(row, participantPrincipalId, includeTechnicalTelemetry) {
  const participantEvent = row.actorPrincipalId === participantPrincipalId;
  const actor = row.eventData?.actor || {};
  return {
    actor: participantEvent ? {
      authentication: actor.authentication,
      gatewaySessionId: includeTechnicalTelemetry ? actor.gatewaySessionId : undefined,
      principalId: participantPrincipalId,
      relationship: "participant",
      requestContext: includeTechnicalTelemetry ? actor.requestContext : undefined,
    } : { relationship: row.actorPrincipalId === "vasi-worker" ? "vasi_service" : "requesting_organization" },
    eventHash: row.eventHash,
    eventId: row.id,
    eventType: row.eventType,
    payload: participantEvent
      ? sanitizeParticipantValue(row.eventData?.payload, includeTechnicalTelemetry)
      : undefined,
    previousHash: row.previousHash,
    receivedAt: iso(row.receivedAt),
    sequence: Number(row.sequence),
  };
}

function sanitizeParticipantValue(value, includeTechnicalTelemetry, key = "") {
  const alwaysExcluded = new Set([
    "answerKey", "content", "correctChoiceIds", "notificationPolicy", "snapshot",
  ]);
  const technical = new Set([
    "acceptLanguage", "clientContext", "clientHints", "ipAddress", "requestContext", "userAgent",
  ]);
  if (alwaysExcluded.has(key) || (!includeTechnicalTelemetry && technical.has(key))) return undefined;
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeParticipantValue(item, includeTechnicalTelemetry)).filter((item) => item !== undefined);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value)
      .map(([childKey, child]) => [
        childKey,
        sanitizeParticipantValue(child, includeTechnicalTelemetry, childKey),
      ])
      .filter(([, child]) => child !== undefined));
  }
  return value;
}

async function persistParticipantDataExport(client, {
  bytes,
  chunkBytes,
  deliveryDays,
  now,
  payload,
  request,
  signingProvider,
}) {
  const id = randomUUID();
  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += chunkBytes) {
    chunks.push(bytes.subarray(offset, Math.min(bytes.length, offset + chunkBytes)));
  }
  const expiresAt = new Date(Math.min(
    plusDays(now, deliveryDays).getTime(),
    new Date(request.expiresAt).getTime(),
  ));
  const seals = signingProvider.signDetached(payload, DATA_EXPORT_PROFILE);
  await client.query(
    `insert into "vasi_engine"."participant_data_export"
      ("id", "requestId", "profile", "mediaType", "filename", "byteLength", "chunkCount",
       "sha256", "payloadHash", "seal", "createdAt", "expiresAt")
     values ($1, $2, $3, 'application/json', $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      id,
      request.id,
      DATA_EXPORT_PROFILE,
      `vasi-my-data-${request.id}.json`,
      bytes.length,
      chunks.length,
      sha256Hex(bytes),
      hashCanonicalJSON(payload),
      JSON.stringify(seals),
      now,
      expiresAt,
    ],
  );
  for (const [sequence, chunk] of chunks.entries()) {
    await client.query(
      `insert into "vasi_engine"."participant_data_export_chunk"
        ("exportId", "sequence", "byteLength", "sha256", "bytes")
       values ($1, $2, $3, $4, $5)`,
      [id, sequence, chunk.length, sha256Hex(chunk), chunk],
    );
  }
  return {
    byteLength: bytes.length,
    chunkCount: chunks.length,
    contentDeletedAt: null,
    createdAt: now,
    expiresAt,
    filename: `vasi-my-data-${request.id}.json`,
    id,
    mediaType: "application/json",
    profile: DATA_EXPORT_PROFILE,
    requestId: request.id,
    seal: seals,
    sha256: sha256Hex(bytes),
  };
}

async function participantDataRequest(client, requestId, actor, lock) {
  const result = await client.query(
    `select * from "vasi_engine"."participant_data_request" where "id" = $1${lock ? " for update" : ""}`,
    [requestId],
  );
  if (!result.rowCount || !participantMatches(actor, result.rows[0].requesterPrincipalId, result.rows[0].requesterEmail)) {
    notFound();
  }
  return result.rows[0];
}

function assertDataRequestExportable(request, now) {
  if (request.status === "expired" || new Date(request.expiresAt) <= now) {
    throw new EngineStoreError("data_request_expired", 410);
  }
  if (request.status === "pending_review") throw new EngineStoreError("data_request_review_pending", 409);
  if (request.status === "denied") throw new EngineStoreError("data_request_denied", 403);
  if (["approved", "partially_approved"].includes(request.status)) {
    throw new EngineStoreError("participant_data_export_preparing", 409);
  }
  if (request.status === "preparation_failed") {
    throw new EngineStoreError("participant_data_export_preparation_failed", 409);
  }
  if (request.status !== "ready") {
    throw new EngineStoreError("data_request_unavailable", 409);
  }
}

async function participantDataExport(client, requestId, exportId) {
  const result = await client.query(
    `select * from "vasi_engine"."participant_data_export"
     where "requestId" = $1${exportId ? ' and "id" = $2' : ""}`,
    exportId ? [requestId, exportId] : [requestId],
  );
  return result.rows[0];
}

async function loadDataRequestProjection(client, requestId, actor) {
  const result = await client.query(
    `select * from "vasi_engine"."participant_data_request" where "id" = $1`,
    [requestId],
  );
  if (!result.rowCount) notFound();
  const request = result.rows[0];
  if (actor && !participantMatches(actor, request.requesterPrincipalId, request.requesterEmail)) notFound();
  const scopes = await client.query(
    `select s."tenantId", t."name" as "tenantName", s."status", s."matchedAssignmentIds",
            s."reviewReason", s."reviewedAt"
     from "vasi_engine"."participant_data_request_scope" s
     join "vasi_engine"."tenant" t on t."id" = s."tenantId"
     where s."requestId" = $1 order by t."name", s."tenantId"`,
    [requestId],
  );
  const artifact = await participantDataExport(client, requestId);
  const notificationResult = await client.query(
    `select j."id", j."notificationType", j."status", j."availableAt", j."createdAt",
            j."completedAt", j."result"->>'outcome' as "resultOutcome",
            j."result"->>'adapter' as "resultAdapter", t."id" as "tenantId",
            t."name" as "tenantName", attempt."outcome" as "attemptOutcome",
            attempt."adapter" as "attemptAdapter", attempt."completedAt" as "attemptCompletedAt"
     from "vasi_engine"."outbox_job" j
     join "vasi_engine"."tenant" t on t."id" = j."tenantId"
     left join lateral (
       select a."outcome", a."adapter", a."completedAt"
       from "vasi_engine"."notification_delivery_attempt" a
       where a."jobId" = j."id" order by a."attempt" desc limit 1
     ) attempt on true
     where j."participantDataRequestId" = $1 and j."jobType" = 'notification'
     order by j."createdAt", j."id"`,
    [requestId],
  );
  return {
    export: artifact ? participantDataExportProjection(artifact) : null,
    expiresAt: iso(request.expiresAt),
    id: request.id,
    notifications: notificationResult.rows.map((job) => ({
      adapter: safeNotificationAdapter(job.attemptAdapter || job.resultAdapter),
      completedAt: iso(job.attemptCompletedAt || job.completedAt),
      notificationType: job.notificationType,
      queuedAt: iso(job.createdAt),
      scheduledFor: iso(job.availableAt),
      status: notificationOperationalStatus({
        attemptOutcome: job.attemptOutcome,
        availableAt: job.availableAt,
        resultOutcome: job.resultOutcome,
        status: job.status,
      }),
      tenant: { id: job.tenantId, name: job.tenantName },
    })),
    requestedAt: iso(request.requestedAt),
    reviewCompletedAt: iso(request.reviewCompletedAt),
    scopes: scopes.rows.map((scope) => ({
      matchedRecordCount: scope.matchedAssignmentIds.length,
      reviewReason: scope.reviewReason,
      reviewedAt: iso(scope.reviewedAt),
      status: scope.status,
      tenant: { id: scope.tenantId, name: scope.tenantName },
    })),
    status: request.status,
  };
}

export async function appendDataRequestEvent(client, {
  actor,
  commandId,
  createdAt,
  eventType,
  payload,
  requestId,
  tenantId,
}) {
  const head = await client.query(
    `select "lastSequence", "lastHash" from "vasi_engine"."participant_data_request_chain_head"
     where "requestId" = $1 for update`,
    [requestId],
  );
  if (!head.rowCount) throw new EngineStoreError("data_request_chain_missing", 500);
  const sequence = Number(head.rows[0].lastSequence) + 1;
  const previousHash = head.rows[0].lastHash;
  const eventId = randomUUID();
  const eventData = {
    actor: lifecycleActorSnapshot(actor),
    createdAt: createdAt.toISOString(),
    engineVersion: ENGINE_VERSION,
    eventId,
    eventType,
    payload,
    previousHash,
    requestId,
    schema: "vasi-participant-data-request-event/v1",
    sequence,
    tenantId,
  };
  const eventHash = hashCanonicalJSON(eventData);
  await client.query(
    `insert into "vasi_engine"."participant_data_request_event"
      ("id", "requestId", "tenantId", "sequence", "eventType", "actorPrincipalId",
       "commandId", "eventData", "previousHash", "eventHash", "createdAt")
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      eventId,
      requestId,
      tenantId || null,
      sequence,
      eventType,
      actor.principalId,
      commandId || null,
      eventData,
      previousHash,
      eventHash,
      createdAt,
    ],
  );
  await client.query(
    `update "vasi_engine"."participant_data_request_chain_head"
     set "lastSequence" = $2, "lastHash" = $3 where "requestId" = $1`,
    [requestId, sequence, eventHash],
  );
}

async function recordDataExportAccess(client, actor, artifact, accessType, sequence) {
  await client.query(
    `insert into "vasi_engine"."participant_data_export_access_event"
      ("id", "requestId", "exportId", "accessType", "actorPrincipalId",
       "gatewaySessionId", "sequence", "occurredAt")
     values ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      randomUUID(),
      artifact.requestId,
      artifact.id,
      accessType,
      actor.principalId,
      actor.gatewaySessionId,
      sequence ?? null,
      new Date(),
    ],
  );
}

async function lifecycleRecord(client, tenantId, assignmentId, lock) {
  const result = await client.query(
    `select * from "vasi_engine"."record_lifecycle_state"
     where "tenantId" = $1 and "assignmentId" = $2${lock ? " for update" : ""}`,
    [tenantId, assignmentId],
  );
  if (!result.rowCount) notFound();
  return result.rows[0];
}

async function replayedHoldCommand(client, commandId, tenantId) {
  const result = await client.query(
    `select h.*, rel."releasedAt", rel."reason" as "releaseReason"
     from "vasi_engine"."legal_hold" h
     left join "vasi_engine"."legal_hold_release" rel on rel."holdId" = h."id"
     where h."tenantId" = $2 and (h."placementCommandId" = $1 or rel."releaseCommandId" = $1)`,
    [commandId, tenantId],
  );
  return result.rowCount ? holdProjection(result.rows[0]) : undefined;
}

async function requirePermission(client, actor, tenantId, permission) {
  const result = await client.query(
    `select "roles" from "vasi_engine"."tenant_membership"
     where "tenantId" = $1 and "principalId" = $2 and "status" = 'active'
       and "validFrom" <= CURRENT_TIMESTAMP
       and ("expiresAt" is null or "expiresAt" > CURRENT_TIMESTAMP)`,
    [tenantId, actor.principalId],
  );
  if (!result.rowCount || !hasTenantPermission(result.rows[0].roles, permission)) {
    throw new EngineStoreError("forbidden", 403);
  }
}

function lifecycleProjection(row) {
  const holds = Array.isArray(row.holds) ? row.holds : [];
  return {
    archiveAt: iso(row.archiveAt),
    assignmentId: row.assignmentId,
    assignmentStatus: row.assignmentStatus,
    contentExpiresAt: iso(row.contentExpiresAt),
    contentStatus: row.contentStatus,
    deleteAt: iso(row.deleteAt),
    evidenceStatus: row.evidenceStatus,
    historyExpiresAt: iso(row.historyExpiresAt),
    historyStatus: row.historyStatus,
    holds,
    intendedEmail: row.intendedEmail,
    participantEmail: row.participantEmail,
    policy: row.policySnapshot,
    policyHash: row.policyHash,
    policyRevisionId: row.policyRevisionId,
    requestId: row.requestId,
    requestStatus: row.requestStatus,
    tenantId: row.tenantId,
    terminalAt: iso(row.terminalAt),
    title: row.title,
  };
}

export function participantHistoryProjection(row, now = new Date()) {
  const responses = participantHistoryResponses(row);
  const contentAccess = participantHistoryContentAccess(row, now);
  return {
    assignmentId: row.assignmentId,
    activity: {
      lastActivityAt: iso(row.lastActivityAt || row.legacyRespondedAt),
      resolved: Number(row.resolvedActivityCount || 0),
      total: Number(row.activityCount || (row.legacyResponseValue === undefined ? 0 : 1)),
    },
    authentication: participantHistoryAuthentication(row),
    completedAt: iso(row.completedAt),
    evidence: {
      archived: row.evidenceStatus === "archived",
      manifestFingerprint: row.manifestHash,
      reportAvailable: Boolean(row.manifestHash),
    },
    expiresAt: iso(row.expiresAt),
    firstOpenedAt: iso(row.firstOpenedAt),
    invitation: participantHistoryInvitation(row, now),
    issuedAt: iso(row.issuedAt),
    lifecycle: {
      archiveAt: iso(row.archiveAt),
      contentAccessPolicy: contentAccess.policy,
      contentAvailable: contentAccess.available,
      contentExpiresAt: contentAccess.expiresAt,
      deleteAt: iso(row.deleteAt),
      historyExpiresAt: iso(row.historyExpiresAt),
    },
    purpose: row.purpose,
    requestId: row.requestId,
    responses,
    schedule: {
      dueAt: iso(row.dueAt),
      expiresAt: iso(row.expiresAt),
      scheduledFor: iso(row.scheduledFor),
    },
    sender: { email: row.requesterSnapshot?.email || null, relationship: "requesting_organization" },
    status: row.status,
    statusChangedAt: participantStatusChangedAt(row),
    tenant: { id: row.tenantId, name: row.tenantName },
    title: row.title,
    workflow: {
      id: row.workflowRevisionId,
      revision: Number(row.revision),
      snapshotHash: row.snapshotHash,
    },
  };
}

function participantHistoryAuthentication(row) {
  const authentication = row.authentication && typeof row.authentication === "object"
    ? row.authentication
    : {};
  const summary = {
    authenticatedAt: evidenceTimestamp(row.authenticatedAt),
    method: safeHistoryToken(authentication.method),
    observedAt: iso(row.authenticationObservedAt),
    provider: safeHistoryToken(authentication.provider),
    provenance: safeHistoryToken(authentication.provenance),
  };
  return Object.values(summary).some(Boolean) ? withoutUndefined(summary) : undefined;
}

function participantHistoryResponses(row) {
  const responses = Array.isArray(row.responses) ? row.responses.map((response) => withoutUndefined({
    activityId: safeHistoryToken(response?.activityId),
    activityTitle: safeHistoryText(response?.activityTitle, 160),
    outcome: safeHistoryToken(response?.outcome),
    respondedAt: iso(response?.respondedAt),
    responseLabel: safeHistoryText(response?.responseLabel, 10_000),
  })).filter((response) => response.activityId && response.responseLabel) : [];
  if (responses.length || row.legacyResponseValue === undefined || row.legacyResponseValue === null) {
    return responses;
  }
  return [withoutUndefined({
    activityId: "legacy_response",
    activityTitle: "Recorded response",
    outcome: safeHistoryToken(row.legacyResponseMode),
    respondedAt: iso(row.legacyRespondedAt),
    responseLabel: safeHistoryText(row.legacyResponseValue, 10_000),
  })];
}

function participantHistoryContentAccess(row, now) {
  const policy = ["receipt_only", "content_until_expiration", "content_always"]
    .includes(row.accessPolicy?.postCompletion)
    ? row.accessPolicy.postCompletion
    : "receipt_only";
  const completed = row.status === "completed";
  const terminal = ["expired", "revoked"].includes(row.status);
  let policyAllows = !terminal;
  let policyDeadline = row.expiresAt;
  if (completed) {
    policyAllows = policy === "content_always" || policy === "content_until_expiration";
    policyDeadline = policy === "content_until_expiration" ? row.expiresAt : null;
  }
  const effectiveDeadline = earliestDate(policyDeadline, row.contentExpiresAt);
  const retentionAllows = row.contentStatus === "active" &&
    (!row.contentExpiresAt || new Date(row.contentExpiresAt) > now);
  const available = policyAllows && retentionAllows &&
    (!effectiveDeadline || effectiveDeadline > now);
  return {
    available,
    expiresAt: available ? iso(effectiveDeadline) : undefined,
    policy,
  };
}

function participantHistoryInvitation(row, now) {
  if (!row.invitationJobStatus) return { status: "manual_link_only" };
  const status = notificationOperationalStatus({
    attemptOutcome: row.invitationAttemptOutcome,
    availableAt: row.invitationAvailableAt,
    resultOutcome: row.invitationResultOutcome,
    status: row.invitationJobStatus,
  }, now);
  return withoutUndefined({
    adapter: safeNotificationAdapter(row.invitationAttemptAdapter || row.invitationResultAdapter),
    completedAt: iso(row.invitationAttemptCompletedAt || row.invitationCompletedAt),
    queuedAt: iso(row.invitationQueuedAt),
    scheduledFor: iso(row.invitationAvailableAt),
    status,
  });
}

function participantStatusChangedAt(row) {
  if (row.status === "completed") return iso(row.completedAt);
  if (row.status === "in_progress") return iso(row.firstOpenedAt);
  if (["expired", "revoked", "issued", "scheduled"].includes(row.status)) {
    return iso(row.statusChangedAt || row.scheduledFor || row.issuedAt);
  }
  return undefined;
}

function safeNotificationAdapter(value) {
  return ["disabled", "engine", "microsoft_graph", "notification", "smtp", "webhook"].includes(value)
    ? value
    : undefined;
}

function safeHistoryToken(value) {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value) ? value : undefined;
}

function safeHistoryText(value, maximum) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum ? value : undefined;
}

function withoutUndefined(value) {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined && entry !== null));
}

function earliestDate(...values) {
  const dates = values.filter(Boolean).map((value) => new Date(value)).filter((value) => !Number.isNaN(value.getTime()));
  return dates.length ? new Date(Math.min(...dates.map((value) => value.getTime()))) : undefined;
}

function evidenceTimestamp(value) {
  if (typeof value === "number" || (typeof value === "string" && /^\d{1,12}$/.test(value))) {
    const seconds = Number(value);
    if (!Number.isSafeInteger(seconds) || seconds < 0 || seconds > 253_402_300_799) return undefined;
    return new Date(seconds * 1_000).toISOString();
  }
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    return undefined;
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function dataReviewProjection(row) {
  return {
    expiresAt: iso(row.expiresAt),
    matchedRecordCount: row.matchedAssignmentIds.length,
    requestId: row.requestId,
    requesterEmail: row.requesterEmail,
    requestedAt: iso(row.requestedAt),
    requestStatus: row.requestStatus,
    reviewPolicy: row.reviewPolicy,
    reviewReason: row.reviewReason,
    reviewedAt: iso(row.reviewedAt),
    status: row.status,
    tenantId: row.tenantId,
  };
}

function holdProjection(row) {
  return {
    assignmentId: row.assignmentId,
    caseReference: row.caseReference,
    id: row.id,
    placedAt: iso(row.placedAt),
    reason: row.reason,
    releaseReason: row.releaseReason,
    releasedAt: iso(row.releasedAt),
    requestId: row.requestId,
    status: row.releasedAt ? "released" : "active",
    tenantId: row.tenantId,
  };
}

function participantDataExportProjection(row) {
  return {
    byteLength: Number(row.byteLength),
    chunkCount: Number(row.chunkCount),
    createdAt: iso(row.createdAt),
    expiresAt: iso(row.expiresAt),
    filename: row.filename,
    id: row.id,
    mediaType: row.mediaType,
    profile: row.profile,
    seal: row.seal,
    sha256: row.sha256,
  };
}

function groupAssignments(rows) {
  const grouped = new Map();
  for (const row of rows) {
    const assignments = grouped.get(row.tenantId) || [];
    assignments.push(row.assignmentId);
    grouped.set(row.tenantId, assignments);
  }
  return [...grouped.entries()].map(([tenantId, assignmentIds]) => ({ tenantId, assignmentIds }));
}

function lifecycleActorSnapshot(actor) {
  return {
    authentication: actor.authentication ? {
      method: actor.authentication.method,
      provider: actor.authentication.provider,
    } : undefined,
    principalId: actor.principalId,
    roles: [...(actor.roles || [])].sort(),
  };
}

function serviceActor(principalId) {
  return { authentication: { method: "service" }, principalId, roles: ["service"] };
}

function participantExportActor(request) {
  return {
    authentication: { method: "service_preparation" },
    email: request.requesterEmail,
    gatewaySessionId: "vasi-worker",
    principalId: request.requesterPrincipalId,
    roles: ["service"],
  };
}

function isoDeadlines(deadlines) {
  return {
    archiveAt: iso(deadlines.archiveAt),
    contentExpiresAt: iso(deadlines.contentExpiresAt),
    deleteAt: iso(deadlines.deleteAt),
    historyExpiresAt: iso(deadlines.historyExpiresAt),
    terminalAt: iso(deadlines.terminalAt),
  };
}

function iso(value) {
  return value ? new Date(value).toISOString() : null;
}

function plusDays(value, days) {
  return new Date(value.getTime() + days * 86_400_000);
}

function token(value, name, maximum = 128) {
  if (typeof value !== "string" || !value || value.length > maximum) {
    throw new EngineStoreError(`invalid_${name}`, 400);
  }
  return value;
}

function integer(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new EngineStoreError(`invalid_${name}`, 400);
  }
  return value;
}

function boundedSetting(value, fallback, minimum, maximum, name) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be a whole number between ${minimum} and ${maximum}.`);
  }
  return parsed;
}

function requireActor(actor) {
  if (!actor?.principalId || !actor.gatewaySessionId) throw new EngineStoreError("forbidden", 403);
}

function requireParticipant(actor) {
  requireActor(actor);
  if (!actor.email || !actor.authenticatedAt) throw new EngineStoreError("forbidden", 403);
}

function notFound() {
  throw new EngineStoreError("not_found", 404);
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
