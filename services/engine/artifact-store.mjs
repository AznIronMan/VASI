import { createHash, randomUUID } from "node:crypto";

import {
  validateArtifactChunkInput,
  validateArtifactCreateInput,
  validateArtifactListInput,
  validateArtifactReferenceInput,
} from "../../packages/engine-domain/artifacts.mjs";
import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import { hasTenantPermission } from "../../packages/engine-domain/workflow.mjs";
import { createDocumentInspector } from "./document-inspection.mjs";
import { EngineStoreError } from "./errors.mjs";
import { createArtifactScanClient } from "./integration-gateway-scan-client.mjs";
import { assertArtifactCapacity } from "./tenant-policy.mjs";

export function createArtifactStore(database, settings, dependencies = {}) {
  const limits = documentLimits(settings);
  const scanArtifact = dependencies.scanArtifact || createArtifactScanClient(settings, dependencies.scanClient);
  return Object.freeze({
    async createArtifact(actor, payload) {
      const input = validateArtifactCreateInput(payload, limits);
      return transaction(database, async (client) => {
        await requireArtifactPermission(client, actor, input.tenantId, "artifact.manage");
        await assertArtifactCapacity(client, input.tenantId, input.expectedByteLength);
        let familyId = randomUUID();
        let revision = 1;
        if (input.replacesArtifactId) {
          const replaced = await publishedArtifact(client, input.tenantId, input.replacesArtifactId);
          familyId = replaced.familyId;
          const next = await client.query(
            `select coalesce(max("revision"), 0) + 1 as "revision"
             from "vasi_engine"."document_artifact"
             where "tenantId" = $1 and "familyId" = $2`,
            [input.tenantId, familyId],
          );
          revision = Number(next.rows[0].revision);
        }
        if (input.sourceArtifactId) await publishedArtifact(client, input.tenantId, input.sourceArtifactId);
        const artifactId = randomUUID();
        const now = new Date();
        await client.query(
          `insert into "vasi_engine"."document_artifact"
            ("id", "tenantId", "familyId", "revision", "role", "originalFilename", "mediaType",
             "expectedByteLength", "sourceArtifactId", "replacesArtifactId", "encryptionMetadata",
             "retentionPolicy", "createdByPrincipalId", "createdAt")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
          [
            artifactId,
            input.tenantId,
            familyId,
            revision,
            input.role,
            input.originalFilename,
            input.mediaType,
            input.expectedByteLength,
            input.sourceArtifactId || null,
            input.replacesArtifactId || null,
            { mode: "database-managed", representation: "postgresql-bytea-chunks/v1" },
            input.retentionPolicy,
            actor.principalId,
            now,
          ],
        );
        return artifactProjection({
          ...input,
          byteLength: null,
          chunkCount: null,
          createdAt: now,
          familyId,
          id: artifactId,
          inspectionStatus: "pending",
          revision,
          sha256: null,
          status: "quarantined",
        });
      });
    },

    async appendChunk(actor, payload) {
      const input = validateArtifactChunkInput(payload, limits);
      const bytes = Buffer.from(input.data, "base64");
      if (!bytes.length || bytes.length > limits.chunkBytes) {
        throw new EngineStoreError("artifact_chunk_too_large", 413);
      }
      return transaction(database, async (client) => {
        await requireArtifactPermission(client, actor, input.tenantId, "artifact.manage");
        const artifact = await client.query(
          `select "status", "expectedByteLength" from "vasi_engine"."document_artifact"
           where "id" = $1 and "tenantId" = $2 for update`,
          [input.artifactId, input.tenantId],
        );
        if (!artifact.rowCount) notFound();
        if (artifact.rows[0].status !== "quarantined") conflict("artifact_finalized");
        const progress = await client.query(
          `select count(*)::integer as "count", coalesce(sum("byteLength"), 0)::bigint as "bytes"
           from "vasi_engine"."document_artifact_chunk" where "artifactId" = $1`,
          [input.artifactId],
        );
        const nextSequence = Number(progress.rows[0].count);
        const currentBytes = Number(progress.rows[0].bytes);
        if (input.sequence !== nextSequence) conflict("artifact_chunk_sequence_conflict");
        if (currentBytes + bytes.length > Number(artifact.rows[0].expectedByteLength)) {
          throw new EngineStoreError("artifact_length_exceeded", 413);
        }
        const sha256 = createHash("sha256").update(bytes).digest("hex");
        await client.query(
          `insert into "vasi_engine"."document_artifact_chunk"
            ("artifactId", "sequence", "byteLength", "sha256", "bytes")
           values ($1, $2, $3, $4, $5)`,
          [input.artifactId, input.sequence, bytes.length, sha256, bytes],
        );
        return { artifactId: input.artifactId, byteLength: bytes.length, sequence: input.sequence, sha256 };
      });
    },

    async finalizeArtifact(actor, payload) {
      const input = validateArtifactReferenceInput(payload, "artifact finalization");
      const result = await transaction(database, async (client) => {
        await requireArtifactPermission(client, actor, input.tenantId, "artifact.manage");
        const selected = await client.query(
          `select * from "vasi_engine"."document_artifact"
           where "id" = $1 and "tenantId" = $2 for update`,
          [input.artifactId, input.tenantId],
        );
        if (!selected.rowCount) notFound();
        const artifact = selected.rows[0];
        if (artifact.status === "published") return { artifact: artifactProjection(artifact) };
        if (artifact.status === "rejected") return { rejected: artifact.inspectionResult?.rejectionCode || "artifact_rejected" };

        const inspector = createDocumentInspector(artifact.mediaType);
        const digest = createHash("sha256");
        let byteLength = 0;
        let chunkCount = 0;
        for (let sequence = 0; sequence < limits.maxChunks; sequence += 1) {
          const chunkResult = await client.query(
            `select "sequence", "byteLength", "sha256", "bytes"
             from "vasi_engine"."document_artifact_chunk"
             where "artifactId" = $1 and "sequence" = $2`,
            [artifact.id, sequence],
          );
          if (!chunkResult.rowCount) break;
          const chunk = chunkResult.rows[0];
          const chunkDigest = createHash("sha256").update(chunk.bytes).digest("hex");
          if (chunkDigest !== chunk.sha256 || chunk.bytes.length !== Number(chunk.byteLength)) {
            return rejectArtifact(client, artifact, "artifact_chunk_integrity_failure", {
              adapter: "vasi-bounded-document-inspector",
              passed: false,
              rejectionCode: "artifact_chunk_integrity_failure",
            });
          }
          digest.update(chunk.bytes);
          inspector.update(chunk.bytes);
          byteLength += chunk.bytes.length;
          chunkCount += 1;
        }
        const extra = await client.query(
          `select 1 from "vasi_engine"."document_artifact_chunk"
           where "artifactId" = $1 and "sequence" >= $2 limit 1`,
          [artifact.id, limits.maxChunks],
        );
        if (extra.rowCount || !chunkCount || byteLength !== Number(artifact.expectedByteLength)) {
          return rejectArtifact(client, artifact, "artifact_length_mismatch", {
            adapter: "vasi-bounded-document-inspector",
            actualByteLength: byteLength,
            expectedByteLength: Number(artifact.expectedByteLength),
            passed: false,
            rejectionCode: "artifact_length_mismatch",
          });
        }
        const inspection = inspector.finalize();
        if (!inspection.passed) return rejectArtifact(client, artifact, inspection.rejectionCode, inspection);
        const sha256 = digest.digest("hex");
        const externalBinding = await activeExternalScanBinding(client, artifact.tenantId);
        let inspectionProfile = `${inspection.adapter}/${inspection.adapterVersion}`;
        let inspectionResult = inspection;
        if (externalBinding) {
          inspectionProfile = `${inspectionProfile}+${externalBinding.adapterId}/${externalBinding.adapterVersion}`;
          let externalScan;
          try {
            externalScan = await scanArtifact({
              byteLength,
              id: artifact.id,
              mediaType: artifact.mediaType,
              sha256,
              tenantId: artifact.tenantId,
            });
          } catch (error) {
            externalScan = {
              adapter: externalBinding.adapterId,
              adapterVersion: externalBinding.adapterVersion,
              errorCode: boundedScanError(error?.code),
              outcome: "failed",
              responseMetadata: {},
            };
          }
          inspectionResult = pipelineInspection(inspection, externalScan);
          if (externalScan.outcome === "completed") {
            inspectionProfile = `${inspection.adapter}/${inspection.adapterVersion}+${externalScan.adapter}/${externalScan.adapterVersion}`;
          }
          if (externalScan.outcome !== "completed") {
            const pending = await client.query(
              `update "vasi_engine"."document_artifact"
               set "inspectionProfile" = $3, "inspectionResult" = $4
               where "id" = $1 and "tenantId" = $2 returning *`,
              [artifact.id, artifact.tenantId, inspectionProfile, inspectionResult],
            );
            return { artifact: artifactProjection(pending.rows[0]) };
          }
          if (externalScan.verdict !== "clean") {
            const rejectionCode = externalScan.verdict === "malicious"
              ? "external_malware_detected"
              : "external_scan_suspicious";
            return rejectArtifact(client, artifact, rejectionCode, {
              ...inspectionResult,
              rejectionCode,
            }, inspectionProfile);
          }
        }
        const publishedAt = new Date();
        const updated = await client.query(
          `update "vasi_engine"."document_artifact"
           set "status" = 'published', "byteLength" = $3, "chunkCount" = $4, "sha256" = $5,
               "inspectionStatus" = 'passed', "inspectionProfile" = $6, "inspectionResult" = $7,
               "publishedAt" = $8
           where "id" = $1 and "tenantId" = $2 returning *`,
          [
            artifact.id,
            artifact.tenantId,
            byteLength,
            chunkCount,
            sha256,
            inspectionProfile,
            inspectionResult,
            publishedAt,
          ],
        );
        return { artifact: artifactProjection(updated.rows[0]) };
      });
      if (result.rejected) throw new EngineStoreError("artifact_rejected", 422, result.rejected);
      return result.artifact;
    },

    async abortArtifact(actor, payload) {
      const input = validateArtifactReferenceInput(payload, "artifact abort");
      return transaction(database, async (client) => {
        await requireArtifactPermission(client, actor, input.tenantId, "artifact.manage");
        const selected = await client.query(
          `select * from "vasi_engine"."document_artifact"
           where "id" = $1 and "tenantId" = $2 for update`,
          [input.artifactId, input.tenantId],
        );
        if (!selected.rowCount) notFound();
        if (selected.rows[0].status !== "quarantined") return artifactProjection(selected.rows[0]);
        await rejectArtifact(client, selected.rows[0], "upload_aborted", {
          adapter: "gateway-upload",
          passed: false,
          rejectionCode: "upload_aborted",
        });
        const rejected = await client.query(
          `select * from "vasi_engine"."document_artifact" where "id" = $1`,
          [input.artifactId],
        );
        return artifactProjection(rejected.rows[0]);
      });
    },

    async listArtifacts(actor, payload) {
      const input = validateArtifactListInput(payload);
      const client = await database.connect();
      try {
        await requireArtifactPermission(client, actor, input.tenantId, "artifact.read");
        const result = await client.query(
          `select * from "vasi_engine"."document_artifact"
           where "tenantId" = $1 order by "createdAt" desc, "id"`,
          [input.tenantId],
        );
        return result.rows.map(artifactProjection);
      } finally {
        client.release();
      }
    },

    async openOwnerArtifact(actor, payload) {
      const input = validateArtifactReferenceInput(payload, "artifact stream");
      return transaction(database, async (client) => {
        await requireArtifactPermission(client, actor, input.tenantId, "artifact.read");
        const artifact = await publishedArtifact(client, input.tenantId, input.artifactId);
        await client.query(
          `insert into "vasi_engine"."document_artifact_access_event"
            ("id", "tenantId", "artifactId", "actorPrincipalId", "accessType", "disposition", "metadata")
           values ($1, $2, $3, $4, 'owner_stream', $5, $6)`,
          [randomUUID(), input.tenantId, input.artifactId, actor.principalId, input.disposition, { source: "owner_gateway" }],
        );
        return artifactProjection(artifact);
      });
    },

    async readOwnerChunk(actor, payload) {
      const input = validateArtifactReferenceInput(payload, "artifact chunk stream");
      if (input.sequence === undefined) throw new EngineStoreError("invalid_artifact_sequence", 400);
      const client = await database.connect();
      try {
        await requireArtifactPermission(client, actor, input.tenantId, "artifact.read");
        await publishedArtifact(client, input.tenantId, input.artifactId);
        return readChunk(client, input.artifactId, input.sequence);
      } finally {
        client.release();
      }
    },

    limits,
  });
}

export async function resolveWorkflowArtifactBindings(client, tenantId, document) {
  const bindings = [];
  const activities = [];
  for (const activity of document.activities) {
    if (activity.type !== "document_review") {
      activities.push(activity);
      continue;
    }
    const artifact = await publishedArtifact(client, tenantId, activity.content.artifactId);
    const binding = Object.freeze({
      byteLength: Number(artifact.byteLength),
      chunkCount: Number(artifact.chunkCount),
      familyId: artifact.familyId,
      id: artifact.id,
      inspection: Object.freeze({
        profile: artifact.inspectionProfile,
        resultHash: hashCanonicalJSON(artifact.inspectionResult),
        status: artifact.inspectionStatus,
      }),
      mediaType: artifact.mediaType,
      originalFilename: artifact.originalFilename,
      revision: Number(artifact.revision),
      role: artifact.role,
      sha256: artifact.sha256,
    });
    activities.push(Object.freeze({
      ...activity,
      content: Object.freeze({ ...activity.content, artifact: binding }),
    }));
    bindings.push(Object.freeze({ activityId: activity.id, artifact: binding }));
  }
  const snapshot = Object.freeze({ ...document, activities: Object.freeze(activities) });
  return Object.freeze({ bindings: Object.freeze(bindings), snapshot, snapshotHash: hashCanonicalJSON(snapshot) });
}

export async function persistWorkflowArtifactBindings(client, tenantId, workflowRevisionId, bindings, boundAt) {
  for (const binding of bindings) {
    await client.query(
      `insert into "vasi_engine"."workflow_artifact_binding"
        ("workflowRevisionId", "tenantId", "activityId", "artifactId", "artifactRole",
         "mediaType", "byteLength", "sha256", "boundAt")
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        workflowRevisionId,
        tenantId,
        binding.activityId,
        binding.artifact.id,
        binding.artifact.role,
        binding.artifact.mediaType,
        binding.artifact.byteLength,
        binding.artifact.sha256,
        boundAt,
      ],
    );
  }
}

export async function readArtifactChunk(client, artifactId, sequence) {
  return readChunk(client, artifactId, sequence);
}

export function documentLimits(settings) {
  const maxBytes = boundedSetting(settings.ENGINE_DOCUMENT_MAX_BYTES, 26_214_400, 1_048_576, 268_435_456, "ENGINE_DOCUMENT_MAX_BYTES");
  const chunkBytes = boundedSetting(settings.ENGINE_DOCUMENT_CHUNK_BYTES, 262_144, 65_536, 524_288, "ENGINE_DOCUMENT_CHUNK_BYTES");
  return Object.freeze({ chunkBytes, maxBytes, maxChunks: Math.ceil(maxBytes / chunkBytes) });
}

async function rejectArtifact(client, artifact, code, inspection, profile) {
  const rejectedAt = new Date();
  await client.query(
    `update "vasi_engine"."document_artifact"
     set "status" = 'rejected', "inspectionStatus" = 'rejected', "inspectionProfile" = $3,
         "inspectionResult" = $4, "rejectedAt" = $5
     where "id" = $1 and "tenantId" = $2`,
    [
      artifact.id,
      artifact.tenantId,
      profile || `${inspection.adapter || "vasi"}/${inspection.adapterVersion || "1"}`,
      inspection,
      rejectedAt,
    ],
  );
  return { rejected: code };
}

async function activeExternalScanBinding(client, tenantId) {
  const result = await client.query(
    `select r."adapterId", r."adapterVersion"
     from "vasi_engine"."integration_binding_pointer" p
     join "vasi_engine"."integration_binding_revision" r
       on r."id" = p."activeRevisionId" and r."tenantId" = p."tenantId"
         and r."capability" = p."capability"
     where p."tenantId" = $1 and p."capability" = 'document.malware_scan'
       and r."status" = 'active'`,
    [tenantId],
  );
  if (!result.rowCount) return undefined;
  return Object.freeze({
    adapterId: result.rows[0].adapterId,
    adapterVersion: result.rows[0].adapterVersion,
  });
}

function pipelineInspection(builtIn, external) {
  return Object.freeze({
    adapter: "vasi-document-inspection-pipeline",
    adapterVersion: "2",
    builtIn,
    external: Object.freeze({
      adapter: external.adapter,
      adapterVersion: external.adapterVersion,
      attemptId: external.attemptId,
      bindingRevisionId: external.bindingRevisionId,
      errorCode: external.errorCode,
      responseMetadata: external.responseMetadata || {},
      scanRequestId: external.scanRequestId,
      status: external.outcome === "completed" ? "completed" : "unavailable",
      verdict: external.verdict,
    }),
    passed: external.outcome === "completed" && external.verdict === "clean",
    retryable: external.outcome !== "completed",
  });
}

function boundedScanError(value) {
  return typeof value === "string" && /^[a-z0-9_]{1,64}$/.test(value)
    ? value
    : "integration_gateway_unavailable";
}

async function publishedArtifact(client, tenantId, artifactId) {
  const result = await client.query(
    `select * from "vasi_engine"."document_artifact"
     where "id" = $1 and "tenantId" = $2 and "status" = 'published'`,
    [artifactId, tenantId],
  );
  if (!result.rowCount) notFound();
  return result.rows[0];
}

async function readChunk(client, artifactId, sequence) {
  const result = await client.query(
    `select "sequence", "byteLength", "sha256", "bytes"
     from "vasi_engine"."document_artifact_chunk"
     where "artifactId" = $1 and "sequence" = $2`,
    [artifactId, sequence],
  );
  if (!result.rowCount) notFound();
  return {
    byteLength: Number(result.rows[0].byteLength),
    data: result.rows[0].bytes.toString("base64"),
    sequence: Number(result.rows[0].sequence),
    sha256: result.rows[0].sha256,
  };
}

async function requireArtifactPermission(client, actor, tenantId, permission) {
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

function artifactProjection(row) {
  return {
    byteLength: row.byteLength === null || row.byteLength === undefined ? undefined : Number(row.byteLength),
    chunkCount: row.chunkCount === null || row.chunkCount === undefined ? undefined : Number(row.chunkCount),
    createdAt: new Date(row.createdAt).toISOString(),
    expectedByteLength: Number(row.expectedByteLength),
    familyId: row.familyId,
    id: row.id,
    inspectionProfile: row.inspectionProfile,
    inspectionResult: row.inspectionResult,
    inspectionStatus: row.inspectionStatus,
    mediaType: row.mediaType,
    originalFilename: row.originalFilename,
    publishedAt: row.publishedAt ? new Date(row.publishedAt).toISOString() : undefined,
    rejectedAt: row.rejectedAt ? new Date(row.rejectedAt).toISOString() : undefined,
    replacesArtifactId: row.replacesArtifactId,
    retentionPolicy: row.retentionPolicy,
    revision: Number(row.revision),
    role: row.role,
    sha256: row.sha256,
    sourceArtifactId: row.sourceArtifactId,
    status: row.status,
    tenantId: row.tenantId,
  };
}

function boundedSetting(value, fallback, minimum, maximum, name) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be a whole number between ${minimum} and ${maximum}.`);
  }
  return parsed;
}

function conflict(code) {
  throw new EngineStoreError(code, 409);
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
