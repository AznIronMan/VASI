import { createHash, randomUUID } from "node:crypto";

import { buildEvidenceBundle } from "../../packages/evidence-bundle/index.mjs";
import {
  buildEvidenceReports,
  evidenceReportMediaType,
  renderEvidenceReport,
} from "../../packages/evidence-reporting/index.mjs";
import {
  sha256Hex,
  verifyCertificateSeal,
  verifyDetachedIntegritySeal,
} from "../../packages/engine-crypto/index.mjs";
import { hasTenantPermission } from "../../packages/engine-domain/workflow.mjs";
import { assertEvidenceRecord } from "../../packages/evidence-verifier/index.mjs";
import { EngineStoreError } from "./errors.mjs";
import { loadEvidenceRecord } from "./evidence-store.mjs";
import { assertLifecycleHistoryAvailable } from "./lifecycle-store.mjs";
import { createSigningProvider } from "./signing-provider.mjs";

const GENERATOR_VERSION = "vasi-evidence-export/1";
const TEMPLATE_VERSION = "vasi-evidence-report/1";

export function createReportStore(database, settings) {
  const signingProvider = createSigningProvider(settings);
  const chunkBytes = boundedSetting(
    settings.ENGINE_EXPORT_CHUNK_BYTES,
    262_144,
    65_536,
    524_288,
    "ENGINE_EXPORT_CHUNK_BYTES",
  );
  const maxBytes = boundedSetting(
    settings.ENGINE_EXPORT_MAX_BYTES,
    67_108_864,
    1_048_576,
    536_870_912,
    "ENGINE_EXPORT_MAX_BYTES",
  );

  return Object.freeze({
    async openOwnerExport(actor, payload) {
      requireActor(actor);
      const input = exportInput(payload);
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "record.read");
        await requireAssignment(client, input.tenantId, input.assignmentId);
        return openExport(client, {
          accessType: input.kind === "bundle" ? "owner_bundle_export" : "owner_report_export",
          actor,
          input,
          maxBytes,
          chunkBytes,
          signingProvider,
        });
      });
    },

    async openParticipantReport(actor, payload) {
      requireParticipant(actor);
      return transaction(database, async (client) => {
        const assignment = payload?.assignmentId
          ? await participantAssignmentById(client, token(payload.assignmentId, "assignmentId"), actor)
          : await participantAssignment(client, digestHandle(payload?.handle), actor);
        await assertLifecycleHistoryAvailable(client, assignment.assignmentId, new Date());
        const input = Object.freeze({
          assignmentId: assignment.assignmentId,
          format: reportFormat(payload?.format),
          kind: "report",
          profile: "participant",
          tenantId: assignment.tenantId,
        });
        return openExport(client, {
          accessType: "participant_report_export",
          actor,
          input,
          maxBytes,
          chunkBytes,
          signingProvider,
        });
      });
    },

    async readOwnerExportChunk(actor, payload) {
      requireActor(actor);
      return readChunk(database, actor, payload, "owner");
    },

    async readParticipantExportChunk(actor, payload) {
      requireParticipant(actor);
      return readChunk(database, actor, payload, "participant");
    },

    async verifyFingerprint(actor, payload) {
      requireVerificationActor(actor);
      const fingerprint = manifestFingerprint(payload?.fingerprint);
      return transaction(database, async (client) => {
        const result = await client.query(
          `select "assignmentId" from "vasi_engine"."evidence_manifest"
           where "manifestHash" = $1 limit 1`,
          [fingerprint],
        );
        if (!result.rowCount) {
          const tombstoneResult = await client.query(
            `select "tombstone", "seal", "purgedAt"
             from "vasi_engine"."retention_purge_tombstone" where "manifestHash" = $1`,
            [fingerprint],
          );
          if (tombstoneResult.rowCount) {
            const tombstone = tombstoneResult.rows[0];
            const seals = Array.isArray(tombstone.seal) ? tombstone.seal : [];
            const sealResults = seals.map((seal) => ({
              algorithm: seal.algorithm,
              keyId: seal.keyId,
              profile: seal.profile,
              role: seal.role,
              verified: seal.profile === "vasi-certificate-seal/v1"
                ? verifyCertificateSeal(tombstone.tombstone, seal)
                : verifyDetachedIntegritySeal(
                  tombstone.tombstone,
                  seal,
                  ["vasi-retention-tombstone/v1"],
                ),
            }));
            await recordAccess(client, {
              actor,
              accessType: "public_verification",
              manifestHash: fingerprint,
              metadata: { known: true, lookup: "retention_tombstone", retired: true },
            });
            return {
              fingerprint,
              known: true,
              purgedAt: new Date(tombstone.purgedAt).toISOString(),
              retired: true,
              schema: "vasi-public-verification/v1",
              seals: sealResults,
              verified: sealResults.length > 0 && sealResults.every((seal) => seal.verified),
            };
          }
          await recordAccess(client, {
            actor,
            accessType: "public_verification",
            manifestHash: fingerprint,
            metadata: { known: false, lookup: "exact_manifest_fingerprint" },
          });
          return verificationProjection(fingerprint);
        }
        const record = await loadEvidenceRecord(client, result.rows[0].assignmentId, signingProvider);
        const verification = assertEvidenceRecord(record);
        await recordAccess(client, {
          actor,
          accessType: "public_verification",
          assignmentId: record.manifest.assignment.id,
          manifestHash: fingerprint,
          metadata: { known: true, lookup: "exact_manifest_fingerprint" },
          requestId: record.manifest.request.id,
          tenantId: record.manifest.tenant.id,
        });
        return verificationProjection(fingerprint, record, verification);
      });
    },
  });
}

async function openExport(client, {
  accessType,
  actor,
  chunkBytes,
  input,
  maxBytes,
  signingProvider,
}) {
  const record = await loadEvidenceRecord(client, input.assignmentId, signingProvider);
  if (record.manifest.tenant.id !== input.tenantId) notFound();
  const sourceManifestHash = record.seal.manifestHash;
  const existing = await findExport(client, input, sourceManifestHash);
  let artifact = existing;
  if (!artifact) {
    await client.query("select pg_advisory_xact_lock(hashtext($1))", [
      [input.assignmentId, sourceManifestHash, input.kind, input.profile, input.format].join(":"),
    ]);
    artifact = await findExport(client, input, sourceManifestHash);
  }
  if (!artifact) {
    const generated = input.kind === "bundle"
      ? await generateBundle(client, record, signingProvider)
      : generateReport(record, input.profile, input.format);
    if (!generated.bytes.length || generated.bytes.length > maxBytes) {
      throw new EngineStoreError("evidence_export_too_large", 413);
    }
    artifact = await persistExport(client, {
      actor,
      bytes: generated.bytes,
      chunkBytes,
      filename: exportFilename(input.assignmentId, input.kind, input.profile, input.format),
      input,
      mediaType: generated.mediaType,
      provenance: generated.provenance,
      record,
      sourceManifestHash,
    });
  }
  await recordAccess(client, {
    accessType,
    actor,
    assignmentId: input.assignmentId,
    exportArtifactId: artifact.id,
    manifestHash: sourceManifestHash,
    metadata: { format: input.format, kind: input.kind, profile: input.profile },
    requestId: record.manifest.request.id,
    tenantId: input.tenantId,
  });
  return exportProjection(artifact);
}

function generateReport(record, profile, format) {
  const reports = buildEvidenceReports(record);
  const report = reports[profile];
  if (!report) throw new EngineStoreError("invalid_evidence_report_profile", 400);
  return Object.freeze({
    bytes: renderEvidenceReport(report, format),
    mediaType: evidenceReportMediaType(format),
    provenance: {
      deterministic: true,
      eventCount: record.events.length,
      generator: GENERATOR_VERSION,
      reportSchema: report.schema,
      template: TEMPLATE_VERSION,
    },
  });
}

async function generateBundle(client, record, signingProvider) {
  const artifacts = await loadAuthoritativeArtifacts(client, record);
  const bundle = buildEvidenceBundle({
    artifacts,
    record,
    signIndex: (index) => signingProvider.signBundleIndex(index),
  });
  return Object.freeze({
    bytes: bundle.bytes,
    mediaType: "application/zip",
    provenance: {
      artifactCount: artifacts.length,
      bundleRootHash: bundle.index.rootHash,
      deterministic: true,
      generator: GENERATOR_VERSION,
      schema: bundle.index.schema,
      template: TEMPLATE_VERSION,
    },
  });
}

async function loadAuthoritativeArtifacts(client, record) {
  const result = await client.query(
    `select distinct d."id", d."revision", d."role", d."originalFilename", d."mediaType",
            d."byteLength", d."chunkCount", d."sha256", d."inspectionProfile", d."inspectionResult"
     from "vasi_engine"."workflow_artifact_binding" b
     join "vasi_engine"."document_artifact" d on d."id" = b."artifactId"
     where b."workflowRevisionId" = $1 and b."tenantId" = $2 and d."status" = 'published'
     order by d."id"`,
    [record.manifest.workflow.id, record.manifest.tenant.id],
  );
  const artifacts = [];
  for (const artifact of result.rows) {
    const chunks = await client.query(
      `select "sequence", "bytes", "sha256", "byteLength"
       from "vasi_engine"."document_artifact_chunk"
       where "artifactId" = $1 order by "sequence"`,
      [artifact.id],
    );
    if (chunks.rowCount !== Number(artifact.chunkCount)) integrityFailure();
    for (const [sequence, chunk] of chunks.rows.entries()) {
      if (
        Number(chunk.sequence) !== sequence || Number(chunk.byteLength) !== chunk.bytes.length ||
        sha256Hex(chunk.bytes) !== chunk.sha256
      ) integrityFailure();
    }
    const bytes = Buffer.concat(chunks.rows.map((chunk) => chunk.bytes));
    if (bytes.length !== Number(artifact.byteLength) || sha256Hex(bytes) !== artifact.sha256) {
      integrityFailure();
    }
    artifacts.push({ ...artifact, bytes, revision: Number(artifact.revision) });
  }
  return artifacts;
}

async function persistExport(client, {
  actor,
  bytes,
  chunkBytes,
  filename,
  input,
  mediaType,
  provenance,
  record,
  sourceManifestHash,
}) {
  const id = randomUUID();
  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += chunkBytes) {
    chunks.push(bytes.subarray(offset, Math.min(bytes.length, offset + chunkBytes)));
  }
  const createdAt = new Date();
  await client.query(
    `insert into "vasi_engine"."evidence_export_artifact"
      ("id", "tenantId", "requestId", "assignmentId", "kind", "profile", "format",
       "mediaType", "filename", "byteLength", "chunkCount", "sha256", "sourceManifestHash",
       "generatorVersion", "templateVersion", "provenance", "createdByPrincipalId", "createdAt")
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
    [
      id,
      input.tenantId,
      record.manifest.request.id,
      input.assignmentId,
      input.kind,
      input.profile,
      input.format,
      mediaType,
      filename,
      bytes.length,
      chunks.length,
      sha256Hex(bytes),
      sourceManifestHash,
      GENERATOR_VERSION,
      TEMPLATE_VERSION,
      provenance,
      actor.principalId,
      createdAt,
    ],
  );
  for (const [sequence, chunk] of chunks.entries()) {
    await client.query(
      `insert into "vasi_engine"."evidence_export_chunk"
        ("exportArtifactId", "sequence", "byteLength", "sha256", "bytes")
       values ($1, $2, $3, $4, $5)`,
      [id, sequence, chunk.length, sha256Hex(chunk), chunk],
    );
  }
  return {
    byteLength: bytes.length,
    chunkCount: chunks.length,
    filename,
    format: input.format,
    id,
    kind: input.kind,
    mediaType,
    profile: input.profile,
    sha256: sha256Hex(bytes),
    sourceManifestHash,
  };
}

async function findExport(client, input, sourceManifestHash) {
  const result = await client.query(
    `select "id", "kind", "profile", "format", "mediaType", "filename", "byteLength",
            "chunkCount", "sha256", "sourceManifestHash"
     from "vasi_engine"."evidence_export_artifact"
     where "assignmentId" = $1 and "sourceManifestHash" = $2 and "kind" = $3
       and "profile" = $4 and "format" = $5 and "generatorVersion" = $6
       and "templateVersion" = $7`,
    [
      input.assignmentId,
      sourceManifestHash,
      input.kind,
      input.profile,
      input.format,
      GENERATOR_VERSION,
      TEMPLATE_VERSION,
    ],
  );
  return result.rows[0];
}

async function readChunk(database, actor, payload, audience) {
  const exportArtifactId = token(payload?.exportArtifactId, "exportArtifactId");
  const sequence = integer(payload?.sequence, "sequence", 0, 100_000);
  const client = await database.connect();
  try {
    const artifactResult = await client.query(
      `select e."tenantId", e."assignmentId", e."kind", e."profile", e."chunkCount",
              a."principalId", a."intendedEmail"
       from "vasi_engine"."evidence_export_artifact" e
       join "vasi_engine"."participant_assignment" a on a."id" = e."assignmentId"
       where e."id" = $1`,
      [exportArtifactId],
    );
    if (!artifactResult.rowCount) notFound();
    const artifact = artifactResult.rows[0];
    if (sequence >= Number(artifact.chunkCount)) notFound();
    if (audience === "owner") {
      await requirePermission(client, actor, artifact.tenantId, "record.read");
    } else if (
      artifact.kind !== "report" || artifact.profile !== "participant" ||
      artifact.principalId !== actor.principalId || artifact.intendedEmail.toLowerCase() !== actor.email
    ) notFound();
    if (audience === "participant") {
      await assertLifecycleHistoryAvailable(client, artifact.assignmentId, new Date());
    }
    const result = await client.query(
      `select "sequence", "byteLength", "sha256", "bytes"
       from "vasi_engine"."evidence_export_chunk"
       where "exportArtifactId" = $1 and "sequence" = $2`,
      [exportArtifactId, sequence],
    );
    if (!result.rowCount) notFound();
    const chunk = result.rows[0];
    if (Number(chunk.byteLength) !== chunk.bytes.length || sha256Hex(chunk.bytes) !== chunk.sha256) {
      integrityFailure();
    }
    return {
      byteLength: Number(chunk.byteLength),
      data: chunk.bytes.toString("base64"),
      sequence: Number(chunk.sequence),
      sha256: chunk.sha256,
    };
  } finally {
    client.release();
  }
}

async function recordAccess(client, entry) {
  await client.query(
    `insert into "vasi_engine"."evidence_access_event"
      ("id", "tenantId", "requestId", "assignmentId", "manifestHash", "exportArtifactId",
       "actorPrincipalId", "accessType", "metadata")
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      randomUUID(),
      entry.tenantId || null,
      entry.requestId || null,
      entry.assignmentId || null,
      entry.manifestHash || null,
      entry.exportArtifactId || null,
      entry.actor.principalId,
      entry.accessType,
      entry.metadata,
    ],
  );
}

function exportInput(payload) {
  const kind = payload?.kind;
  if (!['report', 'bundle'].includes(kind)) throw new EngineStoreError("invalid_evidence_export_kind", 400);
  const profile = kind === "bundle" ? "full" : payload?.profile;
  if (kind === "report" && !['participant', 'nontechnical', 'technical', 'structured'].includes(profile)) {
    throw new EngineStoreError("invalid_evidence_report_profile", 400);
  }
  const format = kind === "bundle" ? "zip" : reportFormat(payload?.format);
  return Object.freeze({
    assignmentId: token(payload?.assignmentId, "assignmentId"),
    format,
    kind,
    profile,
    tenantId: token(payload?.tenantId, "tenantId"),
  });
}

function reportFormat(value) {
  if (!['json', 'text', 'html'].includes(value)) {
    throw new EngineStoreError("invalid_evidence_report_format", 400);
  }
  return value;
}

function exportFilename(assignmentId, kind, profile, format) {
  const extension = format === "text" ? "txt" : format;
  return `vasi-${kind}-${profile}-${assignmentId}.${extension}`;
}

function exportProjection(row) {
  return {
    byteLength: Number(row.byteLength),
    chunkCount: Number(row.chunkCount),
    filename: row.filename,
    format: row.format,
    id: row.id,
    kind: row.kind,
    mediaType: row.mediaType,
    profile: row.profile,
    sha256: row.sha256,
    sourceManifestHash: row.sourceManifestHash,
  };
}

function verificationProjection(fingerprint, record, verification) {
  if (!record) return {
    fingerprint,
    known: false,
    schema: "vasi-public-verification/v1",
  };
  return {
    completedAt: record.manifest.timestamps.completedAt,
    eventCount: record.events.length,
    fingerprint,
    known: true,
    schema: "vasi-public-verification/v1",
    seals: verification.seals.map((seal) => ({
      algorithm: seal.algorithm,
      keyId: seal.keyId,
      profile: seal.profile,
      role: seal.role,
      verified: seal.verified,
    })),
    verified: verification.verified,
  };
}

async function requireAssignment(client, tenantId, assignmentId) {
  const result = await client.query(
    `select 1 from "vasi_engine"."participant_assignment" where "id" = $1 and "tenantId" = $2`,
    [assignmentId, tenantId],
  );
  if (!result.rowCount) notFound();
}

async function participantAssignment(client, handleDigest, actor) {
  const result = await client.query(
    `select "id" as "assignmentId", "tenantId", "principalId", "intendedEmail", "status"
     from "vasi_engine"."participant_assignment" where "handleDigest" = $1`,
    [handleDigest],
  );
  if (!result.rowCount) notFound();
  const row = result.rows[0];
  if (
    row.status !== "completed" || row.principalId !== actor.principalId ||
    row.intendedEmail.toLowerCase() !== actor.email
  ) notFound();
  return row;
}

async function participantAssignmentById(client, assignmentId, actor) {
  const result = await client.query(
    `select "id" as "assignmentId", "tenantId", "principalId", "intendedEmail", "status"
     from "vasi_engine"."participant_assignment" where "id" = $1`,
    [assignmentId],
  );
  if (!result.rowCount) notFound();
  const row = result.rows[0];
  if (
    row.status !== "completed" || row.principalId !== actor.principalId ||
    row.intendedEmail.toLowerCase() !== actor.email
  ) notFound();
  return row;
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

function digestHandle(value) {
  const handle = token(value, "handle", 64);
  if (!/^[A-Za-z0-9_-]{43}$/.test(handle)) notFound();
  return createHash("sha256").update(handle, "utf8").digest();
}

function manifestFingerprint(value) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new EngineStoreError("invalid_manifest_fingerprint", 400);
  }
  return value;
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

function requireVerificationActor(actor) {
  requireActor(actor);
  if (!actor.roles.includes("verification")) throw new EngineStoreError("forbidden", 403);
}

function notFound() {
  throw new EngineStoreError("not_found", 404);
}

function integrityFailure() {
  throw new EngineStoreError("integrity_check_failed", 500);
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
