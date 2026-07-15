import { randomUUID } from "node:crypto";

import {
  decryptJSONEnvelope,
  hashCanonicalJSON,
} from "../../packages/engine-crypto/index.mjs";
import {
  BUILT_IN_ADAPTERS,
  integrationDestinationAllowed,
  validateInstallationProfile,
  validateIntegrationBindingCommand,
} from "../../packages/engine-domain/productization.mjs";
import { createNotificationDispatcher } from "../worker/notification-adapters.mjs";
import { assertTenantAdmitted } from "../engine/tenant-admission.mjs";
import { scanArtifactWithHTTPS } from "./malware-scanner.mjs";

export function createIntegrationGatewayStore(database, settings, installationId, dependencies = {}) {
  const credentialSecret = required32ByteSecret(
    settings.ENGINE_INTEGRATION_CONFIG_ENCRYPTION_SECRET,
    "ENGINE_INTEGRATION_CONFIG_ENCRYPTION_SECRET",
  );

  return Object.freeze({
    async deliver(command) {
      const requestHash = hashCanonicalJSON(command);
      const client = await database.connect();
      try {
        await client.query("begin");
        await client.query("select pg_advisory_xact_lock(hashtext($1), $2)", [command.jobId, command.attempt]);
        const previous = await client.query(
          `select * from "vasi_engine"."integration_gateway_attempt"
           where "jobId" = $1 and "attempt" = $2`,
          [command.jobId, command.attempt],
        );
        if (previous.rowCount) {
          if (previous.rows[0].requestHash !== requestHash) throw gatewayError("integration_attempt_conflict");
          await client.query("commit");
          return attemptProjection(previous.rows[0]);
        }

        const startedAt = new Date();
        let binding;
        let bindingFailure;
        try {
          await assertNotificationJobCurrent(client, command);
          binding = await loadBinding(client, command, credentialSecret, installationId);
        } catch (error) {
          bindingFailure = error;
          binding = Object.freeze({
            adapterId: "unavailable",
            adapterVersion: "0",
            id: null,
          });
        }
        let delivery;
        if (bindingFailure) {
          delivery = {
            adapter: binding.adapterId,
            errorCode: boundedErrorCode(bindingFailure.code),
            outcome: ["notification_job_obsolete", "tenant_not_admitted"].includes(bindingFailure.code)
              ? "suppressed"
              : "failed",
            responseMetadata: {},
          };
        } else try {
          const dispatch = createNotificationDispatcher(binding, {
            createTransport: dependencies.createTransport,
            fetch: dependencies.fetch,
            participantOrigin: settings.ENGINE_PARTICIPANT_ORIGIN,
          });
          delivery = await dispatch({
            id: command.jobId,
            idempotencyKey: command.idempotencyKey,
            payload: command.payload,
          });
        } catch (error) {
          delivery = {
            adapter: binding.adapterId,
            errorCode: boundedErrorCode(error?.code),
            outcome: "failed",
            responseMetadata: {},
          };
        }
        const completedAt = new Date();
        const responseMetadata = boundedResponseMetadata(delivery.responseMetadata);
        const attempt = {
          adapterId: binding.adapterId,
          adapterVersion: binding.adapterVersion,
          attempt: command.attempt,
          bindingRevisionId: binding.id,
          capability: command.capability,
          completedAt,
          errorCode: delivery.errorCode || null,
          id: randomUUID(),
          idempotencyKey: command.idempotencyKey,
          jobId: command.jobId,
          outcome: delivery.outcome,
          requestHash,
          responseMetadata,
          startedAt,
          tenantId: command.tenantId,
        };
        await client.query(
          `insert into "vasi_engine"."integration_gateway_attempt"
            ("id", "tenantId", "jobId", "attempt", "bindingRevisionId", "capability",
             "adapterId", "adapterVersion", "idempotencyKey", "requestHash", "outcome",
             "errorCode", "responseMetadata", "startedAt", "completedAt")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
          [
            attempt.id, attempt.tenantId, attempt.jobId, attempt.attempt, attempt.bindingRevisionId,
            attempt.capability, attempt.adapterId, attempt.adapterVersion, attempt.idempotencyKey,
            attempt.requestHash, attempt.outcome, attempt.errorCode, attempt.responseMetadata,
            attempt.startedAt, attempt.completedAt,
          ],
        );
        await client.query("commit");
        return attemptProjection(attempt);
      } catch (error) {
        await client.query("rollback").catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    },

    async scan(command) {
      const requestHash = hashCanonicalJSON(command);
      const client = await database.connect();
      try {
        await client.query("begin");
        await client.query("select pg_advisory_xact_lock(hashtext($1))", [command.scanRequestId]);
        const previous = await client.query(
          `select * from "vasi_engine"."document_artifact_scan_attempt"
           where "scanRequestId" = $1`,
          [command.scanRequestId],
        );
        if (previous.rowCount) {
          if (previous.rows[0].requestHash !== requestHash) throw gatewayError("artifact_scan_attempt_conflict");
          await client.query("commit");
          return scanAttemptProjection(previous.rows[0]);
        }

        const artifact = await client.query(
          `select "status", "mediaType", "expectedByteLength"
           from "vasi_engine"."document_artifact"
           where "id" = $1 and "tenantId" = $2`,
          [command.artifactId, command.tenantId],
        );
        if (!artifact.rowCount) throw gatewayError("artifact_scan_source_unavailable");
        const startedAt = new Date();
        let binding;
        let bindingFailure;
        try {
          binding = await loadBinding(client, command, credentialSecret, installationId);
        } catch (error) {
          bindingFailure = error;
          binding = Object.freeze({ adapterId: "unavailable", adapterVersion: "0", id: null });
        }
        let scan;
        const source = artifact.rows[0];
        if (
          source.status !== "quarantined" || source.mediaType !== command.mediaType ||
          Number(source.expectedByteLength) !== command.byteLength
        ) {
          scan = failedScan(binding, "artifact_scan_source_mismatch");
        } else if (bindingFailure) {
          scan = failedScan(binding, bindingFailure.code);
        } else try {
          const scanner = dependencies.scanArtifact || scanArtifactWithHTTPS;
          scan = await scanner(client, binding, command, {
            now: dependencies.now,
            request: dependencies.httpsRequest,
          });
        } catch (error) {
          scan = failedScan(binding, error?.code);
        }
        const completedAt = new Date();
        const attempt = {
          adapterId: binding.adapterId,
          adapterVersion: binding.adapterVersion,
          artifactId: command.artifactId,
          bindingRevisionId: binding.id,
          completedAt,
          errorCode: scan.errorCode || null,
          expectedByteLength: command.byteLength,
          expectedSha256: command.sha256,
          id: randomUUID(),
          outcome: scan.outcome,
          requestHash,
          responseMetadata: boundedScanResponseMetadata(scan.responseMetadata),
          scanRequestId: command.scanRequestId,
          startedAt,
          tenantId: command.tenantId,
          verdict: scan.verdict || null,
        };
        await client.query(
          `insert into "vasi_engine"."document_artifact_scan_attempt"
            ("id", "tenantId", "artifactId", "scanRequestId", "bindingRevisionId",
             "adapterId", "adapterVersion", "requestHash", "expectedSha256",
             "expectedByteLength", "outcome", "verdict", "errorCode", "responseMetadata",
             "startedAt", "completedAt")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
          [
            attempt.id, attempt.tenantId, attempt.artifactId, attempt.scanRequestId,
            attempt.bindingRevisionId, attempt.adapterId, attempt.adapterVersion,
            attempt.requestHash, attempt.expectedSha256, attempt.expectedByteLength,
            attempt.outcome, attempt.verdict, attempt.errorCode, attempt.responseMetadata,
            attempt.startedAt, attempt.completedAt,
          ],
        );
        await client.query("commit");
        return scanAttemptProjection(attempt);
      } catch (error) {
        await client.query("rollback").catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    },
  });
}

export async function assertNotificationJobCurrent(client, command) {
  const result = await client.query(
    `select "jobType", "notificationType", "tenantId", "requestId",
            "participantDataRequestId", "idempotencyKey", "payloadHash", "status", "attempts"
     from "vasi_engine"."outbox_job" where "id" = $1 for share`,
    [command.jobId],
  );
  if (!result.rowCount) throw gatewayError("integration_job_integrity_failure");
  const job = result.rows[0];
  if (
    job.jobType !== "notification" ||
    job.notificationType !== command.payload.eventType ||
    job.tenantId !== command.tenantId ||
    job.idempotencyKey !== command.idempotencyKey ||
    job.payloadHash !== hashCanonicalJSON(command.payload) ||
    job.status !== "running" ||
    Number(job.attempts) !== command.attempt
  ) throw gatewayError("integration_job_integrity_failure");

  if (job.participantDataRequestId) {
    const source = await client.query(
      `select r."status" as "requestStatus", s."status" as "scopeStatus"
       from "vasi_engine"."participant_data_request" r
       join "vasi_engine"."participant_data_request_scope" s
         on s."requestId" = r."id" and s."tenantId" = $2
       where r."id" = $1 for share of r, s`,
      [job.participantDataRequestId, command.tenantId],
    );
    if (!source.rowCount || !participantDataStatusAllows(
      job.notificationType,
      source.rows[0].requestStatus,
      source.rows[0].scopeStatus,
    )) throw gatewayError("notification_job_obsolete");
    return;
  }

  if (job.requestId) {
    const source = await client.query(
      `select "status" from "vasi_engine"."request_instance" where "id" = $1 for share`,
      [job.requestId],
    );
    if (!source.rowCount || !workflowStatusAllows(job.notificationType, source.rows[0].status)) {
      throw gatewayError("notification_job_obsolete");
    }
    return;
  }
  throw gatewayError("integration_job_integrity_failure");
}

function participantDataStatusAllows(notificationType, requestStatus, scopeStatus) {
  if (notificationType === "participant_data.ready") {
    return requestStatus === "ready" && scopeStatus === "approved";
  }
  if (notificationType === "participant_data.denied") {
    return ["ready", "denied"].includes(requestStatus) && scopeStatus === "denied";
  }
  if (notificationType === "participant_data.preparation_failed") {
    return requestStatus === "preparation_failed" && scopeStatus === "approved";
  }
  if (notificationType === "participant_data.expired") {
    return requestStatus === "expired" && scopeStatus === "approved";
  }
  return false;
}

function workflowStatusAllows(notificationType, requestStatus) {
  if (["request.issued", "request.reminder"].includes(notificationType)) {
    return ["scheduled", "issued", "in_progress"].includes(requestStatus);
  }
  if (notificationType === "request.completed") return requestStatus === "completed";
  return !["expired", "revoked"].includes(requestStatus);
}

async function loadBinding(client, command, credentialSecret, installationId) {
  await assertTenantAdmitted(client, command.tenantId, { lock: true });
  const selected = await client.query(
    `select r.*, a."manifest", a."manifestHash", a."conformanceStatus"
     from "vasi_engine"."integration_binding_pointer" p
     join "vasi_engine"."integration_binding_revision" r
       on r."id" = p."activeRevisionId" and r."tenantId" = p."tenantId"
         and r."capability" = p."capability"
     join "vasi_engine"."integration_adapter_registry" a
       on a."adapterId" = r."adapterId" and a."adapterVersion" = r."adapterVersion"
     where p."tenantId" = $1 and p."capability" = $2`,
    [command.tenantId, command.capability],
  );
  if (!selected.rowCount) throw gatewayError("integration_binding_unavailable");
  const row = selected.rows[0];
  const knownAdapter = BUILT_IN_ADAPTERS.find(
    (adapter) => adapter.id === row.adapterId && adapter.version === row.adapterVersion,
  );
  if (
    !knownAdapter || row.conformanceStatus !== "built_in_verified" ||
    hashCanonicalJSON(row.manifest) !== row.manifestHash ||
    hashCanonicalJSON(knownAdapter) !== row.manifestHash ||
    hashCanonicalJSON(row.config) !== row.configHash
  ) {
    throw gatewayError("integration_binding_integrity_failure");
  }
  const credentials = decryptJSONEnvelope(row.credentialEnvelope, credentialSecret);
  const normalized = validateIntegrationBindingCommand({
    adapterId: row.adapterId,
    capability: row.capability,
    config: row.config,
    credentials,
    expectedRevision: Number(row.revision),
    status: row.status,
    tenantId: row.tenantId,
  });
  const installation = await client.query(
    `select r."profile", r."profileHash"
     from "vasi_engine"."installation_profile_pointer" p
     join "vasi_engine"."installation_profile_revision" r
       on r."id" = p."activeRevisionId" and r."installationId" = p."installationId"
     where p."installationId" = $1`,
    [installationId],
  );
  if (!installation.rowCount) throw gatewayError("installation_profile_unavailable");
  const profile = validateInstallationProfile(installation.rows[0].profile);
  if (hashCanonicalJSON(profile) !== installation.rows[0].profileHash) {
    throw gatewayError("installation_profile_integrity_failure");
  }
  assertDestinationAllowed(profile, normalized);
  return Object.freeze({
    ...normalized,
    adapterVersion: row.adapterVersion,
    id: row.id,
  });
}

function assertDestinationAllowed(profile, binding) {
  if (binding.status !== "active" || binding.adapterId === "disabled") return;
  if (!profile.adapters.allow.includes(binding.adapterId)) throw gatewayError("integration_adapter_not_allowed");
  if (!integrationDestinationAllowed(profile, binding)) throw gatewayError("integration_destination_not_allowed");
}

function attemptProjection(row) {
  return Object.freeze({
    adapter: row.adapterId,
    adapterVersion: row.adapterVersion,
    attempt: Number(row.attempt),
    bindingRevisionId: row.bindingRevisionId,
    errorCode: row.errorCode || undefined,
    outcome: row.outcome,
    responseMetadata: row.responseMetadata || {},
  });
}

function scanAttemptProjection(row) {
  return Object.freeze({
    adapter: row.adapterId,
    adapterVersion: row.adapterVersion,
    attemptId: row.id,
    bindingRevisionId: row.bindingRevisionId || undefined,
    errorCode: row.errorCode || undefined,
    outcome: row.outcome,
    responseMetadata: row.responseMetadata || {},
    scanRequestId: row.scanRequestId,
    verdict: row.verdict || undefined,
  });
}

function boundedResponseMetadata(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") return {};
  const result = {};
  if (Number.isSafeInteger(value.status) && value.status >= 100 && value.status <= 599) {
    result.status = value.status;
  }
  if (typeof value.messageId === "string") {
    result.messageId = value.messageId.replace(/[^\x20-\x7e]/g, "").slice(0, 512);
  }
  return Object.freeze(result);
}

function boundedScanResponseMetadata(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") return Object.freeze({});
  const allowed = ["reasonCode", "scanner", "scannerVersion", "signatureSet"];
  const result = {};
  for (const key of allowed) {
    if (typeof value[key] !== "string") continue;
    const normalized = value[key].normalize("NFC").trim();
    const maximum = key === "signatureSet" ? 160 : key === "reasonCode" ? 64 : 80;
    if (normalized && normalized.length <= maximum && !/[\u0000-\u001f\u007f]/.test(normalized)) {
      result[key] = normalized;
    }
  }
  return Object.freeze(result);
}

function failedScan(binding, code) {
  return Object.freeze({
    adapter: binding.adapterId,
    errorCode: boundedErrorCode(code, "scan_failed"),
    outcome: "failed",
    responseMetadata: {},
  });
}

function boundedErrorCode(value, fallback = "delivery_failed") {
  return typeof value === "string" && /^[a-z0-9_]{1,64}$/.test(value)
    ? value
    : fallback;
}

function required32ByteSecret(value, name) {
  if (
    typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value) ||
    Buffer.from(value, "base64url").length !== 32
  ) {
    throw new Error(`${name} must contain 32 bytes.`);
  }
  return value;
}

function gatewayError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
