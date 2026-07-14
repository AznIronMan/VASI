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
            outcome: "failed",
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
  });
}

async function loadBinding(client, command, credentialSecret, installationId) {
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

function boundedErrorCode(value) {
  return typeof value === "string" && /^[a-z0-9_]{1,64}$/.test(value)
    ? value
    : "delivery_failed";
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
