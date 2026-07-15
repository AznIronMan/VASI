import { createHmac, randomUUID } from "node:crypto";

import {
  canonicalJSON,
  encryptJSONEnvelope,
  hashCanonicalJSON,
} from "../../packages/engine-crypto/index.mjs";
import {
  applyTenantAdmissionDecision,
  BUILT_IN_ADAPTERS,
  defaultInstallationProfile,
  defaultTenantAdmission,
  defaultTenantProfile,
  integrationDestinationAllowed,
  validateInstallationProfile,
  validateInstallationProfileCommand,
  validateIntegrationBindingCommand,
  validateTenantAdmission,
  validateTenantAdmissionDecisionCommand,
  validateTenantProductionStopCommand,
  validateTenantProfile,
  validateTenantProfileCommand,
  validateTenantProvisionInput,
  validateTenantReference,
} from "../../packages/engine-domain/productization.mjs";
import { hasTenantPermission, permissionsForRoles } from "../../packages/engine-domain/workflow.mjs";
import { appendEvent } from "./evidence-events.mjs";
import { EngineStoreError } from "./errors.mjs";
import { activeTenantProfile, assertTenantCapacity, tenantUsage } from "./tenant-policy.mjs";
import {
  activeTenantAdmission,
  assertTenantAdmitted,
  tenantAdmissionProjection,
} from "./tenant-admission.mjs";

const GENESIS_HASH = "0".repeat(64);

export function createProductStore(database, settings, installationId) {
  const credentialSecret = requiredSetting(settings, "ENGINE_INTEGRATION_CONFIG_ENCRYPTION_SECRET");

  return Object.freeze({
    async initialize() {
      return transaction(database, async (client) => {
        await registerAdapters(client);
        await ensureInstallationProfile(client, installationId, settings);
        const tenants = await client.query(
          `select t."id", t."name" from "vasi_engine"."tenant" t
           left join "vasi_engine"."tenant_profile_pointer" p on p."tenantId" = t."id"
           where p."tenantId" is null order by t."id" for update of t`,
        );
        for (const tenant of tenants.rows) {
          await createTenantProfile(client, tenant.id, defaultTenantProfile(tenant.name), "vasi-migration");
          await ensureInitialIntegrations(client, tenant.id, credentialSecret, "vasi-migration", {
            migrateLegacy: false,
          });
          await appendConfigurationEvent(client, {
            actorPrincipalId: "vasi-migration",
            eventData: { migrated: true },
            eventType: "tenant.provisioned",
            scopeId: tenant.id,
            scopeType: "tenant",
            tenantId: tenant.id,
          });
          await ensureTenantAdmission(client, tenant.id, "vasi-migration");
        }
        const existingTenants = await client.query(
          `select t."id" from "vasi_engine"."tenant" t order by t."id" for update of t`,
        );
        for (const tenant of existingTenants.rows) {
          await ensureTenantAdmission(client, tenant.id, "vasi-migration");
          await ensureInitialIntegrations(client, tenant.id, credentialSecret, "vasi-migration", {
            migrateLegacy: false,
          });
        }
        await client.query(
          `update "vasi_engine"."request_instance" r
           set "tenantProfileRevisionId" = p."activeRevisionId",
               "tenantProfileSnapshot" = rev."profile", "tenantProfileHash" = rev."profileHash",
               "tenantProfileBindingProvenance" = 'migration_default'
           from "vasi_engine"."tenant_profile_pointer" p
           join "vasi_engine"."tenant_profile_revision" rev on rev."id" = p."activeRevisionId"
           where r."tenantId" = p."tenantId" and r."tenantProfileRevisionId" is null`,
        );
      });
    },

    async provisionTenant(actor, payload) {
      requireAdministrator(actor);
      const input = validateTenantProvisionInput(payload);
      return transaction(database, async (client) => {
        const inputHash = tenantProvisionInputHash(input, actor);
        if (input.commandId) {
          await client.query(
            `select pg_advisory_xact_lock(hashtextextended($1, 0))`,
            [`vasi:tenant-provision:${input.commandId}`],
          );
          const replay = await client.query(
            `select "actorPrincipalId", "inputHash", "result", "resultHash"
             from "vasi_engine"."tenant_provision_command" where "commandId" = $1`,
            [input.commandId],
          );
          if (replay.rowCount) {
            const row = replay.rows[0];
            if (row.actorPrincipalId !== actor.principalId || row.inputHash !== inputHash) {
              throw new EngineStoreError("tenant_provision_command_conflict", 409);
            }
            return validateTenantProvisionResult(row.result, row.resultHash, input, actor);
          }
        }
        const installation = await activeInstallationProfile(client, installationId, true);
        const tenantCount = await client.query(
          `select count(*)::integer as "count" from "vasi_engine"."tenant" where "status" = 'active'`,
        );
        if (Number(tenantCount.rows[0].count) >= installation.profile.provisioning.maxTenants) {
          throw new EngineStoreError("installation_tenant_quota_exceeded", 409);
        }
        const tenantId = randomUUID();
        try {
          await client.query(
            `insert into "vasi_engine"."tenant" ("id", "slug", "name") values ($1, $2, $3)`,
            [tenantId, input.slug, input.name],
          );
        } catch (error) {
          if (error?.code === "23505") throw new EngineStoreError("tenant_slug_exists", 409);
          throw error;
        }
        await client.query(
          `insert into "vasi_engine"."tenant_membership"
            ("tenantId", "principalId", "roles", "email", "source")
           values ($1, $2, '{owner}', $3, 'installation_provisioning')`,
          [tenantId, actor.principalId, actor.email || null],
        );
        const ownerGrantCreated = Boolean(
          input.ownerEmail && input.ownerEmail !== actor.email?.toLowerCase(),
        );
        if (ownerGrantCreated) {
          await client.query(
            `insert into "vasi_engine"."tenant_membership_grant"
              ("id", "tenantId", "email", "roles", "status", "createdByPrincipalId")
             values ($1, $2, $3, '{owner}', 'active', $4)`,
            [randomUUID(), tenantId, input.ownerEmail, actor.principalId],
          );
        }
        const profile = await createTenantProfile(client, tenantId, input.profile, actor.principalId);
        await ensureInitialIntegrations(client, tenantId, credentialSecret, actor.principalId);
        await appendConfigurationEvent(client, {
          actorPrincipalId: actor.principalId,
          eventData: {
            ownerGrantCreated,
            profileHash: profile.profileHash,
            profileRevision: profile.revision,
            slug: input.slug,
          },
          eventType: "tenant.provisioned",
          scopeId: tenantId,
          scopeType: "tenant",
          tenantId,
        });
        const admission = await ensureTenantAdmission(client, tenantId, actor.principalId);
        const result = {
          admission,
          id: tenantId,
          name: input.name,
          owner: {
            email: input.ownerEmail || actor.email?.toLowerCase() || null,
            grantCreated: ownerGrantCreated,
          },
          permissions: permissionsForRoles(["owner"]),
          profile,
          roles: ["owner"],
          slug: input.slug,
        };
        if (input.commandId) {
          const resultHash = hashCanonicalJSON(result);
          await client.query(
            `insert into "vasi_engine"."tenant_provision_command"
              ("commandId", "actorPrincipalId", "inputHash", "result", "resultHash")
             values ($1, $2, $3, $4, $5)`,
            [input.commandId, actor.principalId, inputHash, result, resultHash],
          );
        }
        return result;
      });
    },

    async getTenantProfile(actor, payload) {
      const { tenantId } = validateTenantReference(payload, "tenant profile read");
      const client = await database.connect();
      try {
        await requirePermission(client, actor, tenantId, "quota.read");
        return activeTenantProfile(client, tenantId);
      } finally {
        client.release();
      }
    },

    async updateTenantProfile(actor, payload) {
      const input = validateTenantProfileCommand(payload);
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "tenant.configure");
        const current = await activeTenantProfile(client, input.tenantId, { lock: true });
        if (current.revision !== input.expectedRevision) {
          throw new EngineStoreError("tenant_profile_revision_conflict", 409);
        }
        if (!actor.roles.includes("admin") && hashCanonicalJSON(current.profile.quotas) !== hashCanonicalJSON(input.profile.quotas)) {
          throw new EngineStoreError("tenant_quota_changes_require_administrator", 403);
        }
        if (input.profile.policies.defaultRetentionProfile !== "tenant_default") {
          const retention = await client.query(
            `select 1 from "vasi_engine"."retention_policy_pointer"
             where "tenantId" = $1 and "name" = $2`,
            [input.tenantId, input.profile.policies.defaultRetentionProfile],
          );
          if (!retention.rowCount) throw new EngineStoreError("retention_profile_not_found", 409);
        }
        const next = await createTenantProfileRevision(
          client,
          input.tenantId,
          input.profile,
          current.revision + 1,
          actor.principalId,
        );
        const updated = await client.query(
          `update "vasi_engine"."tenant_profile_pointer"
           set "activeRevisionId" = $3, "revision" = $4,
               "updatedByPrincipalId" = $5, "updatedAt" = CURRENT_TIMESTAMP
           where "tenantId" = $1 and "revision" = $2 returning "tenantId"`,
          [input.tenantId, input.expectedRevision, next.id, next.revision, actor.principalId],
        );
        if (!updated.rowCount) throw new EngineStoreError("tenant_profile_revision_conflict", 409);
        await appendConfigurationEvent(client, {
          actorPrincipalId: actor.principalId,
          eventData: { profileHash: next.profileHash, revision: next.revision },
          eventType: "tenant.profile.updated",
          scopeId: input.tenantId,
          scopeType: "tenant",
          tenantId: input.tenantId,
        });
        return next;
      });
    },

    async getTenantUsage(actor, payload) {
      const { tenantId } = validateTenantReference(payload, "tenant quota read");
      const client = await database.connect();
      try {
        await requirePermission(client, actor, tenantId, "quota.read");
        return tenantUsage(client, tenantId);
      } finally {
        client.release();
      }
    },

    async listIntegrations(actor, payload) {
      const { tenantId } = validateTenantReference(payload, "integration list");
      const client = await database.connect();
      try {
        await requirePermission(client, actor, tenantId, "integration.manage");
        const result = await client.query(
          `select r."id", r."capability", r."revision", r."adapterId", r."adapterVersion",
                  r."status", r."config", r."configHash", r."credentialFingerprint", r."createdAt"
           from "vasi_engine"."integration_binding_pointer" p
           join "vasi_engine"."integration_binding_revision" r
             on r."id" = p."activeRevisionId" and r."tenantId" = p."tenantId"
               and r."capability" = p."capability"
           where p."tenantId" = $1 order by r."capability"`,
          [tenantId],
        );
        return result.rows.map(integrationProjection);
      } finally {
        client.release();
      }
    },

    async updateIntegration(actor, payload) {
      const input = validateIntegrationBindingCommand(payload);
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "integration.manage");
        if (input.status === "active") {
          await assertTenantAdmitted(client, input.tenantId, { lock: true });
        }
        const installation = await activeInstallationProfile(client, installationId, false);
        if (input.status === "active" && !installation.profile.adapters.allow.includes(input.adapterId)) {
          throw new EngineStoreError("integration_adapter_not_allowed", 403);
        }
        assertAdapterDestinationAllowed(installation.profile, input);
        const pointer = await client.query(
          `select p."revision", r."status"
           from "vasi_engine"."integration_binding_pointer" p
           join "vasi_engine"."integration_binding_revision" r
             on r."id" = p."activeRevisionId" and r."tenantId" = p."tenantId"
               and r."capability" = p."capability"
           where p."tenantId" = $1 and p."capability" = $2 for update of p`,
          [input.tenantId, input.capability],
        );
        const currentRevision = Number(pointer.rows[0]?.revision || 0);
        if (currentRevision !== input.expectedRevision) {
          throw new EngineStoreError("integration_revision_conflict", 409);
        }
        if (input.status === "active" && pointer.rows[0]?.status !== "active") {
          await assertTenantCapacity(client, input.tenantId, "integrations", 1);
        }
        const nextRevision = currentRevision + 1;
        const id = randomUUID();
        const configHash = hashCanonicalJSON(input.config);
        const credentialEnvelope = encryptJSONEnvelope(input.credentials, credentialSecret);
        const credentialFingerprint = credentialDigest(input.credentials, credentialSecret);
        await client.query(
          `insert into "vasi_engine"."integration_binding_revision"
            ("id", "tenantId", "capability", "revision", "adapterId", "adapterVersion",
             "status", "config", "configHash", "credentialEnvelope", "credentialFingerprint",
             "createdByPrincipalId")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
          [
            id, input.tenantId, input.capability, nextRevision, input.adapterId,
            input.adapterVersion, input.status, input.config, configHash, credentialEnvelope,
            credentialFingerprint, actor.principalId,
          ],
        );
        await client.query(
          `insert into "vasi_engine"."integration_binding_pointer"
            ("tenantId", "capability", "activeRevisionId", "revision", "updatedByPrincipalId")
           values ($1, $2, $3, $4, $5)
           on conflict ("tenantId", "capability") do update
             set "activeRevisionId" = excluded."activeRevisionId", "revision" = excluded."revision",
                 "updatedByPrincipalId" = excluded."updatedByPrincipalId",
                 "updatedAt" = CURRENT_TIMESTAMP`,
          [input.tenantId, input.capability, id, nextRevision, actor.principalId],
        );
        const eventType = input.status === "disabled"
          ? "integration.binding.disabled"
          : currentRevision ? "integration.binding.updated" : "integration.binding.created";
        await appendConfigurationEvent(client, {
          actorPrincipalId: actor.principalId,
          eventData: {
            adapterId: input.adapterId,
            adapterVersion: input.adapterVersion,
            capability: input.capability,
            configHash,
            credentialFingerprint,
            revision: nextRevision,
            status: input.status,
          },
          eventType,
          scopeId: `${input.tenantId}:${input.capability}`,
          scopeType: "integration",
          tenantId: input.tenantId,
        });
        return integrationProjection({
          adapterId: input.adapterId,
          adapterVersion: input.adapterVersion,
          capability: input.capability,
          config: input.config,
          configHash,
          credentialFingerprint,
          id,
          revision: nextRevision,
          status: input.status,
          createdAt: new Date(),
        });
      });
    },

    async getInstallationProfile(actor) {
      requireAdministrator(actor);
      const client = await database.connect();
      try {
        return activeInstallationProfile(client, installationId, false);
      } finally {
        client.release();
      }
    },

    async updateInstallationProfile(actor, payload) {
      requireAdministrator(actor);
      const input = validateInstallationProfileCommand(payload);
      return transaction(database, async (client) => {
        const current = await activeInstallationProfile(client, installationId, true);
        if (current.revision !== input.expectedRevision) {
          throw new EngineStoreError("installation_profile_revision_conflict", 409);
        }
        const next = await createInstallationProfileRevision(
          client,
          installationId,
          input.profile,
          current.revision + 1,
          actor.principalId,
        );
        const updated = await client.query(
          `update "vasi_engine"."installation_profile_pointer"
           set "activeRevisionId" = $3, "revision" = $4,
               "updatedByPrincipalId" = $5, "updatedAt" = CURRENT_TIMESTAMP
           where "installationId" = $1 and "revision" = $2 returning "installationId"`,
          [installationId, input.expectedRevision, next.id, next.revision, actor.principalId],
        );
        if (!updated.rowCount) throw new EngineStoreError("installation_profile_revision_conflict", 409);
        await appendConfigurationEvent(client, {
          actorPrincipalId: actor.principalId,
          eventData: { profileHash: next.profileHash, revision: next.revision },
          eventType: "installation.profile.updated",
          scopeId: installationId,
          scopeType: "installation",
        });
        return next;
      });
    },

    async listTenantAdmissions(actor) {
      requireAdministrator(actor);
      const result = await database.query(
        `select p."revision", r."id", r."admission", r."admissionHash",
                r."createdByPrincipalId", r."createdAt",
                t."id" as "tenantId", t."name" as "tenantName", t."slug" as "tenantSlug",
                s."eventData" as "lastStopEventData", s."eventHash" as "lastStopEventHash",
                s."actorPrincipalId" as "lastStoppedByPrincipalId",
                s."createdAt" as "lastStoppedAt"
         from "vasi_engine"."tenant" t
         join "vasi_engine"."tenant_admission_pointer" p on p."tenantId" = t."id"
         join "vasi_engine"."tenant_admission_revision" r
           on r."id" = p."activeRevisionId" and r."tenantId" = p."tenantId"
         left join lateral (
           select e."eventData", e."eventHash", e."actorPrincipalId", e."createdAt"
           from "vasi_engine"."product_configuration_event" e
           where e."scopeType" = 'tenant' and e."scopeId" = t."id"
             and e."eventType" = 'tenant.production.stopped'
           order by e."sequence" desc limit 1
         ) s on true
         order by t."name", t."id"`,
      );
      return result.rows.map(admissionWithTenantProjection);
    },

    async updateTenantAdmission(actor, payload) {
      requireAdministrator(actor);
      const input = validateTenantAdmissionDecisionCommand(payload);
      return transaction(database, async (client) => {
        const current = await activeTenantAdmission(client, input.tenantId, { lock: "update" });
        if (current.revision !== input.expectedRevision) {
          throw new EngineStoreError("tenant_admission_revision_conflict", 409);
        }
        const admission = applyTenantAdmissionDecision(current.admission, input, new Date());
        const admissionHash = hashCanonicalJSON(admission);
        if (admissionHash === current.admissionHash) {
          throw new EngineStoreError("tenant_admission_decision_unchanged", 409);
        }
        const next = await createTenantAdmissionRevision(
          client,
          input.tenantId,
          admission,
          current.revision + 1,
          actor.principalId,
        );
        const updated = await client.query(
          `update "vasi_engine"."tenant_admission_pointer"
           set "activeRevisionId" = $3, "revision" = $4,
               "updatedByPrincipalId" = $5, "updatedAt" = CURRENT_TIMESTAMP
           where "tenantId" = $1 and "revision" = $2 returning "tenantId"`,
          [input.tenantId, input.expectedRevision, next.id, next.revision, actor.principalId],
        );
        if (!updated.rowCount) throw new EngineStoreError("tenant_admission_revision_conflict", 409);
        await appendConfigurationEvent(client, {
          actorPrincipalId: actor.principalId,
          eventData: {
            admissionHash: next.admissionHash,
            gateId: input.gateId,
            previousStatus: current.status,
            revision: next.revision,
            status: next.status,
          },
          eventType: input.decision === "approved"
            ? "tenant.admission.approved"
            : "tenant.admission.revoked",
          scopeId: input.tenantId,
          scopeType: "tenant",
          tenantId: input.tenantId,
        });
        const tenant = await tenantWithLastProductionStop(client, input.tenantId);
        return admissionWithTenantProjection({
          ...next,
          tenantId: input.tenantId,
          ...tenant,
        });
      });
    },

    async stopTenantProduction(actor, payload) {
      requireAdministrator(actor);
      const input = validateTenantProductionStopCommand(payload);
      return transaction(database, async (client) => {
        await client.query(
          "select pg_advisory_xact_lock(hashtextextended($1, 0))",
          [input.commandId],
        );
        const replay = await client.query(
          `select 1 from "vasi_engine"."product_configuration_event"
           where "eventType" = 'tenant.production.stopped'
             and "eventData"->>'commandId' = $1`,
          [input.commandId],
        );
        if (replay.rowCount) throw new EngineStoreError("tenant_production_stop_replayed", 409);

        const current = await activeTenantAdmission(client, input.tenantId, { lock: "update" });
        if (current.revision !== input.expectedRevision) {
          throw new EngineStoreError("tenant_admission_revision_conflict", 409);
        }

        const stoppedAt = new Date();
        const revokedAdmission = applyTenantAdmissionDecision(current.admission, {
          decision: "pending",
          expectedRevision: current.revision,
          gateId: input.gateId,
          tenantId: input.tenantId,
        }, stoppedAt);
        const revokedAdmissionHash = hashCanonicalJSON(revokedAdmission);
        let admission = current;
        let admissionChanged = false;
        if (revokedAdmissionHash !== current.admissionHash) {
          admission = await createTenantAdmissionRevision(
            client,
            input.tenantId,
            revokedAdmission,
            current.revision + 1,
            actor.principalId,
          );
          const updated = await client.query(
            `update "vasi_engine"."tenant_admission_pointer"
             set "activeRevisionId" = $3, "revision" = $4,
                 "updatedByPrincipalId" = $5, "updatedAt" = $6
             where "tenantId" = $1 and "revision" = $2 returning "tenantId"`,
            [
              input.tenantId,
              input.expectedRevision,
              admission.id,
              admission.revision,
              actor.principalId,
              stoppedAt,
            ],
          );
          if (!updated.rowCount) throw new EngineStoreError("tenant_admission_revision_conflict", 409);
          admissionChanged = true;
        }

        const requests = await client.query(
          `select r."id" as "requestId", r."status", a."id" as "assignmentId"
           from "vasi_engine"."request_instance" r
           join "vasi_engine"."participant_assignment" a on a."requestId" = r."id"
           where r."tenantId" = $1 and r."status" in ('scheduled', 'issued', 'in_progress')
           order by r."id" for update of r, a`,
          [input.tenantId],
        );

        const requestsById = new Map();
        for (const row of requests.rows) {
          const request = requestsById.get(row.requestId) || {
            assignments: [],
            requestId: row.requestId,
            status: row.status,
          };
          request.assignments.push(row.assignmentId);
          requestsById.set(row.requestId, request);
        }

        let revokedAssignmentCount = 0;
        let suppressedNotificationCount = 0;
        for (const request of requestsById.values()) {
          await client.query(
            `update "vasi_engine"."request_instance" set "status" = 'revoked' where "id" = $1`,
            [request.requestId],
          );
          const suppressed = await client.query(
            `update "vasi_engine"."outbox_job"
             set "status" = 'completed', "completedAt" = $2,
                 "result" = jsonb_build_object(
                   'adapter', 'engine', 'outcome', 'suppressed',
                   'reason', 'tenant_production_stopped'
                 ),
                 "payload" = '{"redacted":true}'::jsonb, "updatedAt" = $2
             where "requestId" = $1 and "status" = 'pending'
               and "notificationType" in ('request.issued', 'request.reminder')
             returning "id"`,
            [request.requestId, stoppedAt],
          );
          suppressedNotificationCount += suppressed.rowCount;
          await client.query(
            `insert into "vasi_engine"."request_lifecycle_event"
              ("id", "tenantId", "requestId", "eventType", "actorPrincipalId",
               "idempotencyKey", "eventData", "createdAt")
             values ($1, $2, $3, 'request.revoked', $4, $5, $6, $7)`,
            [
              randomUUID(),
              input.tenantId,
              request.requestId,
              actor.principalId,
              `${input.commandId}:${request.requestId}`,
              {
                commandId: input.commandId,
                incidentReference: input.incidentReference,
                previousStatus: request.status,
                reasonCode: input.reasonCode,
                scope: "tenant_production_stop",
              },
              stoppedAt,
            ],
          );
          for (const assignmentId of request.assignments) {
            await client.query(
              `update "vasi_engine"."participant_assignment" set "status" = 'revoked' where "id" = $1`,
              [assignmentId],
            );
            await appendEvent(client, {
              actor,
              assignmentId,
              eventType: "request.revoked",
              payload: {
                commandId: input.commandId,
                incidentReference: input.incidentReference,
                previousStatus: request.status,
                reasonCode: input.reasonCode,
                scope: "tenant_production_stop",
              },
              receivedAt: stoppedAt,
              requestId: request.requestId,
              tenantId: input.tenantId,
            });
            revokedAssignmentCount += 1;
          }
        }

        const eventData = {
          admissionChanged,
          admissionHash: admission.admissionHash,
          commandId: input.commandId,
          gateId: input.gateId,
          incidentReference: input.incidentReference,
          previousAdmissionStatus: current.status,
          reasonCode: input.reasonCode,
          revokedAssignmentCount,
          resultingAdmissionRevision: admission.revision,
          resultingAdmissionStatus: admission.status,
          revokedRequestCount: requestsById.size,
          stoppedAt: stoppedAt.toISOString(),
          suppressedNotificationCount,
        };
        await appendConfigurationEvent(client, {
          actorPrincipalId: actor.principalId,
          eventData,
          eventType: "tenant.production.stopped",
          scopeId: input.tenantId,
          scopeType: "tenant",
          tenantId: input.tenantId,
        });
        const tenant = await tenantWithLastProductionStop(client, input.tenantId);
        return admissionWithTenantProjection({
          ...admission,
          tenantId: input.tenantId,
          ...tenant,
        });
      });
    },
  });
}

async function registerAdapters(client) {
  for (const adapter of BUILT_IN_ADAPTERS) {
    const manifestHash = hashCanonicalJSON(adapter);
    await client.query(
      `insert into "vasi_engine"."integration_adapter_registry"
        ("adapterId", "adapterVersion", "manifest", "manifestHash", "conformanceStatus")
       values ($1, $2, $3, $4, 'built_in_verified')
       on conflict ("adapterId", "adapterVersion") do nothing`,
      [adapter.id, adapter.version, adapter, manifestHash],
    );
    const existing = await client.query(
      `select "manifestHash", "conformanceStatus" from "vasi_engine"."integration_adapter_registry"
       where "adapterId" = $1 and "adapterVersion" = $2`,
      [adapter.id, adapter.version],
    );
    if (existing.rows[0]?.manifestHash !== manifestHash || existing.rows[0]?.conformanceStatus !== "built_in_verified") {
      throw new EngineStoreError("integration_adapter_registry_integrity_failure", 500);
    }
  }
}

async function ensureInstallationProfile(client, installationId, settings) {
  const pointer = await client.query(
    `select 1 from "vasi_engine"."installation_profile_pointer" where "installationId" = $1`,
    [installationId],
  );
  if (pointer.rowCount) return;
  const profile = installationProfileWithLegacyDestinations(settings);
  const revision = await createInstallationProfileRevision(
    client,
    installationId,
    profile,
    1,
    "vasi-bootstrap",
  );
  await client.query(
    `insert into "vasi_engine"."installation_profile_pointer"
      ("installationId", "activeRevisionId", "revision", "updatedByPrincipalId")
     values ($1, $2, 1, 'vasi-bootstrap')`,
    [installationId, revision.id],
  );
  await appendConfigurationEvent(client, {
    actorPrincipalId: "vasi-bootstrap",
    eventData: { profileHash: revision.profileHash, revision: 1 },
    eventType: "installation.profile.created",
    scopeId: installationId,
    scopeType: "installation",
  });
}

async function activeInstallationProfile(client, installationId, lock) {
  const result = await client.query(
    `select p."revision", r."id", r."profile", r."profileHash"
     from "vasi_engine"."installation_profile_pointer" p
     join "vasi_engine"."installation_profile_revision" r
       on r."id" = p."activeRevisionId" and r."installationId" = p."installationId"
     where p."installationId" = $1${lock ? " for update of p" : ""}`,
    [installationId],
  );
  if (!result.rowCount) throw new EngineStoreError("installation_profile_unavailable", 500);
  const row = result.rows[0];
  const profile = validateInstallationProfile(row.profile);
  if (hashCanonicalJSON(profile) !== row.profileHash) {
    throw new EngineStoreError("installation_profile_integrity_failure", 500);
  }
  return Object.freeze({
    id: row.id,
    profile,
    profileHash: row.profileHash,
    revision: Number(row.revision),
  });
}

async function createInstallationProfileRevision(client, installationId, profile, revision, actorPrincipalId) {
  const id = randomUUID();
  const normalized = validateInstallationProfile(profile);
  const profileHash = hashCanonicalJSON(normalized);
  await client.query(
    `insert into "vasi_engine"."installation_profile_revision"
      ("id", "installationId", "revision", "profile", "profileHash", "createdByPrincipalId")
     values ($1, $2, $3, $4, $5, $6)`,
    [id, installationId, revision, normalized, profileHash, actorPrincipalId],
  );
  return Object.freeze({ id, profile: normalized, profileHash, revision });
}

async function createTenantProfile(client, tenantId, profile, actorPrincipalId) {
  const revision = await createTenantProfileRevision(client, tenantId, profile, 1, actorPrincipalId);
  await client.query(
    `insert into "vasi_engine"."tenant_profile_pointer"
      ("tenantId", "activeRevisionId", "revision", "updatedByPrincipalId")
     values ($1, $2, 1, $3)`,
    [tenantId, revision.id, actorPrincipalId],
  );
  return revision;
}

async function createTenantProfileRevision(client, tenantId, profile, revision, actorPrincipalId) {
  const id = randomUUID();
  const profileHash = hashCanonicalJSON(profile);
  await client.query(
    `insert into "vasi_engine"."tenant_profile_revision"
      ("id", "tenantId", "revision", "profile", "profileHash", "createdByPrincipalId")
     values ($1, $2, $3, $4, $5, $6)`,
    [id, tenantId, revision, profile, profileHash, actorPrincipalId],
  );
  return Object.freeze({ id, profile, profileHash, revision });
}

async function ensureTenantAdmission(client, tenantId, actorPrincipalId) {
  const pointer = await client.query(
    `select 1 from "vasi_engine"."tenant_admission_pointer" where "tenantId" = $1`,
    [tenantId],
  );
  if (pointer.rowCount) return activeTenantAdmission(client, tenantId);
  const admission = await createTenantAdmissionRevision(
    client,
    tenantId,
    defaultTenantAdmission(),
    1,
    actorPrincipalId,
  );
  await client.query(
    `insert into "vasi_engine"."tenant_admission_pointer"
      ("tenantId", "activeRevisionId", "revision", "updatedByPrincipalId")
     values ($1, $2, 1, $3)`,
    [tenantId, admission.id, actorPrincipalId],
  );
  await appendConfigurationEvent(client, {
    actorPrincipalId,
    eventData: {
      admissionHash: admission.admissionHash,
      revision: admission.revision,
      status: admission.status,
    },
    eventType: "tenant.admission.created",
    scopeId: tenantId,
    scopeType: "tenant",
    tenantId,
  });
  return admission;
}

async function createTenantAdmissionRevision(client, tenantId, admission, revision, actorPrincipalId) {
  const id = randomUUID();
  const normalized = validateTenantAdmission(admission);
  const admissionHash = hashCanonicalJSON(normalized);
  const createdAt = new Date();
  await client.query(
    `insert into "vasi_engine"."tenant_admission_revision"
      ("id", "tenantId", "revision", "admission", "admissionHash", "createdByPrincipalId", "createdAt")
     values ($1, $2, $3, $4, $5, $6, $7)`,
    [id, tenantId, revision, normalized, admissionHash, actorPrincipalId, createdAt],
  );
  return tenantAdmissionProjection({
    admission: normalized,
    admissionHash,
    createdAt,
    createdByPrincipalId: actorPrincipalId,
    id,
    revision,
  });
}

async function ensureInitialIntegrations(
  client,
  tenantId,
  credentialSecret,
  actorPrincipalId,
  { migrateLegacy = false, settings = {} } = {},
) {
  await ensureInitialIntegration(client, tenantId, credentialSecret, actorPrincipalId, {
    capability: "notification.delivery",
    input: migrateLegacy ? legacyIntegrationBinding(settings, tenantId) : disabledIntegrationBinding(tenantId),
  });
  await ensureInitialIntegration(client, tenantId, credentialSecret, actorPrincipalId, {
    capability: "document.malware_scan",
    input: disabledScanBinding(tenantId),
  });
}

async function ensureInitialIntegration(
  client,
  tenantId,
  credentialSecret,
  actorPrincipalId,
  { capability, input },
) {
  const exists = await client.query(
    `select 1 from "vasi_engine"."integration_binding_pointer"
     where "tenantId" = $1 and "capability" = $2`,
    [tenantId, capability],
  );
  if (exists.rowCount) return;
  const credentials = input.credentials;
  const id = randomUUID();
  const config = input.config;
  await client.query(
    `insert into "vasi_engine"."integration_binding_revision"
      ("id", "tenantId", "capability", "revision", "adapterId", "adapterVersion", "status",
       "config", "configHash", "credentialEnvelope", "credentialFingerprint", "createdByPrincipalId")
     values ($1, $2, $3, 1, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      id,
      tenantId,
      capability,
      input.adapterId,
      input.adapterVersion,
      input.status,
      config,
      hashCanonicalJSON(config),
      encryptJSONEnvelope(credentials, credentialSecret),
      credentialDigest(credentials, credentialSecret),
      actorPrincipalId,
    ],
  );
  await client.query(
    `insert into "vasi_engine"."integration_binding_pointer"
      ("tenantId", "capability", "activeRevisionId", "revision", "updatedByPrincipalId")
     values ($1, $2, $3, 1, $4)`,
    [tenantId, capability, id, actorPrincipalId],
  );
  await appendConfigurationEvent(client, {
    actorPrincipalId,
    eventData: {
      adapterId: input.adapterId,
      adapterVersion: input.adapterVersion,
      capability,
      configHash: hashCanonicalJSON(config),
      revision: 1,
      status: input.status,
    },
    eventType: "integration.binding.created",
    scopeId: `${tenantId}:${capability}`,
    scopeType: "integration",
    tenantId,
  });
}

function installationProfileWithLegacyDestinations(settings) {
  const profile = defaultInstallationProfile();
  const legacy = legacyIntegrationBinding(settings, "legacy-profile");
  if (legacy.status !== "active") return profile;
  return validateInstallationProfile({
    ...profile,
    adapters: {
      ...profile.adapters,
      smtpAllowedHosts: legacy.adapterId === "smtp" ? [legacy.config.host] : [],
      webhookAllowedHosts: legacy.adapterId === "webhook" ? [new URL(legacy.config.url).hostname] : [],
    },
  });
}

function disabledIntegrationBinding(tenantId) {
  return validateIntegrationBindingCommand({
    adapterId: "disabled",
    capability: "notification.delivery",
    config: {},
    credentials: {},
    expectedRevision: 0,
    status: "disabled",
    tenantId,
  });
}

function disabledScanBinding(tenantId) {
  return validateIntegrationBindingCommand({
    adapterId: "scan_disabled",
    capability: "document.malware_scan",
    config: {},
    credentials: {},
    expectedRevision: 0,
    status: "disabled",
    tenantId,
  });
}

function legacyIntegrationBinding(settings, tenantId) {
  const mode = settings.ENGINE_NOTIFICATION_MODE || "disabled";
  if (mode === "disabled") return disabledIntegrationBinding(tenantId);
  if (mode === "webhook") {
    return validateIntegrationBindingCommand({
      adapterId: "webhook",
      capability: "notification.delivery",
      config: { url: settings.ENGINE_NOTIFICATION_WEBHOOK_URL },
      credentials: { secret: settings.ENGINE_NOTIFICATION_WEBHOOK_SECRET },
      expectedRevision: 0,
      status: "active",
      tenantId,
    });
  }
  if (mode === "smtp") {
    return validateIntegrationBindingCommand({
      adapterId: "smtp",
      capability: "notification.delivery",
      config: {
        from: settings.ENGINE_NOTIFICATION_SMTP_FROM,
        host: settings.ENGINE_NOTIFICATION_SMTP_HOST,
        port: Number(settings.ENGINE_NOTIFICATION_SMTP_PORT || "587"),
        secure: settings.ENGINE_NOTIFICATION_SMTP_SECURE === "true",
        username: settings.ENGINE_NOTIFICATION_SMTP_USER || undefined,
      },
      credentials: { password: settings.ENGINE_NOTIFICATION_SMTP_PASSWORD || undefined },
      expectedRevision: 0,
      status: "active",
      tenantId,
    });
  }
  throw new Error("ENGINE_NOTIFICATION_MODE must be disabled, smtp, or webhook.");
}

async function appendConfigurationEvent(client, {
  actorPrincipalId,
  eventData,
  eventType,
  scopeId,
  scopeType,
  tenantId,
}) {
  await client.query(
    `insert into "vasi_engine"."product_configuration_chain_head"
      ("scopeType", "scopeId", "lastSequence", "lastHash")
     values ($1, $2, 0, $3) on conflict ("scopeType", "scopeId") do nothing`,
    [scopeType, scopeId, GENESIS_HASH],
  );
  const head = await client.query(
    `select "lastSequence", "lastHash" from "vasi_engine"."product_configuration_chain_head"
     where "scopeType" = $1 and "scopeId" = $2 for update`,
    [scopeType, scopeId],
  );
  const sequence = Number(head.rows[0].lastSequence) + 1;
  const previousHash = head.rows[0].lastHash;
  const createdAt = new Date();
  const id = randomUUID();
  const eventHash = hashCanonicalJSON({
    actorPrincipalId,
    createdAt: createdAt.toISOString(),
    eventData,
    eventType,
    id,
    previousHash,
    scopeId,
    scopeType,
    sequence,
    tenantId,
  });
  await client.query(
    `insert into "vasi_engine"."product_configuration_event"
      ("id", "scopeType", "scopeId", "tenantId", "sequence", "eventType",
       "actorPrincipalId", "eventData", "previousHash", "eventHash", "createdAt")
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      id, scopeType, scopeId, tenantId || null, sequence, eventType,
      actorPrincipalId, eventData, previousHash, eventHash, createdAt,
    ],
  );
  await client.query(
    `update "vasi_engine"."product_configuration_chain_head"
     set "lastSequence" = $3, "lastHash" = $4 where "scopeType" = $1 and "scopeId" = $2`,
    [scopeType, scopeId, sequence, eventHash],
  );
  return Object.freeze({ createdAt, eventHash, id, sequence });
}

async function requirePermission(client, actor, tenantId, permission) {
  if (!actor?.principalId) throw new EngineStoreError("forbidden", 403);
  const membership = await client.query(
    `select "roles" from "vasi_engine"."tenant_membership"
     where "tenantId" = $1 and "principalId" = $2 and "status" = 'active'
       and "validFrom" <= CURRENT_TIMESTAMP
       and ("expiresAt" is null or "expiresAt" > CURRENT_TIMESTAMP)`,
    [tenantId, actor.principalId],
  );
  if (!membership.rowCount || !hasTenantPermission(membership.rows[0].roles, permission)) {
    throw new EngineStoreError("forbidden", 403);
  }
}

function requireAdministrator(actor) {
  if (!actor?.principalId || !actor.roles?.includes("admin")) {
    throw new EngineStoreError("forbidden", 403);
  }
}

function tenantProvisionInputHash(input, actor) {
  return hashCanonicalJSON({
    actorEmail: actor.email?.toLowerCase() || null,
    name: input.name,
    ownerEmail: input.ownerEmail,
    profile: input.profile,
    slug: input.slug,
  });
}

function validateTenantProvisionResult(value, resultHash, input, actor) {
  if (!plainObject(value) || hashCanonicalJSON(value) !== resultHash) {
    throw new EngineStoreError("tenant_provision_command_integrity_failure", 500);
  }
  const expectedOwnerEmail = input.ownerEmail || actor.email?.toLowerCase() || null;
  const expectedGrantCreated = Boolean(
    input.ownerEmail && input.ownerEmail !== actor.email?.toLowerCase(),
  );
  const expectedPermissions = permissionsForRoles(["owner"]);
  try {
    exactKeys(value, ["admission", "id", "name", "owner", "permissions", "profile", "roles", "slug"]);
    if (!uuidValue(value.id) || value.name !== input.name || value.slug !== input.slug) throw new Error("tenant identity");
    if (!plainObject(value.owner)) throw new Error("owner shape");
    exactKeys(value.owner, ["email", "grantCreated"]);
    if (value.owner.email !== expectedOwnerEmail || value.owner.grantCreated !== expectedGrantCreated) throw new Error("owner binding");
    if (!sameArray(value.roles, ["owner"]) || !sameArray(value.permissions, expectedPermissions)) throw new Error("owner authorization");

    if (!plainObject(value.profile)) throw new Error("profile shape");
    exactKeys(value.profile, ["id", "profile", "profileHash", "revision"]);
    const profile = validateTenantProfile(value.profile.profile);
    if (
      !uuidValue(value.profile.id) || value.profile.revision !== 1 ||
      value.profile.profileHash !== hashCanonicalJSON(profile) ||
      value.profile.profileHash !== hashCanonicalJSON(input.profile)
    ) throw new Error("profile integrity");

    if (!plainObject(value.admission)) throw new Error("admission shape");
    exactKeys(value.admission, [
      "admission", "admissionHash", "createdAt", "createdByPrincipalId",
      "id", "revision", "status",
    ]);
    const admission = validateTenantAdmission(value.admission.admission);
    if (
      !uuidValue(value.admission.id) || value.admission.revision !== 1 ||
      value.admission.status !== "pending" || admission.status !== "pending" ||
      value.admission.createdByPrincipalId !== actor.principalId ||
      value.admission.admissionHash !== hashCanonicalJSON(admission) ||
      !isoTimestamp(value.admission.createdAt)
    ) throw new Error("admission integrity");
  } catch (error) {
    throw new EngineStoreError(
      "tenant_provision_command_integrity_failure",
      500,
      `tenant_provision_command_integrity_failure:${error instanceof Error ? error.message : "validation"}`,
    );
  }
  return Object.freeze(value);
}

function plainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (!sameArray(actual, expected)) throw new Error("Unexpected tenant provisioning result fields.");
}

function sameArray(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length &&
    actual.every((entry, index) => entry === expected[index]);
}

function uuidValue(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isoTimestamp(value) {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

function integrationProjection(row) {
  return Object.freeze({
    adapterId: row.adapterId,
    adapterVersion: row.adapterVersion,
    capability: row.capability,
    config: row.config,
    configHash: row.configHash,
    configuredCredentials: ["https_malware_scanner", "microsoft_graph", "webhook"].includes(row.adapterId) || Boolean(row.config?.username),
    createdAt: new Date(row.createdAt).toISOString(),
    id: row.id,
    revision: Number(row.revision),
    status: row.status,
  });
}

function admissionWithTenantProjection(row) {
  const admission = row.admission && row.admissionHash && row.id
    ? tenantAdmissionProjection(row)
    : row;
  return Object.freeze({
    ...admission,
    ...(row.lastProductionStop || row.lastStopEventData
      ? { lastProductionStop: row.lastProductionStop || productionStopProjection(row) }
      : {}),
    tenant: Object.freeze({
      id: row.tenantId,
      name: row.tenantName,
      slug: row.tenantSlug,
    }),
  });
}

async function tenantWithLastProductionStop(client, tenantId) {
  const result = await client.query(
    `select t."name" as "tenantName", t."slug" as "tenantSlug",
            s."eventData" as "lastStopEventData", s."eventHash" as "lastStopEventHash",
            s."actorPrincipalId" as "lastStoppedByPrincipalId",
            s."createdAt" as "lastStoppedAt"
     from "vasi_engine"."tenant" t
     left join lateral (
       select e."eventData", e."eventHash", e."actorPrincipalId", e."createdAt"
       from "vasi_engine"."product_configuration_event" e
       where e."scopeType" = 'tenant' and e."scopeId" = t."id"
         and e."eventType" = 'tenant.production.stopped'
       order by e."sequence" desc limit 1
     ) s on true
     where t."id" = $1`,
    [tenantId],
  );
  if (!result.rowCount) throw new EngineStoreError("not_found", 404);
  return result.rows[0];
}

function productionStopProjection(row) {
  const data = row.lastStopEventData;
  if (!data) return undefined;
  return Object.freeze({
    admissionChanged: Boolean(data.admissionChanged),
    commandId: data.commandId,
    eventHash: row.lastStopEventHash,
    gateId: data.gateId,
    incidentReference: data.incidentReference,
    reasonCode: data.reasonCode,
    revokedAssignmentCount: Number(data.revokedAssignmentCount),
    resultingAdmissionRevision: Number(data.resultingAdmissionRevision),
    resultingAdmissionStatus: data.resultingAdmissionStatus,
    revokedRequestCount: Number(data.revokedRequestCount),
    stoppedAt: new Date(row.lastStoppedAt || data.stoppedAt).toISOString(),
    stoppedByPrincipalId: row.lastStoppedByPrincipalId,
    suppressedNotificationCount: Number(data.suppressedNotificationCount),
  });
}

function credentialDigest(credentials, secret) {
  return createHmac("sha256", Buffer.from(secret, "base64url"))
    .update(canonicalJSON(credentials))
    .digest("hex");
}

function assertAdapterDestinationAllowed(profile, input) {
  if (!integrationDestinationAllowed(profile, input)) {
    throw new EngineStoreError("integration_destination_not_allowed", 403);
  }
}

function requiredSetting(settings, name) {
  const value = settings[name];
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required.`);
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error(`${name} must use unpadded base64url encoding.`);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 32) throw new Error(`${name} must contain 32 bytes.`);
  return value;
}

async function transaction(database, callback) {
  const client = await database.connect();
  try {
    await client.query("begin");
    const result = await callback(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
