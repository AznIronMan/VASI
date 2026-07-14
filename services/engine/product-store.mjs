import { createHmac, randomUUID } from "node:crypto";

import {
  canonicalJSON,
  encryptJSONEnvelope,
  hashCanonicalJSON,
} from "../../packages/engine-crypto/index.mjs";
import {
  BUILT_IN_ADAPTERS,
  defaultInstallationProfile,
  defaultTenantProfile,
  integrationDestinationAllowed,
  validateInstallationProfile,
  validateInstallationProfileCommand,
  validateIntegrationBindingCommand,
  validateTenantProfileCommand,
  validateTenantProvisionInput,
  validateTenantReference,
} from "../../packages/engine-domain/productization.mjs";
import { hasTenantPermission, permissionsForRoles } from "../../packages/engine-domain/workflow.mjs";
import { EngineStoreError } from "./errors.mjs";
import { activeTenantProfile, assertTenantCapacity, tenantUsage } from "./tenant-policy.mjs";

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
            migrateLegacy: true,
            settings,
          });
          await appendConfigurationEvent(client, {
            actorPrincipalId: "vasi-migration",
            eventData: { migrated: true },
            eventType: "tenant.provisioned",
            scopeId: tenant.id,
            scopeType: "tenant",
            tenantId: tenant.id,
          });
        }
        const existingTenants = await client.query(
          `select t."id" from "vasi_engine"."tenant" t order by t."id" for update of t`,
        );
        for (const tenant of existingTenants.rows) {
          await ensureInitialIntegrations(client, tenant.id, credentialSecret, "vasi-migration", {
            migrateLegacy: true,
            settings,
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
        if (input.ownerEmail && input.ownerEmail !== actor.email?.toLowerCase()) {
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
            ownerGrantCreated: Boolean(input.ownerEmail && input.ownerEmail !== actor.email?.toLowerCase()),
            profileHash: profile.profileHash,
            profileRevision: profile.revision,
            slug: input.slug,
          },
          eventType: "tenant.provisioned",
          scopeId: tenantId,
          scopeType: "tenant",
          tenantId,
        });
        return {
          id: tenantId,
          name: input.name,
          permissions: permissionsForRoles(["owner"]),
          profile,
          roles: ["owner"],
          slug: input.slug,
        };
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
