import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import { validateTenantProfile } from "../../packages/engine-domain/productization.mjs";
import { EngineStoreError } from "./errors.mjs";

export async function activeTenantProfile(client, tenantId, { lock = false } = {}) {
  const result = await client.query(
    `select p."revision", r."id", r."profile", r."profileHash"
     from "vasi_engine"."tenant_profile_pointer" p
     join "vasi_engine"."tenant_profile_revision" r
       on r."id" = p."activeRevisionId" and r."tenantId" = p."tenantId"
     where p."tenantId" = $1${lock ? " for update of p" : ""}`,
    [tenantId],
  );
  if (!result.rowCount) throw new EngineStoreError("tenant_profile_unavailable", 409);
  const row = result.rows[0];
  const profile = validateTenantProfile(row.profile);
  if (hashCanonicalJSON(profile) !== row.profileHash) {
    throw new EngineStoreError("tenant_profile_integrity_failure", 500);
  }
  return Object.freeze({
    id: row.id,
    profile,
    profileHash: row.profileHash,
    revision: Number(row.revision),
  });
}

export async function tenantUsage(client, tenantId, activeProfile) {
  const profile = activeProfile || await activeTenantProfile(client, tenantId);
  const result = await client.query(
    `select
       (select count(*)::integer from (
          select coalesce(lower("email"), "principalId") as identity
          from "vasi_engine"."tenant_membership"
          where "tenantId" = $1 and "status" = 'active'
          union
          select lower("email") from "vasi_engine"."tenant_membership_grant"
          where "tenantId" = $1 and "status" = 'active'
        ) members) as "members",
       (select count(*)::integer from "vasi_engine"."workflow_definition"
        where "tenantId" = $1 and "status" <> 'archived') as "workflows",
       (select count(*)::integer from "vasi_engine"."request_instance"
        where "tenantId" = $1 and "status" in ('scheduled', 'issued', 'in_progress')) as "activeRequests",
       (select coalesce(sum("expectedByteLength"), 0)::bigint from "vasi_engine"."document_artifact"
        where "tenantId" = $1) as "artifactBytes",
       (select count(*)::integer from "vasi_engine"."integration_binding_pointer" p
        join "vasi_engine"."integration_binding_revision" r on r."id" = p."activeRevisionId"
        where p."tenantId" = $1 and r."status" = 'active') as "integrations"`,
    [tenantId],
  );
  const usage = {
    activeRequests: Number(result.rows[0].activeRequests),
    artifactBytes: Number(result.rows[0].artifactBytes),
    integrations: Number(result.rows[0].integrations),
    members: Number(result.rows[0].members),
    workflows: Number(result.rows[0].workflows),
  };
  return Object.freeze({
    profileHash: profile.profileHash,
    profileRevision: profile.revision,
    resources: Object.freeze({
      activeRequests: quota(usage.activeRequests, profile.profile.quotas.maxActiveRequests),
      artifactBytes: quota(usage.artifactBytes, profile.profile.quotas.maxArtifactBytes),
      integrations: quota(usage.integrations, profile.profile.quotas.maxIntegrations),
      members: quota(usage.members, profile.profile.quotas.maxMembers),
      workflows: quota(usage.workflows, profile.profile.quotas.maxWorkflows),
    }),
    tenantId,
  });
}

export async function assertTenantCapacity(client, tenantId, resource, increment = 1) {
  const profile = await activeTenantProfile(client, tenantId, { lock: true });
  const usage = await tenantUsage(client, tenantId, profile);
  const selected = usage.resources[resource];
  if (!selected || !Number.isSafeInteger(increment) || increment < 0) {
    throw new EngineStoreError("invalid_tenant_quota_check", 500);
  }
  if (selected.used + increment > selected.limit) {
    throw new EngineStoreError(`tenant_quota_${resource}_exceeded`, 409);
  }
  return profile;
}

export async function assertArtifactCapacity(client, tenantId, expectedByteLength) {
  const profile = await activeTenantProfile(client, tenantId, { lock: true });
  if (expectedByteLength > profile.profile.quotas.maxArtifactBytesPerArtifact) {
    throw new EngineStoreError("tenant_quota_artifact_size_exceeded", 413);
  }
  const usage = await tenantUsage(client, tenantId, profile);
  if (usage.resources.artifactBytes.used + expectedByteLength > usage.resources.artifactBytes.limit) {
    throw new EngineStoreError("tenant_quota_artifactBytes_exceeded", 409);
  }
  return profile;
}

function quota(used, limit) {
  return Object.freeze({ available: Math.max(0, limit - used), limit, used });
}
