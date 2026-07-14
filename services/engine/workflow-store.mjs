import { randomUUID } from "node:crypto";

import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import {
  hasTenantPermission,
  permissionsForRoles,
  validateMembershipInput,
  validateWorkflowMutation,
} from "../../packages/engine-domain/workflow.mjs";
import { EvidenceStoreError } from "./evidence-store.mjs";

export function createWorkflowStore(database) {
  return Object.freeze({
    async listTenants(actor) {
      requireActorEmail(actor);
      return transaction(database, async (client) => {
        await claimMembershipGrants(client, actor);
        const result = await client.query(
          `select t."id", t."name", t."slug", m."roles"
           from "vasi_engine"."tenant_membership" m
           join "vasi_engine"."tenant" t on t."id" = m."tenantId"
           where m."principalId" = $1 and m."status" = 'active' and t."status" = 'active'
             and m."validFrom" <= CURRENT_TIMESTAMP
             and (m."expiresAt" is null or m."expiresAt" > CURRENT_TIMESTAMP)
           order by t."name", t."id"`,
          [actor.principalId],
        );
        return result.rows.map((row) => ({
          ...row,
          permissions: permissionsForRoles(row.roles),
        }));
      });
    },

    async createWorkflow(actor, payload) {
      const input = validateWorkflowMutation(payload);
      if (!input.name || !input.document || input.definitionId) invalidWorkflow();
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "workflow.manage");
        const definitionId = randomUUID();
        const now = new Date();
        await client.query(
          `insert into "vasi_engine"."workflow_definition"
            ("id", "tenantId", "name", "createdByPrincipalId", "createdAt", "updatedAt")
           values ($1, $2, $3, $4, $5, $5)`,
          [definitionId, input.tenantId, input.name, actor.principalId, now],
        );
        await client.query(
          `insert into "vasi_engine"."workflow_draft"
            ("definitionId", "tenantId", "version", "schemaVersion", "document", "documentHash",
             "updatedByPrincipalId", "updatedAt")
           values ($1, $2, 1, $3, $4, $5, $6, $7)`,
          [
            definitionId,
            input.tenantId,
            input.document.document.schema,
            input.document.document,
            input.document.documentHash,
            actor.principalId,
            now,
          ],
        );
        return workflowProjection({
          definitionId,
          document: input.document.document,
          documentHash: input.document.documentHash,
          draftVersion: 1,
          name: input.name,
          publishedRevision: null,
          status: "draft",
          tenantId: input.tenantId,
          updatedAt: now,
        });
      });
    },

    async updateDraft(actor, payload) {
      const input = validateWorkflowMutation(payload);
      if (!input.definitionId || !input.document || !input.expectedDraftVersion || input.name) {
        invalidWorkflow();
      }
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "workflow.manage");
        const now = new Date();
        const result = await client.query(
          `update "vasi_engine"."workflow_draft" d
           set "version" = d."version" + 1, "schemaVersion" = $4, "document" = $5,
               "documentHash" = $6, "updatedByPrincipalId" = $7, "updatedAt" = $8
           from "vasi_engine"."workflow_definition" w
           where d."definitionId" = $1 and d."tenantId" = $2 and d."version" = $3
             and w."id" = d."definitionId" and w."tenantId" = d."tenantId" and w."status" <> 'archived'
           returning d."version", w."name", w."status"`,
          [
            input.definitionId,
            input.tenantId,
            input.expectedDraftVersion,
            input.document.document.schema,
            input.document.document,
            input.document.documentHash,
            actor.principalId,
            now,
          ],
        );
        if (!result.rowCount) throw new EvidenceStoreError("draft_version_conflict", 409);
        await client.query(
          `update "vasi_engine"."workflow_definition" set "updatedAt" = $2 where "id" = $1`,
          [input.definitionId, now],
        );
        return workflowProjection({
          definitionId: input.definitionId,
          document: input.document.document,
          documentHash: input.document.documentHash,
          draftVersion: result.rows[0].version,
          name: result.rows[0].name,
          publishedRevision: null,
          status: result.rows[0].status,
          tenantId: input.tenantId,
          updatedAt: now,
        });
      });
    },

    async publishWorkflow(actor, payload) {
      const input = validateWorkflowMutation(payload);
      if (!input.definitionId || input.document || input.name) invalidWorkflow();
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "workflow.manage");
        const draft = await client.query(
          `select d."version", d."schemaVersion", d."document", d."documentHash", w."name", w."status"
           from "vasi_engine"."workflow_draft" d
           join "vasi_engine"."workflow_definition" w on w."id" = d."definitionId"
           where d."definitionId" = $1 and d."tenantId" = $2
           for update of d, w`,
          [input.definitionId, input.tenantId],
        );
        if (!draft.rowCount) notFound();
        if (draft.rows[0].status === "archived") throw new EvidenceStoreError("workflow_archived", 409);
        if (input.expectedDraftVersion && input.expectedDraftVersion !== draft.rows[0].version) {
          throw new EvidenceStoreError("draft_version_conflict", 409);
        }
        const revisionResult = await client.query(
          `select coalesce(max("revision"), 0) + 1 as "revision"
           from "vasi_engine"."workflow_revision" where "definitionId" = $1`,
          [input.definitionId],
        );
        const revision = Number(revisionResult.rows[0].revision);
        const revisionId = randomUUID();
        const document = draft.rows[0].document;
        const firstActivity = document.activities[0];
        const publishedAt = new Date();
        await client.query(
          `insert into "vasi_engine"."workflow_revision"
            ("id", "tenantId", "revision", "title", "purpose", "activityType", "responseMode",
             "content", "contentHash", "publishedByPrincipalId", "publishedAt", "definitionId",
             "schemaVersion", "snapshot", "snapshotHash")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
          [
            revisionId,
            input.tenantId,
            revision,
            document.title,
            document.purpose,
            firstActivity.type,
            firstActivity.responseMode,
            firstActivity.content,
            hashCanonicalJSON(firstActivity.content),
            actor.principalId,
            publishedAt,
            input.definitionId,
            draft.rows[0].schemaVersion,
            document,
            draft.rows[0].documentHash,
          ],
        );
        await client.query(
          `update "vasi_engine"."workflow_definition"
           set "status" = 'active', "updatedAt" = $2 where "id" = $1`,
          [input.definitionId, publishedAt],
        );
        return {
          definitionId: input.definitionId,
          publishedAt: publishedAt.toISOString(),
          revision,
          revisionId,
          snapshotHash: draft.rows[0].documentHash,
          tenantId: input.tenantId,
        };
      });
    },

    async listWorkflows(actor, payload) {
      const tenantId = requiredToken(payload?.tenantId, "tenantId");
      const client = await database.connect();
      try {
        await requirePermission(client, actor, tenantId, "workflow.manage");
        const result = await client.query(
          `select w."id" as "definitionId", w."tenantId", w."name", w."status", w."updatedAt",
                  d."version" as "draftVersion", d."document", d."documentHash",
                  r."id" as "publishedRevisionId", r."revision" as "publishedRevision",
                  r."snapshotHash" as "publishedSnapshotHash"
           from "vasi_engine"."workflow_definition" w
           join "vasi_engine"."workflow_draft" d on d."definitionId" = w."id"
           left join lateral (
             select "id", "revision", "snapshotHash" from "vasi_engine"."workflow_revision"
             where "definitionId" = w."id" order by "revision" desc limit 1
           ) r on true
           where w."tenantId" = $1 order by w."updatedAt" desc, w."id"`,
          [tenantId],
        );
        return result.rows.map(workflowProjection);
      } finally {
        client.release();
      }
    },

    async listMembers(actor, payload) {
      const tenantId = requiredToken(payload?.tenantId, "tenantId");
      const client = await database.connect();
      try {
        await requirePermission(client, actor, tenantId, "member.manage");
        const result = await client.query(
          `select coalesce(m."email", g."email") as "email",
                  coalesce(m."roles", g."roles") as "roles",
                  coalesce(m."status", g."status") as "status",
                  m."principalId", coalesce(m."source", 'grant') as "source"
           from "vasi_engine"."tenant_membership_grant" g
           full join "vasi_engine"."tenant_membership" m
             on m."tenantId" = g."tenantId" and lower(m."email") = lower(g."email")
           where coalesce(m."tenantId", g."tenantId") = $1
           order by lower(coalesce(m."email", g."email")), m."principalId"`,
          [tenantId],
        );
        return result.rows;
      } finally {
        client.release();
      }
    },

    async setMember(actor, payload) {
      const input = validateMembershipInput(payload);
      return transaction(database, async (client) => {
        await requirePermission(client, actor, input.tenantId, "member.manage");
        await client.query(
          `insert into "vasi_engine"."tenant_membership_grant"
            ("id", "tenantId", "email", "roles", "status", "createdByPrincipalId")
           values ($1, $2, $3, $4, $5, $6)
           on conflict ("tenantId", "email") do update
             set "roles" = excluded."roles", "status" = excluded."status",
                 "updatedAt" = CURRENT_TIMESTAMP`,
          [randomUUID(), input.tenantId, input.email, input.roles, input.status, actor.principalId],
        );
        await client.query(
          `update "vasi_engine"."tenant_membership"
           set "roles" = $3, "status" = $4
           where "tenantId" = $1 and lower("email") = $2`,
          [input.tenantId, input.email, input.roles, input.status],
        );
        const owners = await client.query(
          `select count(*)::integer as "count" from "vasi_engine"."tenant_membership"
           where "tenantId" = $1 and "status" = 'active' and 'owner' = any("roles")`,
          [input.tenantId],
        );
        if (owners.rows[0].count < 1) throw new EvidenceStoreError("last_owner_required", 409);
        return input;
      });
    },
  });
}

export async function requirePermission(client, actor, tenantId, permission) {
  const membership = await client.query(
    `select "roles" from "vasi_engine"."tenant_membership"
     where "tenantId" = $1 and "principalId" = $2 and "status" = 'active'
       and "validFrom" <= CURRENT_TIMESTAMP
       and ("expiresAt" is null or "expiresAt" > CURRENT_TIMESTAMP)`,
    [tenantId, actor.principalId],
  );
  if (!membership.rowCount || !hasTenantPermission(membership.rows[0].roles, permission)) {
    throw new EvidenceStoreError("forbidden", 403);
  }
  return membership.rows[0].roles;
}

async function claimMembershipGrants(client, actor) {
  const grants = await client.query(
    `select "tenantId", "roles" from "vasi_engine"."tenant_membership_grant"
     where lower("email") = $1 and "status" = 'active'`,
    [actor.email],
  );
  for (const grant of grants.rows) {
    await client.query(
      `insert into "vasi_engine"."tenant_membership"
        ("tenantId", "principalId", "roles", "status", "email", "source")
       values ($1, $2, $3, 'active', $4, 'email_grant')
       on conflict ("tenantId", "principalId") do update
         set "roles" = excluded."roles", "status" = 'active', "email" = excluded."email",
             "source" = excluded."source"`,
      [grant.tenantId, actor.principalId, grant.roles, actor.email],
    );
  }
}

function workflowProjection(row) {
  return {
    definitionId: row.definitionId,
    document: row.document,
    documentHash: row.documentHash,
    draftVersion: Number(row.draftVersion),
    name: row.name,
    publishedRevision: row.publishedRevision === null || row.publishedRevision === undefined
      ? null
      : Number(row.publishedRevision),
    publishedRevisionId: row.publishedRevisionId,
    publishedSnapshotHash: row.publishedSnapshotHash,
    status: row.status,
    tenantId: row.tenantId,
    updatedAt: new Date(row.updatedAt).toISOString(),
  };
}

function requireActorEmail(actor) {
  if (!actor?.principalId || !actor.email) throw new EvidenceStoreError("forbidden", 403);
}

function requiredToken(value, name) {
  if (typeof value !== "string" || !value || value.length > 128) {
    throw new EvidenceStoreError(`invalid_${name}`, 400);
  }
  return value;
}

function invalidWorkflow() {
  throw new EvidenceStoreError("invalid_workflow_command", 400);
}

function notFound() {
  throw new EvidenceStoreError("not_found", 404);
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
