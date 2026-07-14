import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import { validateTenantAdmission } from "../../packages/engine-domain/productization.mjs";
import { EngineStoreError } from "./errors.mjs";

export async function activeTenantAdmission(client, tenantId, { lock = false } = {}) {
  const lockClause = lock === "update" ? " for update of p" : lock ? " for share of p" : "";
  const result = await client.query(
    `select p."revision", r."id", r."admission", r."admissionHash",
            r."createdByPrincipalId", r."createdAt"
     from "vasi_engine"."tenant_admission_pointer" p
     join "vasi_engine"."tenant_admission_revision" r
       on r."id" = p."activeRevisionId" and r."tenantId" = p."tenantId"
     where p."tenantId" = $1${lockClause}`,
    [tenantId],
  );
  if (!result.rowCount) throw new EngineStoreError("tenant_not_admitted", 409);
  return tenantAdmissionProjection(result.rows[0]);
}

export async function assertTenantAdmitted(client, tenantId, options = {}) {
  const admission = await activeTenantAdmission(client, tenantId, options);
  if (admission.status !== "admitted") throw new EngineStoreError("tenant_not_admitted", 409);
  return admission;
}

export function tenantAdmissionProjection(row) {
  let admission;
  try {
    admission = validateTenantAdmission(row.admission);
  } catch {
    throw new EngineStoreError("tenant_admission_integrity_failure", 500);
  }
  if (hashCanonicalJSON(admission) !== row.admissionHash) {
    throw new EngineStoreError("tenant_admission_integrity_failure", 500);
  }
  const createdAt = row.createdAt instanceof Date ? row.createdAt : new Date(row.createdAt);
  if (Number.isNaN(createdAt.getTime())) {
    throw new EngineStoreError("tenant_admission_integrity_failure", 500);
  }
  return Object.freeze({
    admission,
    admissionHash: row.admissionHash,
    createdAt: createdAt.toISOString(),
    createdByPrincipalId: row.createdByPrincipalId,
    id: row.id,
    revision: Number(row.revision),
    status: admission.status,
  });
}

export function tenantAdmissionEvidenceProjection(record) {
  return Object.freeze({
    admission: record.admission,
    admissionHash: record.admissionHash,
    bindingProvenance: "issued",
    revision: record.revision,
    revisionId: record.id,
  });
}
