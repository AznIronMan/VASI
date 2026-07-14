import { createHash } from "node:crypto";

import { TENANT_ADMISSION_GATES } from "../packages/engine-domain/productization.mjs";

export async function admitConformanceTenant(call, administrator, tenantId) {
  const listed = await call(administrator, "GET", "/v1/admin/tenant-admissions");
  if (listed.status !== 200 || !Array.isArray(listed.body)) {
    throw new Error("The conformance tenant admission list was unavailable.");
  }
  let record = listed.body.find((candidate) => candidate.tenant?.id === tenantId);
  if (!record || record.status !== "pending" || record.revision !== 1) {
    throw new Error("The conformance tenant did not begin with a pending admission revision.");
  }
  for (const gateId of TENANT_ADMISSION_GATES) {
    const decided = await call(administrator, "POST", "/v1/admin/tenant-admissions", {
      decision: "approved",
      evidenceDigest: createHash("sha256")
        .update(`vasi-conformance\u0000${tenantId}\u0000${gateId}`, "utf8")
        .digest("hex"),
      evidenceReference: `conformance:${gateId}`,
      expectedRevision: record.revision,
      gateId,
      reviewerReference: "vasi-conformance-suite",
      tenantId,
    });
    if (decided.status !== 200) {
      throw new Error(`The conformance admission gate ${gateId} failed with ${decided.status}.`);
    }
    record = decided.body;
  }
  if (
    record.status !== "admitted" || record.revision !== TENANT_ADMISSION_GATES.length + 1 ||
    record.admission?.gates?.some((gate) => gate.state !== "approved")
  ) {
    throw new Error("The conformance tenant was not admitted from the complete gate set.");
  }
  return record;
}
