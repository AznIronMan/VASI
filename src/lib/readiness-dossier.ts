import {
  readinessExportJSON as sharedReadinessExportJSON,
  renderReadinessDossierHTML as sharedRenderReadinessDossierHTML,
  SIGNED_READINESS_EXPORT_SCHEMA,
  validateReadinessExport as sharedValidateReadinessExport,
} from "../../packages/readiness-dossier/index.mjs";

import type { AdminTenantReadinessExport } from "@/lib/owner-types";

export function validateReadinessExport(value: unknown): AdminTenantReadinessExport {
  const exported = sharedValidateReadinessExport(value);
  if (exported.schema !== SIGNED_READINESS_EXPORT_SCHEMA) {
    throw new Error("The live VASI readiness export must be signed.");
  }
  return exported as unknown as AdminTenantReadinessExport;
}

export function readinessExportJSON(value: AdminTenantReadinessExport) {
  return sharedReadinessExportJSON(validateReadinessExport(value));
}

export function renderReadinessDossierHTML(value: AdminTenantReadinessExport) {
  return sharedRenderReadinessDossierHTML(validateReadinessExport(value));
}
