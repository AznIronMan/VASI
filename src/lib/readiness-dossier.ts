import {
  readinessExportJSON as sharedReadinessExportJSON,
  renderReadinessDossierHTML as sharedRenderReadinessDossierHTML,
  validateReadinessExport as sharedValidateReadinessExport,
} from "../../packages/readiness-dossier/index.mjs";

import type { AdminTenantReadinessExport } from "@/lib/owner-types";

export function validateReadinessExport(value: unknown): AdminTenantReadinessExport {
  return sharedValidateReadinessExport(value) as unknown as AdminTenantReadinessExport;
}

export function readinessExportJSON(value: AdminTenantReadinessExport) {
  return sharedReadinessExportJSON(value);
}

export function renderReadinessDossierHTML(value: AdminTenantReadinessExport) {
  return sharedRenderReadinessDossierHTML(value);
}
