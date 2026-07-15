import { authorizeAdminMutation } from "@/lib/admin-access";
import { boundedJSONObject } from "@/lib/bounded-json";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import {
  readinessExportJSON,
  renderReadinessDossierHTML,
  validateReadinessExport,
} from "@/lib/readiness-dossier";
import type { AdminTenantReadinessExport } from "@/lib/owner-types";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const result = await requestEngineAction<AdminTenantReadinessExport>(
    await buildEngineActor(authorization.session, request.headers),
    { body: parsed.value, method: "POST", path: "/v1/admin/tenant-readiness-exports" },
  );
  if (result.status < 200 || result.status >= 300) return gatewayEngineResponse(result);

  let exported: AdminTenantReadinessExport;
  let content: string;
  try {
    exported = validateReadinessExport(result.body);
    if (exported.format !== parsed.value.format) throw new Error("format mismatch");
    content = exported.format === "html"
      ? renderReadinessDossierHTML(exported)
      : readinessExportJSON(exported);
  } catch {
    return Response.json(
      { error: "The private VASI engine returned an invalid readiness export." },
      { status: 502 },
    );
  }

  const extension = exported.format;
  const integrityKeyFingerprint = exported.attestation.signingKeys.find(
    (key) => key.role === "vasi_integrity",
  )!.fingerprint;
  return new Response(content, {
    headers: {
      "cache-control": "no-store",
      "content-disposition": `attachment; filename="vasi-readiness-${exported.dossier.tenant.id}.${extension}"`,
      "content-security-policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'",
      "content-type": exported.format === "html"
        ? "text/html; charset=utf-8"
        : "application/json; charset=utf-8",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-vasi-dossier-sha256": exported.dossierHash,
      "x-vasi-integrity-key-sha256": integrityKeyFingerprint,
    },
  });
}
