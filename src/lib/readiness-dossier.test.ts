import { describe, expect, it } from "vitest";

import {
  readinessExportJSON,
  renderReadinessDossierHTML,
  validateReadinessExport,
} from "@/lib/readiness-dossier";
import type { AdminTenantReadinessExport } from "@/lib/owner-types";

const digest = "a".repeat(64);

describe("readiness dossier rendering", () => {
  it("renders inert, printable HTML while preserving the exact embedded dossier", () => {
    const exported = fixture();
    exported.dossier.tenant.name = 'Example <script>alert("x")</script> & Company';
    exported.dossier.limitations = ["Reviewer-supplied <markup> is text only."];
    Object.assign(exported.dossier.tenant.usage.resources.activeRequests, {
      used: '</td><script>alert("quota")</script>',
    });

    const html = renderReadinessDossierHTML(exported);

    expect(html).toContain("Example &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; Company");
    expect(html).not.toContain('<script>alert("x")</script>');
    expect(html).not.toContain('<script>alert("quota")</script>');
    expect(html).toContain('&lt;/td&gt;&lt;script&gt;alert(&quot;quota&quot;)&lt;/script&gt;');
    expect(html).toContain("\\u003cscript\\u003ealert");
    expect(html).toContain(`Dossier SHA-256</dt><dd class="mono">${digest}</dd>`);
    expect(html).toContain('type="application/json" id="vasi-readiness-dossier"');
    expect(html).toContain("default-src 'none'");
  });

  it("produces a newline-terminated machine export and validates its boundary", () => {
    const exported = fixture();
    expect(readinessExportJSON(exported)).toBe(`${JSON.stringify(exported, null, 2)}\n`);
    expect(validateReadinessExport(exported)).toBe(exported);
    expect(() => validateReadinessExport({ ...exported, dossierHash: "not-a-hash" }))
      .toThrow(/invalid readiness export/i);
    expect(() => validateReadinessExport({
      ...exported,
      dossier: { ...exported.dossier, tenant: { ...exported.dossier.tenant, id: "../secret" } },
    })).toThrow(/invalid readiness export/i);
  });
});

function fixture(): AdminTenantReadinessExport {
  return {
    auditEventHash: "b".repeat(64),
    capturedAt: "2026-07-15T20:00:00.000Z",
    dossier: {
      admission: {
        admissionHash: "c".repeat(64),
        gates: [{ id: "exact_release", state: "pending" }],
        revision: 2,
        revisionCreatedAt: "2026-07-15T19:00:00.000Z",
        schema: "vasi-tenant-admission/v1",
        status: "pending",
      },
      installation: {
        adapterPolicy: {
          allowedAdapterIds: ["disabled", "smtp"],
          destinationAllowlistCounts: {
            malwareScannerHosts: 0,
            microsoftGraphClientIds: 0,
            microsoftGraphSenders: 0,
            microsoftGraphTenantIds: 0,
            smtpHosts: 1,
            webhookHosts: 0,
          },
        },
        deployment: {
          engineDatabaseBoundary: "dedicated",
          mode: "self_hosted",
          publicIngress: "gateway_only",
        },
        engineVersion: "0.45.0",
        organizationName: "Example Organization",
        productName: "V·Sign",
        profileHash: "d".repeat(64),
        provisioning: { maxTenants: 1000, mode: "administrators_only" },
        revision: 4,
      },
      integrations: [{
        adapterId: "smtp",
        adapterVersion: "1",
        capability: "notification.delivery",
        configHash: "e".repeat(64),
        configurationWithheld: true,
        revision: 3,
        revisionCreatedAt: "2026-07-15T18:00:00.000Z",
        status: "active",
      }],
      lastProductionStop: null,
      limitations: ["Recorded approvals are not certification."],
      readiness: {
        approvedGateIds: [],
        classification: "recorded_evidence_not_certification",
        externalReviewRequired: true,
        pendingGateIds: ["exact_release"],
        technicalAdmissionStatus: "pending",
      },
      schema: "vasi-tenant-readiness-dossier/v1",
      tenant: {
        id: "11111111-1111-4111-8111-111111111111",
        name: "Example Company",
        profile: {
          defaultRetentionProfile: "tenant_default",
          profileHash: "f".repeat(64),
          quotas: {
            maxActiveRequests: 100,
            maxArtifactBytes: 1000,
            maxArtifactBytesPerArtifact: 100,
            maxIntegrations: 8,
            maxMembers: 20,
            maxWorkflows: 50,
          },
          revision: 3,
        },
        slug: "example-company",
        status: "active",
        usage: {
          profileHash: "f".repeat(64),
          profileRevision: 3,
          resources: {
            activeRequests: { available: 98, limit: 100, used: 2 },
            artifactBytes: { available: 900, limit: 1000, used: 100 },
            integrations: { available: 7, limit: 8, used: 1 },
            members: { available: 17, limit: 20, used: 3 },
            workflows: { available: 46, limit: 50, used: 4 },
          },
          tenantId: "11111111-1111-4111-8111-111111111111",
        },
      },
    },
    dossierHash: digest,
    format: "html",
    schema: "vasi-tenant-readiness-export/v1",
  };
}
