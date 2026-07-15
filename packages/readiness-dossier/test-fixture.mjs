import { hashCanonicalJSON } from "../engine-crypto/index.mjs";
import { TENANT_ADMISSION_GATES } from "../engine-domain/productization.mjs";
import { READINESS_DOSSIER_LIMITATIONS } from "./index.mjs";

export function createReadinessExportFixture(format = "html") {
  const gates = TENANT_ADMISSION_GATES.map((id) => ({ id, state: "pending" }));
  const admission = {
    gates,
    schema: "vasi-tenant-admission/v1",
    status: "pending",
  };
  const tenantId = "11111111-1111-4111-8111-111111111111";
  const tenantProfileHash = "f".repeat(64);
  const dossier = {
    admission: {
      admissionHash: hashCanonicalJSON(admission),
      gates,
      revision: 2,
      revisionCreatedAt: "2026-07-15T19:00:00.000Z",
      schema: admission.schema,
      status: admission.status,
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
      engineVersion: "0.47.0",
      organizationName: "Example Organization",
      productName: "V·Sign",
      profileHash: "d".repeat(64),
      provisioning: { maxTenants: 1_000, mode: "administrators_only" },
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
    limitations: [...READINESS_DOSSIER_LIMITATIONS],
    readiness: {
      approvedGateIds: [],
      classification: "recorded_evidence_not_certification",
      externalReviewRequired: true,
      pendingGateIds: [...TENANT_ADMISSION_GATES],
      technicalAdmissionStatus: "pending",
    },
    schema: "vasi-tenant-readiness-dossier/v1",
    tenant: {
      id: tenantId,
      name: "Example Company",
      profile: {
        defaultRetentionProfile: "tenant_default",
        profileHash: tenantProfileHash,
        quotas: {
          maxActiveRequests: 100,
          maxArtifactBytes: 2_000_000,
          maxArtifactBytesPerArtifact: 100_000,
          maxIntegrations: 8,
          maxMembers: 20,
          maxWorkflows: 50,
        },
        revision: 3,
      },
      slug: "example-company",
      status: "active",
      usage: {
        profileHash: tenantProfileHash,
        profileRevision: 3,
        resources: {
          activeRequests: { available: 98, limit: 100, used: 2 },
          artifactBytes: { available: 1_999_900, limit: 2_000_000, used: 100 },
          integrations: { available: 7, limit: 8, used: 1 },
          members: { available: 17, limit: 20, used: 3 },
          workflows: { available: 46, limit: 50, used: 4 },
        },
        tenantId,
      },
    },
  };
  return {
    auditEventHash: "b".repeat(64),
    capturedAt: "2026-07-15T20:00:00.000Z",
    dossier,
    dossierHash: hashCanonicalJSON(dossier),
    format,
    schema: "vasi-tenant-readiness-export/v1",
  };
}
