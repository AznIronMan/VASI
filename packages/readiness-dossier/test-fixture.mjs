import { createPublicKey, generateKeyPairSync } from "node:crypto";

import {
  createCertificateSeal,
  createDetachedIntegritySeal,
  hashCanonicalJSON,
} from "../engine-crypto/index.mjs";
import { TENANT_ADMISSION_GATES } from "../engine-domain/productization.mjs";
import {
  createReadinessAttestation,
  READINESS_DOSSIER_LIMITATIONS,
  READINESS_DOSSIER_SEAL_PROFILE,
  SIGNED_READINESS_EXPORT_SCHEMA,
} from "./index.mjs";

export function createReadinessExportFixture(
  format = "html",
  {
    admissionEvidence,
    certificateChainPEM,
    certificatePrivateKeyPEM,
    legacy = false,
    tenantName = "Example Company",
  } = {},
) {
  const evidenceByGate = admissionEvidence
    ? new Map(admissionEvidence.map((entry) => [entry.gateId, entry]))
    : null;
  if (evidenceByGate && (
    evidenceByGate.size !== TENANT_ADMISSION_GATES.length ||
    TENANT_ADMISSION_GATES.some((id) => !evidenceByGate.has(id))
  )) throw new Error("The readiness fixture admission evidence is incomplete.");
  const gates = TENANT_ADMISSION_GATES.map((id) => evidenceByGate
    ? {
        decidedAt: evidenceByGate.get(id).decidedAt || "2026-07-15T19:30:00.000Z",
        evidenceDigest: evidenceByGate.get(id).evidenceDigest,
        evidenceReference: evidenceByGate.get(id).evidenceReference,
        id,
        reviewerReference: evidenceByGate.get(id).reviewerReference,
        state: "approved",
      }
    : { id, state: "pending" });
  const admission = {
    gates,
    schema: "vasi-tenant-admission/v1",
    status: evidenceByGate ? "admitted" : "pending",
  };
  const tenantId = "11111111-1111-4111-8111-111111111111";
  const tenantProfileHash = "f".repeat(64);
  const dossier = {
    admission: {
      admissionHash: hashCanonicalJSON(admission),
      gates,
      revision: 2,
      revisionCreatedAt: evidenceByGate
        ? "2026-07-15T19:45:00.000Z"
        : "2026-07-15T19:00:00.000Z",
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
      engineVersion: legacy ? "0.47.0" : "0.55.1",
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
      approvedGateIds: evidenceByGate ? [...TENANT_ADMISSION_GATES] : [],
      classification: "recorded_evidence_not_certification",
      externalReviewRequired: true,
      pendingGateIds: evidenceByGate ? [] : [...TENANT_ADMISSION_GATES],
      technicalAdmissionStatus: evidenceByGate ? "admitted" : "pending",
    },
    schema: "vasi-tenant-readiness-dossier/v1",
    tenant: {
      id: tenantId,
      name: tenantName,
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
  const base = {
    auditEventHash: "b".repeat(64),
    capturedAt: "2026-07-15T20:00:00.000Z",
    dossier,
    dossierHash: hashCanonicalJSON(dossier),
    format,
  };
  if (legacy) return { ...base, schema: "vasi-tenant-readiness-export/v1" };
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateJWK = privateKey.export({ format: "jwk" });
  const publicJWK = createPublicKey(privateKey).export({ format: "jwk" });
  const signingKeys = [{
    fingerprint: hashCanonicalJSON({ publicJWK }),
    keyId: "fixture-readiness-key",
    role: "vasi_integrity",
  }];
  let certificate;
  if (certificateChainPEM || certificatePrivateKeyPEM) {
    if (!certificateChainPEM || !certificatePrivateKeyPEM) throw new Error("Incomplete fixture certificate.");
    certificate = createCertificateSeal({
      certificateChainPEM,
      keyId: "fixture-certificate-key",
      payload: { schema: "vasi-readiness-fixture-certificate/v1" },
      privateKeyPEM: certificatePrivateKeyPEM,
    });
    signingKeys.push({
      fingerprint: hashCanonicalJSON({
        certificateChain: certificate.certificateChain,
        publicJWK: certificate.publicJWK,
      }),
      keyId: certificate.keyId,
      role: "certificate",
    });
  }
  const attestation = createReadinessAttestation({ ...base, signingKeys });
  const seals = [{
    ...createDetachedIntegritySeal({
      keyId: signingKeys[0].keyId,
      payload: attestation,
      privateJWK,
      profile: READINESS_DOSSIER_SEAL_PROFILE,
    }),
    role: "vasi_integrity",
  }];
  if (certificate) {
    seals.push({
      ...createCertificateSeal({
        certificateChainPEM,
        keyId: certificate.keyId,
        payload: attestation,
        privateKeyPEM: certificatePrivateKeyPEM,
      }),
      role: "certificate",
    });
  }
  return { ...base, attestation, schema: SIGNED_READINESS_EXPORT_SCHEMA, seals };
}
