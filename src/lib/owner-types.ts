import type { EvidenceTenant, IssuedEvidenceRequest } from "@/lib/evidence-types";

export type OwnerTenant = EvidenceTenant & { permissions: string[] };

export type TenantProfile = {
  branding: {
    accentColor: string;
    displayName: string;
    primaryColor: string;
    shortName: string;
    supportEmail: string | null;
  };
  policies: { defaultRetentionProfile: string };
  quotas: {
    maxActiveRequests: number;
    maxArtifactBytes: number;
    maxArtifactBytesPerArtifact: number;
    maxIntegrations: number;
    maxMembers: number;
    maxWorkflows: number;
  };
  schema: "vasi-tenant-profile/v1";
};

export type OwnerTenantProfile = {
  id: string;
  profile: TenantProfile;
  profileHash: string;
  revision: number;
};

export type OwnerTenantUsage = {
  profileHash: string;
  profileRevision: number;
  resources: Record<"activeRequests" | "artifactBytes" | "integrations" | "members" | "workflows", {
    available: number;
    limit: number;
    used: number;
  }>;
  tenantId: string;
};

export type OwnerIntegration = {
  adapterId: "disabled" | "https_malware_scanner" | "microsoft_graph" | "scan_disabled" | "smtp" | "webhook";
  adapterVersion: string;
  capability: "document.malware_scan" | "notification.delivery";
  config: {
    clientId?: string;
    from?: string;
    host?: string;
    port?: number;
    secure?: boolean;
    senderEmail?: string;
    tenantId?: string;
    timeoutSeconds?: number;
    url?: string;
    username?: string;
  };
  configHash: string;
  configuredCredentials: boolean;
  createdAt: string;
  id: string;
  revision: number;
  status: "active" | "disabled";
};

export type InstallationProfile = {
  adapters: {
    allow: Array<"disabled" | "https_malware_scanner" | "microsoft_graph" | "scan_disabled" | "smtp" | "webhook">;
    malwareScannerAllowedHosts?: string[];
    microsoftGraphAllowedClientIds?: string[];
    microsoftGraphAllowedSenders?: string[];
    microsoftGraphAllowedTenantIds?: string[];
    smtpAllowedHosts: string[];
    webhookAllowedHosts: string[];
  };
  deployment: {
    engineDatabaseBoundary: "dedicated";
    mode: "self_hosted" | "saas";
    publicIngress: "gateway_only";
  };
  product: { organizationName: string; productName: string; supportEmail: string };
  provisioning: { maxTenants: number; mode: "administrators_only" };
  schema: "vasi-installation-profile/v1";
};

export type AdminInstallationProfile = {
  id: string;
  profile: InstallationProfile;
  profileHash: string;
  revision: number;
};

export type TenantAdmissionGateId =
  | "exact_release"
  | "isolation_integrity"
  | "identity_delivery"
  | "privacy_legal"
  | "accessibility"
  | "malware_content"
  | "recovery_custody"
  | "capacity_support";

export type TenantAdmissionGate = {
  decidedAt?: string;
  evidenceDigest?: string;
  evidenceReference?: string;
  id: TenantAdmissionGateId;
  reviewerReference?: string;
  state: "approved" | "pending";
};

export type TenantProductionStopReason =
  | "security_incident"
  | "privacy_or_legal"
  | "identity_or_delivery"
  | "content_safety"
  | "recovery_or_capacity"
  | "operator_decision";

export type TenantProductionStop = {
  admissionChanged: boolean;
  commandId: string;
  eventHash: string;
  gateId: TenantAdmissionGateId;
  incidentReference: string;
  reasonCode: TenantProductionStopReason;
  revokedAssignmentCount: number;
  resultingAdmissionRevision: number;
  resultingAdmissionStatus: "admitted" | "pending";
  revokedRequestCount: number;
  stoppedAt: string;
  stoppedByPrincipalId: string;
  suppressedNotificationCount: number;
};

export type AdminTenantAdmission = {
  admission: {
    gates: TenantAdmissionGate[];
    schema: "vasi-tenant-admission/v1";
    status: "admitted" | "pending";
  };
  admissionHash: string;
  createdAt: string;
  createdByPrincipalId: string;
  id: string;
  lastProductionStop?: TenantProductionStop;
  revision: number;
  status: "admitted" | "pending";
  tenant: { id: string; name: string; slug: string };
};

export type TenantReadinessDossier = {
  admission: {
    admissionHash: string;
    gates: TenantAdmissionGate[];
    revision: number;
    revisionCreatedAt: string;
    schema: "vasi-tenant-admission/v1";
    status: "admitted" | "pending";
  };
  installation: {
    adapterPolicy: {
      allowedAdapterIds: OwnerIntegration["adapterId"][];
      destinationAllowlistCounts: {
        malwareScannerHosts: number;
        microsoftGraphClientIds: number;
        microsoftGraphSenders: number;
        microsoftGraphTenantIds: number;
        smtpHosts: number;
        webhookHosts: number;
      };
    };
    deployment: InstallationProfile["deployment"];
    engineVersion: string;
    organizationName: string;
    productName: string;
    profileHash: string;
    provisioning: InstallationProfile["provisioning"];
    revision: number;
  };
  integrations: Array<{
    adapterId: OwnerIntegration["adapterId"];
    adapterVersion: string;
    capability: OwnerIntegration["capability"];
    configHash: string;
    configurationWithheld: true;
    revision: number;
    revisionCreatedAt: string;
    status: OwnerIntegration["status"];
  }>;
  lastProductionStop: null | {
    effects: {
      revokedAssignmentCount: number;
      revokedRequestCount: number;
      suppressedNotificationCount: number;
    };
    eventHash: string;
    gateId: TenantAdmissionGateId;
    reasonCode: TenantProductionStopReason;
    resultingAdmissionRevision: number;
    resultingAdmissionStatus: "admitted" | "pending";
    stoppedAt: string;
  };
  limitations: string[];
  readiness: {
    approvedGateIds: TenantAdmissionGateId[];
    classification: "recorded_evidence_not_certification";
    externalReviewRequired: true;
    pendingGateIds: TenantAdmissionGateId[];
    technicalAdmissionStatus: "admitted" | "pending";
  };
  schema: "vasi-tenant-readiness-dossier/v1";
  tenant: {
    id: string;
    name: string;
    profile: {
      defaultRetentionProfile: string;
      profileHash: string;
      quotas: TenantProfile["quotas"];
      revision: number;
    };
    slug: string;
    status: string;
    usage: OwnerTenantUsage;
  };
};

export type AdminTenantReadinessExport = {
  attestation: {
    auditEventHash: string;
    capturedAt: string;
    dossierHash: string;
    dossierSchema: "vasi-tenant-readiness-dossier/v1";
    exportSchema: "vasi-tenant-readiness-export/v2";
    format: "html" | "json";
    schema: "vasi-tenant-readiness-attestation/v1";
    signingKeys: Array<{
      fingerprint: string;
      keyId: string;
      role: "certificate" | "vasi_integrity";
    }>;
  };
  auditEventHash: string;
  capturedAt: string;
  dossier: TenantReadinessDossier;
  dossierHash: string;
  format: "html" | "json";
  schema: "vasi-tenant-readiness-export/v2";
  seals: Array<{
    algorithm: string;
    certificate?: {
      fingerprint256: string;
      issuer: string;
      serialNumber: string;
      subject: string;
      validFrom: string;
      validTo: string;
    };
    certificateChain?: string[];
    keyId: string;
    manifestHash: string;
    profile: "vasi-certificate-seal/v1" | "vasi-readiness-dossier-seal/v1";
    publicJWK: Record<string, unknown>;
    role: "certificate" | "vasi_integrity";
    signature: string;
    validationScope?: "leaf_signature_and_key_match";
  }>;
};

export type ProvisionedCompany = OwnerTenant & {
  admission: Omit<AdminTenantAdmission, "tenant">;
  owner: { email: string | null; grantCreated: boolean };
  profile: OwnerTenantProfile;
};

export type OwnerInvitationOutcome = {
  expiresAt?: string;
  status: "sent" | "existing_account" | "not_required" | "skipped" | "delivery_failed" | "delivery_unknown";
};

export type AdminCompanyProvisioningResult = {
  company: ProvisionedCompany;
  invitation: OwnerInvitationOutcome;
};

export type OwnerArtifact = {
  byteLength?: number;
  chunkCount?: number;
  createdAt: string;
  expectedByteLength: number;
  familyId: string;
  id: string;
  inspectionProfile?: string;
  inspectionResult?: {
    external?: {
      adapter?: string;
      errorCode?: string;
      status?: "completed" | "unavailable";
      verdict?: "clean" | "malicious" | "suspicious";
    };
    limitation?: string;
    rejectionCode?: string;
    retryable?: boolean;
  };
  inspectionStatus: "pending" | "passed" | "rejected";
  mediaType: string;
  originalFilename: string;
  publishedAt?: string;
  rejectedAt?: string;
  replacesArtifactId?: string;
  retentionPolicy: { profile: string };
  revision: number;
  role: string;
  sha256?: string;
  sourceArtifactId?: string;
  status: "quarantined" | "published" | "rejected";
  tenantId: string;
};

export type WorkflowChoice = { description?: string; id: string; label: string };
export type WorkflowQuestion = {
  choices: WorkflowChoice[];
  correctChoiceIds?: string[];
  id: string;
  points?: number;
  prompt: string;
  required?: boolean;
  type: "single_choice" | "multiple_choice";
};

export type ExternalMediaDescriptor = {
  accessMode: "public" | "provider_shared" | "provider_authenticated";
  adapter?: { id: string; version: string };
  allowedOrigins?: string[];
  capability?: "instrumented_player" | "version_aware_preview" | "generic_embed" | "external_link";
  description?: string;
  descriptorHash?: string;
  dimensions?: { height: number; width: number };
  durationMilliseconds?: number;
  durationSeconds?: number;
  embedUrl?: string;
  id?: string;
  itemId?: string;
  kind: "image" | "video" | "audio" | "presentation" | "document";
  limitations?: string[];
  metadataProvenance?: string;
  owner?: string;
  provider: "youtube" | "vimeo" | "sharepoint" | "google_drive" | "dropbox" | "generic" | "external_link";
  sourceUrl: string;
  title: string;
  version?: { cTag?: string; checksum?: string; eTag?: string; id?: string; lastModifiedAt?: string };
};

export type MediaSummary = {
  calculation: { clock: string; policyVersion: string; telemetryPolicy: { heartbeatSeconds: number; idleSeconds: number; maxCreditedGapSeconds: number } };
  capability: string;
  confidence: { level: "none" | "low" | "medium"; limitations: string[] };
  engagement: { engagedMilliseconds: number; openMilliseconds: number; visibleMilliseconds: number };
  eventCount: number;
  gaps: { count: number; uncreditedMilliseconds: number };
  playback: {
    completionMet: boolean;
    durationMilliseconds?: number;
    durationSource: string;
    endedObserved: boolean;
    percentBasisPoints: number;
    providerErrorCount: number;
    seekCount: number;
    skippedMilliseconds: number;
    thresholdPercent: number;
    uniqueMilliseconds: number;
  };
  schema: "vasi-media-summary/v1";
  sessionCount: number;
  sessionIntegrity: { disconnectCount: number; incompleteSessionCount: number };
};

export type ActivityInteractionPolicy = {
  heartbeatSeconds: number;
  idleSeconds: number;
  maxCreditedGapSeconds: number;
  version: "vasi-activity-interaction-policy/v1";
};

export type ActivityInteractionSummary = {
  calculation: {
    clock: "browser_monotonic";
    policyVersion: string;
    telemetryPolicy: Omit<ActivityInteractionPolicy, "version">;
  };
  confidence: { level: "low" | "medium"; limitations: string[] };
  events: {
    count: number;
    firstClientOccurredAt?: string;
    firstReceivedAt?: string;
    focusCount: number;
    heartbeatCount: number;
    interactionCount: number;
    lastClientOccurredAt?: string;
    lastReceivedAt?: string;
    presentedCount: number;
    visibleCount: number;
  };
  schema: "vasi-activity-interaction-summary/v1";
  sessions: { count: number; disconnectCount: number; incompleteCount: number };
  timing: {
    backgroundOrHiddenMilliseconds: number;
    engagedMilliseconds: number;
    foregroundVisibleMilliseconds: number;
    idleForegroundMilliseconds: number;
    openMilliseconds: number;
    uncreditedGapMilliseconds: number;
  };
};

export type WorkflowActivityContent = {
  artifact?: OwnerArtifact;
  artifactId?: string;
  accessibilityAlternative?: { label: string; url?: string };
  acknowledgementLabel?: string;
  choices?: WorkflowChoice[];
  consentText?: string;
  displayName?: string;
  descriptor?: ExternalMediaDescriptor;
  drawnSignatureLabel?: string;
  instructions?: string;
  labels?: { approved?: string; declined?: string; disapproved?: string };
  maxLength?: number;
  maxSelections?: number;
  completionPolicy?: { minimumUniqueSeconds: number; mode: "playback" | "acknowledgement" | "playback_or_acknowledgement"; thresholdPercent: number };
  methods?: Array<"typed" | "drawn">;
  minLength?: number;
  minSelections?: number;
  multiline?: boolean;
  noLabel?: string;
  passingPercent?: number;
  prompt?: string;
  questions?: WorkflowQuestion[];
  responseLabel?: string;
  providerNotice?: string;
  resultDisclosure?: "pass_fail" | "pass_fail_and_score";
  statement?: string;
  terms?: string;
  typedNameLabel?: string;
  telemetryPolicy?: { heartbeatSeconds: number; idleSeconds: number; maxCreditedGapSeconds: number };
  yesLabel?: string;
};

export type WorkflowActivity = {
  content: WorkflowActivityContent;
  contractVersion?: 1;
  id: string;
  instructions?: string;
  responseMode: "acknowledgement" | "yes_no" | "approval" | "single_choice" |
    "multiple_choice" | "free_form" | "electronic_signature" | "document_review" | "questionnaire" |
    "external_media";
  title: string;
  transition?: { cases?: { to: string | null; when: { equals: string } }[]; defaultTo?: string | null };
  type: "terms_response" | "approval" | "single_choice" | "multiple_choice" |
    "free_form" | "electronic_signature" | "document_review" | "questionnaire" | "external_media";
};

export type WorkflowDocument = {
  access?: {
    authentication: "verified_email";
    authenticationAssurance?: {
      acceptedMethods: Array<"any_verified" | "federated" | "password" | "email_verification">;
      maximumAgeSeconds: number | null;
    };
    postCompletion: "receipt_only" | "content_until_expiration" | "content_always";
  };
  activities: WorkflowActivity[];
  instructions?: string;
  notifications?: { onCompletion: boolean; onIssue: boolean; reminderHoursBeforeDue: number[] };
  purpose: string;
  retention?: { profile: string };
  schedule?: { defaultDueDays: number; defaultExpirationDays: number };
  schema?: "vasi-workflow/v1";
  title: string;
};

export type RetentionPolicy = {
  contentAccess: { daysAfterTerminal?: number; mode: "days_after_terminal" | "indefinite" | "request_expiration" };
  evidence: { archiveAfterDays: number | null; deleteAfterDays: number | null };
  participantHistory: { daysAfterTerminal: number | null };
  schema: "vasi-retention-policy/v1";
};

export type OwnerRetentionPolicy = {
  createdAt?: string;
  createdByPrincipalId?: string;
  id: string | null;
  name: string;
  policy: RetentionPolicy;
  policyHash: string;
  revision: number;
  source: "system_default" | "tenant";
};

export type OwnerLegalHold = {
  caseReference: string;
  id: string;
  placedAt: string;
  placedByPrincipalId?: string;
  reason: string;
  releaseReason?: string;
  releasedAt?: string;
};

export type OwnerLifecycleRecord = {
  archiveAt?: string;
  assignmentId: string;
  assignmentStatus: string;
  contentExpiresAt?: string;
  contentStatus: "active" | "expired";
  deleteAt?: string;
  evidenceStatus: "active" | "archived" | "purge_due";
  historyExpiresAt?: string;
  historyStatus: "active" | "expired";
  holds: OwnerLegalHold[];
  intendedEmail: string;
  participantEmail?: string;
  policy: RetentionPolicy;
  policyHash: string;
  policyRevisionId?: string;
  requestId: string;
  requestStatus: string;
  tenantId: string;
  terminalAt: string;
  title: string;
};

export type OwnerDataRequestReview = {
  expiresAt: string;
  matchedRecordCount: number;
  requestId: string;
  requesterEmail: string;
  requestedAt: string;
  requestStatus: string;
  reviewPolicy?: Record<string, unknown>;
  reviewReason?: string;
  reviewedAt?: string;
  status: "pending_review" | "approved" | "denied";
  tenantId: string;
};

export type OwnerWorkflow = {
  definitionId: string;
  document: WorkflowDocument;
  documentHash: string;
  draftVersion: number;
  name: string;
  publishedRevision: number | null;
  publishedRevisionId?: string;
  publishedSnapshotHash?: string;
  status: "draft" | "active" | "archived";
  tenantId: string;
  updatedAt: string;
};

export type PublishedWorkflow = {
  definitionId: string;
  publishedAt: string;
  revision: number;
  revisionId: string;
  snapshotHash: string;
  tenantId: string;
};

export type OwnerNotificationDeliveryState = {
  adapter?: string;
  attempts: number;
  availableAt: string;
  completedAt?: string;
  errorCode?: string;
  status: "scheduled" | "queued" | "processing" | "provider_accepted" | "suppressed" | "failed" | "indeterminate";
  totalJobs: number;
  updatedAt: string;
};

export type OwnerMember = {
  email?: string;
  principalId?: string;
  roles: string[];
  source: string;
  status: "active" | "disabled";
};

export type OwnerRequest = Omit<IssuedEvidenceRequest, "participantPath" | "tenantId"> & {
  assignmentStatus: string;
  completedAt?: string;
  dueAt?: string;
  intendedEmail: string;
  issuedAt: string;
  notificationDelivery: Partial<Record<"invitation" | "reminder" | "completion", OwnerNotificationDeliveryState>>;
  reissuedFromRequestId?: string;
  revision: number;
  scheduledFor?: string;
  snapshotHash?: string;
  status: string;
  title: string;
  workflowRevisionId: string;
};
