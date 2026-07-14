import type { EvidenceTenant, IssuedEvidenceRequest } from "@/lib/evidence-types";

export type OwnerTenant = EvidenceTenant & { permissions: string[] };

export type OwnerArtifact = {
  byteLength?: number;
  chunkCount?: number;
  createdAt: string;
  expectedByteLength: number;
  familyId: string;
  id: string;
  inspectionProfile?: string;
  inspectionResult?: { limitation?: string; rejectionCode?: string };
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
  access?: { authentication: "verified_email"; postCompletion: "receipt_only" | "content_until_expiration" | "content_always" };
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
  reissuedFromRequestId?: string;
  revision: number;
  scheduledFor?: string;
  snapshotHash?: string;
  status: string;
  title: string;
  workflowRevisionId: string;
};
