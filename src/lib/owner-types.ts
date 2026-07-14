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

export type WorkflowActivityContent = {
  acknowledgementLabel?: string;
  artifact?: OwnerArtifact;
  artifactId?: string;
  choices?: WorkflowChoice[];
  consentText?: string;
  displayName?: string;
  drawnSignatureLabel?: string;
  instructions?: string;
  labels?: { approved?: string; declined?: string; disapproved?: string };
  maxLength?: number;
  maxSelections?: number;
  methods?: Array<"typed" | "drawn">;
  minLength?: number;
  minSelections?: number;
  multiline?: boolean;
  noLabel?: string;
  passingPercent?: number;
  prompt?: string;
  questions?: WorkflowQuestion[];
  responseLabel?: string;
  resultDisclosure?: "pass_fail" | "pass_fail_and_score";
  statement?: string;
  terms?: string;
  typedNameLabel?: string;
  yesLabel?: string;
};

export type WorkflowActivity = {
  content: WorkflowActivityContent;
  contractVersion?: 1;
  id: string;
  instructions?: string;
  responseMode: "acknowledgement" | "yes_no" | "approval" | "single_choice" |
    "multiple_choice" | "free_form" | "electronic_signature" | "document_review" | "questionnaire";
  title: string;
  transition?: { cases?: { to: string | null; when: { equals: string } }[]; defaultTo?: string | null };
  type: "terms_response" | "approval" | "single_choice" | "multiple_choice" |
    "free_form" | "electronic_signature" | "document_review" | "questionnaire";
};

export type WorkflowDocument = {
  access?: { authentication: "verified_email"; postCompletion: "receipt_only" | "content_until_expiration" | "content_always" };
  activities: WorkflowActivity[];
  instructions?: string;
  notifications?: { onCompletion: boolean; onIssue: boolean; reminderHoursBeforeDue: number[] };
  purpose: string;
  schedule?: { defaultDueDays: number; defaultExpirationDays: number };
  schema?: "vasi-workflow/v1";
  title: string;
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
