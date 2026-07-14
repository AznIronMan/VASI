import type { EvidenceTenant, IssuedEvidenceRequest } from "@/lib/evidence-types";

export type OwnerTenant = EvidenceTenant & { permissions: string[] };

export type WorkflowActivity = {
  content: { prompt: string; terms: string };
  contractVersion?: 1;
  id: string;
  instructions?: string;
  responseMode: "acknowledgement" | "yes_no";
  title: string;
  transition?: { cases?: { to: string | null; when: { equals: string } }[]; defaultTo?: string | null };
  type: "terms_response";
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
