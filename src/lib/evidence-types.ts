export type EvidenceTenant = {
  id: string;
  name: string;
  roles: string[];
  slug: string;
};

export type IssuedEvidenceRequest = {
  assignmentId: string;
  expiresAt: string;
  participantPath: string;
  requestId: string;
  tenantId: string;
};

export type TenantBranding = {
  accentColor: string;
  displayName: string;
  primaryColor: string;
  shortName: string;
  supportEmail?: string | null;
};

export type ParticipantAssignment = {
  activityId?: string;
  assignmentId?: string;
  completed: boolean;
  content?: import("@/lib/owner-types").WorkflowActivityContent;
  contentHash?: string;
  expiresAt?: string;
  interaction?: { id: string; startedAt: string };
  interactionEvidence?: {
    policy: import("@/lib/owner-types").ActivityInteractionPolicy;
    summary?: import("@/lib/owner-types").ActivityInteractionSummary;
  };
  mediaSummary?: import("@/lib/owner-types").MediaSummary;
  instructions?: string;
  progress?: { current: number; total: number };
  purpose?: string;
  receiptAvailable?: boolean;
  responseMode?: import("@/lib/owner-types").WorkflowActivity["responseMode"];
  savedResponse?: unknown;
  savedResponseLabel?: string;
  tenant?: { branding?: TenantBranding; id: string; name: string };
  title?: string;
  type?: import("@/lib/owner-types").WorkflowActivity["type"];
  workflowTitle?: string;
};

export type OpenParticipantAssignment = ParticipantAssignment & Required<Pick<
  ParticipantAssignment,
  "assignmentId" | "content" | "contentHash" | "expiresAt" | "interaction" |
  "purpose" | "responseMode" | "tenant" | "title"
>>;

export type ParticipantReceipt = {
  assignmentId: string;
  completedAt: string;
  integrity: {
    algorithm: string;
    keyId: string;
    manifestHash: string;
    profile: string;
    verified: boolean;
  };
  issuedAt: string;
  request: {
    activities?: Array<import("@/lib/owner-types").WorkflowActivity>;
    contentAccess?: { available: boolean; policy: string };
    purpose: string;
    response: string;
    responses?: Array<{ activityId: string; outcome?: string; response: unknown; responseLabel?: string; result?: unknown }>;
    title: string;
  };
  tenant: {
    id: string;
    name: string;
    profile?: { branding?: TenantBranding };
  };
};

export type EngineErrorResponse = { error?: string };

export type ParticipantHistoryRecord = {
  assignmentId: string;
  completedAt?: string;
  evidence: { archived: boolean; manifestFingerprint?: string; reportAvailable: boolean };
  expiresAt: string;
  firstOpenedAt?: string;
  issuedAt: string;
  lifecycle: {
    archiveAt?: string;
    contentAvailable: boolean;
    contentExpiresAt?: string;
    deleteAt?: string;
    historyExpiresAt?: string;
  };
  purpose: string;
  requestId: string;
  sender: { email?: string; relationship: "requesting_organization" };
  status: string;
  tenant: { id: string; name: string };
  title: string;
  workflow: { id: string; revision: number; snapshotHash: string };
};

export type ParticipantDataRequest = {
  expiresAt: string;
  export?: {
    byteLength: number;
    chunkCount: number;
    createdAt: string;
    expiresAt: string;
    filename: string;
    id: string;
    mediaType: string;
    profile: string;
    sha256: string;
  };
  id: string;
  requestedAt: string;
  reviewCompletedAt?: string;
  scopes: Array<{
    matchedRecordCount: number;
    reviewReason?: string;
    reviewedAt?: string;
    status: "pending_review" | "approved" | "denied";
    tenant: { id: string; name: string };
  }>;
  status: "pending_review" | "approved" | "partially_approved" | "denied" | "ready" | "expired" | "cancelled";
};
