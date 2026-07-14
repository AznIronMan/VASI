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

export type ParticipantAssignment = {
  activityId?: string;
  assignmentId?: string;
  completed: boolean;
  content?: import("@/lib/owner-types").WorkflowActivityContent;
  contentHash?: string;
  expiresAt?: string;
  interaction?: { id: string; startedAt: string };
  mediaSummary?: import("@/lib/owner-types").MediaSummary;
  instructions?: string;
  progress?: { current: number; total: number };
  purpose?: string;
  receiptAvailable?: boolean;
  responseMode?: import("@/lib/owner-types").WorkflowActivity["responseMode"];
  savedResponse?: unknown;
  savedResponseLabel?: string;
  tenant?: { id: string; name: string };
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
  tenant: { id: string; name: string };
};

export type EngineErrorResponse = { error?: string };
