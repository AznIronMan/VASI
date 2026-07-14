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
  content?: { prompt: string; terms: string };
  contentHash?: string;
  expiresAt?: string;
  interaction?: { id: string; startedAt: string };
  instructions?: string;
  progress?: { current: number; total: number };
  purpose?: string;
  receiptAvailable?: boolean;
  responseMode?: "acknowledgement" | "yes_no";
  tenant?: { id: string; name: string };
  title?: string;
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
    activities?: Array<{ content: { prompt: string; terms: string }; id: string; title: string }>;
    contentAccess?: { available: boolean; policy: string };
    purpose: string;
    response: string;
    responses?: Array<{ activityId: string; response: string }>;
    title: string;
  };
  tenant: { id: string; name: string };
};

export type EngineErrorResponse = { error?: string };
