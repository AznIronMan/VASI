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
  assignmentId?: string;
  completed: boolean;
  content?: { prompt: string; terms: string };
  contentHash?: string;
  expiresAt?: string;
  interaction?: { id: string; startedAt: string };
  purpose?: string;
  receiptAvailable?: boolean;
  responseMode?: "acknowledgement" | "yes_no";
  tenant?: { id: string; name: string };
  title?: string;
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
  request: { purpose: string; response: string; title: string };
  tenant: { id: string; name: string };
};

export type EngineErrorResponse = { error?: string };
