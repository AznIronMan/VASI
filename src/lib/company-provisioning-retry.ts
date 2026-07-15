export type CompanyProvisioningDraft = {
  inviteOwner: boolean;
  name: string;
  ownerEmail: string;
  slug: string;
};

export type CompanyProvisioningRetry = {
  commandId: string;
  fingerprint: string;
};

export function nextCompanyProvisioningCommand(
  previous: CompanyProvisioningRetry | undefined,
  draft: CompanyProvisioningDraft,
  createCommandId: () => string,
): CompanyProvisioningRetry {
  const fingerprint = JSON.stringify({
    inviteOwner: draft.inviteOwner,
    name: draft.name.normalize("NFC").trim(),
    ownerEmail: draft.ownerEmail.normalize("NFC").trim().toLowerCase(),
    slug: draft.slug.normalize("NFC").trim().toLowerCase(),
  });
  if (previous?.fingerprint === fingerprint) return previous;
  return Object.freeze({ commandId: createCommandId(), fingerprint });
}
