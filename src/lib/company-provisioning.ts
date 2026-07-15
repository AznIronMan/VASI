import { emailDomain } from "@/lib/provider-recommendation";

export type CompanyProvisioningInput = {
  commandId: string;
  inviteOwner: boolean;
  name: string;
  ownerEmail: string;
  slug: string;
};

const allowedFields = new Set(["commandId", "inviteOwner", "name", "ownerEmail", "slug"]);

export function validateCompanyProvisioningInput(value: unknown): CompanyProvisioningInput {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new CompanyProvisioningError("The company provisioning request is invalid.");
  }
  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      throw new CompanyProvisioningError(`The company provisioning field ${field} is unsupported.`);
    }
  }

  const input = value as Record<string, unknown>;
  const commandId = typeof input.commandId === "string" ? input.commandId.trim().toLowerCase() : "";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(commandId)) {
    throw new CompanyProvisioningError("The company provisioning command identifier is invalid.");
  }
  const name = safeText(input.name, "Company name", 2, 160);
  const slug = safeText(input.slug, "Company identifier", 2, 64).toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(slug)) {
    throw new CompanyProvisioningError(
      "The company identifier must use lowercase letters, numbers, and interior hyphens.",
    );
  }

  const ownerEmail = typeof input.ownerEmail === "string"
    ? input.ownerEmail.normalize("NFC").trim().toLowerCase()
    : "";
  if (
    ownerEmail.length < 3 || ownerEmail.length > 320 ||
    !/^[^@\s]+@[^@\s]+$/.test(ownerEmail) || !emailDomain(ownerEmail)
  ) {
    throw new CompanyProvisioningError("Enter a valid initial owner email address.");
  }
  if (typeof input.inviteOwner !== "boolean") {
    throw new CompanyProvisioningError("Choose whether to send the initial owner invitation.");
  }

  return Object.freeze({ commandId, inviteOwner: input.inviteOwner, name, ownerEmail, slug });
}

function safeText(value: unknown, label: string, minimum: number, maximum: number) {
  const normalized = typeof value === "string" ? value.normalize("NFC").trim() : "";
  if (
    normalized.length < minimum || normalized.length > maximum ||
    /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new CompanyProvisioningError(
      `${label} must contain ${minimum} to ${maximum} safe characters.`,
    );
  }
  return normalized;
}

export class CompanyProvisioningError extends Error {}
