import { authorizeAdminHeaders, authorizeAdminMutation } from "@/lib/admin-access";
import {
  CompanyProvisioningError,
  validateCompanyProvisioningInput,
} from "@/lib/company-provisioning";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { EvidenceTenant } from "@/lib/evidence-types";
import { createInvitation, InvitationError } from "@/lib/invitations";
import type {
  AdminCompanyProvisioningResult,
  OwnerInvitationOutcome,
  ProvisionedCompany,
} from "@/lib/owner-types";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const authorization = await authorizeAdminHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const result = await requestEngineAction<EvidenceTenant[]>(
    await buildEngineActor(authorization.session, request.headers),
    { method: "GET", path: "/v1/owner/tenants" },
  );
  return gatewayEngineResponse(result);
}

export async function POST(request: Request) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;

  let input;
  try {
    input = validateCompanyProvisioningInput(await request.json());
  } catch (error) {
    const message = error instanceof CompanyProvisioningError
      ? error.message
      : "The company provisioning request is invalid.";
    return Response.json({ error: message }, { status: 400 });
  }

  const result = await requestEngineAction<ProvisionedCompany>(
    await buildEngineActor(authorization.session, request.headers),
    {
      body: { name: input.name, ownerEmail: input.ownerEmail, slug: input.slug },
      method: "POST",
      path: "/v1/owner/tenants",
    },
  );
  if (result.status < 200 || result.status >= 300 || !result.body) {
    return gatewayEngineResponse(result);
  }

  const invitation = await inviteInitialOwner({
    actorEmail: authorization.session.user.email,
    actorUserId: authorization.session.user.id,
    inviteOwner: input.inviteOwner,
    ownerEmail: input.ownerEmail,
  });
  const response: AdminCompanyProvisioningResult = {
    company: result.body,
    invitation,
  };
  return Response.json(response, { status: 201 });
}

async function inviteInitialOwner({
  actorEmail,
  actorUserId,
  inviteOwner,
  ownerEmail,
}: {
  actorEmail: string;
  actorUserId: string;
  inviteOwner: boolean;
  ownerEmail: string;
}): Promise<OwnerInvitationOutcome> {
  if (!inviteOwner) return { status: "skipped" };
  if (ownerEmail === actorEmail.toLowerCase()) return { status: "not_required" };
  try {
    const invitation = await createInvitation(ownerEmail, actorUserId);
    return { expiresAt: invitation.expiresAt, status: "sent" };
  } catch (error) {
    if (error instanceof InvitationError && error.status === 409) {
      return { status: "existing_account" };
    }
    return { status: "delivery_failed" };
  }
}
