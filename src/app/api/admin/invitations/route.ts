import { authorizeAdminMutation } from "@/lib/admin-access";
import {
  beginAdminAuditCommand,
  finishAdminAuditCommand,
} from "@/lib/admin-audit";
import { createInvitation, InvitationError } from "@/lib/invitations";

export async function POST(request: Request) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;

  let body: { email?: unknown };
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid request." }, { status: 400 });
  }

  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const command = await beginAdminAuditCommand({
    action: "invitation.create",
    metadata: { targetEmail: email.slice(0, 320) },
    request,
    session: authorization.session,
  }).catch(() => undefined);
  if (!command) {
    return Response.json(
      { error: "The invitation was not attempted because its audit command could not be recorded." },
      { status: 503 },
    );
  }

  try {
    const invitation = await createInvitation(
      email,
      authorization.session.user.id,
    );
    try {
      await finishAdminAuditCommand(command, "succeeded", {
        deliveryOutcome: "provider_accepted",
        invitationId: invitation.id,
      });
    } catch {
      return Response.json(
        { error: "The invitation was accepted by the provider, but its terminal audit event is unavailable. Review the incomplete command before retrying." },
        { status: 503 },
      );
    }
    return Response.json({ invitation }, { status: 201 });
  } catch (error) {
    if (error instanceof InvitationError) {
      await finishAdminAuditCommand(
        command,
        error.code === "delivery_unknown" ? "ambiguous" : "failed",
        { failureCode: error.code },
      ).catch(() => undefined);
      return Response.json({ error: error.message }, { status: error.status });
    }
    await finishAdminAuditCommand(
      command,
      "ambiguous",
      { failureCode: "unclassified_invitation_outcome" },
    ).catch(() => undefined);
    return Response.json(
      { error: "The invitation could not be delivered." },
      { status: 502 },
    );
  }
}
