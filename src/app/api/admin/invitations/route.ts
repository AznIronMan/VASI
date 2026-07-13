import { authorizeAdminMutation } from "@/lib/admin-access";
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

  try {
    const invitation = await createInvitation(
      typeof body.email === "string" ? body.email : "",
      authorization.session.user.id,
    );
    return Response.json({ invitation }, { status: 201 });
  } catch (error) {
    if (error instanceof InvitationError) {
      return Response.json({ error: error.message }, { status: error.status });
    }
    return Response.json(
      { error: "The invitation could not be delivered." },
      { status: 502 },
    );
  }
}
