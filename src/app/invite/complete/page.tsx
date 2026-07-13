import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { auth } from "@/lib/auth";
import { acceptInvitation } from "@/lib/invitations";

export default async function CompleteInvitationPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const { token = "" } = await searchParams;
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    redirect(`/invite?token=${encodeURIComponent(token)}`);
  }

  const accepted = await acceptInvitation(token, {
    email: session.user.email,
    id: session.user.id,
  });
  if (!accepted) {
    redirect(`/invite?token=${encodeURIComponent(token)}`);
  }

  redirect("/workspace");
}
