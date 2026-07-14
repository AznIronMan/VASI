import { authorizeAdminMutation } from "@/lib/admin-access";
import { writeAdminAudit } from "@/lib/admin-users";
import {
  authProviderIds,
  isProviderConfigured,
  type AuthProviderId,
} from "@/lib/auth-providers";
import { database } from "@/lib/database";
import { getRuntimeSettings } from "@/lib/runtime-settings";

export async function DELETE(
  request: Request,
  {
    params,
  }: { params: Promise<{ provider: string; userId: string }> },
) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;

  const { provider, userId } = await params;
  if (!authProviderIds.includes(provider as AuthProviderId)) {
    return Response.json({ error: "Unknown connector." }, { status: 400 });
  }
  if (userId === authorization.session.user.id) {
    return Response.json(
      { error: "Manage the current administrator's connectors from their account." },
      { status: 409 },
    );
  }

  const [client, settings] = await Promise.all([
    database.connect(),
    getRuntimeSettings(),
  ]);
  try {
    await client.query("begin");
    const accounts = await client.query<{
      password: string | null;
      providerId: string;
    }>(
      `select "providerId", "password"
       from "account"
       where "userId" = $1
       for update`,
      [userId],
    );
    const connected = accounts.rows.some((account) => account.providerId === provider);
    if (!connected) {
      await client.query("rollback");
      return Response.json({ error: "That connector is not linked." }, { status: 404 });
    }

    const remainingMethods = accounts.rows.filter((account) =>
      account.providerId === "credential"
        ? Boolean(account.password)
        : account.providerId !== provider &&
          authProviderIds.includes(account.providerId as AuthProviderId) &&
          isProviderConfigured(account.providerId as AuthProviderId, settings),
    );
    if (!remainingMethods.length) {
      await client.query("rollback");
      return Response.json(
        { error: "A user must retain at least one sign-in method." },
        { status: 409 },
      );
    }

    await client.query(
      `delete from "account"
       where "userId" = $1 and "providerId" = $2`,
      [userId, provider],
    );
    await client.query('delete from "session" where "userId" = $1', [userId]);
    await client.query("commit");
  } catch {
    await client.query("rollback").catch(() => undefined);
    return Response.json(
      { error: "The connector could not be disconnected." },
      { status: 400 },
    );
  } finally {
    client.release();
  }

  await writeAdminAudit({
    action: "connector.disconnected",
    actorUserId: authorization.session.user.id,
    targetUserId: userId,
    metadata: { provider },
  });
  return Response.json({ success: true });
}
