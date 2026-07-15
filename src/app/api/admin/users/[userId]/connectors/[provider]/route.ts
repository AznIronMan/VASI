import { authorizeAdminMutation } from "@/lib/admin-access";
import {
  beginAdminAuditCommand,
  finishAdminAuditCommand,
  type AdminAuditCommand,
} from "@/lib/admin-audit";
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
  let command: AdminAuditCommand | undefined;
  try {
    const preflight = await client.query<{
      password: string | null;
      providerId: string;
    }>(
      `select "providerId", "password"
       from "account"
       where "userId" = $1`,
      [userId],
    );
    const connected = preflight.rows.some((account) => account.providerId === provider);
    if (!connected) {
      return Response.json({ error: "That connector is not linked." }, { status: 404 });
    }

    const remainingMethods = preflight.rows.filter((account) =>
      account.providerId === "credential"
        ? Boolean(account.password)
        : account.providerId !== provider &&
          authProviderIds.includes(account.providerId as AuthProviderId) &&
          isProviderConfigured(account.providerId as AuthProviderId, settings),
    );
    if (!remainingMethods.length) {
      return Response.json(
        { error: "A user must retain at least one sign-in method." },
        { status: 409 },
      );
    }

    command = await beginAdminAuditCommand({
      action: "connector.disconnect",
      metadata: { provider },
      request,
      session: authorization.session,
      targetUserId: userId,
    });

    await client.query("begin");
    const accounts = await client.query<{
      password: string | null;
      providerId: string;
    }>(
      `select "providerId", "password"
       from "account" where "userId" = $1 for update`,
      [userId],
    );
    if (!accounts.rows.some((account) => account.providerId === provider)) {
      throw new Error("The connector state changed before disconnection.");
    }
    const stillRemaining = accounts.rows.filter((account) =>
      account.providerId === "credential"
        ? Boolean(account.password)
        : account.providerId !== provider &&
          authProviderIds.includes(account.providerId as AuthProviderId) &&
          isProviderConfigured(account.providerId as AuthProviderId, settings),
    );
    if (!stillRemaining.length) throw new Error("The user would lose every sign-in method.");

    await client.query(
      `delete from "account"
       where "userId" = $1 and "providerId" = $2`,
      [userId, provider],
    );
    await client.query('delete from "session" where "userId" = $1', [userId]);
    await finishAdminAuditCommand(command, "succeeded", {}, client);
    await client.query("commit");
  } catch {
    await client.query("rollback").catch(() => undefined);
    if (command) {
      await finishAdminAuditCommand(
        command,
        "failed",
        { failureCode: "local_transaction_rolled_back" },
      ).catch(() => undefined);
    }
    return Response.json(
      {
        error: command
          ? "The connector could not be disconnected."
          : "The connector was not changed because its audit command could not be recorded.",
      },
      { status: command ? 409 : 503 },
    );
  } finally {
    client.release();
  }

  return Response.json({ success: true });
}
