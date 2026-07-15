import { randomBytes } from "node:crypto";

import { authorizeAdminMutation } from "@/lib/admin-access";
import { boundedJSONObject } from "@/lib/bounded-json";
import {
  beginAdminAuditCommand,
  finishAdminAuditCommand,
  type AdminAuditCommand,
} from "@/lib/admin-audit";
import { getAuth } from "@/lib/auth";
import {
  authProviderIds,
  isProviderConfigured,
  type AuthProviderId,
} from "@/lib/auth-providers";
import { database } from "@/lib/database";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

type UserAction =
  | { action: "reset-password" }
  | { action: "set-active"; enabled: boolean }
  | { action: "set-password"; enabled: boolean };

export async function POST(
  request: Request,
  { params }: { params: Promise<{ userId: string }> },
) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;

  const { userId } = await params;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const action = parsed.value as UserAction;

  if (!userId || !action || typeof action.action !== "string") {
    return Response.json({ error: "Invalid request." }, { status: 400 });
  }

  try {
    const target = await database.query<{
      email: string;
      manualPassword: boolean;
    }>(
      `select
         u."email",
         exists (
           select 1 from "account" a
           where a."userId" = u."id"
             and a."providerId" = 'credential'
             and a."password" is not null
         ) as "manualPassword"
       from "user" u
       where u."id" = $1`,
      [userId],
    );
    const user = target.rows[0];
    if (!user) return Response.json({ error: "User not found." }, { status: 404 });

    if (action.action === "set-active") {
      if (typeof action.enabled !== "boolean") {
        return Response.json({ error: "Invalid account state." }, { status: 400 });
      }
      if (!action.enabled && userId === authorization.session.user.id) {
        return Response.json(
          { error: "The current administrator cannot disable their own account." },
          { status: 409 },
        );
      }

      const command = await beginAdminAuditCommand({
        action: "user.set_active",
        metadata: { desiredEnabled: action.enabled },
        request,
        session: authorization.session,
        targetUserId: userId,
      });
      return externalMutation(command, async () => {
        const auth = await getAuth();
        if (action.enabled) {
          await auth.api.unbanUser({ body: { userId }, headers: request.headers });
        } else {
          await auth.api.banUser({
            body: { userId, banReason: "Disabled by a V·Sign administrator" },
            headers: request.headers,
          });
        }
      });
    }

    if (action.action === "reset-password") {
      if (!user.manualPassword) {
        return Response.json(
          { error: "Username and password sign-in is not enabled for this user." },
          { status: 409 },
        );
      }
      const command = await beginAdminAuditCommand({
        action: "password.reset_request",
        request,
        session: authorization.session,
        targetUserId: userId,
      });
      return externalMutation(command, () => sendPublicPasswordReset(user.email));
    }

    if (action.action === "set-password") {
      if (typeof action.enabled !== "boolean") {
        return Response.json({ error: "Invalid password state." }, { status: 400 });
      }
      if (!action.enabled && userId === authorization.session.user.id) {
        return Response.json(
          { error: "Manage the current administrator's sign-in methods from their account." },
          { status: 409 },
        );
      }

      if (action.enabled) {
        const command = await beginAdminAuditCommand({
          action: "password.set_enabled",
          metadata: { desiredEnabled: true },
          request,
          session: authorization.session,
          targetUserId: userId,
        });
        return externalMutation(command, async () => {
          const auth = await getAuth();
          if (!user.manualPassword) {
            await auth.api.setUserPassword({
              body: {
                newPassword: randomBytes(48).toString("base64url"),
                userId,
              },
              headers: request.headers,
            });
          }
          await sendPublicPasswordReset(user.email);
        });
      }

      const command = await beginAdminAuditCommand({
        action: "password.set_enabled",
        metadata: { desiredEnabled: false },
        request,
        session: authorization.session,
        targetUserId: userId,
      });
      try {
        await disableManualPassword(userId, command);
        return Response.json({ success: true });
      } catch {
        await finishAdminAuditCommand(
          command,
          "failed",
          { failureCode: "local_transaction_rolled_back" },
        ).catch(() => undefined);
        return Response.json(
          { error: "The password setting was not changed." },
          { status: 409 },
        );
      }
    }

    return Response.json({ error: "Unsupported action." }, { status: 400 });
  } catch {
    return Response.json(
      { error: "The user update could not be completed." },
      { status: 503 },
    );
  }
}

async function sendPublicPasswordReset(email: string) {
  const [auth, settings] = await Promise.all([getAuth(), getRuntimeSettings()]);
  const { baseURL } = resolveServerSettings(settings);
  const publicHeaders = new Headers({
    host: new URL(baseURL).host,
    origin: baseURL,
  });
  await auth.api.requestPasswordReset({
    body: { email, redirectTo: `${baseURL}/reset-password` },
    headers: publicHeaders,
  });
}

async function disableManualPassword(userId: string, command: AdminAuditCommand) {
  const settings = await getRuntimeSettings();
  const client = await database.connect();
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
    const otherMethods = accounts.rows.filter(
      (account) =>
        authProviderIds.includes(account.providerId as AuthProviderId) &&
        isProviderConfigured(account.providerId as AuthProviderId, settings),
    );
    if (!otherMethods.length) {
      throw new Error("A user must retain at least one sign-in method.");
    }

    await client.query(
      `delete from "account"
       where "userId" = $1 and "providerId" = 'credential'`,
      [userId],
    );
    await client.query('delete from "session" where "userId" = $1', [userId]);
    await finishAdminAuditCommand(command, "succeeded", {}, client);
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function externalMutation(command: AdminAuditCommand, operation: () => Promise<unknown>) {
  try {
    await operation();
  } catch {
    const recorded = await finishAdminAuditCommand(
      command,
      "ambiguous",
      { outcomeCode: "external_operation_outcome_unknown" },
    ).then(() => true).catch(() => false);
    return Response.json(
      {
        error: recorded
          ? "The operation may have completed. Review the administrator audit before retrying."
          : "The operation may have completed, and its final audit outcome is unavailable. Do not retry until an operator reviews current state.",
      },
      { status: 502 },
    );
  }

  try {
    await finishAdminAuditCommand(command, "succeeded");
    return Response.json({ success: true });
  } catch {
    return Response.json(
      { error: "The change completed, but its terminal audit event is unavailable. Review the incomplete command before taking another action." },
      { status: 503 },
    );
  }
}
