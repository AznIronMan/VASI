import { randomBytes } from "node:crypto";

import { authorizeAdminMutation } from "@/lib/admin-access";
import { writeAdminAudit } from "@/lib/admin-users";
import { auth } from "@/lib/auth";
import {
  authProviderIds,
  isProviderConfigured,
  type AuthProviderId,
} from "@/lib/auth-providers";
import { database } from "@/lib/database";
import { resolveServerEnvironment } from "@/lib/server-environment";

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
  let action: UserAction;
  try {
    action = await request.json() as UserAction;
  } catch {
    return Response.json({ error: "Invalid request." }, { status: 400 });
  }

  if (!userId || !action || typeof action.action !== "string") {
    return Response.json({ error: "Invalid request." }, { status: 400 });
  }

  try {
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

      if (action.enabled) {
        await auth.api.unbanUser({ body: { userId }, headers: request.headers });
      } else {
        await auth.api.banUser({
          body: { userId, banReason: "Disabled by a V·Sign administrator" },
          headers: request.headers,
        });
      }
      await writeAdminAudit({
        action: action.enabled ? "user.enabled" : "user.disabled",
        actorUserId: authorization.session.user.id,
        targetUserId: userId,
      });
      return Response.json({ success: true });
    }

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

    if (action.action === "reset-password") {
      if (!user.manualPassword) {
        return Response.json(
          { error: "Username and password sign-in is not enabled for this user." },
          { status: 409 },
        );
      }
      await sendPublicPasswordReset(user.email);
      await writeAdminAudit({
        action: "password.reset_requested",
        actorUserId: authorization.session.user.id,
        targetUserId: userId,
      });
      return Response.json({ success: true });
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
      } else {
        await disableManualPassword(userId);
      }

      await writeAdminAudit({
        action: action.enabled ? "password.enabled" : "password.disabled",
        actorUserId: authorization.session.user.id,
        targetUserId: userId,
      });
      return Response.json({ success: true });
    }

    return Response.json({ error: "Unsupported action." }, { status: 400 });
  } catch {
    return Response.json(
      { error: "The user update could not be completed." },
      { status: 400 },
    );
  }
}

async function sendPublicPasswordReset(email: string) {
  const { baseURL } = resolveServerEnvironment();
  const publicHeaders = new Headers({
    host: new URL(baseURL).host,
    origin: baseURL,
  });
  await auth.api.requestPasswordReset({
    body: { email, redirectTo: `${baseURL}/reset-password` },
    headers: publicHeaders,
  });
}

async function disableManualPassword(userId: string) {
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
        isProviderConfigured(account.providerId as AuthProviderId),
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
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
