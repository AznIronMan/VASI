import { createHash, randomBytes, randomUUID } from "node:crypto";

import { database } from "@/lib/database";
import { sendAuthEmail } from "@/lib/email";
import { emailDomain } from "@/lib/provider-recommendation";
import { resolveServerEnvironment } from "@/lib/server-environment";
import { writeAdminAudit } from "@/lib/admin-users";

const INVITATION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1_000;

export async function createInvitation(emailValue: string, actorUserId: string) {
  const email = emailValue.trim().toLowerCase();
  if (!emailDomain(email)) {
    throw new InvitationError("Enter a valid email address.", 400);
  }

  const existing = await database.query(
    'select 1 from "user" where lower("email") = $1 limit 1',
    [email],
  );
  if (existing.rowCount) {
    throw new InvitationError("That email already has a V·Sign account.", 409);
  }

  const token = randomBytes(32).toString("base64url");
  const id = randomUUID();
  const expiresAt = new Date(Date.now() + INVITATION_LIFETIME_MS);
  const tokenHash = hashInvitationToken(token);
  const client = await database.connect();

  try {
    await client.query("begin");
    await client.query(
      `update "vasi_invitation"
       set "revokedAt" = CURRENT_TIMESTAMP, "updatedAt" = CURRENT_TIMESTAMP
       where lower("email") = $1 and "acceptedAt" is null and "revokedAt" is null`,
      [email],
    );
    await client.query(
      `insert into "vasi_invitation"
        ("id", "email", "tokenHash", "invitedBy", "expiresAt")
       values ($1, $2, $3, $4, $5)`,
      [id, email, tokenHash, actorUserId, expiresAt],
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }

  const { baseURL } = resolveServerEnvironment();
  try {
    await sendAuthEmail({
      to: email,
      subject: "You are invited to CNB V·Sign",
      heading: "Your V·Sign invitation",
      message:
        "Choose a trusted identity provider to join V·Sign. A manual password remains available if your organization does not support one.",
      actionLabel: "Accept invitation",
      actionUrl: `${baseURL}/invite?token=${encodeURIComponent(token)}`,
    });
    await writeAdminAudit({
      action: "invitation.sent",
      actorUserId,
      metadata: { invitationId: id },
    });
  } catch (error) {
    await database.query(
      `update "vasi_invitation"
       set "revokedAt" = CURRENT_TIMESTAMP, "updatedAt" = CURRENT_TIMESTAMP
       where "id" = $1`,
      [id],
    );
    await writeAdminAudit({
      action: "invitation.delivery_failed",
      actorUserId,
      metadata: { invitationId: id },
    });
    throw error;
  }

  return { id, email, expiresAt: expiresAt.toISOString() };
}

export async function getInvitation(token: string) {
  if (!/^[A-Za-z0-9_-]{40,64}$/.test(token)) return undefined;

  const result = await database.query<{
    email: string;
    expiresAt: Date | string;
    id: string;
  }>(
    `select "id", "email", "expiresAt"
     from "vasi_invitation"
     where "tokenHash" = $1
       and "acceptedAt" is null
       and "revokedAt" is null
       and "expiresAt" > CURRENT_TIMESTAMP
     limit 1`,
    [hashInvitationToken(token)],
  );
  const invitation = result.rows[0];
  if (!invitation) return undefined;

  return {
    ...invitation,
    expiresAt: new Date(invitation.expiresAt).toISOString(),
  };
}

export async function acceptInvitation(
  token: string,
  user: { email: string; id: string },
) {
  const invitation = await getInvitation(token);
  if (!invitation || invitation.email.toLowerCase() !== user.email.toLowerCase()) {
    return false;
  }

  const result = await database.query(
    `update "vasi_invitation"
     set "acceptedAt" = CURRENT_TIMESTAMP,
         "acceptedBy" = $2,
         "updatedAt" = CURRENT_TIMESTAMP
     where "id" = $1
       and "acceptedAt" is null
       and "revokedAt" is null
       and "expiresAt" > CURRENT_TIMESTAMP`,
    [invitation.id, user.id],
  );
  if (!result.rowCount) return false;

  await writeAdminAudit({
    action: "invitation.accepted",
    targetUserId: user.id,
    metadata: { invitationId: invitation.id },
  });
  return true;
}

function hashInvitationToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export class InvitationError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}
