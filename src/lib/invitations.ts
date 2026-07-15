import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";

import { database } from "@/lib/database";
import { writeAdminAudit } from "@/lib/admin-audit";
import { resolveProductBrand } from "@/lib/branding";
import { AuthEmailDeliveryError, sendAuthEmail } from "@/lib/email";
import { emailDomain } from "@/lib/provider-recommendation";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

const INVITATION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1_000;

type InvitationDeliveryStatus = "failed" | "pending" | "provider_accepted";

type InvitationRow = {
  deliveryStatus: InvitationDeliveryStatus;
  email: string;
  expiresAt: Date | string;
  id: string;
  invitedBy: string | null;
  revokedAt: Date | string | null;
};

export async function createInvitation(
  emailValue: string,
  actorUserId: string,
  { sourceCommandId }: { sourceCommandId?: string } = {},
) {
  const email = emailValue.trim().toLowerCase();
  if (!emailDomain(email)) {
    throw new InvitationError("Enter a valid email address.", 400, "invalid");
  }
  const commandId = sourceCommandId?.trim().toLowerCase();
  if (commandId && !uuid(commandId)) {
    throw new InvitationError("The invitation command identifier is invalid.", 400, "invalid");
  }

  const client = await database.connect();
  const lockKey = commandId ? `vasi:invitation-provision:${commandId}` : undefined;
  try {
    if (lockKey) {
      await client.query("select pg_advisory_lock(hashtextextended($1, 0))", [lockKey]);
    }
    if (commandId) {
      const prior = await client.query(
        `select "id", "email", "invitedBy", "expiresAt", "revokedAt", "deliveryStatus"
         from "vasi_invitation" where "sourceCommandId" = $1`,
        [commandId],
      );
      if (prior.rowCount) {
        return replayInvitation(prior.rows[0] as InvitationRow, email, actorUserId);
      }
    }

    const existing = await client.query(
      'select 1 from "user" where lower("email") = $1 limit 1',
      [email],
    );
    if (existing.rowCount) {
      throw new InvitationError(
        "That email already has a V·Sign account.",
        409,
        "existing_account",
      );
    }

    return await deliverInvitation(client, email, actorUserId, commandId);
  } finally {
    if (lockKey) {
      await client.query("select pg_advisory_unlock(hashtextextended($1, 0))", [lockKey])
        .catch(() => undefined);
    }
    client.release();
  }
}

async function deliverInvitation(
  client: PoolClient,
  email: string,
  actorUserId: string,
  sourceCommandId?: string,
) {
  const token = randomBytes(32).toString("base64url");
  const id = randomUUID();
  const expiresAt = new Date(Date.now() + INVITATION_LIFETIME_MS);
  const tokenHash = hashInvitationToken(token);

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
        ("id", "email", "tokenHash", "invitedBy", "expiresAt", "sourceCommandId", "deliveryStatus")
       values ($1, $2, $3, $4, $5, $6, 'pending')`,
      [id, email, tokenHash, actorUserId, expiresAt, sourceCommandId || null],
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  }

  try {
    const settings = await getRuntimeSettings();
    const { baseURL } = resolveServerSettings(settings);
    const brand = resolveProductBrand(settings);
    await sendAuthEmail({
      to: email,
      subject: `You are invited to ${brand.displayName}`,
      heading: `Your ${brand.productName} invitation`,
      message:
        `Choose a trusted identity provider to join ${brand.productName}. A manual password remains available if your organization does not support one.`,
      actionLabel: "Accept invitation",
      actionUrl: `${baseURL}/invite?token=${encodeURIComponent(token)}`,
    });
  } catch (error) {
    if (error instanceof AuthEmailDeliveryError && error.outcome === "unknown") {
      await recordInvitationUncertainty(client, id, actorUserId).catch(() => undefined);
      throw new InvitationError(
        "The invitation provider outcome is unknown; it will not be sent again automatically.",
        502,
        "delivery_unknown",
        { cause: error },
      );
    }
    await recordInvitationDelivery(client, id, actorUserId, "failed").catch(() => undefined);
    throw new InvitationError(
      "The invitation could not be delivered.",
      502,
      "delivery_failed",
      { cause: error },
    );
  }

  try {
    await recordInvitationDelivery(client, id, actorUserId, "provider_accepted");
  } catch (error) {
    throw new InvitationError(
      "The provider accepted the invitation, but its delivery receipt could not be committed.",
      502,
      "delivery_unknown",
      { cause: error },
    );
  }

  return { id, email, expiresAt: expiresAt.toISOString() };
}

async function recordInvitationUncertainty(
  client: PoolClient,
  invitationId: string,
  actorUserId: string,
) {
  await writeAdminAudit({
    action: "invitation.delivery_unknown",
    actorUserId,
    client,
    metadata: { invitationId },
  });
}

function replayInvitation(row: InvitationRow, email: string, actorUserId: string) {
  if (row.email.toLowerCase() !== email || row.invitedBy !== actorUserId) {
    throw new InvitationError(
      "This company provisioning command is already bound to another invitation.",
      409,
      "source_conflict",
    );
  }
  if (row.revokedAt || row.deliveryStatus === "failed") {
    throw new InvitationError(
      "The command-bound invitation was not delivered and is no longer active.",
      409,
      "delivery_failed",
    );
  }
  if (row.deliveryStatus !== "provider_accepted") {
    throw new InvitationError(
      "The invitation delivery outcome is unknown; it will not be sent again automatically.",
      409,
      "delivery_unknown",
    );
  }
  return {
    email,
    expiresAt: new Date(row.expiresAt).toISOString(),
    id: row.id,
  };
}

async function recordInvitationDelivery(
  client: PoolClient,
  invitationId: string,
  actorUserId: string,
  status: "failed" | "provider_accepted",
) {
  try {
    await client.query("begin");
    const updated = await client.query(
      `update "vasi_invitation"
       set "deliveryStatus" = $2,
           "revokedAt" = case when $2 = 'failed' then CURRENT_TIMESTAMP else "revokedAt" end,
           "updatedAt" = CURRENT_TIMESTAMP
       where "id" = $1 and "deliveryStatus" = 'pending'
       returning "id"`,
      [invitationId, status],
    );
    if (updated.rowCount !== 1) throw new Error("Invitation delivery state changed unexpectedly.");
    await writeAdminAudit({
      action: status === "provider_accepted" ? "invitation.sent" : "invitation.delivery_failed",
      actorUserId,
      client,
      metadata: { invitationId },
    });
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  }
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

  const client = await database.connect();
  try {
    await client.query("begin");
    const result = await client.query(
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
    if (!result.rowCount) {
      await client.query("rollback");
      return false;
    }
    await writeAdminAudit({
      action: "invitation.accepted",
      client,
      metadata: { invitationId: invitation.id },
      targetUserId: user.id,
    });
    await client.query("commit");
    return true;
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function hashInvitationToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export class InvitationError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: InvitationErrorCode = "invalid",
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

export type InvitationErrorCode =
  | "delivery_failed"
  | "delivery_unknown"
  | "existing_account"
  | "invalid"
  | "source_conflict";

function uuid(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
