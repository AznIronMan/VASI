import { randomUUID } from "node:crypto";

import {
  authProviderIds,
  getAuthProviderAvailability,
  type AuthProviderId,
} from "@/lib/auth-providers";
import { database } from "@/lib/database";

export type ConnectorHealth = "active" | "stale" | "error" | "disconnected";

export type AdminConnector = {
  configured: boolean;
  connected: boolean;
  label: string;
  lastAuthenticatedAt: string | null;
  provider: AuthProviderId;
  status: ConnectorHealth;
};

export type AdminUser = {
  active: boolean;
  connectors: AdminConnector[];
  createdAt: string;
  email: string;
  emailVerified: boolean;
  id: string;
  manualPassword: boolean;
  name: string;
  role: string;
  username: string | null;
};

export type PendingInvitation = {
  createdAt: string;
  email: string;
  expiresAt: string;
  id: string;
};

export function resolveConnectorHealth({
  accountId,
  configured,
  connected,
  lastAuthenticatedAt,
  now = Date.now(),
}: {
  accountId?: string;
  configured: boolean;
  connected: boolean;
  lastAuthenticatedAt?: Date | string;
  now?: number;
}): ConnectorHealth {
  if (!connected) return "disconnected";
  if (!configured || !accountId || !lastAuthenticatedAt) return "error";
  return new Date(lastAuthenticatedAt).getTime() < now - 90 * 24 * 60 * 60 * 1_000
    ? "stale"
    : "active";
}

type UserRow = {
  accounts: Array<{
    accountId: string;
    hasPassword: boolean;
    providerId: string;
    updatedAt: Date | string;
  }>;
  banned: boolean;
  createdAt: Date | string;
  email: string;
  emailVerified: boolean;
  id: string;
  name: string;
  role: string;
  username: string | null;
};

export async function loadAdminDashboard() {
  const [usersResult, invitationResult] = await Promise.all([
    database.query<UserRow>(`
      select
        u."id",
        u."name",
        u."email",
        u."emailVerified",
        u."username",
        u."role",
        u."banned",
        u."createdAt",
        coalesce(
          json_agg(
            json_build_object(
              'providerId', a."providerId",
              'accountId', a."accountId",
              'hasPassword', a."password" is not null,
              'updatedAt', a."updatedAt"
            ) order by a."updatedAt" desc
          ) filter (where a."id" is not null),
          '[]'::json
        ) as accounts
      from "user" u
      left join "account" a on a."userId" = u."id"
      group by u."id"
      order by u."createdAt" desc
      limit 250
    `),
    database.query<{
      createdAt: Date | string;
      email: string;
      expiresAt: Date | string;
      id: string;
    }>(`
      select "id", "email", "expiresAt", "createdAt"
      from "vasi_invitation"
      where "acceptedAt" is null
        and "revokedAt" is null
        and "expiresAt" > CURRENT_TIMESTAMP
      order by "createdAt" desc
      limit 25
    `),
  ]);

  return {
    invitations: invitationResult.rows.map((invitation) => ({
      ...invitation,
      createdAt: new Date(invitation.createdAt).toISOString(),
      expiresAt: new Date(invitation.expiresAt).toISOString(),
    })) satisfies PendingInvitation[],
    users: usersResult.rows.map(toAdminUser),
  };
}

function toAdminUser(row: UserRow): AdminUser {
  const availability = new Map(
    getAuthProviderAvailability().map((provider) => [provider.id, provider]),
  );
  const accounts = Array.isArray(row.accounts) ? row.accounts : [];

  return {
    active: !row.banned,
    connectors: authProviderIds.map((provider) => {
      const configured = availability.get(provider)?.configured ?? false;
      const account = accounts.find((item) => item.providerId === provider);
      const lastAuthenticatedAt = account
        ? new Date(account.updatedAt).toISOString()
        : null;
      const status = resolveConnectorHealth({
        accountId: account?.accountId,
        configured,
        connected: Boolean(account),
        lastAuthenticatedAt: account?.updatedAt,
      });

      return {
        configured,
        connected: Boolean(account),
        label: availability.get(provider)?.label ?? provider,
        lastAuthenticatedAt,
        provider,
        status,
      };
    }),
    createdAt: new Date(row.createdAt).toISOString(),
    email: row.email,
    emailVerified: row.emailVerified,
    id: row.id,
    manualPassword: accounts.some(
      (account) => account.providerId === "credential" && account.hasPassword,
    ),
    name: row.name,
    role: row.role,
    username: row.username,
  };
}

export async function writeAdminAudit({
  action,
  actorUserId,
  metadata = {},
  targetUserId,
}: {
  action: string;
  actorUserId?: string | null;
  metadata?: Record<string, unknown>;
  targetUserId?: string | null;
}) {
  await database.query(
    `insert into "vasi_admin_audit"
      ("id", "actorUserId", "targetUserId", "action", "metadata")
     values ($1, $2, $3, $4, $5::jsonb)`,
    [randomUUID(), actorUserId ?? null, targetUserId ?? null, action, JSON.stringify(metadata)],
  );
}
