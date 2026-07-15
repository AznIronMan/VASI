import { randomUUID } from "node:crypto";

import type { PoolClient } from "pg";

import {
  verifyAdminAuditChain,
  type AdminAuditChainRow,
} from "../../packages/admin-audit/index.mjs";
import { database } from "@/lib/database";

export type AdminAuditPhase = "ambiguous" | "event" | "failed" | "started" | "succeeded";
export type AdminAuditTerminalPhase = Exclude<AdminAuditPhase, "event" | "started">;

export type AdminAuditCommand = {
  action: string;
  actorSessionId: string;
  actorUserId: string;
  commandId: string;
  ipAddress: string | null;
  requestId: string;
  targetUserId: string | null;
  userAgent: string | null;
};

export type AdminAuditEvent = {
  action: string;
  actorEmail: string | null;
  actorUserId: string | null;
  commandId: string;
  createdAt: string;
  eventHash: string;
  id: string;
  ipAddress: string | null;
  metadata: Record<string, unknown>;
  phase: AdminAuditPhase;
  requestId: string;
  sequence: number;
  targetEmail: string | null;
  targetUserId: string | null;
  userAgent: string | null;
};

export type AdminAuditOverview = {
  ambiguous24Hours: number;
  events: AdminAuditEvent[];
  incompleteCommands: Array<{
    action: string;
    commandId: string;
    startedAt: string;
  }>;
  integrity: {
    count: number;
    failureCode: string | null;
    failureSequence: number | null;
    headMatches: boolean;
    lastHash: string;
    lastSequence: number;
    valid: boolean;
  };
};

type AuditSession = {
  session: { id: string };
  user: { id: string };
};

type QueryClient = Pick<PoolClient, "query">;

export async function beginAdminAuditCommand({
  action,
  metadata = {},
  request,
  session,
  targetUserId,
}: {
  action: string;
  metadata?: Record<string, unknown>;
  request: Pick<Request, "headers">;
  session: AuditSession;
  targetUserId?: string | null;
}): Promise<AdminAuditCommand> {
  const command: AdminAuditCommand = Object.freeze({
    action: auditToken(action, "action"),
    actorSessionId: auditToken(session.session.id, "actor session"),
    actorUserId: auditToken(session.user.id, "actor user"),
    commandId: randomUUID(),
    ipAddress: boundedHeader(
      request.headers.get("x-forwarded-for")?.split(",")[0] ||
        request.headers.get("x-real-ip"),
    ),
    requestId: randomUUID(),
    targetUserId: targetUserId ? auditToken(targetUserId, "target user") : null,
    userAgent: boundedHeader(request.headers.get("user-agent")),
  });
  await writeAdminAudit({ ...command, metadata, phase: "started" });
  return command;
}

export async function finishAdminAuditCommand(
  command: AdminAuditCommand,
  phase: AdminAuditTerminalPhase,
  metadata: Record<string, unknown> = {},
  client?: QueryClient,
) {
  return writeAdminAudit({ ...command, client, metadata, phase });
}

export async function writeAdminAudit({
  action,
  actorSessionId,
  actorUserId,
  client = database,
  commandId,
  ipAddress,
  metadata = {},
  phase = "event",
  requestId,
  targetUserId,
  userAgent,
}: {
  action: string;
  actorSessionId?: string | null;
  actorUserId?: string | null;
  client?: QueryClient;
  commandId?: string;
  ipAddress?: string | null;
  metadata?: Record<string, unknown>;
  phase?: AdminAuditPhase;
  requestId?: string;
  targetUserId?: string | null;
  userAgent?: string | null;
}) {
  const id = randomUUID();
  const normalizedMetadata = normalizeAdminAuditMetadata(metadata);
  const normalizedAction = auditToken(action, "action");
  const normalizedCommandId = auditToken(commandId || id, "command");
  const normalizedRequestId = auditToken(requestId || id, "request");
  const result = await client.query<{ eventHash: string; sequence: string }>(
    `insert into "vasi_admin_audit"
      ("id", "actorUserId", "targetUserId", "action", "metadata", "commandId",
       "phase", "requestId", "actorSessionId", "ipAddress", "userAgent")
     values ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11)
     returning "sequence", "eventHash"`,
    [
      id,
      actorUserId ?? null,
      targetUserId ?? null,
      normalizedAction,
      JSON.stringify(normalizedMetadata),
      normalizedCommandId,
      phase,
      normalizedRequestId,
      actorSessionId ?? null,
      boundedHeader(ipAddress),
      boundedHeader(userAgent),
    ],
  );
  return Object.freeze({
    eventHash: result.rows[0].eventHash,
    id,
    sequence: Number(result.rows[0].sequence),
  });
}

export async function loadAdminAuditOverview(): Promise<AdminAuditOverview> {
  const [chain, head, recent, incomplete, ambiguous] = await Promise.all([
    database.query<AdminAuditChainRow>(`
      select "id", "actorUserId", "targetUserId", "action", "metadata", "createdAt",
             "commandId", "phase", "requestId", "actorSessionId", "ipAddress",
             "userAgent", "sequence", "previousHash", "canonicalPayload", "eventHash"
      from "vasi_admin_audit" order by "sequence"
    `),
    database.query<{ lastHash: string; lastSequence: string }>(`
      select "lastSequence", "lastHash" from "vasi_admin_audit_chain_head" where "id" = 1
    `),
    database.query<{
      action: string;
      actorEmail: string | null;
      actorUserId: string | null;
      commandId: string;
      createdAt: Date | string;
      eventHash: string;
      id: string;
      ipAddress: string | null;
      metadata: Record<string, unknown>;
      phase: AdminAuditPhase;
      requestId: string;
      sequence: string;
      targetEmail: string | null;
      targetUserId: string | null;
      userAgent: string | null;
    }>(`
      select a."id", a."actorUserId", a."targetUserId", a."action", a."metadata",
             a."createdAt", a."commandId", a."phase", a."requestId", a."ipAddress",
             a."userAgent", a."sequence", a."eventHash",
             actor."email" as "actorEmail", target."email" as "targetEmail"
      from "vasi_admin_audit" a
      left join "user" actor on actor."id" = a."actorUserId"
      left join "user" target on target."id" = a."targetUserId"
      order by a."sequence" desc limit 50
    `),
    database.query<{ action: string; commandId: string; startedAt: Date | string }>(`
      select started."action", started."commandId", started."createdAt" as "startedAt"
      from "vasi_admin_audit" started
      where started."phase" = 'started'
        and not exists (
          select 1 from "vasi_admin_audit" terminal
          where terminal."commandId" = started."commandId"
            and terminal."phase" in ('succeeded', 'failed', 'ambiguous')
        )
      order by started."createdAt" limit 25
    `),
    database.query<{ count: string }>(`
      select count(*)::text as "count" from "vasi_admin_audit"
      where "phase" = 'ambiguous' and "createdAt" >= CURRENT_TIMESTAMP - interval '24 hours'
    `),
  ]);
  const integrity = verifyAdminAuditChain(chain.rows, head.rows[0]);
  return {
    ambiguous24Hours: Number(ambiguous.rows[0]?.count || 0),
    events: recent.rows.map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt).toISOString(),
      sequence: Number(row.sequence),
    })),
    incompleteCommands: incomplete.rows.map((row) => ({
      ...row,
      startedAt: new Date(row.startedAt).toISOString(),
    })),
    integrity: {
      count: integrity.count,
      failureCode: integrity.firstFailure?.code || null,
      failureSequence: integrity.firstFailure?.sequence || null,
      headMatches: integrity.headMatches,
      lastHash: integrity.lastHash,
      lastSequence: integrity.lastSequence,
      valid: integrity.valid,
    },
  };
}

export function normalizeAdminAuditMetadata(value: Record<string, unknown>) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error("Administrator audit metadata must be an object.");
  }
  inspectMetadata(value);
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded, "utf8") > 8_192) {
    throw new Error("Administrator audit metadata is too large.");
  }
  return JSON.parse(encoded) as Record<string, unknown>;
}

function inspectMetadata(value: unknown, depth = 0) {
  if (depth > 8) throw new Error("Administrator audit metadata is too deeply nested.");
  if (typeof value === "string" && value.length > 512) {
    throw new Error("Administrator audit metadata contains an oversized string.");
  }
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new Error("Administrator audit metadata numbers must be safe integers.");
  }
  if (Array.isArray(value)) {
    if (value.length > 100) throw new Error("Administrator audit metadata contains an oversized list.");
    value.forEach((item) => inspectMetadata(item, depth + 1));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (/(?:password|secret|token|credential|authorization|cookie|private.?key|access.?token|refresh.?token|email.?body|content)/i.test(key)) {
        throw new Error("Administrator audit metadata contains a prohibited field.");
      }
      inspectMetadata(item, depth + 1);
    }
  }
}

function boundedHeader(value?: string | null) {
  const normalized = value?.trim();
  return normalized ? normalized.slice(0, 512) : null;
}

function auditToken(value: string, label: string) {
  const normalized = value.trim();
  if (!normalized || normalized.length > 128 || !/^[A-Za-z0-9._:-]+$/.test(normalized)) {
    throw new Error(`The administrator audit ${label} is invalid.`);
  }
  return normalized;
}
