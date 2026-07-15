"use client";

import type { AdminAuditOverview } from "@/lib/admin-audit";

export function AdminAuditPanel({ audit }: { audit: AdminAuditOverview }) {
  const status = audit.integrity.valid ? "verified" : "critical";

  return (
    <section className="admin-audit" aria-labelledby="admin-audit-title">
      <div className="admin-audit__heading">
        <div>
          <p className="eyebrow eyebrow--green">IDENTITY EVIDENCE</p>
          <h2 id="admin-audit-title">Administrator audit trail</h2>
          <p>
            Privileged identity commands are recorded as an append-only, hash-chained
            history with explicit start and terminal outcomes.
          </p>
        </div>
        <span className={`admin-audit__status admin-audit__status--${status}`} role="status">
          {audit.integrity.valid ? "Chain verified" : "Integrity failure"}
        </span>
      </div>

      <div className="admin-audit__metrics" aria-label="Administrator audit status">
        <AuditMetric label="Events" value={String(audit.integrity.count)} />
        <AuditMetric label="Last sequence" value={String(audit.integrity.lastSequence)} />
        <AuditMetric label="Incomplete commands" value={String(audit.incompleteCommands.length)} />
        <AuditMetric label="Ambiguous · 24h" value={String(audit.ambiguous24Hours)} />
      </div>

      {!audit.integrity.valid && (
        <p className="admin-message admin-message--error" role="alert">
          The administrator audit chain did not verify
          {audit.integrity.failureCode ? ` (${audit.integrity.failureCode})` : ""}. Treat
          identity administration evidence as untrusted until this is investigated.
        </p>
      )}

      {audit.incompleteCommands.length > 0 && (
        <details className="admin-audit__incomplete">
          <summary>{audit.incompleteCommands.length} command(s) have no terminal outcome</summary>
          <ul>
            {audit.incompleteCommands.map((command) => (
              <li key={command.commandId}>
                <strong>{humanizeAction(command.action)}</strong>
                <span>{formatDate(command.startedAt)}</span>
                <code>{command.commandId}</code>
              </li>
            ))}
          </ul>
        </details>
      )}

      <div className="admin-audit__events">
        <h3>Recent events</h3>
        {audit.events.length === 0 ? (
          <p className="admin-audit__empty">No administrator events have been recorded.</p>
        ) : audit.events.map((event) => (
          <details className="admin-audit__event" key={event.id}>
            <summary>
              <span className={`admin-audit__phase admin-audit__phase--${event.phase}`}>
                {event.phase}
              </span>
              <strong>{humanizeAction(event.action)}</strong>
              <span>{event.actorEmail || event.actorUserId || "System"}</span>
              <time dateTime={event.createdAt}>{formatDate(event.createdAt)}</time>
              <code>#{event.sequence}</code>
            </summary>
            <dl>
              <AuditDetail label="Actor" value={event.actorEmail || event.actorUserId || "System"} />
              <AuditDetail label="Target" value={event.targetEmail || event.targetUserId || "None"} />
              <AuditDetail label="Command ID" value={event.commandId} mono />
              <AuditDetail label="Request ID" value={event.requestId} mono />
              <AuditDetail label="Source IP" value={event.ipAddress || "Not reported"} mono />
              <AuditDetail label="User agent" value={event.userAgent || "Not reported"} />
              <AuditDetail label="Event hash" value={event.eventHash} mono />
              <AuditDetail label="Metadata" value={JSON.stringify(event.metadata)} mono />
            </dl>
          </details>
        ))}
      </div>

      <p className="admin-audit__footnote">
        Source IP and browser context are bounded observations reported through the trusted
        gateway path; they are evidence, not standalone identity proof. Detailed values are
        restricted to this internal console.
      </p>
    </section>
  );
}

function AuditMetric({ label, value }: { label: string; value: string }) {
  return <article><span>{label}</span><strong>{value}</strong></article>;
}

function AuditDetail({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return <div><dt>{label}</dt><dd className={mono ? "admin-audit__mono" : undefined}>{value}</dd></div>;
}

function formatDate(value: string) {
  return new Date(value).toLocaleString();
}

function humanizeAction(value: string) {
  return value.replaceAll(".", " ").replaceAll("_", " ");
}
