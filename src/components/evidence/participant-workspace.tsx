"use client";

import { useState } from "react";

import { BrandMark } from "@/components/brand-mark";
import { SignOutButton } from "@/components/auth/sign-out-button";
import type {
  ParticipantDataRequest,
  ParticipantHistoryRecord,
} from "@/lib/evidence-types";

export function ParticipantWorkspace({
  email,
  initialDataRequests,
  initialHistory,
  name,
  sessionExpiresAt,
}: {
  email: string;
  initialDataRequests: ParticipantDataRequest[];
  initialHistory: ParticipantHistoryRecord[];
  name: string;
  sessionExpiresAt: string;
}) {
  const [history, setHistory] = useState(initialHistory);
  const [dataRequests, setDataRequests] = useState(initialDataRequests);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string>();
  const activeDataRequest = dataRequests.find((request) =>
    !["cancelled", "denied", "expired"].includes(request.status),
  );

  async function refresh() {
    setPending(true);
    try {
      const [nextHistory, nextRequests] = await Promise.all([
        workspaceGet<ParticipantHistoryRecord[]>("/api/workspace/history"),
        workspaceGet<ParticipantDataRequest[]>("/api/workspace/data-requests"),
      ]);
      setHistory(nextHistory);
      setDataRequests(nextRequests);
      setMessage("Workspace status refreshed.");
    } catch (error) {
      setMessage(workspaceError(error));
    } finally {
      setPending(false);
    }
  }

  async function requestData() {
    if (activeDataRequest) return;
    setPending(true);
    setMessage(undefined);
    try {
      const created = await workspacePost<ParticipantDataRequest>("/api/workspace/data-requests", {
        commandId: crypto.randomUUID(),
      });
      setDataRequests((current) => [created, ...current]);
      setMessage(created.scopes.length
        ? "Your data request was submitted for organization review."
        : "No matching VASI records were found for this account.");
    } catch (error) {
      setMessage(workspaceError(error));
    } finally {
      setPending(false);
    }
  }

  return <main className="workspace-shell workspace-shell--records">
    <header className="workspace-header"><BrandMark compact /><div className="workspace-identity"><span>{name}</span><small>{email}</small></div><SignOutButton /></header>
    <section className="workspace-hero">
      <div><p className="eyebrow eyebrow--green">MY VASI RECORDS</p><h1>Your requests and acknowledgements</h1><p>Return here to see who sent a request, when it was accessed or completed, and the participant-facing record available to you.</p></div>
      <div><span>Verified account</span><strong>{email}</strong><small>Session expires {new Date(sessionExpiresAt).toLocaleString()}</small><button type="button" disabled={pending} onClick={() => void refresh()}>Refresh records</button></div>
    </section>
    {message && <p className="admin-message" role="status">{message}</p>}

    <section className="workspace-records" aria-labelledby="workspace-records-heading">
      <div className="workspace-section-heading"><div><p className="eyebrow eyebrow--green">HISTORY</p><h2 id="workspace-records-heading">Requests sent to you</h2></div><span>{history.length} record{history.length === 1 ? "" : "s"}</span></div>
      {history.length === 0 && <div className="workspace-empty"><h3>No VASI records yet</h3><p>Requests will appear here after you open them with this verified account.</p></div>}
      <div className="workspace-record-grid">{history.map((record) => <article className="workspace-record" key={record.assignmentId}>
        <header><span className={`workspace-status workspace-status--${record.status}`}>{record.status.replaceAll("_", " ")}</span><small>{record.tenant.name}</small></header>
        <h3>{record.title}</h3><p>{record.purpose}</p>
        <dl><div><dt>Sent</dt><dd>{formatWorkspaceDate(record.issuedAt)}</dd></div><div><dt>First opened</dt><dd>{formatWorkspaceDate(record.firstOpenedAt)}</dd></div><div><dt>Completed</dt><dd>{formatWorkspaceDate(record.completedAt)}</dd></div><div><dt>Sent by</dt><dd>{record.sender.email || record.tenant.name}</dd></div></dl>
        <footer><div>{record.evidence.manifestFingerprint && <><span>Record fingerprint</span><code>{record.evidence.manifestFingerprint.slice(0, 18)}…</code></>}</div>{record.evidence.reportAvailable && <a href={`/api/workspace/report?assignmentId=${encodeURIComponent(record.assignmentId)}&format=html`}>Download my record</a>}</footer>
      </article>)}</div>
    </section>

    <details className="workspace-privacy">
      <summary>Privacy and access to my VASI data</summary>
      <div><h2>Request a portable copy</h2><p>You may request the VASI data associated with this verified account. Each requesting organization reviews only its own record scope. Approved exports exclude organization secrets, internal-only workflow material, and unrelated third-party information.</p><p>The resulting sealed JSON file is available for a limited delivery window. Request and access events remain in the audit trail.</p>
        <button className="secondary-button" type="button" disabled={pending || Boolean(activeDataRequest)} onClick={() => void requestData()}>{activeDataRequest ? "A data request is already open" : "Request my VASI data"}</button>
        {dataRequests.map((request) => <article className="workspace-data-request" key={request.id}><div><strong>{request.status.replaceAll("_", " ")}</strong><span>Requested {formatWorkspaceDate(request.requestedAt)}</span><small>{request.scopes.map((scope) => `${scope.tenant.name}: ${scope.status.replaceAll("_", " ")}`).join(" · ") || "No organization scopes matched"}</small></div>{["approved", "partially_approved", "ready"].includes(request.status) && <a href={`/api/workspace/data-export?requestId=${encodeURIComponent(request.id)}`}>Download sealed JSON</a>}</article>)}
      </div>
    </details>
  </main>;
}

function formatWorkspaceDate(value?: string) {
  return value ? new Date(value).toLocaleString() : "Not recorded";
}

async function workspaceGet<T>(url: string): Promise<T> {
  const response = await fetch(url, { cache: "no-store" });
  const result = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(result.error || "The workspace request could not be completed.");
  return result;
}

async function workspacePost<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    body: JSON.stringify(body),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  const result = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(result.error || "The workspace request could not be completed.");
  return result;
}

function workspaceError(error: unknown) {
  return error instanceof Error ? error.message : "The workspace request could not be completed.";
}
