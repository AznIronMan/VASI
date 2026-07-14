"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import type {
  OwnerDataRequestReview,
  OwnerLifecycleRecord,
  OwnerRetentionPolicy,
  RetentionPolicy,
} from "@/lib/owner-types";

export function OwnerGovernance({ permissions, tenantId }: {
  permissions: string[];
  tenantId: string;
}) {
  const permissionSet = useMemo(() => new Set(permissions), [permissions]);
  const [policies, setPolicies] = useState<OwnerRetentionPolicy[]>([]);
  const [records, setRecords] = useState<OwnerLifecycleRecord[]>([]);
  const [reviews, setReviews] = useState<OwnerDataRequestReview[]>([]);
  const [profileName, setProfileName] = useState("tenant_default");
  const [pending, setPending] = useState<string>();
  const [message, setMessage] = useState<string>();

  const refresh = useCallback(async () => {
    if (!tenantId) return;
    setPending("governance-refresh");
    try {
      const tasks: Promise<unknown>[] = [];
      if (permissionSet.has("lifecycle.read")) {
        tasks.push(governanceApi<OwnerRetentionPolicy[]>("/api/owner/lifecycle/policies/list", { tenantId }).then(setPolicies));
        tasks.push(governanceApi<OwnerLifecycleRecord[]>("/api/owner/lifecycle/records", { tenantId }).then(setRecords));
      } else {
        setPolicies([]);
        setRecords([]);
      }
      if (permissionSet.has("data_request.review")) {
        tasks.push(governanceApi<OwnerDataRequestReview[]>("/api/owner/data-requests/list", { tenantId }).then(setReviews));
      } else setReviews([]);
      await Promise.all(tasks);
    } catch (error) {
      setMessage(governanceError(error));
    } finally {
      setPending(undefined);
    }
  }, [permissionSet, tenantId]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void refresh(), 0);
    return () => window.clearTimeout(timeout);
  }, [refresh]);

  const profileNames = [...new Set(policies.map((entry) => entry.name))];
  const activePolicy = policies.find((entry) => entry.name === profileName && entry.source === "tenant") ||
    policies.find((entry) => entry.name === profileName);

  async function savePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const name = String(data.get("name") || "tenant_default").trim().toLowerCase();
    const mode = String(data.get("contentMode")) as RetentionPolicy["contentAccess"]["mode"];
    const current = policies.find((entry) => entry.name === name && entry.source === "tenant");
    const policy: RetentionPolicy = {
      contentAccess: mode === "days_after_terminal"
        ? { daysAfterTerminal: requiredDay(data, "contentDays"), mode }
        : { mode },
      evidence: {
        archiveAfterDays: nullableDay(data, "archiveDays"),
        deleteAfterDays: nullableDay(data, "deleteDays"),
      },
      participantHistory: { daysAfterTerminal: nullableDay(data, "historyDays") },
      schema: "vasi-retention-policy/v1",
    };
    setPending("policy");
    setMessage(undefined);
    try {
      await governanceApi<OwnerRetentionPolicy>("/api/owner/lifecycle/policies", {
        expectedRevision: current?.revision || 0,
        name,
        policy,
        tenantId,
      });
      setProfileName(name);
      setMessage(`Retention profile ${name} was saved as a new immutable revision.`);
      await refresh();
    } catch (error) {
      setMessage(governanceError(error));
    } finally {
      setPending(undefined);
    }
  }

  async function placeHold(event: FormEvent<HTMLFormElement>, assignmentId: string) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setPending(`hold:${assignmentId}`);
    try {
      await governanceApi("/api/owner/lifecycle/holds", {
        action: "place",
        assignmentId,
        caseReference: data.get("caseReference"),
        commandId: crypto.randomUUID(),
        reason: data.get("reason"),
        tenantId,
      });
      form.reset();
      setMessage("Legal hold placed. Automated evidence deletion is blocked until an authorized release is recorded.");
      await refresh();
    } catch (error) {
      setMessage(governanceError(error));
    } finally {
      setPending(undefined);
    }
  }

  async function releaseHold(holdId: string) {
    const reason = window.prompt("Required release reason");
    if (!reason?.trim()) return;
    setPending(`release:${holdId}`);
    try {
      await governanceApi("/api/owner/lifecycle/holds", {
        action: "release",
        commandId: crypto.randomUUID(),
        holdId,
        reason,
        tenantId,
      });
      setMessage("Legal hold release was appended to the lifecycle audit.");
      await refresh();
    } catch (error) {
      setMessage(governanceError(error));
    } finally {
      setPending(undefined);
    }
  }

  async function reviewDataRequest(requestId: string, decision: "approve" | "deny") {
    const reason = window.prompt(
      decision === "approve" ? "Optional review note" : "Required denial reason",
      decision === "approve" ? "Approved after privacy and scope review." : "",
    );
    if (decision === "deny" && !reason?.trim()) return;
    setPending(`review:${requestId}`);
    try {
      await governanceApi("/api/owner/data-requests/review", {
        commandId: crypto.randomUUID(),
        decision,
        includeTechnicalTelemetry: decision === "approve",
        reason: reason?.trim() || undefined,
        requestId,
        tenantId,
      });
      setMessage(`Participant data scope ${decision === "approve" ? "approved" : "denied"}.`);
      await refresh();
    } catch (error) {
      setMessage(governanceError(error));
    } finally {
      setPending(undefined);
    }
  }

  if (!permissionSet.has("lifecycle.read") && !permissionSet.has("data_request.review")) return null;

  return <section className="owner-governance">
    <div className="owner-section-heading">
      <div><p className="eyebrow eyebrow--green">RECORD GOVERNANCE</p><h2>Retention, holds, and participant data review</h2></div>
      <button type="button" onClick={() => void refresh()} disabled={pending === "governance-refresh"}>Refresh governance</button>
    </div>
    {message && <p className="admin-message" role="status">{message}</p>}

    {permissionSet.has("lifecycle.read") && <section className="owner-grid">
      {permissionSet.has("lifecycle.manage") && <form className="evidence-panel" key={`${tenantId}:${activePolicy?.name}:${activePolicy?.revision}`} onSubmit={savePolicy}>
        <p className="eyebrow eyebrow--green">VERSIONED POLICY</p><h2>Retention profile</h2>
        <p>Every issued record binds an immutable policy snapshot. Later profile edits affect only newly issued records.</p>
        {profileNames.length > 0 && <label className="field"><span>Load profile</span><select value={profileName} onChange={(event) => setProfileName(event.target.value)}>{profileNames.map((name) => <option key={name}>{name}</option>)}</select></label>}
        <label className="field"><span>Profile name</span><input name="name" defaultValue={activePolicy?.name || profileName} pattern="[a-z][a-z0-9_-]*" required /></label>
        <label className="field"><span>Participant content access</span><select name="contentMode" defaultValue={activePolicy?.policy.contentAccess.mode || "request_expiration"}><option value="request_expiration">Until request expiration</option><option value="days_after_terminal">Days after completion</option><option value="indefinite">Indefinite</option></select></label>
        <label className="field"><span>Content days after completion (used only for that mode)</span><input name="contentDays" type="number" min="0" max="36500" defaultValue={activePolicy?.policy.contentAccess.daysAfterTerminal ?? 30} /></label>
        <div className="form-row"><label className="field"><span>Archive evidence after days</span><input name="archiveDays" type="number" min="0" max="36500" defaultValue={activePolicy?.policy.evidence.archiveAfterDays ?? ""} placeholder="Blank: no automatic archive" /></label><label className="field"><span>Delete evidence after days</span><input name="deleteDays" type="number" min="0" max="36500" defaultValue={activePolicy?.policy.evidence.deleteAfterDays ?? ""} placeholder="Blank: never automatically delete" /></label></div>
        <label className="field"><span>Participant history after completion</span><input name="historyDays" type="number" min="0" max="36500" defaultValue={activePolicy?.policy.participantHistory.daysAfterTerminal ?? ""} placeholder="Blank: remains available" /></label>
        <p className="participant-limit">Automatic deletion requires a due policy, no active hold, no open participant data request, and a sealed purge tombstone.</p>
        <button className="primary-button" disabled={pending === "policy"} type="submit">Save new policy revision</button>
      </form>}
      <section className="evidence-panel"><p className="eyebrow eyebrow--green">BOUND RECORDS</p><h2>Lifecycle status</h2>
        {records.length === 0 && <p>No records have been issued for this company.</p>}
        {records.map((record) => <article className="governance-record" key={record.assignmentId}>
          <div><strong>{record.title}</strong><span>{record.participantEmail || record.intendedEmail}</span><small>{record.assignmentStatus} · content {record.contentStatus} · evidence {record.evidenceStatus}</small><code>{record.policyHash.slice(0, 18)}…</code></div>
          <dl><div><dt>Archive</dt><dd>{formatDate(record.archiveAt, "Not scheduled")}</dd></div><div><dt>Delete</dt><dd>{formatDate(record.deleteAt, "Never scheduled")}</dd></div></dl>
          {record.holds.map((hold) => <div className="governance-hold" key={hold.id}><span>Hold · {hold.caseReference}</span><small>{hold.releasedAt ? `Released ${formatDate(hold.releasedAt)}` : hold.reason}</small>{!hold.releasedAt && permissionSet.has("lifecycle.manage") && <button type="button" disabled={pending === `release:${hold.id}`} onClick={() => void releaseHold(hold.id)}>Release hold</button>}</div>)}
          {permissionSet.has("lifecycle.manage") && !record.holds.some((hold) => !hold.releasedAt) && <details><summary>Place legal hold</summary><form onSubmit={(event) => void placeHold(event, record.assignmentId)}><label className="field"><span>Case or matter reference</span><input name="caseReference" required /></label><label className="field"><span>Preservation reason</span><textarea name="reason" minLength={2} required /></label><button type="submit" disabled={pending === `hold:${record.assignmentId}`}>Place hold</button></form></details>}
        </article>)}
      </section>
    </section>}

    {permissionSet.has("data_request.review") && <section className="evidence-panel owner-review-panel"><p className="eyebrow eyebrow--green">PRIVACY REVIEW QUEUE</p><h2>Participant data requests</h2><p>Approve only the participant’s own scoped records. VASI excludes organization secrets, internal-only workflow content, and unrelated third-party data from the sealed export.</p>
      {reviews.length === 0 && <p>No participant data requests require or have received review.</p>}
      {reviews.map((review) => <article className="owner-data-review" key={`${review.requestId}:${review.tenantId}`}><div><strong>{review.requesterEmail}</strong><span>{review.matchedRecordCount} scoped record(s) · {review.status.replaceAll("_", " ")}</span><small>Requested {formatDate(review.requestedAt)} · expires {formatDate(review.expiresAt)}</small></div>{review.status === "pending_review" && <div><button type="button" disabled={pending === `review:${review.requestId}`} onClick={() => void reviewDataRequest(review.requestId, "approve")}>Approve scoped export</button><button type="button" disabled={pending === `review:${review.requestId}`} onClick={() => void reviewDataRequest(review.requestId, "deny")}>Deny with reason</button></div>}</article>)}
    </section>}
  </section>;
}

function requiredDay(data: FormData, name: string) {
  const value = Number(data.get(name));
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a whole number of days.`);
  return value;
}

function nullableDay(data: FormData, name: string) {
  const raw = String(data.get(name) || "").trim();
  return raw ? requiredDay(data, name) : null;
}

function formatDate(value?: string, fallback = "Not recorded") {
  return value ? new Date(value).toLocaleString() : fallback;
}

async function governanceApi<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    body: JSON.stringify(body),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  const result = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(result.error || "The governance request could not be completed.");
  return result;
}

function governanceError(error: unknown) {
  return error instanceof Error ? error.message : "The governance request could not be completed.";
}
