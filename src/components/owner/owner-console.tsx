"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import { BrandMark } from "@/components/brand-mark";
import { SignOutButton } from "@/components/auth/sign-out-button";
import type { IssuedEvidenceRequest } from "@/lib/evidence-types";
import type {
  OwnerMember,
  OwnerRequest,
  OwnerTenant,
  OwnerWorkflow,
  PublishedWorkflow,
  WorkflowActivity,
  WorkflowDocument,
} from "@/lib/owner-types";

type EditableActivity = WorkflowActivity & { stopOnNo?: boolean };

const emptyActivity = (index: number): EditableActivity => ({
  content: { prompt: "Do you acknowledge and agree?", terms: "" },
  id: `step_${index + 1}`,
  responseMode: "acknowledgement",
  title: `Step ${index + 1}`,
  type: "terms_response",
});

export function OwnerConsole({ baseURL, initialTenants }: {
  baseURL: string;
  initialTenants: OwnerTenant[];
}) {
  const [tenantId, setTenantId] = useState(initialTenants[0]?.id || "");
  const [workflows, setWorkflows] = useState<OwnerWorkflow[]>([]);
  const [requests, setRequests] = useState<OwnerRequest[]>([]);
  const [members, setMembers] = useState<OwnerMember[]>([]);
  const [activities, setActivities] = useState<EditableActivity[]>([emptyActivity(0)]);
  const [editing, setEditing] = useState<OwnerWorkflow>();
  const [issued, setIssued] = useState<IssuedEvidenceRequest>();
  const [pending, setPending] = useState<string>();
  const [message, setMessage] = useState<string>();
  const tenant = initialTenants.find((entry) => entry.id === tenantId);
  const permissions = useMemo(() => new Set(tenant?.permissions || []), [tenant]);

  const refresh = useCallback(async () => {
    if (!tenantId) return;
    setPending("refresh");
    try {
      const tasks: Promise<unknown>[] = [];
      if (permissions.has("workflow.manage")) {
        tasks.push(api<OwnerWorkflow[]>("/api/owner/workflows/list", { tenantId }).then(setWorkflows));
      } else setWorkflows([]);
      if (permissions.has("request.manage")) {
        tasks.push(api<OwnerRequest[]>("/api/owner/requests/list", { tenantId }).then(setRequests));
      } else setRequests([]);
      if (permissions.has("member.manage")) {
        tasks.push(api<OwnerMember[]>("/api/owner/members/list", { tenantId }).then(setMembers));
      } else setMembers([]);
      await Promise.all(tasks);
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(undefined);
    }
  }, [permissions, tenantId]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void refresh(), 0);
    return () => window.clearTimeout(timeout);
  }, [refresh]);

  async function saveWorkflow(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const document: WorkflowDocument = {
      access: {
        authentication: "verified_email",
        postCompletion: String(data.get("postCompletion")) as NonNullable<WorkflowDocument["access"]>["postCompletion"],
      },
      activities: activities.map(({ stopOnNo, ...activity }) => ({
        ...activity,
        contractVersion: 1,
        transition: stopOnNo && activity.responseMode === "yes_no"
          ? { cases: [{ to: null, when: { equals: "no" } }] }
          : undefined,
      })),
      instructions: String(data.get("instructions") || "") || undefined,
      notifications: {
        onCompletion: true,
        onIssue: true,
        reminderHoursBeforeDue: String(data.get("reminderHours") || "24")
          .split(",")
          .map((value) => Number(value.trim()))
          .filter(Number.isSafeInteger),
      },
      purpose: String(data.get("purpose")),
      schedule: {
        defaultDueDays: Number(data.get("defaultDueDays")),
        defaultExpirationDays: Number(data.get("defaultExpirationDays")),
      },
      schema: "vasi-workflow/v1",
      title: String(data.get("title")),
    };
    setPending("workflow");
    setMessage(undefined);
    try {
      const workflow = editing
        ? await api<OwnerWorkflow>("/api/owner/workflows/draft", {
            definitionId: editing.definitionId,
            document,
            expectedDraftVersion: editing.draftVersion,
            tenantId,
          })
        : await api<OwnerWorkflow>("/api/owner/workflows", {
            document,
            name: data.get("name"),
            tenantId,
          });
      setEditing(undefined);
      setActivities([emptyActivity(0)]);
      form.reset();
      setMessage(`Draft ${workflow.name} saved at version ${workflow.draftVersion}.`);
      await refresh();
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(undefined);
    }
  }

  async function publish(workflow: OwnerWorkflow) {
    setPending(`publish:${workflow.definitionId}`);
    setMessage(undefined);
    try {
      const result = await api<PublishedWorkflow>("/api/owner/workflows/publish", {
        definitionId: workflow.definitionId,
        expectedDraftVersion: workflow.draftVersion,
        tenantId,
      });
      setMessage(`Published immutable revision ${result.revision}.`);
      await refresh();
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(undefined);
    }
  }

  function edit(workflow: OwnerWorkflow) {
    setEditing(workflow);
    setActivities(workflow.document.activities.map((activity) => ({
      ...activity,
      stopOnNo: activity.transition?.cases?.some((entry) => entry.when.equals === "no" && entry.to === null),
    })));
    window.scrollTo({ behavior: "smooth", top: 0 });
  }

  async function issueRequest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setPending("issue");
    setIssued(undefined);
    setMessage(undefined);
    try {
      const optionalDate = (name: string) => {
        const value = String(data.get(name) || "");
        return value ? new Date(value).toISOString() : undefined;
      };
      const result = await api<IssuedEvidenceRequest>("/api/owner/requests", {
        dueAt: optionalDate("dueAt"),
        expiresAt: optionalDate("expiresAt"),
        intendedEmail: data.get("intendedEmail"),
        scheduledFor: optionalDate("scheduledFor"),
        tenantId,
        workflowRevisionId: data.get("workflowRevisionId"),
      });
      setIssued(result);
      setMessage("Request created. Copy the one-time participant link now.");
      await refresh();
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(undefined);
    }
  }

  async function requestAction(request: OwnerRequest, action: "remind" | "reissue" | "revoke") {
    if (action === "revoke" && !window.confirm(`Revoke ${request.title} for ${request.intendedEmail}?`)) return;
    setPending(`${action}:${request.requestId}`);
    setIssued(undefined);
    setMessage(undefined);
    try {
      const result = await api<IssuedEvidenceRequest & { queued?: boolean }>("/api/owner/requests/actions", {
        action,
        commandId: crypto.randomUUID(),
        requestId: request.requestId,
        tenantId,
      });
      if (action === "reissue" && result.participantPath) setIssued(result);
      setMessage(action === "remind" ? "Reminder queued." : `Request ${action} completed.`);
      await refresh();
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(undefined);
    }
  }

  async function setMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setPending("member");
    try {
      await api<OwnerMember>("/api/owner/members", {
        email: data.get("email"),
        roles: [data.get("role")],
        status: data.get("status"),
        tenantId,
      });
      form.reset();
      setMessage("Company access updated.");
      await refresh();
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(undefined);
    }
  }

  if (!initialTenants.length) {
    return <main className="owner-shell"><header><BrandMark compact /><SignOutButton /></header><section className="owner-empty"><h1>No company access yet</h1><p>An identity administrator must create a company space or an owner must grant your verified email access.</p><Link href="/admin">Identity administration</Link></section></main>;
  }

  const published = workflows.filter((workflow) => workflow.publishedRevisionId);
  return (
    <main className="owner-shell">
      <header className="owner-header"><BrandMark compact /><div><p className="eyebrow eyebrow--green">PRIVATE COMPANY CONTROL PLANE</p><h1>Workflows and requests</h1></div><Link href="/admin">Identity administration</Link><SignOutButton /></header>
      <nav className="owner-tenant-nav"><label>Company<select value={tenantId} onChange={(event) => setTenantId(event.target.value)}>{initialTenants.map((entry) => <option key={entry.id} value={entry.id}>{entry.name}</option>)}</select></label><span>{tenant?.roles.join(" · ")}</span><button type="button" onClick={() => void refresh()} disabled={pending === "refresh"}>Refresh</button></nav>
      {message && <p className="admin-message" role="status">{message}</p>}

      {permissions.has("workflow.manage") && <section className="owner-grid">
        <form className="evidence-panel owner-builder" onSubmit={saveWorkflow}>
          <p className="eyebrow eyebrow--green">{editing ? `EDIT DRAFT V${editing.draftVersion}` : "NEW WORKFLOW"}</p>
          <h2>{editing ? editing.name : "Workflow definition"}</h2>
          {!editing && <label className="field"><span>Internal name</span><input name="name" minLength={2} maxLength={160} required /></label>}
          <label className="field"><span>Participant title</span><input name="title" defaultValue={editing?.document.title} minLength={2} maxLength={160} required /></label>
          <label className="field"><span>Purpose</span><textarea name="purpose" defaultValue={editing?.document.purpose} minLength={2} maxLength={1000} required /></label>
          <label className="field"><span>Instructions</span><textarea name="instructions" defaultValue={editing?.document.instructions} maxLength={4000} /></label>
          {activities.map((activity, index) => <ActivityEditor key={`${activity.id}:${index}`} activity={activity} index={index} update={(next) => setActivities((current) => current.map((entry, item) => item === index ? next : entry))} remove={() => setActivities((current) => current.filter((_, item) => item !== index))} />)}
          <button className="secondary-button" type="button" disabled={activities.length >= 50} onClick={() => setActivities((current) => [...current, emptyActivity(current.length)])}>Add ordered step</button>
          <div className="form-row"><label className="field"><span>Default due days</span><input name="defaultDueDays" type="number" min="1" max="365" defaultValue={editing?.document.schedule?.defaultDueDays || 7} required /></label><label className="field"><span>Expiration days</span><input name="defaultExpirationDays" type="number" min="1" max="365" defaultValue={editing?.document.schedule?.defaultExpirationDays || 14} required /></label></div>
          <div className="form-row"><label className="field"><span>Reminder hours before due</span><input name="reminderHours" defaultValue={editing?.document.notifications?.reminderHoursBeforeDue.join(", ") || "24"} /></label><label className="field"><span>After completion</span><select name="postCompletion" defaultValue={editing?.document.access?.postCompletion || "receipt_only"}><option value="receipt_only">Receipt only</option><option value="content_until_expiration">Content until expiration</option><option value="content_always">Content remains available</option></select></label></div>
          <div className="owner-actions"><button className="primary-button" disabled={pending === "workflow"} type="submit">{pending === "workflow" ? "Saving…" : "Save validated draft"}</button>{editing && <button type="button" onClick={() => { setEditing(undefined); setActivities([emptyActivity(0)]); }}>Cancel edit</button>}</div>
        </form>
        <section className="evidence-panel"><p className="eyebrow eyebrow--green">DEFINITIONS</p><h2>Drafts and revisions</h2>{workflows.map((workflow) => <article className="owner-workflow" key={workflow.definitionId}><div><strong>{workflow.name}</strong><span>{workflow.document.activities.length} step(s) · draft v{workflow.draftVersion}{workflow.publishedRevision ? ` · published r${workflow.publishedRevision}` : ""}</span></div><div><button type="button" onClick={() => edit(workflow)}>Edit draft</button><button type="button" disabled={pending === `publish:${workflow.definitionId}`} onClick={() => void publish(workflow)}>Publish immutable revision</button></div></article>)}</section>
      </section>}

      {permissions.has("request.manage") && <section className="owner-grid">
        <form className="evidence-panel" onSubmit={issueRequest}><p className="eyebrow eyebrow--green">ISSUE PUBLISHED REVISION</p><h2>Participant request</h2><label className="field"><span>Workflow</span><select name="workflowRevisionId" required>{published.map((workflow) => <option key={workflow.definitionId} value={workflow.publishedRevisionId}>{workflow.name} · revision {workflow.publishedRevision}</option>)}</select></label><label className="field"><span>Verified participant email</span><input name="intendedEmail" type="email" required /></label><label className="field"><span>Schedule for (optional)</span><input name="scheduledFor" type="datetime-local" /></label><div className="form-row"><label className="field"><span>Due (optional)</span><input name="dueAt" type="datetime-local" /></label><label className="field"><span>Expires (optional)</span><input name="expiresAt" type="datetime-local" /></label></div><button className="primary-button" disabled={!published.length || pending === "issue"} type="submit">{pending === "issue" ? "Issuing…" : "Create request"}</button></form>
        <section className="evidence-panel"><p className="eyebrow eyebrow--green">REQUEST STATUS</p><h2>Lifecycle controls</h2>{requests.map((request) => <article className="owner-request" key={request.requestId}><div><strong>{request.title}</strong><span>{request.intendedEmail} · {request.status}</span><small>Due {request.dueAt ? new Date(request.dueAt).toLocaleString() : "not set"}</small></div><div>{!["completed", "expired", "revoked"].includes(request.status) && <><button type="button" onClick={() => void requestAction(request, "remind")}>Remind</button><button type="button" onClick={() => void requestAction(request, "reissue")}>Reissue</button><button type="button" onClick={() => void requestAction(request, "revoke")}>Revoke</button></>}</div></article>)}</section>
      </section>}

      {issued && <section className="evidence-issued"><p className="eyebrow eyebrow--green">ONE-TIME PARTICIPANT LINK</p><a href={`${baseURL}${issued.participantPath}`}>{baseURL}{issued.participantPath}</a><p>Copy this now. VASI stores only its digest after the encrypted delivery outbox is completed.</p></section>}

      {permissions.has("member.manage") && <section className="owner-grid"><form className="evidence-panel" onSubmit={setMember}><p className="eyebrow eyebrow--green">COMPANY ACCESS</p><h2>Grant by verified email</h2><label className="field"><span>Email</span><input name="email" type="email" required /></label><div className="form-row"><label className="field"><span>Role</span><select name="role"><option value="owner">Owner</option><option value="manager">Manager</option><option value="author">Author</option><option value="auditor">Auditor</option></select></label><label className="field"><span>Status</span><select name="status"><option value="active">Active</option><option value="disabled">Disabled</option></select></label></div><button className="primary-button" disabled={pending === "member"} type="submit">Update access</button></form><section className="evidence-panel"><p className="eyebrow eyebrow--green">MEMBERS</p><h2>Engine-owned roles</h2>{members.map((member, index) => <article className="owner-member" key={`${member.email}:${member.principalId}:${index}`}><strong>{member.email || member.principalId}</strong><span>{member.roles.join(", ")} · {member.status} · {member.source}</span></article>)}</section></section>}
    </main>
  );
}

function ActivityEditor({ activity, index, remove, update }: { activity: EditableActivity; index: number; remove: () => void; update: (activity: EditableActivity) => void }) {
  return <fieldset className="owner-activity"><legend>Step {index + 1}</legend><div className="form-row"><label className="field"><span>Stable step ID</span><input value={activity.id} pattern="[a-z][a-z0-9_-]{0,63}" onChange={(event) => update({ ...activity, id: event.target.value })} required /></label><label className="field"><span>Response</span><select value={activity.responseMode} onChange={(event) => update({ ...activity, responseMode: event.target.value as EditableActivity["responseMode"] })}><option value="acknowledgement">Acknowledgement</option><option value="yes_no">Yes / no</option></select></label></div><label className="field"><span>Step title</span><input value={activity.title} onChange={(event) => update({ ...activity, title: event.target.value })} minLength={2} maxLength={160} required /></label><label className="field"><span>Exact content or terms</span><textarea value={activity.content.terms} onChange={(event) => update({ ...activity, content: { ...activity.content, terms: event.target.value } })} minLength={2} maxLength={50000} rows={6} required /></label><label className="field"><span>Prompt</span><input value={activity.content.prompt} onChange={(event) => update({ ...activity, content: { ...activity.content, prompt: event.target.value } })} minLength={2} maxLength={1000} required /></label>{activity.responseMode === "yes_no" && <label className="owner-check"><input type="checkbox" checked={Boolean(activity.stopOnNo)} onChange={(event) => update({ ...activity, stopOnNo: event.target.checked })} /> A “No” response ends the workflow; otherwise continue to the next ordered step.</label>}{index > 0 && <button type="button" onClick={remove}>Remove step</button>}</fieldset>;
}

async function api<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    body: JSON.stringify(body),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  const result = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(result.error || "The request could not be completed.");
  return result;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "The request could not be completed.";
}
