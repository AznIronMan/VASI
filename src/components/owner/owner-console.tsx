"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import { BrandMark } from "@/components/brand-mark";
import { SignOutButton } from "@/components/auth/sign-out-button";
import type { IssuedEvidenceRequest } from "@/lib/evidence-types";
import type {
  OwnerArtifact,
  OwnerMember,
  OwnerRequest,
  OwnerTenant,
  OwnerWorkflow,
  PublishedWorkflow,
  WorkflowActivity,
  WorkflowDocument,
} from "@/lib/owner-types";

type EditableActivity = WorkflowActivity & {
  choicesText?: string;
  questionsText?: string;
  stopOn?: string;
};

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
  const [artifacts, setArtifacts] = useState<OwnerArtifact[]>([]);
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
      if (permissions.has("artifact.read")) {
        tasks.push(api<OwnerArtifact[]>("/api/owner/artifacts/list", { tenantId }).then(setArtifacts));
      } else setArtifacts([]);
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
      activities: activities.map(toWorkflowActivity),
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
      choicesText: serializeChoices(activity.content.choices),
      questionsText: serializeQuestions(activity.content.questions),
      stopOn: activity.transition?.cases?.find((entry) => entry.to === null)?.when.equals,
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

  async function uploadArtifact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const file = data.get("document");
    if (!(file instanceof File) || !file.size) {
      setMessage("Choose a non-empty document.");
      return;
    }
    setPending("artifact");
    setMessage(undefined);
    try {
      const uploadHeaders: Record<string, string> = {
        "content-type": file.type || "application/octet-stream",
        "x-vasi-artifact-role": String(data.get("role") || "source_document"),
        "x-vasi-filename": encodeURIComponent(file.name),
        "x-vasi-tenant-id": tenantId,
      };
      const replacesArtifactId = String(data.get("replacesArtifactId") || "");
      if (replacesArtifactId) uploadHeaders["x-vasi-replaces-artifact-id"] = replacesArtifactId;
      const sourceArtifactId = String(data.get("sourceArtifactId") || "");
      if (sourceArtifactId) uploadHeaders["x-vasi-source-artifact-id"] = sourceArtifactId;
      const response = await fetch("/api/owner/artifacts/upload", {
        body: file,
        headers: uploadHeaders,
        method: "POST",
      });
      const result = await response.json() as OwnerArtifact & { error?: string };
      if (!response.ok) throw new Error(result.error || "The document was rejected.");
      form.reset();
      setMessage(`Published immutable document revision ${result.revision}: ${result.originalFilename}.`);
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
  const publishedArtifacts = artifacts.filter((artifact) => artifact.status === "published");
  return (
    <main className="owner-shell">
      <header className="owner-header"><BrandMark compact /><div><p className="eyebrow eyebrow--green">PRIVATE COMPANY CONTROL PLANE</p><h1>Workflows and requests</h1></div><Link href="/admin">Identity administration</Link><SignOutButton /></header>
      <nav className="owner-tenant-nav"><label>Company<select value={tenantId} onChange={(event) => setTenantId(event.target.value)}>{initialTenants.map((entry) => <option key={entry.id} value={entry.id}>{entry.name}</option>)}</select></label><span>{tenant?.roles.join(" · ")}</span><button type="button" onClick={() => void refresh()} disabled={pending === "refresh"}>Refresh</button></nav>
      {message && <p className="admin-message" role="status">{message}</p>}

      {permissions.has("artifact.read") && <section className="owner-grid">
        {permissions.has("artifact.manage") && <form className="evidence-panel" onSubmit={uploadArtifact}>
          <p className="eyebrow eyebrow--green">POSTGRESQL DOCUMENT STORE</p>
          <h2>Upload an immutable document</h2>
          <p>Files are streamed into bounded PostgreSQL chunks, quarantined, inspected, hashed, and atomically published. No uploaded document is kept as a loose authoritative file.</p>
          <label className="field"><span>Document</span><input name="document" type="file" accept=".pdf,.txt,.md,.csv,.json,.xml,.docx,.xlsx,.pptx,.odt,.ods,.odp" required /></label>
          <div className="form-row"><label className="field"><span>Artifact role</span><select name="role"><option value="source_document">Source document</option><option value="derived_preview">Derived preview</option></select></label><label className="field"><span>Replace a prior revision (optional)</span><select name="replacesArtifactId"><option value="">Create a new document family</option>{publishedArtifacts.map((artifact) => <option key={artifact.id} value={artifact.id}>{artifact.originalFilename} · r{artifact.revision}</option>)}</select></label></div>
          <label className="field"><span>Source artifact for a derived preview (required only for previews)</span><select name="sourceArtifactId"><option value="">Not a derived representation</option>{publishedArtifacts.map((artifact) => <option key={artifact.id} value={artifact.id}>{artifact.originalFilename} · r{artifact.revision}</option>)}</select></label>
          <button className="primary-button" disabled={pending === "artifact"} type="submit">{pending === "artifact" ? "Streaming and inspecting…" : "Upload and publish"}</button>
        </form>}
        <section className="evidence-panel">
          <p className="eyebrow eyebrow--green">ARTIFACT INVENTORY</p><h2>Published and quarantined revisions</h2>
          {artifacts.map((artifact) => <article className="owner-artifact" key={artifact.id}><div><strong>{artifact.originalFilename}</strong><span>{artifact.status} · r{artifact.revision} · {formatBytes(artifact.byteLength || artifact.expectedByteLength)}</span><small>{artifact.mediaType}{artifact.sha256 ? ` · ${artifact.sha256.slice(0, 16)}…` : ""}</small></div><div>{artifact.status === "published" && <><a href={`/api/owner/artifacts/${artifact.id}?tenantId=${encodeURIComponent(tenantId)}`} target="_blank" rel="noreferrer">View</a><a href={`/api/owner/artifacts/${artifact.id}?tenantId=${encodeURIComponent(tenantId)}&disposition=attachment`}>Download</a></>}</div></article>)}
        </section>
      </section>}

      {permissions.has("workflow.manage") && <section className="owner-grid">
        <form className="evidence-panel owner-builder" onSubmit={saveWorkflow}>
          <p className="eyebrow eyebrow--green">{editing ? `EDIT DRAFT V${editing.draftVersion}` : "NEW WORKFLOW"}</p>
          <h2>{editing ? editing.name : "Workflow definition"}</h2>
          {!editing && <label className="field"><span>Internal name</span><input name="name" minLength={2} maxLength={160} required /></label>}
          <label className="field"><span>Participant title</span><input name="title" defaultValue={editing?.document.title} minLength={2} maxLength={160} required /></label>
          <label className="field"><span>Purpose</span><textarea name="purpose" defaultValue={editing?.document.purpose} minLength={2} maxLength={1000} required /></label>
          <label className="field"><span>Instructions</span><textarea name="instructions" defaultValue={editing?.document.instructions} maxLength={4000} /></label>
          {activities.map((activity, index) => <ActivityEditor key={`${activity.id}:${index}`} activity={activity} artifacts={publishedArtifacts} index={index} update={(next) => setActivities((current) => current.map((entry, item) => item === index ? next : entry))} remove={() => setActivities((current) => current.filter((_, item) => item !== index))} />)}
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

function ActivityEditor({
  activity,
  artifacts,
  index,
  remove,
  update,
}: {
  activity: EditableActivity;
  artifacts: OwnerArtifact[];
  index: number;
  remove: () => void;
  update: (activity: EditableActivity) => void;
}) {
  const branchOutcomes = outcomesFor(activity);
  const changeType = (type: WorkflowActivity["type"]) => {
    const replacement = activityForType(type, index, artifacts);
    update({ ...replacement, id: activity.id, title: activity.title });
  };
  return <fieldset className="owner-activity">
    <legend>Step {index + 1}</legend>
    <div className="form-row">
      <label className="field"><span>Stable step ID</span><input value={activity.id} pattern="[a-z][a-z0-9_-]{0,63}" onChange={(event) => update({ ...activity, id: event.target.value })} required /></label>
      <label className="field"><span>Activity type</span><select value={activity.type} onChange={(event) => changeType(event.target.value as WorkflowActivity["type"])}><option value="terms_response">Terms / acknowledgement</option><option value="approval">Approval decision</option><option value="single_choice">Single-choice question</option><option value="multiple_choice">Multiple-choice question</option><option value="free_form">Free-form answer</option><option value="electronic_signature">Electronic signature</option><option value="document_review">PostgreSQL document review</option><option value="questionnaire">Scored questionnaire / test</option></select></label>
    </div>
    <label className="field"><span>Step title</span><input value={activity.title} onChange={(event) => update({ ...activity, title: event.target.value })} minLength={2} maxLength={160} required /></label>

    {activity.type === "terms_response" && <>
      <label className="field"><span>Exact content or terms</span><textarea value={activity.content.terms || ""} onChange={(event) => update({ ...activity, content: { ...activity.content, terms: event.target.value } })} minLength={2} maxLength={50000} rows={6} required /></label>
      <div className="form-row"><label className="field"><span>Prompt</span><input value={activity.content.prompt} onChange={(event) => update({ ...activity, content: { ...activity.content, prompt: event.target.value } })} required /></label><label className="field"><span>Response</span><select value={activity.responseMode} onChange={(event) => update({ ...activity, responseMode: event.target.value as "acknowledgement" | "yes_no", stopOn: undefined })}><option value="acknowledgement">Acknowledgement</option><option value="yes_no">Yes / no</option></select></label></div>
    </>}

    {activity.type === "approval" && <>
      <label className="field"><span>Exact statement to decide</span><textarea value={activity.content.statement || ""} onChange={(event) => update({ ...activity, content: { ...activity.content, statement: event.target.value } })} rows={6} required /></label>
      <label className="field"><span>Decision prompt</span><input value={activity.content.prompt} onChange={(event) => update({ ...activity, content: { ...activity.content, prompt: event.target.value } })} required /></label>
    </>}

    {(activity.type === "single_choice" || activity.type === "multiple_choice") && <>
      <label className="field"><span>Question</span><input value={activity.content.prompt} onChange={(event) => update({ ...activity, content: { ...activity.content, prompt: event.target.value } })} required /></label>
      <label className="field"><span>Choices — one per line as stable_id | Exact label</span><textarea value={activity.choicesText ?? serializeChoices(activity.content.choices)} onChange={(event) => update({ ...activity, choicesText: event.target.value, content: { ...activity.content, choices: parseChoices(event.target.value) } })} rows={5} required /></label>
      {activity.type === "multiple_choice" && <div className="form-row"><label className="field"><span>Minimum selections</span><input type="number" min="0" max={activity.content.choices?.length || 2} value={activity.content.minSelections ?? 1} onChange={(event) => update({ ...activity, content: { ...activity.content, minSelections: Number(event.target.value) } })} /></label><label className="field"><span>Maximum selections</span><input type="number" min="1" max={activity.content.choices?.length || 2} value={activity.content.maxSelections ?? activity.content.choices?.length ?? 2} onChange={(event) => update({ ...activity, content: { ...activity.content, maxSelections: Number(event.target.value) } })} /></label></div>}
    </>}

    {activity.type === "free_form" && <>
      <label className="field"><span>Question or prompt</span><textarea value={activity.content.prompt} onChange={(event) => update({ ...activity, content: { ...activity.content, prompt: event.target.value } })} required /></label>
      <div className="form-row"><label className="field"><span>Minimum characters</span><input type="number" min="0" max="10000" value={activity.content.minLength ?? 1} onChange={(event) => update({ ...activity, content: { ...activity.content, minLength: Number(event.target.value) } })} /></label><label className="field"><span>Maximum characters</span><input type="number" min="1" max="10000" value={activity.content.maxLength ?? 2000} onChange={(event) => update({ ...activity, content: { ...activity.content, maxLength: Number(event.target.value) } })} /></label></div>
    </>}

    {activity.type === "electronic_signature" && <>
      <label className="field"><span>Exact statement being signed</span><textarea value={activity.content.statement || ""} onChange={(event) => update({ ...activity, content: { ...activity.content, statement: event.target.value } })} rows={5} required /></label>
      <label className="field"><span>Signature prompt</span><input value={activity.content.prompt} onChange={(event) => update({ ...activity, content: { ...activity.content, prompt: event.target.value } })} required /></label>
      <label className="field"><span>Electronic-signature consent text</span><textarea value={activity.content.consentText || ""} onChange={(event) => update({ ...activity, content: { ...activity.content, consentText: event.target.value } })} minLength={10} required /></label>
      <label className="field"><span>Allowed signature input</span><select value={(activity.content.methods || ["typed", "drawn"]).join(",")} onChange={(event) => update({ ...activity, content: { ...activity.content, methods: event.target.value.split(",") as Array<"typed" | "drawn"> } })}><option value="typed,drawn">Typed or drawn</option><option value="typed">Typed only</option><option value="drawn">Drawn only</option></select></label>
    </>}

    {activity.type === "document_review" && <>
      <label className="field"><span>Published document revision</span><select value={activity.content.artifactId || ""} onChange={(event) => { const artifact = artifacts.find((entry) => entry.id === event.target.value); update({ ...activity, content: { ...activity.content, artifactId: event.target.value, displayName: artifact?.originalFilename || activity.content.displayName } }); }} required><option value="">Select a PostgreSQL artifact</option>{artifacts.map((artifact) => <option key={artifact.id} value={artifact.id}>{artifact.originalFilename} · r{artifact.revision} · {artifact.sha256?.slice(0, 12)}…</option>)}</select></label>
      <label className="field"><span>Participant-facing document name</span><input value={activity.content.displayName || ""} onChange={(event) => update({ ...activity, content: { ...activity.content, displayName: event.target.value } })} required /></label>
      <label className="field"><span>Review prompt</span><input value={activity.content.prompt} onChange={(event) => update({ ...activity, content: { ...activity.content, prompt: event.target.value } })} required /></label>
    </>}

    {activity.type === "questionnaire" && <>
      <label className="field"><span>Participant instructions</span><textarea value={activity.content.instructions || ""} onChange={(event) => update({ ...activity, content: { ...activity.content, instructions: event.target.value } })} /></label>
      <label className="field"><span>Questions — ID | Prompt | single/multiple | choice_id:Label;… | correct IDs | points</span><textarea value={activity.questionsText ?? serializeQuestions(activity.content.questions)} onChange={(event) => update({ ...activity, questionsText: event.target.value, content: { ...activity.content, questions: parseQuestions(event.target.value) } })} rows={8} required /></label>
      <label className="field"><span>Passing percentage</span><input type="number" min="0" max="100" value={activity.content.passingPercent ?? 70} onChange={(event) => update({ ...activity, content: { ...activity.content, passingPercent: Number(event.target.value) } })} /></label>
    </>}

    {branchOutcomes.length > 0 && <label className="field"><span>Optional terminal outcome</span><select value={activity.stopOn || ""} onChange={(event) => update({ ...activity, stopOn: event.target.value || undefined })}><option value="">All outcomes continue to the next ordered step</option>{branchOutcomes.map((entry) => <option key={entry.value} value={entry.value}>End when: {entry.label}</option>)}</select></label>}
    {index > 0 && <button type="button" onClick={remove}>Remove step</button>}
  </fieldset>;
}

function activityForType(type: WorkflowActivity["type"], index: number, artifacts: OwnerArtifact[]): EditableActivity {
  const base = { id: `step_${index + 1}`, title: `Step ${index + 1}` };
  switch (type) {
    case "approval": return { ...base, content: { prompt: "Do you approve this statement?", statement: "" }, responseMode: "approval", type };
    case "single_choice": return { ...base, choicesText: "choice_a | First choice\nchoice_b | Second choice", content: { choices: [{ id: "choice_a", label: "First choice" }, { id: "choice_b", label: "Second choice" }], prompt: "Choose one." }, responseMode: "single_choice", type };
    case "multiple_choice": return { ...base, choicesText: "choice_a | First choice\nchoice_b | Second choice", content: { choices: [{ id: "choice_a", label: "First choice" }, { id: "choice_b", label: "Second choice" }], maxSelections: 2, minSelections: 1, prompt: "Choose all that apply." }, responseMode: "multiple_choice", type };
    case "free_form": return { ...base, content: { maxLength: 2000, minLength: 1, multiline: true, prompt: "Enter your response." }, responseMode: "free_form", type };
    case "electronic_signature": return { ...base, content: { consentText: "I intend this electronic mark to be my signature.", methods: ["typed", "drawn"], prompt: "Sign below.", statement: "" }, responseMode: "electronic_signature", type };
    case "document_review": return { ...base, content: { artifactId: artifacts[0]?.id || "", displayName: artifacts[0]?.originalFilename || "Document", prompt: "Review the document and acknowledge when finished." }, responseMode: "document_review", type };
    case "questionnaire": return { ...base, content: { instructions: "Answer each question, then submit for scoring.", passingPercent: 70, questions: [{ choices: [{ id: "answer_a", label: "Answer A" }, { id: "answer_b", label: "Answer B" }], correctChoiceIds: ["answer_b"], id: "question_one", points: 1, prompt: "Question one", type: "single_choice" }] }, questionsText: "question_one | Question one | single | answer_a:Answer A;answer_b:Answer B | answer_b | 1", responseMode: "questionnaire", type };
    default: return { ...base, content: { prompt: "Do you acknowledge and agree?", terms: "" }, responseMode: "acknowledgement", type: "terms_response" };
  }
}

function outcomesFor(activity: EditableActivity) {
  if (activity.type === "terms_response") return activity.responseMode === "yes_no" ? [{ label: "No", value: "no" }] : [];
  if (activity.type === "approval") return [{ label: "Disapproved", value: "disapproved" }, { label: "Declined", value: "declined" }];
  if (activity.type === "single_choice") return (activity.content.choices || []).map((choice) => ({ label: choice.label, value: choice.id }));
  if (activity.type === "questionnaire") return [{ label: "Failed", value: "failed" }];
  return [];
}

function toWorkflowActivity(entry: EditableActivity): WorkflowActivity {
  const definition = Object.fromEntries(
    Object.entries(entry).filter(([key]) => !["choicesText", "questionsText", "stopOn"].includes(key)),
  ) as WorkflowActivity;
  return {
    ...definition,
    contractVersion: 1,
    transition: entry.stopOn ? { cases: [{ to: null, when: { equals: entry.stopOn } }] } : undefined,
  };
}

function parseChoices(value: string) {
  return value.split("\n").map((line) => line.split("|").map((part) => part.trim())).filter(([id, label]) => id && label).map(([id, label]) => ({ id, label }));
}

function serializeChoices(choices?: Array<{ id: string; label: string }>) {
  return (choices || []).map((choice) => `${choice.id} | ${choice.label}`).join("\n");
}

function parseQuestions(value: string) {
  return value.split("\n").map((line) => line.split("|").map((part) => part.trim())).filter((parts) => parts.length >= 6 && parts.every((part) => part.length > 0)).map(([id, prompt, rawType, rawChoices, rawCorrect, rawPoints]) => ({
    choices: rawChoices.split(";").map((entry) => entry.split(":")).filter(([choiceId, label]) => choiceId && label).map(([choiceId, label]) => ({ id: choiceId.trim(), label: label.trim() })),
    correctChoiceIds: rawCorrect.split(",").map((entry) => entry.trim()).filter(Boolean),
    id,
    points: Number(rawPoints),
    prompt,
    type: rawType === "multiple" ? "multiple_choice" as const : "single_choice" as const,
  }));
}

function serializeQuestions(questions?: import("@/lib/owner-types").WorkflowQuestion[]) {
  return (questions || []).map((question) => `${question.id} | ${question.prompt} | ${question.type === "multiple_choice" ? "multiple" : "single"} | ${question.choices.map((choice) => `${choice.id}:${choice.label}`).join(";")} | ${(question.correctChoiceIds || []).join(",")} | ${question.points || 1}`).join("\n");
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1_048_576) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1_048_576).toFixed(1)} MiB`;
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
