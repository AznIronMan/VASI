"use client";

import { FormEvent, useRef, useState } from "react";
import Link from "next/link";

import type {
  EvidenceTenant,
  IssuedEvidenceRequest,
} from "@/lib/evidence-types";
import type { AdminCompanyProvisioningResult } from "@/lib/owner-types";
import {
  nextCompanyProvisioningCommand,
  type CompanyProvisioningRetry,
} from "@/lib/company-provisioning-retry";

export function EvidenceConsole({
  baseURL,
  initialTenants,
}: {
  baseURL: string;
  initialTenants: EvidenceTenant[];
}) {
  const [tenants, setTenants] = useState(initialTenants);
  const [issued, setIssued] = useState<IssuedEvidenceRequest | null>(null);
  const [record, setRecord] = useState<unknown>();
  const [pending, setPending] = useState<string>();
  const [message, setMessage] = useState<string>();
  const tenantRetryCommand = useRef<CompanyProvisioningRetry | undefined>(undefined);

  async function createTenant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setPending("tenant");
    setMessage(undefined);
    const draft = {
      inviteOwner: data.get("inviteOwner") === "on",
      name: String(data.get("name") || ""),
      ownerEmail: String(data.get("ownerEmail") || ""),
      slug: String(data.get("slug") || ""),
    };
    const command = nextCompanyProvisioningCommand(
      tenantRetryCommand.current,
      draft,
      () => crypto.randomUUID(),
    );
    tenantRetryCommand.current = command;
    try {
      const result = await api<AdminCompanyProvisioningResult>("/api/admin/product/tenants", {
        body: JSON.stringify({
          commandId: command.commandId,
          ...draft,
        }),
        method: "POST",
      });
      tenantRetryCommand.current = undefined;
      setTenants((current) => [...current, result.company]);
      form.reset();
      setMessage(
        result.invitation.status === "delivery_failed"
          ? "Company evidence space and owner grant created, but the login invitation was not delivered."
          : result.invitation.status === "delivery_unknown"
            ? "Company evidence space and owner grant created; invitation delivery could not be confirmed and was not repeated."
            : "Company evidence space and owner handoff created.",
      );
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(undefined);
    }
  }

  async function issueRequest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setPending("issue");
    setIssued(null);
    setMessage(undefined);
    try {
      const result = await api<IssuedEvidenceRequest>("/api/admin/evidence/requests", {
        body: JSON.stringify({
          intendedEmail: data.get("intendedEmail"),
          prompt: data.get("prompt"),
          purpose: data.get("purpose"),
          responseMode: data.get("responseMode"),
          tenantId: data.get("tenantId"),
          terms: data.get("terms"),
          title: data.get("title"),
        }),
        method: "POST",
      });
      setIssued(result);
      setMessage("Evidence request issued. The participant link is shown once below.");
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(undefined);
    }
  }

  async function loadRecord(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setPending("record");
    setRecord(undefined);
    setMessage(undefined);
    try {
      setRecord(await api<unknown>("/api/admin/evidence/records", {
        body: JSON.stringify({
          assignmentId: data.get("assignmentId"),
          tenantId: data.get("tenantId"),
        }),
        method: "POST",
      }));
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(undefined);
    }
  }

  return (
    <main className="evidence-admin-shell">
      <header className="evidence-admin-header">
        <div>
          <p className="eyebrow eyebrow--green">PRIVATE ENGINE / COMPATIBILITY TOOL</p>
          <h1>First-slice evidence requests</h1>
          <p>This narrow issuer remains for compatibility. Use the company control plane for draft, publication, branching, scheduling, and lifecycle management.</p>
        </div>
        <div><Link href="/owner">Company workflows</Link> · <Link href="/admin">Identity administration</Link></div>
      </header>

      <section className="evidence-admin-grid">
        <form className="evidence-panel" onSubmit={createTenant}>
          <p className="eyebrow eyebrow--green">COMPANY SPACE</p>
          <h2>Create a company</h2>
          <label className="field"><span>Company name</span><input name="name" minLength={2} maxLength={160} required /></label>
          <label className="field"><span>Initial owner email</span><input name="ownerEmail" type="email" maxLength={320} required /></label>
          <label className="field"><span>Identifier</span><input name="slug" pattern="[a-z0-9][a-z0-9-]{0,62}[a-z0-9]" minLength={2} maxLength={64} placeholder="example-company" required /></label>
          <label className="company-provisioning__invite"><input name="inviteOwner" type="checkbox" defaultChecked /><span>Email a login invitation after provisioning.</span></label>
          <button className="primary-button" disabled={Boolean(pending)} type="submit">{pending === "tenant" ? "Creating…" : "Create company space"}</button>
        </form>

        <form className="evidence-panel evidence-panel--wide" onSubmit={issueRequest}>
          <p className="eyebrow eyebrow--green">ISSUE REQUEST</p>
          <h2>Terms and response</h2>
          <div className="form-row">
            <label className="field"><span>Company</span><select name="tenantId" required disabled={!tenants.length}>{tenants.map((tenant) => <option value={tenant.id} key={tenant.id}>{tenant.name}</option>)}</select></label>
            <label className="field"><span>Participant email</span><input name="intendedEmail" type="email" required /></label>
          </div>
          <label className="field"><span>Title</span><input name="title" minLength={2} maxLength={160} required /></label>
          <label className="field"><span>Purpose</span><textarea name="purpose" minLength={2} maxLength={1000} required /></label>
          <label className="field"><span>Exact terms</span><textarea name="terms" minLength={2} maxLength={50000} rows={8} required /></label>
          <div className="form-row">
            <label className="field"><span>Prompt</span><input name="prompt" defaultValue="Do you acknowledge and agree?" minLength={2} maxLength={1000} required /></label>
            <label className="field"><span>Response</span><select name="responseMode"><option value="acknowledgement">Acknowledgement</option><option value="yes_no">Yes / no</option></select></label>
          </div>
          <button className="primary-button" disabled={Boolean(pending) || !tenants.length} type="submit">{pending === "issue" ? "Issuing…" : "Issue sealed request"}</button>
        </form>
      </section>

      {message && <p className="admin-message" role="status">{message}</p>}
      {issued && (
        <section className="evidence-issued">
          <p className="eyebrow eyebrow--green">OPAQUE PARTICIPANT LINK</p>
          <a href={`${baseURL}${issued.participantPath}`}>{baseURL}{issued.participantPath}</a>
          <dl><div><dt>Assignment ID</dt><dd>{issued.assignmentId}</dd></div><div><dt>Expires</dt><dd>{new Date(issued.expiresAt).toLocaleString()}</dd></div></dl>
        </section>
      )}

      <form className="evidence-panel evidence-record-form" onSubmit={loadRecord}>
        <p className="eyebrow eyebrow--green">VERIFIED RECORD</p>
        <h2>Load a completed structured record</h2>
        <div className="form-row">
          <label className="field"><span>Company</span><select name="tenantId" required>{tenants.map((tenant) => <option value={tenant.id} key={tenant.id}>{tenant.name}</option>)}</select></label>
          <label className="field"><span>Assignment ID</span><input name="assignmentId" defaultValue={issued?.assignmentId} required /></label>
        </div>
        <button className="secondary-button" disabled={Boolean(pending) || !tenants.length} type="submit">{pending === "record" ? "Verifying…" : "Verify and load record"}</button>
      </form>
      {record !== undefined && <pre className="evidence-record">{JSON.stringify(record, null, 2)}</pre>}
    </main>
  );
}

async function api<T>(url: string, init: RequestInit) {
  const response = await fetch(url, {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
  });
  const result = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(result.error || "The request could not be completed.");
  return result;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "The request could not be completed.";
}
