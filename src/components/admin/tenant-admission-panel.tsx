"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

import type {
  AdminTenantAdmission,
  TenantAdmissionGate,
  TenantAdmissionGateId,
} from "@/lib/owner-types";

const gateCopy: Record<TenantAdmissionGateId, { description: string; label: string }> = {
  exact_release: {
    description: "Exact pushed release, migrations, images, source assurance, and deployment evidence.",
    label: "Exact release",
  },
  isolation_integrity: {
    description: "Tenant isolation, authorization, immutable evidence, and independent security review.",
    label: "Isolation and integrity",
  },
  identity_delivery: {
    description: "Approved identity providers, sender tuple, delivery path, and supportable account recovery.",
    label: "Identity and delivery",
  },
  privacy_legal: {
    description: "Approved notices, retention, holds, subject rights, electronic-act use, and legal claims.",
    label: "Privacy and legal",
  },
  accessibility: {
    description: "Automated checks plus manual assistive-technology and supported browser/device review.",
    label: "Accessibility",
  },
  malware_content: {
    description: "Document inspection policy, safe external media use, and content-owner acceptance.",
    label: "Malware and content safety",
  },
  recovery_custody: {
    description: "Encrypted off-host custody, restore exercise, key/certificate ownership, RPO, and RTO.",
    label: "Recovery and custody",
  },
  capacity_support: {
    description: "Named pilot owner, users, scenarios, support contacts, stop criteria, and capacity limits.",
    label: "Capacity and support",
  },
};

export function TenantAdmissionPanel() {
  const [records, setRecords] = useState<AdminTenantAdmission[]>([]);
  const [selectedTenantId, setSelectedTenantId] = useState("");
  const [editingGate, setEditingGate] = useState<TenantAdmissionGateId>();
  const [pending, setPending] = useState(true);
  const [message, setMessage] = useState<string>();
  const [messageType, setMessageType] = useState<"error" | "success">("success");

  useEffect(() => {
    let active = true;
    fetch("/api/admin/product/tenant-admissions", { cache: "no-store" })
      .then(async (response) => {
        const body = await response.json() as AdminTenantAdmission[] & { error?: string };
        if (!response.ok || !Array.isArray(body)) {
          throw new Error(body.error || "Tenant admission records are unavailable.");
        }
        if (!active) return;
        setRecords(body);
        setSelectedTenantId((current) => current || body[0]?.tenant.id || "");
      })
      .catch((error) => {
        if (!active) return;
        setMessage(error instanceof Error ? error.message : "Tenant admission records are unavailable.");
        setMessageType("error");
      })
      .finally(() => { if (active) setPending(false); });
    return () => { active = false; };
  }, []);

  const record = useMemo(
    () => records.find((candidate) => candidate.tenant.id === selectedTenantId),
    [records, selectedTenantId],
  );

  async function decide(
    gate: TenantAdmissionGate,
    decision: "approved" | "pending",
    approval?: { evidenceDigest: string; evidenceReference: string; reviewerReference: string },
  ) {
    if (!record) return;
    setPending(true);
    setMessage(undefined);
    try {
      const response = await fetch("/api/admin/product/tenant-admissions", {
        body: JSON.stringify({
          decision,
          expectedRevision: record.revision,
          gateId: gate.id,
          tenantId: record.tenant.id,
          ...approval,
        }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = await response.json() as AdminTenantAdmission & { error?: string };
      if (!response.ok) throw new Error(admissionError(body.error));
      setRecords((current) => current.map((candidate) =>
        candidate.tenant.id === body.tenant.id ? body : candidate
      ));
      setEditingGate(undefined);
      setMessage(decision === "approved"
        ? `${gateCopy[gate.id].label} approval recorded in immutable revision ${body.revision}.`
        : `${gateCopy[gate.id].label} approval revoked; production work is now blocked.`);
      setMessageType("success");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The admission decision could not be recorded.");
      setMessageType("error");
    } finally {
      setPending(false);
    }
  }

  function approve(event: FormEvent<HTMLFormElement>, gate: TenantAdmissionGate) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    void decide(gate, "approved", {
      evidenceDigest: String(data.get("evidenceDigest") || "").trim().toLowerCase(),
      evidenceReference: String(data.get("evidenceReference") || "").trim(),
      reviewerReference: String(data.get("reviewerReference") || "").trim(),
    });
  }

  return <section className="admin-invite admission-panel" aria-labelledby="tenant-admission-title">
    <div className="admission-panel__heading">
      <div>
        <p className="eyebrow eyebrow--green">PRODUCTION ADMISSION</p>
        <h2 id="tenant-admission-title">Company assurance gates</h2>
        <p>Production requests and outbound integrations stay blocked until every gate has an attributable approval.</p>
      </div>
      {record && <span className={`admission-status admission-status--${record.status}`}>
        {record.status === "admitted" ? "Admitted" : "Pending"}
      </span>}
    </div>

    {records.length > 0 && <label className="field admission-panel__tenant">
      <span>Company tenant</span>
      <select value={selectedTenantId} onChange={(event) => {
        setSelectedTenantId(event.target.value);
        setEditingGate(undefined);
        setMessage(undefined);
      }}>
        {records.map((candidate) => <option value={candidate.tenant.id} key={candidate.tenant.id}>
          {candidate.tenant.name} ({candidate.tenant.slug})
        </option>)}
      </select>
    </label>}

    {message && <p className={`admin-message admin-message--${messageType}`} role={messageType === "error" ? "alert" : "status"}>{message}</p>}
    {!records.length && !pending && !message && <p>No company tenants have been provisioned.</p>}
    {!records.length && pending && <p>Loading admission records…</p>}

    {record && <>
      <div className="admission-gates">
        {record.admission.gates.map((gate) => {
          const copy = gateCopy[gate.id];
          const editing = editingGate === gate.id;
          return <article className={`admission-gate admission-gate--${gate.state}`} key={gate.id}>
            <div className="admission-gate__heading">
              <div><h3>{copy.label}</h3><p>{copy.description}</p></div>
              <span>{gate.state === "approved" ? "Approved" : "Pending"}</span>
            </div>
            {gate.state === "approved" && <dl className="admission-gate__evidence">
              <div><dt>Reviewer</dt><dd>{gate.reviewerReference}</dd></div>
              <div><dt>Evidence</dt><dd>{gate.evidenceReference}</dd></div>
              <div><dt>SHA-256</dt><dd><code>{gate.evidenceDigest}</code></dd></div>
              <div><dt>Recorded</dt><dd>{gate.decidedAt ? new Date(gate.decidedAt).toLocaleString() : "Unavailable"}</dd></div>
            </dl>}
            {editing && <ApprovalForm gate={gate} pending={pending} onCancel={() => setEditingGate(undefined)} onSubmit={approve} />}
            {!editing && <div className="admission-gate__actions">
              <button className="secondary-button" disabled={pending} type="button" onClick={() => setEditingGate(gate.id)}>
                {gate.state === "approved" ? "Replace approval" : "Record approval"}
              </button>
              {gate.state === "approved" && <button className="table-link" disabled={pending} type="button" onClick={() => {
                if (window.confirm(`Revoke ${copy.label}? New production requests and outbound work will be blocked.`)) {
                  void decide(gate, "pending");
                }
              }}>Revoke approval</button>}
            </div>}
          </article>;
        })}
      </div>
      <p className="admission-panel__footnote">
        Revision {record.revision} · admission fingerprint <code>{record.admissionHash}</code> · recorded by {record.createdByPrincipalId} at {new Date(record.createdAt).toLocaleString()}.
        References must be opaque identifiers; approval documents, URLs, credentials, and narrative case notes are not stored here.
      </p>
    </>}
  </section>;
}

function ApprovalForm({
  gate,
  onCancel,
  onSubmit,
  pending,
}: {
  gate: TenantAdmissionGate;
  onCancel: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>, gate: TenantAdmissionGate) => void;
  pending: boolean;
}) {
  return <form className="admission-approval-form" onSubmit={(event) => onSubmit(event, gate)}>
    <div className="form-row">
      <label className="field"><span>Reviewer reference</span><input name="reviewerReference" defaultValue={gate.reviewerReference} pattern="[A-Za-z0-9._:-]+" maxLength={160} required placeholder="customer-legal-2026" /></label>
      <label className="field"><span>Evidence reference</span><input name="evidenceReference" defaultValue={gate.evidenceReference} pattern="[A-Za-z0-9._:-]+" maxLength={160} required placeholder="review-package:2026-07" /></label>
    </div>
    <label className="field"><span>Evidence SHA-256</span><input className="mono-input" name="evidenceDigest" defaultValue={gate.evidenceDigest} pattern="[a-fA-F0-9]{64}" minLength={64} maxLength={64} required placeholder={"a".repeat(64)} /></label>
    <div className="admission-gate__actions">
      <button className="primary-button" disabled={pending} type="submit">Record immutable approval</button>
      <button className="table-link" disabled={pending} type="button" onClick={onCancel}>Cancel</button>
    </div>
  </form>;
}

function admissionError(code?: string) {
  if (code === "tenant_admission_revision_conflict") return "The record changed. Reload before recording another decision.";
  if (code === "tenant_admission_decision_unchanged") return "That gate is already in the requested state.";
  if (code === "invalid_product_configuration") return "Use opaque references and an exact lowercase SHA-256 evidence digest.";
  return code || "The admission decision could not be recorded.";
}
