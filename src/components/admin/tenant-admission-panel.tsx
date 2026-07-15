"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

import { COMPANY_PROVISIONED_EVENT } from "@/components/admin/tenant-provisioning-panel";

import type {
  AdminTenantAdmission,
  TenantAdmissionGate,
  TenantAdmissionGateId,
  TenantProductionStopReason,
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

const stopReasonCopy: Record<TenantProductionStopReason, string> = {
  security_incident: "Security or integrity incident",
  privacy_or_legal: "Privacy or legal direction",
  identity_or_delivery: "Identity or delivery failure",
  content_safety: "Content or malware safety concern",
  recovery_or_capacity: "Recovery, capacity, or support limit",
  operator_decision: "Operator decision",
};

export function TenantAdmissionPanel() {
  const [records, setRecords] = useState<AdminTenantAdmission[]>([]);
  const [selectedTenantId, setSelectedTenantId] = useState("");
  const [editingGate, setEditingGate] = useState<TenantAdmissionGateId>();
  const [stopping, setStopping] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [pending, setPending] = useState(true);
  const [message, setMessage] = useState<string>();
  const [messageType, setMessageType] = useState<"error" | "success">("success");

  useEffect(() => {
    let active = true;
    const load = () => {
      setPending(true);
      fetch("/api/admin/product/tenant-admissions", { cache: "no-store" }).then(async (response) => {
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
    };
    load();
    window.addEventListener(COMPANY_PROVISIONED_EVENT, load);
    return () => {
      active = false;
      window.removeEventListener(COMPANY_PROVISIONED_EVENT, load);
    };
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

  async function stopProduction(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!record) return;
    const data = new FormData(event.currentTarget);
    const gateId = String(data.get("gateId") || "") as TenantAdmissionGateId;
    const reasonCode = String(data.get("reasonCode") || "") as TenantProductionStopReason;
    const incidentReference = String(data.get("incidentReference") || "").trim();
    if (!window.confirm(
      `Stop production for ${record.tenant.name}? Every scheduled, issued, or in-progress request will be permanently revoked. Completed records remain available.`,
    )) return;
    setPending(true);
    setMessage(undefined);
    try {
      const response = await fetch("/api/admin/product/tenant-production-stops", {
        body: JSON.stringify({
          commandId: crypto.randomUUID(),
          expectedRevision: record.revision,
          gateId,
          incidentReference,
          reasonCode,
          tenantId: record.tenant.id,
        }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = await response.json() as AdminTenantAdmission & { error?: string };
      if (!response.ok) throw new Error(admissionError(body.error));
      setRecords((current) => current.map((candidate) =>
        candidate.tenant.id === body.tenant.id ? body : candidate
      ));
      setStopping(false);
      setEditingGate(undefined);
      setMessage(
        `Production stopped. ${body.lastProductionStop?.revokedRequestCount ?? 0} active requests revoked and ${body.lastProductionStop?.suppressedNotificationCount ?? 0} queued notifications suppressed.`,
      );
      setMessageType("success");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Tenant production could not be stopped.");
      setMessageType("error");
    } finally {
      setPending(false);
    }
  }

  async function downloadReadiness(format: "html" | "json") {
    if (!record) return;
    setExporting(true);
    setMessage(undefined);
    try {
      const response = await fetch("/api/admin/product/tenant-readiness-exports", {
        body: JSON.stringify({ format, tenantId: record.tenant.id }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({})) as { error?: string };
        throw new Error(body.error || "The readiness dossier could not be exported.");
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `vasi-readiness-${record.tenant.id}.${format}`;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 0);
      const dossierHash = response.headers.get("x-vasi-dossier-sha256");
      setMessage(`Readiness ${format.toUpperCase()} exported${dossierHash ? ` with dossier SHA-256 ${dossierHash}` : ""}.`);
      setMessageType("success");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The readiness dossier could not be exported.");
      setMessageType("error");
    } finally {
      setExporting(false);
    }
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
        setStopping(false);
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
      <section className="readiness-export" aria-labelledby="readiness-export-title">
        <div>
          <h3 id="readiness-export-title">Pilot readiness dossier</h3>
          <p>Package current hashes, gate references, safe integration facts, capacity, and stop history with the VASI integrity seal and any configured certificate seal. Credentials, destinations, personal contact data, and private signing material are omitted.</p>
        </div>
        <div className="readiness-export__actions">
          <button className="secondary-button" disabled={pending || exporting} type="button" onClick={() => void downloadReadiness("html")}>Download human report</button>
          <button className="table-link" disabled={pending || exporting} type="button" onClick={() => void downloadReadiness("json")}>Download machine JSON</button>
        </div>
      </section>
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
      <section className="production-stop" aria-labelledby="production-stop-title">
        <div className="production-stop__heading">
          <div>
            <h3 id="production-stop-title">Emergency production stop</h3>
            <p>Fails closed in one transaction. Active participant work is revoked, queued invitations and reminders are suppressed, and one admission gate must be freshly approved before production can resume.</p>
          </div>
          {!stopping && <button className="danger-button" disabled={pending} type="button" onClick={() => setStopping(true)}>Prepare stop</button>}
        </div>
        {stopping && <form className="production-stop__form" onSubmit={stopProduction}>
          <label className="field"><span>Admission gate to revoke</span><select name="gateId" defaultValue={record.admission.gates.find((gate) => gate.state === "approved")?.id || "capacity_support"}>
            {record.admission.gates.map((gate) => <option value={gate.id} key={gate.id}>{gateCopy[gate.id].label} ({gate.state})</option>)}
          </select></label>
          <label className="field"><span>Reason</span><select name="reasonCode" defaultValue="operator_decision">
            {(Object.entries(stopReasonCopy) as [TenantProductionStopReason, string][]).map(([value, label]) => <option value={value} key={value}>{label}</option>)}
          </select></label>
          <label className="field"><span>Opaque incident reference</span><input name="incidentReference" pattern="[A-Za-z0-9._:-]+" maxLength={160} required placeholder="incident:2026-001" /></label>
          <div className="production-stop__actions">
            <button className="danger-button" disabled={pending} type="submit">Stop tenant production</button>
            <button className="table-link" disabled={pending} type="button" onClick={() => setStopping(false)}>Cancel</button>
          </div>
        </form>}
        {record.lastProductionStop && <dl className="production-stop__last">
          <div><dt>Last stop</dt><dd>{new Date(record.lastProductionStop.stoppedAt).toLocaleString()}</dd></div>
          <div><dt>Reference</dt><dd>{record.lastProductionStop.incidentReference}</dd></div>
          <div><dt>Effect</dt><dd>{record.lastProductionStop.revokedRequestCount} requests / {record.lastProductionStop.revokedAssignmentCount} participant assignments · {record.lastProductionStop.suppressedNotificationCount} notifications</dd></div>
          <div><dt>Event SHA-256</dt><dd><code>{record.lastProductionStop.eventHash}</code></dd></div>
        </dl>}
      </section>
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
  if (code === "tenant_production_stop_replayed") return "That production-stop command was already recorded.";
  if (code === "invalid_product_configuration") return "Use opaque references and an exact lowercase SHA-256 evidence digest.";
  return code || "The admission decision could not be recorded.";
}
