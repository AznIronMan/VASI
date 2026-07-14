"use client";

import { FormEvent, useEffect, useState } from "react";

import type {
  OwnerIntegration,
  OwnerTenantProfile,
  OwnerTenantUsage,
} from "@/lib/owner-types";
import { integrationCommandFromForm } from "@/lib/integration-configuration";

export function OwnerProductSettings({ permissions, tenantId }: {
  permissions: string[];
  tenantId: string;
}) {
  const canConfigure = permissions.includes("tenant.configure");
  const canManageIntegration = permissions.includes("integration.manage");
  const canReadQuota = permissions.includes("quota.read");
  const [profile, setProfile] = useState<OwnerTenantProfile>();
  const [usage, setUsage] = useState<OwnerTenantUsage>();
  const [notificationIntegration, setNotificationIntegration] = useState<OwnerIntegration>();
  const [scannerIntegration, setScannerIntegration] = useState<OwnerIntegration>();
  const [notificationAdapterId, setNotificationAdapterId] = useState<OwnerIntegration["adapterId"]>("disabled");
  const [scannerAdapterId, setScannerAdapterId] = useState<OwnerIntegration["adapterId"]>("scan_disabled");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string>();

  useEffect(() => {
    if (!tenantId || (!canConfigure && !canManageIntegration && !canReadQuota)) return;
    let active = true;
    const timeout = window.setTimeout(() => {
      setPending(true);
      Promise.all([
        canReadQuota || canConfigure
          ? api<OwnerTenantProfile>("/api/owner/product/profile/read", { tenantId })
          : Promise.resolve(undefined),
        canReadQuota
          ? api<OwnerTenantUsage>("/api/owner/product/usage", { tenantId })
          : Promise.resolve(undefined),
        canManageIntegration
          ? api<OwnerIntegration[]>("/api/owner/product/integrations/list", { tenantId })
          : Promise.resolve([]),
      ]).then(([nextProfile, nextUsage, integrations]) => {
        if (!active) return;
        setProfile(nextProfile);
        setUsage(nextUsage);
        const notification = integrations?.find((entry) => entry.capability === "notification.delivery");
        const scanner = integrations?.find((entry) => entry.capability === "document.malware_scan");
        setNotificationIntegration(notification);
        setScannerIntegration(scanner);
        setNotificationAdapterId(notification?.adapterId || "disabled");
        setScannerAdapterId(scanner?.adapterId || "scan_disabled");
      }).catch((error) => {
        if (active) setMessage(errorMessage(error));
      }).finally(() => {
        if (active) setPending(false);
      });
    }, 0);
    return () => { active = false; window.clearTimeout(timeout); };
  }, [canConfigure, canManageIntegration, canReadQuota, tenantId]);

  if (!canConfigure && !canManageIntegration && !canReadQuota) return null;

  async function updateProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!profile) return;
    const data = new FormData(event.currentTarget);
    setPending(true);
    setMessage(undefined);
    try {
      const updated = await api<OwnerTenantProfile>("/api/owner/product/profile", {
        expectedRevision: profile.revision,
        profile: {
          ...profile.profile,
          branding: {
            accentColor: data.get("accentColor"),
            displayName: data.get("displayName"),
            primaryColor: data.get("primaryColor"),
            shortName: data.get("shortName"),
            supportEmail: String(data.get("supportEmail") || "") || null,
          },
          policies: { defaultRetentionProfile: data.get("defaultRetentionProfile") },
        },
        tenantId,
      });
      setProfile(updated);
      setMessage(`Company profile revision ${updated.revision} is active. Existing evidence keeps its original profile snapshot.`);
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(false);
    }
  }

  async function updateIntegration(
    event: FormEvent<HTMLFormElement>,
    integration: OwnerIntegration,
    adapterId: OwnerIntegration["adapterId"],
    capability: OwnerIntegration["capability"],
    label: string,
    setIntegration: (value: OwnerIntegration) => void,
  ) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const command = integrationCommandFromForm(adapterId, data);
    setPending(true);
    setMessage(undefined);
    try {
      const updated = await api<OwnerIntegration>("/api/owner/product/integrations", {
        adapterId,
        capability,
        config: command.config,
        credentials: command.credentials,
        expectedRevision: integration.revision,
        status: command.status,
        tenantId,
      });
      setIntegration(updated);
      setMessage(`${label} integration revision ${updated.revision} is ${updated.status}.`);
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="owner-governance">
      <div className="owner-section-heading">
        <div><p className="eyebrow eyebrow--green">PRODUCT CONFIGURATION</p><h2>Company profile, capacity, and integrations</h2></div>
        <p>Every change creates an immutable revision. Issued requests retain the exact profile that governed them.</p>
      </div>
      {message && <p className="admin-message" role="status">{message}</p>}
      <div className="owner-grid">
        {profile && <form className="evidence-panel" key={profile.revision} onSubmit={updateProfile}>
          <h3>Company identity and policy</h3>
          <label className="field"><span>Display name</span><input name="displayName" defaultValue={profile.profile.branding.displayName} disabled={!canConfigure} required /></label>
          <label className="field"><span>Short name</span><input name="shortName" defaultValue={profile.profile.branding.shortName} maxLength={48} disabled={!canConfigure} required /></label>
          <div className="form-row"><label className="field"><span>Primary color</span><input name="primaryColor" type="color" defaultValue={profile.profile.branding.primaryColor} disabled={!canConfigure} /></label><label className="field"><span>Accent color</span><input name="accentColor" type="color" defaultValue={profile.profile.branding.accentColor} disabled={!canConfigure} /></label></div>
          <label className="field"><span>Support email (optional)</span><input name="supportEmail" type="email" defaultValue={profile.profile.branding.supportEmail || ""} disabled={!canConfigure} /></label>
          <label className="field"><span>Default retention profile</span><input name="defaultRetentionProfile" defaultValue={profile.profile.policies.defaultRetentionProfile} pattern="[a-z][a-z0-9_-]*" disabled={!canConfigure} required /></label>
          <small>Active revision {profile.revision} · {profile.profileHash.slice(0, 16)}…</small>
          {canConfigure && <button className="primary-button" disabled={pending} type="submit">Save immutable profile revision</button>}
        </form>}

        {usage && <section className="evidence-panel">
          <h3>Capacity policy</h3>
          {Object.entries(usage.resources).map(([name, quota]) => <div className="owner-member" key={name}><strong>{quotaLabel(name)}</strong><span>{formatQuota(name, quota.used)} used · {formatQuota(name, quota.available)} available · limit {formatQuota(name, quota.limit)}</span></div>)}
          <small>Limits are installation-controlled. Usage is calculated transactionally before each governed write.</small>
        </section>}

        {canManageIntegration && notificationIntegration && <form className="evidence-panel" key={notificationIntegration.revision} onSubmit={(event) => void updateIntegration(event, notificationIntegration, notificationAdapterId, "notification.delivery", "Notification", setNotificationIntegration)}>
          <h3>Notification delivery</h3>
          <label className="field"><span>Adapter</span><select value={notificationAdapterId} onChange={(event) => setNotificationAdapterId(event.target.value as OwnerIntegration["adapterId"])}><option value="disabled">Disabled</option><option value="microsoft_graph">Microsoft Graph mail</option><option value="smtp">SMTP</option><option value="webhook">Signed webhook</option></select></label>
          {notificationAdapterId === "webhook" && <><label className="field"><span>Allowlisted HTTPS URL</span><input name="webhookUrl" type="url" defaultValue={notificationIntegration.adapterId === "webhook" ? notificationIntegration.config.url : ""} required /></label><label className="field"><span>Signing secret</span><input name="webhookSecret" type="password" minLength={32} maxLength={1024} autoComplete="new-password" required /><small>Secrets are encrypted in PostgreSQL and never returned to this browser.</small></label></>}
          {notificationAdapterId === "microsoft_graph" && <><label className="field"><span>Allowlisted Microsoft tenant ID</span><input name="graphTenantId" defaultValue={notificationIntegration.adapterId === "microsoft_graph" ? notificationIntegration.config.tenantId : ""} pattern="[0-9A-Fa-f-]{36}" required /></label><label className="field"><span>Allowlisted application (client) ID</span><input name="graphClientId" defaultValue={notificationIntegration.adapterId === "microsoft_graph" ? notificationIntegration.config.clientId : ""} pattern="[0-9A-Fa-f-]{36}" required /></label><label className="field"><span>Allowlisted sender mailbox</span><input name="graphSenderEmail" type="email" defaultValue={notificationIntegration.adapterId === "microsoft_graph" ? notificationIntegration.config.senderEmail : ""} required /></label><label className="field"><span>Application client secret</span><input name="graphClientSecret" type="password" minLength={1} maxLength={2048} autoComplete="new-password" required /><small>The secret is encrypted in PostgreSQL, is never returned to this browser, and must belong to the allowlisted application.</small></label></>}
          {notificationAdapterId === "smtp" && <><label className="field"><span>Allowlisted SMTP host</span><input name="smtpHost" defaultValue={notificationIntegration.adapterId === "smtp" ? notificationIntegration.config.host : ""} required /></label><div className="form-row"><label className="field"><span>Port</span><input name="smtpPort" type="number" min="1" max="65535" defaultValue={notificationIntegration.adapterId === "smtp" ? notificationIntegration.config.port : 587} required /></label><label className="field"><span>Transport</span><select name="smtpSecure" defaultValue={notificationIntegration.adapterId === "smtp" && notificationIntegration.config.secure ? "true" : "false"}><option value="false">STARTTLS</option><option value="true">Implicit TLS</option></select></label></div><label className="field"><span>From</span><input name="smtpFrom" defaultValue={notificationIntegration.adapterId === "smtp" ? notificationIntegration.config.from : ""} required /></label><label className="field"><span>Username (optional)</span><input name="smtpUsername" autoComplete="off" defaultValue={notificationIntegration.adapterId === "smtp" ? notificationIntegration.config.username : ""} /></label><label className="field"><span>Password (required with username)</span><input name="smtpPassword" type="password" autoComplete="new-password" /></label></>}
          <small>Revision {notificationIntegration.revision} · {notificationIntegration.status} · credentials {notificationIntegration.configuredCredentials ? "configured" : "not stored / not required"}</small>
          <button className="primary-button" disabled={pending} type="submit">Activate new integration revision</button>
        </form>}

        {canManageIntegration && scannerIntegration && <form className="evidence-panel" key={scannerIntegration.revision} onSubmit={(event) => void updateIntegration(event, scannerIntegration, scannerAdapterId, "document.malware_scan", "Document scanning", setScannerIntegration)}>
          <h3>Document malware scanning</h3>
          <p>When active, documents remain quarantined until the allowlisted scanner returns a digest-matched clean verdict.</p>
          <label className="field"><span>Adapter</span><select value={scannerAdapterId} onChange={(event) => setScannerAdapterId(event.target.value as OwnerIntegration["adapterId"])}><option value="scan_disabled">Disabled</option><option value="https_malware_scanner">Signed HTTPS scanner</option></select></label>
          {scannerAdapterId === "https_malware_scanner" && <>
            <label className="field"><span>Allowlisted HTTPS scan URL</span><input name="scannerUrl" type="url" defaultValue={scannerIntegration.adapterId === "https_malware_scanner" ? scannerIntegration.config.url : ""} required /></label>
            <label className="field"><span>Timeout seconds</span><input name="scannerTimeoutSeconds" type="number" min="5" max="300" defaultValue={scannerIntegration.adapterId === "https_malware_scanner" ? scannerIntegration.config.timeoutSeconds : 30} required /></label>
            <label className="field"><span>Request-signing secret</span><input name="scannerSecret" type="password" minLength={32} maxLength={1024} autoComplete="new-password" required /><small>The secret is encrypted in PostgreSQL and is never returned to this browser or sent to the evidence engine.</small></label>
            <label className="field"><span>Private CA certificate bundle (optional)</span><textarea name="scannerCaCertificatePem" rows={5} maxLength={131072} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" /><small>Leave empty for a publicly trusted scanner certificate.</small></label>
          </>}
          <small>Revision {scannerIntegration.revision} · {scannerIntegration.status} · credentials {scannerIntegration.configuredCredentials ? "configured" : "not stored / not required"}</small>
          <button className="primary-button" disabled={pending} type="submit">Save immutable scanning revision</button>
        </form>}
      </div>
    </section>
  );
}

function quotaLabel(value: string) {
  return value.replace(/([A-Z])/g, " $1").replace(/^./, (letter) => letter.toUpperCase());
}

function formatQuota(name: string, value: number) {
  if (name !== "artifactBytes") return String(value);
  if (value < 1_048_576) return `${(value / 1_024).toFixed(1)} KiB`;
  if (value < 1_073_741_824) return `${(value / 1_048_576).toFixed(1)} MiB`;
  return `${(value / 1_073_741_824).toFixed(2)} GiB`;
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
