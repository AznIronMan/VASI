"use client";

import { FormEvent, useEffect, useState } from "react";

import type { AdminInstallationProfile } from "@/lib/owner-types";

export function InstallationProfilePanel() {
  const [record, setRecord] = useState<AdminInstallationProfile>();
  const [message, setMessage] = useState<string>();
  const [pending, setPending] = useState(true);

  useEffect(() => {
    let active = true;
    fetch("/api/admin/product/installation-profile", { cache: "no-store" })
      .then(async (response) => {
        const body = await response.json() as AdminInstallationProfile & { error?: string };
        if (!response.ok) throw new Error(body.error || "Installation profile unavailable.");
        if (active) setRecord(body);
      })
      .catch((error) => { if (active) setMessage(error instanceof Error ? error.message : "Installation profile unavailable."); })
      .finally(() => { if (active) setPending(false); });
    return () => { active = false; };
  }, []);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!record) return;
    const data = new FormData(event.currentTarget);
    const lines = (name: string) => String(data.get(name) || "").split(/[\s,]+/).map((entry) => entry.trim().toLowerCase()).filter(Boolean);
    setPending(true);
    setMessage(undefined);
    try {
      const response = await fetch("/api/admin/product/installation-profile", {
        body: JSON.stringify({
          expectedRevision: record.revision,
          profile: {
            ...record.profile,
            adapters: {
              allow: ["disabled", ...(data.get("allowSmtp") ? ["smtp"] : []), ...(data.get("allowWebhook") ? ["webhook"] : [])],
              smtpAllowedHosts: lines("smtpAllowedHosts"),
              webhookAllowedHosts: lines("webhookAllowedHosts"),
            },
            product: {
              organizationName: data.get("organizationName"),
              productName: data.get("productName"),
              supportEmail: data.get("supportEmail"),
            },
            provisioning: { ...record.profile.provisioning, maxTenants: Number(data.get("maxTenants")) },
          },
        }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      const body = await response.json() as AdminInstallationProfile & { error?: string };
      if (!response.ok) throw new Error(body.error || "Installation profile update failed.");
      setRecord(body);
      setMessage(`Installation profile revision ${body.revision} is active.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Installation profile update failed.");
    } finally {
      setPending(false);
    }
  }

  return <section className="admin-invite">
    <div>
      <p className="eyebrow eyebrow--green">INSTALLATION PROFILE</p>
      <h2>Product boundary and outbound allowlists</h2>
      <p>Only exact destinations approved here can be activated by a company owner.</p>
    </div>
    {message && <p className="admin-message" role="status">{message}</p>}
    {record && <form className="credentials-form" key={record.revision} onSubmit={save}>
      <div className="form-row"><label className="field"><span>Organization name</span><input name="organizationName" defaultValue={record.profile.product.organizationName} required /></label><label className="field"><span>Product name</span><input name="productName" defaultValue={record.profile.product.productName} required /></label></div>
      <div className="form-row"><label className="field"><span>Support email</span><input name="supportEmail" type="email" defaultValue={record.profile.product.supportEmail} required /></label><label className="field"><span>Maximum active tenants</span><input name="maxTenants" type="number" min="1" max="1000000" defaultValue={record.profile.provisioning.maxTenants} required /></label></div>
      <div className="form-row"><label className="checkbox"><input name="allowSmtp" type="checkbox" defaultChecked={record.profile.adapters.allow.includes("smtp")} /><span>Allow SMTP adapters</span></label><label className="checkbox"><input name="allowWebhook" type="checkbox" defaultChecked={record.profile.adapters.allow.includes("webhook")} /><span>Allow signed webhooks</span></label></div>
      <label className="field"><span>Allowed SMTP hosts</span><textarea name="smtpAllowedHosts" defaultValue={record.profile.adapters.smtpAllowedHosts.join("\n")} placeholder="smtp.example.com" /><small>One exact host per line.</small></label>
      <label className="field"><span>Allowed webhook hosts</span><textarea name="webhookAllowedHosts" defaultValue={record.profile.adapters.webhookAllowedHosts.join("\n")} placeholder="events.example.com" /><small>The gateway rechecks this list for every delivery.</small></label>
      <small>{record.profile.deployment.mode} · dedicated database · gateway-only public ingress · revision {record.revision} · {record.profileHash.slice(0, 16)}…</small>
      <button className="primary-button" disabled={pending} type="submit">Save immutable installation revision</button>
    </form>}
    {!record && pending && <p>Loading installation policy…</p>}
  </section>;
}
