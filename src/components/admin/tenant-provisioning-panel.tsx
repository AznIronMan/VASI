"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";

import type { AdminCompanyProvisioningResult } from "@/lib/owner-types";

export const COMPANY_PROVISIONED_EVENT = "vasi:company-provisioned";

export function TenantProvisioningPanel() {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<AdminCompanyProvisioningResult>();
  const [message, setMessage] = useState<string>();
  const [messageType, setMessageType] = useState<"error" | "success" | "warning">("success");

  async function provision(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setPending(true);
    setMessage(undefined);
    setResult(undefined);
    try {
      const response = await fetch("/api/admin/product/tenants", {
        body: JSON.stringify({
          inviteOwner: data.get("inviteOwner") === "on",
          name: data.get("name"),
          ownerEmail: data.get("ownerEmail"),
          slug: data.get("slug"),
        }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = await response.json() as AdminCompanyProvisioningResult & { error?: string };
      if (!response.ok) throw new Error(body.error || "The company could not be provisioned.");
      setResult(body);
      const outcome = provisioningMessage(body);
      setMessage(outcome.message);
      setMessageType(outcome.type);
      form.reset();
      setName("");
      setSlug("");
      setSlugEdited(false);
      window.dispatchEvent(new CustomEvent(COMPANY_PROVISIONED_EVENT, {
        detail: { tenantId: body.company.id },
      }));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The company could not be provisioned.");
      setMessageType("error");
    } finally {
      setPending(false);
    }
  }

  return <section className="admin-invite company-provisioning" aria-labelledby="company-provisioning-title">
    <div>
      <p className="eyebrow eyebrow--green">COMPANY ONBOARDING</p>
      <h2 id="company-provisioning-title">Provision a company</h2>
      <p>Create the isolated company control plane and a durable owner grant. Every production gate starts pending; creating a company does not authorize customer requests.</p>
    </div>
    <form onSubmit={provision}>
      <div className="form-row">
        <label className="field">
          <span>Company name</span>
          <input
            name="name"
            minLength={2}
            maxLength={160}
            required
            value={name}
            onChange={(event) => {
              const nextName = event.target.value;
              setName(nextName);
              if (!slugEdited) setSlug(companySlug(nextName));
            }}
          />
        </label>
        <label className="field">
          <span>Initial owner email</span>
          <input name="ownerEmail" type="email" maxLength={320} required placeholder="owner@company.com" />
        </label>
      </div>
      <label className="field">
        <span>Company identifier</span>
        <input
          name="slug"
          minLength={2}
          maxLength={64}
          pattern="[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?"
          required
          value={slug}
          onChange={(event) => {
            setSlug(event.target.value.toLowerCase());
            setSlugEdited(Boolean(event.target.value));
          }}
          placeholder="example-company"
        />
      </label>
      <label className="company-provisioning__invite">
        <input name="inviteOwner" type="checkbox" defaultChecked />
        <span>Email the owner a login invitation after the company and owner grant are committed.</span>
      </label>
      <button className="primary-button" disabled={pending} type="submit">
        {pending ? "Provisioning…" : "Provision company"}
      </button>
    </form>
    {message && <p
      className={`admin-message admin-message--${messageType}`}
      role={messageType === "error" ? "alert" : "status"}
    >{message}</p>}
    {result && <div className="company-provisioning__result">
      <div>
        <strong>{result.company.name}</strong>
        <span>{result.company.slug} · owner {result.company.owner.email}</span>
      </div>
      <span className="admission-status admission-status--pending">Production pending</span>
      <Link href="/owner">Open company control plane</Link>
    </div>}
  </section>;
}

function companySlug(value: string) {
  return value.normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64)
    .replace(/-+$/g, "");
}

function provisioningMessage(result: AdminCompanyProvisioningResult): {
  message: string;
  type: "success" | "warning";
} {
  const owner = result.company.owner.email || "the initial owner";
  switch (result.invitation.status) {
    case "sent":
      return { message: `${result.company.name} was provisioned and a login invitation was sent to ${owner}.`, type: "success" };
    case "existing_account":
      return { message: `${result.company.name} was provisioned. ${owner} already has an account and will receive owner access on the next company login.`, type: "success" };
    case "not_required":
      return { message: `${result.company.name} was provisioned with your existing account as its initial owner.`, type: "success" };
    case "skipped":
      return { message: `${result.company.name} and its owner grant were provisioned. No login invitation was requested.`, type: "success" };
    case "delivery_failed":
      return { message: `${result.company.name} and its owner grant were provisioned, but the login invitation was not delivered. Do not create the company again; retry from Invite a user below.`, type: "warning" };
  }
}
