"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";

import { authClient } from "@/lib/auth-client";
import { useProductBrand } from "@/components/brand-provider";

export function ForgotPasswordForm() {
  const brand = useProductBrand();
  const [pending, setPending] = useState(false);
  const [sent, setSent] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    const email = String(new FormData(event.currentTarget).get("email") ?? "").trim();

    try {
      await authClient.requestPasswordReset({
        email,
        redirectTo: "/reset-password",
      });
    } finally {
      setSent(true);
      setPending(false);
    }
  }

  if (sent) {
    return (
      <div className="recovery-state" role="status">
        <span className="recovery-state__icon" aria-hidden="true">✓</span>
        <h1>Check your inbox</h1>
        <p>If an account matches that address, a secure reset link is on its way.</p>
        <Link className="primary-button primary-button--link" href="/">Return to sign in</Link>
      </div>
    );
  }

  return (
    <>
      <p className="eyebrow eyebrow--green">ACCOUNT RECOVERY</p>
      <h1>Reset your password</h1>
      <p>Enter the email address connected to your {brand.productName} account.</p>
      <form className="credentials-form recovery-form" onSubmit={submit}>
        <label className="field">
          <span>Email address</span>
          <span className="input-wrap">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16v14H4z" /><path d="m4 7 8 6 8-6" /></svg>
            <input name="email" type="email" autoComplete="email" required placeholder="you@company.com" />
          </span>
        </label>
        <button className="primary-button" type="submit" disabled={pending}>
          <span>{pending ? "Sending\u2026" : "Send reset link"}</span>
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M14 7l5 5-5 5" /></svg>
        </button>
      </form>
      <Link className="recovery-back" href="/">← Back to sign in</Link>
    </>
  );
}
