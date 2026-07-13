"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";

import { authClient } from "@/lib/auth-client";

export function ResetPasswordForm({ token }: { token?: string }) {
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [complete, setComplete] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token) return;

    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") ?? "");
    const confirmation = String(form.get("confirmation") ?? "");
    if (password !== confirmation) {
      setMessage("The passwords do not match.");
      return;
    }

    setPending(true);
    setMessage(null);
    const result = await authClient.resetPassword({ newPassword: password, token });
    setPending(false);

    if (result.error) {
      setMessage("This reset link is invalid or expired. Request a new one.");
      return;
    }

    setComplete(true);
  }

  if (!token) {
    return (
      <div className="recovery-state">
        <h1>Reset link unavailable</h1>
        <p>This link is missing or invalid. Request a fresh password reset email.</p>
        <Link className="primary-button primary-button--link" href="/forgot-password">Request new link</Link>
      </div>
    );
  }

  if (complete) {
    return (
      <div className="recovery-state" role="status">
        <span className="recovery-state__icon" aria-hidden="true">✓</span>
        <h1>Password updated</h1>
        <p>Your other active sessions have been revoked. Sign in with your new password.</p>
        <Link className="primary-button primary-button--link" href="/">Continue to sign in</Link>
      </div>
    );
  }

  return (
    <>
      <p className="eyebrow eyebrow--green">ACCOUNT RECOVERY</p>
      <h1>Choose a new password</h1>
      <p>Use at least 12 characters and avoid a password you use elsewhere.</p>
      <form className="credentials-form recovery-form" onSubmit={submit}>
        <label className="field"><span>New password</span><span className="input-wrap"><input name="password" type="password" autoComplete="new-password" minLength={12} maxLength={128} required placeholder="12 characters minimum" /></span></label>
        <label className="field"><span>Confirm password</span><span className="input-wrap"><input name="confirmation" type="password" autoComplete="new-password" minLength={12} maxLength={128} required placeholder="Repeat your password" /></span></label>
        {message && <p className="form-message form-message--error" role="alert">{message}</p>}
        <button className="primary-button" type="submit" disabled={pending}><span>{pending ? "Updating\u2026" : "Update password"}</span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M14 7l5 5-5 5" /></svg></button>
      </form>
    </>
  );
}
