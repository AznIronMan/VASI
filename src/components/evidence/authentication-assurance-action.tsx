"use client";

import { useState } from "react";

import { authClient } from "@/lib/auth-client";

export type AuthenticationAssuranceCode =
  | "authentication_method_not_allowed"
  | "reauthentication_required";

export function AuthenticationAssuranceAction({
  code,
  returnTo,
}: {
  code: AuthenticationAssuranceCode;
  returnTo: string;
}) {
  const [pending, setPending] = useState(false);
  const message = code === "authentication_method_not_allowed"
    ? "This company requires an approved sign-in method for this request. Sign in again and choose a federated provider such as Microsoft, Google, Yahoo, or Zoho."
    : "This company requires a recent authentication for this request. Sign in again to refresh the recorded session.";

  async function authenticateAgain() {
    setPending(true);
    try {
      await authClient.signOut();
    } finally {
      window.location.assign(`/?returnTo=${encodeURIComponent(returnTo)}`);
    }
  }

  return (
    <section className="participant-error" aria-labelledby="authentication-required-heading">
      <h1 id="authentication-required-heading">Sign in again to continue</h1>
      <p>{message}</p>
      <button className="primary-button" disabled={pending} onClick={() => void authenticateAgain()} type="button">
        {pending ? "Signing out…" : "Sign in again"}
      </button>
    </section>
  );
}
