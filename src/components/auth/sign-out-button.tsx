"use client";

import { useState } from "react";

import { authClient } from "@/lib/auth-client";

export function SignOutButton() {
  const [pending, setPending] = useState(false);

  async function signOut() {
    setPending(true);
    await authClient.signOut();
    window.location.assign("/");
  }

  return (
    <button className="workspace-signout" type="button" onClick={signOut} disabled={pending}>
      {pending ? "Signing out\u2026" : "Sign out"}
    </button>
  );
}
