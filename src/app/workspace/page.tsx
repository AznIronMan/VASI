import type { Metadata } from "next";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { BrandMark } from "@/components/brand-mark";
import { SignOutButton } from "@/components/auth/sign-out-button";
import { getAuth } from "@/lib/auth";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Workspace",
};

export default async function WorkspacePage() {
  const auth = await getAuth();
  const session = await auth.api.getSession({ headers: await headers() });

  if (!session) {
    redirect("/");
  }

  return (
    <main className="workspace-shell">
      <header className="workspace-header">
        <BrandMark compact />
        <SignOutButton />
      </header>
      <section className="workspace-card">
        <span className="workspace-card__icon" aria-hidden="true">
          <svg viewBox="0 0 24 24"><path d="m7.5 12.5 3 3 6-7" /><path d="M12 2.7 20 7v5c0 4.8-3.3 8.2-8 9.5C7.3 20.2 4 16.8 4 12V7l8-4.3Z" /></svg>
        </span>
        <p className="eyebrow eyebrow--green">IDENTITY VERIFIED</p>
        <h1>Welcome, {session.user.name}</h1>
        <p>
          Authentication is active. The document signing workspace will be
          connected in the next V·Sign milestone.
        </p>
        <dl>
          <div><dt>Account</dt><dd>{session.user.email}</dd></div>
          <div><dt>Session expires</dt><dd>{new Date(session.session.expiresAt).toLocaleString()}</dd></div>
        </dl>
      </section>
    </main>
  );
}
