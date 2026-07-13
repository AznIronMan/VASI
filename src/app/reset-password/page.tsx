import type { Metadata } from "next";

import { BrandMark } from "@/components/brand-mark";
import { ResetPasswordForm } from "@/components/auth/reset-password-form";

export const metadata: Metadata = { title: "Choose a new password" };

export default async function ResetPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const { token } = await searchParams;
  return (
    <main className="recovery-shell">
      <div className="recovery-brand"><BrandMark compact /></div>
      <section className="recovery-card"><ResetPasswordForm token={token} /></section>
      <p className="recovery-footer">Secure account recovery · CNB V·Sign</p>
    </main>
  );
}
