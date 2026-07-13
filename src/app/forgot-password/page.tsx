import type { Metadata } from "next";

import { BrandMark } from "@/components/brand-mark";
import { ForgotPasswordForm } from "@/components/auth/forgot-password-form";

export const metadata: Metadata = { title: "Reset password" };

export default function ForgotPasswordPage() {
  return (
    <main className="recovery-shell">
      <div className="recovery-brand"><BrandMark compact /></div>
      <section className="recovery-card"><ForgotPasswordForm /></section>
      <p className="recovery-footer">Secure account recovery · CNB V·Sign</p>
    </main>
  );
}
