import type { Metadata } from "next";

import { BrandMark } from "@/components/brand-mark";
import { ForgotPasswordForm } from "@/components/auth/forgot-password-form";
import { resolveProductBrand } from "@/lib/branding";
import { getRuntimeSettings } from "@/lib/runtime-settings";

export const metadata: Metadata = { title: "Reset password" };
export const dynamic = "force-dynamic";

export default async function ForgotPasswordPage() {
  const brand = resolveProductBrand(await getRuntimeSettings());
  return (
    <main className="recovery-shell">
      <div className="recovery-brand"><BrandMark compact /></div>
      <section className="recovery-card"><ForgotPasswordForm /></section>
      <p className="recovery-footer">Secure account recovery · {brand.displayName}</p>
    </main>
  );
}
