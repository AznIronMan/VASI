import type { Metadata } from "next";

import { BrandMark } from "@/components/brand-mark";
import { ResetPasswordForm } from "@/components/auth/reset-password-form";
import { resolveProductBrand } from "@/lib/branding";
import { getRuntimeSettings } from "@/lib/runtime-settings";

export const metadata: Metadata = { title: "Choose a new password" };
export const dynamic = "force-dynamic";

export default async function ResetPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const { token } = await searchParams;
  const brand = resolveProductBrand(await getRuntimeSettings());
  return (
    <main className="recovery-shell">
      <div className="recovery-brand"><BrandMark compact /></div>
      <section className="recovery-card"><ResetPasswordForm token={token} /></section>
      <p className="recovery-footer">Secure account recovery · {brand.displayName}</p>
    </main>
  );
}
