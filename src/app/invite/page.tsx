import type { Metadata } from "next";

import { SsoOnboarding } from "@/components/auth/sso-onboarding";
import { BrandMark } from "@/components/brand-mark";
import { getLoginAuthProviderAvailability } from "@/lib/auth-providers";
import { resolveProductBrand } from "@/lib/branding";
import { getInvitation } from "@/lib/invitations";
import { getRuntimeSettings } from "@/lib/runtime-settings";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Accept invitation",
};

export default async function InvitationPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; token?: string }>;
}) {
  const { error, token = "" } = await searchParams;
  const [invitation, settings] = await Promise.all([
    getInvitation(token),
    getRuntimeSettings(),
  ]);
  const brand = resolveProductBrand(settings);

  return (
    <main className="invite-shell">
      <section className="invite-card">
        <BrandMark compact />
        {invitation ? (
          <>
            <div className="invite-card__heading">
              <p className="eyebrow eyebrow--green">YOU’RE INVITED</p>
              <h1>Join {brand.displayName}</h1>
              <p>
                Start with the trusted account for <strong>{invitation.email}</strong>.
                Your invitation expires {new Date(invitation.expiresAt).toLocaleDateString()}.
              </p>
            </div>
            {error && (
              <p className="form-message form-message--error" role="status">
                Sign-in was cancelled or could not be completed. Please try again.
              </p>
            )}
            <SsoOnboarding
              initialEmail={invitation.email}
              inviteToken={token}
              providers={getLoginAuthProviderAvailability(settings)}
            />
          </>
        ) : (
          <div className="invite-card__heading invite-card__heading--invalid">
            <p className="eyebrow eyebrow--green">INVITATION UNAVAILABLE</p>
            <h1>This invitation is no longer valid</h1>
            <p>It may have expired, already been used, or been replaced. Ask a {brand.productName} administrator for a new invitation.</p>
          </div>
        )}
      </section>
    </main>
  );
}
