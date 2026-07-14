"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";

import { SsoOnboarding } from "@/components/auth/sso-onboarding";
import { BrandMark } from "@/components/brand-mark";
import { useProductBrand } from "@/components/brand-provider";
import { SocialIcon } from "@/components/social-icon";
import { authClient } from "@/lib/auth-client";
import { isGenericOAuthProvider } from "@/lib/auth-providers";
import type {
  AuthProviderAvailability,
  AuthProviderId,
} from "@/lib/auth-providers";

type Mode = "sign-in" | "register";

const GENERIC_AUTH_ERROR =
  "We could not complete that request. Check your details and try again.";

export function AuthPortal({
  allowRegistration = true,
  callbackURL = "/workspace",
  oauthError = false,
  providers,
}: {
  allowRegistration?: boolean;
  callbackURL?: string;
  oauthError?: boolean;
  providers: AuthProviderAvailability[];
}) {
  const brand = useProductBrand();
  const [mode, setMode] = useState<Mode>("sign-in");
  const [showOtherMethods, setShowOtherMethods] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(
    oauthError ? "Sign-in was cancelled or could not be completed. Please try again." : null,
  );
  const [messageType, setMessageType] = useState<"error" | "success">("error");

  function changeMode(nextMode: Mode) {
    setMode(nextMode);
    setMessage(null);
    setShowOtherMethods(false);
    setShowPassword(false);
  }

  async function handleSocialSignIn(provider: AuthProviderId, configured: boolean) {
    setMessage(null);
    if (!configured) {
      setMessage(`${providerName(provider)} sign-in is ready for credentials but is not enabled yet.`);
      setMessageType("error");
      return;
    }

    setPendingAction(provider);
    try {
      const errorCallbackURL = callbackURL === "/workspace"
        ? "/?error=oauth"
        : `/?error=oauth&returnTo=${encodeURIComponent(callbackURL)}`;
      const result = isGenericOAuthProvider(provider)
        ? await authClient.signIn.oauth2({
            providerId: provider,
            callbackURL,
            errorCallbackURL,
          })
        : await authClient.signIn.social({
            provider,
            callbackURL,
            errorCallbackURL,
          });

      if (result.error) {
        setMessage(GENERIC_AUTH_ERROR);
        setMessageType("error");
        setPendingAction(null);
      }
    } catch {
      setMessage(GENERIC_AUTH_ERROR);
      setMessageType("error");
      setPendingAction(null);
    }
  }

  async function handleCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPendingAction("credentials");
    setMessage(null);

    const form = new FormData(event.currentTarget);
    const identifier = String(form.get("identifier") ?? "").trim();
    const password = String(form.get("password") ?? "");
    const rememberMe = form.get("rememberMe") === "on";

    try {
      const result = identifier.includes("@")
        ? await authClient.signIn.email({
            email: identifier,
            password,
            rememberMe,
            callbackURL,
          })
        : await authClient.signIn.username({
            username: identifier,
            password,
            rememberMe,
            callbackURL,
          });

      if (result.error) {
        setMessage(GENERIC_AUTH_ERROR);
        setMessageType("error");
      } else {
        window.location.assign(callbackURL);
        return;
      }
    } catch {
      setMessage(GENERIC_AUTH_ERROR);
      setMessageType("error");
    }
    setPendingAction(null);
  }

  const isPending = pendingAction !== null;

  function toggleOtherMethods() {
    setMessage(null);
    setShowPassword(false);
    setShowOtherMethods((visible) => !visible);
  }

  return (
    <main className="auth-shell">
      <section className="story-panel" aria-labelledby="story-title">
        <div className="story-panel__glow story-panel__glow--one" />
        <div className="story-panel__glow story-panel__glow--two" />
        <BrandMark />

        <div className="story-panel__content">
          <p className="eyebrow">VERIFIED ACCESS</p>
          <h1 id="story-title">
            Sign with confidence.
            <span>Every time.</span>
          </h1>
          <p className="story-panel__lead">
            One trusted identity for every agreement, approval, and signature
            across the {brand.productName} workspace.
          </p>

          <div className="trust-list" aria-label="Platform assurances">
            <TrustItem
              title="Identity verified"
              description="Trusted provider authentication"
              icon={<><path d="m7.5 12.5 3 3 6-7" /><path d="M12 2.7 20 7v5c0 4.8-3.3 8.2-8 9.5C7.3 20.2 4 16.8 4 12V7l8-4.3Z" /></>}
            />
            <TrustItem
              title="Session protected"
              description="Encrypted, revocable access"
              icon={<><path d="M6 10V7a6 6 0 0 1 12 0v3" /><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M12 14v3" /></>}
            />
            <TrustItem
              title="Audit ready"
              description="Built for accountable signing"
              icon={<><path d="M7 3h10v4H7z" /><path d="M5 5H3v16h18V5h-2M8 12h8M8 16h5" /></>}
            />
          </div>
        </div>

        <p className="story-panel__footer">
          <span className="status-dot" aria-hidden="true" />
          Secure authentication portal
        </p>
      </section>

      <section className="portal-panel" aria-labelledby="portal-title">
        <div className="portal-panel__mobile-brand"><BrandMark compact /></div>
        <div className="auth-card">
          <div className="auth-card__heading">
            <p className="eyebrow eyebrow--green">{brand.productMark} ACCESS</p>
            <h2 id="portal-title">
              {mode === "register"
                ? "Start with your email"
                : allowRegistration ? "Welcome back" : "Administrator sign-in"}
            </h2>
            <p>
              {mode === "register"
                ? "We’ll look for your organization’s trusted sign-in provider before offering a manual password."
                : allowRegistration
                  ? "Choose a trusted account to continue securely."
                  : "Use an authorized operator account to continue to the internal console."}
            </p>
          </div>

          {allowRegistration && (
            <div className="mode-switch" aria-label="Authentication mode">
              <button type="button" aria-pressed={mode === "sign-in"} onClick={() => changeMode("sign-in")}>Sign in</button>
              <button type="button" aria-pressed={mode === "register"} onClick={() => changeMode("register")}>Create account</button>
            </div>
          )}

          {mode === "register" ? (
            <SsoOnboarding callbackURL={callbackURL} providers={providers} />
          ) : (
            <>
              <div className="social-grid">
                {providers.map((provider) => (
                  <button
                    className="social-button"
                    disabled={isPending}
                    key={provider.id}
                    onClick={() => handleSocialSignIn(provider.id, provider.configured)}
                    type="button"
                    aria-label={`Continue with ${provider.label}${provider.configured ? "" : ", configuration required"}`}
                  >
                    <SocialIcon provider={provider.id} />
                    <span>{pendingAction === provider.id ? "Connecting…" : provider.label}</span>
                    {!provider.configured && <i className="social-button__status" title="Configuration required" />}
                  </button>
                ))}
              </div>

              <div className="other-methods">
                <button
                  aria-controls="credential-sign-in"
                  aria-expanded={showOtherMethods}
                  className="other-methods__toggle"
                  disabled={isPending}
                  onClick={toggleOtherMethods}
                  type="button"
                >
                  <span>Other methods</span>
                  <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7 9 5 5 5-5" /></svg>
                </button>

                {showOtherMethods && (
                  <div className="other-methods__panel" id="credential-sign-in">
                    <form className="credentials-form" onSubmit={handleCredentials}>
                      <label className="field">
                        <span>Username or email</span>
                        <span className="input-wrap">
                          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16v14H4z" /><path d="m4 7 8 6 8-6" /></svg>
                          <input name="identifier" type="text" autoComplete="username" required placeholder="username@company.com" />
                        </span>
                      </label>

                      <label className="field">
                        <span>Password</span>
                        <span className="input-wrap">
                          <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M7 10V7a5 5 0 0 1 10 0v3" /></svg>
                          <input name="password" type={showPassword ? "text" : "password"} autoComplete="current-password" minLength={12} maxLength={128} required placeholder="Enter your password" />
                          <button className="password-toggle" type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword((visible) => !visible)}>
                            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.5" /></svg>
                          </button>
                        </span>
                      </label>

                      <div className="form-options">
                        <label className="checkbox"><input name="rememberMe" type="checkbox" defaultChecked /><span>Keep me signed in</span></label>
                        <Link href="/forgot-password">Forgot password?</Link>
                      </div>

                      <button className="primary-button" type="submit" disabled={isPending}>
                        <span>{pendingAction === "credentials" ? "Please wait…" : "Continue securely"}</span>
                        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M14 7l5 5-5 5" /></svg>
                      </button>
                    </form>
                  </div>
                )}
              </div>

              {message && <p className={`form-message form-message--${messageType}`} role="status" aria-live="polite">{message}</p>}
            </>
          )}

          <p className="auth-card__legal">
            Authorized access only. Activity may be recorded for security and audit purposes.
          </p>
        </div>

        <p className="portal-panel__help">
          Need access help? <a href={`mailto:${brand.supportEmail}`}>Contact {brand.organizationName} support</a>
        </p>
      </section>
    </main>
  );
}

function TrustItem({
  description,
  icon,
  title,
}: {
  description: string;
  icon: React.ReactNode;
  title: string;
}) {
  return (
    <div className="trust-list__item">
      <span className="trust-list__icon" aria-hidden="true"><svg viewBox="0 0 24 24">{icon}</svg></span>
      <span><strong>{title}</strong><small>{description}</small></span>
    </div>
  );
}

function providerName(provider: AuthProviderId) {
  return provider.charAt(0).toUpperCase() + provider.slice(1);
}
