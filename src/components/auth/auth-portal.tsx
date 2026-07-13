"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";

import { BrandMark } from "@/components/brand-mark";
import { SocialIcon } from "@/components/social-icon";
import { authClient } from "@/lib/auth-client";
import type {
  AuthProviderAvailability,
  AuthProviderId,
} from "@/lib/auth-providers";

type Mode = "sign-in" | "register";

const GENERIC_AUTH_ERROR =
  "We could not complete that request. Check your details and try again.";

export function AuthPortal({
  providers,
  oauthError = false,
}: {
  providers: AuthProviderAvailability[];
  oauthError?: boolean;
}) {
  const [mode, setMode] = useState<Mode>("sign-in");
  const [showPassword, setShowPassword] = useState(false);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(
    oauthError ? "Sign-in was cancelled or could not be completed. Please try again." : null,
  );
  const [messageType, setMessageType] = useState<"error" | "success">("error");

  function changeMode(nextMode: Mode) {
    setMode(nextMode);
    setMessage(null);
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
      const callbackURL = "/workspace";
      const errorCallbackURL = "/?error=oauth";
      const result =
        provider === "yahoo"
          ? await authClient.signIn.oauth2({
              providerId: "yahoo",
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
    const formElement = event.currentTarget;
    setPendingAction("credentials");
    setMessage(null);

    const form = new FormData(formElement);
    const password = String(form.get("password") ?? "");

    try {
      if (mode === "register") {
        const email = String(form.get("email") ?? "").trim();
        const name = String(form.get("name") ?? "").trim();
        const username = String(form.get("username") ?? "").trim();
        const confirmation = String(form.get("passwordConfirmation") ?? "");

        if (password !== confirmation) {
          setMessage("The passwords do not match.");
          setMessageType("error");
          setPendingAction(null);
          return;
        }

        const result = await authClient.signUp.email({
          name,
          email,
          username,
          password,
          callbackURL: "/workspace",
        });

        if (result.error) {
          setMessage(GENERIC_AUTH_ERROR);
          setMessageType("error");
        } else {
          setMessage(
            "Check your inbox for a verification link. Your account will be ready after you confirm your email.",
          );
          setMessageType("success");
          formElement.reset();
        }
      } else {
        const identifier = String(form.get("identifier") ?? "").trim();
        const rememberMe = form.get("rememberMe") === "on";
        const result = identifier.includes("@")
          ? await authClient.signIn.email({
              email: identifier,
              password,
              rememberMe,
              callbackURL: "/workspace",
            })
          : await authClient.signIn.username({
              username: identifier,
              password,
              rememberMe,
              callbackURL: "/workspace",
            });

        if (result.error) {
          setMessage(GENERIC_AUTH_ERROR);
          setMessageType("error");
        } else {
          window.location.assign("/workspace");
          return;
        }
      }
    } catch {
      setMessage(GENERIC_AUTH_ERROR);
      setMessageType("error");
    }

    setPendingAction(null);
  }

  const isPending = pendingAction !== null;

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
            across the V·Sign workspace.
          </p>

          <div className="trust-list" aria-label="Platform assurances">
            <div className="trust-list__item">
              <span className="trust-list__icon" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="m7.5 12.5 3 3 6-7" /><path d="M12 2.7 20 7v5c0 4.8-3.3 8.2-8 9.5C7.3 20.2 4 16.8 4 12V7l8-4.3Z" /></svg>
              </span>
              <span><strong>Identity verified</strong><small>Trusted provider authentication</small></span>
            </div>
            <div className="trust-list__item">
              <span className="trust-list__icon" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="M6 10V7a6 6 0 0 1 12 0v3" /><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M12 14v3" /></svg>
              </span>
              <span><strong>Session protected</strong><small>Encrypted, revocable access</small></span>
            </div>
            <div className="trust-list__item">
              <span className="trust-list__icon" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="M7 3h10v4H7z" /><path d="M5 5H3v16h18V5h-2M8 12h8M8 16h5" /></svg>
              </span>
              <span><strong>Audit ready</strong><small>Built for accountable signing</small></span>
            </div>
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
            <p className="eyebrow eyebrow--green">V·SIGN ACCESS</p>
            <h2 id="portal-title">{mode === "sign-in" ? "Welcome back" : "Create your account"}</h2>
            <p>
              {mode === "sign-in"
                ? "Choose a trusted account or enter your V·Sign credentials."
                : "Use a trusted account or create a secure V·Sign identity."}
            </p>
          </div>

          <div className="mode-switch" aria-label="Authentication mode">
            <button
              type="button"
              aria-pressed={mode === "sign-in"}
              onClick={() => changeMode("sign-in")}
            >
              Sign in
            </button>
            <button
              type="button"
              aria-pressed={mode === "register"}
              onClick={() => changeMode("register")}
            >
              Create account
            </button>
          </div>

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
                <span>{pendingAction === provider.id ? "Connecting\u2026" : provider.label}</span>
                {!provider.configured && <i className="social-button__status" title="Configuration required" />}
              </button>
            ))}
          </div>

          <div className="divider"><span>or continue with credentials</span></div>

          <form className="credentials-form" onSubmit={handleCredentials}>
            {mode === "register" && (
              <div className="form-row">
                <label className="field">
                  <span>Full name</span>
                  <input name="name" type="text" autoComplete="name" minLength={2} maxLength={80} required placeholder="Alex Morgan" />
                </label>
                <label className="field">
                  <span>Username</span>
                  <input name="username" type="text" autoComplete="username" pattern="[A-Za-z0-9._-]{3,32}" required placeholder="alex.morgan" />
                </label>
              </div>
            )}

            <label className="field">
              <span>{mode === "sign-in" ? "Username or email" : "Email address"}</span>
              <span className="input-wrap">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16v14H4z" /><path d="m4 7 8 6 8-6" /></svg>
                <input
                  name={mode === "sign-in" ? "identifier" : "email"}
                  type={mode === "sign-in" ? "text" : "email"}
                  autoComplete={mode === "sign-in" ? "username" : "email"}
                  required
                  placeholder={mode === "sign-in" ? "username@company.com" : "alex@company.com"}
                />
              </span>
            </label>

            <label className="field">
              <span>Password</span>
              <span className="input-wrap">
                <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M7 10V7a5 5 0 0 1 10 0v3" /></svg>
                <input
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete={mode === "sign-in" ? "current-password" : "new-password"}
                  minLength={12}
                  maxLength={128}
                  required
                  placeholder={mode === "sign-in" ? "Enter your password" : "12 characters minimum"}
                />
                <button
                  className="password-toggle"
                  type="button"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  onClick={() => setShowPassword((visible) => !visible)}
                >
                  <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.5" /></svg>
                </button>
              </span>
            </label>

            {mode === "register" ? (
              <label className="field">
                <span>Confirm password</span>
                <span className="input-wrap">
                  <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M7 10V7a5 5 0 0 1 10 0v3" /></svg>
                  <input name="passwordConfirmation" type={showPassword ? "text" : "password"} autoComplete="new-password" minLength={12} maxLength={128} required placeholder="Repeat your password" />
                </span>
              </label>
            ) : (
              <div className="form-options">
                <label className="checkbox"><input name="rememberMe" type="checkbox" defaultChecked /><span>Keep me signed in</span></label>
                <Link href="/forgot-password">Forgot password?</Link>
              </div>
            )}

            {message && (
              <p className={`form-message form-message--${messageType}`} role="status" aria-live="polite">
                {message}
              </p>
            )}

            <button className="primary-button" type="submit" disabled={isPending}>
              <span>
                {pendingAction === "credentials"
                  ? "Please wait\u2026"
                  : mode === "sign-in"
                    ? "Continue securely"
                    : "Create secure account"}
              </span>
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M14 7l5 5-5 5" /></svg>
            </button>
          </form>

          <p className="auth-card__legal">
            Authorized access only. Activity may be recorded for security and audit purposes.
          </p>
        </div>

        <p className="portal-panel__help">
          Need access help? <a href="mailto:support@cnb.llc">Contact CNB support</a>
        </p>
      </section>
    </main>
  );
}

function providerName(provider: AuthProviderId) {
  return provider.charAt(0).toUpperCase() + provider.slice(1);
}
