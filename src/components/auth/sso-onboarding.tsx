"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

import { SocialIcon } from "@/components/social-icon";
import { authClient } from "@/lib/auth-client";
import type {
  AuthProviderAvailability,
  AuthProviderId,
} from "@/lib/auth-providers";

type Stage = "email" | "checking" | "recommendation" | "manual";
type Recommendation = {
  configured: boolean;
  label?: string;
  provider?: AuthProviderId;
};

const GENERIC_AUTH_ERROR =
  "We could not complete that request. Check your details and try again.";

export function SsoOnboarding({
  initialEmail,
  inviteToken,
  providers,
}: {
  initialEmail?: string;
  inviteToken?: string;
  providers: AuthProviderAvailability[];
}) {
  const [email, setEmail] = useState(initialEmail ?? "");
  const [stage, setStage] = useState<Stage>(initialEmail ? "checking" : "email");
  const [recommendation, setRecommendation] = useState<Recommendation>({
    configured: false,
  });
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [messageType, setMessageType] = useState<"error" | "success">("error");

  const callbackURL = inviteToken
    ? `/invite/complete?token=${encodeURIComponent(inviteToken)}`
    : "/workspace";
  const errorCallbackURL = inviteToken
    ? `/invite?token=${encodeURIComponent(inviteToken)}&error=oauth`
    : "/?error=oauth";
  const configuredProviders = useMemo(
    () => providers.filter((provider) => provider.configured),
    [providers],
  );

  async function checkEmail(value: string) {
    const normalized = value.trim().toLowerCase();
    setEmail(normalized);
    setStage("checking");
    setMessage(null);

    try {
      setRecommendation(await fetchRecommendation(normalized));
      setStage("recommendation");
    } catch {
      setMessage("We could not check that email domain. You can still choose a trusted provider.");
      setMessageType("error");
      setRecommendation({ configured: false });
      setStage("recommendation");
    }
  }

  useEffect(() => {
    if (!initialEmail) return;
    let cancelled = false;

    void fetchRecommendation(initialEmail)
      .then((result) => {
        if (cancelled) return;
        setRecommendation(result);
        setStage("recommendation");
      })
      .catch(() => {
        if (cancelled) return;
        setMessage("We could not check that email domain. You can still choose a trusted provider.");
        setMessageType("error");
        setStage("recommendation");
      });

    return () => {
      cancelled = true;
    };
  }, [initialEmail]);

  async function handleEmail(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await checkEmail(String(form.get("email") ?? ""));
  }

  async function handleSocial(provider: AuthProviderId) {
    setPendingAction(provider);
    setMessage(null);

    try {
      const result = provider === "yahoo"
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

  async function handleManualRegistration(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const password = String(form.get("password") ?? "");
    const confirmation = String(form.get("passwordConfirmation") ?? "");
    if (password !== confirmation) {
      setMessage("The passwords do not match.");
      setMessageType("error");
      return;
    }

    setPendingAction("manual");
    setMessage(null);
    try {
      const result = await authClient.signUp.email({
        name: String(form.get("name") ?? "").trim(),
        email,
        username: String(form.get("username") ?? "").trim(),
        password,
        callbackURL,
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
    } catch {
      setMessage(GENERIC_AUTH_ERROR);
      setMessageType("error");
    }
    setPendingAction(null);
  }

  if (stage === "email" || stage === "checking") {
    return (
      <form className="onboarding-email" onSubmit={handleEmail}>
        <label className="field">
          <span>Email address</span>
          <span className="input-wrap">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16v14H4z" /><path d="m4 7 8 6 8-6" /></svg>
            <input
              name="email"
              type="email"
              autoComplete="email"
              defaultValue={email}
              required
              placeholder="you@company.com"
              readOnly={Boolean(initialEmail)}
            />
          </span>
        </label>
        <p className="onboarding-email__hint">
          We’ll check whether your email uses Microsoft, Google, or Yahoo so you can avoid another password.
        </p>
        <button className="primary-button" type="submit" disabled={stage === "checking"}>
          <span>{stage === "checking" ? "Checking your domain…" : "Continue"}</span>
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M14 7l5 5-5 5" /></svg>
        </button>
      </form>
    );
  }

  if (stage === "manual") {
    return (
      <form className="credentials-form onboarding-manual" onSubmit={handleManualRegistration}>
        <div className="manual-account-note">
          <strong>Manual V·Sign account</strong>
          <span>{email}</span>
        </div>
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
        <label className="field">
          <span>Password</span>
          <span className="input-wrap">
            <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M7 10V7a5 5 0 0 1 10 0v3" /></svg>
            <input name="password" type={showPassword ? "text" : "password"} autoComplete="new-password" minLength={12} maxLength={128} required placeholder="12 characters minimum" />
            <button className="password-toggle" type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword((visible) => !visible)}>
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.5" /></svg>
            </button>
          </span>
        </label>
        <label className="field">
          <span>Confirm password</span>
          <span className="input-wrap">
            <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M7 10V7a5 5 0 0 1 10 0v3" /></svg>
            <input name="passwordConfirmation" type={showPassword ? "text" : "password"} autoComplete="new-password" minLength={12} maxLength={128} required placeholder="Repeat your password" />
          </span>
        </label>
        {message && <p className={`form-message form-message--${messageType}`} role="status">{message}</p>}
        <button className="primary-button" type="submit" disabled={pendingAction !== null}>
          <span>{pendingAction === "manual" ? "Please wait…" : "Create manual account"}</span>
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M14 7l5 5-5 5" /></svg>
        </button>
        <button className="onboarding-back" type="button" onClick={() => setStage("recommendation")}>
          Back to trusted sign-in options
        </button>
      </form>
    );
  }

  const recommendedProvider = recommendation.provider
    ? providers.find((provider) => provider.id === recommendation.provider)
    : undefined;
  const alternativeProviders = configuredProviders.filter(
    (provider) => provider.id !== recommendation.provider,
  );

  return (
    <div className="onboarding-options">
      <div className="onboarding-email-summary">
        <span>Email</span>
        <strong>{email}</strong>
        {!initialEmail && <button type="button" onClick={() => setStage("email")}>Change</button>}
      </div>

      {recommendedProvider?.configured ? (
        <div className="provider-recommendation">
          <p className="eyebrow eyebrow--green">RECOMMENDED</p>
          <h3>Use your {recommendedProvider.label} account</h3>
          <p>We found a managed identity provider for this email. It is usually faster and more secure than creating another password.</p>
          <button className="recommended-provider-button" type="button" disabled={pendingAction !== null} onClick={() => handleSocial(recommendedProvider.id)}>
            <SocialIcon provider={recommendedProvider.id} />
            <span>{pendingAction === recommendedProvider.id ? "Connecting…" : `Continue with ${recommendedProvider.label}`}</span>
          </button>
        </div>
      ) : (
        <div className="provider-recommendation provider-recommendation--neutral">
          <h3>{recommendedProvider ? `${recommendedProvider.label} appears to manage this email` : "Choose a trusted account"}</h3>
          <p>{recommendedProvider && !recommendedProvider.configured
            ? `${recommendedProvider.label} is not enabled for V·Sign yet. You can choose another active provider or continue manually.`
            : "If your organization uses one of these providers, connect it so V·Sign does not need to store another password."}</p>
        </div>
      )}

      {alternativeProviders.length > 0 && (
        <div className="onboarding-provider-list" aria-label="Other trusted providers">
          {alternativeProviders.map((provider) => (
            <button type="button" key={provider.id} disabled={pendingAction !== null} onClick={() => handleSocial(provider.id)}>
              <SocialIcon provider={provider.id} />
              <span>{provider.label}</span>
            </button>
          ))}
        </div>
      )}

      {message && <p className={`form-message form-message--${messageType}`} role="status">{message}</p>}
      <button className="manual-account-link" type="button" onClick={() => { setMessage(null); setStage("manual"); }}>
        Use a manual password instead
      </button>
    </div>
  );
}

async function fetchRecommendation(email: string) {
  const response = await fetch(
    `/api/auth/provider-recommendation?email=${encodeURIComponent(email.trim().toLowerCase())}`,
    { cache: "no-store" },
  );
  if (!response.ok) throw new Error("Email lookup failed.");
  return await response.json() as Recommendation;
}
