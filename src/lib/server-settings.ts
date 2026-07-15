import type { RuntimeSettings } from "@/lib/runtime-settings";
import { parseTrustedProxyCIDRs } from "@/lib/client-address";

export type ResolvedServerSettings = {
  adminEmails: string[];
  adminOrigin: string;
  authSecret: string;
  baseURL: string;
  trustedProxyCIDRs: string[];
};

export function resolveServerSettings(
  settings: RuntimeSettings,
  production = process.env.NODE_ENV === "production",
): ResolvedServerSettings {
  const authSecret = required(settings, "BETTER_AUTH_SECRET");
  const baseURL = required(settings, "BETTER_AUTH_URL");
  const adminOrigin = required(settings, "VASI_ADMIN_ORIGIN");
  const adminEmails = parseAdminEmails(required(settings, "VASI_ADMIN_EMAILS"));
  const trustedProxyCIDRs = parseTrustedProxyCIDRs(settings.VASI_TRUSTED_PROXY_CIDRS);

  if (authSecret.length < 32) {
    throw new Error("BETTER_AUTH_SECRET must contain at least 32 characters.");
  }

  const parsedBaseURL = new URL(baseURL);
  const parsedAdminOrigin = new URL(adminOrigin);
  if (production && parsedBaseURL.protocol !== "https:") {
    throw new Error("BETTER_AUTH_URL must use HTTPS in production.");
  }
  if (production && parsedAdminOrigin.protocol !== "https:") {
    throw new Error("VASI_ADMIN_ORIGIN must use HTTPS in production.");
  }
  if (parsedBaseURL.pathname !== "/" || parsedAdminOrigin.pathname !== "/") {
    throw new Error("Authentication origins must not include a path.");
  }

  return {
    adminEmails,
    adminOrigin: parsedAdminOrigin.origin,
    authSecret,
    baseURL: parsedBaseURL.origin,
    trustedProxyCIDRs,
  };
}

function required(settings: RuntimeSettings, name: string) {
  const value = settings[name]?.trim();
  if (!value) throw new Error(`${name} is required in VASI runtime settings.`);
  return value;
}

function parseAdminEmails(value: string) {
  const emails = [
    ...new Set(
      value
        .split(",")
        .map((email) => email.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];

  if (!emails.length || emails.some((email) => !/^[^@\s]+@[^@\s]+$/.test(email))) {
    throw new Error("VASI_ADMIN_EMAILS must contain a comma-separated email allowlist.");
  }
  return emails;
}
