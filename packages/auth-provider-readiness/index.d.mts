export const AUTH_PROVIDER_IDS: readonly ["microsoft", "google", "apple", "yahoo", "zoho"];
export const ZOHO_ACCOUNTS_ORIGINS: readonly string[];

export type AuthProviderId = (typeof AUTH_PROVIDER_IDS)[number];
export type AuthProviderConfigurationState = "ready" | "required" | "invalid";
export type AuthProviderReadinessStatus =
  | "ready"
  | "hidden"
  | "configuration_required"
  | "invalid";

export type AuthProviderReadiness = Readonly<{
  adminCallback: string | null;
  callbackPath: string;
  configuration: AuthProviderConfigurationState;
  configured: boolean;
  id: AuthProviderId;
  label: string;
  publicCallback: string | null;
  reason:
    | "complete"
    | "not_configured"
    | "partial_credentials"
    | "invalid_visibility_setting"
    | "visibility_requires_credentials"
    | "unsupported_accounts_origin";
  status: AuthProviderReadinessStatus;
  visible: boolean;
}>;

export function getAuthProviderReadiness(
  settings: Record<string, string | undefined>,
  origins?: { adminOrigin?: string; publicOrigin?: string },
): AuthProviderReadiness[];

export function validateAuthProviderConfiguration(
  settings: Record<string, string | undefined>,
): AuthProviderReadiness[];

export function normalizeZohoAccountsOrigin(value?: string): string;
