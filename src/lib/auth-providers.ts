import {
  AUTH_PROVIDER_IDS,
  getAuthProviderReadiness as resolveAuthProviderReadiness,
  validateAuthProviderConfiguration as validateSharedAuthProviderConfiguration,
  type AuthProviderReadiness,
} from "../../packages/auth-provider-readiness/index.mjs";

export const authProviderIds = AUTH_PROVIDER_IDS;

export type AuthProviderId = (typeof authProviderIds)[number];

export type AuthProviderAvailability = {
  id: AuthProviderId;
  label: string;
  configured: boolean;
};

type ProviderSettings = Record<string, string | undefined>;

export function isProviderConfigured(
  provider: AuthProviderId,
  settings: ProviderSettings,
) {
  return resolveAuthProviderReadiness(settings)
    .find((candidate) => candidate.id === provider)?.configured ?? false;
}

export function getAuthProviderAvailability(
  settings: ProviderSettings,
): AuthProviderAvailability[] {
  return resolveAuthProviderReadiness(settings).map(({ configured, id, label }) => ({
    configured,
    id,
    label,
  }));
}

export function getLoginAuthProviderAvailability(
  settings: ProviderSettings,
): AuthProviderAvailability[] {
  return resolveAuthProviderReadiness(settings)
    .filter((provider) => provider.visible)
    .map(({ configured, id, label }) => ({ configured, id, label }));
}

export function getAuthProviderReadiness(
  settings: ProviderSettings,
  origins?: { adminOrigin?: string; publicOrigin?: string },
): AuthProviderReadiness[] {
  return resolveAuthProviderReadiness(settings, origins);
}

export function validateAuthProviderConfiguration(settings: ProviderSettings) {
  return validateSharedAuthProviderConfiguration(settings);
}

export type { AuthProviderReadiness } from "../../packages/auth-provider-readiness/index.mjs";

export function isGenericOAuthProvider(
  provider: AuthProviderId,
): provider is Extract<AuthProviderId, "yahoo" | "zoho"> {
  return provider === "yahoo" || provider === "zoho";
}
