export const authProviderIds = ["microsoft", "google", "apple", "yahoo", "zoho"] as const;

export type AuthProviderId = (typeof authProviderIds)[number];

export type AuthProviderAvailability = {
  id: AuthProviderId;
  label: string;
  configured: boolean;
};

type ProviderSettings = Record<string, string | undefined>;

const providerLabels: Record<AuthProviderId, string> = {
  microsoft: "Microsoft",
  google: "Google",
  apple: "Apple",
  yahoo: "Yahoo",
  zoho: "Zoho",
};

function hasValues(settings: ProviderSettings, keys: string[]) {
  return keys.every((key) => Boolean(settings[key]?.trim()));
}

export function isProviderConfigured(
  provider: AuthProviderId,
  settings: ProviderSettings,
) {
  switch (provider) {
    case "microsoft":
      return hasValues(settings, ["MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"]);
    case "google":
      return hasValues(settings, ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]);
    case "apple":
      return (
        hasValues(settings, ["APPLE_CLIENT_ID", "APPLE_CLIENT_SECRET"]) ||
        hasValues(settings, [
          "APPLE_CLIENT_ID",
          "APPLE_TEAM_ID",
          "APPLE_KEY_ID",
          "APPLE_PRIVATE_KEY",
        ])
      );
    case "yahoo":
      return hasValues(settings, ["YAHOO_CLIENT_ID", "YAHOO_CLIENT_SECRET"]);
    case "zoho":
      return hasValues(settings, ["ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET"]);
  }
}

export function getAuthProviderAvailability(
  settings: ProviderSettings,
): AuthProviderAvailability[] {
  return authProviderIds.map((id) => ({
    id,
    label: providerLabels[id],
    configured: isProviderConfigured(id, settings),
  }));
}

export function getLoginAuthProviderAvailability(
  settings: ProviderSettings,
): AuthProviderAvailability[] {
  const appleLoginEnabled = settings.APPLE_LOGIN_ENABLED?.trim().toLowerCase() === "true";

  return getAuthProviderAvailability(settings).filter(
    (provider) => provider.id !== "apple" || appleLoginEnabled,
  );
}

export function isGenericOAuthProvider(
  provider: AuthProviderId,
): provider is Extract<AuthProviderId, "yahoo" | "zoho"> {
  return provider === "yahoo" || provider === "zoho";
}
