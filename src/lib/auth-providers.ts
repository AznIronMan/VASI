export const authProviderIds = ["microsoft", "google", "apple", "yahoo", "zoho"] as const;

export type AuthProviderId = (typeof authProviderIds)[number];

export type AuthProviderAvailability = {
  id: AuthProviderId;
  label: string;
  configured: boolean;
};

type PublicEnvironment = Record<string, string | undefined>;

const providerLabels: Record<AuthProviderId, string> = {
  microsoft: "Microsoft",
  google: "Google",
  apple: "Apple",
  yahoo: "Yahoo",
  zoho: "Zoho",
};

function hasValues(environment: PublicEnvironment, keys: string[]) {
  return keys.every((key) => Boolean(environment[key]?.trim()));
}

export function isProviderConfigured(
  provider: AuthProviderId,
  environment: PublicEnvironment = process.env,
) {
  switch (provider) {
    case "microsoft":
      return hasValues(environment, ["MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"]);
    case "google":
      return hasValues(environment, ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]);
    case "apple":
      return (
        hasValues(environment, ["APPLE_CLIENT_ID", "APPLE_CLIENT_SECRET"]) ||
        hasValues(environment, [
          "APPLE_CLIENT_ID",
          "APPLE_TEAM_ID",
          "APPLE_KEY_ID",
          "APPLE_PRIVATE_KEY",
        ])
      );
    case "yahoo":
      return hasValues(environment, ["YAHOO_CLIENT_ID", "YAHOO_CLIENT_SECRET"]);
    case "zoho":
      return hasValues(environment, ["ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET"]);
  }
}

export function getAuthProviderAvailability(
  environment: PublicEnvironment = process.env,
): AuthProviderAvailability[] {
  return authProviderIds.map((id) => ({
    id,
    label: providerLabels[id],
    configured: isProviderConfigured(id, environment),
  }));
}

export function getLoginAuthProviderAvailability(
  environment: PublicEnvironment = process.env,
): AuthProviderAvailability[] {
  const appleLoginEnabled = environment.APPLE_LOGIN_ENABLED?.trim().toLowerCase() === "true";

  return getAuthProviderAvailability(environment).filter(
    (provider) => provider.id !== "apple" || appleLoginEnabled,
  );
}

export function isGenericOAuthProvider(
  provider: AuthProviderId,
): provider is Extract<AuthProviderId, "yahoo" | "zoho"> {
  return provider === "yahoo" || provider === "zoho";
}
