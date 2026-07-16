export const AUTH_PROVIDER_IDS = Object.freeze([
  "microsoft",
  "google",
  "apple",
  "yahoo",
  "zoho",
]);

export const ZOHO_ACCOUNTS_ORIGINS = Object.freeze([
  "https://accounts.zoho.com",
  "https://accounts.zoho.eu",
  "https://accounts.zoho.in",
  "https://accounts.zoho.com.au",
  "https://accounts.zoho.jp",
  "https://accounts.zohocloud.ca",
  "https://accounts.zoho.sa",
  "https://accounts.zoho.uk",
]);

const providerDefinitions = Object.freeze({
  microsoft: Object.freeze({
    callbackPath: "/api/auth/callback/microsoft",
    keys: Object.freeze(["MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"]),
    label: "Microsoft",
  }),
  google: Object.freeze({
    callbackPath: "/api/auth/callback/google",
    keys: Object.freeze(["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]),
    label: "Google",
  }),
  apple: Object.freeze({
    callbackPath: "/api/auth/callback/apple",
    keys: Object.freeze([
      "APPLE_CLIENT_ID",
      "APPLE_CLIENT_SECRET",
      "APPLE_TEAM_ID",
      "APPLE_KEY_ID",
      "APPLE_PRIVATE_KEY",
    ]),
    label: "Apple",
  }),
  yahoo: Object.freeze({
    callbackPath: "/api/auth/oauth2/callback/yahoo",
    keys: Object.freeze(["YAHOO_CLIENT_ID", "YAHOO_CLIENT_SECRET"]),
    label: "Yahoo",
  }),
  zoho: Object.freeze({
    callbackPath: "/api/auth/oauth2/callback/zoho",
    keys: Object.freeze(["ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET"]),
    label: "Zoho",
  }),
});

export function getAuthProviderReadiness(
  settings,
  { adminOrigin, publicOrigin } = {},
) {
  const appleVisibility = parseAppleVisibility(settings.APPLE_LOGIN_ENABLED);
  return AUTH_PROVIDER_IDS.map((id) => {
    const definition = providerDefinitions[id];
    const configuration = providerConfiguration(id, settings, appleVisibility);
    const visible = id !== "apple" || appleVisibility === true;
    const status = configuration.state === "invalid"
      ? "invalid"
      : !visible
        ? "hidden"
        : configuration.state === "ready"
          ? "ready"
          : "configuration_required";
    return Object.freeze({
      adminCallback: callbackURL(adminOrigin, definition.callbackPath),
      callbackPath: definition.callbackPath,
      configuration: configuration.state,
      configured: configuration.state === "ready",
      id,
      label: definition.label,
      publicCallback: callbackURL(publicOrigin, definition.callbackPath),
      reason: configuration.reason,
      status,
      visible,
    });
  });
}

export function validateAuthProviderConfiguration(settings) {
  const readiness = getAuthProviderReadiness(settings);
  const invalid = readiness.filter((provider) => provider.configuration === "invalid");
  if (invalid.length) {
    throw new Error(
      `Invalid VASI identity-provider configuration: ${invalid
        .map((provider) => `${provider.label} (${provider.reason})`)
        .join(", ")}.`,
    );
  }
  return readiness;
}

export function normalizeZohoAccountsOrigin(value = "https://accounts.zoho.com") {
  let parsed;
  try {
    parsed = new URL(String(value).trim());
  } catch {
    throw new Error("The Zoho accounts origin is unsupported.");
  }
  if (
    parsed.protocol !== "https:" || parsed.username || parsed.password ||
    parsed.pathname !== "/" || parsed.search || parsed.hash ||
    !ZOHO_ACCOUNTS_ORIGINS.includes(parsed.origin)
  ) {
    throw new Error("The Zoho accounts origin is unsupported.");
  }
  return parsed.origin;
}

function providerConfiguration(id, settings, appleVisibility) {
  if (id === "apple") return appleConfiguration(settings, appleVisibility);
  const definition = providerDefinitions[id];
  const present = definition.keys.map((key) => hasValue(settings[key]));
  if (id === "zoho") {
    try {
      normalizeZohoAccountsOrigin(settings.ZOHO_ACCOUNTS_ORIGIN);
    } catch {
      return { reason: "unsupported_accounts_origin", state: "invalid" };
    }
  }
  if (!present.some(Boolean)) return { reason: "not_configured", state: "required" };
  if (!present.every(Boolean)) return { reason: "partial_credentials", state: "invalid" };
  return { reason: "complete", state: "ready" };
}

function appleConfiguration(settings, appleVisibility) {
  if (appleVisibility === null) {
    return { reason: "invalid_visibility_setting", state: "invalid" };
  }
  const clientId = hasValue(settings.APPLE_CLIENT_ID);
  const clientSecret = hasValue(settings.APPLE_CLIENT_SECRET);
  const generatedParts = [
    hasValue(settings.APPLE_TEAM_ID),
    hasValue(settings.APPLE_KEY_ID),
    hasValue(settings.APPLE_PRIVATE_KEY),
  ];
  const anyCredential = clientId || clientSecret || generatedParts.some(Boolean);
  const staticReady = clientId && clientSecret;
  const generatedReady = clientId && generatedParts.every(Boolean);
  const partialGeneratedRoute = generatedParts.some(Boolean) && !generatedParts.every(Boolean);

  if (!anyCredential) {
    return appleVisibility
      ? { reason: "visibility_requires_credentials", state: "invalid" }
      : { reason: "not_configured", state: "required" };
  }
  if ((!staticReady && !generatedReady) || partialGeneratedRoute) {
    return { reason: "partial_credentials", state: "invalid" };
  }
  return { reason: "complete", state: "ready" };
}

function parseAppleVisibility(value) {
  const normalized = String(value ?? "false").trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  return null;
}

function callbackURL(origin, callbackPath) {
  if (!origin) return null;
  const parsed = new URL(String(origin));
  if (
    !["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password ||
    parsed.pathname !== "/" || parsed.search || parsed.hash
  ) throw new Error("The authentication callback origin is invalid.");
  return `${parsed.origin}${callbackPath}`;
}

function hasValue(value) {
  return Boolean(String(value ?? "").trim());
}
