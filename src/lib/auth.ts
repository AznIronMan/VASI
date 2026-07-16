import { betterAuth, type BetterAuthOptions } from "better-auth";
import { admin as adminPlugin, genericOAuth, username } from "better-auth/plugins";

import { generateAppleClientSecret } from "@/lib/apple-secret";
import { resolveProductBrand } from "@/lib/branding";
import { resolveSessionAuthentication } from "@/lib/auth-provenance";
import { recordConnectorAuthentication } from "@/lib/connector-authentication-health";
import { database, getDatabase } from "@/lib/database";
import { sendAuthEmail } from "@/lib/email";
import {
  isProviderConfigured,
  validateAuthProviderConfiguration,
} from "@/lib/auth-providers";
import { normalizeZohoAccountsOrigin } from "../../packages/auth-provider-readiness/index.mjs";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

type VasiAuth = Awaited<ReturnType<typeof createAuth>>;

const globalForAuth = globalThis as unknown as {
  vasiAuth?: Promise<VasiAuth>;
};

export function getAuth() {
  globalForAuth.vasiAuth ??= createAuth();
  return globalForAuth.vasiAuth!;
}

async function createAuth() {
  const settings = await getRuntimeSettings();
  validateAuthProviderConfiguration(settings);
  const brand = resolveProductBrand(settings);
  const { adminEmails, adminOrigin, authSecret, baseURL, trustedProxyCIDRs } =
    resolveServerSettings(settings);
  const authenticationOrigins = [baseURL, adminOrigin];
  const allowedHosts = [...new Set(authenticationOrigins.map((origin) => new URL(origin).host))];
  const socialProviders: NonNullable<BetterAuthOptions["socialProviders"]> = {};

  if (isProviderConfigured("microsoft", settings)) {
    socialProviders.microsoft = {
      clientId: settings.MICROSOFT_CLIENT_ID!,
      clientSecret: settings.MICROSOFT_CLIENT_SECRET!,
      tenantId: settings.MICROSOFT_TENANT_ID || "common",
      prompt: "select_account",
      mapProfileToUser: () => ({ image: undefined }),
    };
  }

  if (isProviderConfigured("google", settings)) {
    socialProviders.google = {
      clientId: settings.GOOGLE_CLIENT_ID!,
      clientSecret: settings.GOOGLE_CLIENT_SECRET!,
      prompt: "select_account",
    };
  }

  if (isProviderConfigured("apple", settings)) {
    socialProviders.apple = async () => ({
      clientId: settings.APPLE_CLIENT_ID!,
      clientSecret:
        settings.APPLE_CLIENT_SECRET ||
        (await generateAppleClientSecret({
          clientId: settings.APPLE_CLIENT_ID!,
          teamId: settings.APPLE_TEAM_ID!,
          keyId: settings.APPLE_KEY_ID!,
          privateKey: settings.APPLE_PRIVATE_KEY!,
        })),
    });
  }

  const genericOAuthConfigs: Parameters<typeof genericOAuth>[0]["config"] = [];

  if (isProviderConfigured("yahoo", settings)) {
    genericOAuthConfigs.push({
      providerId: "yahoo",
      clientId: settings.YAHOO_CLIENT_ID!,
      clientSecret: settings.YAHOO_CLIENT_SECRET!,
      discoveryUrl: "https://api.login.yahoo.com/.well-known/openid-configuration",
      issuer: "https://api.login.yahoo.com",
      scopes: ["openid", "profile", "email"],
      authentication: "basic",
    });
  }

  if (isProviderConfigured("zoho", settings)) {
    const accountsOrigin = normalizeZohoAccountsOrigin(settings.ZOHO_ACCOUNTS_ORIGIN);

    genericOAuthConfigs.push({
      providerId: "zoho",
      clientId: settings.ZOHO_CLIENT_ID!,
      clientSecret: settings.ZOHO_CLIENT_SECRET!,
      discoveryUrl: `${accountsOrigin}/.well-known/openid-configuration`,
      issuer: accountsOrigin,
      scopes: ["openid", "profile", "email"],
      authentication: "basic",
    });
  }

  const genericOAuthPlugin = genericOAuthConfigs.length
    ? genericOAuth({ config: genericOAuthConfigs })
    : undefined;

  return betterAuth({
    appName: brand.displayName,
    baseURL: {
      allowedHosts,
      protocol: new URL(baseURL).protocol === "https:" ? "https" : "http",
      fallback: baseURL,
    },
    secret: authSecret,
    database: getDatabase(),
    disabledPaths: ["/is-username-available"],
    trustedOrigins: [...authenticationOrigins, "https://appleid.apple.com"],
    advanced: {
      ipAddress: {
        ipAddressHeaders: ["x-forwarded-for", "x-real-ip"],
        ipv6Subnet: 64,
        trustedProxies: trustedProxyCIDRs,
      },
      trustedProxyHeaders: false,
      useSecureCookies: new URL(baseURL).protocol === "https:",
    },
    socialProviders,
    plugins: [
      username({
        minUsernameLength: 3,
        maxUsernameLength: 32,
        usernameValidator: (value) => /^[a-zA-Z0-9._-]+$/.test(value),
      }),
      adminPlugin({
        defaultRole: "user",
        bannedUserMessage: `This ${brand.productName} account is disabled. Contact ${brand.organizationName} support for help.`,
      }),
      ...(genericOAuthPlugin ? [genericOAuthPlugin] : []),
    ],
    databaseHooks: {
      session: {
        create: {
          before: async (session, context) => {
            await database.query(
              `update "user"
               set "role" = 'admin', "updatedAt" = CURRENT_TIMESTAMP
               where "id" = $1 and lower("email") = any($2::text[])`,
              [session.userId, adminEmails],
            );
            const authentication = resolveSessionAuthentication(context);
            const account = authentication.provider
              ? await database.query<{ accountId: string }>(
                  `select "accountId" from "account"
                   where "userId" = $1 and "providerId" = $2
                   order by "updatedAt" desc limit 1`,
                  [session.userId, authentication.provider],
                )
              : undefined;
            return {
              data: {
                ...session,
                authenticationAccountId: account?.rows[0]?.accountId,
                authenticationMethod: authentication.method,
                authenticationProvider: authentication.provider,
                authenticationProvenance: authentication.provenance,
              },
            };
          },
          after: async (session) => {
            try {
              const result = await recordConnectorAuthentication(session);
              if (result !== "recorded" && result !== "ignored") {
                console.warn(JSON.stringify({
                  event: "connector_authentication_health_update_incomplete",
                  result,
                }));
              }
            } catch {
              // Connector health must never turn a completed login into a false
              // denial. The attributed session remains the authoritative event.
              console.error(JSON.stringify({
                event: "connector_authentication_health_update_failed",
              }));
            }
          },
        },
      },
    },
    account: {
      encryptOAuthTokens: true,
      storeStateStrategy: "database",
      updateAccountOnSignIn: true,
      accountLinking: {
        enabled: true,
        allowDifferentEmails: false,
      },
    },
    emailAndPassword: {
      enabled: true,
      autoSignIn: false,
      requireEmailVerification: true,
      minPasswordLength: 12,
      maxPasswordLength: 128,
      revokeSessionsOnPasswordReset: true,
      customSyntheticUser: ({ coreFields, additionalFields, id }) => ({
        ...coreFields,
        role: "user",
        banned: false,
        banReason: null,
        banExpires: null,
        ...additionalFields,
        id,
      }),
      resetPasswordTokenExpiresIn: 60 * 60,
      sendResetPassword: async ({ user, url }) => {
        await sendAuthEmail({
          to: user.email,
          subject: `Reset your ${brand.productName} password`,
          heading: "Reset your password",
          message: "Use the secure link below to choose a new password. This link expires in one hour.",
          actionLabel: "Reset password",
          actionUrl: url,
        });
      },
    },
    emailVerification: {
      sendOnSignUp: true,
      autoSignInAfterVerification: true,
      expiresIn: 60 * 60,
      sendVerificationEmail: async ({ user, url }) => {
        await sendAuthEmail({
          to: user.email,
          subject: `Verify your ${brand.productName} account`,
          heading: "Verify your email address",
          message: "Confirm that this address belongs to you before entering the signing workspace.",
          actionLabel: "Verify email",
          actionUrl: url,
        });
      },
    },
    session: {
      additionalFields: {
        authenticationAccountId: { type: "string", required: false, input: false },
        authenticationMethod: { type: "string", required: false, input: false },
        authenticationProvider: { type: "string", required: false, input: false },
        authenticationProvenance: { type: "string", required: false, input: false },
      },
      expiresIn: 60 * 60 * 12,
      updateAge: 60 * 60,
      freshAge: 10 * 60,
    },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 100,
      customRules: {
        "/sign-in/email": { window: 60, max: 5 },
        "/sign-in/username": { window: 60, max: 5 },
        "/sign-up/email": { window: 60, max: 3 },
        "/request-password-reset": { window: 60, max: 3 },
      },
    },
  });
}
