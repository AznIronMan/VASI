import { betterAuth, type BetterAuthOptions } from "better-auth";
import { admin as adminPlugin, genericOAuth, username } from "better-auth/plugins";

import { generateAppleClientSecret } from "@/lib/apple-secret";
import { database } from "@/lib/database";
import { sendAuthEmail } from "@/lib/email";
import { isProviderConfigured } from "@/lib/auth-providers";
import { resolveServerEnvironment } from "@/lib/server-environment";

const { adminEmails, adminOrigin, authSecret, baseURL } = resolveServerEnvironment();
const authenticationOrigins = [baseURL, adminOrigin];
const allowedHosts = [...new Set(authenticationOrigins.map((origin) => new URL(origin).host))];

const socialProviders: NonNullable<BetterAuthOptions["socialProviders"]> = {};

if (isProviderConfigured("microsoft")) {
  socialProviders.microsoft = {
    clientId: process.env.MICROSOFT_CLIENT_ID!,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET!,
    tenantId: process.env.MICROSOFT_TENANT_ID || "common",
    prompt: "select_account",
    mapProfileToUser: () => ({ image: undefined }),
  };
}

if (isProviderConfigured("google")) {
  socialProviders.google = {
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    prompt: "select_account",
  };
}

if (isProviderConfigured("apple")) {
  socialProviders.apple = async () => ({
    clientId: process.env.APPLE_CLIENT_ID!,
    clientSecret:
      process.env.APPLE_CLIENT_SECRET ||
      (await generateAppleClientSecret({
        clientId: process.env.APPLE_CLIENT_ID!,
        teamId: process.env.APPLE_TEAM_ID!,
        keyId: process.env.APPLE_KEY_ID!,
        privateKey: process.env.APPLE_PRIVATE_KEY!,
      })),
  });
}

const genericOAuthConfigs: Parameters<typeof genericOAuth>[0]["config"] = [];

if (isProviderConfigured("yahoo")) {
  genericOAuthConfigs.push({
    providerId: "yahoo",
    clientId: process.env.YAHOO_CLIENT_ID!,
    clientSecret: process.env.YAHOO_CLIENT_SECRET!,
    discoveryUrl: "https://api.login.yahoo.com/.well-known/openid-configuration",
    issuer: "https://api.login.yahoo.com",
    scopes: ["openid", "profile", "email"],
    authentication: "basic",
  });
}

if (isProviderConfigured("zoho")) {
  const accountsOrigin = new URL(
    process.env.ZOHO_ACCOUNTS_ORIGIN?.trim() || "https://accounts.zoho.com",
  );
  if (accountsOrigin.protocol !== "https:") {
    throw new Error("ZOHO_ACCOUNTS_ORIGIN must use HTTPS.");
  }

  genericOAuthConfigs.push({
    providerId: "zoho",
    clientId: process.env.ZOHO_CLIENT_ID!,
    clientSecret: process.env.ZOHO_CLIENT_SECRET!,
    discoveryUrl: `${accountsOrigin.origin}/.well-known/openid-configuration`,
    issuer: accountsOrigin.origin,
    scopes: ["openid", "profile", "email"],
    authentication: "basic",
  });
}

const genericOAuthPlugin = genericOAuthConfigs.length
  ? genericOAuth({ config: genericOAuthConfigs })
  : undefined;

export const auth = betterAuth({
  appName: "CNB V·Sign",
  baseURL: {
    allowedHosts,
    protocol: new URL(baseURL).protocol === "https:" ? "https" : "http",
    fallback: baseURL,
  },
  secret: authSecret,
  database,
  disabledPaths: ["/is-username-available"],
  trustedOrigins: [...authenticationOrigins, "https://appleid.apple.com"],
  socialProviders,
  plugins: [
    username({
      minUsernameLength: 3,
      maxUsernameLength: 32,
      usernameValidator: (value) => /^[a-zA-Z0-9._-]+$/.test(value),
    }),
    adminPlugin({
      defaultRole: "user",
      bannedUserMessage: "This V·Sign account is disabled. Contact CNB support for help.",
    }),
    ...(genericOAuthPlugin ? [genericOAuthPlugin] : []),
  ],
  databaseHooks: {
    session: {
      create: {
        before: async (session) => {
          await database.query(
            `update "user"
             set "role" = 'admin', "updatedAt" = CURRENT_TIMESTAMP
             where "id" = $1 and lower("email") = any($2::text[])`,
            [session.userId, adminEmails],
          );
          return { data: session };
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
        subject: "Reset your V·Sign password",
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
        subject: "Verify your V·Sign account",
        heading: "Verify your email address",
        message: "Confirm that this address belongs to you before entering the signing workspace.",
        actionLabel: "Verify email",
        actionUrl: url,
      });
    },
  },
  session: {
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
