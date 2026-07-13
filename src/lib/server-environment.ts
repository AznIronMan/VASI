type ServerEnvironment = Record<string, string | undefined>;

export type ResolvedServerEnvironment = {
  adminEmails: string[];
  adminOrigin: string;
  authSecret: string;
  baseURL: string;
  databaseURL: string;
};

const developmentDefaults: ResolvedServerEnvironment = {
  adminEmails: ["admin@localhost"],
  adminOrigin: "http://localhost:3000",
  authSecret: "vasi-local-development-secret-change-before-deployment",
  baseURL: "http://localhost:3000",
  databaseURL: "postgresql://vasi:vasi@localhost:5432/vasi",
};

export function resolveServerEnvironment(
  environment: ServerEnvironment = process.env,
): ResolvedServerEnvironment {
  const production =
    environment.NODE_ENV === "production" &&
    environment.NEXT_PHASE !== "phase-production-build";
  const authSecret = environment.BETTER_AUTH_SECRET ||
    requireProductionValue("BETTER_AUTH_SECRET", production, developmentDefaults.authSecret);
  const baseURL = environment.BETTER_AUTH_URL ||
    requireProductionValue("BETTER_AUTH_URL", production, developmentDefaults.baseURL);
  const databaseURL = environment.DATABASE_URL ||
    requireProductionValue("DATABASE_URL", production, developmentDefaults.databaseURL);
  const adminOrigin = environment.VASI_ADMIN_ORIGIN ||
    requireProductionValue(
      "VASI_ADMIN_ORIGIN",
      production,
      developmentDefaults.adminOrigin,
    );
  const adminEmails = parseAdminEmails(
    environment.VASI_ADMIN_EMAILS ||
      requireProductionValue(
        "VASI_ADMIN_EMAILS",
        production,
        developmentDefaults.adminEmails.join(","),
      ),
  );

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

  if (!databaseURL.startsWith("postgresql://") && !databaseURL.startsWith("postgres://")) {
    throw new Error("DATABASE_URL must be a PostgreSQL connection string.");
  }

  return {
    adminEmails,
    adminOrigin: parsedAdminOrigin.origin,
    authSecret,
    baseURL: parsedBaseURL.origin,
    databaseURL,
  };
}

function requireProductionValue(name: string, production: boolean, developmentValue: string) {
  if (production) {
    throw new Error(`${name} is required in production.`);
  }

  return developmentValue;
}

function parseAdminEmails(value: string) {
  const emails = [...new Set(
    value
      .split(",")
      .map((email) => email.trim().toLowerCase())
      .filter(Boolean),
  )];

  if (!emails.length || emails.some((email) => !/^[^@\s]+@[^@\s]+$/.test(email))) {
    throw new Error("VASI_ADMIN_EMAILS must contain a comma-separated email allowlist.");
  }

  return emails;
}
