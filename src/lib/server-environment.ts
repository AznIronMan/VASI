type ServerEnvironment = Record<string, string | undefined>;

export type ResolvedServerEnvironment = {
  authSecret: string;
  baseURL: string;
  databaseURL: string;
};

const developmentDefaults: ResolvedServerEnvironment = {
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

  if (authSecret.length < 32) {
    throw new Error("BETTER_AUTH_SECRET must contain at least 32 characters.");
  }

  const parsedBaseURL = new URL(baseURL);
  if (production && parsedBaseURL.protocol !== "https:") {
    throw new Error("BETTER_AUTH_URL must use HTTPS in production.");
  }

  if (!databaseURL.startsWith("postgresql://") && !databaseURL.startsWith("postgres://")) {
    throw new Error("DATABASE_URL must be a PostgreSQL connection string.");
  }

  return {
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
