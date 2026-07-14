export function resolveDatabaseConnectionOptions(
  connectionString: string,
  sslMode: string | undefined,
) {
  if (sslMode !== undefined && sslMode !== "disable" && sslMode !== "require") {
    throw new Error("The PostgreSQL SSL mode must be either require or disable.");
  }

  if (!sslMode) {
    return { connectionString, ssl: undefined };
  }

  const databaseURL = new URL(connectionString);
  databaseURL.searchParams.set(
    "sslmode",
    sslMode === "require" ? "verify-full" : "disable",
  );

  return {
    connectionString: databaseURL.toString(),
    ssl: sslMode === "require" ? { rejectUnauthorized: true as const } : false,
  };
}
