import { describe, expect, it } from "vitest";

import { resolveDatabaseConnectionOptions } from "@/lib/database-config";

describe("database connection configuration", () => {
  it("leaves the connection string unchanged when no SSL mode is set", () => {
    const connectionString = "postgresql://user@database.example/vasi?application_name=vasi";

    expect(resolveDatabaseConnectionOptions(connectionString, undefined)).toEqual({
      connectionString,
      ssl: undefined,
    });
  });

  it("overrides URL-level SSL hints when SSL is disabled", () => {
    const options = resolveDatabaseConnectionOptions(
      "postgresql://user@database.example/vasi?sslmode=prefer&application_name=vasi",
      "disable",
    );

    expect(new URL(options.connectionString).searchParams.get("sslmode")).toBe("disable");
    expect(options.ssl).toBe(false);
  });

  it("uses full certificate verification when SSL is required", () => {
    const options = resolveDatabaseConnectionOptions(
      "postgresql://user@database.example/vasi?sslmode=disable",
      "require",
    );

    expect(new URL(options.connectionString).searchParams.get("sslmode")).toBe("verify-full");
    expect(options.ssl).toEqual({ rejectUnauthorized: true });
  });

  it("rejects unsupported SSL modes", () => {
    expect(() =>
      resolveDatabaseConnectionOptions(
        "postgresql://user@database.example/vasi",
        "prefer",
      ),
    ).toThrow("The PostgreSQL SSL mode must be either require or disable.");
  });
});
