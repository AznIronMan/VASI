import { describe, expect, it } from "vitest";

import { parseEnvironmentText } from "./settings-core.mjs";

describe("legacy environment parsing", () => {
  it("accepts streamed Docker environment output without exposing values", () => {
    expect(parseEnvironmentText(`
      # ignored
      DATABASE_URL=postgresql://vasi:example@database/vasi
      export BETTER_AUTH_URL="https://vsign.example.test"
      VASI_ADMIN_EMAILS='operator@example.test'
      UNUSED=value # comment
    `)).toEqual({
      BETTER_AUTH_URL: "https://vsign.example.test",
      DATABASE_URL: "postgresql://vasi:example@database/vasi",
      UNUSED: "value",
      VASI_ADMIN_EMAILS: "operator@example.test",
    });
  });

  it("rejects malformed input", () => {
    expect(() => parseEnvironmentText("not an assignment")).toThrow(
      "Invalid environment-file syntax on line 1.",
    );
  });
});
