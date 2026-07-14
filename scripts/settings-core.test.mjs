import { describe, expect, it } from "vitest";

import {
  parseEnvironmentText,
  runtimeSettingNames,
  runtimeSettingScopes,
} from "./settings-core.mjs";

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

describe("runtime setting scopes", () => {
  it("keeps gateway and private-engine settings in explicit scopes", () => {
    expect(runtimeSettingScopes()).toEqual(["gateway", "engine"]);
    expect(runtimeSettingNames("gateway")).toContain("BETTER_AUTH_SECRET");
    expect(runtimeSettingNames("gateway")).not.toContain("ENGINE_INTERNAL_HMAC_SECRET");
    expect(runtimeSettingNames("engine")).toContain("ENGINE_INTERNAL_HMAC_SECRET");
    expect(runtimeSettingNames("engine")).toContain("EVIDENCE_SEAL_PRIVATE_JWK");
    expect(runtimeSettingNames("engine")).toContain("ENGINE_OUTBOX_ENCRYPTION_SECRET");
  });
});
