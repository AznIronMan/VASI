import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  createBootstrapSettings,
  parseEnvironmentText,
  rebindBootstrapSettings,
  runtimeSettingNames,
  runtimeSettingScopes,
} from "./settings-core.mjs";

describe("legacy environment parsing", () => {
  it("accepts streamed Docker environment output without exposing values", () => {
    expect(parseEnvironmentText(`
      # ignored
      DATABASE_URL=postgresql://vasi@database/vasi
      export BETTER_AUTH_URL="https://vsign.example.test"
      VASI_ADMIN_EMAILS='operator@example.test'
      UNUSED=value # comment
    `)).toEqual({
      BETTER_AUTH_URL: "https://vsign.example.test",
      DATABASE_URL: "postgresql://vasi@database/vasi",
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

describe("recovery bootstrap rebind", () => {
  it("atomically changes only database endpoint fields and preserves custody", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "vasi-rebind-"));
    const settingsPath = path.join(directory, "VASI.settings");
    try {
      const original = createBootstrapSettings({
        databasePoolMax: 5,
        databaseSSL: "disable",
        databaseURL: "postgresql://source@database.example/source",
        settingsPath,
      });
      const rebound = rebindBootstrapSettings({
        databasePoolMax: 12,
        databaseSSL: "require",
        databaseURL: "postgresql://recovery@database.example/recovery",
        settingsPath,
      });
      expect(rebound.databaseURL).toBe("postgresql://recovery@database.example/recovery");
      expect(rebound.databaseSSL).toBe("require");
      expect(rebound.databasePoolMax).toBe(12);
      expect(rebound.installationId).toBe(original.installationId);
      expect(rebound.settingsKey).toEqual(original.settingsKey);
      expect(statSync(settingsPath).mode & 0o777).toBe(0o600);
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });
});
