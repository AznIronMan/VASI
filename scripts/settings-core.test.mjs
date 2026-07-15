import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { Socket } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import {
  createBootstrapSettings,
  databaseConnectionOptions,
  loadDatabaseGatewayTransport,
  parseEnvironmentText,
  rebindBootstrapSettings,
  runtimeSettingNames,
  runtimeSettingScopes,
} from "./settings-core.mjs";

describe("database gateway transport", () => {
  it("redirects only the raw socket while retaining the original TLS identity URL", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "vasi-database-transport-"));
    const transportPath = path.join(directory, "transport.json");
    const databaseURL = new URL("postgresql://database.example.test:5444/vasi");
    databaseURL.username = "user";
    databaseURL.password = "password";
    try {
      writeFileSync(transportPath, JSON.stringify({
        host: "database-gateway",
        port: 5432,
        schema: "vasi-database-gateway-transport/v1",
      }));
      const options = databaseConnectionOptions({
        databasePoolMax: 5,
        databaseSSL: "require",
        databaseURL: databaseURL.toString(),
      }, { transportPath });
      expect(new URL(options.connectionString).hostname).toBe("database.example.test");
      expect(new URL(options.connectionString).port).toBe("5444");
      expect(options.ssl).toEqual({ rejectUnauthorized: true });
      const connect = vi.spyOn(Socket.prototype, "connect").mockImplementation(function () { return this; });
      try {
        options.stream().connect(5444, "database.example.test");
        expect(connect).toHaveBeenCalledWith(5432, "database-gateway");
      } finally {
        connect.mockRestore();
      }
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });

  it("uses direct PostgreSQL transport when no marker exists and rejects marker drift", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "vasi-database-transport-"));
    const transportPath = path.join(directory, "transport.json");
    try {
      const direct = databaseConnectionOptions({
        databasePoolMax: 5,
        databaseSSL: "disable",
        databaseURL: "postgresql://database.example.test/vasi",
      }, { transportPath });
      expect(direct.stream).toBeUndefined();
      writeFileSync(transportPath, JSON.stringify({
        host: "unapproved-proxy",
        port: 5432,
        schema: "vasi-database-gateway-transport/v1",
      }));
      expect(() => loadDatabaseGatewayTransport(transportPath)).toThrow("marker is invalid");
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });
});

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
    expect(runtimeSettingNames("gateway")).toContain("BACKUP_CUSTODY_RECIPIENTS");
    expect(runtimeSettingNames("gateway")).not.toContain("ENGINE_INTERNAL_HMAC_SECRET");
    expect(runtimeSettingNames("engine")).toContain("ENGINE_INTERNAL_HMAC_SECRET");
    expect(runtimeSettingNames("engine")).toContain("EVIDENCE_SEAL_PRIVATE_JWK");
    expect(runtimeSettingNames("engine")).toContain("ENGINE_OUTBOX_ENCRYPTION_SECRET");
    expect(runtimeSettingNames("engine")).toContain("BACKUP_CUSTODY_RECIPIENTS");
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
