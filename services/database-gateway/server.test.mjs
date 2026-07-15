import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { createBootstrapSettings } from "../../scripts/settings-core.mjs";
import {
  createDatabaseGateway,
  loadDatabaseGatewayTarget,
  resolveDatabaseGatewayAddresses,
  validateDatabaseGatewayTarget,
} from "./server.mjs";

describe("minimal PostgreSQL transport gateway", () => {
  it("loads only a bounded destination and connection limit from the protected bootstrap", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "vasi-database-gateway-"));
    const settingsPath = path.join(directory, "VASI.settings");
    const databaseURL = new URL("postgresql://database.example.test:5444/vasi");
    databaseURL.username = "private-user";
    databaseURL.password = "private-password";
    try {
      createBootstrapSettings({
        databasePoolMax: 5,
        databaseSSL: "require",
        databaseURL: databaseURL.toString(),
        settingsPath,
      });
      const target = loadDatabaseGatewayTarget(settingsPath);
      expect(target).toEqual({ connectionLimit: 80, hostname: "database.example.test", port: 5444 });
      expect(JSON.stringify(target)).not.toContain("private-user");
      expect(JSON.stringify(target)).not.toContain("private-password");
      expect(JSON.stringify(target)).not.toContain("vasi");
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });

  it("rejects recursive, non-PostgreSQL, and unbounded targets", () => {
    expect(() => validateDatabaseGatewayTarget({
      databasePoolMax: 5,
      databaseURL: "postgresql://database-gateway/vasi",
    })).toThrow("target is invalid");
    expect(() => validateDatabaseGatewayTarget({
      databasePoolMax: 5,
      databaseURL: "https://database.example.test/vasi",
    })).toThrow("target is invalid");
    expect(() => validateDatabaseGatewayTarget({
      databasePoolMax: 101,
      databaseURL: "postgresql://database.example.test/vasi",
    })).toThrow("target is invalid");
  });

  it("deduplicates bounded unicast address resolution and rejects unsafe results", async () => {
    await expect(resolveDatabaseGatewayAddresses("database.example.test", async () => [
      { address: "10.0.10.10", family: 4 },
      { address: "10.0.10.10", family: 4 },
    ])).resolves.toEqual(["10.0.10.10"]);
    await expect(resolveDatabaseGatewayAddresses("database.example.test", async () => [
      { address: "127.0.0.1", family: 4 },
    ])).rejects.toThrow("resolution is invalid");
    await expect(resolveDatabaseGatewayAddresses("database.example.test", async () => [
      { address: "2001:db8::10", family: 6 },
    ])).rejects.toThrow("resolution is invalid");
    await expect(resolveDatabaseGatewayAddresses("database.example.test", async () => {
      throw new Error("private resolver detail");
    })).rejects.toThrow("could not be resolved");
  });

  it("relays bytes without inspecting PostgreSQL content and serves bounded health", async () => {
    const upstream = net.createServer((socket) => socket.pipe(socket));
    await listen(upstream);
    const upstreamAddress = upstream.address();
    const gateway = createDatabaseGateway({
      addressProvider: () => ["127.0.0.1"],
      connectionLimit: 4,
      healthPort: 0,
      listenHost: "127.0.0.1",
      listenPort: 0,
      upstreamPort: upstreamAddress.port,
    });
    const addresses = await gateway.listen();
    try {
      const response = await relay(addresses.transport.port, Buffer.from("postgres-wire-proof"));
      expect(response.toString()).toBe("postgres-wire-proof");
      const health = await fetch(`http://127.0.0.1:${addresses.health.port}/healthz`);
      expect(health.status).toBe(200);
      expect(await health.json()).toEqual({
        schema: "vasi-database-gateway-health/v1",
        status: "ok",
        version: "0.34.0",
      });
    } finally {
      await gateway.close();
      await close(upstream);
    }
  });
});

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function relay(port, content) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const chunks = [];
    socket.once("connect", () => socket.write(content));
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      socket.end();
    });
    socket.once("end", () => resolve(Buffer.concat(chunks)));
    socket.once("error", reject);
  });
}
