import { lookup } from "node:dns/promises";
import { statSync } from "node:fs";
import { createServer as createHTTPServer } from "node:http";
import { isIP } from "node:net";
import net from "node:net";
import process from "node:process";
import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";

export const DATABASE_GATEWAY_VERSION = "0.41.1";
export const DATABASE_GATEWAY_HEALTH_SCHEMA = "vasi-database-gateway-health/v1";
const DEFAULT_SETTINGS_PATH = "/app/data/VASI.settings";
const MAXIMUM_ADDRESSES = 16;
const RESOLUTION_FRESH_MILLISECONDS = 300_000;
const RESOLUTION_INTERVAL_MILLISECONDS = 60_000;
const UPSTREAM_CONNECT_MILLISECONDS = 10_000;

export function loadDatabaseGatewayTarget(settingsPath = DEFAULT_SETTINGS_PATH) {
  const metadata = statSync(settingsPath);
  if (!metadata.isFile() || (metadata.mode & 0o777) !== 0o600) {
    throw new Error("The VASI database gateway bootstrap is unavailable.");
  }
  const sqlite = new DatabaseSync(settingsPath, { readOnly: true });
  try {
    const row = sqlite.prepare(`
      select "schemaVersion", "databaseURL", "databasePoolMax"
      from "vasi_bootstrap" where "id" = 1
    `).get();
    if (!row || row.schemaVersion !== 1) throw new Error("The VASI database gateway bootstrap is unsupported.");
    return validateDatabaseGatewayTarget({
      databasePoolMax: Number(row.databasePoolMax),
      databaseURL: String(row.databaseURL),
    });
  } finally {
    sqlite.close();
  }
}

export function validateDatabaseGatewayTarget({ databasePoolMax, databaseURL }) {
  let target;
  try {
    const parsed = new URL(databaseURL);
    if (!["postgres:", "postgresql:"].includes(parsed.protocol) || parsed.hostname === "database-gateway") {
      throw new Error("unsupported");
    }
    const port = Number(parsed.port || 5432);
    if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("unsupported");
    if (!Number.isInteger(databasePoolMax) || databasePoolMax < 1 || databasePoolMax > 100) {
      throw new Error("unsupported");
    }
    target = {
      connectionLimit: Math.min(1_000, Math.max(64, databasePoolMax * 16)),
      hostname: parsed.hostname,
      port,
    };
  } catch {
    throw new Error("The VASI database gateway target is invalid.");
  }
  return Object.freeze(target);
}

export async function resolveDatabaseGatewayAddresses(hostname, resolver = lookup) {
  let results;
  try {
    results = await resolver(hostname, { all: true, family: 4, verbatim: true });
  } catch {
    throw new Error("The VASI database gateway target could not be resolved.");
  }
  if (!Array.isArray(results) || !results.length || results.length > MAXIMUM_ADDRESSES) {
    throw new Error("The VASI database gateway target resolution is invalid.");
  }
  const addresses = [...new Set(results.map((entry) => validatedAddress(entry)))];
  if (!addresses.length || addresses.length > MAXIMUM_ADDRESSES) {
    throw new Error("The VASI database gateway target resolution is invalid.");
  }
  return Object.freeze(addresses);
}

export function createDatabaseGateway({
  addressProvider,
  connectionLimit,
  healthHost = "127.0.0.1",
  healthPort = 8081,
  listenHost = "0.0.0.0",
  listenPort = 5432,
  now = () => Date.now(),
  upstreamPort,
}) {
  if (typeof addressProvider !== "function") throw new Error("The VASI database gateway address provider is invalid.");
  if (!Number.isInteger(connectionLimit) || connectionLimit < 1 || connectionLimit > 1_000) {
    throw new Error("The VASI database gateway connection limit is invalid.");
  }
  const active = new Set();
  let cursor = 0;
  let lastResolutionMilliseconds = now();
  const server = net.createServer((client) => {
    const addresses = addressProvider();
    if (!Array.isArray(addresses) || !addresses.length || active.size >= connectionLimit) {
      client.destroy();
      return;
    }
    const address = addresses[cursor % addresses.length];
    cursor += 1;
    client.pause();
    const upstream = net.createConnection({ host: address, port: upstreamPort });
    const pair = { client, upstream };
    active.add(pair);
    const timer = setTimeout(() => {
      client.destroy();
      upstream.destroy();
    }, UPSTREAM_CONNECT_MILLISECONDS);
    timer.unref();
    const close = () => {
      clearTimeout(timer);
      active.delete(pair);
    };
    upstream.once("connect", () => {
      clearTimeout(timer);
      upstream.setKeepAlive(true, 30_000);
      client.setKeepAlive(true, 30_000);
      client.pipe(upstream);
      upstream.pipe(client);
      client.resume();
    });
    upstream.once("error", () => client.destroy());
    client.once("error", () => upstream.destroy());
    upstream.once("close", close);
    client.once("close", close);
  });
  server.maxConnections = connectionLimit;
  const health = createHTTPServer((request, response) => {
    const ready =
      request.method === "GET" && request.url === "/healthz" &&
      now() - lastResolutionMilliseconds <= RESOLUTION_FRESH_MILLISECONDS;
    const body = JSON.stringify({
      schema: DATABASE_GATEWAY_HEALTH_SCHEMA,
      status: ready ? "ok" : "unavailable",
      version: DATABASE_GATEWAY_VERSION,
    });
    response.writeHead(ready ? 200 : 503, {
      "cache-control": "no-store",
      "content-length": Buffer.byteLength(body),
      "content-type": "application/json",
    });
    response.end(body);
  });
  return Object.freeze({
    close: async () => {
      for (const pair of active) {
        pair.client.destroy();
        pair.upstream.destroy();
      }
      await Promise.all([closeServer(server), closeServer(health)]);
    },
    listen: async () => {
      await Promise.all([
        listen(server, listenPort, listenHost),
        listen(health, healthPort, healthHost),
      ]);
      return Object.freeze({ health: health.address(), transport: server.address() });
    },
    markResolved: () => { lastResolutionMilliseconds = now(); },
  });
}

function validatedAddress(entry) {
  const address = String(entry?.address || "");
  const family = Number(entry?.family);
  if (family !== 4 || isIP(address) !== family || isUnsafeAddress(address)) {
    throw new Error("The VASI database gateway target resolution is invalid.");
  }
  return address;
}

function isUnsafeAddress(address) {
  const octets = address.split(".").map(Number);
  return octets[0] === 0 || octets[0] === 127 || octets[0] >= 224 ||
    (octets[0] === 169 && octets[1] === 254);
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    const fail = (error) => {
      server.off("listening", ready);
      reject(error);
    };
    const ready = () => {
      server.off("error", fail);
      resolve();
    };
    server.once("error", fail);
    server.once("listening", ready);
    server.listen(port, host);
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server.listening) return resolve();
    server.close(() => resolve());
  });
}

async function main() {
  const target = loadDatabaseGatewayTarget();
  let addresses = await resolveDatabaseGatewayAddresses(target.hostname);
  const gateway = createDatabaseGateway({
    addressProvider: () => addresses,
    connectionLimit: target.connectionLimit,
    upstreamPort: target.port,
  });
  await gateway.listen();
  const refresh = setInterval(async () => {
    try {
      addresses = await resolveDatabaseGatewayAddresses(target.hostname);
      gateway.markResolved();
    } catch {
      // Retain the last bounded address set; health fails when it becomes stale.
    }
  }, RESOLUTION_INTERVAL_MILLISECONDS);
  refresh.unref();
  console.info("VASI database gateway ready.");
  const shutdown = async () => {
    clearInterval(refresh);
    await gateway.close();
    process.exit(0);
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    console.error("VASI database gateway failed.");
    process.exitCode = 1;
  });
}
