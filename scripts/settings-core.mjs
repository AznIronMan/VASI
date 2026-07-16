import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import {
  chownSync,
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { Socket } from "node:net";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import pg from "pg";

import settingDefinitions from "../config/runtime-settings.json" with { type: "json" };
import {
  getAuthProviderReadiness,
  validateAuthProviderConfiguration,
} from "../packages/auth-provider-readiness/index.mjs";

const { Pool } = pg;
const BOOTSTRAP_SCHEMA_VERSION = 1;
const DEFAULT_SETTINGS_SCOPE = "gateway";
const DATABASE_GATEWAY_TRANSPORT_PATH = "/run/vasi/database-gateway.json";

export function defaultSettingsPath() {
  return path.resolve(process.cwd(), "data", "VASI.settings");
}

export function createBootstrapSettings({
  databasePoolMax,
  databaseSSL,
  databaseURL,
  settingsPath = defaultSettingsPath(),
}) {
  if (existsSync(settingsPath)) {
    throw new Error(`VASI bootstrap settings already exist at ${settingsPath}.`);
  }

  validateDatabaseSettings({ databasePoolMax, databaseSSL, databaseURL });
  const directory = path.dirname(settingsPath);
  mkdirSync(directory, { mode: 0o700, recursive: true });
  if (process.getuid?.() === 0) {
    chownSync(directory, 1000, 1000);
  }
  chmodSync(directory, 0o700);

  const installationId = randomUUID();
  const settingsKey = randomBytes(32);
  const sqlite = new DatabaseSync(settingsPath);
  try {
    sqlite.exec(`
      pragma journal_mode = delete;
      pragma synchronous = full;
      create table "vasi_bootstrap" (
        "id" integer primary key check ("id" = 1),
        "schemaVersion" integer not null,
        "installationId" text not null,
        "databaseURL" text not null,
        "databaseSSL" text not null check ("databaseSSL" in ('disable', 'require')),
        "databasePoolMax" integer not null check ("databasePoolMax" between 1 and 100),
        "settingsKey" blob not null check (length("settingsKey") = 32),
        "createdAt" text not null
      )
    `);
    sqlite.prepare(`
      insert into "vasi_bootstrap"
        ("id", "schemaVersion", "installationId", "databaseURL", "databaseSSL", "databasePoolMax", "settingsKey", "createdAt")
      values (1, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      BOOTSTRAP_SCHEMA_VERSION,
      installationId,
      databaseURL,
      databaseSSL,
      databasePoolMax,
      settingsKey,
      new Date().toISOString(),
    );
  } finally {
    sqlite.close();
    if (process.getuid?.() === 0) {
      chownSync(settingsPath, 1000, 1000);
    }
    chmodSync(settingsPath, 0o600);
  }

  return loadBootstrapSettings(settingsPath);
}

export function loadBootstrapSettings(settingsPath = defaultSettingsPath()) {
  if (!existsSync(settingsPath)) {
    throw new Error(`VASI bootstrap settings are unavailable at ${settingsPath}.`);
  }
  if ((statSync(settingsPath).mode & 0o777) !== 0o600) {
    chmodSync(settingsPath, 0o600);
  }
  if ((statSync(settingsPath).mode & 0o777) !== 0o600) {
    throw new Error("The VASI bootstrap settings file must use mode 0600.");
  }

  const sqlite = new DatabaseSync(settingsPath, { readOnly: true });
  try {
    const row = sqlite.prepare(`
      select "schemaVersion", "installationId", "databaseURL", "databaseSSL",
             "databasePoolMax", "settingsKey"
      from "vasi_bootstrap" where "id" = 1
    `).get();
    if (!row) throw new Error("The VASI bootstrap record is missing.");
    if (row.schemaVersion !== BOOTSTRAP_SCHEMA_VERSION) {
      throw new Error(`Unsupported VASI bootstrap schema version ${row.schemaVersion}.`);
    }

    const settings = {
      databasePoolMax: Number(row.databasePoolMax),
      databaseSSL: String(row.databaseSSL),
      databaseURL: String(row.databaseURL),
      installationId: String(row.installationId),
      settingsKey: Buffer.from(row.settingsKey),
    };
    validateDatabaseSettings(settings);
    if (settings.settingsKey.length !== 32) {
      throw new Error("The VASI runtime-settings key is invalid.");
    }
    return settings;
  } finally {
    sqlite.close();
  }
}

export function rebindBootstrapSettings({
  databasePoolMax,
  databaseSSL,
  databaseURL,
  settingsPath = defaultSettingsPath(),
}) {
  const current = loadBootstrapSettings(settingsPath);
  const replacement = {
    databasePoolMax: Number(databasePoolMax),
    databaseSSL,
    databaseURL,
  };
  validateDatabaseSettings(replacement);
  const metadata = statSync(settingsPath);
  const temporary = `${settingsPath}.rebind-${randomUUID()}`;
  try {
    copyFileSync(settingsPath, temporary, constants.COPYFILE_EXCL);
    chmodSync(temporary, 0o600);
    const sqlite = new DatabaseSync(temporary);
    try {
      sqlite.exec("begin immediate");
      const updated = sqlite.prepare(`
        update "vasi_bootstrap"
        set "databaseURL" = ?, "databaseSSL" = ?, "databasePoolMax" = ?
        where "id" = 1 and "installationId" = ?
      `).run(
        replacement.databaseURL,
        replacement.databaseSSL,
        replacement.databasePoolMax,
        current.installationId,
      );
      if (Number(updated.changes) !== 1) throw new Error("The VASI bootstrap recovery record could not be updated.");
      sqlite.exec("commit");
    } catch (error) {
      try {
        sqlite.exec("rollback");
      } catch {
        // Preserve the original update failure when no transaction was opened.
      }
      throw error;
    } finally {
      sqlite.close();
    }
    if (process.getuid?.() === 0) chownSync(temporary, metadata.uid, metadata.gid);
    const fileDescriptor = openSync(temporary, "r");
    try {
      fsyncSync(fileDescriptor);
    } finally {
      closeSync(fileDescriptor);
    }
    renameSync(temporary, settingsPath);
    const directoryDescriptor = openSync(path.dirname(settingsPath), "r");
    try {
      fsyncSync(directoryDescriptor);
    } finally {
      closeSync(directoryDescriptor);
    }
    return loadBootstrapSettings(settingsPath);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

export async function validateBootstrapBinding({ bootstrap, scope }) {
  const runtimeSettings = await readRuntimeSettings({ bootstrap, scope });
  if (scope === "gateway") {
    validateAuthProviderConfiguration(runtimeSettings);
    getAuthProviderReadiness(runtimeSettings, {
      adminOrigin: runtimeSettings.VASI_ADMIN_ORIGIN,
      publicOrigin: runtimeSettings.BETTER_AUTH_URL,
    });
  }
  const pool = createSettingsPool(bootstrap);
  try {
    const result = await pool.query(
      `select count(*)::integer as "count"
       from "vasi_runtime_setting"
       where "installationId" = $1 and "scope" = $2`,
      [bootstrap.installationId, scope],
    );
    if (!Number(result.rows[0]?.count)) {
      throw new Error(`The restored database has no VASI ${scope} settings for this installation.`);
    }
  } finally {
    await pool.end();
  }
}

export async function recordBootstrapRebind({ bootstrap, scope }) {
  const pool = createSettingsPool(bootstrap);
  try {
    await pool.query(
      `insert into "vasi_runtime_setting_audit"
        ("id", "installationId", "scope", "name", "action", "version", "source")
       values ($1, $2, $3, '__bootstrap_database_endpoint__', 'rebind', null, 'recovery-rebind')`,
      [randomUUID(), bootstrap.installationId, scope],
    );
  } finally {
    await pool.end();
  }
}

export function createSettingsPool(bootstrap = loadBootstrapSettings(), options = {}) {
  return new Pool(databaseConnectionOptions(bootstrap, options));
}

export function databaseConnectionOptions(
  bootstrap,
  { transportPath = DATABASE_GATEWAY_TRANSPORT_PATH } = {},
) {
  validateDatabaseSettings(bootstrap);
  const databaseURL = new URL(bootstrap.databaseURL);
  databaseURL.searchParams.set(
    "sslmode",
    bootstrap.databaseSSL === "require" ? "verify-full" : "disable",
  );
  const transport = loadDatabaseGatewayTransport(transportPath);
  return {
    connectionString: databaseURL.toString(),
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
    max: bootstrap.databasePoolMax,
    ssl: bootstrap.databaseSSL === "require" ? { rejectUnauthorized: true } : false,
    ...(transport ? { stream: () => databaseGatewaySocket(transport) } : {}),
  };
}

export function loadDatabaseGatewayTransport(filename = DATABASE_GATEWAY_TRANSPORT_PATH) {
  if (!existsSync(filename)) return null;
  const metadata = statSync(filename);
  if (!metadata.isFile() || metadata.size < 2 || metadata.size > 1_024) {
    throw new Error("The VASI database-gateway transport marker is invalid.");
  }
  let value;
  try {
    value = JSON.parse(readFileSync(filename, "utf8"));
  } catch {
    throw new Error("The VASI database-gateway transport marker is invalid.");
  }
  if (
    !value || Array.isArray(value) || typeof value !== "object" ||
    Object.keys(value).sort().join(",") !== "host,port,schema" ||
    value.schema !== "vasi-database-gateway-transport/v1" ||
    value.host !== "database-gateway" || value.port !== 5432
  ) throw new Error("The VASI database-gateway transport marker is invalid.");
  return Object.freeze({ host: value.host, port: value.port });
}

function databaseGatewaySocket(transport) {
  const socket = new Socket();
  socket.connect = () => Socket.prototype.connect.call(socket, transport.port, transport.host);
  return socket;
}

export async function writeRuntimeSettings({
  bootstrap = loadBootstrapSettings(),
  includeDefaults = false,
  scope = DEFAULT_SETTINGS_SCOPE,
  source,
  values,
}) {
  const pool = createSettingsPool(bootstrap);
  const definitions = new Map(
    definitionsForScope(scope).map((definition) => [definition.name, definition]),
  );
  const configuredValues = { ...values };
  if (includeDefaults) {
    for (const definition of definitions.values()) {
      if (configuredValues[definition.name] === undefined && definition.default !== undefined) {
        configuredValues[definition.name] = definition.default;
      }
    }
  }

  const unknown = Object.keys(configuredValues).filter((name) => !definitions.has(name));
  if (unknown.length) throw new Error(`Unknown VASI runtime settings: ${unknown.join(", ")}.`);

  const client = await pool.connect();
  try {
    await client.query("begin");
    for (const [name, rawValue] of Object.entries(configuredValues)) {
      if (rawValue === undefined || rawValue === "") continue;
      const definition = definitions.get(name);
      const value = String(rawValue);
      const encrypted = encryptRuntimeSetting({
        installationId: bootstrap.installationId,
        name,
        scope,
        settingsKey: bootstrap.settingsKey,
        value,
      });
      const result = await client.query(
        `insert into "vasi_runtime_setting"
          ("installationId", "scope", "name", "ciphertext", "iv", "authTag", "isSecret")
         values ($1, $2, $3, $4, $5, $6, $7)
         on conflict ("installationId", "scope", "name") do update set
           "ciphertext" = excluded."ciphertext",
           "iv" = excluded."iv",
           "authTag" = excluded."authTag",
           "isSecret" = excluded."isSecret",
           "version" = "vasi_runtime_setting"."version" + 1,
           "updatedAt" = CURRENT_TIMESTAMP
         returning "version"`,
        [
          bootstrap.installationId,
          scope,
          name,
          encrypted.ciphertext,
          encrypted.iv,
          encrypted.authTag,
          definition.secret,
        ],
      );
      await client.query(
        `insert into "vasi_runtime_setting_audit"
          ("id", "installationId", "scope", "name", "action", "version", "source")
         values ($1, $2, $3, $4, 'set', $5, $6)`,
        [
          randomUUID(),
          bootstrap.installationId,
          scope,
          name,
          result.rows[0].version,
          source,
        ],
      );
    }
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

export async function unsetRuntimeSetting(name, source, scope = DEFAULT_SETTINGS_SCOPE) {
  const definition = settingDefinition(name, scope);
  if (!definition) throw new Error(`Unknown VASI runtime setting ${name}.`);
  if (definition.required) throw new Error(`Required VASI runtime setting ${name} cannot be removed.`);

  const bootstrap = loadBootstrapSettings();
  const pool = createSettingsPool(bootstrap);
  const client = await pool.connect();
  try {
    await client.query("begin");
    const result = await client.query(
      `delete from "vasi_runtime_setting"
       where "installationId" = $1 and "scope" = $2 and "name" = $3
       returning "version"`,
      [bootstrap.installationId, scope, name],
    );
    if (result.rowCount) {
      await client.query(
        `insert into "vasi_runtime_setting_audit"
          ("id", "installationId", "scope", "name", "action", "version", "source")
         values ($1, $2, $3, $4, 'unset', $5, $6)`,
        [
          randomUUID(),
          bootstrap.installationId,
          scope,
          name,
          result.rows[0].version,
          source,
        ],
      );
    }
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

export async function listRuntimeSettings(scope = DEFAULT_SETTINGS_SCOPE) {
  const bootstrap = loadBootstrapSettings();
  const pool = createSettingsPool(bootstrap);
  try {
    const result = await pool.query(
      `select "name", "isSecret", "version", "updatedAt"
       from "vasi_runtime_setting"
       where "installationId" = $1 and "scope" = $2
       order by "name"`,
      [bootstrap.installationId, scope],
    );
    return result.rows;
  } finally {
    await pool.end();
  }
}

export async function readRuntimeSettings({
  bootstrap = loadBootstrapSettings(),
  scope = DEFAULT_SETTINGS_SCOPE,
} = {}) {
  const definitions = definitionsForScope(scope);
  const known = new Map(definitions.map((definition) => [definition.name, definition]));
  const values = Object.fromEntries(
    definitions
      .filter((definition) => definition.default !== undefined)
      .map((definition) => [definition.name, definition.default]),
  );
  const pool = createSettingsPool(bootstrap);
  try {
    const result = await pool.query(
      `select "name", "scope", "ciphertext", "iv", "authTag"
       from "vasi_runtime_setting"
       where "installationId" = $1 and "scope" = $2`,
      [bootstrap.installationId, scope],
    );
    for (const row of result.rows) {
      if (!known.has(row.name)) continue;
      values[row.name] = decryptRuntimeSetting({
        authTag: row.authTag,
        ciphertext: row.ciphertext,
        installationId: bootstrap.installationId,
        iv: row.iv,
        name: row.name,
        scope,
        settingsKey: bootstrap.settingsKey,
      });
    }
  } finally {
    await pool.end();
  }

  const missing = definitions
    .filter((definition) => definition.required && !String(values[definition.name] || "").trim())
    .map((definition) => definition.name);
  if (missing.length) {
    throw new Error(`Required VASI ${scope} settings are missing: ${missing.join(", ")}.`);
  }
  return values;
}

export async function readRuntimeSetting({
  bootstrap = loadBootstrapSettings(),
  name,
  scope = DEFAULT_SETTINGS_SCOPE,
} = {}) {
  const definition = settingDefinition(name, scope);
  if (!definition) throw new Error(`Unknown VASI runtime setting ${name || "(missing)"}.`);
  const pool = createSettingsPool(bootstrap);
  try {
    const result = await pool.query(
      `select "name", "scope", "ciphertext", "iv", "authTag"
       from "vasi_runtime_setting"
       where "installationId" = $1 and "scope" = $2 and "name" = $3`,
      [bootstrap.installationId, scope, name],
    );
    const row = result.rows[0];
    if (!row) return definition.default;
    return decryptRuntimeSetting({
      authTag: row.authTag,
      ciphertext: row.ciphertext,
      installationId: bootstrap.installationId,
      iv: row.iv,
      name,
      scope,
      settingsKey: bootstrap.settingsKey,
    });
  } finally {
    await pool.end();
  }
}

export function parseEnvironmentFile(filePath) {
  return parseEnvironmentText(readFileSync(filePath, "utf8"));
}

export function parseEnvironmentText(contents) {
  const values = {};
  for (const [index, sourceLine] of contents.split(/\r?\n/).entries()) {
    const line = sourceLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) throw new Error(`Invalid environment-file syntax on line ${index + 1}.`);
    const [, name, sourceValue] = match;
    values[name] = parseEnvironmentValue(sourceValue);
  }
  return values;
}

export function settingDefinition(name, scope = DEFAULT_SETTINGS_SCOPE) {
  return definitionsForScope(scope).find((definition) => definition.name === name);
}

export function runtimeSettingNames(scope = DEFAULT_SETTINGS_SCOPE) {
  return definitionsForScope(scope).map((definition) => definition.name);
}

export function runtimeSettingScopes() {
  return [...new Set(settingDefinitions.map((definition) => definition.scope))];
}

function parseEnvironmentValue(sourceValue) {
  if (sourceValue.startsWith('"')) {
    try {
      return JSON.parse(sourceValue);
    } catch {
      throw new Error("Invalid double-quoted environment value.");
    }
  }
  if (sourceValue.startsWith("'")) {
    if (!sourceValue.endsWith("'")) throw new Error("Invalid single-quoted environment value.");
    return sourceValue.slice(1, -1);
  }
  return sourceValue.replace(/\s+#.*$/, "").trim();
}

function encryptRuntimeSetting({ installationId, name, scope, settingsKey, value }) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", settingsKey, iv);
  cipher.setAAD(runtimeSettingAAD({ installationId, name, scope }));
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return { authTag: cipher.getAuthTag(), ciphertext, iv };
}

function decryptRuntimeSetting({
  authTag,
  ciphertext,
  installationId,
  iv,
  name,
  scope,
  settingsKey,
}) {
  try {
    const decipher = createDecipheriv("aes-256-gcm", settingsKey, iv);
    decipher.setAAD(runtimeSettingAAD({ installationId, name, scope }));
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    throw new Error(`Runtime setting ${name} could not be authenticated.`);
  }
}

function runtimeSettingAAD({ installationId, name, scope }) {
  return Buffer.from(
    ["vasi-runtime-setting-v1", installationId, scope, name].join("\0"),
    "utf8",
  );
}

function validateDatabaseSettings({ databasePoolMax, databaseSSL, databaseURL }) {
  if (!String(databaseURL).startsWith("postgresql://") && !String(databaseURL).startsWith("postgres://")) {
    throw new Error("The VASI PostgreSQL bootstrap URL is invalid.");
  }
  if (!['disable', 'require'].includes(databaseSSL)) {
    throw new Error("The VASI PostgreSQL SSL mode is invalid.");
  }
  if (!Number.isInteger(Number(databasePoolMax)) || Number(databasePoolMax) < 1 || Number(databasePoolMax) > 100) {
    throw new Error("The VASI PostgreSQL pool size must be between 1 and 100.");
  }
}

function definitionsForScope(scope) {
  const definitions = settingDefinitions.filter((definition) => definition.scope === scope);
  if (!definitions.length) throw new Error(`Unknown VASI runtime setting scope ${scope}.`);
  return definitions;
}
