import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import process from "node:process";
import { createInterface } from "node:readline/promises";

import { runMigrations } from "./migrations.mjs";
import { runEngineMigrations } from "./engine-migrations.mjs";
import {
  createBootstrapSettings,
  defaultSettingsPath,
  listRuntimeSettings,
  loadBootstrapSettings,
  parseEnvironmentFile,
  parseEnvironmentText,
  runtimeSettingNames,
  runtimeSettingScopes,
  settingDefinition,
  unsetRuntimeSetting,
  writeRuntimeSettings,
} from "./settings-core.mjs";

try {
  const { args, command, scope } = parseArguments(process.argv.slice(2));
  switch (command) {
    case "init":
      if (scope === "engine") {
        await initializeEngineInteractively();
      } else {
        await initializeInteractively();
      }
      break;
    case "bootstrap":
      await bootstrapFromJSON(args[0], scope);
      break;
    case "import-json":
      await importRuntimeJSON(args[0], scope);
      break;
    case "import-env":
      if (scope !== "gateway") throw new Error("Legacy environment import is gateway-only.");
      await importLegacyEnvironment(args[0]);
      break;
    case "set":
      await setOne(args[0], scope);
      break;
    case "unset":
      await unsetOne(args[0], scope);
      break;
    case "list":
      await listConfigured(scope);
      break;
    default:
      printUsage();
      process.exitCode = command ? 1 : 0;
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : "VASI settings operation failed.");
  process.exitCode = 1;
}

async function initializeInteractively() {
  requireTTY();
  const host = (await visibleQuestion("PostgreSQL host [127.0.0.1]: ")) || "127.0.0.1";
  const port = (await visibleQuestion("PostgreSQL port [5432]: ")) || "5432";
  const database = (await visibleQuestion("PostgreSQL database [vasi]: ")) || "vasi";
  const username = (await visibleQuestion("PostgreSQL username [vasi]: ")) || "vasi";
  const password = await hiddenQuestion("PostgreSQL password: ");
  const sslAnswer = await visibleQuestion("Require verified PostgreSQL TLS? [y/N]: ");
  const poolAnswer = await visibleQuestion("PostgreSQL pool maximum [10]: ");
  const baseURL = (await visibleQuestion("Public VASI origin [http://localhost:3000]: ")) || "http://localhost:3000";
  const adminOrigin = (await visibleQuestion("Private admin origin [http://localhost:3000]: ")) || "http://localhost:3000";
  const adminEmails = await visibleQuestion("Administrator email allowlist: ");
  if (!password) throw new Error("PostgreSQL password is required.");
  if (!adminEmails) throw new Error("At least one administrator email is required.");

  const databaseURL = new URL(`postgresql://${host}:${port}/${database}`);
  databaseURL.username = username;
  databaseURL.password = password;
  const bootstrap = createBootstrapSettings({
    databasePoolMax: Number(poolAnswer || "10"),
    databaseSSL: /^y(?:es)?$/i.test(sslAnswer) ? "require" : "disable",
    databaseURL: databaseURL.toString(),
  });
  await runMigrations(bootstrap);
  await writeRuntimeSettings({
    bootstrap,
    includeDefaults: true,
    source: "interactive-init",
    values: {
      BETTER_AUTH_SECRET: randomBytes(48).toString("base64url"),
      BETTER_AUTH_URL: baseURL,
      VASI_ADMIN_EMAILS: adminEmails,
      VASI_ADMIN_ORIGIN: adminOrigin,
    },
  });
  console.info("VASI settings initialized. No secret values were printed.");
}

async function initializeEngineInteractively() {
  requireTTY();
  const bootstrap = await promptForBootstrap();
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  await runEngineMigrations(bootstrap);
  await writeRuntimeSettings({
    bootstrap,
    includeDefaults: true,
    scope: "engine",
    source: "interactive-engine-init",
    values: {
      EVIDENCE_SEAL_KEY_ID: `vasi-seal-${randomUUID()}`,
      EVIDENCE_SEAL_PRIVATE_JWK: JSON.stringify(privateKey.export({ format: "jwk" })),
      EVIDENCE_SEAL_PUBLIC_JWK: JSON.stringify(publicKey.export({ format: "jwk" })),
      ENGINE_INTERNAL_HMAC_SECRET: randomBytes(48).toString("base64url"),
      ENGINE_INTEGRATION_CONFIG_ENCRYPTION_SECRET: randomBytes(32).toString("base64url"),
      ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET: randomBytes(48).toString("base64url"),
      ENGINE_OUTBOX_ENCRYPTION_SECRET: randomBytes(32).toString("base64url"),
    },
  });
  console.info("VASI engine bootstrap initialized. Complete the required trust settings before startup.");
}

async function promptForBootstrap() {
  const host = (await visibleQuestion("PostgreSQL host [127.0.0.1]: ")) || "127.0.0.1";
  const port = (await visibleQuestion("PostgreSQL port [5432]: ")) || "5432";
  const database = (await visibleQuestion("PostgreSQL database [vasi_engine]: ")) || "vasi_engine";
  const username = (await visibleQuestion("PostgreSQL username [vasi_engine]: ")) || "vasi_engine";
  const password = await hiddenQuestion("PostgreSQL password: ");
  const sslAnswer = await visibleQuestion("Require verified PostgreSQL TLS? [y/N]: ");
  const poolAnswer = await visibleQuestion("PostgreSQL pool maximum [10]: ");
  if (!password) throw new Error("PostgreSQL password is required.");

  const databaseURL = new URL(`postgresql://${host}:${port}/${database}`);
  databaseURL.username = username;
  databaseURL.password = password;
  return createBootstrapSettings({
    databasePoolMax: Number(poolAnswer || "10"),
    databaseSSL: /^y(?:es)?$/i.test(sslAnswer) ? "require" : "disable",
    databaseURL: databaseURL.toString(),
  });
}

async function bootstrapFromJSON(source, selectedScope) {
  if (source !== "-") throw new Error("Bootstrap JSON must be streamed on standard input.");
  const payload = parseJSONObject(await readStandardInput());
  const bootstrap = createBootstrapSettings({
    databasePoolMax: Number(payload.databasePoolMax || 10),
    databaseSSL: payload.databaseSSL || "disable",
    databaseURL: payload.databaseURL,
  });
  if (selectedScope === "engine") {
    await runEngineMigrations(bootstrap);
  } else {
    await runMigrations(bootstrap);
  }
  console.info(`VASI ${selectedScope} bootstrap initialized. No values were printed.`);
}

async function importRuntimeJSON(source, selectedScope) {
  if (source !== "-") throw new Error("Runtime settings JSON must be streamed on standard input.");
  const values = parseJSONObject(await readStandardInput());
  await writeRuntimeSettings({
    includeDefaults: true,
    scope: selectedScope,
    source: "json-stdin-import",
    values,
  });
  console.info(`Imported ${Object.keys(values).length} ${selectedScope} setting(s). No values were printed.`);
}

async function importLegacyEnvironment(filePath) {
  if (!filePath) throw new Error("Provide the path to the legacy environment file.");
  const values = filePath === "-"
    ? parseEnvironmentText(await readStandardInput())
    : parseEnvironmentFile(filePath);
  let bootstrap;
  if (existsSync(defaultSettingsPath())) {
    bootstrap = loadBootstrapSettings();
  } else {
    if (!values.DATABASE_URL) throw new Error("The legacy file does not contain DATABASE_URL.");
    bootstrap = createBootstrapSettings({
      databasePoolMax: Number(values.DATABASE_POOL_MAX || "10"),
      databaseSSL: values.DATABASE_SSL || "disable",
      databaseURL: values.DATABASE_URL,
    });
  }
  await runMigrations(bootstrap);
  const allowed = new Set(runtimeSettingNames("gateway"));
  const runtimeValues = Object.fromEntries(
    Object.entries(values).filter(([name]) => allowed.has(name)),
  );
  await writeRuntimeSettings({
    bootstrap,
    includeDefaults: true,
    source: "legacy-environment-import",
    values: runtimeValues,
  });
  console.info(`Imported ${Object.keys(runtimeValues).length} known runtime setting(s). No values were printed.`);
}

async function setOne(name, selectedScope) {
  const definition = settingDefinition(name, selectedScope);
  if (!definition) throw new Error(`Unknown VASI runtime setting ${name || "(missing)"}.`);
  requireTTY();
  const value = definition.secret
    ? await hiddenQuestion(`${name}: `)
    : await visibleQuestion(`${name}: `);
  if (!value && definition.required) throw new Error(`${name} cannot be empty.`);
  if (!value) return unsetOne(name, selectedScope);
  await writeRuntimeSettings({
    scope: selectedScope,
    source: "interactive-set",
    values: { [name]: value },
  });
  console.info(`${name} was updated. Its value was not printed.`);
}

async function unsetOne(name, selectedScope) {
  if (!name) throw new Error("Provide the runtime setting name to remove.");
  await unsetRuntimeSetting(name, "interactive-unset", selectedScope);
  console.info(`${name} was removed.`);
}

async function listConfigured(selectedScope) {
  const rows = await listRuntimeSettings(selectedScope);
  for (const row of rows) {
    console.info(`${row.name}\tconfigured\tversion=${row.version}\tsecret=${row.isSecret}`);
  }
}

function parseJSONObject(contents) {
  let value;
  try {
    value = JSON.parse(contents);
  } catch {
    throw new Error("Input must be a valid JSON object.");
  }
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error("Input must be a valid JSON object.");
  }
  for (const [name, settingValue] of Object.entries(value)) {
    if (typeof settingValue !== "string" && typeof settingValue !== "number") {
      throw new Error(`JSON setting ${name} must be a string or number.`);
    }
  }
  return value;
}

function parseArguments(rawArguments) {
  const args = [...rawArguments];
  const scopeIndex = args.indexOf("--scope");
  let selectedScope = "gateway";
  if (scopeIndex >= 0) {
    selectedScope = args[scopeIndex + 1];
    args.splice(scopeIndex, 2);
  }
  if (!runtimeSettingScopes().includes(selectedScope)) {
    throw new Error(`Unknown VASI runtime setting scope ${selectedScope || "(missing)"}.`);
  }
  const [selectedCommand, ...commandArguments] = args;
  return { args: commandArguments, command: selectedCommand, scope: selectedScope };
}

async function readStandardInput() {
  process.stdin.setEncoding("utf8");
  let contents = "";
  for await (const chunk of process.stdin) contents += chunk;
  return contents;
}

async function visibleQuestion(prompt) {
  const answers = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await answers.question(prompt)).trim();
  } finally {
    answers.close();
  }
}

async function hiddenQuestion(prompt) {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) {
    throw new Error("A terminal is required for hidden secret input.");
  }
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");

  return new Promise((resolve, reject) => {
    let value = "";
    const finish = () => {
      process.stdin.off("data", onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write("\n");
    };
    const onData = (character) => {
      if (character === "\u0003") {
        finish();
        reject(new Error("Input cancelled."));
      } else if (character === "\r" || character === "\n") {
        finish();
        resolve(value);
      } else if (character === "\u007f" || character === "\b") {
        value = value.slice(0, -1);
      } else if (character >= " ") {
        value += character;
      }
    };
    process.stdin.on("data", onData);
  });
}

function requireTTY() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("This settings operation requires an interactive terminal.");
  }
}

function printUsage() {
  console.info(`VASI settings commands:
  node scripts/settings.mjs [--scope gateway|engine] init
  node scripts/settings.mjs --scope engine bootstrap -
  node scripts/settings.mjs [--scope gateway|engine] import-json -
  docker inspect CONTAINER --format '{{range .Config.Env}}{{println .}}{{end}}' | node scripts/settings.mjs import-env -
  node scripts/settings.mjs import-env /secure/path/to/legacy.env
  node scripts/settings.mjs [--scope gateway|engine] set SETTING_NAME
  node scripts/settings.mjs [--scope gateway|engine] unset SETTING_NAME
  node scripts/settings.mjs [--scope gateway|engine] list`);
}
