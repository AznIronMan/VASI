import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import process from "node:process";
import { createInterface } from "node:readline/promises";

import { runMigrations } from "./migrations.mjs";
import {
  createBootstrapSettings,
  defaultSettingsPath,
  listRuntimeSettings,
  loadBootstrapSettings,
  parseEnvironmentFile,
  parseEnvironmentText,
  runtimeSettingNames,
  settingDefinition,
  unsetRuntimeSetting,
  writeRuntimeSettings,
} from "./settings-core.mjs";

const [command, ...args] = process.argv.slice(2);

try {
  switch (command) {
    case "init":
      await initializeInteractively();
      break;
    case "import-env":
      await importLegacyEnvironment(args[0]);
      break;
    case "set":
      await setOne(args[0]);
      break;
    case "unset":
      await unsetOne(args[0]);
      break;
    case "list":
      await listConfigured();
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
  const allowed = new Set(runtimeSettingNames());
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

async function setOne(name) {
  const definition = settingDefinition(name);
  if (!definition) throw new Error(`Unknown VASI runtime setting ${name || "(missing)"}.`);
  requireTTY();
  const value = definition.secret
    ? await hiddenQuestion(`${name}: `)
    : await visibleQuestion(`${name}: `);
  if (!value && definition.required) throw new Error(`${name} cannot be empty.`);
  if (!value) return unsetOne(name);
  await writeRuntimeSettings({ source: "interactive-set", values: { [name]: value } });
  console.info(`${name} was updated. Its value was not printed.`);
}

async function unsetOne(name) {
  if (!name) throw new Error("Provide the runtime setting name to remove.");
  await unsetRuntimeSetting(name, "interactive-unset");
  console.info(`${name} was removed.`);
}

async function listConfigured() {
  const rows = await listRuntimeSettings();
  for (const row of rows) {
    console.info(`${row.name}\tconfigured\tversion=${row.version}\tsecret=${row.isSecret}`);
  }
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
  node scripts/settings.mjs init
  docker inspect CONTAINER --format '{{range .Config.Env}}{{println .}}{{end}}' | node scripts/settings.mjs import-env -
  node scripts/settings.mjs import-env /secure/path/to/legacy.env
  node scripts/settings.mjs set SETTING_NAME
  node scripts/settings.mjs unset SETTING_NAME
  node scripts/settings.mjs list`);
}
