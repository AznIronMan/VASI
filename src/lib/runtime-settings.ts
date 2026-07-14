import settingDefinitions from "../../config/runtime-settings.json";

import { loadBootstrapSettings } from "@/lib/bootstrap-settings";
import { database } from "@/lib/database";
import { decryptRuntimeSetting } from "@/lib/settings-crypto";

type SettingDefinition = {
  default?: string;
  name: string;
  required: boolean;
  scope: string;
  secret: boolean;
};

export type RuntimeSettings = Record<string, string | undefined>;

type RuntimeSettingRow = {
  authTag: Buffer;
  ciphertext: Buffer;
  iv: Buffer;
  name: string;
  scope: string;
};

const definitions = (settingDefinitions as SettingDefinition[]).filter(
  (definition) => definition.scope === "gateway",
);
const knownNames = new Set(definitions.map((definition) => definition.name));

const globalForRuntimeSettings = globalThis as unknown as {
  vasiRuntimeSettings?: Promise<RuntimeSettings>;
};

export function resolveRuntimeSettingValues(rows: RuntimeSettingRow[], bootstrap: {
  installationId: string;
  settingsKey: Buffer;
}) {
  const values: RuntimeSettings = Object.fromEntries(
    definitions
      .filter((definition) => definition.default !== undefined)
      .map((definition) => [definition.name, definition.default]),
  );

  for (const row of rows) {
    if (!knownNames.has(row.name)) continue;
    values[row.name] = decryptRuntimeSetting(row, bootstrap.installationId, bootstrap.settingsKey);
  }

  const missing = definitions
    .filter((definition) => definition.required && !values[definition.name]?.trim())
    .map((definition) => definition.name);
  if (missing.length) {
    throw new Error(`Required VASI runtime settings are missing: ${missing.join(", ")}.`);
  }

  return values;
}

export function getRuntimeSettings() {
  globalForRuntimeSettings.vasiRuntimeSettings ??= loadRuntimeSettings();
  return globalForRuntimeSettings.vasiRuntimeSettings;
}

async function loadRuntimeSettings() {
  const bootstrap = loadBootstrapSettings();
  const result = await database.query<RuntimeSettingRow>(
    `select "name", "scope", "ciphertext", "iv", "authTag"
     from "vasi_runtime_setting"
     where "installationId" = $1 and "scope" = 'gateway'`,
    [bootstrap.installationId],
  );
  return resolveRuntimeSettingValues(result.rows, bootstrap);
}

export function resetRuntimeSettingsForTests() {
  globalForRuntimeSettings.vasiRuntimeSettings = undefined;
}
