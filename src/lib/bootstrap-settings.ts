import { chmodSync, statSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const BOOTSTRAP_SCHEMA_VERSION = 1;

export type BootstrapSettings = {
  databasePoolMax: number;
  databaseSSL: "disable" | "require";
  databaseURL: string;
  installationId: string;
  settingsKey: Buffer;
};

export function defaultBootstrapSettingsPath() {
  return path.resolve(process.cwd(), "data", "VASI.settings");
}

export function loadBootstrapSettings(
  settingsPath = defaultBootstrapSettingsPath(),
): BootstrapSettings {
  restrictSettingsPermissions(settingsPath);

  let sqlite: DatabaseSync;
  try {
    sqlite = new DatabaseSync(settingsPath, { readOnly: true });
  } catch {
    throw new Error(
      `VASI bootstrap settings are unavailable at ${settingsPath}. Run the settings initializer.`,
    );
  }

  try {
    const row = sqlite
      .prepare(`
        select
          "schemaVersion",
          "installationId",
          "databaseURL",
          "databaseSSL",
          "databasePoolMax",
          "settingsKey"
        from "vasi_bootstrap"
        where "id" = 1
      `)
      .get() as
      | {
          databasePoolMax: number;
          databaseSSL: string;
          databaseURL: string;
          installationId: string;
          schemaVersion: number;
          settingsKey: Uint8Array;
        }
      | undefined;

    if (!row) throw new Error("The VASI bootstrap record is missing.");
    if (row.schemaVersion !== BOOTSTRAP_SCHEMA_VERSION) {
      throw new Error(`Unsupported VASI bootstrap schema version ${row.schemaVersion}.`);
    }
    if (!/^[0-9a-f-]{36}$/i.test(row.installationId)) {
      throw new Error("The VASI installation identifier is invalid.");
    }
    if (!row.databaseURL.startsWith("postgresql://") && !row.databaseURL.startsWith("postgres://")) {
      throw new Error("The VASI PostgreSQL bootstrap URL is invalid.");
    }
    if (row.databaseSSL !== "disable" && row.databaseSSL !== "require") {
      throw new Error("The VASI PostgreSQL SSL mode is invalid.");
    }
    if (!Number.isInteger(row.databasePoolMax) || row.databasePoolMax < 1 || row.databasePoolMax > 100) {
      throw new Error("The VASI PostgreSQL pool size is invalid.");
    }

    const settingsKey = Buffer.from(row.settingsKey);
    if (settingsKey.length !== 32) {
      throw new Error("The VASI runtime-settings key is invalid.");
    }

    return {
      databasePoolMax: row.databasePoolMax,
      databaseSSL: row.databaseSSL,
      databaseURL: row.databaseURL,
      installationId: row.installationId,
      settingsKey,
    };
  } finally {
    sqlite.close();
  }
}

function restrictSettingsPermissions(settingsPath: string) {
  try {
    let mode = statSync(settingsPath).mode & 0o777;
    if (mode !== 0o600) {
      chmodSync(settingsPath, 0o600);
      mode = statSync(settingsPath).mode & 0o777;
    }
    if (mode !== 0o600) {
      throw new Error("The VASI bootstrap settings file must use mode 0600.");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
}
