import { mkdirSync, mkdtempSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { rmSync } from "node:fs";

import { loadBootstrapSettings } from "@/lib/bootstrap-settings";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("VASI bootstrap settings", () => {
  it("loads a valid SQLite bootstrap record and restricts its permissions", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "vasi-settings-"));
    temporaryDirectories.push(directory);
    mkdirSync(path.join(directory, "data"));
    const settingsPath = path.join(directory, "data", "VASI.settings");
    const sqlite = new DatabaseSync(settingsPath);
    sqlite.exec(`
      create table "vasi_bootstrap" (
        "id" integer primary key,
        "schemaVersion" integer not null,
        "installationId" text not null,
        "databaseURL" text not null,
        "databaseSSL" text not null,
        "databasePoolMax" integer not null,
        "settingsKey" blob not null
      )
    `);
    sqlite.prepare(`
      insert into "vasi_bootstrap"
        ("id", "schemaVersion", "installationId", "databaseURL", "databaseSSL", "databasePoolMax", "settingsKey")
      values (1, 1, ?, ?, 'require', 12, ?)
    `).run(
      "4af8f8bf-3109-45c6-91fa-273257a321d8",
      "postgresql://vasi:secret@database.example/vasi",
      Buffer.alloc(32, 7),
    );
    sqlite.close();

    const settings = loadBootstrapSettings(settingsPath);

    expect(settings.databaseSSL).toBe("require");
    expect(settings.databasePoolMax).toBe(12);
    expect(settings.settingsKey).toEqual(Buffer.alloc(32, 7));
    expect(statSync(settingsPath).mode & 0o777).toBe(0o600);
  });

  it("rejects missing bootstrap settings without creating a file", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "vasi-settings-"));
    temporaryDirectories.push(directory);
    const settingsPath = path.join(directory, "VASI.settings");

    expect(() => loadBootstrapSettings(settingsPath)).toThrow(
      "VASI bootstrap settings are unavailable",
    );
  });
});
