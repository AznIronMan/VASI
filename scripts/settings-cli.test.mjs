import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const script = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "settings.mjs");

describe("settings CLI", () => {
  it("reads a legacy import from standard input", () => {
    const workingDirectory = mkdtempSync(path.join(tmpdir(), "vasi-settings-cli-"));
    try {
      const result = spawnSync(process.execPath, [script, "import-env", "-"], {
        cwd: workingDirectory,
        encoding: "utf8",
        input: "BETTER_AUTH_URL=https://vsign.example.test\n",
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("does not contain DATABASE_URL");
      expect(result.stderr).not.toContain("path");
    } finally {
      rmSync(workingDirectory, { force: true, recursive: true });
    }
  });
});
