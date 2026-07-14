import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { describe, expect, it } from "vitest";

const sourcePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "engine-migrations.mjs",
);

describe("engine migration ledger", () => {
  it("remains anchored to public after the engine user schema exists", async () => {
    const source = await readFile(sourcePath, "utf8");

    expect(source).toContain("set search_path to public, pg_catalog");
    expect(source.match(/public\.\"_vasi_engine_migrations\"/g)).toHaveLength(3);
  });
});
