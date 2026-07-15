import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("gateway migration ledger", () => {
  it("includes command-bound invitation delivery state after session provenance", async () => {
    const ledger = await readFile(path.join(root, "scripts", "migrations.mjs"), "utf8");
    const migration = await readFile(
      path.join(root, "database", "invitation-provision-command.sql"),
      "utf8",
    );

    expect(ledger).toContain("0005_invitation_provision_command");
    expect(migration).toContain('"sourceCommandId" uuid');
    expect(migration).toContain('"deliveryStatus" text not null');
    expect(migration).toContain("provider_accepted");
    expect(migration).toContain("vasi_invitation_source_command_idx");
    expect(migration).toContain("VASI invitation command bindings are immutable");
    expect(migration).toContain("VASI command-bound invitation identity is immutable");
    expect(migration).toContain("VASI invitation delivery state transitions are invalid");
  });
});
