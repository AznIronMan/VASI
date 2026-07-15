import { chmod, lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { runBackupCustodyCommand } from "./backup-custody.mjs";

const roots = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("backup custody CLI", () => {
  it("prints only the public recipient record and writes the private key at mode 0600", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "vasi-backup-custody-cli-"));
    roots.push(root);
    await chmod(root, 0o700);
    const privateKeyFile = path.join(root, "recipient.private.jwk");
    const output = [];
    vi.spyOn(console, "info").mockImplementation((value) => output.push(String(value)));
    const result = await runBackupCustodyCommand(["recipient", "opaque-1", privateKeyFile]);
    const printed = output.join("\n");
    const privateJwk = JSON.parse(await readFile(privateKeyFile, "utf8"));
    expect(result).toEqual({ keyId: "opaque-1", publicJwk: { crv: "X25519", kty: "OKP", x: privateJwk.x } });
    expect(privateJwk.d).toBeTypeOf("string");
    expect(printed).not.toContain(privateJwk.d);
    expect(printed).not.toContain(privateKeyFile);
    expect((await lstat(privateKeyFile)).mode & 0o777).toBe(0o600);
  });

  it("rejects unknown and repeated options before doing custody work", async () => {
    await expect(runBackupCustodyCommand(["check", "/not-used", "--unknown", "1"]))
      .rejects.toThrow("Unknown backup custody option");
    await expect(runBackupCustodyCommand([
      "check", "/not-used", "--maximum-age-hours", "26", "--maximum-age-hours", "27",
    ])).rejects.toThrow("was repeated");
  });
});
