import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { BACKUP_SCHEMA } from "../../scripts/backup.mjs";
import {
  BackupCustodyError,
  CUSTODY_READINESS_SCHEMA,
  authenticateCustodyPackage,
  checkLatestCustody,
  createCustodyCycle,
  createCustodyEnvelope,
  extractCustodyPackage,
  generateCustodyRecipient,
  inspectCustodyPackage,
  parseCustodyRecipients,
} from "./index.mjs";

const roots = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("recipient-encrypted matched-backup custody", () => {
  it("streams one authenticated package to multiple recipients and recovers for either custodian", async () => {
    const fixture = await custodyFixture();
    const alpha = await recipient(fixture.keys, "alpha", "alpha.private.jwk");
    const bravo = await recipient(fixture.keys, "bravo", "bravo.private.jwk");
    const created = await createCustodyEnvelope({
      custodyRoot: fixture.custody,
      now: new Date("2026-07-14T18:00:00.000Z"),
      recipients: [bravo.public, alpha.public],
      source: fixture.backup,
      verify: fakeVerify,
    });
    expect(created).toMatchObject({ copyDigestVerified: true, created: true, recipientCount: 2, structureVerified: true });
    expect(created.packageName).toMatch(/^vasi-custody-20260714T170000Z-[a-f0-9]{64}\.vbc$/);
    const packagePath = path.join(fixture.custody, created.packageName);
    const encrypted = await readFile(packagePath);
    expect(encrypted.includes(Buffer.from("bootstrap-secret-sentinel"))).toBe(false);
    expect(encrypted.includes(Buffer.from("database-row-sentinel"))).toBe(false);
    expect((await lstat(packagePath)).mode & 0o777).toBe(0o600);

    await expect(authenticateCustodyPackage({
      keyId: "alpha",
      packagePath,
      privateKeyFile: alpha.privateFile,
    })).resolves.toMatchObject({ chunksAuthenticated: 1, recipientAuthenticated: true });

    for (const [name, key] of [["alpha", alpha], ["bravo", bravo]]) {
      const destination = path.join(fixture.recovery, name);
      await expect(extractCustodyPackage({
        destination,
        keyId: name,
        packagePath,
        privateKeyFile: key.privateFile,
        verify: fakeVerify,
      })).resolves.toMatchObject({ extracted: true, recipientAuthenticated: true });
      expect(await readFile(path.join(destination, "VASI.settings"), "utf8")).toBe("bootstrap-secret-sentinel");
      expect(await readFile(path.join(destination, "postgresql.dump"), "utf8")).toBe("database-row-sentinel");
      expect((await lstat(destination)).mode & 0o777).toBe(0o700);
    }
  });

  it("fails closed for wrong keys, ciphertext tampering, truncation, and partial recovery output", async () => {
    const fixture = await custodyFixture();
    const alpha = await recipient(fixture.keys, "alpha", "alpha.private.jwk");
    const wrong = await recipient(fixture.keys, "wrong", "wrong.private.jwk");
    const created = await createCustodyEnvelope({
      custodyRoot: fixture.custody,
      recipients: [alpha.public],
      source: fixture.backup,
      verify: fakeVerify,
    });
    const original = path.join(fixture.custody, created.packageName);
    const wrongDestination = path.join(fixture.recovery, "wrong-key");
    await expect(extractCustodyPackage({
      destination: wrongDestination,
      keyId: "alpha",
      packagePath: original,
      privateKeyFile: wrong.privateFile,
      verify: fakeVerify,
    })).rejects.toThrow("could not be authenticated");
    await expect(authenticateCustodyPackage({
      keyId: "alpha",
      packagePath: original,
      privateKeyFile: wrong.privateFile,
    })).rejects.toThrow("could not be authenticated");
    await expect(lstat(wrongDestination)).rejects.toMatchObject({ code: "ENOENT" });

    const tampered = Buffer.from(await readFile(original));
    const ciphertextOffset = 12 + tampered.readUInt32BE(8);
    tampered[ciphertextOffset + 8] ^= 0x40;
    const tamperedPath = await writeManagedMutation(fixture.custody, created.packageName, tampered, "tampered");
    await expect(inspectCustodyPackage(tamperedPath)).resolves.toMatchObject({ copyDigestVerified: true, structureVerified: true });
    const tamperedDestination = path.join(fixture.recovery, "tampered");
    await expect(extractCustodyPackage({
      destination: tamperedDestination,
      keyId: "alpha",
      packagePath: tamperedPath,
      privateKeyFile: alpha.privateFile,
      verify: fakeVerify,
    })).rejects.toThrow("could not be authenticated");
    await expect(authenticateCustodyPackage({
      keyId: "alpha",
      packagePath: tamperedPath,
      privateKeyFile: alpha.privateFile,
    })).rejects.toThrow("could not be authenticated");
    await expect(lstat(tamperedDestination)).rejects.toMatchObject({ code: "ENOENT" });
    expect((await readdir(fixture.recovery)).some((name) => name.includes(".partial-"))).toBe(false);

    const truncated = tampered.subarray(0, tampered.length - 1);
    const truncatedPath = await writeManagedMutation(fixture.custody, created.packageName, truncated, "truncated");
    await expect(inspectCustodyPackage(truncatedPath)).rejects.toThrow("length is invalid");

    const wrappedTagTamper = Buffer.from(await readFile(original));
    const headerLength = wrappedTagTamper.readUInt32BE(8);
    const header = JSON.parse(wrappedTagTamper.subarray(12, 12 + headerLength).toString("utf8"));
    header.recipients[0].tag = `${header.recipients[0].tag[0] === "A" ? "B" : "A"}${header.recipients[0].tag.slice(1)}`;
    const changedHeader = Buffer.from(JSON.stringify(header));
    expect(changedHeader).toHaveLength(headerLength);
    changedHeader.copy(wrappedTagTamper, 12);
    const wrappedTagPath = await writeManagedMutation(fixture.custody, created.packageName, wrappedTagTamper, "wrapped-tag");
    await expect(inspectCustodyPackage(wrappedTagPath)).resolves.toMatchObject({ structureVerified: true });
    await expect(extractCustodyPackage({
      destination: path.join(fixture.recovery, "wrapped-tag"),
      keyId: "alpha",
      packagePath: wrappedTagPath,
      privateKeyFile: alpha.privateFile,
      verify: fakeVerify,
    })).rejects.toThrow("could not be authenticated");

    const contentTagTamper = Buffer.from(await readFile(original));
    contentTagTamper[contentTagTamper.length - 1] ^= 1;
    const contentTagPath = await writeManagedMutation(fixture.custody, created.packageName, contentTagTamper, "content-tag");
    await expect(extractCustodyPackage({
      destination: path.join(fixture.recovery, "content-tag"),
      keyId: "alpha",
      packagePath: contentTagPath,
      privateKeyFile: alpha.privateFile,
      verify: fakeVerify,
    })).rejects.toThrow("could not be authenticated");

    const falseDigestName = created.packageName.replace(/-[a-f0-9]{64}\.vbc$/, `-${"0".repeat(64)}.vbc`);
    const falseDigestPath = path.join(fixture.custody, falseDigestName);
    await copyFile(original, falseDigestPath);
    await chmod(falseDigestPath, 0o600);
    await expect(inspectCustodyPackage(falseDigestPath)).rejects.toThrow("copy digest is invalid");
  });

  it("requires bounded canonical recipients and protected real paths", async () => {
    const fixture = await custodyFixture();
    const alpha = await recipient(fixture.keys, "alpha", "alpha.private.jwk");
    expect(parseCustodyRecipients(JSON.stringify([alpha.public]))).toEqual([alpha.public]);
    expect(() => parseCustodyRecipients([alpha.public, alpha.public])).toThrow("unique");
    expect(() => parseCustodyRecipients([{ ...alpha.public, publicJwk: { ...alpha.public.publicJwk, d: "x" } }]))
      .toThrow("fields are unsupported");
    expect(() => parseCustodyRecipients([])).toThrow("between 1 and 8");
    expect(() => parseCustodyRecipients(Array.from({ length: 9 }, (_, index) => ({
      keyId: `key-${index}`,
      publicJwk: alpha.public.publicJwk,
    })))).toThrow("between 1 and 8");

    await chmod(fixture.custody, 0o755);
    await expect(createCustodyEnvelope({
      custodyRoot: fixture.custody,
      recipients: [alpha.public],
      source: fixture.backup,
      verify: fakeVerify,
    })).rejects.toThrow("0700");
    await chmod(fixture.custody, 0o700);

    const link = path.join(fixture.root, "backup-link");
    await symlink(fixture.backup, link);
    await expect(createCustodyEnvelope({
      custodyRoot: fixture.custody,
      recipients: [alpha.public],
      source: link,
      verify: fakeVerify,
    })).rejects.toThrow("existing real directory");

    await chmod(alpha.privateFile, 0o644);
    await expect(extractCustodyPackage({
      destination: path.join(fixture.recovery, "unsafe-key"),
      keyId: "alpha",
      packagePath: path.join(fixture.custody, (await readdir(fixture.custody))[0] || "missing"),
      privateKeyFile: alpha.privateFile,
      verify: fakeVerify,
    })).rejects.toThrow("0600");
  });

  it("assesses declared source freshness and prunes only structurally verified managed packages", async () => {
    const fixture = await custodyFixture({ sourceCreatedAt: "2026-07-10T03:00:00.000Z" });
    const alpha = await recipient(fixture.keys, "alpha", "alpha.private.jwk");
    await createCustodyCycle({
      custodyRoot: fixture.custody,
      matchedBackupRoot: fixture.matchedRoot,
      now: new Date("2026-07-10T04:00:00.000Z"),
      recipients: [alpha.public],
      retain: 2,
      verify: fakeVerify,
    });
    await addBackup(fixture.matchedRoot, "2026-07-11T03:00:00.000Z");
    await createCustodyCycle({
      custodyRoot: fixture.custody,
      matchedBackupRoot: fixture.matchedRoot,
      now: new Date("2026-07-11T04:00:00.000Z"),
      recipients: [alpha.public],
      retain: 2,
      verify: fakeVerify,
    });
    const before = await readdir(fixture.custody);
    const oldest = before.filter((name) => name.endsWith(".vbc")).sort()[0];
    const corrupted = Buffer.from(await readFile(path.join(fixture.custody, oldest)));
    corrupted[corrupted.length - 1] ^= 1;
    await writeFile(path.join(fixture.custody, oldest), corrupted, { mode: 0o600 });
    await addBackup(fixture.matchedRoot, "2026-07-12T03:00:00.000Z");
    await expect(createCustodyCycle({
      custodyRoot: fixture.custody,
      matchedBackupRoot: fixture.matchedRoot,
      now: new Date("2026-07-12T04:00:00.000Z"),
      recipients: [alpha.public],
      retain: 2,
      verify: fakeVerify,
    })).rejects.toThrow("copy digest is invalid");
    expect((await readdir(fixture.custody)).filter((name) => name.endsWith(".vbc"))).toHaveLength(3);

    const newest = (await readdir(fixture.custody)).filter((name) => name.endsWith(".vbc")).sort().at(-1);
    await expect(checkLatestCustody({
      custodyRoot: fixture.custody,
      maximumAgeHours: 26,
      now: new Date("2026-07-12T05:00:00.000Z"),
    })).resolves.toMatchObject({
      managedPackages: 3,
      schema: CUSTODY_READINESS_SCHEMA,
      sourceCreatedAt: "2026-07-12T03:00:00.000Z",
      status: "ready",
    });
    expect(newest).toContain("20260712T030000Z");
    await expect(checkLatestCustody({
      custodyRoot: fixture.custody,
      maximumAgeHours: 24,
      now: new Date("2026-07-14T05:00:00.000Z"),
    })).rejects.toBeInstanceOf(BackupCustodyError);
  });

  it("streams content larger than its I/O chunk and authenticates exact recovery bytes", async () => {
    const fixture = await custodyFixture({ dump: Buffer.alloc(9 * 1024 * 1024 + 17, 0x5a) });
    const alpha = await recipient(fixture.keys, "alpha", "alpha.private.jwk");
    const created = await createCustodyEnvelope({
      custodyRoot: fixture.custody,
      recipients: [alpha.public],
      source: fixture.backup,
      verify: fakeVerify,
    });
    const destination = path.join(fixture.recovery, "large");
    await extractCustodyPackage({
      destination,
      keyId: "alpha",
      packagePath: path.join(fixture.custody, created.packageName),
      privateKeyFile: alpha.privateFile,
      verify: fakeVerify,
    });
    const recovered = await readFile(path.join(destination, "postgresql.dump"));
    expect(recovered).toHaveLength(9 * 1024 * 1024 + 17);
    expect(createHash("sha256").update(recovered).digest("hex"))
      .toBe(createHash("sha256").update(Buffer.alloc(9 * 1024 * 1024 + 17, 0x5a)).digest("hex"));
    await expect(authenticateCustodyPackage({
      keyId: "alpha",
      packagePath: path.join(fixture.custody, created.packageName),
      privateKeyFile: alpha.privateFile,
    })).resolves.toMatchObject({ chunksAuthenticated: 2 });
  });
});

async function custodyFixture({ dump, sourceCreatedAt = "2026-07-14T17:00:00.000Z" } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "vasi-backup-custody-"));
  roots.push(root);
  await chmod(root, 0o700);
  const matchedRoot = path.join(root, "matched");
  const custody = path.join(root, "custody");
  const recovery = path.join(root, "recovery");
  const keys = path.join(root, "keys");
  for (const directory of [matchedRoot, custody, recovery, keys]) await mkdir(directory, { mode: 0o700 });
  const backup = await addBackup(matchedRoot, sourceCreatedAt, dump);
  return { backup, custody, keys, matchedRoot, recovery, root };
}

async function addBackup(matchedRoot, createdAt, dumpValue) {
  const date = new Date(createdAt);
  const backup = path.join(matchedRoot, `vasi-${date.toISOString().slice(0, 19).replaceAll("-", "").replaceAll(":", "")}Z`);
  await mkdir(backup, { mode: 0o700 });
  const settings = Buffer.from("bootstrap-secret-sentinel");
  const dump = dumpValue || Buffer.from("database-row-sentinel");
  await writeFile(path.join(backup, "VASI.settings"), settings, { mode: 0o600 });
  await writeFile(path.join(backup, "postgresql.dump"), dump, { mode: 0o600 });
  const manifest = {
    createdAt: date.toISOString(),
    files: {
      "VASI.settings": createHash("sha256").update(settings).digest("hex"),
      "postgresql.dump": createHash("sha256").update(dump).digest("hex"),
    },
    installationFingerprint: "0".repeat(64),
    schema: BACKUP_SCHEMA,
  };
  await writeFile(path.join(backup, "manifest.json"), `${JSON.stringify(manifest)}\n`, { mode: 0o600 });
  return backup;
}

async function recipient(keys, keyId, name) {
  const privateFile = path.join(keys, name);
  const publicRecord = await generateCustodyRecipient({ keyId, privateKeyFile: privateFile });
  return { privateFile, public: publicRecord };
}

async function fakeVerify(directory) {
  const manifest = JSON.parse(await readFile(path.join(directory, "manifest.json"), "utf8"));
  for (const filename of ["VASI.settings", "postgresql.dump"]) {
    const actual = createHash("sha256").update(await readFile(path.join(directory, filename))).digest("hex");
    if (actual !== manifest.files[filename]) throw new Error(`${filename} checksum failed`);
  }
  return manifest;
}

async function writeManagedMutation(root, originalName, contents, label) {
  const timestamp = /^vasi-custody-(\d{8}T\d{6}Z)-/.exec(originalName)[1];
  const digest = createHash("sha256").update(contents).digest("hex");
  const temporary = path.join(root, `${label}.vbc`);
  const managed = path.join(root, `vasi-custody-${timestamp}-${digest}.vbc`);
  await writeFile(temporary, contents, { mode: 0o600 });
  await rename(temporary, managed);
  return managed;
}
