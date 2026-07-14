import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { BACKUP_SCHEMA } from "./backup.mjs";
import {
  BackupContinuityError,
  checkLatestBackup,
  createBackupCycle,
} from "./backup-continuity.mjs";

const temporaryRoots = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((entry) => rm(entry, { force: true, recursive: true })));
});

describe("recurring matched backup continuity", () => {
  it("creates and verifies before pruning only managed backups", async () => {
    const root = await protectedRoot();
    const unrelated = path.join(root, "operator-notes");
    await mkdir(unrelated);
    const symlinkedBackup = path.join(root, "vasi-20260709T030000Z");
    await symlink(unrelated, symlinkedBackup);
    for (const value of ["2026-07-10T03:00:00.000Z", "2026-07-11T03:00:00.000Z", "2026-07-12T03:00:00.000Z"]) {
      await fakeCreate(path.join(root, backupName(new Date(value))), { now: new Date(value) });
    }
    const result = await createBackupCycle({
      backupRoot: root,
      create: fakeCreate,
      maximumAgeHours: 26,
      now: new Date("2026-07-13T03:00:00.000Z"),
      retain: 2,
      verify: fakeVerify,
    });
    expect(result).toMatchObject({ created: true, managedBackups: 2, removed: 2, retained: 2, status: "ready" });
    expect(await readdir(root)).toEqual(expect.arrayContaining([
      "operator-notes",
      "vasi-20260709T030000Z",
      "vasi-20260712T030000Z",
      "vasi-20260713T030000Z",
    ]));
    expect(JSON.stringify(result)).not.toContain(root);
    await expect(readFile(path.join(root, ".vasi-backup.lock"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("fails closed when the newest backup is absent, stale, or corrupt", async () => {
    const root = await protectedRoot();
    await expect(checkLatestBackup({ backupRoot: root, now: new Date(), verify: fakeVerify }))
      .rejects.toMatchObject({ result: { reasons: ["backup_missing"], status: "critical" } });

    const stale = new Date("2026-07-10T03:00:00.000Z");
    await fakeCreate(path.join(root, backupName(stale)), { now: stale });
    await expect(checkLatestBackup({
      backupRoot: root,
      maximumAgeHours: 24,
      now: new Date("2026-07-12T03:00:00.000Z"),
      verify: fakeVerify,
    })).rejects.toMatchObject({ result: { reasons: ["backup_age_threshold_exceeded"], status: "critical" } });

    await expect(checkLatestBackup({
      backupRoot: root,
      now: new Date("2026-07-10T04:00:00.000Z"),
      verify: async () => { throw new Error("corrupt archive"); },
    })).rejects.toMatchObject({ result: { reasons: ["backup_verification_failed"], status: "critical" } });

    const futureRoot = await protectedRoot();
    const future = new Date("2026-07-12T06:00:00.000Z");
    await fakeCreate(path.join(futureRoot, backupName(future)), { now: future });
    await expect(checkLatestBackup({
      backupRoot: futureRoot,
      now: new Date("2026-07-12T03:00:00.000Z"),
      verify: fakeVerify,
    })).rejects.toMatchObject({ result: { reasons: ["backup_time_in_future"], status: "critical" } });
  });

  it("rejects unsafe roots, symlink roots, and concurrent cycles", async () => {
    const unsafe = await protectedRoot();
    await chmod(unsafe, 0o755);
    await expect(checkLatestBackup({ backupRoot: unsafe, verify: fakeVerify })).rejects.toThrow("0700");

    const target = await protectedRoot();
    const linkParent = await protectedRoot();
    const link = path.join(linkParent, "backup-link");
    await symlink(target, link);
    await expect(checkLatestBackup({ backupRoot: link, verify: fakeVerify })).rejects.toThrow("real directory");

    const locked = await protectedRoot();
    await writeFile(path.join(locked, ".vasi-backup.lock"), "active\n", { mode: 0o600 });
    await expect(createBackupCycle({
      backupRoot: locked,
      create: fakeCreate,
      now: new Date("2026-07-13T03:00:00.000Z"),
      verify: fakeVerify,
    })).rejects.toThrow("holds the protected backup lock");
  });

  it("removes a newly created backup when post-create verification fails", async () => {
    const root = await protectedRoot();
    const now = new Date("2026-07-13T03:00:00.000Z");
    await expect(createBackupCycle({
      backupRoot: root,
      create: fakeCreate,
      now,
      verify: async () => { throw new BackupContinuityError("invalid", {}); },
    })).rejects.toThrow("invalid");
    expect(await readdir(root)).toEqual([]);
  });
});

async function protectedRoot() {
  const root = await mkdtemp(path.join(tmpdir(), "vasi-backup-continuity-"));
  temporaryRoots.push(root);
  await chmod(root, 0o700);
  return root;
}

async function fakeCreate(destination, { now }) {
  await mkdir(destination, { mode: 0o700 });
  const manifest = {
    createdAt: now.toISOString(),
    files: { "VASI.settings": "1".repeat(64), "postgresql.dump": "2".repeat(64) },
    installationFingerprint: "0".repeat(64),
    schema: BACKUP_SCHEMA,
  };
  await writeFile(path.join(destination, "manifest.json"), JSON.stringify(manifest), { mode: 0o600 });
  return manifest;
}

async function fakeVerify(destination) {
  return JSON.parse(await readFile(path.join(destination, "manifest.json"), "utf8"));
}

function backupName(date) {
  return `vasi-${date.toISOString().slice(0, 19).replaceAll("-", "").replaceAll(":", "")}Z`;
}
