import { createHash } from "node:crypto";
import { execFile, spawnSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readlink,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";

import { afterEach, describe, expect, it } from "vitest";

import { stageProductionRelease } from "./stage-production-release.mjs";

const execFileAsync = promisify(execFile);
const roots = [];
const stagingCLI = fileURLToPath(new URL("./stage-production-release.mjs", import.meta.url));

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("fail-closed production release staging", () => {
  it("inspects a physical Git archive without changing live state", async () => {
    const fixture = await stagingFixture();
    const result = await stageProductionRelease(
      fixture.configurationFile,
      fixture.archiveFile,
      fixture.releaseId,
      fixture.archiveSha256,
      { dryRun: true, uid: process.getuid() },
    );

    expect(result).toEqual({
      archiveSha256: fixture.archiveSha256,
      entries: expect.any(Number),
      expandedBytes: expect.any(Number),
      role: "gateway",
      schema: "vasi-production-release-staging/v1",
      sourceCommit: expect.stringMatching(/^[a-f0-9]{40}$/),
      status: "ready",
      version: fixture.version,
    });
    expect(await readlink(fixture.currentLink)).toBe(fixture.previous);
    await expect(lstat(fixture.candidate)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("normalizes ownership and modes, binds protected state, and publishes once", async () => {
    const fixture = await stagingFixture();
    const result = await stageProductionRelease(
      fixture.configurationFile,
      fixture.archiveFile,
      fixture.releaseId,
      fixture.archiveSha256,
      {
        publishDirectory: (source, destination) => rename(source, destination),
        uid: process.getuid(),
      },
    );

    expect(result.status).toBe("staged");
    expect((await lstat(fixture.candidate)).mode & 0o777).toBe(0o750);
    expect((await lstat(path.join(fixture.candidate, "README.md"))).mode & 0o777).toBe(0o644);
    expect((await lstat(path.join(fixture.candidate, "scripts", "tool.sh"))).mode & 0o777).toBe(0o755);
    expect(await readlink(path.join(fixture.candidate, "data"))).toBe(fixture.dataRoot);
    expect(await readlink(path.join(fixture.candidate, "compose.live.yaml"))).toBe(fixture.overlayFile);
    expect(await readlink(fixture.currentLink)).toBe(fixture.previous);
    await expect(stageProductionRelease(
      fixture.configurationFile,
      fixture.archiveFile,
      fixture.releaseId,
      fixture.archiveSha256,
      { dryRun: true, uid: process.getuid() },
    )).rejects.toMatchObject({ code: "candidate_exists" });
  });

  it("rejects a digest mismatch and loose protected or archive permissions", async () => {
    const fixture = await stagingFixture();
    await expectClosed(fixture, fixture.archiveFile, "0".repeat(64), "archive_digest_mismatch");

    await chmod(fixture.configurationFile, 0o644);
    await expectClosed(fixture, fixture.archiveFile, fixture.archiveSha256, "invalid_staging_configuration_ownership");
    await chmod(fixture.configurationFile, 0o600);

    await chmod(fixture.archiveFile, 0o666);
    await expectClosed(fixture, fixture.archiveFile, fixture.archiveSha256, "invalid_release_archive_file");
  });

  it("rejects traversal, private material, special entries, and duplicate paths", async () => {
    const fixture = await stagingFixture();
    const cases = [
      ["traversal", mutateHeader(fixture.tar, "README.md", (header) => setName(
        header,
        `${fixture.releaseId}/../escape`,
      )), "invalid_archive_entry_path"],
      ["private", mutateHeader(fixture.tar, "README.md", (header) => setName(
        header,
        `${fixture.releaseId}/.private`,
      )), "forbidden_archive_path"],
      ["symlink", mutateHeader(fixture.tar, "README.md", (header) => {
        header[156] = "2".charCodeAt(0);
        updateChecksum(header);
      }), "unsafe_archive_entry_type"],
      ["duplicate", duplicateEntry(fixture.tar, "README.md"), "duplicate_archive_entry"],
    ];

    for (const [name, tar, code] of cases) {
      const archive = await writeArchive(fixture.root, name, tar);
      await expectClosed(fixture, archive.filename, archive.sha256, code);
    }
  });

  it("rejects malformed checksums, ambiguous executable modes, and oversized entries before payload reads", async () => {
    const fixture = await stagingFixture();
    const badChecksum = mutateHeader(fixture.tar, "README.md", (header) => {
      header[0] = header[0] === 65 ? 66 : 65;
    });
    const ambiguousMode = mutateHeader(fixture.tar, "README.md", (header) => {
      setOctal(header, 100, 8, 0o744);
      updateChecksum(header);
    });
    const oversized = mutateHeader(fixture.tar, "README.md", (header) => {
      setOctal(header, 124, 12, 4 * 1024 * 1024 + 1);
      updateChecksum(header);
    });
    const cases = [
      ["checksum", badChecksum, "archive_checksum_mismatch"],
      ["mode", ambiguousMode, "ambiguous_archive_mode"],
      ["oversized", oversized, "archive_file_too_large"],
    ];

    for (const [name, tar, code] of cases) {
      const archive = await writeArchive(fixture.root, name, tar);
      await expectClosed(fixture, archive.filename, archive.sha256, code);
    }
  });

  it("does not bypass an existing staging lock", async () => {
    const fixture = await stagingFixture();
    await mkdir(path.join(fixture.releaseRoot, ".vasi-release-stage-lock"), { mode: 0o700 });
    await expectClosed(fixture, fixture.archiveFile, fixture.archiveSha256, "staging_locked", false);
  });

  it("fails with one generic CLI error and no archive or installation facts", async () => {
    const fixture = await stagingFixture();
    const result = spawnSync(process.execPath, [
      stagingCLI,
      fixture.configurationFile,
      fixture.archiveFile,
      fixture.releaseId,
      "0".repeat(64),
      "--dry-run",
    ], { encoding: "utf8", timeout: 5_000 });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("VASI production release staging failed closed.\n");
    expect(result.stderr).not.toContain(fixture.root);
    expect(result.stderr).not.toContain("archive_digest_mismatch");
  });
});

async function stagingFixture() {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "vasi-staging-")));
  roots.push(root);
  await chmod(root, 0o700);
  const installation = path.join(root, "installation");
  const releaseRoot = path.join(installation, "releases");
  const dataRoot = path.join(root, "data");
  const protectedRoot = path.join(root, "protected");
  const repository = path.join(root, "repository");
  await mkdir(installation, { mode: 0o700 });
  await mkdir(releaseRoot, { mode: 0o755 });
  await mkdir(dataRoot, { mode: 0o700 });
  await mkdir(protectedRoot, { mode: 0o700 });
  await mkdir(repository, { mode: 0o700 });

  const version = "9.8.7";
  const releaseId = `${version}-candidate`;
  await mkdir(path.join(repository, "scripts"), { mode: 0o755 });
  await writeFile(path.join(repository, "package.json"), `${JSON.stringify({
    name: "vasi",
    private: true,
    version,
  })}\n`);
  await writeFile(path.join(repository, "compose.production.yaml"), "name: vasi\nservices: {}\n");
  await writeFile(path.join(repository, "README.md"), "Sanitized release fixture.\n");
  const executable = path.join(repository, "scripts", "tool.sh");
  await writeFile(executable, "#!/bin/sh\nexit 0\n");
  await chmod(executable, 0o755);
  await execFileAsync("git", ["init", "--quiet"], { cwd: repository });
  await execFileAsync("git", ["add", "."], { cwd: repository });
  await execFileAsync("git", [
    "-c", "user.name=VASI Test", "-c", "user.email=vasi@example.invalid",
    "commit", "--quiet", "-m", "fixture",
  ], { cwd: repository });
  const { stdout } = await execFileAsync("git", [
    "archive", "--format=tar", `--prefix=${releaseId}/`, "HEAD",
  ], { cwd: repository, encoding: null, maxBuffer: 16 * 1024 * 1024 });
  const tar = Buffer.from(stdout);
  const archive = await writeArchive(root, "release", tar);

  const previous = path.join(releaseRoot, "9.8.6-previous");
  await mkdir(previous, { mode: 0o750 });
  const currentLink = path.join(installation, "current");
  await symlink(previous, currentLink);
  const overlayFile = path.join(protectedRoot, "gateway.live.yaml");
  await writeFile(
    overlayFile,
    "services:\n  app:\n    ports: !override\n      - 10.0.0.10:14443:3000\n",
    { mode: 0o600 },
  );
  const configurationFile = path.join(protectedRoot, "gateway.json");
  await writeFile(configurationFile, `${JSON.stringify({
    currentLink,
    dataRoot,
    overlayFile,
    releaseOwnerUid: process.getuid(),
    releaseRoot,
    role: "gateway",
    schema: "vasi-production-release-activation/v1",
  })}\n`, { mode: 0o600 });

  return {
    archiveFile: archive.filename,
    archiveSha256: archive.sha256,
    candidate: path.join(releaseRoot, releaseId),
    configurationFile,
    currentLink,
    dataRoot,
    overlayFile,
    previous,
    releaseId,
    releaseRoot,
    root,
    tar,
    version,
  };
}

async function expectClosed(fixture, archiveFile, sha256, code, dryRun = true) {
  await expect(stageProductionRelease(
    fixture.configurationFile,
    archiveFile,
    fixture.releaseId,
    sha256,
    { dryRun, uid: process.getuid() },
  )).rejects.toMatchObject({ code });
  await expect(lstat(fixture.candidate)).rejects.toMatchObject({ code: "ENOENT" });
  expect(await readlink(fixture.currentLink)).toBe(fixture.previous);
}

async function writeArchive(root, name, tar) {
  const contents = gzipSync(tar, { level: 9, mtime: 0 });
  const filename = path.join(root, `${name}.tar.gz`);
  await writeFile(filename, contents, { mode: 0o644 });
  await chmod(filename, 0o644);
  return { filename, sha256: createHash("sha256").update(contents).digest("hex") };
}

function mutateHeader(sourceTar, suffix, mutate) {
  const tar = Buffer.from(sourceTar);
  const entry = tarEntries(tar).find((candidate) => candidate.name.endsWith(`/${suffix}`));
  if (!entry) throw new Error(`Missing archive fixture entry: ${suffix}`);
  mutate(tar.subarray(entry.offset, entry.offset + 512));
  return tar;
}

function duplicateEntry(sourceTar, suffix) {
  const entries = tarEntries(sourceTar);
  const entry = entries.find((candidate) => candidate.name.endsWith(`/${suffix}`));
  if (!entry) throw new Error(`Missing archive fixture entry: ${suffix}`);
  const end = entries.at(-1).nextOffset;
  return Buffer.concat([
    sourceTar.subarray(0, end),
    sourceTar.subarray(entry.offset, entry.nextOffset),
    sourceTar.subarray(end),
  ]);
}

function tarEntries(tar) {
  const entries = [];
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = tarField(header, 0, 100);
    const prefix = tarField(header, 345, 155);
    const size = Number.parseInt(tarField(header, 124, 12).trim(), 8);
    const nextOffset = offset + 512 + Math.ceil(size / 512) * 512;
    entries.push({ name: prefix ? `${prefix}/${name}` : name, nextOffset, offset });
    offset = nextOffset;
  }
  return entries;
}

function tarField(header, offset, length) {
  return header.subarray(offset, offset + length).toString("utf8").replaceAll("\0", "");
}

function setName(header, value) {
  const encoded = Buffer.from(value);
  if (encoded.length > 100) throw new Error("Test archive path is too long.");
  header.fill(0, 0, 100);
  encoded.copy(header, 0);
  updateChecksum(header);
}

function setOctal(header, offset, length, value) {
  const encoded = Buffer.from(`${value.toString(8).padStart(length - 1, "0")}\0`, "ascii");
  encoded.copy(header, offset);
}

function updateChecksum(header) {
  header.fill(32, 148, 156);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  Buffer.from(`${checksum.toString(8).padStart(6, "0")}\0 `, "ascii").copy(header, 148);
}
