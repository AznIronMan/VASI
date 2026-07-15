import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import {
  chmod,
  chown,
  lchown,
  lstat,
  mkdir,
  open,
  readdir,
  readlink,
  realpath,
  rm,
  stat,
  symlink,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { Readable } from "node:stream";
import { TextDecoder } from "node:util";
import { createGunzip } from "node:zlib";

import {
  parseProtectedOverlay,
  validateActivationConfigurationValue,
} from "./activate-production-release.mjs";
import { isDirectExecution } from "./direct-execution.mjs";

export const RELEASE_STAGING_SCHEMA = "vasi-production-release-staging/v1";

const MAXIMUM_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAXIMUM_DECOMPRESSED_BYTES = 160 * 1024 * 1024;
const MAXIMUM_ENTRIES = 4_096;
const MAXIMUM_EXPANDED_BYTES = 128 * 1024 * 1024;
const MAXIMUM_FILE_BYTES = 4 * 1024 * 1024;
const MAXIMUM_PAX_BYTES = 64 * 1024;
const TAR_BLOCK_BYTES = 512;
const allowedPath = /^[A-Za-z0-9./_@+,:=\[\]-]+$/;
const forbiddenPathPatterns = Object.freeze([
  /(^|\/)\.env(?:\.|$)/,
  /(^|\/)\.git(?:\/|$)/,
  /(^|\/)\.private(?:\/|$)/,
  /(^|\/)\.tasks(?:\/|$)/,
  /(^|\/)data(?:\/|$)/,
  /(^|\/)VASI\.settings$/,
  /\.(?:jks|key|p12|pfx)$/i,
]);
const reservedPaths = new Set(["compose.live.yaml", "data"]);

export class ReleaseStagingError extends Error {
  constructor(code) {
    super("VASI production release staging failed closed.");
    this.code = code;
    this.name = "ReleaseStagingError";
  }
}

export async function stageProductionRelease(
  configurationFile,
  archiveFile,
  releaseId,
  expectedSha256,
  {
    dryRun = false,
    publishDirectory = publishDirectoryNoReplace,
    uid = process.getuid?.() ?? 0,
  } = {},
) {
  try {
    return await stageProductionReleaseInner(
      configurationFile,
      archiveFile,
      releaseId,
      expectedSha256,
      { dryRun, publishDirectory, uid },
    );
  } catch (error) {
    if (error instanceof ReleaseStagingError) throw error;
    fail("staging_unavailable");
  }
}

async function stageProductionReleaseInner(
  configurationFile,
  archiveFile,
  releaseId,
  expectedSha256,
  { dryRun, publishDirectory, uid },
) {
  const version = releaseVersion(releaseId);
  hash(expectedSha256, "expected_archive_sha256");
  const configuration = await loadStagingConfiguration(configurationFile, uid);
  if (uid !== 0 && uid !== configuration.releaseOwnerUid) fail("untrusted_staging_user");
  const candidate = path.join(configuration.releaseRoot, releaseId);
  if (path.dirname(candidate) !== configuration.releaseRoot) fail("invalid_candidate_path");
  await requireAbsent(candidate, "candidate_exists");

  const archive = await openArchive(archiveFile, [0, uid, configuration.releaseOwnerUid]);
  try {
    const archiveContents = await readArchive(archive);
    const archiveSha256 = digestArchive(archiveContents);
    if (archiveSha256 !== expectedSha256) fail("archive_digest_mismatch");
    const inspection = await inspectReleaseArchive(
      archiveContents,
      releaseId,
      configuration.role,
      version,
    );
    await requireUnchangedArchive(archive);
    const result = {
      archiveSha256,
      entries: inspection.entries,
      expandedBytes: inspection.expandedBytes,
      role: configuration.role,
      schema: RELEASE_STAGING_SCHEMA,
      sourceCommit: inspection.sourceCommit,
      status: dryRun ? "ready" : "staged",
      version,
    };
    if (dryRun) return Object.freeze(result);

    const lock = path.join(configuration.releaseRoot, ".vasi-release-stage-lock");
    try {
      await mkdir(lock, { mode: 0o700 });
    } catch (error) {
      if (error?.code === "EEXIST") fail("staging_locked");
      throw error;
    }
    let temporary;
    let published = false;
    try {
      await requireAbsent(candidate, "candidate_exists");
      temporary = path.join(
        configuration.releaseRoot,
        `.stage-${releaseId}-${randomUUID()}`,
      );
      await mkdir(temporary, { mode: 0o700 });
      const extracted = await extractReleaseArchive(
        archiveContents,
        releaseId,
        configuration,
        temporary,
        uid,
      );
      if (
        extracted.indexSha256 !== inspection.indexSha256 ||
        extracted.sourceCommit !== inspection.sourceCommit
      ) fail("archive_changed");
      await createBoundaryLinks(temporary, configuration, uid);
      await normalizeAndVerifyTree(temporary, inspection, configuration, uid);
      await requireUnchangedArchive(archive);
      await requireAbsent(candidate, "candidate_exists");
      await syncDirectory(temporary);
      await publishDirectory(temporary, candidate);
      published = true;
      await verifyPublishedCandidate(candidate, configuration.releaseOwnerUid);
      await syncDirectory(configuration.releaseRoot);
      return Object.freeze(result);
    } finally {
      if (!published && temporary) await rm(temporary, { force: true, recursive: true });
      await rm(lock, { force: true, recursive: true });
    }
  } catch (error) {
    if (error instanceof ReleaseStagingError) throw error;
    fail("staging_unavailable");
  } finally {
    await archive.handle.close().catch(() => undefined);
  }
}

export async function inspectReleaseArchive(archiveContents, releaseId, role, version) {
  const summary = await parseTarGzip(archiveContents, releaseId);
  const packageBytes = summary.fileContents.get("package.json");
  const composeName = role === "engine" ? "compose.engine.yaml" : "compose.production.yaml";
  if (!packageBytes || !summary.files.has(composeName)) fail("required_release_file_missing");
  let packageJSON;
  try {
    packageJSON = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(packageBytes));
  } catch {
    fail("invalid_release_manifest");
  }
  if (
    packageJSON?.name !== "vasi" || packageJSON?.private !== true ||
    packageJSON?.version !== version
  ) fail("invalid_release_manifest");
  return summary;
}

async function extractReleaseArchive(archiveContents, releaseId, configuration, directory, uid) {
  return parseTarGzip(archiveContents, releaseId, {
    async onEntry(entry) {
      if (!entry.relativePath) return;
      const destination = path.join(directory, ...entry.relativePath.split("/"));
      if (!isWithin(directory, destination)) fail("unsafe_extraction_path");
      if (entry.type === "directory") {
        await mkdir(destination, { mode: 0o755 });
        return;
      }
      const file = await open(
        destination,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0),
        entry.mode,
      );
      try {
        await file.writeFile(entry.contents);
        await file.sync();
      } finally {
        await file.close();
      }
      await chmod(destination, entry.mode);
      await setOwner(destination, configuration.releaseOwnerUid, uid);
    },
  });
}

async function parseTarGzip(archiveContents, releaseId, { onEntry } = {}) {
  const gunzip = createGunzip();
  const source = Readable.from([archiveContents]);
  source.on("error", (error) => gunzip.destroy(error));
  source.pipe(gunzip);
  const reader = streamReader(gunzip);
  const rootPrefix = `${releaseId}/`;
  const paths = new Set();
  const directories = new Set([""]);
  const files = new Map();
  const fileContents = new Map();
  const indexHash = createHash("sha256");
  let entries = 0;
  let expandedBytes = 0;
  let sourceCommit;
  let rootSeen = false;
  let ended = false;
  try {
    while (true) {
      const header = await reader.read(TAR_BLOCK_BYTES);
      if (isZeroBlock(header)) {
        if (!isZeroBlock(await reader.read(TAR_BLOCK_BYTES))) fail("invalid_archive_end");
        await reader.requireZeroRemainder();
        ended = true;
        break;
      }
      validateTarHeader(header);
      const typeFlag = header[156] === 0 ? "0" : String.fromCharCode(header[156]);
      const size = tarOctal(header, 124, 12, MAXIMUM_EXPANDED_BYTES);
      const padding = (TAR_BLOCK_BYTES - (size % TAR_BLOCK_BYTES)) % TAR_BLOCK_BYTES;

      if (!sourceCommit) {
        if (typeFlag !== "g" || tarPath(header) !== "pax_global_header" || size > MAXIMUM_PAX_BYTES) {
          fail("missing_archive_provenance");
        }
        const contents = await reader.read(size);
        if (padding && !isZeroBlock(await reader.read(padding))) fail("invalid_archive_padding");
        const pax = parsePax(contents);
        if (pax.size !== 1 || !/^[a-f0-9]{40}$/.test(pax.get("comment") || "")) {
          fail("invalid_archive_provenance");
        }
        sourceCommit = pax.get("comment");
        continue;
      }
      if (typeFlag === "g" || typeFlag === "x") fail("unexpected_archive_extension");
      if (typeFlag !== "0" && typeFlag !== "5") fail("unsafe_archive_entry_type");
      if (++entries > MAXIMUM_ENTRIES) fail("too_many_archive_entries");
      const fullPath = tarPath(header);
      const entry = archiveEntry(fullPath, rootPrefix, typeFlag, size, header);
      if (entry.type === "file" && expandedBytes + entry.size > MAXIMUM_EXPANDED_BYTES) {
        fail("archive_expanded_size_exceeded");
      }
      const contents = await reader.read(size);
      if (padding && !isZeroBlock(await reader.read(padding))) fail("invalid_archive_padding");
      if (!rootSeen) {
        if (entry.relativePath || entry.type !== "directory") fail("invalid_archive_root");
        rootSeen = true;
      } else if (!entry.relativePath) {
        fail("duplicate_archive_root");
      }
      if (paths.has(entry.relativePath)) fail("duplicate_archive_entry");
      paths.add(entry.relativePath);
      if (entry.relativePath) {
        const parent = path.posix.dirname(entry.relativePath);
        if (!directories.has(parent === "." ? "" : parent)) fail("archive_parent_missing");
      }
      if (entry.type === "directory") {
        directories.add(entry.relativePath);
      } else {
        expandedBytes += entry.size;
        const sha256 = createHash("sha256").update(contents).digest("hex");
        files.set(entry.relativePath, Object.freeze({ mode: entry.mode, sha256, size: entry.size }));
        if (entry.relativePath === "package.json") fileContents.set(entry.relativePath, contents);
      }
      indexHash.update(`${entry.type}\0${entry.relativePath}\0${entry.mode}\0${entry.size}\0`);
      if (entry.type === "file") indexHash.update(files.get(entry.relativePath).sha256);
      indexHash.update("\0");
      if (onEntry) await onEntry(Object.freeze({ ...entry, contents }));
    }
  } catch (error) {
    source.destroy();
    gunzip.destroy();
    if (error instanceof ReleaseStagingError) throw error;
    fail("invalid_release_archive");
  } finally {
    source.destroy();
    gunzip.destroy();
  }
  if (!ended || !sourceCommit || !rootSeen || !files.size) fail("incomplete_release_archive");
  return Object.freeze({
    directories,
    entries,
    expandedBytes,
    fileContents,
    files,
    indexSha256: indexHash.digest("hex"),
    sourceCommit,
  });
}

function archiveEntry(fullPath, rootPrefix, typeFlag, size, header) {
  if (!fullPath.startsWith(rootPrefix)) fail("unexpected_archive_root");
  const directory = typeFlag === "5";
  if (directory !== fullPath.endsWith("/")) fail("invalid_archive_entry_path");
  const relativePath = fullPath.slice(rootPrefix.length, directory ? -1 : undefined);
  validateRelativePath(relativePath);
  if (relativePath && (reservedPaths.has(relativePath) || forbiddenPathPatterns.some((rule) => rule.test(relativePath)))) {
    fail("forbidden_archive_path");
  }
  const mode = tarOctal(header, 100, 8, 0o7777);
  if (mode & 0o7000) fail("unsafe_archive_mode");
  if (directory) {
    if (size !== 0) fail("invalid_archive_directory");
    return Object.freeze({ mode: 0o755, relativePath, size: 0, type: "directory" });
  }
  if (size > MAXIMUM_FILE_BYTES) fail("archive_file_too_large");
  const execute = mode & 0o111;
  if (execute !== 0 && execute !== 0o111) fail("ambiguous_archive_mode");
  return Object.freeze({ mode: execute ? 0o755 : 0o644, relativePath, size, type: "file" });
}

function validateRelativePath(value) {
  if (!value) return;
  if (
    value.length > 1_024 || !allowedPath.test(value) || value !== value.normalize("NFC") ||
    value.startsWith("/") || value.endsWith("/") || value.includes("//")
  ) fail("invalid_archive_entry_path");
  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === ".." || segment.length > 255)) {
    fail("invalid_archive_entry_path");
  }
}

function validateTarHeader(header) {
  if (header.length !== TAR_BLOCK_BYTES) fail("truncated_archive_header");
  const magic = header.subarray(257, 263).toString("latin1");
  if (!magic.startsWith("ustar") || header.subarray(263, 265).toString("latin1") !== "00") {
    fail("unsupported_archive_format");
  }
  const recorded = tarOctal(header, 148, 8, 1_000_000);
  let calculated = 0;
  for (let index = 0; index < header.length; index += 1) {
    calculated += index >= 148 && index < 156 ? 32 : header[index];
  }
  if (recorded !== calculated) fail("archive_checksum_mismatch");
  if (tarText(header, 157, 100)) fail("archive_link_target_present");
}

function tarPath(header) {
  const name = tarText(header, 0, 100);
  const prefix = tarText(header, 345, 155);
  const value = prefix ? `${prefix}/${name}` : name;
  if (!value || value.length > 1_200 || !allowedPath.test(value)) fail("invalid_archive_entry_path");
  return value;
}

function tarText(header, offset, length) {
  const field = header.subarray(offset, offset + length);
  const zero = field.indexOf(0);
  const bytes = zero < 0 ? field : field.subarray(0, zero);
  if (zero >= 0 && field.subarray(zero).some((byte) => byte !== 0)) fail("invalid_archive_header_text");
  try {
    const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (/[\u0000-\u001f\u007f]/.test(value)) fail("invalid_archive_header_text");
    return value;
  } catch {
    fail("invalid_archive_header_text");
  }
}

function tarOctal(header, offset, length, maximum) {
  const source = header.subarray(offset, offset + length).toString("latin1").replaceAll("\0", "").trim();
  if (!/^[0-7]+$/.test(source)) fail("invalid_archive_numeric_field");
  const value = Number.parseInt(source, 8);
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail("invalid_archive_numeric_field");
  return value;
}

function parsePax(contents) {
  if (!contents.length || contents.length > MAXIMUM_PAX_BYTES) fail("invalid_archive_provenance");
  const records = new Map();
  let offset = 0;
  while (offset < contents.length) {
    const space = contents.indexOf(32, offset);
    if (space < 0) fail("invalid_archive_provenance");
    const lengthText = contents.subarray(offset, space).toString("ascii");
    if (!/^[1-9][0-9]{1,5}$/.test(lengthText)) fail("invalid_archive_provenance");
    const length = Number(lengthText);
    const end = offset + length;
    if (end > contents.length || contents[end - 1] !== 10) fail("invalid_archive_provenance");
    const record = contents.subarray(space + 1, end - 1);
    const equals = record.indexOf(61);
    if (equals < 1) fail("invalid_archive_provenance");
    const key = record.subarray(0, equals).toString("ascii");
    let value;
    try {
      value = new TextDecoder("utf-8", { fatal: true }).decode(record.subarray(equals + 1));
    } catch {
      fail("invalid_archive_provenance");
    }
    if (!/^[a-z][a-z0-9._-]{0,63}$/.test(key) || records.has(key)) fail("invalid_archive_provenance");
    records.set(key, value);
    offset = end;
  }
  return records;
}

function streamReader(stream) {
  const iterator = stream[Symbol.asyncIterator]();
  let buffered = Buffer.alloc(0);
  let decompressedBytes = 0;
  async function fill(length) {
    while (buffered.length < length) {
      const next = await iterator.next();
      if (next.done) fail("truncated_release_archive");
      const chunk = Buffer.from(next.value);
      decompressedBytes += chunk.length;
      if (decompressedBytes > MAXIMUM_DECOMPRESSED_BYTES) fail("archive_decompressed_size_exceeded");
      buffered = buffered.length ? Buffer.concat([buffered, chunk]) : chunk;
    }
  }
  return Object.freeze({
    async read(length) {
      if (!Number.isSafeInteger(length) || length < 0 || length > MAXIMUM_EXPANDED_BYTES) {
        fail("invalid_archive_read");
      }
      await fill(length);
      const result = buffered.subarray(0, length);
      buffered = buffered.subarray(length);
      return result;
    },
    async requireZeroRemainder() {
      if (buffered.some((byte) => byte !== 0)) fail("invalid_archive_trailer");
      buffered = Buffer.alloc(0);
      while (true) {
        const next = await iterator.next();
        if (next.done) return;
        const chunk = Buffer.from(next.value);
        decompressedBytes += chunk.length;
        if (decompressedBytes > MAXIMUM_DECOMPRESSED_BYTES || chunk.some((byte) => byte !== 0)) {
          fail("invalid_archive_trailer");
        }
      }
    },
  });
}

async function loadStagingConfiguration(filename, uid) {
  const resolved = path.resolve(filename);
  const directory = path.dirname(resolved);
  const directoryMetadata = await lstat(directory);
  if (
    !directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink() ||
    (directoryMetadata.mode & 0o777) !== 0o700 || await realpath(directory) !== directory
  ) fail("invalid_configuration_directory");
  const protectedFile = await readPhysicalFile(resolved, 64 * 1024);
  let configuration;
  try {
    configuration = validateActivationConfigurationValue(JSON.parse(protectedFile.contents.toString("utf8")));
  } catch {
    fail("invalid_staging_configuration");
  }
  const owners = new Set([0, uid, configuration.releaseOwnerUid]);
  if (!owners.has(directoryMetadata.uid) || !owners.has(protectedFile.metadata.uid) ||
      (protectedFile.metadata.mode & 0o777) !== 0o600) {
    fail("invalid_staging_configuration_ownership");
  }
  await validateDirectory(configuration.releaseRoot, owners, false);
  await validateDirectory(configuration.dataRoot, new Set([...owners, 1000]), true);
  const overlayDirectory = path.dirname(configuration.overlayFile);
  await validateDirectory(overlayDirectory, owners, true);
  const overlay = await readPhysicalFile(configuration.overlayFile, 4_096);
  if (!owners.has(overlay.metadata.uid) || (overlay.metadata.mode & 0o777) !== 0o600) {
    fail("invalid_overlay_ownership");
  }
  try {
    parseProtectedOverlay(overlay.contents.toString("utf8"), configuration.role);
  } catch {
    fail("invalid_protected_overlay");
  }
  return configuration;
}

async function validateDirectory(filename, owners, exactPrivateMode) {
  const resolved = path.resolve(filename);
  const metadata = await lstat(resolved);
  const mode = metadata.mode & 0o777;
  if (
    !metadata.isDirectory() || metadata.isSymbolicLink() || await realpath(resolved) !== resolved ||
    !owners.has(metadata.uid) || (exactPrivateMode ? mode !== 0o700 : Boolean(mode & 0o022))
  ) fail("invalid_staging_directory");
}

async function readPhysicalFile(filename, maximumBytes) {
  const resolved = path.resolve(filename);
  const handle = await open(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > maximumBytes || await realpath(resolved) !== resolved) {
      fail("invalid_physical_file");
    }
    return Object.freeze({ contents: await handle.readFile(), metadata });
  } finally {
    await handle.close();
  }
}

async function openArchive(filename, owners) {
  if (typeof filename !== "string" || !filename || Buffer.byteLength(filename) > 4_096 || filename.includes("\0")) {
    fail("invalid_archive_path");
  }
  const resolved = path.resolve(filename);
  const handle = await open(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const metadata = await handle.stat({ bigint: true });
    if (
      !metadata.isFile() || metadata.size < 1n || metadata.size > BigInt(MAXIMUM_ARCHIVE_BYTES) ||
      (Number(metadata.mode) & 0o022) !== 0 || !owners.includes(Number(metadata.uid)) ||
      await realpath(resolved) !== resolved
    ) fail("invalid_release_archive_file");
    return Object.freeze({ handle, metadata });
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function readArchive(archive) {
  const contents = await archive.handle.readFile();
  if (contents.length !== Number(archive.metadata.size)) fail("archive_changed");
  return contents;
}

function digestArchive(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

async function requireUnchangedArchive(archive) {
  const current = await archive.handle.stat({ bigint: true });
  for (const name of ["dev", "ino", "mode", "nlink", "size", "uid", "gid", "mtimeNs"]) {
    if (current[name] !== archive.metadata[name]) fail("archive_changed");
  }
}

async function createBoundaryLinks(directory, configuration, uid) {
  const dataLink = path.join(directory, "data");
  const overlayLink = path.join(directory, "compose.live.yaml");
  await symlink(configuration.dataRoot, dataLink);
  await symlink(configuration.overlayFile, overlayLink);
  if (uid === 0) {
    const dataMetadata = await lstat(dataLink);
    const overlayMetadata = await lstat(overlayLink);
    await lchown(dataLink, configuration.releaseOwnerUid, dataMetadata.gid);
    await lchown(overlayLink, configuration.releaseOwnerUid, overlayMetadata.gid);
  }
}

async function normalizeAndVerifyTree(directory, inspection, configuration, uid) {
  const ownerUid = configuration.releaseOwnerUid;
  const directories = [...inspection.directories]
    .filter(Boolean)
    .sort((left, right) => right.split("/").length - left.split("/").length || right.localeCompare(left));
  for (const relative of directories) {
    const absolute = path.join(directory, ...relative.split("/"));
    await chmod(absolute, 0o755);
    await setOwner(absolute, ownerUid, uid);
  }
  await chmod(directory, 0o750);
  await setOwner(directory, ownerUid, uid);

  const seenFiles = new Set();
  const seenDirectories = new Set([""]);
  const seenLinks = new Set();
  async function walk(current, relative = "") {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
      const absolute = path.join(current, entry.name);
      const metadata = await lstat(absolute);
      if (entry.isSymbolicLink()) {
        const expectedTarget = childRelative === "data"
          ? configuration.dataRoot
          : configuration.overlayFile;
        if (
          !reservedPaths.has(childRelative) || metadata.uid !== ownerUid ||
          await readlink(absolute) !== expectedTarget
        ) fail("invalid_staged_link");
        seenLinks.add(childRelative);
      } else if (entry.isDirectory()) {
        if (!inspection.directories.has(childRelative) || metadata.uid !== ownerUid ||
            (metadata.mode & 0o777) !== 0o755) fail("invalid_staged_directory");
        seenDirectories.add(childRelative);
        await walk(absolute, childRelative);
      } else if (entry.isFile()) {
        const expected = inspection.files.get(childRelative);
        if (!expected || metadata.uid !== ownerUid || metadata.nlink !== 1 ||
            (metadata.mode & 0o777) !== expected.mode || metadata.size !== expected.size) {
          fail("invalid_staged_file");
        }
        const contents = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
        try {
          const sha256 = createHash("sha256").update(await contents.readFile()).digest("hex");
          if (sha256 !== expected.sha256) fail("staged_file_digest_mismatch");
        } finally {
          await contents.close();
        }
        seenFiles.add(childRelative);
      } else {
        fail("invalid_staged_entry_type");
      }
    }
  }
  await walk(directory);
  if (
    seenFiles.size !== inspection.files.size ||
    seenDirectories.size !== inspection.directories.size ||
    seenLinks.size !== reservedPaths.size
  ) fail("incomplete_staged_tree");
  const rootMetadata = await lstat(directory);
  if (rootMetadata.uid !== ownerUid || (rootMetadata.mode & 0o777) !== 0o750) {
    fail("invalid_staged_root");
  }
}

async function setOwner(filename, ownerUid, uid) {
  if (uid !== 0) {
    const metadata = await lstat(filename);
    if (metadata.uid !== ownerUid) fail("staged_owner_mismatch");
    return;
  }
  const metadata = await lstat(filename);
  await chown(filename, ownerUid, metadata.gid);
}

async function publishDirectoryNoReplace(source, destination) {
  if (process.platform !== "linux") fail("unsupported_staging_host");
  const sourceMetadata = await stat(source, { bigint: true });
  await runBounded("/bin/mv", ["--no-clobber", "--no-target-directory", source, destination]);
  let remaining;
  try {
    await lstat(source);
    remaining = true;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    remaining = false;
  }
  const destinationMetadata = await stat(destination, { bigint: true });
  if (remaining || destinationMetadata.dev !== sourceMetadata.dev || destinationMetadata.ino !== sourceMetadata.ino) {
    fail("candidate_publish_conflict");
  }
}

async function runBounded(command, argumentsList) {
  await new Promise((resolve, reject) => {
    const child = spawn(command, argumentsList, {
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let bytes = 0;
    const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
    function consume(chunk) {
      bytes += chunk.length;
      if (bytes > 16 * 1024) child.kill("SIGKILL");
    }
    child.stdout.on("data", consume);
    child.stderr.on("data", consume);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (bytes > 16 * 1024 || code !== 0) reject(new Error("Release staging publish failed."));
      else resolve();
    });
  });
}

async function verifyPublishedCandidate(candidate, ownerUid) {
  const metadata = await lstat(candidate);
  if (
    !metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== ownerUid ||
    (metadata.mode & 0o777) !== 0o750 || await realpath(candidate) !== candidate
  ) fail("invalid_published_candidate");
}

async function syncDirectory(directory) {
  const handle = await open(directory, constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function requireAbsent(filename, code) {
  try {
    await lstat(filename);
    fail(code);
  } catch (error) {
    if (error instanceof ReleaseStagingError) throw error;
    if (error?.code !== "ENOENT") throw error;
  }
}

function releaseVersion(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) {
    fail("invalid_release_identifier");
  }
  const match = /^(\d+\.\d+\.\d+)(?:-[A-Za-z0-9][A-Za-z0-9._-]*)?$/.exec(value);
  if (!match) fail("invalid_release_identifier");
  return match[1];
}

function hash(value, name) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) fail(`invalid_${name}`);
  return value;
}

function isWithin(parent, child) {
  const relative = path.relative(parent, child);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function isZeroBlock(value) {
  return value.length > 0 && value.every((byte) => byte === 0);
}

function fail(code) {
  throw new ReleaseStagingError(code);
}

function usage() {
  console.error(
    "Usage: node scripts/stage-production-release.mjs " +
    "CONFIG_FILE ARCHIVE_FILE RELEASE_ID EXPECTED_SHA256 [--dry-run]",
  );
  process.exitCode = 64;
}

async function main(argumentsList) {
  const [configurationFile, archiveFile, releaseId, expectedSha256, option, ...extra] = argumentsList;
  if (
    !configurationFile || !archiveFile || !releaseId || !expectedSha256 || extra.length ||
    (option && option !== "--dry-run")
  ) return usage();
  try {
    const result = await stageProductionRelease(
      configurationFile,
      archiveFile,
      releaseId,
      expectedSha256,
      { dryRun: option === "--dry-run" },
    );
    console.info(JSON.stringify(result));
  } catch {
    console.error("VASI production release staging failed closed.");
    process.exitCode = 1;
  }
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  await main(process.argv.slice(2));
}
