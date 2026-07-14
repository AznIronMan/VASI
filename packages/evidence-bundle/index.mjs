import { crc32 } from "node:zlib";

import { canonicalJSON, hashCanonicalJSON, sha256Hex } from "../engine-crypto/index.mjs";
import {
  buildEvidenceReports,
  evidenceReportMediaType,
  renderEvidenceReport,
} from "../evidence-reporting/index.mjs";

export const EVIDENCE_BUNDLE_PROFILE = "vasi-evidence-bundle/v1";

export function buildEvidenceBundle({ artifacts = [], record, signIndex }) {
  if (typeof signIndex !== "function") throw new Error("An evidence-bundle signing function is required.");
  const reports = buildEvidenceReports(record);
  const entries = new Map();
  addJSON(entries, "record.json", record);
  addJSON(entries, "manifest.json", record.manifest);
  addEntry(entries, "events.jsonl", Buffer.from(record.events.map((event) => canonicalJSON(event)).join("\n") + "\n", "utf8"), "application/x-ndjson");
  for (const [profile, report] of Object.entries(reports)) {
    for (const format of ["json", "text", "html"]) {
      addEntry(entries, `reports/${profile}.${format === "text" ? "txt" : format}`, renderEvidenceReport(report, format), evidenceReportMediaType(format));
    }
  }
  const artifactIndex = [];
  for (const artifact of artifacts) {
    const filename = safeFilename(artifact.filename || artifact.originalFilename || "artifact.bin");
    const path = `artifacts/${safePathToken(artifact.id)}/${filename}`;
    const bytes = Buffer.from(artifact.bytes);
    if (artifact.sha256 && sha256Hex(bytes) !== artifact.sha256) {
      throw new Error(`Artifact ${artifact.id} does not match its recorded SHA-256 digest.`);
    }
    addEntry(entries, path, bytes, artifact.mediaType || "application/octet-stream");
    artifactIndex.push({
      byteLength: bytes.length,
      id: artifact.id,
      ...(artifact.inspectionProfile && artifact.inspectionResult ? {
        inspection: Object.freeze({
          profile: artifact.inspectionProfile,
          resultHash: hashCanonicalJSON(artifact.inspectionResult),
        }),
      } : {}),
      mediaType: artifact.mediaType || "application/octet-stream",
      originalFilename: artifact.originalFilename,
      path,
      revision: artifact.revision,
      role: artifact.role,
      sha256: sha256Hex(bytes),
    });
  }
  addJSON(entries, "artifacts/index.json", { artifacts: artifactIndex, schema: "vasi-bundle-artifacts/v1" });
  addEntry(entries, "verification/README.txt", Buffer.from(verificationReadme(), "utf8"), "text/plain; charset=utf-8");

  const descriptors = [...entries.entries()]
    .map(([path, entry]) => ({
      byteLength: entry.bytes.length,
      mediaType: entry.mediaType,
      path,
      sha256: sha256Hex(entry.bytes),
    }))
    .sort((left, right) => comparePath(left.path, right.path));
  const primarySeal = (record.seals || [record.seal]).find((seal) => (seal.role || "vasi_integrity") === "vasi_integrity") || record.seal;
  const index = Object.freeze({
    entries: Object.freeze(descriptors),
    evidenceCompletedAt: record.manifest.timestamps?.completedAt,
    generator: "vasi-evidence-bundle/1",
    rootHash: hashCanonicalJSON(descriptors),
    schema: EVIDENCE_BUNDLE_PROFILE,
    sourceManifestHash: primarySeal.manifestHash,
  });
  const seals = signIndex(index);
  const normalizedSeals = Array.isArray(seals) ? seals : [seals];
  addJSON(entries, "bundle-index.json", index);
  addJSON(entries, "bundle-seals.json", { schema: "vasi-bundle-seals/v1", seals: normalizedSeals });

  return Object.freeze({
    bytes: createStoredZip([...entries.entries()].map(([path, entry]) => ({ path, ...entry }))),
    index,
    seals: Object.freeze(normalizedSeals),
  });
}

export function createStoredZip(entries) {
  const normalized = entries.map((entry) => ({
    bytes: Buffer.from(entry.bytes),
    path: validatePath(entry.path),
  })).sort((left, right) => comparePath(left.path, right.path));
  if (!normalized.length || normalized.length > 10_000) throw new Error("The ZIP entry count is invalid.");
  if (new Set(normalized.map((entry) => entry.path)).size !== normalized.length) {
    throw new Error("A ZIP entry path cannot repeat.");
  }
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of normalized) {
    if (entry.bytes.length > 0xffff_ffff || offset > 0xffff_ffff) {
      throw new Error("The VASI ZIP exceeds the supported non-ZIP64 size.");
    }
    const name = Buffer.from(entry.path, "utf8");
    const checksum = Number(crc32(entry.bytes)) >>> 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(33, 12);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(entry.bytes.length, 18);
    local.writeUInt32LE(entry.bytes.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, name, entry.bytes);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x033f, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(33, 14);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(entry.bytes.length, 20);
    central.writeUInt32LE(entry.bytes.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE((0o100644 * 65_536) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);
    offset += local.length + name.length + entry.bytes.length;
  }
  const centralBytes = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(normalized.length, 8);
  end.writeUInt16LE(normalized.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralBytes, end]);
}

export function parseStoredZip(value, limits = {}) {
  const bytes = Buffer.from(value);
  const maxBytes = limits.maxBytes ?? 1_073_741_824;
  const maxEntries = limits.maxEntries ?? 10_000;
  if (bytes.length < 22 || bytes.length > maxBytes) throw new Error("The VASI ZIP size is invalid.");
  const endOffset = bytes.length - 22;
  if (bytes.readUInt32LE(endOffset) !== 0x06054b50 || bytes.readUInt16LE(endOffset + 20) !== 0) {
    throw new Error("The VASI ZIP end record is invalid.");
  }
  const entryCount = bytes.readUInt16LE(endOffset + 10);
  const centralSize = bytes.readUInt32LE(endOffset + 12);
  const centralOffset = bytes.readUInt32LE(endOffset + 16);
  if (!entryCount || entryCount > maxEntries || centralOffset + centralSize !== endOffset) {
    throw new Error("The VASI ZIP central directory is invalid.");
  }
  const entries = new Map();
  const localMetadata = [];
  let offset = 0;
  while (offset < centralOffset) {
    if (offset + 30 > centralOffset || bytes.readUInt32LE(offset) !== 0x04034b50) {
      throw new Error("The VASI ZIP local entry is invalid.");
    }
    if (bytes.readUInt16LE(offset + 6) !== 0 || bytes.readUInt16LE(offset + 8) !== 0) {
      throw new Error("The VASI ZIP uses unsupported flags or compression.");
    }
    const checksum = bytes.readUInt32LE(offset + 14);
    const compressedSize = bytes.readUInt32LE(offset + 18);
    const uncompressedSize = bytes.readUInt32LE(offset + 22);
    const nameLength = bytes.readUInt16LE(offset + 26);
    const extraLength = bytes.readUInt16LE(offset + 28);
    if (compressedSize !== uncompressedSize || extraLength !== 0) throw new Error("The VASI ZIP entry shape is invalid.");
    const nameStart = offset + 30;
    const dataStart = nameStart + nameLength;
    const dataEnd = dataStart + compressedSize;
    if (!nameLength || dataEnd > centralOffset) throw new Error("The VASI ZIP entry bounds are invalid.");
    const path = validatePath(bytes.subarray(nameStart, dataStart).toString("utf8"));
    const data = Buffer.from(bytes.subarray(dataStart, dataEnd));
    if ((Number(crc32(data)) >>> 0) !== checksum || entries.has(path)) {
      throw new Error("The VASI ZIP entry checksum or path is invalid.");
    }
    entries.set(path, data);
    localMetadata.push({ checksum, compressedSize, offset, path });
    offset = dataEnd;
  }
  if (offset !== centralOffset || localMetadata.length !== entryCount) throw new Error("The VASI ZIP entry count is invalid.");
  let centralCursor = centralOffset;
  for (const expected of localMetadata) {
    if (centralCursor + 46 > endOffset || bytes.readUInt32LE(centralCursor) !== 0x02014b50) {
      throw new Error("The VASI ZIP central entry is invalid.");
    }
    const nameLength = bytes.readUInt16LE(centralCursor + 28);
    const extraLength = bytes.readUInt16LE(centralCursor + 30);
    const commentLength = bytes.readUInt16LE(centralCursor + 32);
    const path = bytes.subarray(centralCursor + 46, centralCursor + 46 + nameLength).toString("utf8");
    if (
      bytes.readUInt16LE(centralCursor + 8) !== 0 ||
      bytes.readUInt16LE(centralCursor + 10) !== 0 ||
      validatePath(path) !== expected.path || extraLength || commentLength ||
      bytes.readUInt32LE(centralCursor + 16) !== expected.checksum ||
      bytes.readUInt32LE(centralCursor + 20) !== expected.compressedSize ||
      bytes.readUInt32LE(centralCursor + 24) !== expected.compressedSize ||
      bytes.readUInt32LE(centralCursor + 42) !== expected.offset
    ) throw new Error("The VASI ZIP central entry does not match its local entry.");
    centralCursor += 46 + nameLength;
  }
  if (centralCursor !== endOffset) throw new Error("The VASI ZIP central directory length is invalid.");
  return entries;
}

function addJSON(entries, path, value) {
  addEntry(entries, path, Buffer.from(`${JSON.stringify(JSON.parse(canonicalJSON(value)), null, 2)}\n`, "utf8"), "application/json");
}

function addEntry(entries, path, bytes, mediaType) {
  const safe = validatePath(path);
  if (entries.has(safe)) throw new Error(`Bundle entry ${safe} already exists.`);
  entries.set(safe, { bytes: Buffer.from(bytes), mediaType });
}

function validatePath(value) {
  if (
    typeof value !== "string" || !value || value.length > 512 || value.startsWith("/") ||
    value.includes("\\") || value.split("/").some((part) => !part || part === "." || part === "..") ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) throw new Error("The bundle entry path is unsafe.");
  return value;
}

function safePathToken(value) {
  const token = String(value || "");
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(token)) throw new Error("The artifact ID is unsafe for a bundle path.");
  return token;
}

function safeFilename(value) {
  const filename = String(value).normalize("NFKC").replaceAll(/[^A-Za-z0-9._-]/g, "_").replaceAll(/_+/g, "_").slice(0, 180);
  if (!filename || filename === "." || filename === "..") return "artifact.bin";
  return filename;
}

function comparePath(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function verificationReadme() {
  return "VASI portable evidence bundle\n\nRun the open-source offline verifier from the matching VASI release:\n\n  node scripts/vasi-verify.mjs this-bundle.vasi.zip\n\nThe verifier checks every entry digest, the deterministic bundle index, the bundle seal, the evidence event chain, and every included record seal without a private key or an LLM. Certificate-chain trust and revocation require an explicitly configured trust policy or online status source.\n";
}
