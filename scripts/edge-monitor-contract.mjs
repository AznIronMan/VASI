import { createHash } from "node:crypto";
import {
  lstat,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { isDirectExecution } from "./direct-execution.mjs";

import policy from "../config/edge-monitor-policy.json" with { type: "json" };

const CONFIGURATION_SCHEMA = "vasi-edge-monitor/v1";
const IMAGE_ASSURANCE_SCHEMA = "vasi-edge-image-assurance/v1";
const EVIDENCE_SCHEMA = "vasi-edge-image-evidence-result/v1";
const REQUIRED_ARTIFACTS = Object.freeze([
  "image-id.txt",
  "packages.txt",
  "sbom.cdx.json",
  "scanner-version.json",
  "vulnerabilities.json",
]);
const CONFIGURATION_KEYS = Object.freeze([
  "gatewayUpstreamName",
  "imageReference",
  "listenerPorts",
  "liveContainer",
  "maximumScanAgeHours",
  "publicHost",
  "retainedScans",
  "retiredHost",
  "rollbackContainer",
  "scanRoot",
  "scannerCache",
  "schema",
]);

export async function loadEdgeMonitorConfiguration(filename) {
  const metadata = await regularFile(filename, policy.maximumConfigurationBytes, "configuration");
  if (metadata.size < 2) throw new Error("The edge monitor configuration is empty.");
  let parsed;
  try {
    parsed = JSON.parse(await readFile(filename, "utf8"));
  } catch {
    throw new Error("The edge monitor configuration is malformed.");
  }
  return parseEdgeMonitorConfiguration(parsed);
}

export function parseEdgeMonitorConfiguration(value) {
  strictRecord(value, CONFIGURATION_KEYS, "edge monitor configuration");
  if (value.schema !== CONFIGURATION_SCHEMA) {
    throw new Error("The edge monitor configuration schema is unsupported.");
  }
  const liveContainer = dockerName(value.liveContainer, "live container");
  const rollbackContainer = dockerName(value.rollbackContainer, "rollback container");
  if (liveContainer === rollbackContainer) {
    throw new Error("The live and rollback containers must be distinct.");
  }
  const publicHost = hostname(value.publicHost, "public host");
  const retiredHost = hostname(value.retiredHost, "retired host");
  if (publicHost === retiredHost) throw new Error("The public and retired hosts must be distinct.");
  const listenerPorts = uniqueIntegerArray(value.listenerPorts, "listener ports", 1, 65_535, 16);
  if (!listenerPorts.includes(443)) throw new Error("The edge monitor must verify the HTTPS listener.");
  const maximumScanAgeHours = boundedInteger(
    value.maximumScanAgeHours,
    "maximum scan age",
    1,
    policy.maximumScanAgeHours,
  );
  const retainedScans = boundedInteger(
    value.retainedScans,
    "retained scan count",
    2,
    policy.maximumRetainedScans,
  );
  return Object.freeze({
    gatewayUpstreamName: nginxIdentifier(value.gatewayUpstreamName, "gateway upstream name"),
    imageReference: imageReference(value.imageReference),
    listenerPorts,
    liveContainer,
    maximumScanAgeHours,
    publicHost,
    retainedScans,
    retiredHost,
    rollbackContainer,
    scanRoot: protectedRoot(value.scanRoot, "/var/lib/vasi-edge", "scan root"),
    scannerCache: protectedRoot(value.scannerCache, "/var/cache/vasi-edge", "scanner cache"),
    schema: CONFIGURATION_SCHEMA,
  });
}

export async function createEdgeImageManifest({
  directory,
  imageId,
  now = new Date(),
  scanDirectory,
}) {
  const normalizedImageId = imageIdentifier(imageId);
  const normalizedScanDirectory = scanDirectoryName(scanDirectory);
  const entries = (await readdir(directory)).sort();
  if (JSON.stringify(entries) !== JSON.stringify(REQUIRED_ARTIFACTS)) {
    throw new Error("The edge scan directory contains an unexpected artifact inventory.");
  }
  const artifacts = await artifactInventory(directory);
  const imageIdentity = (await readFile(path.join(directory, "image-id.txt"), "utf8")).trim();
  if (imageIdentity !== normalizedImageId) throw new Error("The edge image identity artifact does not match.");
  const vulnerabilities = await vulnerabilitySummary(path.join(directory, "vulnerabilities.json"));
  await validateCycloneDX(path.join(directory, "sbom.cdx.json"));
  const generatedAt = validDate(now, "scan time").toISOString();
  await validateScannerEvidence(path.join(directory, "scanner-version.json"), now);
  const manifest = Object.freeze({
    artifacts,
    blockingFindings: vulnerabilities.blocking,
    generatedAt,
    imageId: normalizedImageId,
    scanDirectory: normalizedScanDirectory,
    scannerImage: policy.scannerImage,
    schema: IMAGE_ASSURANCE_SCHEMA,
    status: vulnerabilities.blocking === 0 ? "pass" : "fail",
  });
  await writeFile(
    path.join(directory, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    { flag: "wx", mode: 0o600 },
  );
  return manifest;
}

export async function verifyEdgeImageEvidence({
  configuration,
  evidenceRoot,
  expectedImageId,
  now = new Date(),
}) {
  const config = parseEdgeMonitorConfiguration(configuration);
  const normalizedImageId = imageIdentifier(expectedImageId);
  const latestPath = path.join(evidenceRoot, "latest.json");
  await regularFile(latestPath, policy.maximumArtifactBytes, "latest edge scan state");
  const latestBytes = await readFile(latestPath);
  let manifest;
  try {
    manifest = JSON.parse(latestBytes.toString("utf8"));
  } catch {
    throw new Error("The latest edge scan state is malformed.");
  }
  const parsed = parseImageManifest(manifest);
  if (parsed.imageId !== normalizedImageId) throw new Error("The edge scan does not match the live image.");
  if (parsed.scannerImage !== policy.scannerImage) throw new Error("The edge scan used an unapproved scanner.");
  if (parsed.status !== "pass" || parsed.blockingFindings !== 0) {
    throw new Error("The edge scan contains a blocking finding.");
  }
  const current = validDate(now, "verification time").getTime();
  const generated = Date.parse(parsed.generatedAt);
  if (!Number.isFinite(generated) || generated > current + 60_000) {
    throw new Error("The edge scan time is invalid or future-dated.");
  }
  const ageMilliseconds = current - generated;
  if (ageMilliseconds > config.maximumScanAgeHours * 3_600_000) {
    throw new Error("The edge scan is stale.");
  }
  const directory = path.join(evidenceRoot, parsed.scanDirectory);
  const directoryMetadata = await lstat(directory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new Error("The edge scan directory is not a real directory.");
  }
  const expectedEntries = [...REQUIRED_ARTIFACTS, "manifest.json"].sort();
  const actualEntries = (await readdir(directory)).sort();
  if (JSON.stringify(actualEntries) !== JSON.stringify(expectedEntries)) {
    throw new Error("The retained edge scan inventory is invalid.");
  }
  const manifestPath = path.join(directory, "manifest.json");
  await regularFile(manifestPath, policy.maximumArtifactBytes, "retained edge scan manifest");
  const retainedBytes = await readFile(manifestPath);
  if (!retainedBytes.equals(latestBytes)) throw new Error("The latest edge scan state was replaced or diverged.");
  const actualArtifacts = await artifactInventory(directory);
  if (JSON.stringify(actualArtifacts) !== JSON.stringify(parsed.artifacts)) {
    throw new Error("The retained edge scan artifact digest does not match.");
  }
  const imageIdentity = (await readFile(path.join(directory, "image-id.txt"), "utf8")).trim();
  if (imageIdentity !== normalizedImageId) throw new Error("The retained edge image identity does not match.");
  const vulnerabilities = await vulnerabilitySummary(path.join(directory, "vulnerabilities.json"));
  if (vulnerabilities.blocking !== 0) throw new Error("The retained edge scan contains a blocking finding.");
  await validateCycloneDX(path.join(directory, "sbom.cdx.json"));
  await validateScannerEvidence(path.join(directory, "scanner-version.json"), now);
  return Object.freeze({
    ageSeconds: Math.floor(ageMilliseconds / 1_000),
    artifacts: actualArtifacts.length,
    blockingFindings: 0,
    schema: EVIDENCE_SCHEMA,
    status: "pass",
  });
}

function parseImageManifest(value) {
  strictRecord(value, [
    "artifacts",
    "blockingFindings",
    "generatedAt",
    "imageId",
    "scanDirectory",
    "scannerImage",
    "schema",
    "status",
  ], "edge image assurance manifest");
  if (value.schema !== IMAGE_ASSURANCE_SCHEMA) throw new Error("The edge image assurance schema is unsupported.");
  if (!Array.isArray(value.artifacts) || value.artifacts.length !== REQUIRED_ARTIFACTS.length) {
    throw new Error("The edge image assurance artifact inventory is invalid.");
  }
  const artifacts = value.artifacts.map((artifact) => {
    strictRecord(artifact, ["bytes", "name", "sha256"], "edge image artifact");
    if (!REQUIRED_ARTIFACTS.includes(artifact.name)) throw new Error("The edge image artifact name is unsupported.");
    return Object.freeze({
      bytes: boundedInteger(artifact.bytes, "edge artifact size", 1, policy.maximumArtifactBytes),
      name: artifact.name,
      sha256: sha256(artifact.sha256),
    });
  }).sort((left, right) => left.name.localeCompare(right.name));
  if (new Set(artifacts.map((artifact) => artifact.name)).size !== REQUIRED_ARTIFACTS.length) {
    throw new Error("The edge image artifact inventory contains a duplicate.");
  }
  const blockingFindings = boundedInteger(value.blockingFindings, "blocking finding count", 0, 100_000);
  if (!["pass", "fail"].includes(value.status) || (value.status === "pass") !== (blockingFindings === 0)) {
    throw new Error("The edge image assurance result is inconsistent.");
  }
  if (
    typeof value.generatedAt !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value.generatedAt) ||
    !Number.isFinite(Date.parse(value.generatedAt))
  ) {
    throw new Error("The edge image assurance time is invalid.");
  }
  return Object.freeze({
    artifacts: Object.freeze(artifacts),
    blockingFindings,
    generatedAt: value.generatedAt,
    imageId: imageIdentifier(value.imageId),
    scanDirectory: scanDirectoryName(value.scanDirectory),
    scannerImage: value.scannerImage,
    schema: IMAGE_ASSURANCE_SCHEMA,
    status: value.status,
  });
}

async function artifactInventory(directory) {
  return Promise.all(REQUIRED_ARTIFACTS.map(async (name) => {
    const filename = path.join(directory, name);
    const metadata = await regularFile(filename, policy.maximumArtifactBytes, `edge scan artifact ${name}`);
    if (metadata.size < 1) throw new Error(`The edge scan artifact ${name} is empty.`);
    const contents = await readFile(filename);
    return Object.freeze({
      bytes: metadata.size,
      name,
      sha256: createHash("sha256").update(contents).digest("hex"),
    });
  }));
}

async function vulnerabilitySummary(filename) {
  let value;
  try {
    value = JSON.parse(await readFile(filename, "utf8"));
  } catch {
    throw new Error("The edge vulnerability evidence is malformed.");
  }
  if (!isPlainRecord(value) || !Array.isArray(value.Results) || value.Results.length > 10_000) {
    throw new Error("The edge vulnerability evidence contract is invalid.");
  }
  let blocking = 0;
  for (const result of value.Results) {
    if (!isPlainRecord(result)) throw new Error("The edge vulnerability result is invalid.");
    const findings = result.Vulnerabilities ?? [];
    if (!Array.isArray(findings) || findings.length > 100_000) {
      throw new Error("The edge vulnerability finding inventory is invalid.");
    }
    for (const finding of findings) {
      if (!isPlainRecord(finding) || typeof finding.Severity !== "string") {
        throw new Error("The edge vulnerability finding is invalid.");
      }
      if (["HIGH", "CRITICAL"].includes(finding.Severity)) blocking += 1;
    }
  }
  return Object.freeze({ blocking });
}

async function validateCycloneDX(filename) {
  let value;
  try {
    value = JSON.parse(await readFile(filename, "utf8"));
  } catch {
    throw new Error("The edge SBOM evidence is malformed.");
  }
  if (!isPlainRecord(value) || value.bomFormat !== "CycloneDX" || !Array.isArray(value.components)) {
    throw new Error("The edge SBOM evidence contract is invalid.");
  }
}

async function validateScannerEvidence(filename, now) {
  let value;
  try {
    value = JSON.parse(await readFile(filename, "utf8"));
  } catch {
    throw new Error("The edge scanner evidence is malformed.");
  }
  strictRecord(value, ["Version", "VulnerabilityDB"], "edge scanner evidence");
  strictRecord(
    value.VulnerabilityDB,
    ["DownloadedAt", "NextUpdate", "UpdatedAt", "Version"],
    "edge vulnerability database evidence",
  );
  if (
    typeof value.Version !== "string" ||
    !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value.Version) ||
    !Number.isSafeInteger(value.VulnerabilityDB.Version) ||
    value.VulnerabilityDB.Version < 1 || value.VulnerabilityDB.Version > 10
  ) throw new Error("The edge scanner version evidence is invalid.");
  const current = validDate(now, "scanner verification time").getTime();
  const updated = scannerDate(value.VulnerabilityDB.UpdatedAt, "updated");
  const downloaded = scannerDate(value.VulnerabilityDB.DownloadedAt, "downloaded");
  const nextUpdate = scannerDate(value.VulnerabilityDB.NextUpdate, "next-update");
  const futureTolerance = 5 * 60_000;
  const maximumAge = policy.maximumVulnerabilityDatabaseAgeHours * 3_600_000;
  if (
    updated > current + futureTolerance || downloaded > current + futureTolerance ||
    current - updated > maximumAge || current - downloaded > maximumAge ||
    downloaded + futureTolerance < updated || nextUpdate <= updated
  ) throw new Error("The edge vulnerability database evidence is stale or inconsistent.");
}

function scannerDate(value, label) {
  if (
    typeof value !== "string" || value.length < 20 || value.length > 48 ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)
  ) throw new Error(`The edge vulnerability database ${label} time is invalid.`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`The edge vulnerability database ${label} time is invalid.`);
  return parsed;
}

async function regularFile(filename, maximumBytes, label) {
  const metadata = await lstat(filename);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maximumBytes) {
    throw new Error(`The ${label} is not a bounded regular file.`);
  }
  return metadata;
}

function strictRecord(value, expectedKeys, label) {
  if (!isPlainRecord(value)) throw new Error(`The ${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`The ${label} fields are unsupported.`);
  }
}

function isPlainRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function dockerName(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value)) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value;
}

function imageReference(value) {
  if (
    typeof value !== "string" || value.length > 255 || value.includes("..") ||
    !/^[a-z0-9][a-z0-9._/-]{0,190}:[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value)
  ) throw new Error("The edge image reference is invalid.");
  return value;
}

function imageIdentifier(value) {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value)) {
    throw new Error("The edge image identifier is invalid.");
  }
  return value;
}

function hostname(value, label) {
  if (typeof value !== "string" || value !== value.toLowerCase() || value.length > 253) {
    throw new Error(`The ${label} is invalid.`);
  }
  const labels = value.split(".");
  if (
    labels.length < 2 || labels.some((entry) =>
      entry.length < 1 || entry.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(entry)
    )
  ) throw new Error(`The ${label} is invalid.`);
  return value;
}

function nginxIdentifier(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(value)) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value;
}

function protectedRoot(value, prefix, label) {
  if (
    typeof value !== "string" || value.length > 240 || !path.isAbsolute(value) ||
    path.normalize(value) !== value || value === prefix || !value.startsWith(`${prefix}/`)
  ) throw new Error(`The ${label} is invalid.`);
  return value;
}

function uniqueIntegerArray(value, label, minimum, maximum, maximumItems) {
  if (
    !Array.isArray(value) || value.length < 1 || value.length > maximumItems ||
    value.some((entry) => !Number.isSafeInteger(entry) || entry < minimum || entry > maximum) ||
    new Set(value).size !== value.length
  ) throw new Error(`The ${label} are invalid.`);
  return Object.freeze([...value].sort((left, right) => left - right));
}

function boundedInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value;
}

function scanDirectoryName(value) {
  if (typeof value !== "string" || !/^scan-[0-9]{8}T[0-9]{6}Z$/.test(value)) {
    throw new Error("The edge scan directory name is invalid.");
  }
  return value;
}

function sha256(value) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error("The edge artifact digest is invalid.");
  }
  return value;
}

function validDate(value, label) {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`The ${label} is invalid.`);
  return value;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "validate-config" && args.length === 1) {
    console.info(JSON.stringify(await loadEdgeMonitorConfiguration(args[0])));
    return;
  }
  if (command === "create-manifest" && args.length === 3) {
    const manifest = await createEdgeImageManifest({
      directory: path.resolve(args[0]),
      imageId: args[2],
      scanDirectory: args[1],
    });
    console.info(JSON.stringify({ blockingFindings: manifest.blockingFindings, status: manifest.status }));
    return;
  }
  if (command === "verify-evidence" && args.length === 3) {
    const configuration = await loadEdgeMonitorConfiguration(args[0]);
    console.info(JSON.stringify(await verifyEdgeImageEvidence({
      configuration,
      evidenceRoot: path.resolve(args[1]),
      expectedImageId: args[2],
    })));
    return;
  }
  throw new Error("Usage: edge-monitor-contract validate-config|create-manifest|verify-evidence ...");
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main().catch(() => {
    console.error("VASI edge monitor contract rejected its bounded input.");
    process.exitCode = 1;
  });
}
