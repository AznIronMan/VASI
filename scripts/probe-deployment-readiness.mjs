import { X509Certificate } from "node:crypto";
import { statfs } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import process from "node:process";
import tls from "node:tls";
import { pathToFileURL } from "node:url";

import policy from "../config/assurance-policy.json" with { type: "json" };
import packageJSON from "../package.json" with { type: "json" };
import { loadBootstrapSettings, readRuntimeSettings } from "./settings-core.mjs";

export const DEPLOYMENT_READINESS_SCHEMA = "vasi-deployment-readiness/v1";
const DAY_MILLISECONDS = 86_400_000;
const CERTIFICATE_INPUTS = Object.freeze({
  engine: Object.freeze([
    Object.freeze({ code: "engine_server", name: "ENGINE_INGRESS_TLS_CERT" }),
    Object.freeze({ code: "authorized_client_ca", name: "ENGINE_AUTHORIZED_CLIENT_CA_CERT" }),
  ]),
  gateway: Object.freeze([
    Object.freeze({ code: "gateway_client", name: "ENGINE_CLIENT_CERT" }),
    Object.freeze({ code: "engine_server_ca", name: "ENGINE_CA_CERT" }),
  ]),
});

export class DeploymentReadinessError extends Error {
  constructor(result) {
    super("VASI deployment readiness thresholds failed.");
    this.result = result;
  }
}

export async function runDeploymentReadinessProbe({
  fetchHealth = defaultHealthProbe,
  inspectPublicTLS = defaultPublicTLSProbe,
  inspectStorage = defaultStorageProbe,
  maximumStorageUsedPercent = policy.deployment.maximumStorageUsedPercent,
  minimumCertificateDays = policy.deployment.minimumCertificateDays,
  minimumStorageFreeBytes = policy.deployment.minimumStorageFreeBytes,
  now = new Date(),
  origin,
  readSettings = defaultReadSettings,
  scope,
  storagePath,
  timeoutMilliseconds = policy.deployment.timeoutMilliseconds,
} = {}) {
  const target = validatedOrigin(origin);
  const checkedScope = validatedScope(scope);
  const checkedPath = validatedStoragePath(storagePath);
  const instant = validDate(now);
  boundedNumber(maximumStorageUsedPercent, "maximum storage use", 1, 99);
  boundedNumber(minimumCertificateDays, "minimum certificate days", 1, 3_650);
  boundedNumber(minimumStorageFreeBytes, "minimum storage free bytes", 1, Number.MAX_SAFE_INTEGER);
  boundedInteger(timeoutMilliseconds, "timeout", 100, 60_000);

  const reasons = [];
  let health;
  let publicTLS;
  let storage;
  let serviceCertificates = [];
  const [healthOutcome, tlsOutcome, storageOutcome, settingsOutcome] = await Promise.allSettled([
    fetchHealth(target, timeoutMilliseconds),
    inspectPublicTLS(target, timeoutMilliseconds),
    inspectStorage(checkedPath),
    readSettings(checkedScope),
  ]);

  if (healthOutcome.status === "fulfilled") {
    try {
      health = validatedHealth(healthOutcome.value);
      if (health.version !== packageJSON.version) reasons.push("public_version_mismatch");
    } catch {
      reasons.push("public_health_unavailable");
    }
  } else {
    reasons.push("public_health_unavailable");
  }

  if (tlsOutcome.status === "fulfilled") {
    try {
      publicTLS = certificateWindow(tlsOutcome.value, instant);
      if (publicTLS.notYetValid) reasons.push("public_tls_not_yet_valid");
      if (publicTLS.daysRemaining < minimumCertificateDays) reasons.push("public_tls_expiring");
    } catch {
      reasons.push("public_tls_unavailable");
    }
  } else {
    reasons.push("public_tls_unavailable");
  }

  if (storageOutcome.status === "fulfilled") {
    try {
      storage = validatedStorage(storageOutcome.value);
      if (storage.freeBytes < minimumStorageFreeBytes || storage.usedPercent > maximumStorageUsedPercent) {
        reasons.push("storage_pressure");
      }
    } catch {
      reasons.push("storage_unavailable");
    }
  } else {
    reasons.push("storage_unavailable");
  }

  if (settingsOutcome.status === "fulfilled") {
    try {
      serviceCertificates = inspectServiceCertificates(settingsOutcome.value, checkedScope, instant);
      if (serviceCertificates.some((entry) => entry.notYetValid)) reasons.push("service_certificate_not_yet_valid");
      if (serviceCertificates.some((entry) => entry.daysRemaining < minimumCertificateDays)) {
        reasons.push("service_certificate_expiring");
      }
    } catch (error) {
      reasons.push(error?.code === "missing" ? "service_certificate_missing" : "service_certificate_invalid");
    }
  } else {
    reasons.push("service_settings_unavailable");
  }

  const result = Object.freeze({
    expectedVersion: packageJSON.version,
    generatedAt: instant.toISOString(),
    observedVersion: health?.version || null,
    public: Object.freeze({
      healthMilliseconds: health?.milliseconds ?? null,
      tlsDaysRemaining: publicTLS?.daysRemaining ?? null,
      tlsExpiresAt: publicTLS?.expiresAt ?? null,
    }),
    reasons: Object.freeze([...new Set(reasons)].sort()),
    schema: DEPLOYMENT_READINESS_SCHEMA,
    scope: checkedScope,
    serviceCertificates: Object.freeze(serviceCertificates.map((entry) => Object.freeze({
      certificates: entry.certificates,
      code: entry.code,
      daysRemaining: entry.daysRemaining,
      expiresAt: entry.expiresAt,
    }))),
    status: reasons.length ? "critical" : "ready",
    storage: Object.freeze({
      freeBytes: storage?.freeBytes ?? null,
      totalBytes: storage?.totalBytes ?? null,
      usedPercent: storage?.usedPercent ?? null,
    }),
    thresholds: Object.freeze({
      maximumStorageUsedPercent,
      minimumCertificateDays,
      minimumStorageFreeBytes,
    }),
  });
  if (reasons.length) throw new DeploymentReadinessError(result);
  return result;
}

export function inspectServiceCertificates(settings, scope, now = new Date()) {
  if (!settings || Array.isArray(settings) || typeof settings !== "object") throw new Error("Service settings are unavailable.");
  const definitions = [...CERTIFICATE_INPUTS[validatedScope(scope)]];
  if (scope === "engine" && String(settings.EVIDENCE_CERTIFICATE_CHAIN_PEM || "").trim()) {
    definitions.push({ code: "evidence_certificate", name: "EVIDENCE_CERTIFICATE_CHAIN_PEM" });
  }
  return definitions.map((definition) => {
    const source = String(settings[definition.name] || "").trim();
    if (!source) {
      const error = new Error("A required service certificate is missing.");
      error.code = "missing";
      throw error;
    }
    const certificates = certificateWindowsFromPEM(source, now);
    const limiting = certificates.reduce((earliest, candidate) =>
      candidate.expiresAt < earliest.expiresAt ? candidate : earliest
    );
    return Object.freeze({
      certificates: certificates.length,
      code: definition.code,
      daysRemaining: limiting.daysRemaining,
      expiresAt: limiting.expiresAt,
      notYetValid: certificates.some((entry) => entry.notYetValid),
    });
  });
}

export function certificateWindowsFromPEM(value, now = new Date()) {
  const blocks = String(value).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (!blocks?.length || blocks.length > 10) throw new Error("The certificate chain is malformed or unbounded.");
  return blocks.map((block) => {
    const certificate = new X509Certificate(block);
    return certificateWindow({ expiresAt: certificate.validTo, validFrom: certificate.validFrom }, validDate(now));
  });
}

async function defaultHealthProbe(origin, timeoutMilliseconds) {
  const startedAt = performance.now();
  const response = await fetch(new URL("/api/health", origin), {
    cache: "no-store",
    headers: { accept: "application/json", "user-agent": "VASI-deployment-readiness/1" },
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMilliseconds),
  });
  const text = await response.text();
  if (!response.ok || text.length > 16_384) throw new Error("Public health failed.");
  const payload = JSON.parse(text);
  return { milliseconds: performance.now() - startedAt, version: payload?.version };
}

function defaultPublicTLSProbe(origin, timeoutMilliseconds) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: origin.hostname,
      port: Number(origin.port || 443),
      rejectUnauthorized: true,
      servername: origin.hostname,
      timeout: timeoutMilliseconds,
    });
    const fail = (error) => {
      socket.destroy();
      reject(error);
    };
    socket.once("error", fail);
    socket.once("timeout", () => fail(new Error("Public TLS timed out.")));
    socket.once("secureConnect", () => {
      try {
        const certificate = socket.getPeerX509Certificate();
        if (!socket.authorized || !certificate) throw new Error("Public TLS is unauthorized.");
        resolve({ expiresAt: certificate.validTo, validFrom: certificate.validFrom });
      } catch (error) {
        reject(error);
      } finally {
        socket.destroy();
      }
    });
  });
}

async function defaultStorageProbe(storagePath) {
  const result = await statfs(storagePath, { bigint: true });
  return {
    freeBytes: Number(result.bavail * result.bsize),
    totalBytes: Number(result.blocks * result.bsize),
  };
}

function defaultReadSettings(scope) {
  return readRuntimeSettings({ bootstrap: loadBootstrapSettings(), scope });
}

function validatedHealth(value) {
  if (!value || typeof value !== "object" || typeof value.version !== "string" || !Number.isFinite(value.milliseconds)) {
    throw new Error("The public health result is invalid.");
  }
  return Object.freeze({ milliseconds: rounded(value.milliseconds), version: value.version });
}

function validatedStorage(value) {
  const freeBytes = safeBytes(value?.freeBytes);
  const totalBytes = safeBytes(value?.totalBytes);
  if (totalBytes <= 0 || freeBytes > totalBytes) throw new Error("The storage result is invalid.");
  return Object.freeze({
    freeBytes,
    totalBytes,
    usedPercent: rounded(((totalBytes - freeBytes) / totalBytes) * 100),
  });
}

function certificateWindow(value, now) {
  const expires = validDate(new Date(value?.expiresAt));
  const validFrom = validDate(new Date(value?.validFrom));
  return Object.freeze({
    daysRemaining: rounded((expires.getTime() - now.getTime()) / DAY_MILLISECONDS),
    expiresAt: expires.toISOString(),
    notYetValid: validFrom.getTime() > now.getTime(),
  });
}

function validatedOrigin(value) {
  const origin = new URL(value);
  if (origin.protocol !== "https:" || origin.pathname !== "/" || origin.search || origin.hash || origin.username || origin.password) {
    throw new Error("Deployment readiness requires a credential-free HTTPS origin.");
  }
  return origin;
}

function validatedScope(value) {
  if (!Object.hasOwn(CERTIFICATE_INPUTS, value)) throw new Error("Deployment readiness scope must be gateway or engine.");
  return value;
}

function validatedStoragePath(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.includes("\0")) {
    throw new Error("Deployment readiness storage must be an absolute path.");
  }
  return value;
}

function safeBytes(value) {
  const number = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 0) throw new Error("The storage byte count is invalid.");
  return number;
}

function validDate(value) {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error("A readiness timestamp is invalid.");
  return value;
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Deployment readiness ${name} must be between ${minimum} and ${maximum}.`);
  }
}

function boundedNumber(value, name, minimum, maximum) {
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`Deployment readiness ${name} must be between ${minimum} and ${maximum}.`);
  }
}

function rounded(value) {
  return Number(value.toFixed(2));
}

function parseArguments(args) {
  const [origin, ...options] = args;
  if (!origin) usage();
  const parsed = { origin };
  for (let index = 0; index < options.length; index += 2) {
    const name = options[index];
    const value = options[index + 1];
    if (!value) throw new Error(`Deployment readiness option ${name || "(missing)"} requires a value.`);
    if (name === "--scope") parsed.scope = value;
    else if (name === "--storage") parsed.storagePath = value;
    else if (name === "--minimum-certificate-days") parsed.minimumCertificateDays = Number(value);
    else if (name === "--minimum-storage-free-bytes") parsed.minimumStorageFreeBytes = Number(value);
    else if (name === "--maximum-storage-used-percent") parsed.maximumStorageUsedPercent = Number(value);
    else if (name === "--timeout-ms") parsed.timeoutMilliseconds = Number(value);
    else throw new Error(`Unknown deployment readiness option ${name}.`);
  }
  return parsed;
}

function usage() {
  console.info("Usage: node scripts/probe-deployment-readiness.mjs HTTPS_ORIGIN --scope gateway|engine --storage ABSOLUTE_PATH [threshold options]");
  process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runDeploymentReadinessProbe(parseArguments(process.argv.slice(2)))
    .then((result) => console.info(JSON.stringify(result, null, 2)))
    .catch((error) => {
      if (error?.result) console.error(JSON.stringify(error.result, null, 2));
      console.error(error instanceof DeploymentReadinessError
        ? error.message
        : "VASI deployment readiness probe failed.");
      process.exitCode = 1;
    });
}
