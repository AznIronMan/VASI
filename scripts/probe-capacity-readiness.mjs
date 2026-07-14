import { readFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { statfs } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import policy from "../config/assurance-policy.json" with { type: "json" };
import packageJSON from "../package.json" with { type: "json" };
import { createSettingsPool, loadBootstrapSettings } from "./settings-core.mjs";

export const CAPACITY_READINESS_SCHEMA = "vasi-capacity-readiness/v1";
const MAXIMUM_PROC_BYTES = 65_536;
const STORAGE_CODES = Object.freeze(["backup", "database", "docker", "system"]);

export class CapacityReadinessError extends Error {
  constructor(result) {
    super("VASI capacity readiness thresholds failed.");
    this.result = result;
  }
}

export async function runCapacityReadinessProbe({
  inspectDatabase = defaultDatabaseProbe,
  inspectHost = defaultHostProbe,
  inspectStorage = defaultStorageProbe,
  now = new Date(),
  procRoot = "/host/proc",
  scope,
  storageTargets,
  thresholds = policy.capacity,
} = {}) {
  const checkedScope = validatedScope(scope);
  const checkedProcRoot = validatedAbsolutePath(procRoot, "proc root");
  const checkedStorageTargets = validatedStorageTargets(storageTargets);
  const checkedThresholds = validatedThresholds(thresholds);
  const instant = validDate(now);

  const [hostOutcome, databaseOutcome, storageOutcomes] = await Promise.all([
    settle(inspectHost(checkedProcRoot, checkedThresholds.sampleMilliseconds)),
    settle(inspectDatabase(checkedThresholds.timeoutMilliseconds)),
    Promise.all(checkedStorageTargets.map(async (target) => ({
      ...target,
      outcome: await settle(inspectStorage(target.path)),
    }))),
  ]);

  const reasons = [];
  let host = null;
  let database = null;
  const storage = [];

  if (hostOutcome.status === "fulfilled") {
    try {
      host = validatedHost(hostOutcome.value);
      if (host.cpu.usedPercent > checkedThresholds.maximumCpuUsedPercent) reasons.push("cpu_use_pressure");
      if (host.cpu.load1PerCpu > checkedThresholds.maximumLoad1PerCpu) reasons.push("load_pressure");
      if (host.cpu.pressureSome10 > checkedThresholds.maximumCpuPressureSome10) reasons.push("cpu_stall_pressure");
      if (host.memory.usedPercent > checkedThresholds.maximumMemoryUsedPercent) reasons.push("memory_pressure");
      if (
        host.memory.swapUsedPercent !== null &&
        host.memory.swapUsedPercent > checkedThresholds.maximumSwapUsedPercent
      ) reasons.push("swap_pressure");
      if (host.memory.pressureFull10 > checkedThresholds.maximumMemoryPressureFull10) {
        reasons.push("memory_stall_pressure");
      }
      if (host.ioPressureFull10 > checkedThresholds.maximumIOPressureFull10) reasons.push("io_stall_pressure");
    } catch {
      reasons.push("host_metrics_unavailable");
    }
  } else {
    reasons.push("host_metrics_unavailable");
  }

  for (const target of storageOutcomes) {
    if (target.outcome.status === "fulfilled") {
      try {
        const snapshot = validatedStorage(target.outcome.value, target.code);
        storage.push(snapshot);
        if (
          snapshot.freeBytes < checkedThresholds.minimumStorageFreeBytes ||
          snapshot.usedPercent > checkedThresholds.maximumStorageUsedPercent
        ) reasons.push(`storage_${target.code}_bytes_pressure`);
        if (
          snapshot.freeInodes < checkedThresholds.minimumStorageFreeInodes ||
          snapshot.usedInodesPercent > checkedThresholds.maximumStorageUsedInodesPercent
        ) reasons.push(`storage_${target.code}_inode_pressure`);
      } catch {
        reasons.push(`storage_${target.code}_unavailable`);
      }
    } else {
      reasons.push(`storage_${target.code}_unavailable`);
    }
  }

  if (databaseOutcome.status === "fulfilled") {
    try {
      database = validatedDatabase(databaseOutcome.value);
      if (database.queryMilliseconds > checkedThresholds.maximumDatabaseQueryMilliseconds) {
        reasons.push("database_query_pressure");
      }
      if (database.connectionsUsedPercent > checkedThresholds.maximumDatabaseConnectionsUsedPercent) {
        reasons.push("database_connection_pressure");
      }
      if (database.oldestTransactionSeconds > checkedThresholds.maximumDatabaseTransactionSeconds) {
        reasons.push("database_transaction_pressure");
      }
      if (database.sizeBytes > checkedThresholds.maximumDatabaseBytes) reasons.push("database_size_pressure");
      if (
        checkedThresholds.requirePrimaryReplica &&
        database.mode === "primary" &&
        database.replicas < 1
      ) reasons.push("database_replica_missing");
    } catch {
      reasons.push("database_metrics_unavailable");
    }
  } else {
    reasons.push("database_metrics_unavailable");
  }

  const result = Object.freeze({
    database,
    expectedVersion: packageJSON.version,
    generatedAt: instant.toISOString(),
    host,
    reasons: Object.freeze([...new Set(reasons)].sort()),
    schema: CAPACITY_READINESS_SCHEMA,
    scope: checkedScope,
    status: reasons.length ? "critical" : "ready",
    storage: Object.freeze(storage.sort((left, right) => left.code.localeCompare(right.code))),
    thresholds: checkedThresholds,
  });
  if (reasons.length) throw new CapacityReadinessError(result);
  return result;
}

export async function defaultHostProbe(procRoot, sampleMilliseconds) {
  const files = {
    cpuPressure: path.join(procRoot, "pressure", "cpu"),
    ioPressure: path.join(procRoot, "pressure", "io"),
    load: path.join(procRoot, "loadavg"),
    memory: path.join(procRoot, "meminfo"),
    memoryPressure: path.join(procRoot, "pressure", "memory"),
    stat: path.join(procRoot, "stat"),
  };
  const [firstCPU, load, memory, cpuPressure, memoryPressure, ioPressure] = await Promise.all([
    readBounded(files.stat),
    readBounded(files.load),
    readBounded(files.memory),
    readBounded(files.cpuPressure),
    readBounded(files.memoryPressure),
    readBounded(files.ioPressure),
  ]);
  await new Promise((resolve) => setTimeout(resolve, sampleMilliseconds));
  const secondCPU = await readBounded(files.stat);
  return parseHostMetrics({ cpuPressure, firstCPU, ioPressure, load, memory, memoryPressure, secondCPU });
}

export async function defaultStorageProbe(storagePath) {
  const result = await statfs(storagePath, { bigint: true });
  return {
    freeBytes: result.bavail * result.bsize,
    freeInodes: result.ffree,
    totalBytes: result.blocks * result.bsize,
    totalInodes: result.files,
  };
}

export async function defaultDatabaseProbe(timeoutMilliseconds) {
  const database = createSettingsPool(loadBootstrapSettings());
  const startedAt = performance.now();
  try {
    const result = await database.query({
      query_timeout: timeoutMilliseconds,
      text: `
        select
          pg_database_size(current_database())::text as "sizeBytes",
          current_setting('max_connections')::integer as "maximumConnections",
          coalesce((select "numbackends" from "pg_stat_database" where "datname" = current_database()), 0)::integer as "connections",
          (select count(*)::integer from "pg_stat_activity" where "datname" = current_database() and "state" = 'active') as "activeConnections",
          coalesce((select extract(epoch from max(clock_timestamp() - "xact_start")) from "pg_stat_activity" where "datname" = current_database() and "xact_start" is not null), 0)::double precision as "oldestTransactionSeconds",
          pg_is_in_recovery() as "inRecovery",
          (select count(*)::integer from "pg_stat_replication") as "replicas"
      `,
    });
    return { ...result.rows[0], queryMilliseconds: performance.now() - startedAt };
  } finally {
    await database.end();
  }
}

export function parseHostMetrics({
  cpuPressure,
  firstCPU,
  ioPressure,
  load,
  memory,
  memoryPressure,
  secondCPU,
}) {
  const first = parseCPUStat(firstCPU);
  const second = parseCPUStat(secondCPU);
  if (first.logicalCpus !== second.logicalCpus) throw new Error("The logical CPU count changed during sampling.");
  const totalDelta = second.total - first.total;
  const idleDelta = second.idle - first.idle;
  if (totalDelta <= 0 || idleDelta < 0 || idleDelta > totalDelta) throw new Error("The CPU sample is invalid.");

  const memoryValues = new Map();
  for (const line of String(memory).trim().split("\n")) {
    const match = /^([A-Za-z_()]+):\s+(\d+)\s+kB$/.exec(line.trim());
    if (match) memoryValues.set(match[1], Number(match[2]) * 1024);
  }
  const totalBytes = memoryValues.get("MemTotal");
  const availableBytes = memoryValues.get("MemAvailable");
  const swapTotalBytes = memoryValues.get("SwapTotal");
  const swapFreeBytes = memoryValues.get("SwapFree");
  if (
    !Number.isSafeInteger(totalBytes) || totalBytes <= 0 ||
    !Number.isSafeInteger(availableBytes) || availableBytes < 0 || availableBytes > totalBytes ||
    !Number.isSafeInteger(swapTotalBytes) || swapTotalBytes < 0 ||
    !Number.isSafeInteger(swapFreeBytes) || swapFreeBytes < 0 || swapFreeBytes > swapTotalBytes
  ) throw new Error("The memory sample is invalid.");

  const load1 = Number(String(load).trim().split(/\s+/)[0]);
  if (!Number.isFinite(load1) || load1 < 0) throw new Error("The load sample is invalid.");
  return {
    cpu: {
      load1PerCpu: rounded(load1 / first.logicalCpus),
      logicalCpus: first.logicalCpus,
      pressureSome10: parsePressure(cpuPressure, "some"),
      usedPercent: rounded(((totalDelta - idleDelta) / totalDelta) * 100),
    },
    ioPressureFull10: parsePressure(ioPressure, "full"),
    memory: {
      availableBytes,
      pressureFull10: parsePressure(memoryPressure, "full"),
      swapTotalBytes,
      swapUsedPercent: swapTotalBytes
        ? rounded(((swapTotalBytes - swapFreeBytes) / swapTotalBytes) * 100)
        : null,
      totalBytes,
      usedPercent: rounded(((totalBytes - availableBytes) / totalBytes) * 100),
    },
  };
}

function parseCPUStat(value) {
  const lines = String(value).trim().split("\n");
  const fields = /^cpu\s+(.+)$/.exec(lines[0] || "")?.[1]?.trim().split(/\s+/).slice(0, 8).map(Number);
  const logicalCpus = lines.filter((line) => /^cpu\d+\s/.test(line)).length;
  if (!fields || fields.length < 5 || fields.some((entry) => !Number.isSafeInteger(entry) || entry < 0) || !logicalCpus) {
    throw new Error("The CPU stat sample is invalid.");
  }
  return {
    idle: fields[3] + fields[4],
    logicalCpus,
    total: fields.reduce((total, entry) => total + entry, 0),
  };
}

function parsePressure(value, kind) {
  const line = String(value).trim().split("\n").find((candidate) => candidate.startsWith(`${kind} `));
  const match = /(?:^|\s)avg10=(\d+(?:\.\d+)?)\b/.exec(line || "");
  const number = Number(match?.[1]);
  if (!Number.isFinite(number) || number < 0 || number > 100) throw new Error("The pressure sample is invalid.");
  return rounded(number);
}

function validatedHost(value) {
  const availableBytes = safeInteger(value?.memory?.availableBytes);
  const totalBytes = safeInteger(value?.memory?.totalBytes);
  const swapTotalBytes = safeInteger(value?.memory?.swapTotalBytes);
  const usedPercent = boundedMetric(value?.memory?.usedPercent, 0, 100);
  const swapUsedPercent = value?.memory?.swapUsedPercent === null
    ? null
    : boundedMetric(value?.memory?.swapUsedPercent, 0, 100);
  if (
    !totalBytes || availableBytes > totalBytes ||
    (!swapTotalBytes && swapUsedPercent !== null) ||
    usedPercent !== rounded(((totalBytes - availableBytes) / totalBytes) * 100)
  ) throw new Error("The host memory sample is inconsistent.");
  return Object.freeze({
    cpu: Object.freeze({
      load1PerCpu: boundedMetric(value?.cpu?.load1PerCpu, 0, 1_000),
      logicalCpus: boundedIntegerMetric(value?.cpu?.logicalCpus, 1, 65_536),
      pressureSome10: boundedMetric(value?.cpu?.pressureSome10, 0, 100),
      usedPercent: boundedMetric(value?.cpu?.usedPercent, 0, 100),
    }),
    ioPressureFull10: boundedMetric(value?.ioPressureFull10, 0, 100),
    memory: Object.freeze({
      availableBytes,
      pressureFull10: boundedMetric(value?.memory?.pressureFull10, 0, 100),
      swapTotalBytes,
      swapUsedPercent,
      totalBytes,
      usedPercent,
    }),
  });
}

function validatedStorage(value, code) {
  const freeBytes = safeInteger(value?.freeBytes);
  const totalBytes = safeInteger(value?.totalBytes);
  const freeInodes = safeInteger(value?.freeInodes);
  const totalInodes = safeInteger(value?.totalInodes);
  if (!totalBytes || freeBytes > totalBytes || !totalInodes || freeInodes > totalInodes) {
    throw new Error("The storage sample is invalid.");
  }
  return Object.freeze({
    code,
    freeBytes,
    freeInodes,
    totalBytes,
    totalInodes,
    usedInodesPercent: rounded(((totalInodes - freeInodes) / totalInodes) * 100),
    usedPercent: rounded(((totalBytes - freeBytes) / totalBytes) * 100),
  });
}

function validatedDatabase(value) {
  const connections = boundedIntegerMetric(value?.connections, 0, 1_000_000);
  const maximumConnections = boundedIntegerMetric(value?.maximumConnections, 1, 1_000_000);
  const activeConnections = boundedIntegerMetric(value?.activeConnections, 0, 1_000_000);
  const replicas = boundedIntegerMetric(value?.replicas, 0, 10_000);
  if (connections > maximumConnections || activeConnections > connections || typeof value?.inRecovery !== "boolean") {
    throw new Error("The database sample is invalid.");
  }
  return Object.freeze({
    activeConnections,
    connections,
    connectionsUsedPercent: rounded((connections / maximumConnections) * 100),
    maximumConnections,
    mode: value.inRecovery ? "standby" : "primary",
    oldestTransactionSeconds: boundedMetric(value?.oldestTransactionSeconds, 0, Number.MAX_SAFE_INTEGER),
    queryMilliseconds: boundedMetric(value?.queryMilliseconds, 0, Number.MAX_SAFE_INTEGER),
    replicas,
    sizeBytes: safeInteger(value?.sizeBytes),
  });
}

function validatedThresholds(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("Capacity thresholds are invalid.");
  const checked = {
    maximumCpuPressureSome10: thresholdNumber(value.maximumCpuPressureSome10, "CPU pressure", 0, 100),
    maximumCpuUsedPercent: thresholdNumber(value.maximumCpuUsedPercent, "CPU use", 1, 100),
    maximumDatabaseBytes: thresholdInteger(value.maximumDatabaseBytes, "database bytes", 1, Number.MAX_SAFE_INTEGER),
    maximumDatabaseConnectionsUsedPercent: thresholdNumber(value.maximumDatabaseConnectionsUsedPercent, "database connection use", 1, 100),
    maximumDatabaseQueryMilliseconds: thresholdInteger(value.maximumDatabaseQueryMilliseconds, "database query", 1, 60_000),
    maximumDatabaseTransactionSeconds: thresholdInteger(value.maximumDatabaseTransactionSeconds, "database transaction", 1, 86_400),
    maximumIOPressureFull10: thresholdNumber(value.maximumIOPressureFull10, "I/O pressure", 0, 100),
    maximumLoad1PerCpu: thresholdNumber(value.maximumLoad1PerCpu, "load per CPU", 0.01, 1_000),
    maximumMemoryPressureFull10: thresholdNumber(value.maximumMemoryPressureFull10, "memory pressure", 0, 100),
    maximumMemoryUsedPercent: thresholdNumber(value.maximumMemoryUsedPercent, "memory use", 1, 100),
    maximumStorageUsedInodesPercent: thresholdNumber(value.maximumStorageUsedInodesPercent, "storage inode use", 1, 100),
    maximumStorageUsedPercent: thresholdNumber(value.maximumStorageUsedPercent, "storage use", 1, 100),
    maximumSwapUsedPercent: thresholdNumber(value.maximumSwapUsedPercent, "swap use", 1, 100),
    minimumStorageFreeBytes: thresholdInteger(value.minimumStorageFreeBytes, "storage free bytes", 1, Number.MAX_SAFE_INTEGER),
    minimumStorageFreeInodes: thresholdInteger(value.minimumStorageFreeInodes, "storage free inodes", 1, Number.MAX_SAFE_INTEGER),
    requirePrimaryReplica: validatedBoolean(value.requirePrimaryReplica, "primary replica"),
    sampleMilliseconds: thresholdInteger(value.sampleMilliseconds, "sample interval", 100, 10_000),
    timeoutMilliseconds: thresholdInteger(value.timeoutMilliseconds, "timeout", 100, 60_000),
  };
  return Object.freeze(checked);
}

function validatedStorageTargets(value) {
  if (!Array.isArray(value) || !value.length || value.length > STORAGE_CODES.length) {
    throw new Error("Capacity readiness requires one to four storage targets.");
  }
  const seen = new Set();
  return Object.freeze(value.map((target) => {
    if (!target || typeof target !== "object" || !STORAGE_CODES.includes(target.code) || seen.has(target.code)) {
      throw new Error("A capacity storage target is invalid or duplicated.");
    }
    seen.add(target.code);
    return Object.freeze({
      code: target.code,
      path: validatedAbsolutePath(target.path, "storage path"),
    });
  }));
}

function validatedScope(value) {
  if (!["engine", "gateway"].includes(value)) throw new Error("Capacity readiness scope must be gateway or engine.");
  return value;
}

function validatedAbsolutePath(value, name) {
  if (typeof value !== "string" || !path.isAbsolute(value) || value.includes("\0")) {
    throw new Error(`Capacity readiness ${name} must be an absolute path.`);
  }
  return value;
}

function thresholdNumber(value, name, minimum, maximum) {
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`Capacity readiness ${name} threshold is invalid.`);
  }
  return value;
}

function thresholdInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Capacity readiness ${name} threshold is invalid.`);
  }
  return value;
}

function validatedBoolean(value, name) {
  if (typeof value !== "boolean") throw new Error(`Capacity readiness ${name} threshold is invalid.`);
  return value;
}

function boundedMetric(value, minimum, maximum) {
  const number = typeof value === "string" && value.trim() ? Number(value) : value;
  if (!Number.isFinite(number) || number < minimum || number > maximum) throw new Error("A capacity metric is invalid.");
  return rounded(number);
}

function boundedIntegerMetric(value, minimum, maximum) {
  const number = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) throw new Error("A capacity metric is invalid.");
  return number;
}

function safeInteger(value) {
  const number = typeof value === "bigint"
    ? Number(value)
    : typeof value === "string" && /^\d+$/.test(value)
      ? Number(value)
      : value;
  if (!Number.isSafeInteger(number) || number < 0) throw new Error("A capacity integer is invalid.");
  return number;
}

async function readBounded(filename) {
  const content = await readFile(filename, "utf8");
  if (!content.length || Buffer.byteLength(content) > MAXIMUM_PROC_BYTES) throw new Error("A host metric file is invalid.");
  return content;
}

async function settle(promise) {
  try {
    return { status: "fulfilled", value: await promise };
  } catch {
    return { status: "rejected" };
  }
}

function validDate(value) {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error("A capacity timestamp is invalid.");
  return value;
}

function rounded(value) {
  return Number(value.toFixed(2));
}

function parseArguments(argumentsList) {
  const thresholds = { ...policy.capacity };
  const parsed = { storageTargets: [], thresholds };
  const numericOptions = {
    "--maximum-cpu-pressure-some-10": "maximumCpuPressureSome10",
    "--maximum-cpu-used-percent": "maximumCpuUsedPercent",
    "--maximum-database-bytes": "maximumDatabaseBytes",
    "--maximum-database-connections-used-percent": "maximumDatabaseConnectionsUsedPercent",
    "--maximum-database-query-ms": "maximumDatabaseQueryMilliseconds",
    "--maximum-database-transaction-seconds": "maximumDatabaseTransactionSeconds",
    "--maximum-io-pressure-full-10": "maximumIOPressureFull10",
    "--maximum-load-1-per-cpu": "maximumLoad1PerCpu",
    "--maximum-memory-pressure-full-10": "maximumMemoryPressureFull10",
    "--maximum-memory-used-percent": "maximumMemoryUsedPercent",
    "--maximum-storage-used-inodes-percent": "maximumStorageUsedInodesPercent",
    "--maximum-storage-used-percent": "maximumStorageUsedPercent",
    "--maximum-swap-used-percent": "maximumSwapUsedPercent",
    "--minimum-storage-free-bytes": "minimumStorageFreeBytes",
    "--minimum-storage-free-inodes": "minimumStorageFreeInodes",
    "--sample-ms": "sampleMilliseconds",
    "--timeout-ms": "timeoutMilliseconds",
  };
  for (let index = 0; index < argumentsList.length; index += 2) {
    const name = argumentsList[index];
    const value = argumentsList[index + 1];
    if (!value) throw new Error(`Capacity readiness option ${name || "(missing)"} requires a value.`);
    if (name === "--scope") parsed.scope = value;
    else if (name === "--proc") parsed.procRoot = value;
    else if (name === "--storage") {
      const separator = value.indexOf("=");
      parsed.storageTargets.push({ code: value.slice(0, separator), path: value.slice(separator + 1) });
    } else if (name === "--require-primary-replica") {
      if (!["true", "false"].includes(value)) throw new Error("Capacity readiness replica option must be true or false.");
      thresholds.requirePrimaryReplica = value === "true";
    } else if (numericOptions[name]) {
      thresholds[numericOptions[name]] = Number(value);
    } else {
      throw new Error(`Unknown capacity readiness option ${name}.`);
    }
  }
  return parsed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCapacityReadinessProbe(parseArguments(process.argv.slice(2)))
    .then((result) => console.info(JSON.stringify(result, null, 2)))
    .catch((error) => {
      if (error?.result) console.error(JSON.stringify(error.result, null, 2));
      console.error(error instanceof CapacityReadinessError
        ? error.message
        : "VASI capacity readiness probe failed.");
      process.exitCode = 1;
    });
}
