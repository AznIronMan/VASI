import { describe, expect, it } from "vitest";

import packageJSON from "../package.json" with { type: "json" };
import {
  parseHostMetrics,
  runCapacityReadinessProbe,
} from "./probe-capacity-readiness.mjs";

describe("host and PostgreSQL capacity readiness", () => {
  it("returns a bounded ready result without paths, endpoints, process data, or customer fields", async () => {
    const result = await runCapacityReadinessProbe(readyOptions());
    expect(result).toMatchObject({
      database: {
        connections: 10,
        connectionsUsedPercent: 10,
        maximumConnections: 100,
        mode: "primary",
        replicas: 0,
      },
      expectedVersion: packageJSON.version,
      host: {
        cpu: { load1PerCpu: 0.5, logicalCpus: 4, pressureSome10: 0.1, usedPercent: 25 },
        memory: { usedPercent: 50 },
      },
      reasons: [],
      scope: "engine",
      status: "ready",
      storage: [{ code: "system", usedInodesPercent: 20, usedPercent: 20 }],
    });
    const serialized = JSON.stringify(result);
    for (const forbidden of [
      "/host/proc",
      "/host/storage",
      "postgresql://",
      "participant",
      "tenantId",
      "process",
      "credential",
    ]) expect(serialized).not.toContain(forbidden);
  });

  it("fails every bounded capacity threshold with fixed reason codes", async () => {
    await expect(runCapacityReadinessProbe({
      ...readyOptions(),
      inspectDatabase: async () => ({
        activeConnections: 89,
        connections: 90,
        inRecovery: false,
        maximumConnections: 100,
        oldestTransactionSeconds: 301,
        queryMilliseconds: 2_001,
        replicas: 0,
        sizeBytes: 536_870_912_001,
      }),
      inspectHost: async () => ({
        cpu: { load1PerCpu: 1.51, logicalCpus: 4, pressureSome10: 80.01, usedPercent: 90.01 },
        ioPressureFull10: 10.01,
        memory: {
          availableBytes: 0,
          pressureFull10: 10.01,
          swapTotalBytes: 100,
          swapUsedPercent: 80.01,
          totalBytes: 10,
          usedPercent: 100,
        },
      }),
      inspectStorage: async () => ({
        freeBytes: 1,
        freeInodes: 1,
        totalBytes: 10_000_000_000,
        totalInodes: 1_000_000,
      }),
      thresholds: { ...readyOptions().thresholds, requirePrimaryReplica: true },
    })).rejects.toMatchObject({
      result: {
        reasons: [
          "cpu_stall_pressure",
          "cpu_use_pressure",
          "database_connection_pressure",
          "database_query_pressure",
          "database_replica_missing",
          "database_size_pressure",
          "database_transaction_pressure",
          "io_stall_pressure",
          "load_pressure",
          "memory_pressure",
          "memory_stall_pressure",
          "storage_system_bytes_pressure",
          "storage_system_inode_pressure",
          "swap_pressure",
        ],
        status: "critical",
      },
    });
  });

  it("fails closed with bounded reasons when host, database, or individual storage metrics are unavailable", async () => {
    await expect(runCapacityReadinessProbe({
      ...readyOptions(),
      inspectDatabase: async () => { throw new Error("postgresql://secret@private.example/customer"); },
      inspectHost: async () => { throw new Error("/proc/private/details"); },
      inspectStorage: async (storagePath) => {
        if (storagePath.includes("docker")) throw new Error("/var/lib/docker");
        return { freeBytes: 8_000_000_000, freeInodes: 800_000, totalBytes: 10_000_000_000, totalInodes: 1_000_000 };
      },
      storageTargets: [
        { code: "system", path: "/host/storage" },
        { code: "docker", path: "/host/docker" },
      ],
    })).rejects.toMatchObject({
      result: {
        reasons: ["database_metrics_unavailable", "host_metrics_unavailable", "storage_docker_unavailable"],
        storage: [{ code: "system" }],
      },
    });
  });

  it("maps malformed aggregate metrics to unavailable reasons", async () => {
    await expect(runCapacityReadinessProbe({
      ...readyOptions(),
      inspectDatabase: async () => ({ ...databaseSample(), connections: 101 }),
      inspectHost: async () => ({ ...hostSample(), ioPressureFull10: Number.NaN }),
      inspectStorage: async () => ({ freeBytes: 11, freeInodes: 1, totalBytes: 10, totalInodes: 10 }),
    })).rejects.toMatchObject({
      result: {
        database: null,
        host: null,
        reasons: ["database_metrics_unavailable", "host_metrics_unavailable", "storage_system_unavailable"],
        storage: [],
      },
    });
  });

  it("parses only bounded aggregate Linux proc metrics", () => {
    expect(parseHostMetrics({
      cpuPressure: "some avg10=1.25 avg60=0.50 avg300=0.10 total=123\n",
      firstCPU: "cpu 100 0 50 800 50 0 0 0 0 0\ncpu0 0\ncpu1 0\n",
      ioPressure: "some avg10=0.10 avg60=0.10 avg300=0.10 total=10\nfull avg10=0.25 avg60=0.10 avg300=0.10 total=5\n",
      load: "1.00 0.50 0.25 1/100 1\n",
      memory: "MemTotal:       1000000 kB\nMemAvailable:    400000 kB\nSwapTotal:        100000 kB\nSwapFree:          50000 kB\n",
      memoryPressure: "some avg10=0.50 avg60=0.10 avg300=0.10 total=10\nfull avg10=0.75 avg60=0.10 avg300=0.10 total=5\n",
      secondCPU: "cpu 150 0 60 840 50 0 0 0 0 0\ncpu0 0\ncpu1 0\n",
    })).toEqual({
      cpu: { load1PerCpu: 0.5, logicalCpus: 2, pressureSome10: 1.25, usedPercent: 60 },
      ioPressureFull10: 0.25,
      memory: {
        availableBytes: 409_600_000,
        pressureFull10: 0.75,
        swapTotalBytes: 102_400_000,
        swapUsedPercent: 50,
        totalBytes: 1_024_000_000,
        usedPercent: 60,
      },
    });
    expect(() => parseHostMetrics({
      cpuPressure: "private data",
      firstCPU: "private data",
      ioPressure: "private data",
      load: "private data",
      memory: "private data",
      memoryPressure: "private data",
      secondCPU: "private data",
    })).toThrow();
  });

  it("requires a known scope, explicit bounded storage targets, absolute proc paths, and complete thresholds", async () => {
    await expect(runCapacityReadinessProbe({ ...readyOptions(), scope: "other" })).rejects.toThrow("gateway or engine");
    await expect(runCapacityReadinessProbe({ ...readyOptions(), procRoot: "relative" })).rejects.toThrow("absolute path");
    await expect(runCapacityReadinessProbe({ ...readyOptions(), storageTargets: [] })).rejects.toThrow("one to four");
    await expect(runCapacityReadinessProbe({
      ...readyOptions(),
      storageTargets: [{ code: "customer-name", path: "/host/storage" }],
    })).rejects.toThrow("invalid or duplicated");
    await expect(runCapacityReadinessProbe({
      ...readyOptions(),
      thresholds: { ...readyOptions().thresholds, maximumCpuUsedPercent: 101 },
    })).rejects.toThrow("CPU use threshold");
  });
});

function readyOptions() {
  return {
    inspectDatabase: async () => databaseSample(),
    inspectHost: async () => hostSample(),
    inspectStorage: async () => ({
      freeBytes: 8_000_000_000,
      freeInodes: 800_000,
      totalBytes: 10_000_000_000,
      totalInodes: 1_000_000,
    }),
    now: new Date("2026-07-14T18:00:00.000Z"),
    procRoot: "/host/proc",
    scope: "engine",
    storageTargets: [{ code: "system", path: "/host/storage" }],
    thresholds: {
      maximumCpuPressureSome10: 80,
      maximumCpuUsedPercent: 90,
      maximumDatabaseBytes: 536_870_912_000,
      maximumDatabaseConnectionsUsedPercent: 80,
      maximumDatabaseQueryMilliseconds: 2_000,
      maximumDatabaseTransactionSeconds: 300,
      maximumIOPressureFull10: 10,
      maximumLoad1PerCpu: 1.5,
      maximumMemoryPressureFull10: 10,
      maximumMemoryUsedPercent: 90,
      maximumStorageUsedInodesPercent: 85,
      maximumStorageUsedPercent: 85,
      maximumSwapUsedPercent: 80,
      minimumStorageFreeBytes: 5_368_709_120,
      minimumStorageFreeInodes: 100_000,
      requirePrimaryReplica: false,
      sampleMilliseconds: 1_000,
      timeoutMilliseconds: 10_000,
    },
  };
}

function hostSample() {
  return {
    cpu: { load1PerCpu: 0.5, logicalCpus: 4, pressureSome10: 0.1, usedPercent: 25 },
    ioPressureFull10: 0.1,
    memory: {
      availableBytes: 4_000_000_000,
      pressureFull10: 0.1,
      swapTotalBytes: 2_000_000_000,
      swapUsedPercent: 10,
      totalBytes: 8_000_000_000,
      usedPercent: 50,
    },
  };
}

function databaseSample() {
  return {
    activeConnections: 2,
    connections: 10,
    inRecovery: false,
    maximumConnections: 100,
    oldestTransactionSeconds: 1,
    queryMilliseconds: 12,
    replicas: 0,
    sizeBytes: 1_000_000,
  };
}
