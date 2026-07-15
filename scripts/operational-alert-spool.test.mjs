import { spawn } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const script = path.join(repositoryRoot, "scripts", "operational-alert-spool.sh");
const temporaryRoots = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) =>
    rm(root, { force: true, recursive: true })
  ));
});

describe("durable operational-alert handoff", () => {
  it("records, exposes, and explicitly acknowledges a privacy-bounded failure", async () => {
    const root = await testRoot();
    const empty = await run(root, ["status", "gateway"]);
    expect(empty.code).toBe(0);
    expect(JSON.parse(empty.stdout)).toEqual({
      invalidRecords: 0,
      oldestPendingAgeSeconds: 0,
      overflowCount: 0,
      pendingRecords: 0,
      role: "gateway",
      schema: "vasi-operational-alert-spool/v1",
      status: "ready",
    });

    const recorded = await run(
      root,
      ["record", "gateway", "vasi-gateway-capacity-readiness.service"],
      {
        MONITOR_EXIT_CODE: "exited",
        MONITOR_EXIT_STATUS: "secret@example.test",
        MONITOR_INVOCATION_ID: "not-an-invocation-id",
        MONITOR_SERVICE_RESULT: "exit-code",
        MONITOR_UNIT: "vasi-gateway-capacity-readiness.service",
      },
    );
    expect(recorded.code).toBe(0);
    const recordResult = JSON.parse(recorded.stdout);
    expect(recordResult).toMatchObject({
      role: "gateway",
      schema: "vasi-operational-alert-record-result/v1",
      status: "recorded",
    });

    const pending = await run(root, ["status", "gateway"]);
    expect(pending.code).toBe(1);
    expect(JSON.parse(pending.stdout)).toMatchObject({
      invalidRecords: 0,
      overflowCount: 0,
      pendingRecords: 1,
      status: "pending",
    });

    const next = await run(root, ["next", "gateway"]);
    expect(next.code).toBe(0);
    const alert = JSON.parse(next.stdout);
    expect(alert).toEqual({
      exitCode: "exited",
      exitStatus: "unknown",
      invocationId: "unknown",
      occurredAt: expect.stringMatching(/^[0-9]{8}T[0-9]{6}Z$/),
      recordId: recordResult.recordId,
      role: "gateway",
      schema: "vasi-operational-alert/v1",
      serviceResult: "exit-code",
      sourceUnit: "vasi-gateway-capacity-readiness.service",
    });
    expect(next.stdout).not.toMatch(/email|tenant|participant|request|secret@example|hostname|endpoint/i);

    const pendingFile = path.join(root, "gateway", "pending", recordResult.recordId);
    expect((await lstat(pendingFile)).mode & 0o777).toBe(0o600);
    for (const directory of [
      path.join(root, "gateway"),
      path.join(root, "gateway", "pending"),
      path.join(root, "gateway", "acknowledged"),
    ]) expect((await lstat(directory)).mode & 0o777).toBe(0o700);

    expect((await run(root, [
      "acknowledge", "gateway", recordResult.recordId, "customer email",
    ])).code).toBe(1);
    expect((await run(root, [
      "acknowledge", "gateway", "../../outside", "incident-1",
    ])).code).toBe(1);

    const acknowledged = await run(root, [
      "acknowledge", "gateway", recordResult.recordId, "incident-1",
    ]);
    expect(acknowledged.code).toBe(0);
    expect(JSON.parse(acknowledged.stdout)).toMatchObject({
      recordId: recordResult.recordId,
      role: "gateway",
      schema: "vasi-operational-alert-acknowledgement/v1",
      status: "acknowledged",
    });
    const archive = await readdir(path.join(root, "gateway", "acknowledged"));
    expect(archive).toHaveLength(1);
    expect(archive[0]).toContain("--ack-");
    expect(archive[0]).toContain("-incident-1.json");
    expect((await lstat(path.join(root, "gateway", "acknowledged", archive[0]))).mode & 0o777)
      .toBe(0o600);
    expect((await run(root, ["status", "gateway"]))).toMatchObject({ code: 0 });
    expect((await run(root, ["next", "gateway"])).stdout).toBe("null\n");
  }, 20_000);

  it("uses exact role/unit and systemd monitor bindings", async () => {
    const root = await testRoot();
    for (const [role, unit] of [
      ["gateway", "vasi-gateway-backup-check.service"],
      ["engine", "vasi-engine-egress-boundary.service"],
      ["edge", "vasi-edge-runtime-readiness.service"],
    ]) {
      const result = await run(root, ["record", role, unit], { MONITOR_UNIT: unit });
      expect(result.code).toBe(0);
    }
    expect((await run(root, [
      "record", "gateway", "vasi-gateway-alert-readiness.service",
    ])).code).toBe(1);
    expect((await run(root, [
      "record", "gateway", "vasi-gateway-backup-check.service",
    ], { MONITOR_UNIT: "vasi-gateway-backup-create.service" })).code).toBe(1);
    expect((await run(root, [
      "record", "unknown", "vasi-gateway-backup-check.service",
    ])).code).toBe(1);
  });

  it("fails closed on unsafe state, symlinks, and malformed records", async () => {
    const unsafeModeRoot = await testRoot();
    await run(unsafeModeRoot, ["status", "engine"]);
    await chmod(path.join(unsafeModeRoot, "engine"), 0o755);
    expect((await run(unsafeModeRoot, ["status", "engine"])).code).toBe(1);

    const symlinkRoot = await testRoot();
    await run(symlinkRoot, ["status", "edge"]);
    const outside = path.join(symlinkRoot, "outside");
    await mkdir(outside, { mode: 0o700 });
    await rm(path.join(symlinkRoot, "edge"), { recursive: true });
    await symlink(outside, path.join(symlinkRoot, "edge"));
    expect((await run(symlinkRoot, ["status", "edge"])).code).toBe(1);

    const malformedRoot = await testRoot();
    await run(malformedRoot, ["status", "gateway"]);
    const malformed = path.join(malformedRoot, "gateway", "pending", "foreign.json");
    await writeFile(malformed, '{"recipient":"person@example.test"}\n', { mode: 0o600 });
    const status = await run(malformedRoot, ["status", "gateway"]);
    expect(status.code).toBe(1);
    expect(JSON.parse(status.stdout)).toMatchObject({ invalidRecords: 1, status: "invalid" });
    expect((await run(malformedRoot, ["next", "gateway"])).code).toBe(1);
  });

  it("preserves overflow visibility instead of deleting unacknowledged records", async () => {
    const root = await testRoot();
    await run(root, ["status", "gateway"]);
    const pendingDirectory = path.join(root, "gateway", "pending");
    for (let index = 0; index < 256; index += 1) {
      const suffix = index.toString(16).padStart(32, "0");
      const recordId = `20260101T000000Z-${suffix}.json`;
      const record = {
        exitCode: "exited",
        exitStatus: "1",
        invocationId: "unknown",
        occurredAt: "20260101T000000Z",
        recordId,
        role: "gateway",
        schema: "vasi-operational-alert/v1",
        serviceResult: "exit-code",
        sourceUnit: "vasi-gateway-backup-check.service",
      };
      const filename = path.join(pendingDirectory, recordId);
      await writeFile(filename, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    }

    const overflowRecord = await run(root, [
      "record", "gateway", "vasi-gateway-backup-create.service",
    ], { MONITOR_UNIT: "vasi-gateway-backup-create.service" });
    expect(overflowRecord.code).toBe(0);
    expect(JSON.parse(overflowRecord.stdout).recordId).toBe("overflow");
    const status = await run(root, ["status", "gateway"]);
    expect(status.code).toBe(1);
    expect(JSON.parse(status.stdout)).toMatchObject({
      invalidRecords: 0,
      overflowCount: 1,
      pendingRecords: 256,
      status: "pending",
    });
    const next = JSON.parse((await run(root, ["next", "gateway"])).stdout);
    expect(next).toMatchObject({
      overflowCount: 1,
      recordId: "overflow",
      schema: "vasi-operational-alert-overflow/v1",
    });
    expect((await run(root, [
      "acknowledge", "gateway", "overflow", "overflow-reviewed",
    ])).code).toBe(0);
    await expect(lstat(path.join(root, "gateway", "overflow.json"))).rejects.toThrow();
    expect(await readdir(pendingDirectory)).toHaveLength(256);
  }, 60_000);

  it("serializes concurrent failure records without collisions", async () => {
    const root = await testRoot();
    const unit = "vasi-engine-operational-readiness.service";
    const results = await Promise.all([0, 1, 2].map((index) => run(
      root,
      ["record", "engine", unit],
      {
        MONITOR_EXIT_STATUS: String(index + 1),
        MONITOR_INVOCATION_ID: index.toString(16).padStart(32, "0"),
        MONITOR_UNIT: unit,
      },
    )));
    expect(results.map((result) => result.code)).toEqual([0, 0, 0]);
    const records = await readdir(path.join(root, "engine", "pending"));
    expect(records).toHaveLength(3);
    expect(new Set(records).size).toBe(3);
  }, 10_000);
});

async function testRoot() {
  const created = await mkdtemp(path.join(tmpdir(), "vasi-operational-alert-test-"));
  const root = await realpath(created);
  await chmod(root, 0o700);
  temporaryRoots.push(root);
  return root;
}

function run(root, args, extraEnvironment = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn("/bin/sh", [script, ...args], {
      env: {
        PATH: process.env.PATH,
        VASI_OPERATIONAL_ALERT_TEST_ROOT: root,
        ...extraEnvironment,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code, signal, stderr, stdout }));
  });
}
