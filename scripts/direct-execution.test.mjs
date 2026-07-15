import { spawnSync } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { isDirectExecution } from "./direct-execution.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const helper = path.join(root, "scripts", "direct-execution.mjs");
const activation = path.join(root, "scripts", "activate-production-release.mjs");
const staging = path.join(root, "scripts", "stage-production-release.mjs");
const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })
  ));
});

describe("direct operational CLI execution identity", () => {
  it("matches physical, file-symlink, and release-selector paths", async () => {
    const temporary = await mkdtemp(path.join(tmpdir(), "vasi-direct-execution-"));
    temporaryDirectories.push(temporary);
    const fileLink = path.join(temporary, "direct-execution.mjs");
    const releaseLink = path.join(temporary, "current");
    await symlink(helper, fileLink);
    await symlink(root, releaseLink, "dir");

    const moduleURL = pathToFileURL(helper).href;
    expect(isDirectExecution(moduleURL, helper)).toBe(true);
    expect(isDirectExecution(moduleURL, fileLink)).toBe(true);
    expect(isDirectExecution(
      pathToFileURL(activation).href,
      path.join(releaseLink, "scripts", "activate-production-release.mjs"),
    )).toBe(true);
  });

  it("fails closed for unrelated, missing, malformed, and oversized paths", async () => {
    const temporary = await mkdtemp(path.join(tmpdir(), "vasi-direct-execution-denial-"));
    temporaryDirectories.push(temporary);
    const unrelated = path.join(temporary, "unrelated.mjs");
    const loop = path.join(temporary, "loop.mjs");
    await writeFile(unrelated, "export {};\n");
    await symlink(loop, loop);
    const moduleURL = pathToFileURL(helper).href;

    expect(isDirectExecution(moduleURL, unrelated)).toBe(false);
    expect(isDirectExecution(moduleURL, path.join(temporary, "missing.mjs"))).toBe(false);
    expect(isDirectExecution(moduleURL, loop)).toBe(false);
    expect(isDirectExecution("https://example.test/module.mjs", helper)).toBe(false);
    expect(isDirectExecution(moduleURL, "bad\0path")).toBe(false);
    expect(isDirectExecution(moduleURL, "x".repeat(4_097))).toBe(false);
    expect(isDirectExecution(moduleURL, undefined)).toBe(false);
  });

  it("runs the activation CLI through a selected release path exactly as a physical path", async () => {
    const temporary = await mkdtemp(path.join(tmpdir(), "vasi-selected-release-cli-"));
    temporaryDirectories.push(temporary);
    const releaseLink = path.join(temporary, "current");
    await symlink(root, releaseLink, "dir");
    const selected = path.join(releaseLink, "scripts", "activate-production-release.mjs");

    for (const entrypoint of [activation, selected]) {
      const result = spawnSync(process.execPath, [entrypoint], {
        encoding: "utf8",
        timeout: 5_000,
      });
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("Usage: node scripts/activate-production-release.mjs");
    }
  });

  it("does not execute main when the activation module is imported", () => {
    const result = spawnSync(process.execPath, [
      "--input-type=module",
      "--eval",
      `await import(${JSON.stringify(pathToFileURL(activation).href)});`,
    ], {
      encoding: "utf8",
      timeout: 5_000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });

  it("runs the staging CLI through a selected release path exactly as a physical path", async () => {
    const temporary = await mkdtemp(path.join(tmpdir(), "vasi-selected-staging-cli-"));
    temporaryDirectories.push(temporary);
    const releaseLink = path.join(temporary, "current");
    await symlink(root, releaseLink, "dir");
    const selected = path.join(releaseLink, "scripts", "stage-production-release.mjs");

    for (const entrypoint of [staging, selected]) {
      const result = spawnSync(process.execPath, [entrypoint], {
        encoding: "utf8",
        timeout: 5_000,
      });
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(64);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("Usage: node scripts/stage-production-release.mjs");
    }
  });

  it("does not execute main when the staging module is imported", () => {
    const result = spawnSync(process.execPath, [
      "--input-type=module",
      "--eval",
      `await import(${JSON.stringify(pathToFileURL(staging).href)});`,
    ], {
      encoding: "utf8",
      timeout: 5_000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });
});
