import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  inspectTrackedSource,
  runtimeContractForImage,
  validateAutomationContract,
  validateComposeContracts,
  validateVersionAlignment,
} from "./release-assurance.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("release assurance policy", () => {
  it("keeps private/runtime material out of tracked source", async () => {
    const result = await inspectTrackedSource(root);
    expect(result.forbiddenPaths).toEqual([]);
    expect(result.secretFindings).toEqual([]);
    expect(result.files.length).toBeGreaterThan(100);
  });

  it("aligns all authoritative version declarations", async () => {
    const result = await validateVersionAlignment(root);
    expect(result.mismatches).toEqual([]);
  });

  it("keeps public and private runtime services hardened", async () => {
    const result = await validateComposeContracts(root);
    expect(result.failures).toEqual([]);
  });

  it("keeps release automation least-privileged and commit-pinned", async () => {
    const result = await validateAutomationContract(root);
    expect(result.failures).toEqual([]);
    expect(result.jobs).toBeGreaterThan(0);
  });

  it("requires an explicit non-root readability contract for every release image role", () => {
    expect(runtimeContractForImage("vasi:0.19.1")).toMatchObject({
      entrypoint: "server.js",
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage("registry.example.test/vasi-engine:0.19.1")).toMatchObject({
      entrypoint: "services/engine/server.mjs",
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage(`vasi-engine-tools@sha256:${"a".repeat(64)}`)).toMatchObject({
      entrypoint: "scripts/settings.mjs",
      imageUser: "",
      runUser: "0:0",
    });
    expect(() => runtimeContractForImage("unreviewed-image:latest")).toThrow(/no supported runtime contract/i);
    expect(() => runtimeContractForImage("vasi:latest", [{
      entrypoint: "../server.js",
      image: "vasi",
      imageUser: "node",
      runUser: "1000:1000",
    }])).toThrow(/no supported runtime contract/i);
  });
});
