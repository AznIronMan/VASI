import { createServer } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import { percentile, runReadinessLoadProbe } from "./probe-readiness-load.mjs";

let server;

afterEach(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  server = undefined;
});

describe("bounded readiness load probe", () => {
  it("measures only validated read-only readiness endpoints", async () => {
    server = createServer((request, response) => {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(request.url === "/api/health"
        ? { status: "ok", version: "test" }
        : { organizationName: "Example", productName: "Verify" }));
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const result = await runReadinessLoadProbe({
      allowHttpLoopback: true,
      concurrency: 4,
      maximumP95Milliseconds: 5_000,
      origin: `http://127.0.0.1:${address.port}`,
      requests: 20,
    });
    expect(result.failed).toBe(0);
    expect(result.requests).toBe(20);
  });

  it("rejects unsafe origins and calculates nearest-rank percentiles", async () => {
    await expect(runReadinessLoadProbe({ origin: "http://example.test" })).rejects.toThrow("require HTTPS");
    expect(percentile([1, 2, 3, 4, 5], 95)).toBe(5);
  });
});
