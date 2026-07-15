import { describe, expect, it } from "vitest";

import {
  boundedJSONObject,
  GATEWAY_JSON_MAXIMUM_BYTES,
  readBoundedJSONObject,
} from "@/lib/bounded-json";

describe("bounded gateway JSON", () => {
  it("accepts an object delivered in multiple chunks at the exact byte limit", async () => {
    const source = JSON.stringify({ value: "x".repeat(GATEWAY_JSON_MAXIMUM_BYTES - 12) });
    expect(new TextEncoder().encode(source)).toHaveLength(GATEWAY_JSON_MAXIMUM_BYTES);
    const request = streamedRequest([
      source.slice(0, 17),
      source.slice(17, 32_000),
      source.slice(32_000),
    ], String(GATEWAY_JSON_MAXIMUM_BYTES));

    await expect(readBoundedJSONObject(request)).resolves.toEqual({
      value: "x".repeat(GATEWAY_JSON_MAXIMUM_BYTES - 12),
    });
  });

  it("counts UTF-8 bytes instead of JavaScript characters", async () => {
    const source = JSON.stringify({ value: "é".repeat(40_000) });
    expect(source.length).toBeLessThan(GATEWAY_JSON_MAXIMUM_BYTES);
    const result = await boundedJSONObject(streamedRequest([source]));

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.response.status).toBe(413);
  });

  it("rejects an oversized advertised length without reading the stream", async () => {
    let bodyRead = false;
    const request = {
      get body() {
        bodyRead = true;
        throw new Error("The body must not be inspected.");
      },
      headers: new Headers({
        "content-length": String(GATEWAY_JSON_MAXIMUM_BYTES + 1),
      }),
    } as unknown as Request;

    const result = await boundedJSONObject(request);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(413);
      expect(result.response.headers.get("cache-control")).toBe("no-store");
      await expect(result.response.json()).resolves.toEqual({ error: "The request body is too large." });
    }
    expect(bodyRead).toBe(false);
  });

  it.each([
    ["malformed JSON", ["{\"value\":"], undefined],
    ["non-object JSON", ["[]"], undefined],
    ["invalid UTF-8", [new Uint8Array([0xff, 0xfe])], undefined],
    ["malformed length", ["{}"], "1, 2"],
    ["mismatched length", ["{}"], "3"],
  ])("returns a generic 400 for %s", async (_name, chunks, contentLength) => {
    const result = await boundedJSONObject(streamedRequest(chunks, contentLength));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(400);
      await expect(result.response.json()).resolves.toEqual({ error: "Invalid request." });
    }
  });

  it("hides stream read failures", async () => {
    const request = new Request("https://vsign.example.test/api/test", {
      body: new ReadableStream<Uint8Array>({
        pull() {
          throw new Error("transport implementation detail");
        },
      }),
      duplex: "half",
      method: "POST",
    } as RequestInit);
    const result = await boundedJSONObject(request);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(400);
      expect(await result.response.text()).not.toContain("transport implementation detail");
    }
  });
});

function streamedRequest(
  chunks: Array<string | Uint8Array>,
  contentLength?: string,
) {
  const encoder = new TextEncoder();
  const queue = chunks.map((chunk) => typeof chunk === "string" ? encoder.encode(chunk) : chunk);
  return new Request("https://vsign.example.test/api/test", {
    body: new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = queue.shift();
        if (chunk) controller.enqueue(chunk);
        else controller.close();
      },
    }),
    duplex: "half",
    headers: contentLength === undefined ? undefined : { "content-length": contentLength },
    method: "POST",
  } as RequestInit);
}
