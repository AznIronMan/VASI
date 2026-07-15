import { describe, expect, it } from "vitest";

import { accessDenialResponse, hiddenResourceResponse } from "@/lib/access-denial";

describe("gateway access-denial responses", () => {
  it("returns an empty host-varying non-cacheable hidden-resource denial", async () => {
    const response = hiddenResourceResponse();
    expect(response.status).toBe(404);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("vary")).toBe("Host");
    expect(response.headers.has("content-type")).toBe(false);
    expect(await response.text()).toBe("");
  });

  it("returns a bounded exact non-cacheable JSON denial", async () => {
    const response = accessDenialResponse("Authentication required.", 401);
    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await response.text()).toBe('{"error":"Authentication required."}');
  });

  it("rejects empty, multiline, and oversized denial messages", () => {
    expect(() => accessDenialResponse("", 403)).toThrow(/outside its bound/i);
    expect(() => accessDenialResponse("line one\nline two", 403)).toThrow(/outside its bound/i);
    expect(() => accessDenialResponse("x".repeat(161), 403)).toThrow(/outside its bound/i);
  });
});
