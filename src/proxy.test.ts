import { unstable_doesMiddlewareMatch } from "next/experimental/testing/server";
import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { config, pageMethodDecision, proxy } from "./proxy";

describe("public page method boundary", () => {
  it.each(["GET", "HEAD"])("allows %s page requests", (method) => {
    expect(pageMethodDecision(method, "/forgot-password")).toBe("allow");
  });

  it.each(["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"])(
    "denies %s page requests",
    (method) => {
      expect(pageMethodDecision(method, "/")).toBe("deny");
      expect(pageMethodDecision(method.toLowerCase(), "/r/request-1")).toBe("deny");
    },
  );

  it("never replaces explicit API route method handling", () => {
    for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      expect(pageMethodDecision(method, "/api/owner/requests")).toBe("allow");
      expect(pageMethodDecision(method, "/api")).toBe("allow");
    }
  });

  it("returns a bounded side-effect-free 405 contract", async () => {
    const result = proxy(new NextRequest("https://vsign.example.test/forgot-password?next=%2Fowner", {
      method: "DELETE",
    }));
    expect(result.status).toBe(405);
    expect(result.headers.get("allow")).toBe("GET, HEAD");
    expect(result.headers.get("cache-control")).toBe("no-store");
    expect(result.headers.has("location")).toBe(false);
    expect(result.headers.has("set-cookie")).toBe(false);
    expect(await result.text()).toBe("");
  });

  it("passes safe page requests through without adding client state", () => {
    const result = proxy(new NextRequest("https://vsign.example.test/owner", { method: "GET" }));
    expect(result.status).toBe(200);
    expect(result.headers.get("x-middleware-next")).toBe("1");
    expect(result.headers.has("set-cookie")).toBe(false);
  });

  it.each([
    ["/", true],
    ["/forgot-password", true],
    ["/r/request-1", true],
    ["/api/health", false],
    ["/apiary", true],
    ["/_next/static/app.js", false],
    ["/_next/image", false],
    ["/_nextish", true],
    ["/brand-mark.svg", true],
    ["/r/request.with-dots", true],
  ])("matches only application page path %s", (url, expected) => {
    expect(unstable_doesMiddlewareMatch({ config, nextConfig: {}, url })).toBe(expected);
  });
});
