import { describe, expect, it } from "vitest";

import { inspectAdversarialBoundary, runPublicIngressProbe } from "./probe-public-ingress.mjs";

const tlsProof = async () => ["TLSv1.2", "TLSv1.3"];
const adversarialProof = async () => ({ canonicalHostIsolationCases: 3, normalizationDenials: 8 });
const probe = (options) => runPublicIngressProbe({ inspectAdversarial: adversarialProof, ...options });

describe("public ingress black-box probe", () => {
  it("proves protocol, redirect, page, CORS, body, retirement, header, and rate boundaries", async () => {
    await expect(probe({
      exerciseRateLimit: true,
      fetchImplementation: ingressFetch(),
      inspectTLS: tlsProof,
      origin: "https://public.example.test",
      rateRequests: 40,
      retiredOrigin: "https://retired.example.test",
    })).resolves.toMatchObject({
      adversarial: {
        canonicalHostIsolationCases: 3,
        forwardedHeaders: "not_reflected",
        methodOverride: "denied",
        normalizationDenials: 8,
        sessionPrivacy: "no_store_null",
      },
      bodyLimitBytes: 65_536,
      canonicalRedirect: true,
      crossOriginPreflight: "denied",
      observedVersion: "0.48.0",
      pageMethods: { allowed: ["GET", "HEAD"], denied: 5 },
      rateLimit: { accepted: 30, limited: 10, requests: 40 },
      retiredStatus: 404,
      schema: "vasi-public-ingress-probe/v3",
      status: "pass",
      tlsProtocols: ["TLSv1.2", "TLSv1.3"],
    });
  });

  it("rejects version disclosure, engine exposure, and absent rate enforcement", async () => {
    await expect(probe({
      fetchImplementation: ingressFetch({ server: "nginx/1.28.3" }),
      inspectTLS: tlsProof,
      origin: "https://public.example.test",
      retiredOrigin: "https://retired.example.test",
    })).rejects.toThrow(/server version/i);

    await expect(probe({
      exerciseRateLimit: true,
      fetchImplementation: ingressFetch({ rateLimit: false }),
      inspectTLS: tlsProof,
      origin: "https://public.example.test",
      rateRequests: 32,
    })).rejects.toThrow(/not independently observable/i);

    await expect(probe({
      fetchImplementation: ingressFetch({ retiredBody: "VASI private engine", retiredStatus: 200 }),
      inspectTLS: tlsProof,
      origin: "https://public.example.test",
      retiredOrigin: "https://retired.example.test",
    })).rejects.toThrow(/content-free denial/i);
  });

  it.each([
    ["a request-derived redirect", { redirectLocation: "https://attacker.invalid/api/health?canonical-redirect=1" }, tlsProof, /canonical HTTPS origin/i],
    ["a malformed redirect", { redirectLocation: "https://[invalid" }, tlsProof, /canonical HTTPS origin/i],
    ["page rendering for DELETE", { pageMethodStatus: 200 }, tlsProof, /prohibited method/i],
    ["hostile CORS authorization", { corsHeaders: { "access-control-allow-origin": "https://attacker.invalid" } }, tlsProof, /hostile cross-origin/i],
    ["an incomplete browser policy", { rootHeaders: secureHeaders({ "content-security-policy": "default-src 'self'" }) }, tlsProof, /CSP is missing/i],
    ["an incomplete TLS contract", {}, async () => ["TLSv1.3"], /TLS protocol contract/i],
  ])("rejects %s", async (_label, options, inspectTLS, error) => {
    await expect(probe({
      fetchImplementation: ingressFetch(options),
      inspectTLS,
      origin: "https://public.example.test",
    })).rejects.toThrow(error);
  });

  it("rejects unsafe origins and unbounded request counts", async () => {
    await expect(probe({ origin: "http://public.example.test" })).rejects.toThrow(/HTTPS origin/i);
    await expect(probe({ origin: "https://public.example.test:8443" })).rejects.toThrow(/HTTPS origin/i);
    await expect(probe({
      origin: "https://public.example.test",
      retiredOrigin: "https://public.example.test",
    })).rejects.toThrow(/must differ/i);
    await expect(probe({
      origin: "https://public.example.test",
      rateRequests: 201,
    })).rejects.toThrow(/between 32 and 200/i);
    await expect(runPublicIngressProbe({
      inspectAdversarial: async () => ({ canonicalHostIsolationCases: 2, normalizationDenials: 8 }),
      inspectTLS: tlsProof,
      origin: "https://public.example.test",
    })).rejects.toThrow(/adversarial request-target proof is incomplete/i);
  });

  it("validates raw hostile-host and request-target observations without following redirects", async () => {
    const raw = async (_origin, target) => target.host === "public.example.test" && !target.path.startsWith("https://")
      ? observation(400, "{\"error\":\"Bad request.\"}", { "cache-control": "no-store" })
      : observation(302, "", { location: "https://www.example.test" });

    await expect(inspectAdversarialBoundary(
      new URL("https://public.example.test"),
      1_000,
      raw,
    )).resolves.toEqual({ canonicalHostIsolationCases: 3, normalizationDenials: 8 });
  });

  it("rejects raw product selection, hostile redirect reflection, and normalized redirects", async () => {
    await expect(inspectAdversarialBoundary(
      new URL("https://public.example.test"),
      1_000,
      async () => observation(200, "V·Sign"),
    )).rejects.toThrow(/selected application content/i);

    await expect(inspectAdversarialBoundary(
      new URL("https://public.example.test"),
      1_000,
      async () => observation(302, "", { location: "https://attacker.invalid/" }),
    )).rejects.toThrow(/hostile host/i);

    let calls = 0;
    await expect(inspectAdversarialBoundary(
      new URL("https://public.example.test"),
      1_000,
      async () => ++calls <= 3
        ? observation(404, "Not Found")
        : observation(308, "", { location: "https://public.example.test/admin" }),
    )).rejects.toThrow(/ambiguous or traversal-style/i);

    calls = 0;
    await expect(inspectAdversarialBoundary(
      new URL("https://public.example.test"),
      1_000,
      async () => ++calls <= 3
        ? observation(404, "Not Found")
        : observation(400, "{\"error\":\"Bad request.\"}"),
    )).rejects.toThrow(/cacheable/i);
  });
});

function ingressFetch({
  corsHeaders = {},
  pageMethodStatus = 405,
  rateLimit = true,
  redirectLocation,
  retiredBody = "Not Found",
  retiredStatus = 404,
  rootHeaders = secureHeaders(),
  server = "nginx",
} = {}) {
  let rateRequest = 0;
  return async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || "GET";
    if (url.protocol === "http:") {
      return response("", 301, {
        location: redirectLocation || `https://${url.hostname}${url.pathname}${url.search}`,
        server,
      });
    }
    if (url.hostname === "retired.example.test") {
      return response(retiredBody, retiredStatus, { server: "nginx" });
    }
    if (url.pathname === "/api/health") {
      return response(JSON.stringify({ service: "vasi-auth", status: "ok", version: "0.48.0" }), 200, {
        ...secureHeaders(),
        server,
      });
    }
    if (url.pathname === "/" && method === "GET") {
      expect(init.headers["x-forwarded-host"]).toBe("attacker.invalid");
      return response("<html>V Sign</html>", 200, rootHeaders);
    }
    if (url.pathname === "/" && ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(method)) {
      if (method === "POST") expect(init.headers["x-http-method-override"]).toBe("GET");
      return pageMethodStatus === 405
        ? response("", 405, { ...rootHeaders, allow: "GET, HEAD", "cache-control": "no-store" })
        : response("<html>V Sign</html>", pageMethodStatus, rootHeaders);
    }
    if (url.pathname === "/api/auth/sign-in/email") {
      expect(init.body).toHaveLength(65_537);
      return response(JSON.stringify({ error: "The request body is too large." }), 413, {
        "cache-control": "no-store",
      });
    }
    if (url.pathname === "/api/auth/get-session") {
      expect(init.headers.origin).toBe("https://attacker.invalid");
      expect(init.headers["sec-fetch-site"]).toBe("cross-site");
      return response("null", 200, secureHeaders());
    }
    if (url.pathname === "/api/auth/provider-recommendation" && method === "OPTIONS") {
      return response("", 204, corsHeaders);
    }
    if (url.pathname === "/api/auth/provider-recommendation") {
      rateRequest += 1;
      return !rateLimit || rateRequest <= 30
        ? response(JSON.stringify({ configured: true, provider: "google" }), 200)
        : response(JSON.stringify({ error: "Too many requests." }), 429, {
          "cache-control": "no-store",
          "retry-after": "1",
        });
    }
    throw new Error(`Unexpected URL ${url} with ${method}`);
  };
}

function observation(status, body, headers = {}) {
  return { body, headers: new Headers(headers), status };
}

function response(body, status, headers = {}) {
  return new Response([204, 205, 304].includes(status) ? null : body, { headers, status });
}

function secureHeaders(overrides = {}) {
  return {
    "cache-control": "no-store",
    "content-security-policy": [
      "default-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
    ].join("; "),
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), browsing-topics=()",
    "referrer-policy": "strict-origin-when-cross-origin",
    server: "nginx",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-permitted-cross-domain-policies": "none",
    ...overrides,
  };
}
