import { describe, expect, it } from "vitest";

import { runPublicIngressProbe } from "./probe-public-ingress.mjs";

describe("public ingress black-box probe", () => {
  it("proves health, body, retirement, header, and rate boundaries", async () => {
    let rateRequest = 0;
    const fetchImplementation = async (input, init) => {
      const url = new URL(input);
      if (url.hostname === "retired.example.test") {
        return response("Not Found", 404, { server: "nginx" });
      }
      if (url.pathname === "/api/health") {
        return response(JSON.stringify({ service: "vasi-auth", status: "ok", version: "0.40.0" }), 200, secureHeaders());
      }
      if (url.pathname === "/" && init.method === "GET") {
        return response("<html>V Sign</html>", 200, secureHeaders());
      }
      if (url.pathname === "/api/auth/sign-in/email") {
        expect(init.body).toHaveLength(65_537);
        return response(JSON.stringify({ error: "The request body is too large." }), 413, {
          "cache-control": "no-store",
        });
      }
      if (url.pathname === "/api/auth/provider-recommendation") {
        rateRequest += 1;
        return rateRequest <= 30
          ? response(JSON.stringify({ configured: true, provider: "google" }), 200)
          : response(JSON.stringify({ error: "Too many requests." }), 429, {
            "cache-control": "no-store",
            "retry-after": "1",
          });
      }
      throw new Error(`Unexpected URL ${url}`);
    };
    await expect(runPublicIngressProbe({
      exerciseRateLimit: true,
      fetchImplementation,
      origin: "https://public.example.test",
      rateRequests: 40,
      retiredOrigin: "https://retired.example.test",
    })).resolves.toMatchObject({
      bodyLimitBytes: 65_536,
      observedVersion: "0.40.0",
      rateLimit: { accepted: 30, limited: 10, requests: 40 },
      retiredStatus: 404,
      status: "pass",
    });
  });

  it("rejects version disclosure, engine exposure, weak bodies, and absent rate enforcement", async () => {
    const baseline = async (input) => {
      const url = new URL(input);
      if (url.hostname === "retired.example.test") return response("VASI private engine", 200);
      if (url.pathname === "/api/health") {
        return response(JSON.stringify({ service: "vasi-auth", status: "ok", version: "0.40.0" }), 200, {
          ...secureHeaders(),
          server: "nginx/1.28.3",
        });
      }
      return response("ok", 200, secureHeaders());
    };
    await expect(runPublicIngressProbe({
      fetchImplementation: baseline,
      origin: "https://public.example.test",
      retiredOrigin: "https://retired.example.test",
    })).rejects.toThrow(/server version/i);

    const noRateLimit = async (input) => {
      const url = new URL(input);
      if (url.pathname === "/api/health") {
        return response(JSON.stringify({ service: "vasi-auth", status: "ok", version: "0.40.0" }), 200, secureHeaders());
      }
      if (url.pathname === "/api/auth/sign-in/email") {
        return response(JSON.stringify({ error: "The request body is too large." }), 413, { "cache-control": "no-store" });
      }
      if (url.pathname === "/") return response("root", 200, secureHeaders());
      return response("{}", 200);
    };
    await expect(runPublicIngressProbe({
      exerciseRateLimit: true,
      fetchImplementation: noRateLimit,
      origin: "https://public.example.test",
      rateRequests: 32,
    })).rejects.toThrow(/not independently observable/i);
  });

  it("rejects unsafe origins and unbounded request counts", async () => {
    await expect(runPublicIngressProbe({ origin: "http://public.example.test" })).rejects.toThrow(/HTTPS origin/i);
    await expect(runPublicIngressProbe({
      origin: "https://public.example.test",
      retiredOrigin: "https://public.example.test",
    })).rejects.toThrow(/must differ/i);
    await expect(runPublicIngressProbe({
      origin: "https://public.example.test",
      rateRequests: 201,
    })).rejects.toThrow(/between 32 and 200/i);
  });
});

function response(body, status, headers = {}) {
  return new Response(body, { headers, status });
}

function secureHeaders() {
  return {
    "cache-control": "no-store",
    server: "nginx",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
  };
}
