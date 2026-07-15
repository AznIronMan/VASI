import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  discoverSensitiveRoutes,
  exportedHTTPMethods,
  runPublicRouteIsolationProbe,
} from "./probe-public-route-isolation.mjs";

describe("public sensitive-route isolation", () => {
  it("discovers every current sensitive route method from tracked source", async () => {
    const routes = await discoverSensitiveRoutes();
    expect(routes).toHaveLength(54);
    expect(counts(routes)).toEqual({ admin: 17, evidence: 4, owner: 25, request: 3, workspace: 5 });
    expect(routes).toContainEqual({
      audience: "internal",
      method: "DELETE",
      namespace: "admin",
      path: "/api/admin/users/00000000-0000-4000-8000-000000000000/connectors/google",
      source: "src/app/api/admin/users/[userId]/connectors/[provider]/route.ts",
    });
    expect(routes).toContainEqual({
      audience: "participant",
      method: "GET",
      namespace: "request",
      path: `/r/${"A".repeat(43)}/media/activity_1/frame`,
      source: "src/app/r/[handle]/media/[activityId]/frame/route.ts",
    });
  });

  it("parses functions, constants, aliases, and re-exports without trusting comments or literals", () => {
    expect(exportedHTTPMethods(`
      // export function PUT() {}
      const decoy = "export const PATCH =";
      export async function GET() {}
      export const DELETE = handler;
      export { internalPost as POST, HEAD } from "./implementation";
    `)).toEqual(["GET", "HEAD", "POST", "DELETE"]);
    expect(() => exportedHTTPMethods("export const GET = `unterminated"))
      .toThrow(/unterminated literal/i);
    expect(() => exportedHTTPMethods("x".repeat(65_537))).toThrow(/outside its bound/i);
  });

  it("discovers re-exported and dynamic fixture routes and rejects an unguarded route", async () => {
    const fixture = await routeFixture();
    try {
      const routes = await discoverSensitiveRoutes(fixture);
      expect(routes).toHaveLength(6);
      expect(counts(routes)).toEqual({ admin: 1, evidence: 1, owner: 1, request: 1, workspace: 2 });
      expect(routes.some((entry) => entry.path.includes("00000000-0000-4000-8000-000000000000"))).toBe(true);

      await writeFile(path.join(fixture, "src/app/api/admin/check/route.ts"), "export const dynamic = 'force-dynamic';\n");
      await expect(discoverSensitiveRoutes(fixture)).rejects.toThrow(/exports no supported HTTP method/i);
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("proves every internal, participant, and protected-page denial contract", async () => {
    const routes = routeInventory();
    const observedBodies = [];
    await expect(runPublicRouteIsolationProbe({
      fetchImplementation: isolationFetch({ observedBodies, routes }),
      origin: "https://public.example.test",
      routes,
    })).resolves.toEqual({
      apiMethods: 5,
      internalApiMethods: 2,
      namespaces: { admin: 1, evidence: 1, owner: 1, request: 1, workspace: 1 },
      participantApiMethods: 3,
      protectedPages: 6,
      schema: "vasi-public-route-isolation-probe/v1",
      status: "pass",
    });
    expect(observedBodies).toEqual(["{\"vasi\":", "{\"vasi\":", "{\"vasi\":"]);
  });

  it.each([
    ["visible internal route", { api: (entry) => entry.namespace === "admin" ? response("visible", 404, apiHeaders({ vary: "Host" })) : undefined }, /discovered an internal API/i],
    ["participant validation before authentication", { api: (entry) => entry.namespace === "evidence" ? response("bad", 400, apiHeaders()) : undefined }, /exact authentication denial/i],
    ["cacheable API denial", { api: (entry) => entry.namespace === "admin" ? response("", 404, { vary: "Host" }) : undefined }, /cacheable/i],
    ["look-alike cache directive", { api: (entry) => entry.namespace === "admin" ? response("", 404, { "cache-control": "private, no-cache, no-storex", vary: "Host" }) : undefined }, /cacheable/i],
    ["API cookie", { api: (entry) => entry.namespace === "admin" ? response("", 404, apiHeaders({ "set-cookie": "session=bad", vary: "Host" })) : undefined }, /cookie or redirect/i],
    ["API CORS disclosure", { api: (entry) => entry.namespace === "admin" ? response("", 404, apiHeaders({ "access-control-allow-origin": "https://attacker.invalid", vary: "Host" })) : undefined }, /cross-origin/i],
    ["missing host variation", { api: (entry) => entry.namespace === "admin" ? response("", 404, apiHeaders()) : undefined }, /host cache key/i],
    ["protected metadata", { page: (pathname) => pathname === "/admin" ? response("<html>Identity administration</html>", 404, pageHeaders()) : undefined }, /protected page metadata/i],
    ["cross-origin login redirect", { page: (pathname) => pathname === "/workspace" ? response("<html>redirect</html>", 307, pageHeaders({ location: "https://attacker.invalid/" })) : undefined }, /non-canonical login redirect/i],
    ["page cookie", { page: (pathname) => pathname === "/owner" ? response("<html>not found</html>", 404, pageHeaders({ "set-cookie": "bad=1" })) : undefined }, /issued a cookie/i],
    ["oversized API response", { api: () => response("", 404, apiHeaders({ "content-length": "4097", vary: "Host" })) }, /oversized response/i],
  ])("rejects %s", async (_label, mutations, error) => {
    const routes = routeInventory();
    await expect(runPublicRouteIsolationProbe({
      fetchImplementation: isolationFetch({ mutations, routes }),
      origin: "https://public.example.test",
      routes,
    })).rejects.toThrow(error);
  });

  it("rejects unsafe origins, incomplete inventories, and unbounded timeouts", async () => {
    const routes = routeInventory();
    await expect(runPublicRouteIsolationProbe({ origin: "http://public.example.test", routes }))
      .rejects.toThrow(/HTTPS origin/i);
    await expect(runPublicRouteIsolationProbe({ origin: "https://public.example.test:8443", routes }))
      .rejects.toThrow(/HTTPS origin/i);
    await expect(runPublicRouteIsolationProbe({
      fetchImplementation: isolationFetch({ routes }),
      origin: "https://public.example.test",
      routes: routes.filter((entry) => entry.namespace !== "owner"),
    })).rejects.toThrow(/incomplete/i);
    await expect(runPublicRouteIsolationProbe({
      fetchImplementation: isolationFetch({ routes }),
      origin: "https://public.example.test",
      routes,
      timeoutMilliseconds: 31_000,
    })).rejects.toThrow(/between 500 and 30000/i);
  });
});

function routeInventory() {
  return [
    route("internal", "GET", "admin", "/api/admin/check"),
    route("participant", "POST", "evidence", "/api/evidence/check"),
    route("internal", "POST", "owner", "/api/owner/check"),
    route("participant", "GET", "request", `/r/${"A".repeat(43)}/report`),
    route("participant", "POST", "workspace", "/api/workspace/check"),
  ];
}

function route(audience, method, namespace, pathname) {
  return { audience, method, namespace, path: pathname, source: `src/app/${namespace}/check/route.ts` };
}

function isolationFetch({ mutations = {}, observedBodies = [], routes }) {
  const inventory = new Map(routes.map((entry) => [`${entry.method} ${entry.path}`, entry]));
  return async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || "GET";
    const entry = inventory.get(`${method} ${url.pathname}`);
    if (entry) {
      if (init.body) observedBodies.push(init.body);
      const mutated = mutations.api?.(entry);
      if (mutated) return mutated;
      return entry.audience === "internal"
        ? response("", 404, apiHeaders({ vary: "Host" }))
        : response('{"error":"Authentication required."}', 401, apiHeaders({ "content-type": "application/json" }));
    }
    const mutated = mutations.page?.(url.pathname);
    if (mutated) return mutated;
    if (["/admin", "/admin/evidence", "/owner"].includes(url.pathname)) {
      return response("<html><title>Secure access</title>Not Found</html>", 404, pageHeaders());
    }
    if (url.pathname === "/workspace") {
      return response("<html>Redirecting</html>", 307, pageHeaders({ location: "/" }));
    }
    if (url.pathname.startsWith(`/r/${"A".repeat(43)}`)) {
      return response("<html>Redirecting</html>", 307, pageHeaders({
        location: `/?returnTo=${encodeURIComponent(`/r/${"A".repeat(43)}`)}`,
      }));
    }
    throw new Error(`Unexpected request ${method} ${url.pathname}`);
  };
}

function apiHeaders(overrides = {}) {
  return { "cache-control": "no-store", server: "nginx", ...overrides };
}

function pageHeaders(overrides = {}) {
  return {
    "cache-control": "private, no-cache, no-store, max-age=0, must-revalidate",
    "content-type": "text/html; charset=utf-8",
    server: "nginx",
    ...overrides,
  };
}

function response(body, status, headers = {}) {
  return new Response(body === "" ? null : body, { headers, status });
}

function counts(routes) {
  return Object.fromEntries([...new Set(routes.map((entry) => entry.namespace))].sort().map((namespace) => [
    namespace,
    routes.filter((entry) => entry.namespace === namespace).length,
  ]));
}

async function routeFixture() {
  const root = await mkdtemp(path.join(tmpdir(), "vasi-sensitive-routes-"));
  const files = {
    "src/app/api/admin/check/route.ts": "export async function GET() {}\n",
    "src/app/api/evidence/check/route.ts": "// export function PUT() {}\nexport function PATCH() {}\n",
    "src/app/api/owner/[tenantId]/route.ts": "export const DELETE = handler;\n",
    "src/app/api/workspace/check/route.ts": "export { GET, POST } from './implementation';\n",
    "src/app/r/[handle]/report/route.ts": "export async function GET() {}\n",
  };
  for (const [relative, contents] of Object.entries(files)) {
    const filename = path.join(root, relative);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, contents);
  }
  return root;
}
