import { beforeEach, describe, expect, it, vi } from "vitest";

import { createReadinessExportFixture } from "../../../../../../packages/readiness-dossier/test-fixture.mjs";
import { verifyReadinessDossierBytes } from "../../../../../../packages/readiness-dossier/index.mjs";
import type { AdminTenantReadinessExport } from "@/lib/owner-types";

const mocks = vi.hoisted(() => ({
  actor: vi.fn(),
  authorize: vi.fn(),
  engine: vi.fn(),
}));

vi.mock("@/lib/admin-access", () => ({ authorizeAdminMutation: mocks.authorize }));
vi.mock("@/lib/engine-actor", () => ({ buildEngineActor: mocks.actor }));
vi.mock("@/lib/engine-client", () => ({ requestEngineAction: mocks.engine }));

import { POST } from "./route";

const tenantId = "11111111-1111-4111-8111-111111111111";

describe("administrator tenant readiness exports", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authorize.mockResolvedValue({ ok: true, session: { user: { id: "admin" } } });
    mocks.actor.mockResolvedValue({ principalId: "admin" });
  });

  it("returns a non-cacheable attachment with the engine dossier hash", async () => {
    const exported = exportFixture("json");
    mocks.engine.mockResolvedValue({ status: 200, body: exported });
    const response = await POST(request("json"));

    expect(response.status).toBe(200);
    expect(response.headers.get("content-disposition")).toBe(
      `attachment; filename="vasi-readiness-${tenantId}.json"`,
    );
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-vasi-dossier-sha256")).toBe(exported.dossierHash);
    expect(await response.json()).toMatchObject({ dossierHash: exported.dossierHash, format: "json" });
    expect(mocks.engine).toHaveBeenCalledWith(
      { principalId: "admin" },
      {
        body: { format: "json", tenantId },
        method: "POST",
        path: "/v1/admin/tenant-readiness-exports",
      },
    );
  });

  it("fails closed when the engine response does not match the requested format", async () => {
    mocks.engine.mockResolvedValue({ status: 200, body: exportFixture("html") });
    const response = await POST(request("json"));
    expect(response.status).toBe(502);
    expect(response.headers.get("content-disposition")).toBeNull();
  });

  it("returns HTML that the framework-independent verifier reproduces exactly", async () => {
    const exported = exportFixture("html");
    mocks.engine.mockResolvedValue({ status: 200, body: exported });
    const response = await POST(request("html"));
    const bytes = new Uint8Array(await response.arrayBuffer());

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("content-security-policy")).toContain("sandbox");
    expect(verifyReadinessDossierBytes(bytes, { expectedDigest: exported.dossierHash }))
      .toMatchObject({ expectedDigest: "matched", format: "html", presentation: "exact", status: "pass" });
  });

  it("does not read or export state before administrator mutation authorization", async () => {
    mocks.authorize.mockResolvedValue({
      ok: false,
      response: Response.json({ error: "forbidden" }, { status: 403 }),
    });
    const response = await POST(request("json"));
    expect(response.status).toBe(403);
    expect(mocks.actor).not.toHaveBeenCalled();
    expect(mocks.engine).not.toHaveBeenCalled();
  });
});

function request(format: "html" | "json") {
  return new Request("https://vasi.example.test/api/admin/product/tenant-readiness-exports", {
    body: JSON.stringify({ format, tenantId }),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
}

function exportFixture(format: "html" | "json") {
  return createReadinessExportFixture(format) as AdminTenantReadinessExport;
}
