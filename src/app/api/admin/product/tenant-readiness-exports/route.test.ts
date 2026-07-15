import { beforeEach, describe, expect, it, vi } from "vitest";

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
const digest = "a".repeat(64);

describe("administrator tenant readiness exports", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authorize.mockResolvedValue({ ok: true, session: { user: { id: "admin" } } });
    mocks.actor.mockResolvedValue({ principalId: "admin" });
  });

  it("returns a non-cacheable attachment with the engine dossier hash", async () => {
    mocks.engine.mockResolvedValue({ status: 200, body: exportFixture("json") });
    const response = await POST(request("json"));

    expect(response.status).toBe(200);
    expect(response.headers.get("content-disposition")).toBe(
      `attachment; filename="vasi-readiness-${tenantId}.json"`,
    );
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-vasi-dossier-sha256")).toBe(digest);
    expect(await response.json()).toMatchObject({ dossierHash: digest, format: "json" });
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
  return {
    auditEventHash: "b".repeat(64),
    capturedAt: "2026-07-15T20:00:00.000Z",
    dossier: {
      admission: { gates: [], status: "pending" },
      integrations: [],
      limitations: [],
      readiness: { pendingGateIds: [] },
      schema: "vasi-tenant-readiness-dossier/v1",
      tenant: { id: tenantId, name: "Example Tenant" },
    },
    dossierHash: digest,
    format,
    schema: "vasi-tenant-readiness-export/v1",
  };
}
