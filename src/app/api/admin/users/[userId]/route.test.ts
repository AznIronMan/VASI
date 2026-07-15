import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authorize: vi.fn(),
  banUser: vi.fn(),
  begin: vi.fn(),
  finish: vi.fn(),
  getAuth: vi.fn(),
  query: vi.fn(),
  unbanUser: vi.fn(),
}));

vi.mock("@/lib/admin-access", () => ({ authorizeAdminMutation: mocks.authorize }));
vi.mock("@/lib/admin-audit", () => ({
  beginAdminAuditCommand: mocks.begin,
  finishAdminAuditCommand: mocks.finish,
}));
vi.mock("@/lib/auth", () => ({ getAuth: mocks.getAuth }));
vi.mock("@/lib/database", () => ({
  database: { connect: vi.fn(), query: mocks.query },
}));
vi.mock("@/lib/runtime-settings", () => ({ getRuntimeSettings: vi.fn() }));
vi.mock("@/lib/server-settings", () => ({ resolveServerSettings: vi.fn() }));

import { POST } from "@/app/api/admin/users/[userId]/route";

const command = {
  action: "user.set_active",
  actorSessionId: "session-1",
  actorUserId: "admin-1",
  commandId: "command-1",
  ipAddress: "192.0.2.10",
  requestId: "request-1",
  targetUserId: "user-1",
  userAgent: "VASI test",
};

describe("identity administrator command outcomes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authorize.mockResolvedValue({
      ok: true,
      session: { session: { id: "session-1" }, user: { id: "admin-1" } },
    });
    mocks.query.mockResolvedValue({
      rowCount: 1,
      rows: [{ email: "user@example.test", manualPassword: false }],
    });
    mocks.begin.mockResolvedValue(command);
    mocks.finish.mockResolvedValue({ eventHash: "a".repeat(64), id: "audit-1", sequence: 2 });
    mocks.banUser.mockResolvedValue(undefined);
    mocks.unbanUser.mockResolvedValue(undefined);
    mocks.getAuth.mockResolvedValue({
      api: { banUser: mocks.banUser, unbanUser: mocks.unbanUser },
    });
  });

  it("does not inspect or mutate a request rejected at the internal boundary", async () => {
    mocks.authorize.mockResolvedValue({
      ok: false,
      response: Response.json({ error: "Not found." }, { status: 404 }),
    });
    const response = await post({ action: "set-active", enabled: false });
    expect(response.status).toBe(404);
    expect(mocks.query).not.toHaveBeenCalled();
    expect(mocks.begin).not.toHaveBeenCalled();
  });

  it("records start before the provider mutation and a succeeded terminal event", async () => {
    const response = await post({ action: "set-active", enabled: false });
    expect(response.status).toBe(200);
    expect(mocks.begin).toHaveBeenCalledWith(expect.objectContaining({
      action: "user.set_active",
      metadata: { desiredEnabled: false },
      targetUserId: "user-1",
    }));
    expect(mocks.banUser).toHaveBeenCalledWith(expect.objectContaining({
      body: { banReason: expect.any(String), userId: "user-1" },
    }));
    expect(mocks.finish).toHaveBeenCalledWith(command, "succeeded");
    expect(mocks.begin.mock.invocationCallOrder[0]).toBeLessThan(mocks.banUser.mock.invocationCallOrder[0]);
  });

  it("preserves external-operation uncertainty instead of reporting clean failure", async () => {
    mocks.banUser.mockRejectedValue(new Error("provider response lost"));
    const response = await post({ action: "set-active", enabled: false });
    expect(response.status).toBe(502);
    expect(mocks.finish).toHaveBeenCalledWith(
      command,
      "ambiguous",
      { outcomeCode: "external_operation_outcome_unknown" },
    );
    expect(await response.json()).toMatchObject({ error: expect.stringContaining("may have completed") });
  });

  it("reports a completed change with an unavailable terminal audit as incomplete", async () => {
    mocks.finish.mockRejectedValue(new Error("audit unavailable"));
    const response = await post({ action: "set-active", enabled: false });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: expect.stringContaining("change completed") });
  });

  it("does not attempt the mutation when its started event cannot be recorded", async () => {
    mocks.begin.mockRejectedValue(new Error("audit unavailable"));
    const response = await post({ action: "set-active", enabled: false });
    expect(response.status).toBe(503);
    expect(mocks.banUser).not.toHaveBeenCalled();
  });
});

function post(body: unknown) {
  return POST(new Request("https://admin.example.test/api/admin/users/user-1", {
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", Origin: "https://admin.example.test" },
    method: "POST",
  }), { params: Promise.resolve({ userId: "user-1" }) });
}
