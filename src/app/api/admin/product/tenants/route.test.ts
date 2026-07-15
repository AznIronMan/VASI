import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/admin-access", () => ({
  authorizeAdminHeaders: vi.fn(),
  authorizeAdminMutation: vi.fn(),
}));
vi.mock("@/lib/engine-actor", () => ({ buildEngineActor: vi.fn() }));
vi.mock("@/lib/engine-client", () => ({ requestEngineAction: vi.fn() }));
vi.mock("@/lib/invitations", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/invitations")>();
  return { ...actual, createInvitation: vi.fn() };
});

import { authorizeAdminMutation } from "@/lib/admin-access";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { createInvitation, InvitationError } from "@/lib/invitations";
import { POST } from "@/app/api/admin/product/tenants/route";

const company = {
  admission: { admission: { gates: [], schema: "vasi-tenant-admission/v1", status: "pending" }, status: "pending" },
  id: "tenant-1",
  name: "Example Company",
  owner: { email: "owner@example.com", grantCreated: true },
  permissions: [],
  profile: {},
  roles: ["owner"],
  slug: "example-company",
};

describe("administrator company provisioning route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(authorizeAdminMutation).mockResolvedValue({
      ok: true,
      session: { user: { email: "admin@example.com", id: "admin-1" } },
    } as never);
    vi.mocked(buildEngineActor).mockResolvedValue({} as never);
    vi.mocked(requestEngineAction).mockResolvedValue({ body: company, status: 200 } as never);
    vi.mocked(createInvitation).mockResolvedValue({
      email: "owner@example.com",
      expiresAt: "2026-07-21T00:00:00.000Z",
      id: "11111111-1111-4111-8111-111111111111",
    });
  });

  it("commits the private-engine company before sending the owner invitation", async () => {
    const response = await POST(provisionRequest());
    const body = await response.json();

    expect(response.status).toBe(201);
    expect(requestEngineAction).toHaveBeenCalledWith(
      expect.anything(),
      {
        body: {
          name: "Example Company",
          ownerEmail: "owner@example.com",
          slug: "example-company",
        },
        method: "POST",
        path: "/v1/owner/tenants",
      },
    );
    expect(createInvitation).toHaveBeenCalledWith("owner@example.com", "admin-1");
    expect(body).toMatchObject({
      company: { id: "tenant-1" },
      invitation: { status: "sent", expiresAt: "2026-07-21T00:00:00.000Z" },
    });
    expect(vi.mocked(requestEngineAction).mock.invocationCallOrder[0])
      .toBeLessThan(vi.mocked(createInvitation).mock.invocationCallOrder[0]);
  });

  it("reports an existing account as a completed owner handoff", async () => {
    vi.mocked(createInvitation).mockRejectedValue(
      new InvitationError("That email already has an account.", 409),
    );

    const response = await POST(provisionRequest());

    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({ invitation: { status: "existing_account" } });
  });

  it("reports delivery failure without hiding the durable company result", async () => {
    vi.mocked(createInvitation).mockRejectedValue(new Error("delivery unavailable"));

    const response = await POST(provisionRequest());

    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({
      company: { id: "tenant-1" },
      invitation: { status: "delivery_failed" },
    });
  });

  it("does not invite when the administrator is the requested owner", async () => {
    vi.mocked(authorizeAdminMutation).mockResolvedValue({
      ok: true,
      session: { user: { email: "owner@example.com", id: "admin-1" } },
    } as never);

    const response = await POST(provisionRequest());

    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({ invitation: { status: "not_required" } });
    expect(createInvitation).not.toHaveBeenCalled();
  });

  it("honors an explicit decision to skip the invitation", async () => {
    const response = await POST(provisionRequest({ inviteOwner: false }));

    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({ invitation: { status: "skipped" } });
    expect(createInvitation).not.toHaveBeenCalled();
  });

  it("does not attempt an invitation when engine provisioning fails", async () => {
    vi.mocked(requestEngineAction).mockResolvedValue({
      body: { error: "tenant_slug_exists" },
      status: 409,
    } as never);

    const response = await POST(provisionRequest());

    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "That company identifier is already in use." });
    expect(createInvitation).not.toHaveBeenCalled();
  });

  it("rejects incomplete commands before invoking the private engine", async () => {
    const response = await POST(provisionRequest({ inviteOwner: undefined }));

    expect(response.status).toBe(400);
    expect(requestEngineAction).not.toHaveBeenCalled();
    expect(createInvitation).not.toHaveBeenCalled();
  });
});

function provisionRequest(overrides: Record<string, unknown> = {}) {
  return new Request("https://admin.example.test/api/admin/product/tenants", {
    body: JSON.stringify({
      inviteOwner: true,
      name: "Example Company",
      ownerEmail: "owner@example.com",
      slug: "EXAMPLE-COMPANY",
      ...overrides,
    }),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
}
