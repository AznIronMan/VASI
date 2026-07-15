import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  actor: vi.fn(),
  authorizeHeaders: vi.fn(),
  authorizeMutation: vi.fn(),
  engine: vi.fn(),
}));

vi.mock("@/lib/engine-actor", () => ({ buildEngineActor: mocks.actor }));
vi.mock("@/lib/engine-client", () => ({ requestEngineAction: mocks.engine }));
vi.mock("@/lib/owner-access", () => ({
  authorizeOwnerHeaders: mocks.authorizeHeaders,
  authorizeOwnerMutation: mocks.authorizeMutation,
}));

import { GATEWAY_JSON_MAXIMUM_BYTES } from "@/lib/bounded-json";
import { ownerEngineMutation, ownerEngineQuery } from "@/lib/owner-engine";

describe("owner engine gateway request boundary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    const authorized = { ok: true, session: { user: { id: "owner-1" } } };
    mocks.authorizeHeaders.mockResolvedValue(authorized);
    mocks.authorizeMutation.mockResolvedValue(authorized);
    mocks.actor.mockResolvedValue({ principalId: "owner-1" });
    mocks.engine.mockResolvedValue({ body: { accepted: true }, status: 200 });
  });

  it("rejects an oversized owner mutation before actor construction or engine contact", async () => {
    const response = await ownerEngineMutation(
      request(JSON.stringify({ value: "x".repeat(GATEWAY_JSON_MAXIMUM_BYTES) })),
      "/v1/owner/test",
    );

    expect(response.status).toBe(413);
    expect(mocks.actor).not.toHaveBeenCalled();
    expect(mocks.engine).not.toHaveBeenCalled();
  });

  it("rejects malformed owner query JSON before engine contact", async () => {
    const response = await ownerEngineQuery(request("{"), "/v1/owner/test-list");

    expect(response.status).toBe(400);
    expect(mocks.engine).not.toHaveBeenCalled();
  });

  it("forwards an accepted object through the normal authorization boundary", async () => {
    const response = await ownerEngineMutation(request('{"tenantId":"tenant-1"}'), "/v1/owner/test");

    expect(response.status).toBe(200);
    expect(mocks.engine).toHaveBeenCalledWith(
      { principalId: "owner-1" },
      { body: { tenantId: "tenant-1" }, method: "POST", path: "/v1/owner/test" },
    );
  });
});

function request(body: string) {
  return new Request("https://admin.example.test/api/owner/test", {
    body,
    headers: { "content-type": "application/json" },
    method: "POST",
  });
}
