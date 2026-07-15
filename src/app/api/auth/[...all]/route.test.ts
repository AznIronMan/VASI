import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  auth: vi.fn(),
  handler: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({ getAuth: mocks.auth }));

import { GATEWAY_JSON_MAXIMUM_BYTES } from "@/lib/bounded-json";
import { POST } from "@/app/api/auth/[...all]/route";

describe("authentication request body boundary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.handler.mockImplementation(async (request: Request) => Response.json({
      body: await request.text(),
      contentLength: request.headers.get("content-length"),
    }));
    mocks.auth.mockResolvedValue({ handler: mocks.handler });
  });

  it("rejects oversized auth payloads before constructing the provider handler", async () => {
    const response = await POST(request("x".repeat(GATEWAY_JSON_MAXIMUM_BYTES + 1)));

    expect(response.status).toBe(413);
    expect(mocks.auth).not.toHaveBeenCalled();
    expect(mocks.handler).not.toHaveBeenCalled();
  });

  it("forwards an accepted payload without trusting the original length header", async () => {
    const body = "response=provider-form-post";
    const response = await POST(request(body));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ body, contentLength: null });
    expect(mocks.handler).toHaveBeenCalledOnce();
  });

  it("rejects a declared auth body that is absent", async () => {
    const response = await POST(new Request(
      "https://vsign.example.test/api/auth/sign-out",
      { headers: { "content-length": "1" }, method: "POST" },
    ));

    expect(response.status).toBe(400);
    expect(mocks.auth).not.toHaveBeenCalled();
  });
});

function request(body: string) {
  return new Request("https://vsign.example.test/api/auth/sign-in/email", {
    body,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    method: "POST",
  });
}
