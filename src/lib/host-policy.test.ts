import { describe, expect, it } from "vitest";

import {
  hasExpectedMutationOrigin,
  isCrossSiteRequest,
  isRequestForOrigin,
  requestHostname,
} from "@/lib/host-policy";

describe("host policy", () => {
  it("normalizes an inbound host and ignores its port", () => {
    const headers = new Headers({ host: "Admin.Internal.Example:443" });

    expect(requestHostname(headers)).toBe("admin.internal.example");
    expect(isRequestForOrigin(headers, "https://admin.internal.example")).toBe(true);
  });

  it("does not trust forwarded hosts for the admin boundary", () => {
    const headers = new Headers({
      host: "public.example.com",
      "x-forwarded-host": "admin.internal.example",
    });

    expect(isRequestForOrigin(headers, "https://admin.internal.example")).toBe(false);
  });

  it("requires an exact origin on state-changing requests", () => {
    expect(
      hasExpectedMutationOrigin(
        new Headers({ origin: "https://admin.internal.example" }),
        "https://admin.internal.example",
      ),
    ).toBe(true);
    expect(
      hasExpectedMutationOrigin(
        new Headers({ origin: "https://public.example.com" }),
        "https://admin.internal.example",
      ),
    ).toBe(false);
  });

  it("rejects browser export requests initiated by another site", () => {
    expect(isCrossSiteRequest(new Headers({ "sec-fetch-site": "cross-site" }))).toBe(true);
    expect(isCrossSiteRequest(new Headers({ "sec-fetch-site": "same-origin" }))).toBe(false);
    expect(isCrossSiteRequest(new Headers())).toBe(false);
  });
});
