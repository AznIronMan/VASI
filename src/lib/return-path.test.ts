import { describe, expect, it } from "vitest";

import { safeAuthenticationReturnPath } from "@/lib/return-path";

describe("authentication return paths", () => {
  const handle = "A".repeat(43);

  it("accepts only an exact opaque evidence request path", () => {
    expect(safeAuthenticationReturnPath(`/r/${handle}`)).toBe(`/r/${handle}`);
  });

  it.each([
    "https://attacker.example/r/anything",
    `//attacker.example/r/${handle}`,
    `/r/${handle}/receipt`,
    `/r/${handle}?next=https://attacker.example`,
    "/workspace",
  ])("rejects %s", (value) => {
    expect(safeAuthenticationReturnPath(value)).toBe("/workspace");
  });
});
