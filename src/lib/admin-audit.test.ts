import { describe, expect, it } from "vitest";

import { normalizeAdminAuditMetadata } from "@/lib/admin-audit";

describe("administrator audit metadata", () => {
  it("accepts bounded outcome metadata and returns a detached value", () => {
    const metadata = { outcomeCode: "completed", provider: "google", result: { changed: true } };
    const normalized = normalizeAdminAuditMetadata(metadata);
    expect(normalized).toEqual(metadata);
    expect(normalized).not.toBe(metadata);
  });

  it.each([
    [{ accessToken: "not-recordable" }, "prohibited field"],
    [{ nested: { password: "not-recordable" } }, "prohibited field"],
    [{ value: "x".repeat(513) }, "oversized string"],
    [{ value: Number.MAX_VALUE }, "safe integers"],
    [{ values: Array.from({ length: 101 }, () => 1) }, "oversized list"],
  ])("rejects unsafe metadata %#", (metadata, message) => {
    expect(() => normalizeAdminAuditMetadata(metadata)).toThrow(message);
  });

  it("rejects an oversized encoded object", () => {
    const metadata = Object.fromEntries(
      Array.from({ length: 40 }, (_, index) => [`field${index}`, "x".repeat(300)]),
    );
    expect(() => normalizeAdminAuditMetadata(metadata)).toThrow("too large");
  });
});
