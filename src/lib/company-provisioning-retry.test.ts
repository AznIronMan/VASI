import { createHash } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  clearCompanyProvisioningRetry,
  companyProvisioningRetryDefinitelyRejected,
  loadCompanyProvisioningRetry,
  nextCompanyProvisioningCommand,
  saveCompanyProvisioningRetry,
} from "@/lib/company-provisioning-retry";

const draft = {
  inviteOwner: true,
  name: "Example Company",
  ownerEmail: "owner@example.com",
  slug: "example-company",
};
const firstCommand = "11111111-1111-4111-8111-111111111111";
const secondCommand = "22222222-2222-4222-8222-222222222222";
const now = 1_784_070_000_000;

describe("company provisioning retry command", () => {
  it("reuses the command for the same normalized submission without retaining plaintext", async () => {
    const create = vi.fn().mockReturnValueOnce(firstCommand).mockReturnValueOnce(secondCommand);
    const first = await nextCompanyProvisioningCommand(undefined, draft, create, { digest, now });
    const retry = await nextCompanyProvisioningCommand(first, {
      ...draft,
      name: "  Example Company ",
      ownerEmail: "OWNER@EXAMPLE.COM",
      slug: "EXAMPLE-COMPANY",
    }, create, { digest, now: now + 1_000 });

    expect(retry).toBe(first);
    expect(create).toHaveBeenCalledTimes(1);
    expect(first.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(first)).not.toContain("Example Company");
    expect(JSON.stringify(first)).not.toContain("owner@example.com");
  });

  it.each([
    ["company name", { name: "Another Company" }],
    ["owner email", { ownerEmail: "another@example.com" }],
    ["company identifier", { slug: "another-company" }],
    ["invitation choice", { inviteOwner: false }],
  ])("creates a new command when the %s changes", async (_label, change) => {
    const create = vi.fn().mockReturnValueOnce(firstCommand).mockReturnValueOnce(secondCommand);
    const first = await nextCompanyProvisioningCommand(undefined, draft, create, { digest, now });
    const changed = await nextCompanyProvisioningCommand(
      first,
      { ...draft, ...change },
      create,
      { digest, now: now + 1_000 },
    );

    expect(changed.commandId).toBe(secondCommand);
    expect(changed).not.toBe(first);
  });

  it("still creates a server command when browser digesting is unavailable", async () => {
    const command = await nextCompanyProvisioningCommand(undefined, draft, () => firstCommand, {
      digest: async () => { throw new Error("Web Crypto unavailable"); },
      now,
    });

    expect(command).toEqual({ commandId: firstCommand, createdAt: now, fingerprint: "" });
  });

  it("distinguishes definite client rejection from ambiguous client-facing status", () => {
    expect(companyProvisioningRetryDefinitelyRejected(400)).toBe(true);
    expect(companyProvisioningRetryDefinitelyRejected(409)).toBe(true);
    expect(companyProvisioningRetryDefinitelyRejected(422)).toBe(true);
    expect(companyProvisioningRetryDefinitelyRejected(408)).toBe(false);
    expect(companyProvisioningRetryDefinitelyRejected(425)).toBe(false);
    expect(companyProvisioningRetryDefinitelyRejected(429)).toBe(false);
    expect(companyProvisioningRetryDefinitelyRejected(499)).toBe(false);
    expect(companyProvisioningRetryDefinitelyRejected(500)).toBe(false);
  });
});

describe("company provisioning retry storage", () => {
  it("restores an unchanged opaque command after a simulated reload", async () => {
    const storage = memoryStorage();
    const first = await nextCompanyProvisioningCommand(undefined, draft, () => firstCommand, { digest, now });
    saveCompanyProvisioningRetry(first, storage, now);
    const serialized = storage.value();
    const restored = loadCompanyProvisioningRetry(storage, now + 1_000);
    const retry = await nextCompanyProvisioningCommand(
      restored,
      draft,
      () => secondCommand,
      { digest, now: now + 1_000 },
    );

    expect(retry.commandId).toBe(firstCommand);
    expect(serialized).not.toContain("Example Company");
    expect(serialized).not.toContain("owner@example.com");
  });

  it("removes expired, corrupt, and extended records", async () => {
    const storage = memoryStorage();
    const valid = await nextCompanyProvisioningCommand(undefined, draft, () => firstCommand, { digest, now });
    saveCompanyProvisioningRetry(valid, storage, now);
    expect(loadCompanyProvisioningRetry(storage, now + 24 * 60 * 60 * 1_000 + 1)).toBeUndefined();
    expect(storage.value()).toBe("");

    storage.set(JSON.stringify({ ...valid, ownerEmail: "owner@example.com" }));
    expect(loadCompanyProvisioningRetry(storage, now)).toBeUndefined();
    storage.set("not-json");
    expect(loadCompanyProvisioningRetry(storage, now)).toBeUndefined();

    storage.set(JSON.stringify({ ...valid, commandId: "not-a-uuid" }));
    expect(loadCompanyProvisioningRetry(storage, now)).toBeUndefined();
    storage.set(JSON.stringify({ ...valid, fingerprint: "not-a-digest" }));
    expect(loadCompanyProvisioningRetry(storage, now)).toBeUndefined();
    storage.set(JSON.stringify({ ...valid, createdAt: now + 60_001 }));
    expect(loadCompanyProvisioningRetry(storage, now)).toBeUndefined();
  });

  it("clears completed commands and tolerates unavailable storage", async () => {
    const storage = memoryStorage();
    const valid = await nextCompanyProvisioningCommand(undefined, draft, () => firstCommand, { digest, now });
    saveCompanyProvisioningRetry(valid, storage, now);
    clearCompanyProvisioningRetry(storage);
    expect(storage.value()).toBe("");

    const unavailable = {
      getItem: () => { throw new Error("denied"); },
      removeItem: () => { throw new Error("denied"); },
      setItem: () => { throw new Error("denied"); },
    };
    expect(() => saveCompanyProvisioningRetry(valid, unavailable, now)).not.toThrow();
    expect(loadCompanyProvisioningRetry(unavailable, now)).toBeUndefined();
    expect(() => clearCompanyProvisioningRetry(unavailable)).not.toThrow();
  });
});

async function digest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function memoryStorage() {
  let value = "";
  return {
    getItem: () => value || null,
    removeItem: () => { value = ""; },
    set: (next: string) => { value = next; },
    setItem: (_key: string, next: string) => { value = next; },
    value: () => value,
  };
}
