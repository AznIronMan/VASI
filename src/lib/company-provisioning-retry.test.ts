import { describe, expect, it, vi } from "vitest";

import { nextCompanyProvisioningCommand } from "@/lib/company-provisioning-retry";

const draft = {
  inviteOwner: true,
  name: "Example Company",
  ownerEmail: "owner@example.com",
  slug: "example-company",
};

describe("company provisioning retry command", () => {
  it("reuses the command for the same normalized submission", () => {
    const create = vi.fn()
      .mockReturnValueOnce("11111111-1111-4111-8111-111111111111")
      .mockReturnValueOnce("22222222-2222-4222-8222-222222222222");
    const first = nextCompanyProvisioningCommand(undefined, draft, create);
    const retry = nextCompanyProvisioningCommand(first, {
      ...draft,
      name: "  Example Company ",
      ownerEmail: "OWNER@EXAMPLE.COM",
      slug: "EXAMPLE-COMPANY",
    }, create);

    expect(retry).toBe(first);
    expect(create).toHaveBeenCalledTimes(1);
  });

  it("creates a new command when any durable decision changes", () => {
    const create = vi.fn()
      .mockReturnValueOnce("11111111-1111-4111-8111-111111111111")
      .mockReturnValueOnce("22222222-2222-4222-8222-222222222222");
    const first = nextCompanyProvisioningCommand(undefined, draft, create);
    const changed = nextCompanyProvisioningCommand(first, { ...draft, inviteOwner: false }, create);

    expect(changed.commandId).toBe("22222222-2222-4222-8222-222222222222");
    expect(changed).not.toBe(first);
  });
});
