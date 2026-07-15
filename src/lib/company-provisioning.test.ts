import { describe, expect, it } from "vitest";

import {
  CompanyProvisioningError,
  validateCompanyProvisioningInput,
} from "@/lib/company-provisioning";

describe("company provisioning input", () => {
  it("normalizes the durable company and owner command", () => {
    expect(validateCompanyProvisioningInput({
      commandId: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
      inviteOwner: true,
      name: "  Example Company  ",
      ownerEmail: " Owner@Example.COM ",
      slug: "EXAMPLE-COMPANY",
    })).toEqual({
      commandId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      inviteOwner: true,
      name: "Example Company",
      ownerEmail: "owner@example.com",
      slug: "example-company",
    });
  });

  it("requires an explicit invitation preference and rejects unknown fields", () => {
    expect(() => validateCompanyProvisioningInput({
      commandId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      name: "Example Company",
      ownerEmail: "owner@example.com",
      slug: "example-company",
    })).toThrow(CompanyProvisioningError);
    expect(() => validateCompanyProvisioningInput({
      commandId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      inviteOwner: true,
      name: "Example Company",
      ownerEmail: "owner@example.com",
      role: "admin",
      slug: "example-company",
    })).toThrow(/unsupported/i);
  });

  it("rejects unsafe names, invalid owner addresses, and invalid slugs", () => {
    expect(() => validateCompanyProvisioningInput({
      commandId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      inviteOwner: false,
      name: "Unsafe\nCompany",
      ownerEmail: "owner@example.com",
      slug: "unsafe-company",
    })).toThrow(/safe characters/i);
    expect(() => validateCompanyProvisioningInput({
      commandId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      inviteOwner: false,
      name: "Example Company",
      ownerEmail: "not an email@example.com",
      slug: "example-company",
    })).toThrow(/owner email/i);
    expect(() => validateCompanyProvisioningInput({
      commandId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      inviteOwner: false,
      name: "Example Company",
      ownerEmail: "owner@example.com",
      slug: "example--company?",
    })).toThrow(/identifier/i);
  });

  it("requires a UUID command identifier", () => {
    expect(() => validateCompanyProvisioningInput({
      commandId: "not-a-command",
      inviteOwner: true,
      name: "Example Company",
      ownerEmail: "owner@example.com",
      slug: "example-company",
    })).toThrow(/command identifier/i);
  });
});
