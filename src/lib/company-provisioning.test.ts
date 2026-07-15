import { describe, expect, it } from "vitest";

import {
  CompanyProvisioningError,
  validateCompanyProvisioningInput,
} from "@/lib/company-provisioning";

describe("company provisioning input", () => {
  it("normalizes the durable company and owner command", () => {
    expect(validateCompanyProvisioningInput({
      inviteOwner: true,
      name: "  Example Company  ",
      ownerEmail: " Owner@Example.COM ",
      slug: "EXAMPLE-COMPANY",
    })).toEqual({
      inviteOwner: true,
      name: "Example Company",
      ownerEmail: "owner@example.com",
      slug: "example-company",
    });
  });

  it("requires an explicit invitation preference and rejects unknown fields", () => {
    expect(() => validateCompanyProvisioningInput({
      name: "Example Company",
      ownerEmail: "owner@example.com",
      slug: "example-company",
    })).toThrow(CompanyProvisioningError);
    expect(() => validateCompanyProvisioningInput({
      inviteOwner: true,
      name: "Example Company",
      ownerEmail: "owner@example.com",
      role: "admin",
      slug: "example-company",
    })).toThrow(/unsupported/i);
  });

  it("rejects unsafe names, invalid owner addresses, and invalid slugs", () => {
    expect(() => validateCompanyProvisioningInput({
      inviteOwner: false,
      name: "Unsafe\nCompany",
      ownerEmail: "owner@example.com",
      slug: "unsafe-company",
    })).toThrow(/safe characters/i);
    expect(() => validateCompanyProvisioningInput({
      inviteOwner: false,
      name: "Example Company",
      ownerEmail: "not an email@example.com",
      slug: "example-company",
    })).toThrow(/owner email/i);
    expect(() => validateCompanyProvisioningInput({
      inviteOwner: false,
      name: "Example Company",
      ownerEmail: "owner@example.com",
      slug: "example--company?",
    })).toThrow(/identifier/i);
  });
});
