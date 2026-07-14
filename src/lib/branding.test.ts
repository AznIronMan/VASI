import { describe, expect, it } from "vitest";

import { resolveProductBrand } from "@/lib/branding";

describe("product branding", () => {
  it("resolves an installation-neutral brand", () => {
    expect(resolveProductBrand({
      BRAND_ORGANIZATION_NAME: "Example Corp",
      BRAND_PRODUCT_MARK: "VERIFY",
      BRAND_PRODUCT_NAME: "Verify Portal",
      BRAND_SUPPORT_EMAIL: "HELP@EXAMPLE.TEST",
    })).toEqual({
      displayName: "Example Corp Verify Portal",
      organizationName: "Example Corp",
      productMark: "VERIFY",
      productName: "Verify Portal",
      supportEmail: "help@example.test",
    });
  });
});
