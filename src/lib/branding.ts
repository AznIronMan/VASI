import type { RuntimeSettings } from "@/lib/runtime-settings";

export type ProductBrand = Readonly<{
  displayName: string;
  organizationName: string;
  productMark: string;
  productName: string;
  supportEmail: string;
}>;

export const DEFAULT_PRODUCT_BRAND: ProductBrand = Object.freeze({
  displayName: "VASI V·Sign",
  organizationName: "VASI",
  productMark: "V·SIGN",
  productName: "V·Sign",
  supportEmail: "support@example.invalid",
});

export function resolveProductBrand(settings: RuntimeSettings): ProductBrand {
  const organizationName = safeText(settings.BRAND_ORGANIZATION_NAME, "BRAND_ORGANIZATION_NAME", 2, 120);
  const productName = safeText(settings.BRAND_PRODUCT_NAME, "BRAND_PRODUCT_NAME", 2, 80);
  const productMark = safeText(settings.BRAND_PRODUCT_MARK, "BRAND_PRODUCT_MARK", 2, 32);
  const supportEmail = safeEmail(settings.BRAND_SUPPORT_EMAIL);
  return Object.freeze({
    displayName: `${organizationName} ${productName}`,
    organizationName,
    productMark,
    productName,
    supportEmail,
  });
}

function safeText(value: string | undefined, name: string, minimum: number, maximum: number) {
  const normalized = value?.normalize("NFC").trim();
  if (!normalized || normalized.length < minimum || normalized.length > maximum || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error(`${name} must contain ${minimum} to ${maximum} safe characters.`);
  }
  return normalized;
}

function safeEmail(value: string | undefined) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized.length > 320 || !/^[^@\s]+@[^@\s]+$/.test(normalized)) {
    throw new Error("BRAND_SUPPORT_EMAIL must contain a valid email address.");
  }
  return normalized;
}
