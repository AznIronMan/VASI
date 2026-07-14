"use client";

import { useProductBrand } from "@/components/brand-provider";

export function BrandMark({ compact = false }: { compact?: boolean }) {
  const brand = useProductBrand();
  return (
    <div className={`brand-mark${compact ? " brand-mark--compact" : ""}`} aria-label={brand.displayName}>
      <span className="brand-mark__seal" aria-hidden="true">
        <svg viewBox="0 0 42 42" role="img">
          <path d="M21 2.5 37.1 11.8v18.4L21 39.5 4.9 30.2V11.8L21 2.5Z" />
          <path d="m13.4 21.2 5.1 5.1 10.2-11" />
        </svg>
      </span>
      <span className="brand-mark__type">
        <span className="brand-mark__company">{brand.organizationName}</span>
        <span className="brand-mark__divider" aria-hidden="true" />
        <span className="brand-mark__product">{brand.productMark}</span>
      </span>
    </div>
  );
}
