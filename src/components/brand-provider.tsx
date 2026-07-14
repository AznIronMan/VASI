"use client";

import { createContext, useContext, useEffect, useState } from "react";

import { DEFAULT_PRODUCT_BRAND, type ProductBrand } from "@/lib/branding";

const ProductBrandContext = createContext<ProductBrand>(DEFAULT_PRODUCT_BRAND);

export function BrandProvider({ children, initialBrand }: { children: React.ReactNode; initialBrand: ProductBrand }) {
  const [brand, setBrand] = useState(initialBrand);
  useEffect(() => {
    let active = true;
    const timeout = window.setTimeout(() => {
      fetch("/api/brand", { cache: "no-store" })
        .then(async (response) => response.ok ? response.json() as Promise<ProductBrand> : DEFAULT_PRODUCT_BRAND)
        .then((configured) => { if (active) setBrand(configured); })
        .catch(() => undefined);
    }, 0);
    return () => { active = false; window.clearTimeout(timeout); };
  }, []);
  return <ProductBrandContext.Provider value={brand}>{children}</ProductBrandContext.Provider>;
}

export function useProductBrand() {
  return useContext(ProductBrandContext);
}
