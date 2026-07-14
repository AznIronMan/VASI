import type { Metadata } from "next";

import { BrandProvider } from "@/components/brand-provider";
import { resolveProductBrand } from "@/lib/branding";
import { getRuntimeSettings } from "@/lib/runtime-settings";

import "./globals.css";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: {
    default: "V·Sign | Secure access",
    template: "%s | V·Sign",
  },
  description: "Secure identity access and independently verifiable evidence for VASI workflows.",
  applicationName: "V·Sign",
  robots: {
    index: false,
    follow: false,
  },
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const brand = resolveProductBrand(await getRuntimeSettings());
  return (
    <html lang="en">
      <body><BrandProvider initialBrand={brand}>{children}</BrandProvider></body>
    </html>
  );
}
