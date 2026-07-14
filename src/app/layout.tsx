import type { Metadata } from "next";

import "./globals.css";

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

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
