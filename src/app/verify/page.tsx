import type { Metadata } from "next";
import Link from "next/link";

import { BrandMark } from "@/components/brand-mark";
import { EvidenceVerifier } from "@/components/evidence/evidence-verifier";

export const metadata: Metadata = {
  description: "Verify the cryptographic fingerprint and integrity seals for a VASI evidence record.",
  referrer: "no-referrer",
  title: "Verify evidence",
};

export default async function VerificationPage({
  searchParams,
}: {
  searchParams: Promise<{ fingerprint?: string }>;
}) {
  const { fingerprint } = await searchParams;
  return (
    <main className="verification-shell">
      <header><Link href="/" aria-label="Return to V Sign"><BrandMark compact /></Link></header>
      <EvidenceVerifier initialFingerprint={fingerprint?.toLowerCase()} />
      <p className="verification-note">This lookup proves only that VASI recognizes the exact fingerprint and can validate its stored event chain and seals. It is not a legal conclusion or a certificate-chain trust opinion.</p>
    </main>
  );
}
