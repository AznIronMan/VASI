import type { SVGAttributes } from 'react';

export type LogoProps = SVGAttributes<SVGSVGElement>;

/**
 * VASI wordmark using the Clark & Burke monogram and CNB's public brand colors.
 * The mark remains monochrome through currentColor so it works in dark mode,
 * print certificates, transactional surfaces, and customer-branded contexts.
 */
export const BrandingLogo = ({ ...props }: LogoProps) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 430 84"
      role="img"
      aria-labelledby="vasi-logo-title"
      {...props}
    >
      <title id="vasi-logo-title">VASI by Clark &amp; Burke</title>
      <g fill="none" stroke="currentColor" strokeWidth="3">
        <rect x="3" y="3" width="78" height="78" rx="2" />
        <circle cx="42" cy="42" r="34" />
      </g>
      <text x="42" y="51" fill="currentColor" fontFamily="Georgia, serif" fontSize="25" textAnchor="middle">
        C&amp;B
      </text>
      <text
        x="101"
        y="49"
        fill="currentColor"
        fontFamily="Inter, sans-serif"
        fontSize="42"
        fontWeight="750"
        letterSpacing="3"
      >
        VASI
      </text>
      <text
        x="104"
        y="69"
        fill="currentColor"
        fontFamily="Inter, sans-serif"
        fontSize="11"
        fontWeight="600"
        letterSpacing="2.2"
      >
        VERIFIED AUTHORIZED SIGNING
      </text>
    </svg>
  );
};
