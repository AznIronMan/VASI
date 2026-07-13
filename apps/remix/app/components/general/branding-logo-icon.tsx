import type { SVGAttributes } from 'react';

export type LogoProps = SVGAttributes<SVGSVGElement>;

export const BrandingLogoIcon = ({ ...props }: LogoProps) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 84 84" role="img" aria-labelledby="vasi-icon-title" {...props}>
      <title id="vasi-icon-title">Clark &amp; Burke VASI</title>
      <g fill="none" stroke="currentColor" strokeWidth="3">
        <rect x="3" y="3" width="78" height="78" rx="2" />
        <circle cx="42" cy="42" r="34" />
      </g>
      <text x="42" y="51" fill="currentColor" fontFamily="Georgia, serif" fontSize="25" textAnchor="middle">
        C&amp;B
      </text>
    </svg>
  );
};
