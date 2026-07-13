import backgroundPattern from '@documenso/assets/images/background-pattern.png';
import { Link, Outlet } from 'react-router';

import { BrandingLogo } from '~/components/general/branding-logo';

export default function Layout() {
  return (
    <main className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-4 py-12 md:p-12 lg:p-24">
      <div>
        <div className="absolute -inset-[min(600px,max(400px,60vw))] -z-[1] flex items-center justify-center opacity-70">
          <img
            src={backgroundPattern}
            alt="background pattern"
            className="dark:brightness-95 dark:contrast-[70%] dark:invert dark:sepia"
            style={{
              mask: 'radial-gradient(rgba(255, 255, 255, 1) 0%, transparent 80%)',
              WebkitMask: 'radial-gradient(rgba(255, 255, 255, 1) 0%, transparent 80%)',
            }}
          />
        </div>

        <div className="relative w-full">
          <Link
            to="/"
            aria-label="VASI home"
            className="mx-auto mb-6 block w-fit rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
          >
            <BrandingLogo className="h-12 w-auto max-w-[min(82vw,300px)]" />
          </Link>
          <Outlet />
        </div>
      </div>
    </main>
  );
}
