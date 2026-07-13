import type { AuthProviderId } from "@/lib/auth-providers";

export function SocialIcon({ provider }: { provider: AuthProviderId }) {
  if (provider === "microsoft") {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path fill="#f25022" d="M2 2h9.5v9.5H2z" />
        <path fill="#7fba00" d="M12.5 2H22v9.5h-9.5z" />
        <path fill="#00a4ef" d="M2 12.5h9.5V22H2z" />
        <path fill="#ffb900" d="M12.5 12.5H22V22h-9.5z" />
      </svg>
    );
  }

  if (provider === "google") {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path fill="#4285F4" d="M21.6 12.2c0-.7-.1-1.5-.2-2.2H12v4.2h5.4a4.6 4.6 0 0 1-2 3v2.7h3.5c2-1.9 3.2-4.6 3.2-7.7Z" />
        <path fill="#34A853" d="M12 22c2.9 0 5.3-1 7-2.6l-3.5-2.7c-1 .7-2.2 1-3.5 1a6.1 6.1 0 0 1-5.8-4.2H2.7v2.8A10 10 0 0 0 12 22Z" />
        <path fill="#FBBC05" d="M6.2 13.5A6 6 0 0 1 6 12c0-.5 0-1 .2-1.5V7.7H2.7A10 10 0 0 0 2 12c0 1.6.4 3 1.1 4.3l3.1-2.8Z" />
        <path fill="#EA4335" d="M12 6.3c1.6 0 3 .5 4.1 1.6l3.1-3A10 10 0 0 0 2.7 7.7l3.5 2.8A6.1 6.1 0 0 1 12 6.3Z" />
      </svg>
    );
  }

  if (provider === "apple") {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path fill="currentColor" d="M18.8 12.7c0-3 2.5-4.5 2.6-4.6a5.6 5.6 0 0 0-4.4-2.4c-1.8-.2-3.6 1.1-4.5 1.1-1 0-2.4-1-4-1-2.1 0-4.1 1.3-5.2 3.2-2.3 4-.6 9.9 1.6 13.1 1.1 1.6 2.4 3.3 4.1 3.2 1.6 0 2.3-1 4.3-1 2 0 2.6 1 4.3 1 1.8 0 3-1.6 4-3.2 1.3-1.8 1.8-3.6 1.8-3.7-.1 0-4.6-1.8-4.6-5.7ZM15.8 3.8A5.2 5.2 0 0 0 17 0a5.4 5.4 0 0 0-3.5 1.8 5 5 0 0 0-1.3 3.6 4.5 4.5 0 0 0 3.6-1.6Z" transform="scale(.88) translate(1.2 0)" />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#6001d2" d="M12.7 13.4 8.2 2H3l7 16.5L7.4 24h4.9L24 2h-5.1l-6.2 11.4Z" />
    </svg>
  );
}
