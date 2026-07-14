import { headers } from "next/headers";

import { AuthPortal } from "@/components/auth/auth-portal";
import { getLoginAuthProviderAvailability } from "@/lib/auth-providers";
import { isRequestForOrigin } from "@/lib/host-policy";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { safeAuthenticationReturnPath } from "@/lib/return-path";
import { resolveServerSettings } from "@/lib/server-settings";

export const dynamic = "force-dynamic";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; returnTo?: string }>;
}) {
  const { error, returnTo } = await searchParams;
  const [requestHeaders, settings] = await Promise.all([headers(), getRuntimeSettings()]);
  const { adminOrigin } = resolveServerSettings(settings);
  const internalAdminHost = isRequestForOrigin(requestHeaders, adminOrigin);

  return (
    <AuthPortal
      allowRegistration={!internalAdminHost}
      callbackURL={internalAdminHost ? "/admin" : safeAuthenticationReturnPath(returnTo)}
      providers={getLoginAuthProviderAvailability(settings)}
      oauthError={Boolean(error)}
    />
  );
}
