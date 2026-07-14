import { headers } from "next/headers";

import { AuthPortal } from "@/components/auth/auth-portal";
import { getLoginAuthProviderAvailability } from "@/lib/auth-providers";
import { isRequestForOrigin } from "@/lib/host-policy";
import { resolveServerEnvironment } from "@/lib/server-environment";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  const requestHeaders = await headers();
  const { adminOrigin } = resolveServerEnvironment();
  const internalAdminHost = isRequestForOrigin(requestHeaders, adminOrigin);

  return (
    <AuthPortal
      allowRegistration={!internalAdminHost}
      callbackURL={internalAdminHost ? "/admin" : "/workspace"}
      providers={getLoginAuthProviderAvailability()}
      oauthError={Boolean(error)}
    />
  );
}
