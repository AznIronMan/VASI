import { AuthPortal } from "@/components/auth/auth-portal";
import { getAuthProviderAvailability } from "@/lib/auth-providers";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  return (
    <AuthPortal
      providers={getAuthProviderAvailability()}
      oauthError={Boolean(error)}
    />
  );
}
