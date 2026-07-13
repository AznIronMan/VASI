import { NextResponse } from "next/server";

import {
  getAuthProviderAvailability,
  type AuthProviderId,
} from "@/lib/auth-providers";
import {
  emailDomain,
  recommendProviderForEmail,
} from "@/lib/provider-recommendation";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const email = new URL(request.url).searchParams.get("email") ?? "";
  if (!emailDomain(email)) {
    return NextResponse.json({ error: "Enter a valid email address." }, { status: 400 });
  }

  const provider = await recommendProviderForEmail(email);
  const availability = getAuthProviderAvailability();
  const selected = provider
    ? availability.find((item) => item.id === provider)
    : undefined;

  return NextResponse.json(
    {
      provider: provider as AuthProviderId | undefined,
      label: selected?.label,
      configured: selected?.configured ?? false,
    },
    {
      headers: {
        "Cache-Control": "no-store",
      },
    },
  );
}
