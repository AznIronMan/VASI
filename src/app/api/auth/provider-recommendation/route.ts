import { NextResponse } from "next/server";

import {
  getLoginAuthProviderAvailability,
} from "@/lib/auth-providers";
import { resolveTrustedClientAddress } from "@/lib/client-address";
import { isCrossSiteRequest, isRequestForOrigin } from "@/lib/host-policy";
import {
  emailDomain,
  providerFromDomain,
  recommendProviderForEmail,
} from "@/lib/provider-recommendation";
import { consumeProviderRecommendationRateLimit } from "@/lib/provider-recommendation-rate-limit";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const settings = await getRuntimeSettings();
  const { authSecret, baseURL, trustedProxyCIDRs } = resolveServerSettings(settings);
  if (!isRequestForOrigin(request.headers, baseURL)) return new Response(null, { status: 404 });
  if (isCrossSiteRequest(request.headers)) {
    return NextResponse.json(
      { error: "Invalid request origin." },
      { headers: { "Cache-Control": "no-store" }, status: 403 },
    );
  }
  const email = new URL(request.url).searchParams.get("email") ?? "";
  const domain = emailDomain(email);
  if (!domain) {
    return NextResponse.json(
      { error: "Enter a valid email address." },
      { headers: { "Cache-Control": "no-store" }, status: 400 },
    );
  }

  const availability = getLoginAuthProviderAvailability(settings);
  const obviousProvider = providerFromDomain(domain);
  if (obviousProvider) return recommendationResponse(obviousProvider, availability);

  const address = resolveTrustedClientAddress(request.headers, trustedProxyCIDRs);
  let rateLimit;
  try {
    rateLimit = await consumeProviderRecommendationRateLimit({ address, authSecret });
  } catch {
    console.error(JSON.stringify({ event: "provider_recommendation_rate_limit_unavailable" }));
    return NextResponse.json(
      { error: "Provider detection is temporarily unavailable." },
      { headers: { "Cache-Control": "no-store", "Retry-After": "60" }, status: 503 },
    );
  }
  if (!rateLimit.accepted) {
    return NextResponse.json(
      { error: "Too many provider checks. Try again shortly." },
      {
        headers: {
          "Cache-Control": "no-store",
          "Retry-After": String(rateLimit.retryAfterSeconds),
        },
        status: 429,
      },
    );
  }

  const provider = await recommendProviderForEmail(email);
  return recommendationResponse(provider, availability);
}

function recommendationResponse(
  provider: ReturnType<typeof providerFromDomain>,
  availability: ReturnType<typeof getLoginAuthProviderAvailability>,
) {
  const selected = provider ? availability.find((item) => item.id === provider) : undefined;
  return NextResponse.json(
    {
      provider: selected?.id,
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
