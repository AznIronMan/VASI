import { resolveMx } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

import type { AuthProviderId } from "@/lib/auth-providers";

type MxRecord = { exchange: string; priority: number };
type MxResolver = (domain: string) => Promise<MxRecord[]>;

const recommendationCache = new Map<
  string,
  { expiresAt: number; provider: AuthProviderId | null }
>();
const CACHE_DURATION_MS = 6 * 60 * 60 * 1_000;
const MAX_CACHE_ENTRIES = 1_000;

const consumerDomains: Record<string, AuthProviderId> = {
  "gmail.com": "google",
  "googlemail.com": "google",
  "outlook.com": "microsoft",
  "hotmail.com": "microsoft",
  "live.com": "microsoft",
  "msn.com": "microsoft",
  "icloud.com": "apple",
  "me.com": "apple",
  "mac.com": "apple",
  "yahoo.com": "yahoo",
  "ymail.com": "yahoo",
  "rocketmail.com": "yahoo",
  "zoho.com": "zoho",
  "zohomail.com": "zoho",
  "zohomail.eu": "zoho",
  "zohomail.in": "zoho",
  "zohomail.com.au": "zoho",
};

const zohoMxNamespaces = new Set([
  "zoho.com",
  "zoho.eu",
  "zoho.in",
  "zoho.com.au",
  "zoho.jp",
  "zohocloud.ca",
  "zoho.sa",
  "zoho.uk",
]);

export function emailDomain(value: string) {
  const email = value.trim().toLowerCase();
  const at = email.lastIndexOf("@");
  if (at < 1 || at !== email.indexOf("@") || at === email.length - 1) return undefined;

  const domain = domainToASCII(email.slice(at + 1));
  if (
    !domain ||
    domain.length > 253 ||
    isIP(domain) ||
    !domain.includes(".") ||
    !domain.split(".").every((label) =>
      /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(label),
    )
  ) {
    return undefined;
  }

  return domain;
}

export function providerFromDomain(domain: string) {
  if (consumerDomains[domain]) return consumerDomains[domain];
  if (/^yahoo\.[a-z.]+$/.test(domain)) return "yahoo" as const;
  if (/^zohomail\.(?:jp|ca|sa|uk)$/.test(domain)) return "zoho" as const;
  return undefined;
}

export async function recommendProviderForEmail(
  email: string,
  resolver: MxResolver = resolveMx,
) {
  const domain = emailDomain(email);
  if (!domain) return undefined;

  const obviousProvider = providerFromDomain(domain);
  if (obviousProvider) return obviousProvider;

  const cached = recommendationCache.get(domain);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.provider ?? undefined;
  }

  let provider: AuthProviderId | undefined;
  try {
    const records = await withTimeout(resolver(domain), 1_500);
    const exchanges = records.map((record) => record.exchange.toLowerCase().replace(/\.$/, ""));

    if (exchanges.some((exchange) => exchange.endsWith(".mail.protection.outlook.com"))) {
      provider = "microsoft";
    } else if (
      exchanges.some((exchange) =>
        exchange === "aspmx.l.google.com" ||
        exchange.endsWith(".google.com") ||
        exchange.endsWith(".googlemail.com"),
      )
    ) {
      provider = "google";
    } else if (exchanges.some(isZohoMx)) {
      provider = "zoho";
    } else if (exchanges.some((exchange) => exchange.endsWith(".icloud.com"))) {
      provider = "apple";
    } else if (exchanges.some((exchange) => exchange.endsWith(".yahoodns.net"))) {
      provider = "yahoo";
    }
  } catch {
    provider = undefined;
  }

  if (recommendationCache.size >= MAX_CACHE_ENTRIES) {
    recommendationCache.delete(recommendationCache.keys().next().value ?? "");
  }
  recommendationCache.set(domain, {
    expiresAt: Date.now() + CACHE_DURATION_MS,
    provider: provider ?? null,
  });

  return provider;
}

function isZohoMx(exchange: string) {
  const match = /^mx\d*\.(.+)$/.exec(exchange);
  return Boolean(match && zohoMxNamespaces.has(match[1]));
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number) {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      const timeout = setTimeout(() => reject(new Error("DNS lookup timed out.")), timeoutMs);
      timeout.unref?.();
    }),
  ]);
}

export function resetProviderRecommendationCacheForTests() {
  recommendationCache.clear();
}
