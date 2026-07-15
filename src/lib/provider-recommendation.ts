import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

import type { AuthProviderId } from "@/lib/auth-providers";

type MxRecord = { exchange: string; priority: number };
type CancellableMxLookup = {
  cancel: () => void;
  promise: Promise<MxRecord[]>;
};
type MxResolver = (domain: string) => CancellableMxLookup | Promise<MxRecord[]>;

const recommendationCache = new Map<
  string,
  { expiresAt: number; provider: AuthProviderId | null }
>();
const inFlightRecommendations = new Map<string, Promise<AuthProviderId | undefined>>();
const lookupWaiters: Array<{
  activate: () => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
}> = [];
const POSITIVE_CACHE_DURATION_MS = 6 * 60 * 60 * 1_000;
const NEGATIVE_CACHE_DURATION_MS = 15 * 60 * 1_000;
const MAX_CACHE_ENTRIES = 1_000;
const MAX_CONCURRENT_MX_LOOKUPS = 16;
const MAX_QUEUED_MX_LOOKUPS = 64;
const MAX_MX_RECORDS = 20;
const MX_LOOKUP_TIMEOUT_MS = 1_500;
const MX_QUEUE_TIMEOUT_MS = 750;
let activeMxLookups = 0;

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
  if (email.length > 320) return undefined;
  const at = email.lastIndexOf("@");
  if (at < 1 || at !== email.indexOf("@") || at === email.length - 1) return undefined;
  const local = email.slice(0, at);
  if (local.length > 64 || /[\u0000-\u0020\u007f]/.test(local)) return undefined;

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
  resolver: MxResolver = cancellableMxResolver,
) {
  const domain = emailDomain(email);
  if (!domain) return undefined;

  const obviousProvider = providerFromDomain(domain);
  if (obviousProvider) return obviousProvider;

  const cached = recommendationCache.get(domain);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.provider ?? undefined;
  }
  if (cached) recommendationCache.delete(domain);

  const existing = inFlightRecommendations.get(domain);
  if (existing) return await existing;

  const recommendation = resolveProviderForDomain(domain, resolver)
    .finally(() => inFlightRecommendations.delete(domain));
  inFlightRecommendations.set(domain, recommendation);
  return await recommendation;
}

async function resolveProviderForDomain(domain: string, resolver: MxResolver) {
  let provider: AuthProviderId | undefined;
  try {
    const records = await withLookupSlot(async () => {
      const lookup = resolver(domain);
      const cancellable = isCancellableLookup(lookup) ? lookup : undefined;
      return await withTimeout(
        cancellable ? cancellable.promise : lookup as Promise<MxRecord[]>,
        MX_LOOKUP_TIMEOUT_MS,
        cancellable?.cancel,
      );
    });
    const exchanges = validateMxRecords(records);

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
    cacheRecommendation(domain, provider);
  } catch (error) {
    if (isAuthoritativeNegativeDnsError(error)) {
      cacheRecommendation(domain, undefined);
    }
  }
  return provider;
}

function cacheRecommendation(domain: string, provider?: AuthProviderId) {
  if (recommendationCache.size >= MAX_CACHE_ENTRIES) {
    recommendationCache.delete(recommendationCache.keys().next().value ?? "");
  }
  recommendationCache.set(domain, {
    expiresAt: Date.now() + (
      provider ? POSITIVE_CACHE_DURATION_MS : NEGATIVE_CACHE_DURATION_MS
    ),
    provider: provider ?? null,
  });
}

function isZohoMx(exchange: string) {
  const match = /^mx\d*\.(.+)$/.exec(exchange);
  return Boolean(match && zohoMxNamespaces.has(match[1]));
}

function cancellableMxResolver(domain: string): CancellableMxLookup {
  const resolver = new Resolver({ timeout: 1_000, tries: 1 });
  return {
    cancel: () => resolver.cancel(),
    promise: resolver.resolveMx(domain),
  };
}

function isCancellableLookup(
  value: CancellableMxLookup | Promise<MxRecord[]>,
): value is CancellableMxLookup {
  return "promise" in value && typeof value.cancel === "function";
}

function validateMxRecords(records: MxRecord[]) {
  if (!Array.isArray(records) || records.length > MAX_MX_RECORDS) {
    throw new Error("The MX response is invalid.");
  }
  return records.map((record) => {
    if (
      !record || typeof record.exchange !== "string" ||
      !Number.isInteger(record.priority) || record.priority < 0 || record.priority > 65_535
    ) {
      throw new Error("The MX response is invalid.");
    }
    if (record.exchange === ".") return "";
    const raw = record.exchange.endsWith(".")
      ? record.exchange.slice(0, -1)
      : record.exchange;
    if (raw !== raw.trim() || !raw) throw new Error("The MX response is invalid.");
    const exchange = domainToASCII(raw.toLowerCase());
    if (
      !exchange || exchange.length > 253 || isIP(exchange) || !exchange.includes(".") ||
      !exchange.split(".").every((label) =>
        /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(label),
      )
    ) {
      throw new Error("The MX response is invalid.");
    }
    return exchange;
  }).filter(Boolean);
}

async function withLookupSlot<T>(operation: () => Promise<T>) {
  const release = await acquireLookupSlot();
  try {
    return await operation();
  } finally {
    release();
  }
}

function acquireLookupSlot(): Promise<() => void> {
  if (activeMxLookups < MAX_CONCURRENT_MX_LOOKUPS) {
    activeMxLookups += 1;
    return Promise.resolve(releaseLookupSlot());
  }
  if (lookupWaiters.length >= MAX_QUEUED_MX_LOOKUPS) {
    return Promise.reject(new Error("The MX lookup queue is full."));
  }
  return new Promise((resolve, reject) => {
    const waiter = {
      activate: () => {
        clearTimeout(waiter.timeout);
        activeMxLookups += 1;
        resolve(releaseLookupSlot());
      },
      reject,
      timeout: undefined as unknown as ReturnType<typeof setTimeout>,
    };
    waiter.timeout = setTimeout(() => {
      const index = lookupWaiters.indexOf(waiter);
      if (index >= 0) lookupWaiters.splice(index, 1);
      waiter.reject(new Error("The MX lookup queue timed out."));
    }, MX_QUEUE_TIMEOUT_MS);
    waiter.timeout.unref?.();
    lookupWaiters.push(waiter);
  });
}

function releaseLookupSlot() {
  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeMxLookups -= 1;
    lookupWaiters.shift()?.activate();
  };
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, cancel?: () => void) {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => {
      try {
        cancel?.();
      } finally {
        reject(new Error("DNS lookup timed out."));
      }
    }, timeoutMs);
    timeout.unref?.();
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

function isAuthoritativeNegativeDnsError(error: unknown) {
  const code = typeof error === "object" && error && "code" in error
    ? String(error.code)
    : "";
  return code === "ENODATA" || code === "ENOTFOUND";
}

export function resetProviderRecommendationCacheForTests() {
  if (activeMxLookups || lookupWaiters.length || inFlightRecommendations.size) {
    throw new Error("Provider recommendation work is still active.");
  }
  recommendationCache.clear();
}
