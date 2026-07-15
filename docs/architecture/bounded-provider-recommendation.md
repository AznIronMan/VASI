# Bounded email-provider recommendation

Status: implemented in VASI 0.38.0.

## Purpose and boundary

V·Sign recommends an identity provider from an entered email address so a
participant is more likely to use an existing Microsoft, Google, Yahoo, Apple,
or Zoho identity instead of creating another password. Consumer domains are a
fixed local mapping. A custom domain may require one MX lookup to recognize
Microsoft 365, Google Workspace, Zoho Mail, iCloud Mail, or Yahoo Mail.

This is a convenience signal, not account discovery. VASI does not ask a
provider whether the address exists, does not validate mailbox ownership at
this step, and does not treat MX ownership as proof that a particular person
can authenticate with that provider. The selected provider must still complete
its normal OIDC/OAuth protocol and return the required verified identity.

## Public request decision

The gateway evaluates a recommendation request in this order:

1. Require the configured public gateway hostname. The private administrator
   hostname and every unknown host receive 404.
2. Reject browser requests labeled cross-site by Fetch Metadata.
3. Parse one bounded email address with a maximum 320-character total,
   64-character local part, strict domain labels, and no address-literal domain.
4. Resolve fixed consumer-domain mappings without DNS or throttle state.
5. For a custom domain, resolve the client address through the shared strict
   trusted-proxy policy and atomically consume both client and installation
   PostgreSQL buckets.
6. Only an accepted custom-domain request can enter the bounded MX resolver.

Every response is `no-store`. A throttle-storage failure returns a generic 503
and performs no DNS lookup. An exceeded client or installation bucket returns a
generic 429 with a bounded `Retry-After`. The browser preserves all configured
provider choices and the deliberately secondary manual-account path when
recommendation is unavailable.

## Durable throttle and privacy

Gateway migration `0009_gateway_rate_limit` stores mutable expiry-indexed
counter rows. One SQL statement increments the client and installation buckets
under PostgreSQL conflict serialization. The client limit is 30 accepted custom
domain checks per 60 seconds; the installation limit is 600 per 60 seconds.
Both values are fixed application security policy rather than tenant settings.

Keys are domain-separated HMAC-SHA-256 values derived from the gateway auth
secret. The client key uses the same normalized address identity as public
verification, including IPv6 `/64` grouping and one shared unattributable
bucket. The global key contains no address. Raw email addresses, domains,
client addresses, and request values never enter the throttle table. Expired
rows older than one day are pruned in bounded batches during accepted counter
operations. Secret rotation intentionally starts new opaque buckets.

## DNS work contract

Custom-domain work has three independent bounds:

- concurrent calls for the same normalized domain share one in-flight promise;
- at most 16 MX lookups run and at most 64 additional domains wait for a slot;
  excess work or a queue wait over 750 milliseconds returns a neutral result;
- each lookup has a 1.5-second application timeout. The first-party resolver
  also uses one one-second DNS attempt and is cancelled on timeout.

Responses may contain at most 20 strictly validated MX records. Priorities,
host lengths, labels, IP-literal exchanges, whitespace, and null-MX syntax are
checked before provider matching. A successful recognized result is cached for
six hours. A successful unrecognized or authoritative `ENODATA`/`ENOTFOUND`
result is cached for 15 minutes. Timeout, saturation, malformed response, and
transient resolver failures are not cached, so an outage does not create a
long-lived false negative. The process cache is bounded to 1,000 domains and is
only a performance layer; PostgreSQL remains the cross-process abuse boundary.

## Interpretation, operations, and rollback

A recommendation means only that fixed domain or MX metadata resembles a
supported provider. DNS can be stale, delegated, compromised, unavailable, or
intentionally routed differently from identity. The UI therefore describes a
recommendation and always exposes other configured providers.

Operators must preserve the trusted-proxy boundary, database availability, and
normal DNS egress for the gateway host. Monitoring should alert on the generic
rate-limit-unavailable event count without logging an address, email, domain,
bucket digest, or DNS answer. Installation-specific upstream connection and
query-size limits remain complementary denial-of-service controls.

Migration `0009` is additive. VASI 0.37.0 ignores the new table and can remain
the immediate rollback runtime after migration. It does not gain the durable
provider-recommendation bounds, so rollback duration should remain short while
the upstream proxy retains its own request controls.
