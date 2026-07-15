import process from "node:process";
import { connect as connectTLS } from "node:tls";
import { pathToFileURL } from "node:url";

import packageJSON from "../package.json" with { type: "json" };

const MAXIMUM_RESPONSE_BYTES = 65_536;
const OVERSIZED_AUTHENTICATION_BYTES = 65_537;
const PAGE_METHODS_DENIED = Object.freeze(["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const SUPPORTED_TLS_PROTOCOLS = Object.freeze(["TLSv1.2", "TLSv1.3"]);

export async function runPublicIngressProbe({
  exerciseRateLimit = false,
  fetchImplementation = fetch,
  inspectTLS = inspectSupportedTLS,
  origin,
  rateRequests = 48,
  retiredOrigin,
  timeoutMilliseconds = 10_000,
} = {}) {
  const publicOrigin = validHTTPSOrigin(origin, "public");
  const retired = retiredOrigin ? validHTTPSOrigin(retiredOrigin, "retired") : undefined;
  if (retired?.origin === publicOrigin.origin) throw new Error("The public and retired ingress origins must differ.");
  boundedInteger(timeoutMilliseconds, "timeout", 500, 30_000);
  boundedInteger(rateRequests, "rate request count", 32, 200);

  const tlsProtocols = await inspectTLS(publicOrigin, timeoutMilliseconds);
  if (
    !Array.isArray(tlsProtocols) || tlsProtocols.length !== SUPPORTED_TLS_PROTOCOLS.length ||
    !SUPPORTED_TLS_PROTOCOLS.every((protocol) => tlsProtocols.includes(protocol)) ||
    new Set(tlsProtocols).size !== tlsProtocols.length
  ) throw new Error("The public ingress supported TLS protocol contract failed.");

  const redirectPath = "/api/health?canonical-redirect=1";
  const httpURL = new URL(redirectPath, publicOrigin);
  httpURL.protocol = "http:";
  httpURL.port = "";
  const redirect = await request(fetchImplementation, httpURL, {
    headers: spoofedHeaders(),
    timeoutMilliseconds,
  });
  if (redirect.response.status !== 301) throw new Error("The public ingress HTTP route is not a permanent canonical redirect.");
  const redirectLocation = redirect.response.headers.get("location");
  if (!canonicalRedirectMatches(redirectLocation, httpURL, new URL(redirectPath, publicOrigin))) {
    throw new Error("The public ingress HTTP route did not use the canonical HTTPS origin.");
  }
  requireNoResponseSideEffect(redirect.response, "public HTTP redirect", { allowLocation: true });
  requireNoServerVersion(redirect.response, "public HTTP redirect");

  const health = await request(fetchImplementation, new URL("/api/health", publicOrigin), {
    headers: spoofedHeaders(),
    timeoutMilliseconds,
  });
  if (health.response.status !== 200) throw new Error("The public ingress health route is unavailable.");
  const healthPayload = parseJSONObject(health.body, "public health");
  if (
    healthPayload.status !== "ok" || healthPayload.service !== "vasi-auth" ||
    healthPayload.version !== packageJSON.version
  ) throw new Error("The public ingress health identity or version is invalid.");
  requireNoStore(health.response, "public health");
  requireNoServerVersion(health.response, "public health");

  const root = await request(fetchImplementation, publicOrigin, {
    headers: spoofedHeaders(),
    timeoutMilliseconds,
  });
  if (root.response.status !== 200 || root.body.length < 1) {
    throw new Error("The public ingress application route is unavailable.");
  }
  requirePublicSecurityHeaders(root.response);
  requireNoServerVersion(root.response, "public application");

  for (const method of PAGE_METHODS_DENIED) {
    const denied = await request(fetchImplementation, publicOrigin, {
      headers: spoofedHeaders(),
      method,
      timeoutMilliseconds,
    });
    if (denied.response.status !== 405 || denied.body !== "") {
      throw new Error("The public ingress rendered an application page for a prohibited method.");
    }
    requireNoStore(denied.response, "public page method denial");
    requirePublicSecurityHeaders(denied.response);
    requireNoResponseSideEffect(denied.response, "public page method denial");
    const allowed = new Set((denied.response.headers.get("allow") || "").split(",").map((value) => value.trim()));
    if (allowed.size !== 2 || !allowed.has("GET") || !allowed.has("HEAD")) {
      throw new Error("The public page method denial returned an invalid Allow contract.");
    }
  }

  const hostilePreflight = await request(
    fetchImplementation,
    new URL("/api/auth/provider-recommendation", publicOrigin),
    {
      headers: {
        ...spoofedHeaders(),
        "access-control-request-method": "POST",
        origin: "https://attacker.invalid",
      },
      method: "OPTIONS",
      timeoutMilliseconds,
    },
  );
  if (![204, 405].includes(hostilePreflight.response.status)) {
    throw new Error("The hostile cross-origin preflight returned an unexpected status.");
  }
  if (
    hostilePreflight.response.headers.has("access-control-allow-origin") ||
    hostilePreflight.response.headers.has("access-control-allow-credentials") ||
    hostilePreflight.response.headers.has("set-cookie")
  ) throw new Error("The public ingress authorized a hostile cross-origin preflight.");

  const oversized = await request(fetchImplementation, new URL("/api/auth/sign-in/email", publicOrigin), {
    body: new Uint8Array(OVERSIZED_AUTHENTICATION_BYTES),
    headers: {
      ...spoofedHeaders(),
      "content-type": "application/json",
      origin: publicOrigin.origin,
    },
    method: "POST",
    timeoutMilliseconds,
  });
  if (oversized.response.status !== 413) throw new Error("The public ingress did not reject an oversized authentication body.");
  requireNoStore(oversized.response, "oversized authentication");
  const oversizedPayload = parseJSONObject(oversized.body, "oversized authentication");
  if (oversizedPayload.error !== "The request body is too large.") {
    throw new Error("The public ingress returned an unexpected oversized-body response.");
  }

  let retiredStatus = null;
  if (retired) {
    const response = await request(fetchImplementation, retired, {
      headers: spoofedHeaders(),
      timeoutMilliseconds,
    });
    retiredStatus = response.response.status;
    if (retiredStatus !== 404) throw new Error("The retired public engine origin is not a content-free denial route.");
    if (response.response.headers.has("set-cookie")) throw new Error("The retired public engine origin issued a cookie.");
    if (response.response.headers.has("x-powered-by")) throw new Error("The retired public engine origin exposed an application runtime.");
    if (/vasi|private engine|v·sign/i.test(response.body)) {
      throw new Error("The retired public engine origin exposed product content.");
    }
  }

  let rateLimit;
  if (exerciseRateLimit) {
    const responses = await Promise.all(Array.from({ length: rateRequests }, (_, index) =>
      request(fetchImplementation, new URL(
        `/api/auth/provider-recommendation?email=${encodeURIComponent(`edge-proof-${index}@gmail.com`)}`,
        publicOrigin,
      ), {
        headers: { ...spoofedHeaders(), "sec-fetch-site": "same-origin" },
        timeoutMilliseconds,
      })
    ));
    const statuses = responses.map((entry) => entry.response.status);
    if (statuses.some((status) => ![200, 429].includes(status))) {
      throw new Error("The public ingress rate exercise returned an unexpected status.");
    }
    const accepted = statuses.filter((status) => status === 200).length;
    const limited = statuses.filter((status) => status === 429).length;
    if (!accepted || !limited) throw new Error("The public ingress authentication rate limit was not independently observable.");
    for (const entry of responses.filter((candidate) => candidate.response.status === 429)) {
      requireNoStore(entry.response, "authentication rate limit");
      if (entry.response.headers.get("retry-after") !== "1") {
        throw new Error("The public ingress rate response is missing its bounded retry interval.");
      }
      const payload = parseJSONObject(entry.body, "authentication rate limit");
      if (payload.error !== "Too many requests.") {
        throw new Error("The public ingress returned an unexpected rate-limit response.");
      }
    }
    rateLimit = Object.freeze({ accepted, limited, requests: rateRequests });
  }

  return Object.freeze({
    bodyLimitBytes: OVERSIZED_AUTHENTICATION_BYTES - 1,
    canonicalRedirect: true,
    crossOriginPreflight: "denied",
    observedVersion: healthPayload.version,
    pageMethods: Object.freeze({ allowed: Object.freeze(["GET", "HEAD"]), denied: PAGE_METHODS_DENIED.length }),
    rateLimit: rateLimit || null,
    retiredStatus,
    schema: "vasi-public-ingress-probe/v2",
    status: "pass",
    tlsProtocols: Object.freeze([...tlsProtocols].sort()),
  });
}

function canonicalRedirectMatches(location, requestURL, expectedURL) {
  if (!location) return false;
  try {
    return new URL(location, requestURL).href === expectedURL.href;
  } catch {
    return false;
  }
}

export async function inspectSupportedTLS(origin, timeoutMilliseconds) {
  const target = origin instanceof URL ? origin : validHTTPSOrigin(origin, "public");
  const protocols = await Promise.all(SUPPORTED_TLS_PROTOCOLS.map((protocol) =>
    connectTLSProtocol(target, protocol, timeoutMilliseconds)
  ));
  return Object.freeze(protocols);
}

function connectTLSProtocol(origin, protocol, timeoutMilliseconds) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = connectTLS({
      host: origin.hostname,
      maxVersion: protocol,
      minVersion: protocol,
      port: Number(origin.port || 443),
      rejectUnauthorized: true,
      servername: origin.hostname,
      timeout: timeoutMilliseconds,
    });
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    socket.once("error", () => finish(new Error("The public ingress TLS handshake failed.")));
    socket.once("timeout", () => finish(new Error("The public ingress TLS handshake timed out.")));
    socket.once("secureConnect", () => {
      if (!socket.authorized || socket.getProtocol() !== protocol) {
        finish(new Error("The public ingress TLS handshake contract failed."));
      } else {
        finish(null, protocol);
      }
    });
  });
}

async function request(fetchImplementation, url, {
  body,
  headers,
  method = "GET",
  timeoutMilliseconds,
}) {
  const response = await fetchImplementation(url, {
    body,
    cache: "no-store",
    headers,
    method,
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMilliseconds),
  });
  const advertised = response.headers.get("content-length");
  if (advertised && (!/^\d{1,10}$/.test(advertised) || Number(advertised) > MAXIMUM_RESPONSE_BYTES)) {
    throw new Error("The public ingress returned an oversized response.");
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > MAXIMUM_RESPONSE_BYTES) throw new Error("The public ingress returned an oversized response.");
  return { body: new TextDecoder().decode(bytes), response };
}

function spoofedHeaders() {
  return {
    accept: "application/json, text/html;q=0.9",
    forwarded: "for=198.51.100.7;proto=http;host=attacker.invalid",
    "user-agent": "VASI-public-ingress-probe/1",
    "x-forwarded-for": "203.0.113.9, 198.51.100.11",
    "x-forwarded-host": "attacker.invalid",
    "x-forwarded-proto": "http",
  };
}

function parseJSONObject(body, label) {
  let value;
  try {
    value = JSON.parse(body);
  } catch {
    throw new Error(`The ${label} response is not valid JSON.`);
  }
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error(`The ${label} response is not a JSON object.`);
  }
  return value;
}

function requireNoStore(response, label) {
  if (!/(?:^|,)\s*no-store\s*(?:,|$)/i.test(response.headers.get("cache-control") || "")) {
    throw new Error(`The ${label} response is cacheable.`);
  }
}

function requireNoResponseSideEffect(response, label, { allowLocation = false } = {}) {
  if (response.headers.has("set-cookie") || (!allowLocation && response.headers.has("location"))) {
    throw new Error(`The ${label} response produced a cookie or redirect side effect.`);
  }
}

function requireNoServerVersion(response, label) {
  const server = response.headers.get("server");
  if (server && /\/[0-9]/.test(server)) throw new Error(`The ${label} response discloses its server version.`);
  if (response.headers.has("x-powered-by")) throw new Error(`The ${label} response discloses its application runtime.`);
}

function requirePublicSecurityHeaders(response) {
  const exact = new Map([
    ["cross-origin-opener-policy", "same-origin"],
    ["cross-origin-resource-policy", "same-origin"],
    ["referrer-policy", "strict-origin-when-cross-origin"],
    ["x-content-type-options", "nosniff"],
    ["x-frame-options", "DENY"],
    ["x-permitted-cross-domain-policies", "none"],
  ]);
  for (const [name, value] of exact) {
    if (response.headers.get(name) !== value) throw new Error(`The public application ${name} contract failed.`);
  }
  const hsts = response.headers.get("strict-transport-security") || "";
  if (!/^max-age=31536000;\s*includeSubDomains$/i.test(hsts)) {
    throw new Error("The public application HSTS contract failed.");
  }
  const csp = new Set((response.headers.get("content-security-policy") || "").split(";").map((value) => value.trim()));
  for (const directive of [
    "default-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ]) {
    if (!csp.has(directive)) throw new Error(`The public application CSP is missing ${directive}.`);
  }
  const permissions = new Set((response.headers.get("permissions-policy") || "").split(",").map((value) => value.trim()));
  for (const directive of ["camera=()", "microphone=()", "geolocation=()", "browsing-topics=()"]) {
    if (!permissions.has(directive)) throw new Error(`The public application permissions policy is missing ${directive}.`);
  }
  requireNoServerVersion(response, "public application");
}

function validHTTPSOrigin(value, label) {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    throw new Error(`The ${label} ingress origin is invalid.`);
  }
  if (
    origin.protocol !== "https:" || origin.port || origin.pathname !== "/" || origin.search || origin.hash ||
    origin.username || origin.password
  ) throw new Error(`The ${label} ingress origin must be a credential-free HTTPS origin.`);
  return origin;
}

function boundedInteger(value, label, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`The public ingress ${label} must be between ${minimum} and ${maximum}.`);
  }
}

function parseArguments(args) {
  const [origin, ...rest] = args;
  if (!origin) usage();
  const result = { origin };
  for (let index = 0; index < rest.length; index += 1) {
    const name = rest[index];
    if (name === "--exercise-rate-limit") {
      result.exerciseRateLimit = true;
      continue;
    }
    const value = rest[++index];
    if (!value) usage();
    if (name === "--retired-origin") result.retiredOrigin = value;
    else if (name === "--rate-requests") result.rateRequests = Number(value);
    else if (name === "--timeout-ms") result.timeoutMilliseconds = Number(value);
    else usage();
  }
  return result;
}

function usage() {
  throw new Error(
    "Usage: node scripts/probe-public-ingress.mjs HTTPS_ORIGIN " +
    "[--retired-origin HTTPS_ORIGIN] [--exercise-rate-limit] [--rate-requests N]",
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runPublicIngressProbe(parseArguments(process.argv.slice(2)))
    .then((result) => console.info(JSON.stringify(result, null, 2)))
    .catch((error) => {
      console.error(error instanceof Error ? error.message : "VASI public ingress probe failed.");
      process.exitCode = 1;
    });
}
