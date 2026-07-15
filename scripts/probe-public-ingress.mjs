import process from "node:process";
import { request as requestHTTPS } from "node:https";
import { connect as connectTLS } from "node:tls";
import { pathToFileURL } from "node:url";

import packageJSON from "../package.json" with { type: "json" };

const MAXIMUM_RESPONSE_BYTES = 65_536;
const OVERSIZED_AUTHENTICATION_BYTES = 65_537;
const PAGE_METHODS_DENIED = Object.freeze(["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const SUPPORTED_TLS_PROTOCOLS = Object.freeze(["TLSv1.2", "TLSv1.3"]);
const NORMALIZATION_TARGETS = Object.freeze([
  "/%2e%2e/admin",
  "/..%2fadmin",
  "/%2e%2e%2fapi%2fadmin",
  "/%252e%252e%252fadmin",
  "/%00",
  "//admin",
  "/%5cadmin",
]);
const PRIVATE_RESPONSE_MARKERS = Object.freeze([
  "Identity administration",
  "Company workflows",
  "Private engine",
  "Company assurance gates",
]);

export async function runPublicIngressProbe({
  exerciseRateLimit = false,
  fetchImplementation = fetch,
  inspectAdversarial = inspectAdversarialBoundary,
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

  const adversarialBoundary = await inspectAdversarial(publicOrigin, timeoutMilliseconds);
  if (
    adversarialBoundary?.canonicalHostIsolationCases !== 3 ||
    adversarialBoundary?.normalizationDenials !== NORMALIZATION_TARGETS.length
  ) throw new Error("The public ingress adversarial request-target proof is incomplete.");

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
  requireNoTokenReflection(
    { body: root.body, headers: root.response.headers },
    "attacker.invalid",
    "public forwarded-header handling",
  );

  for (const method of PAGE_METHODS_DENIED) {
    const denied = await request(fetchImplementation, publicOrigin, {
      headers: {
        ...spoofedHeaders(),
        ...(method === "POST" ? { "x-http-method-override": "GET" } : {}),
      },
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

  const session = await request(fetchImplementation, new URL("/api/auth/get-session", publicOrigin), {
    headers: {
      ...spoofedHeaders(),
      origin: "https://attacker.invalid",
      "sec-fetch-site": "cross-site",
    },
    timeoutMilliseconds,
  });
  if (session.response.status !== 200 || session.body !== "null") {
    throw new Error("The unauthenticated session response exposed unexpected state.");
  }
  requireNoStore(session.response, "unauthenticated session");
  requireNoResponseSideEffect(session.response, "unauthenticated session");
  requireNoCorsAuthorization(session.response, "unauthenticated session");
  requirePublicSecurityHeaders(session.response);
  requireNoTokenReflection(
    { body: session.body, headers: session.response.headers },
    "attacker.invalid",
    "unauthenticated session",
  );

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
    adversarial: Object.freeze({
      canonicalHostIsolationCases: adversarialBoundary.canonicalHostIsolationCases,
      forwardedHeaders: "not_reflected",
      methodOverride: "denied",
      normalizationDenials: adversarialBoundary.normalizationDenials,
      sessionPrivacy: "no_store_null",
    }),
    bodyLimitBytes: OVERSIZED_AUTHENTICATION_BYTES - 1,
    canonicalRedirect: true,
    crossOriginPreflight: "denied",
    observedVersion: healthPayload.version,
    pageMethods: Object.freeze({ allowed: Object.freeze(["GET", "HEAD"]), denied: PAGE_METHODS_DENIED.length }),
    rateLimit: rateLimit || null,
    retiredStatus,
    schema: "vasi-public-ingress-probe/v3",
    status: "pass",
    tlsProtocols: Object.freeze([...tlsProtocols].sort()),
  });
}

export async function inspectAdversarialBoundary(
  origin,
  timeoutMilliseconds,
  rawRequestImplementation = rawHTTPSRequest,
) {
  const canonicalHost = origin instanceof URL ? origin : validHTTPSOrigin(origin, "public");
  const hostileHostCases = [
    Object.freeze({ host: "attacker.invalid", path: "/" }),
    Object.freeze({ host: `${canonicalHost.hostname}.attacker.invalid`, path: "/" }),
    Object.freeze({ host: canonicalHost.hostname, path: "https://attacker.invalid/" }),
  ];
  for (const requestTarget of hostileHostCases) {
    const observation = await rawRequestImplementation(canonicalHost, requestTarget, timeoutMilliseconds);
    requireHostIsolatedObservation(observation, canonicalHost);
  }
  for (const path of NORMALIZATION_TARGETS) {
    const observation = await rawRequestImplementation(canonicalHost, {
      host: canonicalHost.hostname,
      path,
    }, timeoutMilliseconds);
    requireNormalizedPathDenial(observation);
  }
  return Object.freeze({
    canonicalHostIsolationCases: hostileHostCases.length,
    normalizationDenials: NORMALIZATION_TARGETS.length,
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

function rawHTTPSRequest(origin, requestTarget, timeoutMilliseconds) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const outbound = requestHTTPS({
      agent: false,
      headers: {
        accept: "application/json, text/html;q=0.9",
        connection: "close",
        host: requestTarget.host,
        "user-agent": "VASI-public-ingress-probe/3",
      },
      hostname: origin.hostname,
      method: "GET",
      path: requestTarget.path,
      port: Number(origin.port || 443),
      rejectUnauthorized: true,
      servername: origin.hostname,
      timeout: timeoutMilliseconds,
    }, (response) => {
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        length += chunk.length;
        if (length > MAXIMUM_RESPONSE_BYTES) {
          outbound.destroy();
          finish(new Error("The public ingress adversarial response exceeded its bound."));
          return;
        }
        chunks.push(chunk);
      });
      response.once("error", () => finish(new Error("The public ingress adversarial response failed.")));
      response.once("end", () => {
        const headers = new Headers();
        for (const [name, value] of Object.entries(response.headers)) {
          if (Array.isArray(value)) value.forEach((entry) => headers.append(name, entry));
          else if (value !== undefined) headers.set(name, value);
        }
        finish(null, Object.freeze({
          body: Buffer.concat(chunks).toString("utf8"),
          headers,
          status: response.statusCode || 0,
        }));
      });
    });
    outbound.once("error", () => finish(new Error("The public ingress adversarial request failed.")));
    outbound.once("timeout", () => {
      outbound.destroy();
      finish(new Error("The public ingress adversarial request timed out."));
    });
    outbound.end();
  });
}

function requireHostIsolatedObservation(observation, origin) {
  requireBoundedRawObservation(observation, "canonical-host isolation");
  const allowed = new Set([301, 302, 307, 308, 400, 404, 421]);
  if (!allowed.has(observation.status)) {
    throw new Error("The public ingress selected application content for a hostile host or absolute target.");
  }
  const redirect = observation.headers.get("location");
  if ([301, 302, 307, 308].includes(observation.status)) {
    let target;
    try {
      target = new URL(redirect || "", origin);
    } catch {
      throw new Error("The public ingress hostile-host redirect is malformed.");
    }
    if (
      target.protocol !== "https:" || target.username || target.password ||
      target.hostname === "attacker.invalid" || target.hostname.endsWith(".attacker.invalid")
    ) throw new Error("The public ingress reflected a hostile host into a redirect.");
  } else if (redirect) {
    throw new Error("The public ingress hostile-host denial produced an unexpected redirect.");
  }
  requireRawPrivacy(observation, "canonical-host isolation");
  requireNoTokenReflection(observation, "attacker.invalid", "canonical-host isolation");
  if (/VASI|V·Sign|Identity administration|Company workflows|Private engine/i.test(observation.body)) {
    throw new Error("The public ingress hostile-host response exposed product content.");
  }
}

function requireNormalizedPathDenial(observation) {
  requireBoundedRawObservation(observation, "normalized-path denial");
  if (![400, 404].includes(observation.status)) {
    throw new Error("The public ingress did not reject an ambiguous or traversal-style request target.");
  }
  requireRawPrivacy(observation, "normalized-path denial");
  if (observation.headers.has("location")) {
    throw new Error("The public ingress normalized-path denial produced a redirect.");
  }
  if (!/(?:^|,)\s*no-store\s*(?:,|$)/i.test(observation.headers.get("cache-control") || "")) {
    throw new Error("The public ingress normalized-path denial is cacheable.");
  }
  const server = observation.headers.get("server");
  if (server && /\/[0-9]/.test(server)) {
    throw new Error("The public ingress normalized-path denial disclosed its server version.");
  }
  if (PRIVATE_RESPONSE_MARKERS.some((marker) => observation.body.includes(marker))) {
    throw new Error("The public ingress normalized-path denial exposed protected content.");
  }
}

function requireBoundedRawObservation(observation, label) {
  if (
    !observation || !Number.isInteger(observation.status) || !(observation.headers instanceof Headers) ||
    typeof observation.body !== "string" || Buffer.byteLength(observation.body) > MAXIMUM_RESPONSE_BYTES
  ) throw new Error(`The public ingress ${label} observation is invalid.`);
}

function requireRawPrivacy(observation, label) {
  if (
    observation.headers.has("set-cookie") || observation.headers.has("x-powered-by") ||
    observation.headers.has("access-control-allow-origin") ||
    observation.headers.has("access-control-allow-credentials")
  ) throw new Error(`The public ingress ${label} produced a state, runtime, or CORS side effect.`);
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

function requireNoCorsAuthorization(response, label) {
  if (
    response.headers.has("access-control-allow-origin") ||
    response.headers.has("access-control-allow-credentials")
  ) throw new Error(`The ${label} response authorized cross-origin access.`);
}

function requireNoTokenReflection(observation, token, label) {
  const headers = [...observation.headers.entries()].flat().join("\n");
  if (`${observation.body || ""}\n${headers}`.toLowerCase().includes(token.toLowerCase())) {
    throw new Error(`The ${label} response reflected hostile request metadata.`);
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
