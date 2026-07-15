import process from "node:process";
import { pathToFileURL } from "node:url";

import packageJSON from "../package.json" with { type: "json" };

const MAXIMUM_RESPONSE_BYTES = 65_536;
const OVERSIZED_AUTHENTICATION_BYTES = 65_537;

export async function runPublicIngressProbe({
  exerciseRateLimit = false,
  fetchImplementation = fetch,
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
  requireHeader(health.response, "strict-transport-security", "public health");
  if (health.response.headers.get("x-content-type-options")?.toLowerCase() !== "nosniff") {
    throw new Error("The public ingress is missing nosniff protection.");
  }
  const server = health.response.headers.get("server");
  if (server && /\/[0-9]/.test(server)) throw new Error("The public ingress discloses its server version.");

  const root = await request(fetchImplementation, publicOrigin, {
    headers: spoofedHeaders(),
    timeoutMilliseconds,
  });
  if (root.response.status !== 200 || root.body.length < 1) {
    throw new Error("The public ingress application route is unavailable.");
  }
  requireHeader(root.response, "strict-transport-security", "public application");

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
    observedVersion: healthPayload.version,
    rateLimit: rateLimit || null,
    retiredStatus,
    schema: "vasi-public-ingress-probe/v1",
    status: "pass",
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

function requireHeader(response, name, label) {
  if (!response.headers.get(name)) throw new Error(`The ${label} response is missing ${name}.`);
}

function validHTTPSOrigin(value, label) {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    throw new Error(`The ${label} ingress origin is invalid.`);
  }
  if (
    origin.protocol !== "https:" || origin.pathname !== "/" || origin.search || origin.hash ||
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
