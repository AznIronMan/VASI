import { performance } from "node:perf_hooks";
import process from "node:process";
import { isDirectExecution } from "./direct-execution.mjs";

import policy from "../config/assurance-policy.json" with { type: "json" };

export async function runReadinessLoadProbe({
  allowHttpLoopback = false,
  concurrency = policy.load.concurrency,
  endpoints = policy.load.endpoints,
  maximumErrorRate = policy.load.maximumErrorRate,
  maximumP95Milliseconds = policy.load.maximumP95Milliseconds,
  origin,
  requests = policy.load.requests,
  timeoutMilliseconds = policy.load.timeoutMilliseconds,
}) {
  const target = validatedOrigin(origin, allowHttpLoopback);
  boundedInteger(concurrency, "concurrency", 1, 100);
  boundedInteger(requests, "requests", 1, 10_000);
  boundedInteger(timeoutMilliseconds, "timeout", 100, 60_000);
  if (concurrency > requests) throw new Error("Load-probe concurrency cannot exceed request count.");
  if (!Number.isFinite(maximumErrorRate) || maximumErrorRate < 0 || maximumErrorRate > 1) {
    throw new Error("Load-probe maximum error rate must be between zero and one.");
  }
  if (!Number.isFinite(maximumP95Milliseconds) || maximumP95Milliseconds < 1) {
    throw new Error("Load-probe p95 threshold must be positive.");
  }

  const latencies = [];
  const failures = [];
  let cursor = 0;
  const startedAt = performance.now();
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= requests) return;
      const endpoint = endpoints[index % endpoints.length];
      const started = performance.now();
      try {
        const response = await fetch(new URL(endpoint, target), {
          cache: "no-store",
          headers: { accept: "application/json", "user-agent": "VASI-readiness-load-probe/1" },
          redirect: "error",
          signal: AbortSignal.timeout(timeoutMilliseconds),
        });
        const body = await response.text();
        if (!response.ok || body.length > 16_384) throw new Error(`status ${response.status}`);
        const parsed = JSON.parse(body);
        validatePayload(endpoint, parsed);
      } catch (error) {
        failures.push({ endpoint, reason: boundedReason(error) });
      } finally {
        latencies.push(performance.now() - started);
      }
    }
  }));
  const durationMilliseconds = performance.now() - startedAt;
  const errorRate = failures.length / requests;
  const summary = {
    concurrency,
    durationMilliseconds: rounded(durationMilliseconds),
    errorRate: rounded(errorRate, 6),
    failed: failures.length,
    latencyMilliseconds: {
      maximum: rounded(Math.max(...latencies)),
      p50: rounded(percentile(latencies, 50)),
      p95: rounded(percentile(latencies, 95)),
      p99: rounded(percentile(latencies, 99)),
    },
    requests,
    requestsPerSecond: rounded(requests / (durationMilliseconds / 1000)),
    schema: "vasi-readiness-load-result/v1",
  };
  if (errorRate > maximumErrorRate) {
    throw new LoadProbeError(`Readiness error rate ${summary.errorRate} exceeded ${maximumErrorRate}.`, summary, failures.slice(0, 10));
  }
  if (summary.latencyMilliseconds.p95 > maximumP95Milliseconds) {
    throw new LoadProbeError(`Readiness p95 ${summary.latencyMilliseconds.p95}ms exceeded ${maximumP95Milliseconds}ms.`, summary, failures.slice(0, 10));
  }
  return summary;
}

export function percentile(values, requested) {
  if (!values.length) throw new Error("Cannot calculate a percentile without samples.");
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.max(0, Math.ceil((requested / 100) * sorted.length) - 1);
  return sorted[index];
}

class LoadProbeError extends Error {
  constructor(message, summary, failures) {
    super(message);
    this.failures = failures;
    this.summary = summary;
  }
}

function validatedOrigin(value, allowHttpLoopback) {
  const origin = new URL(value);
  if (origin.pathname !== "/" || origin.search || origin.hash || origin.username || origin.password) {
    throw new Error("Load-probe origin must not contain credentials, a path, query, or fragment.");
  }
  const loopback = ["127.0.0.1", "::1", "localhost"].includes(origin.hostname);
  if (origin.protocol !== "https:" && !(allowHttpLoopback && loopback && origin.protocol === "http:")) {
    throw new Error("Load probes require HTTPS except for explicitly allowed loopback fixtures.");
  }
  return origin;
}

function validatePayload(endpoint, payload) {
  if (!payload || Array.isArray(payload) || typeof payload !== "object") throw new Error("non-object response");
  if (endpoint === "/api/health" && (payload.status !== "ok" || typeof payload.version !== "string")) {
    throw new Error("invalid health response");
  }
  if (endpoint === "/api/brand" && (typeof payload.productName !== "string" || typeof payload.organizationName !== "string")) {
    throw new Error("invalid brand response");
  }
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Load-probe ${name} must be between ${minimum} and ${maximum}.`);
  }
}

function boundedReason(error) {
  return (error instanceof Error ? error.message : "request failed").slice(0, 160);
}

function rounded(value, digits = 2) {
  return Number(value.toFixed(digits));
}

function parseArguments(args) {
  const [origin, ...options] = args;
  if (!origin) usage();
  const parsed = { origin };
  for (let index = 0; index < options.length; index += 2) {
    const name = options[index];
    const value = Number(options[index + 1]);
    if (!Number.isFinite(value)) throw new Error(`Load-probe option ${name || "(missing)"} requires a number.`);
    if (name === "--concurrency") parsed.concurrency = value;
    else if (name === "--requests") parsed.requests = value;
    else if (name === "--p95-ms") parsed.maximumP95Milliseconds = value;
    else if (name === "--maximum-error-rate") parsed.maximumErrorRate = value;
    else throw new Error(`Unknown load-probe option ${name}.`);
  }
  return parsed;
}

function usage() {
  console.info("Usage: node scripts/probe-readiness-load.mjs HTTPS_ORIGIN [--requests N] [--concurrency N] [--p95-ms N] [--maximum-error-rate N]");
  process.exit(1);
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  runReadinessLoadProbe(parseArguments(process.argv.slice(2)))
    .then((summary) => console.info(JSON.stringify(summary, null, 2)))
    .catch((error) => {
      if (error?.summary) console.error(JSON.stringify({ failures: error.failures, summary: error.summary }, null, 2));
      console.error(error instanceof Error ? error.message : "VASI readiness load probe failed.");
      process.exitCode = 1;
    });
}
