import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { isDirectExecution } from "./direct-execution.mjs";

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SENSITIVE_API_NAMESPACES = Object.freeze(["admin", "evidence", "owner", "workspace"]);
const REQUIRED_NAMESPACES = Object.freeze([...SENSITIVE_API_NAMESPACES, "request"]);
const INTERNAL_NAMESPACES = new Set(["admin", "owner"]);
const HTTP_METHODS = Object.freeze(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const HTTP_METHOD_SET = new Set(HTTP_METHODS);
const MAXIMUM_ROUTE_FILES = 128;
const MAXIMUM_ROUTE_METHODS = 256;
const MAXIMUM_ROUTE_SOURCE_BYTES = 65_536;
const MAXIMUM_API_RESPONSE_BYTES = 4_096;
const MAXIMUM_PAGE_RESPONSE_BYTES = 32_768;
const AUTHENTICATION_DENIAL = '{"error":"Authentication required."}';
const DYNAMIC_VALUES = Object.freeze({
  activityId: "activity_1",
  artifactId: "00000000-0000-4000-8000-000000000000",
  handle: "A".repeat(43),
  provider: "google",
  userId: "00000000-0000-4000-8000-000000000000",
});
const PRIVATE_PAGE_MARKERS = Object.freeze([
  "Administrator access is required",
  "COMPANY ACCESS",
  "Company workflows",
  "Identity administration",
  "Sealed evidence requests",
  "Workspace | V·Sign",
]);

export async function discoverSensitiveRoutes(repositoryRoot = PROJECT_ROOT) {
  const root = path.resolve(repositoryRoot);
  const apiRoot = path.join(root, "src", "app", "api");
  const discovered = [];
  let routeFiles = 0;
  for (const namespace of SENSITIVE_API_NAMESPACES) {
    const namespaceRoot = path.join(apiRoot, namespace);
    const files = await routeFilesUnder(namespaceRoot);
    if (!files.length) throw new Error(`Sensitive route namespace ${namespace} is empty or unavailable.`);
    routeFiles += files.length;
    for (const filename of files) {
      const source = await boundedRouteSource(filename);
      const methods = exportedHTTPMethods(source);
      if (!methods.length) throw new Error(`Sensitive route ${relativeSource(root, filename)} exports no supported HTTP method.`);
      const route = apiRoutePath(apiRoot, filename);
      for (const method of methods) {
        discovered.push(routeEntry({ filename, method, namespace, root, route }));
      }
    }
  }

  const requestRoot = path.join(root, "src", "app", "r");
  const requestFiles = await routeFilesUnder(requestRoot);
  if (!requestFiles.length) throw new Error("Sensitive route namespace request is empty or unavailable.");
  routeFiles += requestFiles.length;
  for (const filename of requestFiles) {
    const source = await boundedRouteSource(filename);
    const methods = exportedHTTPMethods(source);
    if (!methods.length) throw new Error(`Sensitive route ${relativeSource(root, filename)} exports no supported HTTP method.`);
    const route = requestRoutePath(path.join(root, "src", "app"), filename);
    for (const method of methods) {
      discovered.push(routeEntry({ filename, method, namespace: "request", root, route }));
    }
  }
  if (routeFiles > MAXIMUM_ROUTE_FILES) throw new Error("The sensitive route-file inventory exceeds its bound.");
  discovered.sort((left, right) => left.path.localeCompare(right.path) ||
    HTTP_METHODS.indexOf(left.method) - HTTP_METHODS.indexOf(right.method));
  validateRouteInventory(discovered);
  return Object.freeze(discovered.map((entry) => Object.freeze(entry)));
}

export async function runPublicRouteIsolationProbe({
  fetchImplementation = fetch,
  origin,
  repositoryRoot = PROJECT_ROOT,
  routes,
  timeoutMilliseconds = 10_000,
} = {}) {
  const publicOrigin = validHTTPSOrigin(origin);
  boundedInteger(timeoutMilliseconds, "timeout", 500, 30_000);
  const inventory = routes || await discoverSensitiveRoutes(repositoryRoot);
  validateRouteInventory(inventory);
  await mapBounded(inventory, 8, async (entry) => {
    const target = new URL(entry.path, publicOrigin);
    const malformedJSONBody = ["GET", "HEAD"].includes(entry.method) ? undefined : '{"vasi":';
    const result = await boundedRequest(fetchImplementation, target, {
      body: malformedJSONBody,
      headers: requestHeaders(publicOrigin, Boolean(malformedJSONBody)),
      maximumBytes: MAXIMUM_API_RESPONSE_BYTES,
      method: entry.method,
      timeoutMilliseconds,
    });
    assertAPIDenial(entry, result);
  });

  const pages = protectedPages();
  for (const page of pages) {
    const target = new URL(page.path, publicOrigin);
    const result = await boundedRequest(fetchImplementation, target, {
      headers: requestHeaders(publicOrigin, false),
      maximumBytes: MAXIMUM_PAGE_RESPONSE_BYTES,
      method: "GET",
      timeoutMilliseconds,
    });
    assertPageDenial(page, target, publicOrigin, result);
  }

  const namespaceMethods = Object.fromEntries(REQUIRED_NAMESPACES.map((namespace) => [
    namespace,
    inventory.filter((entry) => entry.namespace === namespace).length,
  ]));
  return Object.freeze({
    apiMethods: inventory.length,
    internalApiMethods: inventory.filter((entry) => entry.audience === "internal").length,
    namespaces: Object.freeze(namespaceMethods),
    participantApiMethods: inventory.filter((entry) => entry.audience === "participant").length,
    protectedPages: pages.length,
    schema: "vasi-public-route-isolation-probe/v1",
    status: "pass",
  });
}

async function routeFilesUnder(directory, depth = 0) {
  if (depth > 16) throw new Error("The sensitive route tree exceeds its depth bound.");
  let metadata;
  try {
    metadata = await lstat(directory);
  } catch {
    return [];
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("A sensitive route namespace is not a physical directory.");
  }
  const files = [];
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const filename = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error("The sensitive route tree contains a symbolic link.");
    if (entry.isDirectory()) files.push(...await routeFilesUnder(filename, depth + 1));
    else if (entry.isFile() && entry.name === "route.ts") files.push(filename);
  }
  return files;
}

async function boundedRouteSource(filename) {
  const metadata = await lstat(filename);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1 || metadata.size > MAXIMUM_ROUTE_SOURCE_BYTES) {
    throw new Error("A sensitive route source is unavailable or outside its bound.");
  }
  return readFile(filename, "utf8");
}

export function exportedHTTPMethods(source) {
  if (typeof source !== "string" || Buffer.byteLength(source) > MAXIMUM_ROUTE_SOURCE_BYTES) {
    throw new Error("A sensitive route source is unavailable or outside its bound.");
  }
  const code = maskNonCode(source);
  const methods = new Set();
  for (const pattern of [
    /\bexport\s+(?:async\s+)?function\s+(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s*\(/g,
    /\bexport\s+const\s+(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\b/g,
  ]) {
    for (const match of code.matchAll(pattern)) methods.add(match[1]);
  }
  for (const match of code.matchAll(/\bexport\s*\{([^}]*)\}/g)) {
    for (const candidate of match[1].split(",")) {
      const parts = candidate.trim().split(/\s+as\s+/);
      const exported = parts.at(-1)?.trim();
      if (exported && HTTP_METHOD_SET.has(exported)) methods.add(exported);
    }
  }
  return Object.freeze(HTTP_METHODS.filter((method) => methods.has(method)));
}

function maskNonCode(source) {
  let state = "code";
  let escaped = false;
  let output = "";
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (state === "code") {
      if (character === "/" && next === "/") {
        output += "  ";
        index += 1;
        state = "line";
      } else if (character === "/" && next === "*") {
        output += "  ";
        index += 1;
        state = "block";
      } else if (["'", '"', "`"].includes(character)) {
        output += " ";
        state = character;
        escaped = false;
      } else output += character;
      continue;
    }
    if (state === "line") {
      output += character === "\n" ? "\n" : " ";
      if (character === "\n") state = "code";
      continue;
    }
    if (state === "block") {
      if (character === "*" && next === "/") {
        output += "  ";
        index += 1;
        state = "code";
      } else output += character === "\n" ? "\n" : " ";
      continue;
    }
    output += character === "\n" ? "\n" : " ";
    if (escaped) escaped = false;
    else if (character === "\\") escaped = true;
    else if (character === state) state = "code";
  }
  if (!["code", "line"].includes(state)) throw new Error("A sensitive route source contains an unterminated literal or comment.");
  return output;
}

function apiRoutePath(apiRoot, filename) {
  return sourceRoutePath("/api", path.relative(apiRoot, path.dirname(filename)).split(path.sep));
}

function requestRoutePath(appRoot, filename) {
  return sourceRoutePath("", path.relative(appRoot, path.dirname(filename)).split(path.sep));
}

function sourceRoutePath(prefix, segments) {
  const rendered = [];
  for (const segment of segments) {
    if (/^\([a-z0-9-]+\)$/.test(segment)) continue;
    if (/^[a-z0-9][a-z0-9-]*$/.test(segment)) {
      rendered.push(segment);
      continue;
    }
    let match = /^\[([A-Za-z][A-Za-z0-9]*)\]$/.exec(segment);
    if (match) {
      rendered.push(DYNAMIC_VALUES[match[1]] || "00000000-0000-4000-8000-000000000000");
      continue;
    }
    match = /^\[\[?\.\.\.([A-Za-z][A-Za-z0-9]*)\]\]?$/.exec(segment);
    if (match) {
      rendered.push("proof");
      continue;
    }
    throw new Error(`The sensitive route segment ${segment} is unsupported.`);
  }
  const value = `${prefix}/${rendered.join("/")}`.replaceAll(/\/{2,}/g, "/");
  if (!value.startsWith("/") || value.includes("..")) throw new Error("A sensitive route path is unsafe.");
  return value;
}

function routeEntry({ filename, method, namespace, root, route }) {
  return {
    audience: INTERNAL_NAMESPACES.has(namespace) ? "internal" : "participant",
    method,
    namespace,
    path: route,
    source: relativeSource(root, filename),
  };
}

function relativeSource(root, filename) {
  const relative = path.relative(root, filename).split(path.sep).join("/");
  if (!relative || relative.startsWith("../") || path.isAbsolute(relative)) {
    throw new Error("A sensitive route source is outside the repository.");
  }
  return relative;
}

function validateRouteInventory(inventory) {
  if (!Array.isArray(inventory) || inventory.length < REQUIRED_NAMESPACES.length || inventory.length > MAXIMUM_ROUTE_METHODS) {
    throw new Error("The sensitive route-method inventory is incomplete or outside its bound.");
  }
  const namespaces = new Set();
  const unique = new Set();
  for (const entry of inventory) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) ||
      !REQUIRED_NAMESPACES.includes(entry.namespace) || !HTTP_METHOD_SET.has(entry.method) ||
      !["internal", "participant"].includes(entry.audience) ||
      typeof entry.path !== "string" || !entry.path.startsWith("/") || entry.path.length > 512 ||
      typeof entry.source !== "string" || !entry.source.startsWith("src/app/") || entry.source.length > 512) {
      throw new Error("The sensitive route-method inventory is malformed.");
    }
    const expectedAudience = INTERNAL_NAMESPACES.has(entry.namespace) ? "internal" : "participant";
    const expectedPrefix = entry.namespace === "request" ? "/r/" : `/api/${entry.namespace}/`;
    if (entry.audience !== expectedAudience || !entry.path.startsWith(expectedPrefix)) {
      throw new Error("The sensitive route-method inventory has an invalid namespace boundary.");
    }
    const key = `${entry.method} ${entry.path}`;
    if (unique.has(key)) throw new Error("The sensitive route-method inventory contains a duplicate.");
    unique.add(key);
    namespaces.add(entry.namespace);
  }
  if (REQUIRED_NAMESPACES.some((namespace) => !namespaces.has(namespace))) {
    throw new Error("The sensitive route-method inventory is incomplete.");
  }
}

function assertAPIDenial(entry, { body, response }) {
  const label = `sensitive API denial ${entry.method} ${entry.path}`;
  requireNoStore(response, label);
  requireNoSideEffects(response, label);
  requireNoCORS(response, label);
  requireNoRuntimeDisclosure(response, label);
  if (entry.audience === "internal") {
    if (response.status !== 404 || body !== "" || response.headers.has("content-type")) {
      throw new Error("A public caller discovered an internal API route.");
    }
    const vary = new Set((response.headers.get("vary") || "").split(",").map((value) => value.trim().toLowerCase()));
    if (!vary.has("host")) throw new Error("An internal API denial is not isolated by host cache key.");
    return;
  }
  if (response.status !== 401 || body !== AUTHENTICATION_DENIAL ||
    !/^application\/json(?:;|$)/i.test(response.headers.get("content-type") || "")) {
    throw new Error("A participant API route did not return the exact authentication denial.");
  }
}

function protectedPages() {
  const handle = DYNAMIC_VALUES.handle;
  return Object.freeze([
    { expectedStatus: 404, kind: "hidden", path: "/admin" },
    { expectedStatus: 404, kind: "hidden", path: "/admin/evidence" },
    { expectedStatus: 404, kind: "hidden", path: "/owner" },
    { expectedLocation: "/", expectedStatus: 307, kind: "redirect", path: "/workspace" },
    {
      expectedLocation: `/?returnTo=${encodeURIComponent(`/r/${handle}`)}`,
      expectedStatus: 307,
      kind: "redirect",
      path: `/r/${handle}`,
    },
    {
      expectedLocation: `/?returnTo=${encodeURIComponent(`/r/${handle}`)}`,
      expectedStatus: 307,
      kind: "redirect",
      path: `/r/${handle}/receipt`,
    },
  ]);
}

function assertPageDenial(page, requestURL, publicOrigin, { body, response }) {
  const label = `protected page denial ${page.path}`;
  requireNoStore(response, label);
  requireNoCORS(response, label);
  requireNoRuntimeDisclosure(response, label);
  if (response.headers.has("set-cookie")) throw new Error("A protected page denial issued a cookie.");
  if (response.status !== page.expectedStatus || body.length < 1 ||
    !/^text\/html(?:;|$)/i.test(response.headers.get("content-type") || "")) {
    throw new Error("A protected page returned an unexpected denial contract.");
  }
  if (page.kind === "hidden") {
    if (response.headers.has("location")) throw new Error("A hidden internal page redirected a public caller.");
    if (PRIVATE_PAGE_MARKERS.some((marker) => body.toLowerCase().includes(marker.toLowerCase()))) {
      throw new Error("A hidden internal page disclosed protected page metadata or content.");
    }
  } else {
    const location = response.headers.get("location");
    let actual;
    try {
      actual = location ? new URL(location, requestURL) : undefined;
    } catch {
      throw new Error("A protected page returned a malformed login redirect.");
    }
    const expected = new URL(page.expectedLocation, publicOrigin);
    if (!actual || actual.href !== expected.href || actual.origin !== publicOrigin.origin) {
      throw new Error("A protected page returned a non-canonical login redirect.");
    }
    if (PRIVATE_PAGE_MARKERS.some((marker) => body.toLowerCase().includes(marker.toLowerCase()))) {
      throw new Error("An unauthenticated page redirect disclosed protected page metadata.");
    }
  }
}

async function boundedRequest(fetchImplementation, url, {
  body,
  headers,
  maximumBytes,
  method,
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
  if (advertised && (!/^\d{1,10}$/.test(advertised) || Number(advertised) > maximumBytes)) {
    throw new Error("A sensitive route returned an oversized response.");
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > maximumBytes) throw new Error("A sensitive route returned an oversized response.");
  return { body: new TextDecoder().decode(bytes), response };
}

function requestHeaders(origin, hasBody) {
  return {
    accept: "application/json, text/html;q=0.9",
    ...(hasBody ? { "content-type": "application/json" } : {}),
    forwarded: "for=198.51.100.7;proto=http;host=attacker.invalid",
    origin: origin.origin,
    "sec-fetch-site": "same-origin",
    "user-agent": "VASI-public-route-isolation-probe/1",
    "x-forwarded-for": "203.0.113.9, 198.51.100.11",
    "x-forwarded-host": "attacker.invalid",
    "x-forwarded-proto": "http",
  };
}

function requireNoStore(response, label) {
  const directives = (response.headers.get("cache-control") || "")
    .split(",")
    .map((value) => value.trim().toLowerCase());
  if (!directives.includes("no-store")) throw new Error(`The ${label} is cacheable.`);
}

function requireNoSideEffects(response, label) {
  if (response.headers.has("set-cookie") || response.headers.has("location")) {
    throw new Error(`The ${label} produced a cookie or redirect side effect.`);
  }
}

function requireNoCORS(response, label) {
  if (response.headers.has("access-control-allow-origin") ||
    response.headers.has("access-control-allow-credentials")) {
    throw new Error(`The ${label} disclosed cross-origin authorization.`);
  }
}

function requireNoRuntimeDisclosure(response, label) {
  if (response.headers.has("x-powered-by") || /\/[0-9]/.test(response.headers.get("server") || "")) {
    throw new Error(`The ${label} disclosed its application or server runtime.`);
  }
}

async function mapBounded(values, concurrency, operation) {
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= values.length) return;
      await operation(values[index]);
    }
  }));
}

function validHTTPSOrigin(value) {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    throw new Error("The public route-isolation origin is invalid.");
  }
  if (origin.protocol !== "https:" || origin.port || origin.pathname !== "/" || origin.search || origin.hash ||
    origin.username || origin.password) {
    throw new Error("The public route-isolation origin must be a credential-free HTTPS origin.");
  }
  return origin;
}

function boundedInteger(value, label, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`The public route-isolation ${label} must be between ${minimum} and ${maximum}.`);
  }
}

function parseArguments(args) {
  const [origin, ...rest] = args;
  if (!origin) usage();
  const parsed = { origin };
  for (let index = 0; index < rest.length; index += 2) {
    if (rest[index] !== "--timeout-ms" || !rest[index + 1]) usage();
    parsed.timeoutMilliseconds = Number(rest[index + 1]);
  }
  return parsed;
}

function usage() {
  throw new Error("Usage: node scripts/probe-public-route-isolation.mjs HTTPS_ORIGIN [--timeout-ms N]");
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  runPublicRouteIsolationProbe(parseArguments(process.argv.slice(2)))
    .then((result) => console.info(JSON.stringify(result, null, 2)))
    .catch((error) => {
      console.error(error instanceof Error ? error.message : "VASI public route-isolation probe failed.");
      process.exitCode = 1;
    });
}
