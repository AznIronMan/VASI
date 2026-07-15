import { readFile } from "node:fs/promises";
import process from "node:process";
import { isDirectExecution } from "./direct-execution.mjs";

const MAXIMUM_CONFIG_BYTES = 4 * 1024 * 1024;
const MAXIMUM_TOKENS = 100_000;
const MAXIMUM_DEPTH = 64;

export const PUBLIC_INGRESS_EXAMPLE_SETTINGS = Object.freeze({
  gatewayUpstreamAddress: "127.0.0.1:3000",
  gatewayUpstreamName: "vasi_public_gateway",
  publicCertificate: "/etc/nginx/certs/vsign.example.com.crt",
  publicCertificateKey: "/etc/nginx/certs/vsign.example.com.key",
  publicHost: "vsign.example.com",
  retiredCertificate: "/etc/nginx/certs/vasi.example.com.crt",
  retiredCertificateKey: "/etc/nginx/certs/vasi.example.com.key",
  retiredHost: "vasi.example.com",
});

export function renderPublicIngressConfiguration(input) {
  const settings = renderSettings(input);
  const retired = settings.retiredHost ? `
server {
    listen 80;
    server_name ${settings.retiredHost};
    server_tokens off;
    return 404;
}

server {
    listen 443 ssl;
    http2 on;
    server_name ${settings.retiredHost};
    server_tokens off;

    ssl_certificate ${settings.retiredCertificate};
    ssl_certificate_key ${settings.retiredCertificateKey};
    ssl_protocols TLSv1.2 TLSv1.3;

    return 404;
}
` : "";

  return `# VASI public-ingress contract. Include this file only in Nginx's http context.
limit_req_zone $binary_remote_addr zone=vasi_public_general:10m rate=100r/s;
limit_req_zone $binary_remote_addr zone=vasi_public_auth:10m rate=5r/s;
limit_conn_zone $binary_remote_addr zone=vasi_public_connections:10m;
map $status $vasi_public_bad_request_cache_control {
    default "";
    400 no-store;
}

upstream ${settings.gatewayUpstreamName} {
    server ${settings.gatewayUpstreamAddress};
    keepalive 16;
}

server {
    listen 80;
    server_name ${settings.publicHost};
    server_tokens off;
    return 301 https://${settings.publicHost}$request_uri;
}
${retired}
server {
    listen 443 ssl;
    http2 on;
    server_name ${settings.publicHost};
    server_tokens off;

    ssl_certificate ${settings.publicCertificate};
    ssl_certificate_key ${settings.publicCertificateKey};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:VASI_Public_TLS:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    client_max_body_size 64k;
    client_body_buffer_size 64k;
    client_body_timeout 10s;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
    client_header_timeout 10s;
    keepalive_timeout 30s;
    keepalive_requests 1000;
    send_timeout 30s;
    reset_timedout_connection on;

    limit_req_status 429;
    limit_conn_status 429;
    add_header Cache-Control $vasi_public_bad_request_cache_control always;

    error_page 413 = @vasi_request_too_large;
    error_page 429 = @vasi_rate_limited;

    location / {
        if ($request_uri ~* "^(?://|[^?]*%(?:00|25|2e|2f|5c))") {
            return 400;
        }
        limit_req zone=vasi_public_general burst=400 nodelay;
        limit_conn vasi_public_connections 80;
${proxyDirectives(settings.gatewayUpstreamName, 8)}
    }

    location ^~ /api/auth/ {
        if ($request_uri ~* "^(?://|[^?]*%(?:00|25|2e|2f|5c))") {
            return 400;
        }
        limit_req zone=vasi_public_auth burst=30 nodelay;
        limit_conn vasi_public_connections 80;
${proxyDirectives(settings.gatewayUpstreamName, 8)}
    }

    location @vasi_request_too_large {
        internal;
        default_type application/json;
        add_header Cache-Control "no-store" always;
        return 413 '{"error":"The request body is too large."}';
    }

    location @vasi_rate_limited {
        internal;
        default_type application/json;
        add_header Cache-Control "no-store" always;
        add_header Retry-After "1" always;
        return 429 '{"error":"Too many requests."}';
    }
}
`;
}

export function auditPublicIngressConfiguration(source, input) {
  const settings = auditSettings(input);
  const nodes = parseNginxConfiguration(source);
  const failures = [];
  requireZone(nodes, "limit_req_zone", [
    "$binary_remote_addr",
    "zone=vasi_public_general:10m",
    "rate=100r/s",
  ], failures, "general request zone");
  requireZone(nodes, "limit_req_zone", [
    "$binary_remote_addr",
    "zone=vasi_public_auth:10m",
    "rate=5r/s",
  ], failures, "authentication request zone");
  requireZone(nodes, "limit_conn_zone", [
    "$binary_remote_addr",
    "zone=vasi_public_connections:10m",
  ], failures, "connection zone");
  validateBadRequestCacheMap(nodes, failures);

  const servers = blocksNamed(nodes, "server");
  const publicServers = servers.filter((server) => serverNames(server).includes(settings.publicHost));
  validatePublicServers(publicServers, settings, failures);
  if (settings.retiredHost) {
    const retiredServers = servers.filter((server) => serverNames(server).includes(settings.retiredHost));
    validateRetiredServers(retiredServers, settings, failures);
  }

  return Object.freeze({
    failures: Object.freeze(failures),
    publicHost: settings.publicHost,
    retiredHost: settings.retiredHost || null,
    schema: "vasi-public-ingress-config-audit/v1",
    serversChecked: publicServers.length + (settings.retiredHost
      ? servers.filter((server) => serverNames(server).includes(settings.retiredHost)).length
      : 0),
    upstreamName: settings.gatewayUpstreamName,
  });
}

export function parseNginxConfiguration(source) {
  if (typeof source !== "string" || Buffer.byteLength(source) > MAXIMUM_CONFIG_BYTES) {
    throw new Error("The Nginx configuration is unavailable or outside the audit bound.");
  }
  const tokens = tokenize(source);
  let cursor = 0;

  function parse(depth, closingBrace) {
    if (depth > MAXIMUM_DEPTH) throw new Error("The Nginx configuration nesting is outside the audit bound.");
    const nodes = [];
    let words = [];
    while (cursor < tokens.length) {
      const token = tokens[cursor++];
      if (token === ";") {
        if (!words.length) throw new Error("The Nginx configuration contains an empty directive.");
        nodes.push(Object.freeze({ args: Object.freeze(words.slice(1)), name: words[0] }));
        words = [];
        continue;
      }
      if (token === "{") {
        if (!words.length) throw new Error("The Nginx configuration contains an unnamed block.");
        nodes.push(Object.freeze({
          args: Object.freeze(words.slice(1)),
          children: Object.freeze(parse(depth + 1, true)),
          name: words[0],
        }));
        words = [];
        continue;
      }
      if (token === "}") {
        if (!closingBrace || words.length) throw new Error("The Nginx configuration braces are malformed.");
        return nodes;
      }
      words.push(token);
    }
    if (closingBrace || words.length) throw new Error("The Nginx configuration is incomplete.");
    return nodes;
  }

  return Object.freeze(parse(0, false));
}

function validatePublicServers(servers, settings, failures) {
  if (servers.length !== 2) {
    failures.push("the public host must have exactly one HTTP and one HTTPS server");
    return;
  }
  const http = servers.filter((server) => listensOn(server, 80, false));
  const https = servers.filter((server) => listensOn(server, 443, true));
  if (http.length !== 1 || https.length !== 1) {
    failures.push("the public host must have exact HTTP redirect and HTTPS application servers");
    return;
  }
  requireExactServerName(http[0], settings.publicHost, failures, "public HTTP server");
  requireDirective(http[0], "server_tokens", ["off"], failures, "public HTTP server");
  requireDirective(
    http[0],
    "return",
    ["301", `https://${settings.publicHost}$request_uri`],
    failures,
    "public HTTP redirect",
  );
  if (descendantsNamed(http[0], "proxy_pass").length) failures.push("the public HTTP redirect must not proxy");

  const server = https[0];
  requireExactServerName(server, settings.publicHost, failures, "public HTTPS server");
  for (const [name, args] of [
    ["server_tokens", ["off"]],
    ["ssl_protocols", ["TLSv1.2", "TLSv1.3"]],
    ["ssl_session_cache", ["shared:VASI_Public_TLS:10m"]],
    ["ssl_session_timeout", ["1d"]],
    ["ssl_session_tickets", ["off"]],
    ["client_max_body_size", ["64k"]],
    ["client_body_buffer_size", ["64k"]],
    ["client_body_timeout", ["10s"]],
    ["client_header_buffer_size", ["1k"]],
    ["large_client_header_buffers", ["4", "8k"]],
    ["client_header_timeout", ["10s"]],
    ["keepalive_timeout", ["30s"]],
    ["keepalive_requests", ["1000"]],
    ["send_timeout", ["30s"]],
    ["reset_timedout_connection", ["on"]],
    ["limit_req_status", ["429"]],
    ["limit_conn_status", ["429"]],
    ["add_header", ["Cache-Control", "$vasi_public_bad_request_cache_control", "always"]],
    ["error_page", ["413", "=", "@vasi_request_too_large"]],
    ["error_page", ["429", "=", "@vasi_rate_limited"]],
  ]) requireDirective(server, name, args, failures, "public HTTPS server");
  requireNonemptyDirective(server, "ssl_certificate", failures, "public HTTPS server");
  requireNonemptyDirective(server, "ssl_certificate_key", failures, "public HTTPS server");

  const locations = directBlocks(server, "location");
  const root = locations.filter((location) => equalArgs(location.args, ["/"]));
  const auth = locations.filter((location) => equalArgs(location.args, ["^~", "/api/auth/"]));
  const tooLarge = locations.filter((location) => equalArgs(location.args, ["@vasi_request_too_large"]));
  const rateLimited = locations.filter((location) => equalArgs(location.args, ["@vasi_rate_limited"]));
  if (
    locations.length !== 4 || root.length !== 1 || auth.length !== 1 ||
    tooLarge.length !== 1 || rateLimited.length !== 1
  ) {
    failures.push("the public HTTPS server must expose only the reviewed root, authentication, and error locations");
    return;
  }
  validateInvalidTargetGuards(server, [root[0], auth[0]], failures);
  validateProxyLocation(root[0], settings.gatewayUpstreamName, failures, "public root location");
  requireDirective(root[0], "limit_req", ["zone=vasi_public_general", "burst=400", "nodelay"], failures, "public root location");
  requireDirective(root[0], "limit_conn", ["vasi_public_connections", "80"], failures, "public root location");
  validateProxyLocation(auth[0], settings.gatewayUpstreamName, failures, "public authentication location");
  requireDirective(auth[0], "limit_req", ["zone=vasi_public_auth", "burst=30", "nodelay"], failures, "public authentication location");
  requireDirective(auth[0], "limit_conn", ["vasi_public_connections", "80"], failures, "public authentication location");
  validateErrorLocation(tooLarge[0], 413, false, failures);
  validateErrorLocation(rateLimited[0], 429, true, failures);
  if (descendantsNamed(server, "proxy_pass").length !== 2) {
    failures.push("the public HTTPS server contains an unreviewed or missing proxy target");
  }
}

function validateBadRequestCacheMap(nodes, failures) {
  const maps = blocksNamed(nodes, "map").filter((block) =>
    equalArgs(block.args, ["$status", "$vasi_public_bad_request_cache_control"])
  );
  if (maps.length !== 1) {
    failures.push("the effective configuration must contain exactly one bad-request cache map");
    return;
  }
  const directives = maps[0].children || [];
  if (
    directives.length !== 2 || directives.some((directive) => directive.children) ||
    directives[0].name !== "default" || !equalArgs(directives[0].args, [""]) ||
    directives[1].name !== "400" || !equalArgs(directives[1].args, ["no-store"])
  ) failures.push("the bad-request cache map must add no-store only to status 400");
}

function validateInvalidTargetGuards(server, locations, failures) {
  if (directBlocks(server, "if").length) {
    failures.push("public HTTPS invalid request-target guards must be scoped to the proxy locations");
  }
  const expected = ["($request_uri", "~*", "^(?://|[^?]*%(?:00|25|2e|2f|5c)))"];
  for (const [index, location] of locations.entries()) {
    const label = index === 0 ? "root" : "authentication";
    const guards = directBlocks(location, "if");
    const matching = guards.filter((guard) => equalArgs(guard.args, expected));
    if (guards.length !== 1 || matching.length !== 1) {
      failures.push(`public HTTPS ${label} location must contain the exact invalid request-target guard`);
      continue;
    }
    const children = matching[0].children || [];
    if (
      children.length !== 1 || children[0].children || children[0].name !== "return" ||
      !equalArgs(children[0].args, ["400"])
    ) failures.push(`public HTTPS ${label} invalid request-target guard must return only 400`);
  }
}

function validateRetiredServers(servers, settings, failures) {
  if (servers.length !== 2) {
    failures.push("the retired host must have exactly one HTTP and one HTTPS denial server");
    return;
  }
  const http = servers.filter((server) => listensOn(server, 80, false));
  const https = servers.filter((server) => listensOn(server, 443, true));
  if (http.length !== 1 || https.length !== 1) {
    failures.push("the retired host must have exact HTTP and HTTPS denial servers");
    return;
  }
  for (const [label, server] of [["HTTP", http[0]], ["HTTPS", https[0]]]) {
    requireExactServerName(server, settings.retiredHost, failures, `retired ${label} server`);
    requireDirective(server, "server_tokens", ["off"], failures, `retired ${label} server`);
    requireDirective(server, "return", ["404"], failures, `retired ${label} denial`);
    if (descendantsNamed(server, "proxy_pass").length) failures.push(`the retired ${label} server must not proxy`);
    if (directBlocks(server, "location").length) failures.push(`the retired ${label} server must not define a location`);
  }
  requireDirective(https[0], "ssl_protocols", ["TLSv1.2", "TLSv1.3"], failures, "retired HTTPS server");
  requireNonemptyDirective(https[0], "ssl_certificate", failures, "retired HTTPS server");
  requireNonemptyDirective(https[0], "ssl_certificate_key", failures, "retired HTTPS server");
}

function validateProxyLocation(location, upstreamName, failures, label) {
  for (const [name, args] of [
    ["proxy_pass", [`http://${upstreamName}`]],
    ["proxy_http_version", ["1.1"]],
    ["proxy_connect_timeout", ["5s"]],
    ["proxy_send_timeout", ["30s"]],
    ["proxy_read_timeout", ["30s"]],
    ["proxy_request_buffering", ["on"]],
    ["proxy_buffering", ["on"]],
    ["proxy_socket_keepalive", ["on"]],
    ["proxy_next_upstream", ["off"]],
    ["proxy_intercept_errors", ["off"]],
    ["proxy_redirect", ["off"]],
  ]) requireDirective(location, name, args, failures, label);
  const expectedHeaders = new Map([
    ["host", ["$host"]],
    ["x-real-ip", ["$remote_addr"]],
    ["x-forwarded-for", ["$remote_addr"]],
    ["x-forwarded-proto", ["https"]],
    ["x-forwarded-host", ["$host"]],
    ["x-forwarded-port", ["443"]],
    ["forwarded", [""]],
    ["upgrade", [""]],
    ["connection", [""]],
  ]);
  const headers = directDirectives(location, "proxy_set_header");
  for (const [name, args] of expectedHeaders) {
    const matches = headers.filter((directive) => directive.args[0]?.toLowerCase() === name);
    if (matches.length !== 1 || !equalArgs(matches[0].args.slice(1), args)) {
      failures.push(`${label} must replace ${name} with the reviewed value`);
    }
  }
  if (headers.length !== expectedHeaders.size) failures.push(`${label} contains an unreviewed proxy header rule`);
  if (directDirectives(location, "include").length) failures.push(`${label} must not inherit an opaque proxy include`);
}

function validateErrorLocation(location, status, retry, failures) {
  const label = `public ${status} error location`;
  requireDirective(location, "internal", [], failures, label);
  requireDirective(location, "default_type", ["application/json"], failures, label);
  requireDirective(location, "add_header", ["Cache-Control", "no-store", "always"], failures, label);
  if (retry) requireDirective(location, "add_header", ["Retry-After", "1", "always"], failures, label);
  const returns = directDirectives(location, "return");
  if (returns.length !== 1 || returns[0].args[0] !== String(status) || returns[0].args.length !== 2) {
    failures.push(`${label} must return a bounded generic JSON response`);
  }
  if (descendantsNamed(location, "proxy_pass").length) failures.push(`${label} must not proxy`);
}

function proxyDirectives(upstreamName, spaces) {
  const indentation = " ".repeat(spaces);
  return [
    `proxy_pass http://${upstreamName};`,
    "proxy_http_version 1.1;",
    "proxy_set_header Host $host;",
    "proxy_set_header X-Real-IP $remote_addr;",
    "proxy_set_header X-Forwarded-For $remote_addr;",
    "proxy_set_header X-Forwarded-Proto https;",
    "proxy_set_header X-Forwarded-Host $host;",
    "proxy_set_header X-Forwarded-Port 443;",
    'proxy_set_header Forwarded "";',
    'proxy_set_header Upgrade "";',
    'proxy_set_header Connection "";',
    "proxy_connect_timeout 5s;",
    "proxy_send_timeout 30s;",
    "proxy_read_timeout 30s;",
    "proxy_request_buffering on;",
    "proxy_buffering on;",
    "proxy_socket_keepalive on;",
    "proxy_next_upstream off;",
    "proxy_intercept_errors off;",
    "proxy_redirect off;",
  ].map((line) => `${indentation}${line}`).join("\n");
}

function renderSettings(input) {
  const settings = auditSettings(input);
  const gatewayUpstreamAddress = validUpstreamAddress(input?.gatewayUpstreamAddress);
  const publicCertificate = validAbsolutePath(input?.publicCertificate, "public certificate");
  const publicCertificateKey = validAbsolutePath(input?.publicCertificateKey, "public certificate key");
  const hasRetired = Boolean(settings.retiredHost);
  const retiredCertificate = hasRetired
    ? validAbsolutePath(input?.retiredCertificate, "retired certificate")
    : undefined;
  const retiredCertificateKey = hasRetired
    ? validAbsolutePath(input?.retiredCertificateKey, "retired certificate key")
    : undefined;
  if (!hasRetired && (input?.retiredCertificate || input?.retiredCertificateKey)) {
    throw new Error("Retired certificate inputs require a retired host.");
  }
  return Object.freeze({
    ...settings,
    gatewayUpstreamAddress,
    publicCertificate,
    publicCertificateKey,
    retiredCertificate,
    retiredCertificateKey,
  });
}

function auditSettings(input) {
  const publicHost = validHostname(input?.publicHost, "public host");
  const retiredHost = input?.retiredHost ? validHostname(input.retiredHost, "retired host") : undefined;
  if (retiredHost === publicHost) throw new Error("The public and retired hosts must be different.");
  const gatewayUpstreamName = String(input?.gatewayUpstreamName || "");
  if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(gatewayUpstreamName)) {
    throw new Error("The gateway upstream name is invalid.");
  }
  return Object.freeze({ gatewayUpstreamName, publicHost, retiredHost });
}

function validHostname(value, label) {
  const hostname = String(value || "").toLowerCase();
  if (
    hostname.length < 1 || hostname.length > 253 || hostname.endsWith(".") ||
    !hostname.includes(".") || hostname.split(".").some((part) =>
      part.length < 1 || part.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part)
    )
  ) throw new Error(`The ${label} is invalid.`);
  return hostname;
}

function validUpstreamAddress(value) {
  const source = String(value || "");
  if (source.length < 3 || source.length > 320 || /[\s/$;{}]/.test(source)) {
    throw new Error("The gateway upstream address is invalid.");
  }
  let url;
  try {
    url = new URL(`http://${source}`);
  } catch {
    throw new Error("The gateway upstream address is invalid.");
  }
  if (
    !url.hostname || !url.port || url.username || url.password ||
    url.pathname !== "/" || url.search || url.hash || Number(url.port) > 65535
  ) throw new Error("The gateway upstream address is invalid.");
  return source;
}

function validAbsolutePath(value, label) {
  const source = String(value || "");
  if (
    source.length < 2 || source.length > 512 || !source.startsWith("/") ||
    source.split("/").includes("..") || !/^\/[A-Za-z0-9._/-]+$/.test(source)
  ) throw new Error(`The ${label} path is invalid.`);
  return source;
}

function tokenize(source) {
  const tokens = [];
  let cursor = 0;
  while (cursor < source.length) {
    const character = source[cursor];
    if (/\s/.test(character)) {
      cursor += 1;
      continue;
    }
    if (character === "#") {
      while (cursor < source.length && source[cursor] !== "\n") cursor += 1;
      continue;
    }
    if (["{", "}", ";"].includes(character)) {
      tokens.push(character);
      cursor += 1;
      continue;
    }
    let word = "";
    let quote;
    while (cursor < source.length) {
      const next = source[cursor];
      if (quote) {
        cursor += 1;
        if (next === quote) {
          quote = undefined;
          continue;
        }
        if (next === "\\" && cursor < source.length) {
          word += source[cursor++];
          continue;
        }
        word += next;
        continue;
      }
      if (next === "\"" || next === "'") {
        quote = next;
        cursor += 1;
        continue;
      }
      if (["{", "}"].includes(next) && word.length) {
        word += next;
        cursor += 1;
        continue;
      }
      if (/\s/.test(next) || ["{", "}", ";", "#"].includes(next)) break;
      word += next;
      cursor += 1;
    }
    if (quote) throw new Error("The Nginx configuration contains an unterminated quote.");
    tokens.push(word);
    if (tokens.length > MAXIMUM_TOKENS) throw new Error("The Nginx configuration token count is outside the audit bound.");
  }
  return tokens;
}

function blocksNamed(nodes, name) {
  const matches = [];
  for (const node of nodes) {
    if (node.children) {
      if (node.name === name) matches.push(node);
      matches.push(...blocksNamed(node.children, name));
    }
  }
  return matches;
}

function descendantsNamed(node, name) {
  const matches = [];
  for (const child of node.children || []) {
    if (child.name === name) matches.push(child);
    if (child.children) matches.push(...descendantsNamed(child, name));
  }
  return matches;
}

function directBlocks(node, name) {
  return (node.children || []).filter((candidate) => candidate.name === name && candidate.children);
}

function directDirectives(node, name) {
  return (node.children || []).filter((candidate) => candidate.name === name && !candidate.children);
}

function serverNames(server) {
  return directDirectives(server, "server_name").flatMap((directive) => directive.args);
}

function listensOn(server, port, requireTLS) {
  return directDirectives(server, "listen").some((directive) => {
    const address = directive.args[0] || "";
    const matchesPort = address === String(port) || address.endsWith(`:${port}`);
    return matchesPort && (!requireTLS || directive.args.includes("ssl"));
  });
}

function requireExactServerName(server, hostname, failures, label) {
  const names = directDirectives(server, "server_name");
  if (names.length !== 1 || !equalArgs(names[0].args, [hostname])) {
    failures.push(`${label} must serve only ${hostname}`);
  }
}

function requireDirective(node, name, args, failures, label) {
  const matches = directDirectives(node, name).filter((candidate) => equalArgs(candidate.args, args));
  if (matches.length !== 1) failures.push(`${label} must contain exactly one ${name} ${args.join(" ")}`.trim());
}

function requireNonemptyDirective(node, name, failures, label) {
  const matches = directDirectives(node, name);
  if (matches.length !== 1 || matches[0].args.length !== 1 || !matches[0].args[0]) {
    failures.push(`${label} must contain one bounded ${name}`);
  }
}

function requireZone(nodes, name, args, failures, label) {
  const matches = [];
  function visit(candidates) {
    for (const candidate of candidates) {
      if (!candidate.children && candidate.name === name && equalArgs(candidate.args, args)) matches.push(candidate);
      if (candidate.children) visit(candidate.children);
    }
  }
  visit(nodes);
  if (matches.length !== 1) failures.push(`the effective configuration must contain exactly one ${label}`);
}

function equalArgs(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!name?.startsWith("--") || value === undefined || options[name] !== undefined) usage();
    options[name] = value;
  }
  return options;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const options = parseOptions(rest);
  const common = {
    gatewayUpstreamName: options["--gateway-upstream-name"],
    publicHost: options["--public-host"],
    retiredHost: options["--retired-host"],
  };
  if (command === "render") {
    process.stdout.write(renderPublicIngressConfiguration({
      ...common,
      gatewayUpstreamAddress: options["--gateway-upstream-address"],
      publicCertificate: options["--public-certificate"],
      publicCertificateKey: options["--public-certificate-key"],
      retiredCertificate: options["--retired-certificate"],
      retiredCertificateKey: options["--retired-certificate-key"],
    }));
    return;
  }
  if (command === "audit") {
    const filename = options["--config"];
    if (!filename) usage();
    const source = filename === "-" ? await readStandardInput() : await readFile(filename, "utf8");
    const result = auditPublicIngressConfiguration(source, common);
    if (result.failures.length) throw new Error(`Public ingress configuration failed: ${result.failures.join("; ")}.`);
    console.info(JSON.stringify({ ...result, failures: [] }, null, 2));
    return;
  }
  usage();
}

async function readStandardInput() {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > MAXIMUM_CONFIG_BYTES) throw new Error("The Nginx configuration is outside the audit bound.");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function usage() {
  throw new Error(
    "Usage: node scripts/public-ingress-config.mjs render|audit --public-host HOST " +
    "--gateway-upstream-name NAME [bounded render inputs or --config FILE|-]",
  );
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : "VASI public ingress configuration failed.");
    process.exitCode = 1;
  });
}
