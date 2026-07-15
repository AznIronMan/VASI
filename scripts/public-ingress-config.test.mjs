import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  auditPublicIngressConfiguration,
  parseNginxConfiguration,
  PUBLIC_INGRESS_EXAMPLE_SETTINGS,
  renderPublicIngressConfiguration,
} from "./public-ingress-config.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const example = await readFile(path.join(root, "deployment/nginx/vasi-public.conf.example"), "utf8");
const auditSettings = {
  gatewayUpstreamName: PUBLIC_INGRESS_EXAMPLE_SETTINGS.gatewayUpstreamName,
  publicHost: PUBLIC_INGRESS_EXAMPLE_SETTINGS.publicHost,
  retiredHost: PUBLIC_INGRESS_EXAMPLE_SETTINGS.retiredHost,
};

describe("public ingress configuration contract", () => {
  it("keeps the sanitized example equal to canonical rendering and audit-clean", () => {
    expect(renderPublicIngressConfiguration(PUBLIC_INGRESS_EXAMPLE_SETTINGS)).toBe(example);
    expect(auditPublicIngressConfiguration(example, auditSettings)).toMatchObject({
      failures: [],
      serversChecked: 4,
    });
  });

  it("supports fresh installations without a retired hostname", () => {
    const settings = {
      ...PUBLIC_INGRESS_EXAMPLE_SETTINGS,
      retiredCertificate: undefined,
      retiredCertificateKey: undefined,
      retiredHost: undefined,
    };
    const rendered = renderPublicIngressConfiguration(settings);
    expect(rendered).not.toContain("vasi.example.com");
    expect(auditPublicIngressConfiguration(rendered, {
      gatewayUpstreamName: settings.gatewayUpstreamName,
      publicHost: settings.publicHost,
    }).failures).toEqual([]);
  });

  it.each([
    ["request-derived redirect hosts", "return 301 https://vsign.example.com$request_uri;", "return 301 https://$host$request_uri;", "public HTTP redirect"],
    ["appended forwarding chains", "proxy_set_header X-Forwarded-For $remote_addr;", "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;", "replace x-forwarded-for"],
    ["oversized public bodies", "client_max_body_size 64k;", "client_max_body_size 128m;", "client_max_body_size 64k"],
    ["unbounded upstream reads", "proxy_read_timeout 30s;", "proxy_read_timeout 120s;", "proxy_read_timeout 30s"],
    ["opaque proxy includes", "proxy_redirect off;", "proxy_redirect off;\n        include /etc/nginx/proxy_params;", "opaque proxy include"],
    ["engine proxying on the retired host", "    return 404;\n}\n\nserver {\n    listen 443 ssl;", "    location / { proxy_pass https://private_engine; }\n}\n\nserver {\n    listen 443 ssl;", "retired HTTP server must not proxy"],
  ])("rejects %s", (_label, current, replacement, failure) => {
    const weakened = example.replace(current, replacement);
    expect(auditPublicIngressConfiguration(weakened, auditSettings).failures.join("; ")).toContain(failure);
  });

  it("rejects unreviewed locations and missing rate zones", () => {
    const extra = example.replace(
      "    location / {",
      "    location = /unreviewed { return 200; }\n\n    location / {",
    );
    expect(auditPublicIngressConfiguration(extra, auditSettings).failures).toContain(
      "the public HTTPS server must expose only the reviewed root, authentication, and error locations",
    );
    const missing = example.replace(
      "limit_req_zone $binary_remote_addr zone=vasi_public_auth:10m rate=5r/s;\n",
      "",
    );
    expect(auditPublicIngressConfiguration(missing, auditSettings).failures).toContain(
      "the effective configuration must contain exactly one authentication request zone",
    );
  });

  it("bounds and validates renderer inputs", () => {
    expect(() => renderPublicIngressConfiguration({
      ...PUBLIC_INGRESS_EXAMPLE_SETTINGS,
      publicHost: "*.example.com",
    })).toThrow(/public host/i);
    expect(() => renderPublicIngressConfiguration({
      ...PUBLIC_INGRESS_EXAMPLE_SETTINGS,
      gatewayUpstreamAddress: "user:password@database.example:5432",
    })).toThrow(/upstream address/i);
    expect(() => renderPublicIngressConfiguration({
      ...PUBLIC_INGRESS_EXAMPLE_SETTINGS,
      publicCertificateKey: "/etc/nginx/../secret.key",
    })).toThrow(/certificate key path/i);
    expect(() => renderPublicIngressConfiguration({
      ...PUBLIC_INGRESS_EXAMPLE_SETTINGS,
      retiredHost: undefined,
    })).toThrow(/retired certificate inputs/i);
  });

  it("parses comments, quoted bodies, regex braces, and rejects malformed or excessive input", () => {
    const parsed = parseNginxConfiguration("# comment\nlocation ~ ^/v[0-9]{1,3}$ { return 429 '{\"error\":\"bounded\"}'; }");
    expect(parsed[0]).toMatchObject({ args: ["~", "^/v[0-9]{1,3}$"], name: "location" });
    expect(() => parseNginxConfiguration("server { listen 443;")).toThrow(/incomplete/i);
    expect(() => parseNginxConfiguration("server { return 200 'unterminated; }")).toThrow(/unterminated quote/i);
    expect(() => parseNginxConfiguration("x".repeat(4 * 1024 * 1024 + 1))).toThrow(/outside the audit bound/i);
  });
});
