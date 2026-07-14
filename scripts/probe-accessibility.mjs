import process from "node:process";

import AxeBuilder from "@axe-core/playwright";
import { chromium } from "playwright-core";

import policy from "../config/assurance-policy.json" with { type: "json" };

try {
  const { channel, origin } = parseArguments(process.argv.slice(2));
  const base = validatedOrigin(origin);
  const browser = await chromium.launch({ channel, headless: true });
  const results = [];
  try {
    const context = await browser.newContext({ reducedMotion: "reduce" });
    for (const route of policy.accessibility.routes) {
      const page = await context.newPage();
      try {
        const response = await page.goto(new URL(route, base).href, { waitUntil: "networkidle", timeout: 30_000 });
        if (!response?.ok()) throw new Error(`Accessibility route ${route} returned ${response?.status() || "no response"}.`);
        await page.locator("body").waitFor({ state: "visible" });
        const structural = await page.evaluate(() => ({
          headings: document.querySelectorAll("h1").length,
          lang: document.documentElement.lang,
          main: document.querySelectorAll("main").length,
          title: document.title,
        }));
        if (structural.main !== 1 || structural.headings !== 1 || !structural.lang || !structural.title) {
          throw new Error(`Accessibility route ${route} failed document structure requirements.`);
        }
        const analysis = await new AxeBuilder({ page }).withTags(policy.accessibility.tags).analyze();
        results.push({
          route,
          violations: analysis.violations.map((entry) => ({
            id: entry.id,
            impact: entry.impact,
            nodes: entry.nodes.slice(0, 10).map((node) => ({
              failure: String(node.failureSummary || "").slice(0, 320),
              target: node.target.slice(0, 4),
            })),
          })),
        });
      } finally {
        await page.close();
      }
    }
    await context.close();
  } finally {
    await browser.close();
  }
  const violations = results.flatMap((result) => result.violations.map((entry) => ({ ...entry, route: result.route })));
  if (violations.length) {
    console.error(JSON.stringify({ schema: "vasi-accessibility-result/v1", violations }, null, 2));
    throw new Error(`VASI public pages have ${violations.length} WCAG violation group(s).`);
  }
  console.info(JSON.stringify({ routes: results.length, schema: "vasi-accessibility-result/v1", violations: 0 }, null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : "VASI accessibility probe failed.");
  process.exitCode = 1;
}

function parseArguments(args) {
  const [origin, ...rest] = args;
  if (!origin) throw new Error("Usage: node scripts/probe-accessibility.mjs HTTPS_ORIGIN [--channel chrome]");
  let channel;
  for (let index = 0; index < rest.length; index += 2) {
    if (rest[index] !== "--channel" || !rest[index + 1]) throw new Error(`Unknown accessibility option ${rest[index] || "(missing)"}.`);
    channel = rest[index + 1];
  }
  return { channel, origin };
}

function validatedOrigin(value) {
  const origin = new URL(value);
  if (origin.protocol !== "https:" || origin.pathname !== "/" || origin.search || origin.hash || origin.username || origin.password) {
    throw new Error("Accessibility probes require a credential-free HTTPS origin.");
  }
  return origin;
}
