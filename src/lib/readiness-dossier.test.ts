import { describe, expect, it } from "vitest";

import { hashReadinessDossier } from "../../packages/readiness-dossier/index.mjs";
import { createReadinessExportFixture } from "../../packages/readiness-dossier/test-fixture.mjs";
import {
  readinessExportJSON,
  renderReadinessDossierHTML,
  validateReadinessExport,
} from "@/lib/readiness-dossier";
import type { AdminTenantReadinessExport } from "@/lib/owner-types";

describe("readiness dossier rendering", () => {
  it("renders inert, printable HTML while preserving the exact embedded dossier", () => {
    const exported = fixture();
    exported.dossier.tenant.name = 'Example <script>alert("x")</script> & Company';
    exported.dossierHash = hashReadinessDossier(exported.dossier);

    const html = renderReadinessDossierHTML(exported);

    expect(html).toContain("Example &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; Company");
    expect(html).not.toContain('<script>alert("x")</script>');
    expect(html).toContain("\\u003cscript\\u003ealert");
    expect(html).toContain(`Dossier SHA-256</dt><dd class="mono">${exported.dossierHash}</dd>`);
    expect(html).toContain('type="application/json" id="vasi-readiness-export"');
    expect(html).toContain('type="application/json" id="vasi-readiness-dossier"');
    expect(html).toContain("default-src 'none'");
  });

  it("produces a newline-terminated machine export and validates its boundary", () => {
    const exported = fixture("json");
    expect(readinessExportJSON(exported)).toBe(`${JSON.stringify(exported, null, 2)}\n`);
    expect(validateReadinessExport(exported)).toBe(exported);
    expect(() => validateReadinessExport({ ...exported, dossierHash: "not-a-hash" }))
      .toThrow("VASI readiness dossier verification failed.");
    expect(() => validateReadinessExport({
      ...exported,
      dossier: { ...exported.dossier, tenant: { ...exported.dossier.tenant, id: "../secret" } },
    })).toThrow("VASI readiness dossier verification failed.");
  });
});

function fixture(format: "html" | "json" = "html"): AdminTenantReadinessExport {
  return createReadinessExportFixture(format) as AdminTenantReadinessExport;
}
