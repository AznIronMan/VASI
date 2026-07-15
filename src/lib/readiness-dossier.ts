import type {
  AdminTenantReadinessExport,
  TenantAdmissionGateId,
  TenantReadinessDossier,
} from "@/lib/owner-types";

const gateLabels: Record<TenantAdmissionGateId, string> = {
  exact_release: "Exact release",
  isolation_integrity: "Isolation and integrity",
  identity_delivery: "Identity and delivery",
  privacy_legal: "Privacy and legal",
  accessibility: "Accessibility",
  malware_content: "Malware and content safety",
  recovery_custody: "Recovery and custody",
  capacity_support: "Capacity and support",
};

export function validateReadinessExport(value: unknown): AdminTenantReadinessExport {
  if (!plainObject(value) || value.schema !== "vasi-tenant-readiness-export/v1") invalid();
  if (!isHash(value.auditEventHash) || !isHash(value.dossierHash)) invalid();
  if (!canonicalTimestamp(value.capturedAt)) invalid();
  if (value.format !== "html" && value.format !== "json") invalid();
  const dossier = value.dossier;
  if (!plainObject(dossier) || dossier.schema !== "vasi-tenant-readiness-dossier/v1") invalid();
  const tenant = dossier.tenant;
  if (!plainObject(tenant) || !uuid(tenant.id)) invalid();
  if (typeof tenant.name !== "string" || tenant.name.length > 160) invalid();
  if (!plainObject(dossier.readiness) || !Array.isArray(dossier.readiness.pendingGateIds)) invalid();
  if (!plainObject(dossier.admission) || !Array.isArray(dossier.admission.gates)) invalid();
  if (!Array.isArray(dossier.integrations) || !Array.isArray(dossier.limitations)) invalid();
  return value as unknown as AdminTenantReadinessExport;
}

export function readinessExportJSON(value: AdminTenantReadinessExport) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function renderReadinessDossierHTML(exported: AdminTenantReadinessExport) {
  const dossier = exported.dossier;
  const usage = dossier.tenant.usage.resources;
  const allowlistCounts = dossier.installation.adapterPolicy.destinationAllowlistCounts;
  const embeddedDossier = JSON.stringify(dossier).replace(/[<>&]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
  );
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>VASI pilot readiness dossier — ${h(dossier.tenant.name)}</title>
<style>${reportCSS}</style>
</head>
<body>
<main>
  <header>
    <p class="eyebrow">VASI PILOT READINESS DOSSIER</p>
    <h1>${h(dossier.tenant.name)}</h1>
    <p class="lede">A privacy-bounded technical snapshot for accountable pilot review. Recorded approvals are evidence references, not certification or legal conclusions.</p>
    <dl class="summary">
      ${pair("Technical admission", title(dossier.readiness.technicalAdmissionStatus))}
      ${pair("Captured", exported.capturedAt)}
      ${pair("Engine release", dossier.installation.engineVersion)}
      ${pair("Dossier SHA-256", exported.dossierHash, true)}
      ${pair("Immutable export event", exported.auditEventHash, true)}
    </dl>
  </header>

  <section>
    <h2>Readiness decision record</h2>
    <p>${dossier.readiness.pendingGateIds.length
      ? `${dossier.readiness.pendingGateIds.length} gate(s) remain pending. Production admission remains closed.`
      : "All required gates have recorded approvals. This reports VASI's technical admission state only."}</p>
    <table>
      <thead><tr><th>Gate</th><th>State</th><th>Reviewer / evidence</th><th>Evidence SHA-256</th><th>Recorded</th></tr></thead>
      <tbody>${dossier.admission.gates.map((gate) => `<tr>
        <td>${h(gateLabels[gate.id])}</td>
        <td><span class="state state--${h(gate.state)}">${h(title(gate.state))}</span></td>
        <td>${gate.state === "approved" ? `${h(gate.reviewerReference)}<br>${h(gate.evidenceReference)}` : "—"}</td>
        <td class="mono">${gate.evidenceDigest ? h(gate.evidenceDigest) : "—"}</td>
        <td>${gate.decidedAt ? h(gate.decidedAt) : "—"}</td>
      </tr>`).join("")}</tbody>
    </table>
    <p class="fingerprint">Admission revision ${h(dossier.admission.revision)} · <span class="mono">${h(dossier.admission.admissionHash)}</span></p>
  </section>

  <section>
    <h2>Bound installation and company configuration</h2>
    <div class="columns">
      <dl>
        ${pair("Product", `${dossier.installation.productName} / ${dossier.installation.organizationName}`)}
        ${pair("Deployment", dossier.installation.deployment.mode)}
        ${pair("Public ingress", dossier.installation.deployment.publicIngress)}
        ${pair("Engine database", dossier.installation.deployment.engineDatabaseBoundary)}
        ${pair("Installation profile", `revision ${dossier.installation.revision}`)}
        ${pair("Installation SHA-256", dossier.installation.profileHash, true)}
      </dl>
      <dl>
        ${pair("Tenant identifier", dossier.tenant.id, true)}
        ${pair("Tenant status", dossier.tenant.status)}
        ${pair("Tenant profile", `revision ${dossier.tenant.profile.revision}`)}
        ${pair("Tenant profile SHA-256", dossier.tenant.profile.profileHash, true)}
        ${pair("Retention profile", dossier.tenant.profile.defaultRetentionProfile)}
        ${pair("Provisioning", dossier.installation.provisioning.mode)}
      </dl>
    </div>
  </section>

  <section>
    <h2>Capacity snapshot</h2>
    <table>
      <thead><tr><th>Resource</th><th>Used</th><th>Limit</th><th>Available</th></tr></thead>
      <tbody>${Object.entries(usage).map(([resource, quota]) => `<tr><td>${h(resourceLabel(resource))}</td><td>${h(quota.used)}</td><td>${h(quota.limit)}</td><td>${h(quota.available)}</td></tr>`).join("")}</tbody>
    </table>
  </section>

  <section>
    <h2>Integration bindings</h2>
    <p>Configuration and credential values are withheld. Hashes bind the active configuration revisions.</p>
    <table>
      <thead><tr><th>Capability</th><th>Adapter</th><th>Status</th><th>Revision</th><th>Configuration SHA-256</th></tr></thead>
      <tbody>${dossier.integrations.map((integration) => `<tr><td>${h(integration.capability)}</td><td>${h(integration.adapterId)} v${h(integration.adapterVersion)}</td><td>${h(title(integration.status))}</td><td>${h(integration.revision)}</td><td class="mono">${h(integration.configHash)}</td></tr>`).join("")}</tbody>
    </table>
    <p>Permitted adapters: ${dossier.installation.adapterPolicy.allowedAdapterIds.map(h).join(", ")}.</p>
    <p>Destination allowlist entry counts: scanner ${h(allowlistCounts.malwareScannerHosts)}; Graph clients ${h(allowlistCounts.microsoftGraphClientIds)}, senders ${h(allowlistCounts.microsoftGraphSenders)}, tenants ${h(allowlistCounts.microsoftGraphTenantIds)}; SMTP ${h(allowlistCounts.smtpHosts)}; webhook ${h(allowlistCounts.webhookHosts)}. Values are withheld.</p>
  </section>

  ${renderProductionStop(dossier)}

  <section>
    <h2>Interpretation limits</h2>
    <ul>${dossier.limitations.map((limitation) => `<li>${h(limitation)}</li>`).join("")}</ul>
  </section>

  <footer>
    <p>Schema ${h(dossier.schema)} · classification ${h(dossier.readiness.classification)}</p>
    <p>The machine-readable dossier used for this report is embedded below as inert JSON. Recompute canonical VASI JSON SHA-256 and compare it with <span class="mono">${h(exported.dossierHash)}</span>.</p>
  </footer>
</main>
<script type="application/json" id="vasi-readiness-dossier">${embeddedDossier}</script>
</body>
</html>\n`;
}

function renderProductionStop(dossier: TenantReadinessDossier) {
  const stop = dossier.lastProductionStop;
  if (!stop) return `<section><h2>Production-stop history</h2><p>No tenant production-stop event is present in the current snapshot.</p></section>`;
  return `<section>
    <h2>Latest production stop</h2>
    <dl class="summary">
      ${pair("Stopped", stop.stoppedAt)}
      ${pair("Reason", stop.reasonCode)}
      ${pair("Gate", gateLabels[stop.gateId])}
      ${pair("Result", `${stop.resultingAdmissionStatus}, revision ${stop.resultingAdmissionRevision}`)}
      ${pair("Effects", `${stop.effects.revokedRequestCount} request(s), ${stop.effects.revokedAssignmentCount} assignment(s), ${stop.effects.suppressedNotificationCount} notification(s)`)}
      ${pair("Event SHA-256", stop.eventHash, true)}
    </dl>
  </section>`;
}

function pair(label: string, value: string, mono = false) {
  return `<div><dt>${h(label)}</dt><dd${mono ? ' class="mono"' : ""}>${h(value)}</dd></div>`;
}

function resourceLabel(value: string) {
  return value.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, (character) => character.toUpperCase());
}

function title(value: string) {
  return value.replaceAll("_", " ").replace(/^./, (character) => character.toUpperCase());
}

function h(value: unknown) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isHash(value: unknown) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function uuid(value: unknown) {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function canonicalTimestamp(value: unknown) {
  if (typeof value !== "string") return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && date.toISOString() === value;
}

function invalid(): never {
  throw new Error("The private VASI engine returned an invalid readiness export.");
}

const reportCSS = `
:root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #17231f; background: #f3f6f4; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px; background: #f3f6f4; }
main { max-width: 1080px; margin: 0 auto; background: #fff; border: 1px solid #d7dfdb; border-radius: 18px; overflow: hidden; box-shadow: 0 18px 48px rgba(20, 55, 46, .08); }
header, section, footer { padding: 28px 36px; border-bottom: 1px solid #e2e8e5; }
footer { border-bottom: 0; background: #f7f9f8; }
h1, h2 { color: #15372e; margin: 0 0 14px; }
h1 { font-size: 34px; }
h2 { font-size: 22px; }
p, li, dd, dt, td, th { line-height: 1.5; }
.eyebrow { color: #28745f; font-size: 12px; font-weight: 800; letter-spacing: .12em; }
.lede { max-width: 780px; color: #4e5e58; }
.summary, .columns dl { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0; margin: 22px 0 0; border: 1px solid #dce4e0; border-radius: 10px; overflow: hidden; }
.summary div, .columns dl div { padding: 12px 14px; border-bottom: 1px solid #e3e9e6; }
.summary div:nth-last-child(-n+2), .columns dl div:nth-last-child(-n+2) { border-bottom: 0; }
dt { color: #596861; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
dd { margin: 3px 0 0; overflow-wrap: anywhere; }
.columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; color: #4b5e56; background: #f2f6f4; }
th, td { padding: 10px; border: 1px solid #dce4e0; vertical-align: top; overflow-wrap: anywhere; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; overflow-wrap: anywhere; }
.state { display: inline-block; border-radius: 999px; padding: 3px 8px; font-weight: 700; }
.state--approved { color: #175c47; background: #dff2ea; }
.state--pending { color: #795b00; background: #fff2c7; }
.fingerprint { color: #5b6964; }
ul { padding-left: 22px; }
@media print { body { padding: 0; background: #fff; } main { max-width: none; border: 0; border-radius: 0; box-shadow: none; } section, header, footer { break-inside: avoid; } }
@media (max-width: 720px) { body { padding: 0; } main { border: 0; border-radius: 0; } header, section, footer { padding: 22px 18px; } .summary, .columns { grid-template-columns: 1fr; } table { display: block; overflow-x: auto; } }
`;
