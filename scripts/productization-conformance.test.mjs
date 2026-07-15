import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { validateInstallationProfile } from "../packages/engine-domain/productization.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("productized deployment and transfer conformance", () => {
  it("keeps both sanitized deployment profiles schema-valid", async () => {
    for (const name of ["self-hosted", "saas"]) {
      const profile = JSON.parse(await readFile(path.join(root, "config", "deployment-profiles", `${name}.json`), "utf8"));
      expect(validateInstallationProfile(profile).deployment.mode).toBe(name === "self-hosted" ? "self_hosted" : "saas");
      expect(JSON.stringify(profile)).not.toMatch(/cnb\.llc|password|secret/i);
    }
  });

  it("forces every tenant-owned engine table into transfer coverage or an explicit safe exclusion", async () => {
    const databaseFiles = [
      "engine-boundary-schema.sql", "engine-evidence-slice.sql", "engine-workflow-control-plane.sql",
      "engine-document-activities.sql", "engine-media-evidence.sql", "engine-evidence-reports.sql",
      "engine-lifecycle-governance.sql", "engine-productization.sql",
      "engine-activity-interaction.sql", "engine-participant-context.sql",
      "engine-document-malware-scanning.sql", "engine-tenant-provision-replay.sql",
    ];
    const created = new Set();
    for (const filename of databaseFiles) {
      const source = await readFile(path.join(root, "database", filename), "utf8");
      for (const match of source.matchAll(/create table "vasi_engine"\."([a-z0-9_]+)"/g)) created.add(match[1]);
    }
    const transferSource = await readFile(path.join(root, "scripts", "tenant-transfer.mjs"), "utf8");
    const covered = new Set([...transferSource.matchAll(/(?:direct|dependent|custom)\("([a-z0-9_]+)"/g)].map((match) => match[1]));
    const excluded = new Set([
      "actor_assertion_replay",
      "evidence_seal_key",
      "evidence_seal_key_status_event",
      "installation_profile_pointer",
      "installation_profile_revision",
      "integration_adapter_registry",
      "tenant_provision_command",
      "participant_data_export",
      "participant_data_export_access_event",
      "participant_data_export_chunk",
      "participant_data_request",
      "participant_data_request_chain_head",
      "participant_data_request_event",
      "participant_data_request_scope",
    ]);
    expect([...created].filter((table) => !covered.has(table) && !excluded.has(table))).toEqual([]);
    expect(transferSource).toContain("Complete or expire participant data-request scopes");
    expect(transferSource).toContain("transferCredentials");
    expect(transferSource).toContain("mode 0600 or stricter");
    expect(transferSource).toContain("begin isolation level repeatable read read only");
  });

  it("keeps PostgreSQL passwords out of backup arguments and environment values", async () => {
    const source = await readFile(path.join(root, "scripts", "backup.mjs"), "utf8");
    expect(source).toContain("PGPASSFILE: passfile");
    expect(source).not.toContain("PGPASSWORD");
    expect(source).toContain('parsed.password = ""');
    expect(source).toContain('{ mode: 0o600 }');
    expect(source).toContain('await rm(temporary, { force: true, recursive: true })');
  });
});
