import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { describe, expect, it } from "vitest";

const sourcePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "engine-migrations.mjs",
);
const notificationMigrationPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "database",
  "engine-notification-delivery.sql",
);
const requesterMigrationPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "database",
  "engine-requester-provenance.sql",
);
const productionStopMigrationPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "database",
  "engine-tenant-production-stop.sql",
);

describe("engine migration ledger", () => {
  it("remains anchored to public after the engine user schema exists", async () => {
    const source = await readFile(sourcePath, "utf8");

    expect(source).toContain("set search_path to public, pg_catalog");
    expect(source.match(/public\.\"_vasi_engine_migrations\"/g)).toHaveLength(3);
    expect(source).toContain("0008_engine_lifecycle_governance");
    expect(source).toContain("0009_engine_productization");
    expect(source).toContain("0010_engine_activity_interaction");
    expect(source).toContain("0011_engine_participant_context");
    expect(source).toContain("0012_engine_document_malware_scanning");
    expect(source).toContain("0013_engine_notification_delivery");
    expect(source).toContain("0014_engine_requester_provenance");
    expect(source).toContain("0015_engine_tenant_admission");
    expect(source).toContain("0016_engine_tenant_production_stop");
  });

  it("makes tenant production-stop command IDs replay-resistant in the immutable configuration chain", async () => {
    const source = await readFile(productionStopMigrationPath, "utf8");

    expect(source).toContain("tenant.production.stopped");
    expect(source).toContain("product_configuration_tenant_stop_command_idx");
    expect(source).toContain("eventData\"->>'commandId'");
    expect(source).toContain("product_configuration_event_event_type_check_v3");
  });

  it("extends tombstone-authorized retention purge to integration gateway attempts", async () => {
    const source = await readFile(notificationMigrationPath, "utf8");

    expect(source).toContain("integration_gateway_attempt_change_guard");
    expect(source).toContain("outbox_job_retention_gateway_cleanup");
    expect(source).toContain('delete from "vasi_engine"."integration_gateway_attempt"');
    expect(source).toContain("retention_purge_tombstone");
    expect(source).toContain("OLD.\"requestId\" = purge_request");
  });

  it("backfills and then freezes the issuance-time requester snapshot", async () => {
    const source = await readFile(requesterMigrationPath, "utf8");

    expect(source).toContain("requesterSnapshot");
    expect(source).toContain("evidence_event_backfill");
    expect(source).toContain("membership_backfill");
    expect(source).toContain("legacy_unavailable");
    expect(source).toContain("request_requester_snapshot_immutable");
    expect(source).toContain('"requesterSnapshot" ?& array[');
    expect(source).toContain('"requesterSnapshot" - array[');
    expect(source).toContain("request_requester_snapshot_legacy_insert");
    expect(source).toContain("then 'legacy_unavailable' else 'membership_backfill'");
    expect(source).toContain('before insert on "vasi_engine"."request_instance"');
    expect(source).toContain('before update on "vasi_engine"."request_instance"');
  });
});
