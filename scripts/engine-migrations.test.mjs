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
  });

  it("extends tombstone-authorized retention purge to integration gateway attempts", async () => {
    const source = await readFile(notificationMigrationPath, "utf8");

    expect(source).toContain("integration_gateway_attempt_change_guard");
    expect(source).toContain("outbox_job_retention_gateway_cleanup");
    expect(source).toContain('delete from "vasi_engine"."integration_gateway_attempt"');
    expect(source).toContain("retention_purge_tombstone");
    expect(source).toContain("OLD.\"requestId\" = purge_request");
  });
});
