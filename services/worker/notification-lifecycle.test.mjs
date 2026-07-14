import { describe, expect, it, vi } from "vitest";

import { suppressObsoleteJobs } from "./notification-lifecycle.mjs";

describe("notification lifecycle suppression", () => {
  it("redacts only pending invitations and reminders for terminal requests", async () => {
    const database = { query: vi.fn().mockResolvedValue({ rowCount: 2 }) };
    await suppressObsoleteJobs(database);
    const sql = database.query.mock.calls[0][0];
    expect(sql).toContain(`j."status" = 'pending'`);
    expect(sql).toContain(`j."notificationType" in ('request.issued', 'request.reminder')`);
    expect(sql).toContain(`r."status" in ('completed', 'revoked', 'expired')`);
    expect(sql).toContain(`"payload" = '{"redacted":true}'::jsonb`);
    expect(sql).not.toContain("request.completed')");
  });
});
