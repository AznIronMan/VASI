import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  connect: vi.fn(),
  getRuntimeSettings: vi.fn(),
  resolveProductBrand: vi.fn(),
  resolveServerSettings: vi.fn(),
  sendAuthEmail: vi.fn(),
  writeAdminAudit: vi.fn(),
}));

vi.mock("@/lib/database", () => ({
  database: {
    connect: mocks.connect,
    query: vi.fn(),
  },
}));
vi.mock("@/lib/email", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/email")>();
  return { ...actual, sendAuthEmail: mocks.sendAuthEmail };
});
vi.mock("@/lib/runtime-settings", () => ({ getRuntimeSettings: mocks.getRuntimeSettings }));
vi.mock("@/lib/server-settings", () => ({ resolveServerSettings: mocks.resolveServerSettings }));
vi.mock("@/lib/branding", () => ({ resolveProductBrand: mocks.resolveProductBrand }));
vi.mock("@/lib/admin-audit", () => ({ writeAdminAudit: mocks.writeAdminAudit }));

import { createInvitation } from "@/lib/invitations";
import { AuthEmailDeliveryError } from "@/lib/email";

const sourceCommandId = "33333333-3333-4333-8333-333333333333";

describe("command-bound invitation delivery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getRuntimeSettings.mockResolvedValue({});
    mocks.resolveServerSettings.mockReturnValue({ baseURL: "https://vsign.example.test" });
    mocks.resolveProductBrand.mockReturnValue({ displayName: "V·Sign", productName: "V·Sign" });
    mocks.sendAuthEmail.mockResolvedValue(undefined);
    mocks.writeAdminAudit.mockResolvedValue({
      eventHash: "a".repeat(64),
      id: "audit-1",
      sequence: 1,
    });
  });

  it("returns the committed invitation on retry without sending a second message", async () => {
    const fixture = invitationDatabase();
    mocks.connect.mockResolvedValue(fixture.client);

    const first = await createInvitation("OWNER@EXAMPLE.COM", "admin-1", { sourceCommandId });
    const replay = await createInvitation("owner@example.com", "admin-1", { sourceCommandId });

    expect(replay).toEqual(first);
    expect(mocks.sendAuthEmail).toHaveBeenCalledTimes(1);
    expect(fixture.state.invitationInsertCount).toBe(1);
    expect(fixture.client.query.mock.calls.filter(([sql]) => String(sql).includes("pg_advisory_lock")))
      .toHaveLength(2);
    expect(fixture.client.query.mock.calls.filter(([sql]) => String(sql).includes("pg_advisory_unlock")))
      .toHaveLength(2);
  });

  it("rejects a different email or actor reusing the same invitation command", async () => {
    const fixture = invitationDatabase({
      prior: priorInvitation({ deliveryStatus: "provider_accepted" }),
    });
    mocks.connect.mockResolvedValue(fixture.client);

    await expect(createInvitation("different@example.com", "admin-1", { sourceCommandId }))
      .rejects.toMatchObject({ code: "source_conflict", status: 409 });
    await expect(createInvitation("owner@example.com", "admin-2", { sourceCommandId }))
      .rejects.toMatchObject({ code: "source_conflict", status: 409 });
    expect(mocks.sendAuthEmail).not.toHaveBeenCalled();
  });

  it("does not resend when a previous provider outcome is unknown", async () => {
    const fixture = invitationDatabase({ prior: priorInvitation({ deliveryStatus: "pending" }) });
    mocks.connect.mockResolvedValue(fixture.client);

    await expect(createInvitation("owner@example.com", "admin-1", { sourceCommandId }))
      .rejects.toMatchObject({ code: "delivery_unknown", status: 409 });
    expect(mocks.sendAuthEmail).not.toHaveBeenCalled();
  });

  it("records a provider failure and returns a bounded delivery error", async () => {
    const fixture = invitationDatabase();
    mocks.connect.mockResolvedValue(fixture.client);
    mocks.sendAuthEmail.mockRejectedValue(new Error("provider unavailable"));

    await expect(createInvitation("owner@example.com", "admin-1", { sourceCommandId }))
      .rejects.toMatchObject({ code: "delivery_failed", status: 502 });
    expect(fixture.state.prior?.deliveryStatus).toBe("failed");
    expect(fixture.state.prior?.revokedAt).toBeTruthy();
  });

  it("leaves an indeterminate provider attempt pending and refuses automatic redelivery", async () => {
    const fixture = invitationDatabase();
    mocks.connect.mockResolvedValue(fixture.client);
    mocks.sendAuthEmail.mockRejectedValue(
      new AuthEmailDeliveryError("transport outcome unknown", "unknown"),
    );

    await expect(createInvitation("owner@example.com", "admin-1", { sourceCommandId }))
      .rejects.toMatchObject({ code: "delivery_unknown", status: 502 });
    expect(fixture.state.prior?.deliveryStatus).toBe("pending");
    expect(fixture.state.prior?.revokedAt).toBeNull();
    expect(mocks.sendAuthEmail).toHaveBeenCalledTimes(1);

    await expect(createInvitation("owner@example.com", "admin-1", { sourceCommandId }))
      .rejects.toMatchObject({ code: "delivery_unknown", status: 409 });
    expect(mocks.sendAuthEmail).toHaveBeenCalledTimes(1);
  });

  it("distinguishes an existing account from other conflicts", async () => {
    const fixture = invitationDatabase({ userExists: true });
    mocks.connect.mockResolvedValue(fixture.client);

    await expect(createInvitation("owner@example.com", "admin-1", { sourceCommandId }))
      .rejects.toMatchObject({ code: "existing_account", status: 409 });
    expect(fixture.state.invitationInsertCount).toBe(0);
  });
});

function invitationDatabase({
  prior,
  userExists = false,
}: {
  prior?: ReturnType<typeof priorInvitation>;
  userExists?: boolean;
} = {}) {
  const state = {
    invitationInsertCount: 0,
    prior,
  };
  const client = {
    query: vi.fn(async (sql: unknown, values: unknown[] = []) => {
      const statement = String(sql);
      if (statement.includes("pg_advisory_lock") || statement.includes("pg_advisory_unlock")) {
        return result([{}]);
      }
      if (statement.includes('from "vasi_invitation" where "sourceCommandId"')) {
        return result(state.prior ? [state.prior] : []);
      }
      if (statement.includes('from "user"')) return result(userExists ? [{}] : []);
      if (["begin", "commit", "rollback"].includes(statement)) return result();
      if (statement.includes('set "revokedAt" = CURRENT_TIMESTAMP') && statement.includes('lower("email")')) {
        return result();
      }
      if (statement.includes('insert into "vasi_invitation"')) {
        state.invitationInsertCount += 1;
        state.prior = priorInvitation({
          deliveryStatus: "pending",
          email: String(values[1]),
          expiresAt: values[4] as Date,
          id: String(values[0]),
          invitedBy: String(values[3]),
        });
        return result();
      }
      if (statement.includes('update "vasi_invitation"') && statement.includes('"deliveryStatus" = $2')) {
        if (!state.prior || state.prior.deliveryStatus !== "pending") return result();
        state.prior.deliveryStatus = values[1] as "failed" | "provider_accepted";
        if (values[1] === "failed") state.prior.revokedAt = new Date();
        return result([{ id: state.prior.id }]);
      }
      if (statement.includes('insert into "vasi_admin_audit"')) return result();
      throw new Error(`Unexpected invitation query: ${statement}`);
    }),
    release: vi.fn(),
  };
  return { client, state };
}

function priorInvitation(overrides: Partial<{
  deliveryStatus: "failed" | "pending" | "provider_accepted";
  email: string;
  expiresAt: Date;
  id: string;
  invitedBy: string;
  revokedAt: Date | null;
}> = {}) {
  return {
    deliveryStatus: "provider_accepted" as const,
    email: "owner@example.com",
    expiresAt: new Date("2026-07-21T00:00:00.000Z"),
    id: "11111111-1111-4111-8111-111111111111",
    invitedBy: "admin-1",
    revokedAt: null,
    ...overrides,
  };
}

function result(rows: unknown[] = []) {
  return { rowCount: rows.length, rows };
}
