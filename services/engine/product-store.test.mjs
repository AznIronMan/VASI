import { describe, expect, it, vi } from "vitest";

import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import {
  applyTenantAdmissionDecision,
  defaultInstallationProfile,
  defaultTenantAdmission,
  TENANT_ADMISSION_GATES,
  validateInstallationProfile,
} from "../../packages/engine-domain/productization.mjs";
import { createProductStore } from "./product-store.mjs";

const actor = {
  email: "administrator@example.test",
  principalId: "principal-admin",
  roles: ["admin"],
};

describe("tenant provisioning", () => {
  it("commits the requested owner grant and reports the durable handoff", async () => {
    const profile = validateInstallationProfile(defaultInstallationProfile());
    const client = {
      query: vi.fn(async (sql, values = []) => {
        const statement = String(sql);
        if (["begin", "commit", "rollback"].includes(statement)) return result();
        if (statement.includes('from "vasi_engine"."installation_profile_pointer"')) {
          return result([{
            id: "installation-profile-1",
            profile,
            profileHash: hashCanonicalJSON(profile),
            revision: 1,
          }]);
        }
        if (statement.includes('count(*)::integer as "count"')) return result([{ count: 0 }]);
        if (statement.includes('select "lastSequence", "lastHash"')) {
          return result([{ lastHash: "0".repeat(64), lastSequence: 0 }]);
        }
        if (statement.includes('select 1 from "vasi_engine"."integration_binding_pointer"')) {
          return result();
        }
        if (statement.includes('select 1 from "vasi_engine"."tenant_admission_pointer"')) {
          return result();
        }
        if (/^(insert|update)/.test(statement.trim())) return result();
        throw new Error(`Unexpected provisioning query: ${statement} (${values.length} values)`);
      }),
      release: vi.fn(),
    };
    const store = createProductStore(
      { connect: vi.fn(async () => client) },
      settings(),
      "installation-test",
    );

    const provisioned = await store.provisionTenant(actor, {
      name: "Example Company",
      ownerEmail: "OWNER@EXAMPLE.COM",
      slug: "example-company",
    });

    expect(provisioned).toMatchObject({
      admission: { revision: 1, status: "pending" },
      name: "Example Company",
      owner: { email: "owner@example.com", grantCreated: true },
      roles: ["owner"],
      slug: "example-company",
    });
    const ownerGrant = client.query.mock.calls.find(([sql]) =>
      String(sql).includes('insert into "vasi_engine"."tenant_membership_grant"')
    );
    expect(ownerGrant?.[1]?.[2]).toBe("owner@example.com");
    expect(client.query.mock.calls.at(-1)?.[0]).toBe("commit");
  });

  it("serializes a stable command and returns its exact committed result without a second tenant", async () => {
    const fixture = replayProvisionDatabase();
    const store = createProductStore(fixture.database, settings(), "installation-test");
    const command = {
      commandId: "33333333-3333-4333-8333-333333333333",
      name: "Replay-safe Company",
      ownerEmail: "owner@example.com",
      slug: "replay-safe-company",
    };

    const created = await store.provisionTenant(actor, command);
    const replayed = await store.provisionTenant(actor, command);

    expect(replayed).toEqual(created);
    expect(fixture.state.tenantInsertCount).toBe(1);
    expect(fixture.state.commandInsertCount).toBe(1);
    const statements = fixture.client.query.mock.calls.map(([sql]) => String(sql));
    expect(statements.filter((sql) => sql.includes("pg_advisory_xact_lock"))).toHaveLength(2);
    expect(statements.indexOf(statements.find((sql) => sql.includes("pg_advisory_xact_lock"))))
      .toBeLessThan(statements.indexOf(statements.find((sql) => sql.includes('from "vasi_engine"."tenant_provision_command"'))));
    expect(statements.filter((sql) => sql === "commit")).toHaveLength(2);
  });

  it("rejects changed-input and cross-actor command reuse before creating another tenant", async () => {
    const fixture = replayProvisionDatabase();
    const store = createProductStore(fixture.database, settings(), "installation-test");
    const command = {
      commandId: "44444444-4444-4444-8444-444444444444",
      name: "Bound Company",
      ownerEmail: "owner@example.com",
      slug: "bound-company",
    };
    await store.provisionTenant(actor, command);

    await expect(store.provisionTenant(actor, { ...command, name: "Changed Company" }))
      .rejects.toMatchObject({ code: "tenant_provision_command_conflict", status: 409 });
    await expect(store.provisionTenant({ ...actor, principalId: "other-admin" }, command))
      .rejects.toMatchObject({ code: "tenant_provision_command_conflict", status: 409 });

    expect(fixture.state.tenantInsertCount).toBe(1);
    expect(fixture.client.query.mock.calls.filter(([sql]) => sql === "rollback")).toHaveLength(2);
  });

  it("fails closed when a stored provisioning result or its digest is altered", async () => {
    const fixture = replayProvisionDatabase();
    const store = createProductStore(fixture.database, settings(), "installation-test");
    const command = {
      commandId: "55555555-5555-4555-8555-555555555555",
      name: "Integrity Company",
      ownerEmail: "owner@example.com",
      slug: "integrity-company",
    };
    await store.provisionTenant(actor, command);
    fixture.state.replayRow.resultHash = "0".repeat(64);

    await expect(store.provisionTenant(actor, command))
      .rejects.toMatchObject({ code: "tenant_provision_command_integrity_failure", status: 500 });
    expect(fixture.state.tenantInsertCount).toBe(1);
    expect(fixture.client.query.mock.calls.at(-1)?.[0]).toBe("rollback");
  });
});

function replayProvisionDatabase() {
  const profile = validateInstallationProfile(defaultInstallationProfile());
  const state = {
    commandInsertCount: 0,
    replayRow: undefined,
    tenantInsertCount: 0,
  };
  const client = {
    query: vi.fn(async (sql, values = []) => {
      const statement = String(sql);
      if (["begin", "commit", "rollback"].includes(statement)) return result();
      if (statement.includes("pg_advisory_xact_lock")) return result([{}]);
      if (statement.includes('from "vasi_engine"."tenant_provision_command"')) {
        return result(state.replayRow ? [state.replayRow] : []);
      }
      if (statement.includes('insert into "vasi_engine"."tenant_provision_command"')) {
        state.commandInsertCount += 1;
        state.replayRow = {
          actorPrincipalId: values[1],
          inputHash: values[2],
          result: structuredClone(values[3]),
          resultHash: values[4],
        };
        return result();
      }
      if (statement.includes('from "vasi_engine"."installation_profile_pointer"')) {
        return result([{
          id: "installation-profile-1",
          profile,
          profileHash: hashCanonicalJSON(profile),
          revision: 1,
        }]);
      }
      if (statement.includes('count(*)::integer as "count"')) return result([{ count: 0 }]);
      if (statement.includes('insert into "vasi_engine"."tenant"')) state.tenantInsertCount += 1;
      if (statement.includes('select "lastSequence", "lastHash"')) {
        return result([{ lastHash: "0".repeat(64), lastSequence: 0 }]);
      }
      if (statement.includes('select 1 from "vasi_engine"."integration_binding_pointer"')) return result();
      if (statement.includes('select 1 from "vasi_engine"."tenant_admission_pointer"')) return result();
      if (/^(insert|update)/.test(statement.trim())) return result();
      throw new Error(`Unexpected replay provisioning query: ${statement} (${values.length} values)`);
    }),
    release: vi.fn(),
  };
  return {
    client,
    database: { connect: vi.fn(async () => client) },
    state,
  };
}

describe("tenant production stop", () => {
  it("atomically revokes active requests, suppresses notifications, and records both audit layers", async () => {
    const { client, database } = productionStopDatabase();
    const store = createProductStore(database, settings(), "installation-test");

    const result = await store.stopTenantProduction(actor, stopCommand());

    expect(result).toMatchObject({
      lastProductionStop: {
        admissionChanged: true,
        commandId: "stop-command-1",
        gateId: "isolation_integrity",
        incidentReference: "incident:2026-001",
        reasonCode: "security_incident",
        revokedAssignmentCount: 2,
        resultingAdmissionRevision: 10,
        resultingAdmissionStatus: "pending",
        revokedRequestCount: 2,
        suppressedNotificationCount: 2,
      },
      revision: 10,
      status: "pending",
      tenant: { id: "tenant-1", name: "Example Tenant", slug: "example-tenant" },
    });
    const statements = client.query.mock.calls.map(([sql]) => String(sql));
    expect(statements.filter((sql) => sql.includes('set "status" = \'revoked\''))).toHaveLength(4);
    expect(statements.filter((sql) => sql.includes('"request_lifecycle_event"'))).toHaveLength(2);
    expect(statements.filter((sql) => sql.includes('"evidence_event"'))).toHaveLength(2);
    expect(statements.some((sql) => sql.includes("tenant.production.stopped"))).toBe(true);
    expect(statements.at(-1)).toBe("commit");
  });

  it("records one request lifecycle event and one evidence event per assignment", async () => {
    const { client, database } = productionStopDatabase({
      requestRows: [
        { assignmentId: "assignment-1", requestId: "request-1", status: "issued" },
        { assignmentId: "assignment-1b", requestId: "request-1", status: "issued" },
        { assignmentId: "assignment-2", requestId: "request-2", status: "in_progress" },
      ],
    });
    const store = createProductStore(database, settings(), "installation-test");

    const result = await store.stopTenantProduction(actor, stopCommand());

    expect(result.lastProductionStop).toMatchObject({
      revokedAssignmentCount: 3,
      revokedRequestCount: 2,
      suppressedNotificationCount: 2,
    });
    const statements = client.query.mock.calls.map(([sql]) => String(sql));
    expect(statements.filter((sql) => sql.includes('update "vasi_engine"."request_instance"'))).toHaveLength(2);
    expect(statements.filter((sql) => sql.includes('update "vasi_engine"."participant_assignment"'))).toHaveLength(3);
    expect(statements.filter((sql) => sql.includes('insert into "vasi_engine"."request_lifecycle_event"'))).toHaveLength(2);
    expect(statements.filter((sql) => sql.includes('insert into "vasi_engine"."evidence_event"'))).toHaveLength(3);
  });

  it("rolls the complete stop back when an assignment evidence append fails", async () => {
    const { client, database } = productionStopDatabase({ failAssignmentId: "assignment-2" });
    const store = createProductStore(database, settings(), "installation-test");

    await expect(store.stopTenantProduction(actor, stopCommand())).rejects.toThrow("evidence append failed");
    const statements = client.query.mock.calls.map(([sql]) => String(sql));
    expect(statements.at(-1)).toBe("rollback");
    expect(statements).not.toContain("commit");
    expect(statements.some((sql) =>
      sql.includes('insert into "vasi_engine"."product_configuration_event"')
    )).toBe(false);
  });

  it("requires an installation administrator before opening a transaction", async () => {
    const database = { connect: vi.fn() };
    const store = createProductStore(database, settings(), "installation-test");

    await expect(store.stopTenantProduction({ ...actor, roles: ["owner"] }, stopCommand()))
      .rejects.toMatchObject({ code: "forbidden", status: 403 });
    expect(database.connect).not.toHaveBeenCalled();
  });
});

function productionStopDatabase({ failAssignmentId, requestRows = [
  { assignmentId: "assignment-1", requestId: "request-1", status: "scheduled" },
  { assignmentId: "assignment-2", requestId: "request-2", status: "in_progress" },
] } = {}) {
  const admission = admittedAdmission();
  let currentAssignmentId;
  const client = {
    query: vi.fn(async (sql, values = []) => {
      const statement = String(sql);
      if (["begin", "commit", "rollback"].includes(statement)) return result();
      if (statement.includes("pg_advisory_xact_lock")) return result([{}]);
      if (statement.includes("tenant.production.stopped") && statement.includes("select 1")) return result();
      if (statement.includes('from "vasi_engine"."tenant_admission_pointer" p')) {
        return result([{
          admission,
          admissionHash: hashCanonicalJSON(admission),
          createdAt: new Date("2026-07-14T20:00:00.000Z"),
          createdByPrincipalId: "principal-reviewer",
          id: "admission-9",
          revision: 9,
        }]);
      }
      if (statement.includes('insert into "vasi_engine"."tenant_admission_revision"')) return result();
      if (statement.includes('update "vasi_engine"."tenant_admission_pointer"')) return result([{ tenantId: "tenant-1" }]);
      if (statement.includes('from "vasi_engine"."request_instance" r') && statement.includes("for update of r, a")) {
        return result(requestRows);
      }
      if (statement.includes('update "vasi_engine"."request_instance"')) return result();
      if (statement.includes('update "vasi_engine"."participant_assignment"')) return result();
      if (statement.includes('update "vasi_engine"."outbox_job"')) return result([{ id: `job-${values[0]}` }]);
      if (statement.includes('from "vasi_engine"."evidence_chain_head"')) {
        currentAssignmentId = values[0];
        if (currentAssignmentId === failAssignmentId) throw new Error("evidence append failed");
        return result([{ lastHash: "0".repeat(64), lastSequence: 0 }]);
      }
      if (statement.includes('insert into "vasi_engine"."evidence_event"')) return result();
      if (statement.includes('update "vasi_engine"."evidence_chain_head"')) return result();
      if (statement.includes('insert into "vasi_engine"."request_lifecycle_event"')) return result();
      if (statement.includes('insert into "vasi_engine"."product_configuration_chain_head"')) return result();
      if (statement.includes('from "vasi_engine"."product_configuration_chain_head"')) {
        return result([{ lastHash: "0".repeat(64), lastSequence: 0 }]);
      }
      if (statement.includes('insert into "vasi_engine"."product_configuration_event"')) return result();
      if (statement.includes('update "vasi_engine"."product_configuration_chain_head"')) return result();
      if (statement.includes('from "vasi_engine"."tenant" t') && statement.includes('where t."id" = $1')) {
        return result([{
          lastStopEventData: {
            admissionChanged: true,
            commandId: "stop-command-1",
            gateId: "isolation_integrity",
            incidentReference: "incident:2026-001",
            reasonCode: "security_incident",
            revokedAssignmentCount: requestRows.length,
            resultingAdmissionRevision: 10,
            resultingAdmissionStatus: "pending",
            revokedRequestCount: new Set(requestRows.map((row) => row.requestId)).size,
            stoppedAt: "2026-07-14T21:00:00.000Z",
            suppressedNotificationCount: 2,
          },
          lastStopEventHash: "b".repeat(64),
          lastStoppedAt: new Date("2026-07-14T21:00:00.000Z"),
          lastStoppedByPrincipalId: "principal-admin",
          tenantName: "Example Tenant",
          tenantSlug: "example-tenant",
        }]);
      }
      throw new Error(`Unexpected query after ${currentAssignmentId || "initialization"}: ${statement}`);
    }),
    release: vi.fn(),
  };
  return {
    client,
    database: { connect: vi.fn(async () => client) },
  };
}

function admittedAdmission() {
  let admission = defaultTenantAdmission();
  for (const gateId of TENANT_ADMISSION_GATES) {
    admission = applyTenantAdmissionDecision(admission, {
      decision: "approved",
      evidenceDigest: "a".repeat(64),
      evidenceReference: `evidence:${gateId}`,
      expectedRevision: 1,
      gateId,
      reviewerReference: "reviewer:test",
      tenantId: "tenant-1",
    }, new Date("2026-07-14T20:00:00.000Z"));
  }
  return admission;
}

function stopCommand() {
  return {
    commandId: "stop-command-1",
    expectedRevision: 9,
    gateId: "isolation_integrity",
    incidentReference: "incident:2026-001",
    reasonCode: "security_incident",
    tenantId: "tenant-1",
  };
}

function settings() {
  return { ENGINE_INTEGRATION_CONFIG_ENCRYPTION_SECRET: Buffer.alloc(32, 7).toString("base64url") };
}

function result(rows = []) {
  return { rowCount: rows.length, rows };
}
