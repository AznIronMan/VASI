import { describe, expect, it } from "vitest";

import {
  EGRESS_BOUNDARY_SCHEMA,
  probeEngineEgressBoundary,
  verifyDatabaseFirewallRules,
} from "./probe-engine-egress-boundary.mjs";

const containerIds = {
  "database-gateway": "a".repeat(64),
  engine: "b".repeat(64),
  "integration-gateway": "c".repeat(64),
  "private-ingress": "d".repeat(64),
  worker: "e".repeat(64),
};
const policy = `*filter
-F VASI_DATABASE_EGRESS
-A VASI_DATABASE_EGRESS -s 172.30.4.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A VASI_DATABASE_EGRESS -s 172.30.4.0/24 -d 172.30.4.0/24 -j ACCEPT
-A VASI_DATABASE_EGRESS -s 172.30.4.0/24 -d 10.0.0.10/32 -p tcp -m tcp --dport 5432 -j ACCEPT
-A VASI_DATABASE_EGRESS -s 172.30.4.0/24 -j REJECT --reject-with icmp-port-unreachable
-A VASI_DATABASE_EGRESS -j RETURN
COMMIT
`;
const installed = `*filter
:VASI_DATABASE_EGRESS - [0:0]
-A DOCKER-USER -j VASI_DATABASE_EGRESS
${policy.split("\n").filter((line) => line.startsWith("-A VASI_DATABASE_EGRESS ")).join("\n")}
COMMIT
`;

describe("engine egress boundary probe", () => {
  it("proves exact firewall, private denial, integration egress, health, and database transport", async () => {
    const result = await probeEngineEgressBoundary({ runner: successfulRunner() });
    expect(result).toEqual({
      checks: {
        databasePolicy: "ok",
        databaseTransport: "ok",
        deniedPrivateServices: 4,
        integrationEgress: "ok",
        runtimeHealth: "ok",
      },
      schema: EGRESS_BOUNDARY_SCHEMA,
      status: "ok",
      version: "0.21.1",
    });
  });

  it("fails when an isolated service reaches the canary or the integration path cannot", async () => {
    await expect(probeEngineEgressBoundary({ runner: successfulRunner({ exposed: "engine" }) }))
      .rejects.toThrow("private service egress boundary is unavailable");
    await expect(probeEngineEgressBoundary({ runner: successfulRunner({ integrationDenied: true }) }))
      .rejects.toThrow("integration egress path is unavailable");
    await expect(probeEngineEgressBoundary({ runner: successfulRunner({ privateExecutionError: "worker" }) }))
      .rejects.toThrow("private service egress boundary is unavailable");
  });

  it("requires the exact ordered policy and one Docker forwarding jump", () => {
    expect(verifyDatabaseFirewallRules(policy, installed.replace(
      "--ctstate ESTABLISHED,RELATED",
      "--ctstate RELATED,ESTABLISHED",
    ))).toBe(true);
    expect(() => verifyDatabaseFirewallRules(policy, installed.replace(
      "-A DOCKER-USER -j VASI_DATABASE_EGRESS\n",
      "",
    ))).toThrow("firewall policy is unavailable");
    expect(() => verifyDatabaseFirewallRules(policy, installed.replace(
      "-d 10.0.0.10/32",
      "-d 10.0.0.11/32",
    ))).toThrow("firewall policy is unavailable");
  });

  it("supports isolated project and chain names and rejects unsafe arguments", async () => {
    const customPolicy = policy.replaceAll("VASI_DATABASE_EGRESS", "VASI_TEST_EGRESS");
    const customInstalled = installed.replaceAll("VASI_DATABASE_EGRESS", "VASI_TEST_EGRESS");
    const runner = successfulRunner({ installedPolicy: customInstalled, renderedPolicy: customPolicy });
    await expect(probeEngineEgressBoundary({
      chain: "VASI_TEST_EGRESS",
      projectName: "vasi-egress-test",
      runner,
    })).resolves.toMatchObject({ status: "ok" });
    await expect(probeEngineEgressBoundary({ chain: "unsafe-chain", runner }))
      .rejects.toThrow("arguments are invalid");
    await expect(probeEngineEgressBoundary({ projectName: "../unsafe", runner }))
      .rejects.toThrow("arguments are invalid");
  });
});

function successfulRunner({
  exposed,
  installedPolicy = installed,
  integrationDenied = false,
  privateExecutionError,
  renderedPolicy = policy,
} = {}) {
  return async (command, args) => {
    if (command === "iptables-save") return { code: 0, stderr: "", stdout: installedPolicy };
    if (args[0] === "network") return { code: 0, stderr: "", stdout: "172.30.4.0/24\n" };
    const ps = args.indexOf("ps");
    if (ps >= 0) return { code: 0, stderr: "", stdout: `${containerIds[args[ps + 2]]}\n` };
    if (args.includes("egress-policy")) return { code: 0, stderr: "", stdout: renderedPolicy };
    if (args[0] === "inspect") {
      const service = Object.entries(containerIds).find(([, value]) => value === args.at(-1))?.[0];
      return {
        code: 0,
        stderr: "",
        stdout: ["database-gateway", "engine", "integration-gateway"].includes(service)
          ? "running|healthy\n"
          : "running|\n",
      };
    }
    if (args[0] === "exec" && args.at(-1).includes("fetch(")) {
      const service = Object.entries(containerIds).find(([, value]) => value === args[1])?.[0];
      const allowed = service === "integration-gateway" ? !integrationDenied : service === exposed;
      return { code: service === privateExecutionError ? 1 : (allowed ? 0 : 42), stderr: "", stdout: "" };
    }
    if (args[0] === "exec" && args.at(-1).includes("select 1")) {
      return { code: 0, stderr: "", stdout: "" };
    }
    return { code: 1, stderr: "", stdout: "" };
  };
}
