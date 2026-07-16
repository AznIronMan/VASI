import { describe, expect, it } from "vitest";

import {
  EGRESS_BOUNDARY_SCHEMA,
  probeEngineEgressBoundary,
  verifyFirewallRules,
} from "./probe-engine-egress-boundary.mjs";

const containerIds = {
  "database-gateway": "a".repeat(64),
  engine: "b".repeat(64),
  "integration-gateway": "c".repeat(64),
  "private-ingress": "d".repeat(64),
  worker: "e".repeat(64),
};
const databasePolicy = `*filter
-F VASI_DATABASE_EGRESS
-A VASI_DATABASE_EGRESS -s 172.30.4.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A VASI_DATABASE_EGRESS -s 172.30.4.0/24 -d 172.30.4.0/24 -j ACCEPT
-A VASI_DATABASE_EGRESS -s 172.30.4.0/24 -d 10.0.0.10/32 -p tcp -m tcp --dport 5432 -j ACCEPT
-A VASI_DATABASE_EGRESS -s 172.30.4.0/24 -j REJECT --reject-with icmp-port-unreachable
-A VASI_DATABASE_EGRESS -j RETURN
COMMIT
`;
const ingressPolicy = `*filter
-F VASI_INGRESS_EGRESS
-A VASI_INGRESS_EGRESS -s 172.30.5.0/28 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A VASI_INGRESS_EGRESS -s 172.30.5.0/28 -j REJECT --reject-with icmp-port-unreachable
-A VASI_INGRESS_EGRESS -j RETURN
COMMIT
`;
const installed = `*filter
:VASI_DATABASE_EGRESS - [0:0]
:VASI_INGRESS_EGRESS - [0:0]
-A DOCKER-USER -j VASI_DATABASE_EGRESS
-A DOCKER-USER -j VASI_INGRESS_EGRESS
${databasePolicy.split("\n").filter((line) => line.startsWith("-A VASI_DATABASE_EGRESS ")).join("\n")}
${ingressPolicy.split("\n").filter((line) => line.startsWith("-A VASI_INGRESS_EGRESS ")).join("\n")}
COMMIT
`;

describe("engine egress boundary probe", () => {
  it("proves exact firewall, private denial, integration egress, health, and database transport", async () => {
    const result = await probeEngineEgressBoundary({ runner: successfulRunner(), tcpProbe: successfulTCPProbe });
    expect(result).toEqual({
      checks: {
        databasePolicy: "ok",
        databaseTransport: "ok",
        deniedPrivateServices: 4,
        integrationEgress: "ok",
        privateIngress: "ok",
        privateIngressPolicy: "ok",
        runtimeHealth: "ok",
      },
      schema: EGRESS_BOUNDARY_SCHEMA,
      status: "ok",
      version: "0.54.0",
    });
  });

  it("fails when an isolated service reaches the canary or the integration path cannot", async () => {
    await expect(probeEngineEgressBoundary({ runner: successfulRunner({ exposed: "engine" }), tcpProbe: successfulTCPProbe }))
      .rejects.toThrow("private service egress boundary is unavailable");
    await expect(probeEngineEgressBoundary({ runner: successfulRunner({ integrationDenied: true }), tcpProbe: successfulTCPProbe }))
      .rejects.toThrow("integration egress path is unavailable");
    await expect(probeEngineEgressBoundary({ runner: successfulRunner({ privateExecutionError: "worker" }), tcpProbe: successfulTCPProbe }))
      .rejects.toThrow("private service egress boundary is unavailable");
  });

  it("requires the exact ordered policy and one Docker forwarding jump", () => {
    expect(verifyFirewallRules(databasePolicy, installed.replace(
      "--ctstate ESTABLISHED,RELATED",
      "--ctstate RELATED,ESTABLISHED",
    ))).toBe(true);
    expect(() => verifyFirewallRules(databasePolicy, installed.replace(
      "-A DOCKER-USER -j VASI_DATABASE_EGRESS\n",
      "",
    ))).toThrow("firewall policy is unavailable");
    expect(() => verifyFirewallRules(databasePolicy, installed.replace(
      "-d 10.0.0.10/32",
      "-d 10.0.0.11/32",
    ))).toThrow("firewall policy is unavailable");
  });

  it("supports isolated project and chain names and rejects unsafe arguments", async () => {
    const customDatabasePolicy = databasePolicy.replaceAll("VASI_DATABASE_EGRESS", "VASI_TEST_EGRESS");
    const customIngressPolicy = ingressPolicy.replaceAll("VASI_INGRESS_EGRESS", "VASI_TEST_INGRESS");
    const customInstalled = installed
      .replaceAll("VASI_DATABASE_EGRESS", "VASI_TEST_EGRESS")
      .replaceAll("VASI_INGRESS_EGRESS", "VASI_TEST_INGRESS");
    const runner = successfulRunner({
      installedPolicy: customInstalled,
      renderedDatabasePolicy: customDatabasePolicy,
      renderedIngressPolicy: customIngressPolicy,
    });
    await expect(probeEngineEgressBoundary({
      databaseChain: "VASI_TEST_EGRESS",
      ingressChain: "VASI_TEST_INGRESS",
      projectName: "vasi-egress-test",
      runner,
      tcpProbe: successfulTCPProbe,
    })).resolves.toMatchObject({ status: "ok" });
    await expect(probeEngineEgressBoundary({ databaseChain: "unsafe-chain", runner }))
      .rejects.toThrow("arguments are invalid");
    await expect(probeEngineEgressBoundary({ projectName: "../unsafe", runner }))
      .rejects.toThrow("arguments are invalid");
    await expect(probeEngineEgressBoundary({ databaseChain: "VASI_SAME", ingressChain: "VASI_SAME", runner }))
      .rejects.toThrow("arguments are invalid");
  });

  it("requires a published and reachable private ingress listener", async () => {
    await expect(probeEngineEgressBoundary({
      runner: successfulRunner({ listenerBindings: null }),
      tcpProbe: successfulTCPProbe,
    })).rejects.toThrow("private ingress listener is unavailable");
    await expect(probeEngineEgressBoundary({
      runner: successfulRunner({ listenerBindings: [{ HostIp: "not-an-ip", HostPort: "11121" }] }),
      tcpProbe: successfulTCPProbe,
    })).rejects.toThrow("private ingress listener is unavailable");
    await expect(probeEngineEgressBoundary({
      runner: successfulRunner(),
      tcpProbe: async () => false,
    })).rejects.toThrow("private ingress listener is unavailable");
  });
});

function successfulRunner({
  exposed,
  installedPolicy = installed,
  integrationDenied = false,
  listenerBindings = [{ HostIp: "127.0.0.1", HostPort: "11121" }],
  privateExecutionError,
  renderedDatabasePolicy = databasePolicy,
  renderedIngressPolicy = ingressPolicy,
} = {}) {
  return async (command, args) => {
    if (command === "iptables-save") return { code: 0, stderr: "", stdout: installedPolicy };
    if (args[0] === "network") {
      return { code: 0, stderr: "", stdout: args[2].endsWith("private-ingress-listener") ? "172.30.5.0/28\n" : "172.30.4.0/24\n" };
    }
    const ps = args.indexOf("ps");
    if (ps >= 0) return { code: 0, stderr: "", stdout: `${containerIds[args[ps + 2]]}\n` };
    if (args.includes("egress-policy")) {
      return {
        code: 0,
        stderr: "",
        stdout: args.includes("scripts/render-private-ingress-egress-policy.mjs")
          ? renderedIngressPolicy
          : renderedDatabasePolicy,
      };
    }
    if (args[0] === "inspect") {
      if (args[2]?.includes("PortBindings")) {
        return { code: 0, stderr: "", stdout: `${JSON.stringify(listenerBindings)}\n` };
      }
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

async function successfulTCPProbe() {
  return true;
}
