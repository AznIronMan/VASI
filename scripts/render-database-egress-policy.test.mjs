import { describe, expect, it } from "vitest";

import {
  databaseEgressPolicy,
  renderDatabaseEgressRules,
} from "./render-database-egress-policy.mjs";

describe("database egress firewall policy", () => {
  it("renders an exact bounded destination set with an established path and terminal denial", async () => {
    const databaseURL = new URL("postgresql://database.example.test:5444/vasi");
    databaseURL.username = "private-user";
    databaseURL.password = "private-password";
    const result = await databaseEgressPolicy({
      bootstrap: { databaseURL: databaseURL.toString() },
      resolver: async () => [
        { address: "10.0.10.20", family: 4 },
        { address: "10.0.10.10", family: 4 },
        { address: "10.0.10.20", family: 4 },
        { address: "2001:db8::1", family: 6 },
      ],
      subnet: "172.30.4.0/24",
    });
    expect(result).toMatchObject({
      addresses: ["10.0.10.10", "10.0.10.20"],
      port: 5444,
      subnet: "172.30.4.0/24",
    });
    expect(result.portable).toEqual({
      defaultAction: "deny",
      destinations: [
        { address: "10.0.10.10", port: 5444, protocol: "tcp" },
        { address: "10.0.10.20", port: 5444, protocol: "tcp" },
      ],
      establishedReturn: "allow",
      intraSubnet: "allow",
      schema: "vasi-database-egress-policy/v1",
      sourceSubnet: "172.30.4.0/24",
    });
    expect(result.rules).toContain("--ctstate ESTABLISHED,RELATED -j ACCEPT");
    expect(result.rules).toContain("-d 10.0.10.10/32 -p tcp -m tcp --dport 5444 -j ACCEPT");
    expect(result.rules).toContain("-s 172.30.4.0/24 -j REJECT --reject-with icmp-port-unreachable");
    expect(result.rules).toContain("-A VASI_DATABASE_EGRESS -j RETURN");
    expect(result.rules).not.toContain("private-user");
    expect(result.rules).not.toContain("private-password");
    expect(result.rules).not.toContain("database.example.test");
    expect(JSON.stringify(result.portable)).not.toContain("private-user");
    expect(JSON.stringify(result.portable)).not.toContain("private-password");
    expect(JSON.stringify(result.portable)).not.toContain("database.example.test");
  });

  it("rejects malformed/noncanonical subnets, unsafe destinations, duplicate rules, and unbounded ports", async () => {
    expect(() => renderDatabaseEgressRules({
      addresses: ["10.0.10.10"],
      port: 5432,
      subnet: "172.30.4.1/24",
    })).toThrow("subnet is invalid");
    expect(() => renderDatabaseEgressRules({
      addresses: ["127.0.0.1"],
      port: 5432,
      subnet: "172.30.4.0/24",
    })).toThrow("address is invalid");
    expect(() => renderDatabaseEgressRules({
      addresses: ["10.0.10.10", "10.0.10.10"],
      port: 5432,
      subnet: "172.30.4.0/24",
    })).toThrow("address set is invalid");
    expect(() => renderDatabaseEgressRules({
      addresses: ["10.0.10.10"],
      port: 65_536,
      subnet: "172.30.4.0/24",
    })).toThrow("port is invalid");
    expect(() => renderDatabaseEgressRules({
      addresses: ["10.0.10.10"],
      chain: "unsafe-chain",
      port: 5432,
      subnet: "172.30.4.0/24",
    })).toThrow("chain is invalid");
    await expect(databaseEgressPolicy({
      bootstrap: { databaseURL: "postgresql://database.example.test/vasi" },
      resolver: async () => [{ address: "2001:db8::1", family: 6 }],
      subnet: "172.30.4.0/24",
    })).rejects.toThrow("resolution is invalid");
  });

  it("supports a bounded installation-specific adapter chain", () => {
    const rules = renderDatabaseEgressRules({
      addresses: ["10.0.10.10"],
      chain: "VASI_TEST_EGRESS",
      port: 5432,
      subnet: "172.30.4.0/24",
    });
    expect(rules).toContain("-A VASI_TEST_EGRESS -s 172.30.4.0/24");
    expect(rules).not.toContain("VASI_DATABASE_EGRESS");
  });

  it("collapses resolver failures to a bounded error", async () => {
    await expect(databaseEgressPolicy({
      bootstrap: { databaseURL: "postgresql://database.example.test/vasi" },
      resolver: async () => { throw new Error("private resolver details"); },
      subnet: "172.30.4.0/24",
    })).rejects.toThrow("could not be resolved");
    await expect(databaseEgressPolicy({
      bootstrap: { databaseURL: "not a URL" },
      resolver: async () => [{ address: "10.0.10.10", family: 4 }],
      subnet: "172.30.4.0/24",
    })).rejects.toThrow("target is invalid");
  });
});
