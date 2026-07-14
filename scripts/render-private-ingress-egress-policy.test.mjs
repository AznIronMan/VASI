import { describe, expect, it } from "vitest";

import {
  privateIngressEgressPolicy,
  renderPrivateIngressEgressRules,
} from "./render-private-ingress-egress-policy.mjs";

describe("private-ingress egress firewall policy", () => {
  it("allows only established replies before terminal new-flow denial", () => {
    const result = privateIngressEgressPolicy({ subnet: "172.30.5.0/28" });
    expect(result.portable).toEqual({
      defaultAction: "deny-new",
      establishedReturn: "allow",
      schema: "vasi-private-ingress-egress-policy/v1",
      sourceSubnet: "172.30.5.0/28",
    });
    expect(result.rules).toContain("--ctstate ESTABLISHED,RELATED -j ACCEPT");
    expect(result.rules).toContain("-s 172.30.5.0/28 -j REJECT --reject-with icmp-port-unreachable");
    expect(result.rules.indexOf("ESTABLISHED,RELATED")).toBeLessThan(result.rules.indexOf("-j REJECT"));
  });

  it("supports a bounded per-installation chain and rejects unsafe drift", () => {
    const rules = renderPrivateIngressEgressRules({
      chain: "VASI_TEST_INGRESS",
      subnet: "172.30.5.0/28",
    });
    expect(rules).toContain("-A VASI_TEST_INGRESS -s 172.30.5.0/28");
    expect(() => renderPrivateIngressEgressRules({
      chain: "unsafe-chain",
      subnet: "172.30.5.0/28",
    })).toThrow("chain is invalid");
    expect(() => renderPrivateIngressEgressRules({
      subnet: "172.30.5.1/28",
    })).toThrow("subnet is invalid");
    expect(() => renderPrivateIngressEgressRules({
      subnet: "127.0.0.0/24",
    })).toThrow("subnet is invalid");
  });
});
