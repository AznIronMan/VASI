import process from "node:process";
import { isDirectExecution } from "./direct-execution.mjs";

export const PRIVATE_INGRESS_EGRESS_CHAIN = "VASI_INGRESS_EGRESS";
export const PRIVATE_INGRESS_EGRESS_POLICY_SCHEMA = "vasi-private-ingress-egress-policy/v1";

export function privateIngressEgressPolicy({
  chain = PRIVATE_INGRESS_EGRESS_CHAIN,
  subnet,
} = {}) {
  const checkedChain = validatedChain(chain);
  const checkedSubnet = validatedIPv4Subnet(subnet);
  return Object.freeze({
    portable: Object.freeze({
      defaultAction: "deny-new",
      establishedReturn: "allow",
      schema: PRIVATE_INGRESS_EGRESS_POLICY_SCHEMA,
      sourceSubnet: checkedSubnet,
    }),
    rules: renderPrivateIngressEgressRules({ chain: checkedChain, subnet: checkedSubnet }),
    subnet: checkedSubnet,
  });
}

export function renderPrivateIngressEgressRules({
  chain = PRIVATE_INGRESS_EGRESS_CHAIN,
  subnet,
}) {
  const checkedChain = validatedChain(chain);
  const checkedSubnet = validatedIPv4Subnet(subnet);
  return [
    "*filter",
    `-F ${checkedChain}`,
    `-A ${checkedChain} -s ${checkedSubnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
    `-A ${checkedChain} -s ${checkedSubnet} -j REJECT --reject-with icmp-port-unreachable`,
    `-A ${checkedChain} -j RETURN`,
    "COMMIT",
    "",
  ].join("\n");
}

function validatedChain(value) {
  const chain = String(value || "");
  if (!/^[A-Z][A-Z0-9_]{0,27}$/.test(chain)) {
    throw new Error("The VASI private-ingress egress chain is invalid.");
  }
  return chain;
}

function validatedIPv4Subnet(value) {
  const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(value || ""));
  if (!match) throw new Error("The VASI private-ingress egress subnet is invalid.");
  const octets = match[1].split(".").map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255) || octets[0] === 0 ||
      octets[0] === 127 || octets[0] >= 224 || (octets[0] === 169 && octets[1] === 254)) {
    throw new Error("The VASI private-ingress egress subnet is invalid.");
  }
  const prefix = Number(match[2]);
  if (prefix < 8 || prefix > 30) throw new Error("The VASI private-ingress egress subnet is invalid.");
  const integer = octets.reduce((value, octet) => ((value << 8) | octet) >>> 0, 0);
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  if (((integer & mask) >>> 0) !== integer) {
    throw new Error("The VASI private-ingress egress subnet is invalid.");
  }
  return `${octets.join(".")}/${prefix}`;
}

function parseArguments(args) {
  const parsed = { chain: PRIVATE_INGRESS_EGRESS_CHAIN, format: "iptables", subnet: "" };
  const seen = new Set();
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (!value || seen.has(option) || !["--chain", "--format", "--subnet"].includes(option)) {
      throw new Error("VASI private-ingress egress policy arguments are invalid.");
    }
    seen.add(option);
    if (option === "--chain") parsed.chain = validatedChain(value);
    if (option === "--format") parsed.format = value;
    if (option === "--subnet") parsed.subnet = value;
  }
  if (!parsed.subnet || !["iptables", "portable-json"].includes(parsed.format)) {
    throw new Error("VASI private-ingress egress policy arguments are invalid.");
  }
  return parsed;
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  let parsed;
  try {
    parsed = parseArguments(process.argv.slice(2));
  } catch {
    console.error("VASI private-ingress egress policy generation failed.");
    process.exitCode = 1;
  }
  if (parsed) {
    try {
      const result = privateIngressEgressPolicy(parsed);
      process.stdout.write(parsed.format === "portable-json"
        ? `${JSON.stringify(result.portable)}\n`
        : result.rules);
    } catch {
      console.error("VASI private-ingress egress policy generation failed.");
      process.exitCode = 1;
    }
  }
}
