import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import process from "node:process";
import { pathToFileURL } from "node:url";

import { loadBootstrapSettings } from "./settings-core.mjs";

export const DATABASE_EGRESS_CHAIN = "VASI_DATABASE_EGRESS";
export const DATABASE_EGRESS_POLICY_SCHEMA = "vasi-database-egress-policy/v1";
const MAXIMUM_ADDRESSES = 16;

export async function databaseEgressPolicy({
  bootstrap = loadBootstrapSettings(),
  chain = DATABASE_EGRESS_CHAIN,
  resolver = lookup,
  subnet,
} = {}) {
  const checkedChain = validatedChain(chain);
  const checkedSubnet = validatedIPv4Subnet(subnet);
  let target;
  try {
    target = new URL(bootstrap.databaseURL);
  } catch {
    throw new Error("The VASI database egress target is invalid.");
  }
  if (!["postgres:", "postgresql:"].includes(target.protocol)) {
    throw new Error("The VASI database egress target is invalid.");
  }
  const port = Number(target.port || 5432);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("The VASI database egress target is invalid.");
  }
  let resolved;
  try {
    resolved = await resolver(target.hostname, { all: true, verbatim: true });
  } catch {
    throw new Error("The VASI database egress target could not be resolved.");
  }
  const addresses = [...new Set((resolved || [])
    .filter((entry) => Number(entry?.family) === 4)
    .map((entry) => validatedIPv4Address(entry.address)))]
    .sort(compareIPv4);
  if (!addresses.length || addresses.length > MAXIMUM_ADDRESSES) {
    throw new Error("The VASI database egress target resolution is invalid.");
  }
  const portable = portableDatabaseEgressPolicy({ addresses, port, subnet: checkedSubnet });
  return Object.freeze({
    addresses: Object.freeze(addresses),
    port,
    portable,
    rules: renderDatabaseEgressRules({ addresses, chain: checkedChain, port, subnet: checkedSubnet }),
    subnet: checkedSubnet,
  });
}

export function portableDatabaseEgressPolicy({ addresses, port, subnet }) {
  const checkedSubnet = validatedIPv4Subnet(subnet);
  if (!Array.isArray(addresses) || !addresses.length || addresses.length > MAXIMUM_ADDRESSES) {
    throw new Error("The VASI database egress address set is invalid.");
  }
  const checkedAddresses = [...new Set(addresses.map(validatedIPv4Address))].sort(compareIPv4);
  if (checkedAddresses.length !== addresses.length) throw new Error("The VASI database egress address set is invalid.");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("The VASI database egress port is invalid.");
  return Object.freeze({
    defaultAction: "deny",
    destinations: Object.freeze(checkedAddresses.map((address) => Object.freeze({ address, port, protocol: "tcp" }))),
    establishedReturn: "allow",
    intraSubnet: "allow",
    schema: DATABASE_EGRESS_POLICY_SCHEMA,
    sourceSubnet: checkedSubnet,
  });
}

export function renderDatabaseEgressRules({ addresses, chain = DATABASE_EGRESS_CHAIN, port, subnet }) {
  const checkedChain = validatedChain(chain);
  const checkedSubnet = validatedIPv4Subnet(subnet);
  if (!Array.isArray(addresses) || !addresses.length || addresses.length > MAXIMUM_ADDRESSES) {
    throw new Error("The VASI database egress address set is invalid.");
  }
  const checkedAddresses = [...new Set(addresses.map(validatedIPv4Address))].sort(compareIPv4);
  if (checkedAddresses.length !== addresses.length) throw new Error("The VASI database egress address set is invalid.");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("The VASI database egress port is invalid.");
  return [
    "*filter",
    `-F ${checkedChain}`,
    `-A ${checkedChain} -s ${checkedSubnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
    `-A ${checkedChain} -s ${checkedSubnet} -d ${checkedSubnet} -j ACCEPT`,
    ...checkedAddresses.map((address) =>
      `-A ${checkedChain} -s ${checkedSubnet} -d ${address}/32 -p tcp -m tcp --dport ${port} -j ACCEPT`
    ),
    `-A ${checkedChain} -s ${checkedSubnet} -j REJECT --reject-with icmp-port-unreachable`,
    `-A ${checkedChain} -j RETURN`,
    "COMMIT",
    "",
  ].join("\n");
}

function validatedChain(value) {
  const chain = String(value || "");
  if (!/^[A-Z][A-Z0-9_]{0,27}$/.test(chain)) {
    throw new Error("The VASI database egress chain is invalid.");
  }
  return chain;
}

function validatedIPv4Subnet(value) {
  const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(value || ""));
  if (!match) throw new Error("The VASI database egress subnet is invalid.");
  const address = validatedIPv4Address(match[1]);
  const prefix = Number(match[2]);
  if (prefix < 8 || prefix > 30) throw new Error("The VASI database egress subnet is invalid.");
  const integer = ipv4Integer(address);
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  if (((integer & mask) >>> 0) !== integer) throw new Error("The VASI database egress subnet is invalid.");
  return `${address}/${prefix}`;
}

function validatedIPv4Address(value) {
  const address = String(value || "");
  if (isIP(address) !== 4) throw new Error("The VASI database egress address is invalid.");
  const octets = address.split(".").map(Number);
  if (octets[0] === 0 || octets[0] === 127 || octets[0] >= 224 || (octets[0] === 169 && octets[1] === 254)) {
    throw new Error("The VASI database egress address is invalid.");
  }
  return octets.join(".");
}

function compareIPv4(left, right) {
  return ipv4Integer(left) - ipv4Integer(right);
}

function ipv4Integer(address) {
  return address.split(".").map(Number).reduce((value, octet) => ((value << 8) | octet) >>> 0, 0);
}

function parseArguments(args) {
  const parsed = { chain: DATABASE_EGRESS_CHAIN, format: "iptables", subnet: "" };
  const seen = new Set();
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (!value || seen.has(option) || !["--chain", "--format", "--subnet"].includes(option)) {
      throw new Error("VASI database egress policy arguments are invalid.");
    }
    seen.add(option);
    if (option === "--chain") parsed.chain = validatedChain(value);
    if (option === "--format") parsed.format = value;
    if (option === "--subnet") parsed.subnet = value;
  }
  if (!parsed.subnet || !["iptables", "portable-json"].includes(parsed.format)) {
    throw new Error("VASI database egress policy arguments are invalid.");
  }
  return parsed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const parsed = parseArguments(process.argv.slice(2));
  databaseEgressPolicy(parsed)
    .then((result) => process.stdout.write(parsed.format === "portable-json"
      ? `${JSON.stringify(result.portable)}\n`
      : result.rules))
    .catch(() => {
      console.error("VASI database egress policy generation failed.");
      process.exitCode = 1;
    });
}
