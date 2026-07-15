import { isIP } from "node:net";

const MAXIMUM_FORWARDING_HEADER_BYTES = 1_024;
const MAXIMUM_FORWARDING_HOPS = 16;

type ParsedAddress = {
  bytes: Uint8Array;
  family: 4 | 6;
  normalized: string;
};

type TrustedNetwork = {
  bytes: Uint8Array;
  family: 4 | 6;
  prefix: number;
};

export function parseTrustedProxyCIDRs(value?: string) {
  if (!value?.trim()) return [];
  const entries = value.split(",").map((entry) => entry.trim());
  if (!entries.length || entries.length > MAXIMUM_FORWARDING_HOPS || entries.some((entry) => !entry)) {
    throw new Error(
      `VASI_TRUSTED_PROXY_CIDRS must contain at most ${MAXIMUM_FORWARDING_HOPS} comma-separated IP networks.`,
    );
  }

  return entries.map((entry) => {
    parseNetwork(entry);
    return entry.toLowerCase();
  });
}

export function resolveTrustedClientAddress(
  headers: Pick<Headers, "get">,
  trustedProxyCIDRs: readonly string[],
) {
  const forwarded = headers.get("x-forwarded-for");
  const source = forwarded === null ? headers.get("x-real-ip") : forwarded;
  if (!source || Buffer.byteLength(source, "utf8") > MAXIMUM_FORWARDING_HEADER_BYTES) {
    return undefined;
  }

  const rawAddresses = source.split(",").map((address) => address.trim());
  if (
    !rawAddresses.length ||
    rawAddresses.length > MAXIMUM_FORWARDING_HOPS ||
    rawAddresses.some((address) => !address)
  ) {
    return undefined;
  }

  const addresses = rawAddresses.map(parseAddress);
  if (addresses.some((address) => !address)) return undefined;
  const validAddresses = addresses as ParsedAddress[];

  if (!trustedProxyCIDRs.length) {
    return validAddresses.length === 1 ? validAddresses[0].normalized : undefined;
  }

  let trustedNetworks: TrustedNetwork[];
  try {
    trustedNetworks = trustedProxyCIDRs.map(parseNetwork);
  } catch {
    return undefined;
  }

  for (let index = validAddresses.length - 1; index >= 0; index -= 1) {
    const address = validAddresses[index];
    if (!trustedNetworks.some((network) => containsAddress(network, address))) {
      return address.normalized;
    }
  }
  return undefined;
}

export function clientAddressRateLimitIdentity(address?: string) {
  if (!address) return "unattributed";
  const parsed = parseAddress(address);
  if (!parsed) return "unattributed";
  if (parsed.family === 4) return `ipv4:${parsed.normalized}`;
  return `ipv6-64:${Buffer.from(parsed.bytes.subarray(0, 8)).toString("hex")}`;
}

function parseNetwork(value: string): TrustedNetwork {
  const components = value.split("/");
  if (components.length > 2) throw new Error("Invalid trusted proxy network.");
  const address = parseAddress(components[0]);
  if (!address) throw new Error("Invalid trusted proxy network.");
  const maximum = address.family === 4 ? 32 : 128;
  const prefix = components[1] === undefined ? maximum : Number(components[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maximum) {
    throw new Error("Invalid trusted proxy network prefix.");
  }
  if (!networkBitsAreZero(address.bytes, prefix)) {
    throw new Error("Trusted proxy networks must use their canonical network address.");
  }
  return { bytes: address.bytes, family: address.family, prefix };
}

function parseAddress(value: string): ParsedAddress | undefined {
  const candidate = value.trim().toLowerCase();
  const family = isIP(candidate);
  if (family === 4) {
    const bytes = Uint8Array.from(candidate.split(".").map(Number));
    return { bytes, family: 4, normalized: [...bytes].join(".") };
  }
  if (family !== 6) return undefined;

  const bytes = parseIPv6Bytes(candidate);
  if (!bytes) return undefined;
  if (
    bytes.subarray(0, 10).every((byte) => byte === 0) &&
    bytes[10] === 0xff &&
    bytes[11] === 0xff
  ) {
    const mapped = bytes.subarray(12);
    return { bytes: mapped, family: 4, normalized: [...mapped].join(".") };
  }
  return { bytes, family: 6, normalized: formatIPv6(bytes) };
}

function parseIPv6Bytes(value: string) {
  const pieces = value.split("::");
  if (pieces.length > 2) return undefined;
  const left = parseIPv6Side(pieces[0]);
  const right = parseIPv6Side(pieces[1] || "");
  if (!left || !right) return undefined;
  const missing = 8 - left.length - right.length;
  if ((pieces.length === 1 && missing !== 0) || (pieces.length === 2 && missing < 1)) {
    return undefined;
  }
  const words = [...left, ...Array(Math.max(0, missing)).fill(0), ...right];
  if (words.length !== 8) return undefined;
  const bytes = new Uint8Array(16);
  words.forEach((word, index) => {
    bytes[index * 2] = word >> 8;
    bytes[index * 2 + 1] = word & 0xff;
  });
  return bytes;
}

function parseIPv6Side(value: string) {
  if (!value) return [];
  const parts = value.split(":");
  const words: number[] = [];
  for (const [index, part] of parts.entries()) {
    if (part.includes(".")) {
      if (index !== parts.length - 1 || isIP(part) !== 4) return undefined;
      const bytes = part.split(".").map(Number);
      words.push((bytes[0] << 8) | bytes[1], (bytes[2] << 8) | bytes[3]);
    } else {
      if (!/^[a-f0-9]{1,4}$/.test(part)) return undefined;
      words.push(Number.parseInt(part, 16));
    }
  }
  return words;
}

function formatIPv6(bytes: Uint8Array) {
  const words = Array.from({ length: 8 }, (_, index) =>
    ((bytes[index * 2] << 8) | bytes[index * 2 + 1]).toString(16));
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < words.length;) {
    if (words[start] !== "0") {
      start += 1;
      continue;
    }
    let end = start;
    while (end < words.length && words[end] === "0") end += 1;
    if (end - start > bestLength && end - start >= 2) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  if (bestStart < 0) return words.join(":");
  const left = words.slice(0, bestStart).join(":");
  const right = words.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
}

function containsAddress(network: TrustedNetwork, address: ParsedAddress) {
  if (network.family !== address.family) return false;
  const completeBytes = Math.floor(network.prefix / 8);
  const remainingBits = network.prefix % 8;
  for (let index = 0; index < completeBytes; index += 1) {
    if (network.bytes[index] !== address.bytes[index]) return false;
  }
  if (!remainingBits) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return (network.bytes[completeBytes] & mask) === (address.bytes[completeBytes] & mask);
}

function networkBitsAreZero(bytes: Uint8Array, prefix: number) {
  const completeBytes = Math.floor(prefix / 8);
  const remainingBits = prefix % 8;
  if (remainingBits) {
    const hostMask = (1 << (8 - remainingBits)) - 1;
    if ((bytes[completeBytes] & hostMask) !== 0) return false;
  }
  const firstHostByte = completeBytes + (remainingBits ? 1 : 0);
  return bytes.subarray(firstHostByte).every((byte) => byte === 0);
}
