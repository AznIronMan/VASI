export type CompanyProvisioningDraft = {
  inviteOwner: boolean;
  name: string;
  ownerEmail: string;
  slug: string;
};

export type CompanyProvisioningRetry = {
  commandId: string;
  createdAt: number;
  fingerprint: string;
};

type RetryStorage = Pick<Storage, "getItem" | "removeItem" | "setItem">;

const RETRY_STORAGE_KEY = "vasi:company-provisioning-command:v1";
const RETRY_LIFETIME_MS = 24 * 60 * 60 * 1_000;

export async function nextCompanyProvisioningCommand(
  previous: CompanyProvisioningRetry | undefined,
  draft: CompanyProvisioningDraft,
  createCommandId: () => string,
  { digest = sha256, now = Date.now() }: {
    digest?: (value: string) => Promise<string>;
    now?: number;
  } = {},
): Promise<CompanyProvisioningRetry> {
  const canonical = JSON.stringify({
    inviteOwner: draft.inviteOwner,
    name: draft.name.normalize("NFC").trim(),
    ownerEmail: draft.ownerEmail.normalize("NFC").trim().toLowerCase(),
    slug: draft.slug.normalize("NFC").trim().toLowerCase(),
  });
  let fingerprint = "";
  try {
    const candidate = (await digest(canonical)).toLowerCase();
    if (/^[a-f0-9]{64}$/.test(candidate)) fingerprint = candidate;
  } catch {
    // A missing browser digest must not block the server-enforced command.
  }
  if (fingerprint && retryValid(previous, now) && previous.fingerprint === fingerprint) {
    return previous;
  }
  return Object.freeze({ commandId: createCommandId(), createdAt: now, fingerprint });
}

export function loadCompanyProvisioningRetry(
  storage: RetryStorage | undefined = browserStorage(),
  now = Date.now(),
): CompanyProvisioningRetry | undefined {
  if (!storage) return undefined;
  try {
    const serialized = storage.getItem(RETRY_STORAGE_KEY);
    if (!serialized) return undefined;
    const value = JSON.parse(serialized) as unknown;
    if (!retryValid(value, now)) {
      storage.removeItem(RETRY_STORAGE_KEY);
      return undefined;
    }
    return Object.freeze(value);
  } catch {
    try {
      storage.removeItem(RETRY_STORAGE_KEY);
    } catch {
      // Browser storage is an optional recovery aid.
    }
    return undefined;
  }
}

export function saveCompanyProvisioningRetry(
  retry: CompanyProvisioningRetry,
  storage: RetryStorage | undefined = browserStorage(),
  now = Date.now(),
) {
  if (!storage) return;
  try {
    if (!retryValid(retry, now)) {
      storage.removeItem(RETRY_STORAGE_KEY);
      return;
    }
    storage.setItem(RETRY_STORAGE_KEY, JSON.stringify(retry));
  } catch {
    // Browser storage is an optional recovery aid.
  }
}

export function clearCompanyProvisioningRetry(
  storage: RetryStorage | undefined = browserStorage(),
) {
  try {
    storage?.removeItem(RETRY_STORAGE_KEY);
  } catch {
    // Browser storage is an optional recovery aid.
  }
}

export function companyProvisioningRetryDefinitelyRejected(status: number) {
  return status >= 400 && status < 500 && ![408, 425, 429, 499].includes(status);
}

function retryValid(value: unknown, now: number): value is CompanyProvisioningRetry {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(",") !== "commandId,createdAt,fingerprint" ||
    typeof record.commandId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(record.commandId) ||
    typeof record.fingerprint !== "string" ||
    !/^[a-f0-9]{64}$/.test(record.fingerprint) ||
    !Number.isSafeInteger(record.createdAt) ||
    Number(record.createdAt) < 1 ||
    Number(record.createdAt) > now + 60_000 ||
    now - Number(record.createdAt) > RETRY_LIFETIME_MS
  ) return false;
  return true;
}

async function sha256(value: string) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function browserStorage(): RetryStorage | undefined {
  if (typeof window === "undefined") return undefined;
  try {
    return window.sessionStorage;
  } catch {
    return undefined;
  }
}
