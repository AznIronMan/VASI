import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rm,
} from "node:fs/promises";
import path from "node:path";

export const CUSTODY_SCHEMA = "vasi-backup-custody/v1";
export const CUSTODY_CONTENT_SCHEMA = "vasi-matched-backup-stream/v1";
export const CUSTODY_READINESS_SCHEMA = "vasi-backup-custody-readiness/v1";

const OUTER_MAGIC = Buffer.from("VASICU01", "ascii");
const INNER_MAGIC = Buffer.from("VASIBM01", "ascii");
const OUTER_PREFIX_BYTES = OUTER_MAGIC.length + 4;
const AUTH_TAG_BYTES = 16;
const CONTENT_CHUNK_BYTES = 8 * 1024 * 1024;
const MAX_HEADER_BYTES = 64 * 1024;
const MAX_PACKAGE_BYTES = 2 ** 40 + 128 * 1024 * 1024;
const PACKAGE_NAME = /^vasi-custody-(\d{8}T\d{6}Z)-([a-f0-9]{64})\.vbc$/;
const BACKUP_NAME = /^vasi-\d{8}T\d{6}Z$/;
const LOCK_NAME = ".vasi-custody.lock";
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const WRAP_SCHEMA = "vasi-backup-content-key-wrap/v1";
const FILES = Object.freeze([
  Object.freeze({ code: 1, maximumBytes: 1024 * 1024, minimumBytes: 2, name: "manifest.json" }),
  Object.freeze({ code: 2, maximumBytes: 64 * 1024 * 1024, minimumBytes: 1, name: "VASI.settings" }),
  Object.freeze({ code: 3, maximumBytes: 2 ** 40, minimumBytes: 1, name: "postgresql.dump" }),
]);

export class BackupCustodyError extends Error {
  constructor(message, result) {
    super(message);
    this.result = result;
  }
}

export function parseCustodyRecipients(rawValue) {
  let value;
  try {
    value = typeof rawValue === "string" ? JSON.parse(rawValue) : rawValue;
  } catch {
    throw new Error("The backup custody recipient configuration is not valid JSON.");
  }
  if (!Array.isArray(value) || value.length < 1 || value.length > 8) {
    throw new Error("Backup custody requires between 1 and 8 recipients.");
  }
  const recipients = value.map((entry) => {
    assertObjectKeys(entry, ["keyId", "publicJwk"], "backup custody recipient");
    const keyId = validKeyId(entry.keyId);
    const publicJwk = validatePublicJwk(entry.publicJwk);
    return Object.freeze({ keyId, publicJwk });
  }).sort((left, right) => left.keyId < right.keyId ? -1 : left.keyId > right.keyId ? 1 : 0);
  if (new Set(recipients.map((entry) => entry.keyId)).size !== recipients.length) {
    throw new Error("Backup custody recipient key IDs must be unique.");
  }
  return Object.freeze(recipients);
}

export async function generateCustodyRecipient({ keyId, privateKeyFile }) {
  const validatedKeyId = validKeyId(keyId);
  if (typeof privateKeyFile !== "string" || !privateKeyFile.trim()) {
    throw new Error("A private recipient-key file is required.");
  }
  const target = path.resolve(privateKeyFile);
  const parent = await secureDirectory(path.dirname(target), "recipient-key directory");
  await assertMissing(target, "The private recipient-key file already exists.");
  const { privateKey } = generateKeyPairSync("x25519");
  const privateJwk = canonicalPrivateJwk(privateKey.export({ format: "jwk" }));
  const publicJwk = canonicalPublicJwk(createPublicKey(privateKey).export({ format: "jwk" }));
  const privateBytes = Buffer.from(`${JSON.stringify(privateJwk, null, 2)}\n`, "utf8");
  let handle;
  try {
    handle = await open(target, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    await writeAll(handle, privateBytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await syncDirectory(parent);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await rm(target, { force: true }).catch(() => undefined);
    throw error;
  } finally {
    privateBytes.fill(0);
  }
  return Object.freeze({ keyId: validatedKeyId, publicJwk });
}

export async function createCustodyEnvelope({
  custodyRoot,
  now = new Date(),
  recipients,
  source,
  verify,
}) {
  if (typeof verify !== "function") throw new Error("A matched-backup verifier is required.");
  const root = await secureDirectory(custodyRoot, "backup custody root");
  const sourceDirectory = await secureDirectory(source, "matched-backup directory");
  const instant = validDate(now, "custody creation time");
  const validatedRecipients = parseCustodyRecipients(recipients);
  const fileInventory = [];
  for (const definition of FILES) {
    const filename = path.join(sourceDirectory, definition.name);
    const details = await secureRegularPath(filename, `${definition.name} backup file`, definition.maximumBytes);
    if (details.size < definition.minimumBytes) throw new Error(`The ${definition.name} backup file is empty or truncated.`);
    fileInventory.push({ ...definition, filename, size: details.size });
  }
  const manifest = await verify(sourceDirectory, { quiet: true });
  const sourceCreatedAt = validIsoTimestamp(manifest?.createdAt, "matched-backup creation time").toISOString();
  const contentBytes = safeContentSize(fileInventory);
  const contentKey = randomBytes(32);
  const contentSalt = randomBytes(16);
  const noncePrefix = randomBytes(8);
  const { privateKey: ephemeralPrivateKey, publicKey: ephemeralPublicKey } = generateKeyPairSync("x25519");
  const ephemeralPublicJwk = canonicalPublicJwk(ephemeralPublicKey.export({ format: "jwk" }));
  const wrappedRecipients = [];
  let partial;
  let destination;
  let verified = false;
  try {
    for (const recipient of validatedRecipients) {
      wrappedRecipients.push(wrapContentKey({
        contentKey,
        contentSalt,
        ephemeralPrivateKey,
        ephemeralPublicJwk,
        recipient,
      }));
    }
    const header = canonicalHeader({
      content: {
        bytes: contentBytes,
        chunkBytes: CONTENT_CHUNK_BYTES,
        chunks: contentChunkCount(contentBytes),
        format: CUSTODY_CONTENT_SCHEMA,
      },
      createdAt: instant.toISOString(),
      encryption: {
        content: "A256GCM-CHUNKED",
        keyAgreement: "X25519-HKDF-SHA256",
        noncePrefix: noncePrefix.toString("base64url"),
        salt: contentSalt.toString("base64url"),
      },
      ephemeralPublicKey: ephemeralPublicJwk,
      recipients: wrappedRecipients,
      schema: CUSTODY_SCHEMA,
      sourceCreatedAt,
    });
    const headerBytes = Buffer.from(JSON.stringify(header), "utf8");
    if (headerBytes.length > MAX_HEADER_BYTES) throw new Error("The backup custody header is too large.");
    const prefix = Buffer.alloc(OUTER_PREFIX_BYTES);
    OUTER_MAGIC.copy(prefix, 0);
    prefix.writeUInt32BE(headerBytes.length, OUTER_MAGIC.length);
    partial = path.join(root, `.vasi-custody.partial-${randomUUID()}`);
    const handle = await open(partial, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const packageDigest = createHash("sha256");
    const encryptor = new ContentChunkEncryptor({
      contentKey,
      digest: packageDigest,
      handle,
      headerBytes,
      noncePrefix,
      plaintextBytes: contentBytes,
    });
    try {
      await writeHashed(handle, packageDigest, prefix);
      await writeHashed(handle, packageDigest, headerBytes);
      await encryptor.feed(INNER_MAGIC);
      for (const entry of fileInventory) {
        const entryHeader = Buffer.alloc(9);
        entryHeader.writeUInt8(entry.code, 0);
        entryHeader.writeBigUInt64BE(BigInt(entry.size), 1);
        await encryptor.feed(entryHeader);
        const input = await openReadonlyRegular(entry.filename, `${entry.name} backup file`, entry.maximumBytes);
        try {
          await readChunks(input, entry.size, async (chunk) => encryptor.feed(chunk));
        } finally {
          await input.close();
        }
      }
      await encryptor.finish();
      await handle.sync();
    } finally {
      encryptor.destroy();
      await handle.close();
    }
    const digest = packageDigest.digest("hex");
    const name = custodyPackageName(new Date(sourceCreatedAt), digest);
    destination = path.join(root, name);
    await assertMissing(destination, "A custody package with this exact digest already exists.");
    await rename(partial, destination);
    partial = undefined;
    await syncDirectory(root);
    const inspected = await inspectCustodyPackage(destination);
    if (inspected.sourceCreatedAt !== sourceCreatedAt) throw new Error("The custody package source timestamp changed during creation.");
    verified = true;
    return Object.freeze({ ...inspected, created: true });
  } finally {
    contentKey.fill(0);
    contentSalt.fill(0);
    noncePrefix.fill(0);
    await rm(partial, { force: true }).catch(() => undefined);
    if (destination && !verified) await rm(destination, { force: true }).catch(() => undefined);
  }
}

export async function createCustodyCycle({
  custodyRoot,
  matchedBackupRoot,
  maximumAgeHours = 26,
  now = new Date(),
  recipients,
  retain = 30,
  verify,
} = {}) {
  const backupRoot = await secureDirectory(matchedBackupRoot, "matched-backup root");
  const root = await secureDirectory(custodyRoot, "backup custody root");
  const instant = validDate(now, "custody cycle time");
  boundedInteger(retain, "retained custody-package count", 2, 365);
  boundedNumber(maximumAgeHours, "maximum custody source age", 1, 8_760);
  const validatedRecipients = parseCustodyRecipients(recipients);
  const releaseLock = await acquireLock(root, instant);
  try {
    const backups = await managedBackupNames(backupRoot);
    if (!backups.length) {
      throw custodyFailure("No managed matched backup is available for custody.", maximumAgeHours, "matched_backup_missing");
    }
    const sourceName = backups.at(-1);
    const created = await createCustodyEnvelope({
      custodyRoot: root,
      now: instant,
      recipients: validatedRecipients,
      source: path.join(backupRoot, sourceName),
      verify,
    });
    if (backupDirectoryName(new Date(created.sourceCreatedAt)) !== sourceName) {
      throw new Error("The managed backup name and custody source timestamp disagree.");
    }
    let names = await managedCustodyNames(root);
    let removed = 0;
    while (names.length > retain) {
      const candidate = names.find((entry) => entry !== created.packageName);
      if (!candidate) throw new Error("Custody retention cannot remove the newly verified package.");
      await inspectCustodyPackage(path.join(root, candidate));
      await rm(path.join(root, candidate));
      removed += 1;
      names = await managedCustodyNames(root);
    }
    return Object.freeze({
      ...custodyReadiness({
        managedPackages: names.length,
        maximumAgeHours,
        now: instant,
        recipientCount: created.recipientCount,
        sourceCreatedAt: created.sourceCreatedAt,
      }),
      created: true,
      removed,
      retained: names.length,
    });
  } finally {
    await releaseLock();
  }
}

export async function inspectCustodyPackage(packagePath) {
  const input = await openReadonlyRegular(packagePath, "backup custody package", MAX_PACKAGE_BYTES);
  try {
    const inspected = await inspectOpenPackage(input, packagePath);
    return publicInspection(inspected);
  } finally {
    await input.close();
  }
}

export async function checkLatestCustody({
  custodyRoot,
  maximumAgeHours = 26,
  now = new Date(),
} = {}) {
  const root = await secureDirectory(custodyRoot, "backup custody root");
  const instant = validDate(now, "custody check time");
  boundedNumber(maximumAgeHours, "maximum custody source age", 1, 8_760);
  const names = await managedCustodyNames(root);
  if (!names.length) {
    throw custodyFailure("No managed backup custody package is available.", maximumAgeHours, "custody_package_missing");
  }
  let inspected;
  try {
    inspected = await inspectCustodyPackage(path.join(root, names.at(-1)));
  } catch {
    throw custodyFailure(
      "The newest managed backup custody package failed verification.",
      maximumAgeHours,
      "custody_package_verification_failed",
      names.length,
    );
  }
  return custodyReadiness({
    managedPackages: names.length,
    maximumAgeHours,
    now: instant,
    recipientCount: inspected.recipientCount,
    sourceCreatedAt: inspected.sourceCreatedAt,
  });
}

export async function authenticateCustodyPackage({ keyId, packagePath, privateKeyFile }) {
  const validatedKeyId = validKeyId(keyId);
  const privateKey = await readPrivateKey(privateKeyFile);
  const input = await openReadonlyRegular(packagePath, "backup custody package", MAX_PACKAGE_BYTES);
  let contentKey;
  try {
    const inspected = await inspectOpenPackage(input, packagePath);
    const recipient = inspected.header.recipients.find((entry) => entry.keyId === validatedKeyId);
    if (!recipient) throw new Error("The selected recipient key is not present in this custody package.");
    contentKey = unwrapContentKey({ header: inspected.header, privateKey, recipient });
    await decryptContentChunks({ contentKey, input, inspected });
    return Object.freeze({
      chunksAuthenticated: inspected.header.content.chunks,
      recipientAuthenticated: true,
      schema: CUSTODY_SCHEMA,
      sourceCreatedAt: inspected.header.sourceCreatedAt,
    });
  } catch (error) {
    throw normalizeAuthenticationError(error);
  } finally {
    contentKey?.fill(0);
    await input.close();
  }
}

export async function extractCustodyPackage({
  destination,
  keyId,
  packagePath,
  privateKeyFile,
  verify,
}) {
  if (typeof verify !== "function") throw new Error("A matched-backup verifier is required.");
  const validatedKeyId = validKeyId(keyId);
  const privateKey = await readPrivateKey(privateKeyFile);
  const target = path.resolve(destination || "");
  if (!destination) throw new Error("A recovery destination is required.");
  const parent = await secureDirectory(path.dirname(target), "recovery destination parent");
  await assertMissing(target, "The recovery destination already exists.");
  const input = await openReadonlyRegular(packagePath, "backup custody package", MAX_PACKAGE_BYTES);
  let contentKey;
  let temporary;
  let extractor;
  try {
    const inspected = await inspectOpenPackage(input, packagePath);
    const recipient = inspected.header.recipients.find((entry) => entry.keyId === validatedKeyId);
    if (!recipient) throw new Error("The selected recipient key is not present in this custody package.");
    contentKey = unwrapContentKey({ header: inspected.header, privateKey, recipient });
    temporary = `${target}.partial-${randomUUID()}`;
    await mkdir(temporary, { mode: 0o700, recursive: false });
    extractor = new InnerExtractor(temporary);
    await decryptContentChunks({
      consume: async (plaintext) => extractor.feed(plaintext),
      contentKey,
      input,
      inspected,
    });
    await extractor.finish();
    extractor = undefined;
    const manifest = await verify(temporary, { quiet: true });
    if (manifest?.createdAt !== inspected.header.sourceCreatedAt) {
      throw new Error("The recovered backup timestamp does not match the authenticated custody header.");
    }
    await rename(temporary, target);
    temporary = undefined;
    await syncDirectory(parent);
    return Object.freeze({
      extracted: true,
      recipientAuthenticated: true,
      schema: CUSTODY_SCHEMA,
      sourceCreatedAt: inspected.header.sourceCreatedAt,
    });
  } catch (error) {
    throw normalizeAuthenticationError(error);
  } finally {
    contentKey?.fill(0);
    await extractor?.abort().catch(() => undefined);
    await input.close();
    await rm(temporary, { force: true, recursive: true }).catch(() => undefined);
  }
}

function wrapContentKey({ contentKey, contentSalt, ephemeralPrivateKey, ephemeralPublicJwk, recipient }) {
  const recipientPublicKey = createPublicKey({ format: "jwk", key: recipient.publicJwk });
  const shared = diffieHellman({ privateKey: ephemeralPrivateKey, publicKey: recipientPublicKey });
  const wrappingKey = Buffer.from(hkdfSync(
    "sha256",
    shared,
    contentSalt,
    Buffer.from(`${CUSTODY_SCHEMA}\0${recipient.keyId}`, "utf8"),
    32,
  ));
  const nonce = randomBytes(12);
  try {
    const cipher = createCipheriv("aes-256-gcm", wrappingKey, nonce, { authTagLength: AUTH_TAG_BYTES });
    cipher.setAAD(wrapAAD(recipient.keyId, ephemeralPublicJwk));
    const wrappedKey = Buffer.concat([cipher.update(contentKey), cipher.final()]);
    return Object.freeze({
      keyId: recipient.keyId,
      nonce: nonce.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
      wrappedKey: wrappedKey.toString("base64url"),
    });
  } finally {
    shared.fill(0);
    wrappingKey.fill(0);
    nonce.fill(0);
  }
}

function unwrapContentKey({ header, privateKey, recipient }) {
  const ephemeralPublicKey = createPublicKey({ format: "jwk", key: header.ephemeralPublicKey });
  const shared = diffieHellman({ privateKey, publicKey: ephemeralPublicKey });
  const contentSalt = decodeBase64Url(header.encryption.salt, 16, "content key salt");
  const wrappingKey = Buffer.from(hkdfSync(
    "sha256",
    shared,
    contentSalt,
    Buffer.from(`${CUSTODY_SCHEMA}\0${recipient.keyId}`, "utf8"),
    32,
  ));
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      wrappingKey,
      decodeBase64Url(recipient.nonce, 12, "recipient nonce"),
      { authTagLength: AUTH_TAG_BYTES },
    );
    decipher.setAAD(wrapAAD(recipient.keyId, header.ephemeralPublicKey));
    decipher.setAuthTag(decodeBase64Url(recipient.tag, AUTH_TAG_BYTES, "recipient authentication tag"));
    const key = Buffer.concat([
      decipher.update(decodeBase64Url(recipient.wrappedKey, 32, "wrapped content key")),
      decipher.final(),
    ]);
    if (key.length !== 32) throw new Error("The unwrapped backup content key is invalid.");
    return key;
  } finally {
    shared.fill(0);
    contentSalt.fill(0);
    wrappingKey.fill(0);
  }
}

async function decryptContentChunks({ consume, contentKey, input, inspected }) {
  const noncePrefix = decodeBase64Url(inspected.header.encryption.noncePrefix, 8, "content nonce prefix");
  let position = inspected.contentOffset;
  let remaining = inspected.header.content.bytes;
  try {
    for (let index = 0; index < inspected.header.content.chunks; index += 1) {
      const plaintextLength = Math.min(CONTENT_CHUNK_BYTES, remaining);
      const ciphertext = await readExact(input, plaintextLength, position);
      const authTag = await readExact(input, AUTH_TAG_BYTES, position + plaintextLength);
      const nonce = chunkNonce(noncePrefix, index);
      const decipher = createDecipheriv("aes-256-gcm", contentKey, nonce, {
        authTagLength: AUTH_TAG_BYTES,
      });
      decipher.setAAD(chunkAAD(inspected.headerBytes, index, plaintextLength), { plaintextLength });
      decipher.setAuthTag(authTag);
      const updated = decipher.update(ciphertext);
      let finalPlaintext;
      let plaintext;
      try {
        finalPlaintext = decipher.final();
        plaintext = Buffer.concat([updated, finalPlaintext]);
        if (consume) await consume(plaintext, index);
      } finally {
        nonce.fill(0);
        updated.fill(0);
        finalPlaintext?.fill(0);
        plaintext?.fill(0);
      }
      position += plaintextLength + AUTH_TAG_BYTES;
      remaining -= plaintextLength;
    }
    if (remaining !== 0) throw new Error("The authenticated custody chunk inventory is invalid.");
  } finally {
    noncePrefix.fill(0);
  }
}

function wrapAAD(keyId, ephemeralPublicJwk) {
  return Buffer.from(`${WRAP_SCHEMA}\0${keyId}\0${ephemeralPublicJwk.x}`, "utf8");
}

async function inspectOpenPackage(handle, packagePath) {
  const details = await handle.stat();
  if (!details.isFile() || details.size < OUTER_PREFIX_BYTES + AUTH_TAG_BYTES || details.size > MAX_PACKAGE_BYTES) {
    throw new Error("The backup custody package size is invalid.");
  }
  if ((details.mode & 0o077) !== 0) throw new Error("The backup custody package must be mode 0600 or stricter.");
  const parsedName = PACKAGE_NAME.exec(path.basename(path.resolve(packagePath || "")));
  if (!parsedName) throw new Error("The backup custody package name is invalid.");
  const digest = createHash("sha256");
  await readRangeChunks(handle, 0, details.size, async (chunk) => digest.update(chunk));
  if (digest.digest("hex") !== parsedName[2]) throw new Error("The backup custody package copy digest is invalid.");
  const prefix = await readExact(handle, OUTER_PREFIX_BYTES, 0);
  if (!prefix.subarray(0, OUTER_MAGIC.length).equals(OUTER_MAGIC)) {
    throw new Error("The backup custody package magic is unsupported.");
  }
  const headerLength = prefix.readUInt32BE(OUTER_MAGIC.length);
  if (headerLength < 2 || headerLength > MAX_HEADER_BYTES) throw new Error("The backup custody header length is invalid.");
  const headerBytes = await readExact(handle, headerLength, OUTER_PREFIX_BYTES);
  let parsedHeader;
  try {
    parsedHeader = JSON.parse(headerBytes.toString("utf8"));
  } catch {
    throw new Error("The backup custody header is not valid JSON.");
  }
  const header = validateHeader(parsedHeader);
  const canonicalBytes = Buffer.from(JSON.stringify(canonicalHeader(header)), "utf8");
  if (!canonicalBytes.equals(headerBytes)) throw new Error("The backup custody header is not canonical.");
  const contentOffset = OUTER_PREFIX_BYTES + headerLength;
  const expectedSize = contentOffset + header.content.bytes + header.content.chunks * AUTH_TAG_BYTES;
  if (expectedSize !== details.size) throw new Error("The backup custody package length is invalid.");
  const sourceNameTimestamp = parsedName[1];
  if (custodyTimestamp(new Date(header.sourceCreatedAt)) !== sourceNameTimestamp) {
    throw new Error("The backup custody filename and source timestamp disagree.");
  }
  return { contentOffset, header, headerBytes, packageName: path.basename(packagePath) };
}

function validateHeader(value) {
  assertObjectKeys(
    value,
    ["content", "createdAt", "encryption", "ephemeralPublicKey", "recipients", "schema", "sourceCreatedAt"],
    "backup custody header",
  );
  if (value.schema !== CUSTODY_SCHEMA) throw new Error("The backup custody schema is unsupported.");
  validIsoTimestamp(value.createdAt, "custody creation time");
  validIsoTimestamp(value.sourceCreatedAt, "custody source creation time");
  assertObjectKeys(value.content, ["bytes", "chunkBytes", "chunks", "format"], "backup custody content descriptor");
  if (value.content.format !== CUSTODY_CONTENT_SCHEMA) throw new Error("The backup custody content format is unsupported.");
  if (!Number.isSafeInteger(value.content.bytes) || value.content.bytes < minimumContentSize() || value.content.bytes > MAX_PACKAGE_BYTES) {
    throw new Error("The backup custody content length is invalid.");
  }
  if (value.content.chunkBytes !== CONTENT_CHUNK_BYTES || value.content.chunks !== contentChunkCount(value.content.bytes)) {
    throw new Error("The backup custody content chunk inventory is invalid.");
  }
  assertObjectKeys(value.encryption, ["content", "keyAgreement", "noncePrefix", "salt"], "backup custody encryption descriptor");
  if (value.encryption.content !== "A256GCM-CHUNKED" || value.encryption.keyAgreement !== "X25519-HKDF-SHA256") {
    throw new Error("The backup custody encryption suite is unsupported.");
  }
  decodeBase64Url(value.encryption.noncePrefix, 8, "content nonce prefix");
  decodeBase64Url(value.encryption.salt, 16, "content key salt");
  validatePublicJwk(value.ephemeralPublicKey);
  if (!Array.isArray(value.recipients) || value.recipients.length < 1 || value.recipients.length > 8) {
    throw new Error("The backup custody recipient inventory is invalid.");
  }
  const keyIds = [];
  for (const recipient of value.recipients) {
    assertObjectKeys(recipient, ["keyId", "nonce", "tag", "wrappedKey"], "wrapped backup custody recipient");
    keyIds.push(validKeyId(recipient.keyId));
    decodeBase64Url(recipient.nonce, 12, "recipient nonce");
    decodeBase64Url(recipient.tag, AUTH_TAG_BYTES, "recipient authentication tag");
    decodeBase64Url(recipient.wrappedKey, 32, "wrapped content key");
  }
  if (new Set(keyIds).size !== keyIds.length || [...keyIds].sort().join("\0") !== keyIds.join("\0")) {
    throw new Error("Backup custody recipients must have unique, sorted key IDs.");
  }
  return value;
}

function canonicalHeader(value) {
  return {
    content: {
      bytes: value.content.bytes,
      chunkBytes: value.content.chunkBytes,
      chunks: value.content.chunks,
      format: value.content.format,
    },
    createdAt: value.createdAt,
    encryption: {
      content: value.encryption.content,
      keyAgreement: value.encryption.keyAgreement,
      noncePrefix: value.encryption.noncePrefix,
      salt: value.encryption.salt,
    },
    ephemeralPublicKey: canonicalPublicJwk(value.ephemeralPublicKey),
    recipients: value.recipients.map((recipient) => ({
      keyId: recipient.keyId,
      nonce: recipient.nonce,
      tag: recipient.tag,
      wrappedKey: recipient.wrappedKey,
    })),
    schema: value.schema,
    sourceCreatedAt: value.sourceCreatedAt,
  };
}

function validatePublicJwk(value) {
  assertObjectKeys(value, ["crv", "kty", "x"], "X25519 public JWK");
  if (value.kty !== "OKP" || value.crv !== "X25519") throw new Error("The backup custody recipient key must be X25519.");
  decodeBase64Url(value.x, 32, "X25519 public key");
  let key;
  try {
    key = createPublicKey({ format: "jwk", key: value });
  } catch {
    throw new Error("The backup custody X25519 public key is invalid.");
  }
  if (key.asymmetricKeyType !== "x25519") throw new Error("The backup custody recipient key must be X25519.");
  return Object.freeze(canonicalPublicJwk(value));
}

function canonicalPublicJwk(value) {
  return Object.freeze({ crv: "X25519", kty: "OKP", x: value.x });
}

function canonicalPrivateJwk(value) {
  assertObjectKeys(value, ["crv", "d", "kty", "x"], "X25519 private JWK");
  if (value.kty !== "OKP" || value.crv !== "X25519") throw new Error("The backup custody private key must be X25519.");
  decodeBase64Url(value.d, 32, "X25519 private key");
  decodeBase64Url(value.x, 32, "X25519 public key");
  return Object.freeze({ crv: "X25519", d: value.d, kty: "OKP", x: value.x });
}

async function readPrivateKey(filename) {
  const details = await secureRegularPath(filename, "private recipient-key file", 64 * 1024);
  if (details.size < 2) throw new Error("The private recipient-key file is empty.");
  const handle = await openReadonlyRegular(filename, "private recipient-key file", 64 * 1024);
  let contents;
  try {
    contents = await readExact(handle, details.size, 0);
  } finally {
    await handle.close();
  }
  try {
    let jwk;
    try {
      jwk = canonicalPrivateJwk(JSON.parse(contents.toString("utf8")));
    } catch (error) {
      if (error?.message?.startsWith("The backup custody")) throw error;
      throw new Error("The private recipient-key file is invalid.");
    }
    const key = createPrivateKey({ format: "jwk", key: jwk });
    if (key.asymmetricKeyType !== "x25519") throw new Error("The backup custody private key must be X25519.");
    const derived = canonicalPublicJwk(createPublicKey(key).export({ format: "jwk" }));
    if (derived.x !== jwk.x) throw new Error("The backup custody private-key public component is invalid.");
    return key;
  } finally {
    contents.fill(0);
  }
}

class ContentChunkEncryptor {
  constructor({ contentKey, digest, handle, headerBytes, noncePrefix, plaintextBytes }) {
    this.buffer = Buffer.allocUnsafe(CONTENT_CHUNK_BYTES);
    this.contentKey = contentKey;
    this.digest = digest;
    this.handle = handle;
    this.headerBytes = headerBytes;
    this.index = 0;
    this.noncePrefix = noncePrefix;
    this.offset = 0;
    this.plaintextBytes = plaintextBytes;
    this.total = 0;
  }

  async feed(value) {
    const plaintext = Buffer.isBuffer(value) ? value : Buffer.from(value);
    let sourceOffset = 0;
    while (sourceOffset < plaintext.length) {
      const length = Math.min(this.buffer.length - this.offset, plaintext.length - sourceOffset);
      plaintext.copy(this.buffer, this.offset, sourceOffset, sourceOffset + length);
      this.offset += length;
      this.total += length;
      sourceOffset += length;
      if (this.offset === this.buffer.length) await this.flush();
    }
  }

  async finish() {
    if (this.offset) await this.flush();
    if (this.total !== this.plaintextBytes || this.index !== contentChunkCount(this.plaintextBytes)) {
      throw new Error("The backup custody content stream length changed during creation.");
    }
  }

  destroy() {
    this.buffer.fill(0);
  }

  async flush() {
    const plaintextLength = this.offset;
    const nonce = chunkNonce(this.noncePrefix, this.index);
    const cipher = createCipheriv("aes-256-gcm", this.contentKey, nonce, { authTagLength: AUTH_TAG_BYTES });
    cipher.setAAD(chunkAAD(this.headerBytes, this.index, plaintextLength), { plaintextLength });
    const ciphertext = Buffer.concat([cipher.update(this.buffer.subarray(0, plaintextLength)), cipher.final()]);
    try {
      await writeHashed(this.handle, this.digest, ciphertext);
      await writeHashed(this.handle, this.digest, cipher.getAuthTag());
    } finally {
      this.buffer.fill(0, 0, plaintextLength);
      nonce.fill(0);
      ciphertext.fill(0);
    }
    this.index += 1;
    this.offset = 0;
  }
}

class InnerExtractor {
  constructor(directory) {
    this.directory = directory;
    this.entryIndex = -1;
    this.remaining = 0;
    this.state = "magic";
    this.buffer = Buffer.alloc(0);
    this.handle = undefined;
  }

  async feed(value) {
    let chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    while (chunk.length) {
      if (this.state === "magic" || this.state === "header") {
        const required = this.state === "magic" ? INNER_MAGIC.length : 9;
        const take = Math.min(required - this.buffer.length, chunk.length);
        this.buffer = Buffer.concat([this.buffer, chunk.subarray(0, take)]);
        chunk = chunk.subarray(take);
        if (this.buffer.length < required) continue;
        if (this.state === "magic") {
          if (!this.buffer.equals(INNER_MAGIC)) throw new Error("The authenticated custody content magic is unsupported.");
          this.buffer = Buffer.alloc(0);
          this.state = "header";
          continue;
        }
        this.entryIndex += 1;
        const definition = FILES[this.entryIndex];
        if (!definition || this.buffer.readUInt8(0) !== definition.code) {
          throw new Error("The authenticated custody file inventory is invalid.");
        }
        const size = Number(this.buffer.readBigUInt64BE(1));
        if (!Number.isSafeInteger(size) || size < definition.minimumBytes || size > definition.maximumBytes) {
          throw new Error(`The authenticated ${definition.name} length is invalid.`);
        }
        this.buffer = Buffer.alloc(0);
        this.remaining = size;
        this.handle = await open(
          path.join(this.directory, definition.name),
          fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
          0o600,
        );
        this.state = "body";
      }
      if (this.state === "body") {
        const take = Math.min(this.remaining, chunk.length);
        await writeAll(this.handle, chunk.subarray(0, take));
        this.remaining -= take;
        chunk = chunk.subarray(take);
        if (this.remaining === 0) {
          await this.handle.sync();
          await this.handle.close();
          this.handle = undefined;
          this.state = this.entryIndex === FILES.length - 1 ? "complete" : "header";
        }
      }
      if (this.state === "complete" && chunk.length) {
        throw new Error("The authenticated custody content contains trailing data.");
      }
    }
  }

  async finish() {
    if (this.state !== "complete" || this.buffer.length || this.handle) {
      throw new Error("The authenticated custody content is truncated.");
    }
    await syncDirectory(this.directory);
  }

  async abort() {
    await this.handle?.close();
    this.handle = undefined;
  }
}

function publicInspection(inspected) {
  return Object.freeze({
    copyDigestVerified: true,
    createdAt: inspected.header.createdAt,
    packageName: inspected.packageName,
    recipientCount: inspected.header.recipients.length,
    recipientAuthentication: "not_performed",
    schema: CUSTODY_SCHEMA,
    sourceCreatedAt: inspected.header.sourceCreatedAt,
    structureVerified: true,
  });
}

function custodyReadiness({ managedPackages, maximumAgeHours, now, recipientCount, sourceCreatedAt }) {
  const created = validDate(new Date(sourceCreatedAt), "custody source creation time");
  const ageHours = rounded((now.getTime() - created.getTime()) / 3_600_000);
  if (ageHours < -5 / 60) {
    throw custodyFailure(
      "The newest custody package has a future source creation time.",
      maximumAgeHours,
      "custody_source_time_in_future",
      managedPackages,
    );
  }
  const result = Object.freeze({
    ageHours: Math.max(0, ageHours),
    managedPackages,
    maximumAgeHours,
    reasons: [],
    recipientCount,
    recipientAuthentication: "not_performed",
    schema: CUSTODY_READINESS_SCHEMA,
    sourceCreatedAt: created.toISOString(),
    status: "ready",
  });
  if (ageHours > maximumAgeHours) {
    throw new BackupCustodyError(
      "The newest custody package source backup is older than the configured threshold.",
      Object.freeze({ ...result, reasons: ["custody_source_age_threshold_exceeded"], status: "critical" }),
    );
  }
  return result;
}

function custodyFailure(message, maximumAgeHours, reason, managedPackages = 0) {
  return new BackupCustodyError(message, Object.freeze({
    ageHours: null,
    managedPackages,
    maximumAgeHours,
    reasons: [reason],
    recipientCount: null,
    recipientAuthentication: "not_performed",
    schema: CUSTODY_READINESS_SCHEMA,
    sourceCreatedAt: null,
    status: "critical",
  }));
}

async function secureDirectory(value, label) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`A protected ${label} is required.`);
  const directory = path.resolve(value);
  const details = await lstat(directory).catch(() => undefined);
  if (!details?.isDirectory() || details.isSymbolicLink()) throw new Error(`The ${label} must be an existing real directory.`);
  if ((details.mode & 0o077) !== 0) throw new Error(`The ${label} must be mode 0700 or stricter.`);
  return directory;
}

async function secureRegularPath(value, label, maximumBytes) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`A ${label} is required.`);
  const filename = path.resolve(value);
  const details = await lstat(filename).catch(() => undefined);
  if (!details?.isFile() || details.isSymbolicLink()) throw new Error(`The ${label} must be an existing real file.`);
  if ((details.mode & 0o077) !== 0) throw new Error(`The ${label} must be mode 0600 or stricter.`);
  if (!Number.isSafeInteger(details.size) || details.size > maximumBytes) throw new Error(`The ${label} is too large.`);
  return details;
}

async function openReadonlyRegular(value, label, maximumBytes) {
  await secureRegularPath(value, label, maximumBytes);
  const noFollow = fsConstants.O_NOFOLLOW || 0;
  const handle = await open(path.resolve(value), fsConstants.O_RDONLY | noFollow);
  try {
    const details = await handle.stat();
    if (!details.isFile() || (details.mode & 0o077) !== 0 || details.size > maximumBytes) {
      throw new Error(`The ${label} changed during validation.`);
    }
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function acquireLock(root, now) {
  const lockPath = path.join(root, LOCK_NAME);
  let handle;
  try {
    handle = await open(lockPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    await writeAll(handle, Buffer.from(`${JSON.stringify({ schema: "vasi-backup-custody-lock/v1", startedAt: now.toISOString() })}\n`));
    await handle.sync();
  } catch (error) {
    if (error?.code === "EEXIST") throw new Error("Another backup custody cycle holds the protected custody lock.");
    throw error;
  } finally {
    await handle?.close().catch(() => undefined);
  }
  return async () => rm(lockPath, { force: true });
}

async function managedBackupNames(root) {
  const entries = await readdir(root, { withFileTypes: true });
  return entries.filter((entry) => entry.isDirectory() && BACKUP_NAME.test(entry.name)).map((entry) => entry.name).sort();
}

async function managedCustodyNames(root) {
  const entries = await readdir(root, { withFileTypes: true });
  return entries.filter((entry) => entry.isFile() && PACKAGE_NAME.test(entry.name)).map((entry) => entry.name).sort();
}

function safeContentSize(inventory) {
  const bytes = INNER_MAGIC.length + inventory.reduce((total, entry) => total + 9 + entry.size, 0);
  if (!Number.isSafeInteger(bytes) || bytes > MAX_PACKAGE_BYTES) throw new Error("The matched backup is too large for a custody package.");
  return bytes;
}

function minimumContentSize() {
  return INNER_MAGIC.length + FILES.reduce((total, entry) => total + 9 + entry.minimumBytes, 0);
}

function contentChunkCount(bytes) {
  const chunks = Math.ceil(bytes / CONTENT_CHUNK_BYTES);
  if (!Number.isSafeInteger(chunks) || chunks < 1 || chunks > 0xffff_ffff) {
    throw new Error("The backup custody content chunk count is invalid.");
  }
  return chunks;
}

function chunkNonce(prefix, index) {
  if (!Buffer.isBuffer(prefix) || prefix.length !== 8 || !Number.isInteger(index) || index < 0 || index > 0xffff_ffff) {
    throw new Error("The backup custody content nonce is invalid.");
  }
  const nonce = Buffer.alloc(12);
  prefix.copy(nonce, 0);
  nonce.writeUInt32BE(index, 8);
  return nonce;
}

function chunkAAD(headerBytes, index, plaintextLength) {
  if (!Number.isInteger(plaintextLength) || plaintextLength < 1 || plaintextLength > CONTENT_CHUNK_BYTES) {
    throw new Error("The backup custody plaintext chunk length is invalid.");
  }
  const descriptor = Buffer.alloc(8);
  descriptor.writeUInt32BE(index, 0);
  descriptor.writeUInt32BE(plaintextLength, 4);
  return Buffer.concat([
    headerBytes,
    Buffer.from("\0vasi-backup-content-chunk/v1\0", "utf8"),
    descriptor,
  ]);
}

async function writeHashed(handle, digest, value) {
  if (!value.length) return;
  digest.update(value);
  await writeAll(handle, value);
}

async function writeAll(handle, value) {
  let offset = 0;
  while (offset < value.length) {
    const { bytesWritten } = await handle.write(value, offset, value.length - offset);
    if (!bytesWritten) throw new Error("A protected file write made no progress.");
    offset += bytesWritten;
  }
}

async function readChunks(handle, size, consume) {
  await readRangeChunks(handle, 0, size, consume);
}

async function readRangeChunks(handle, position, size, consume) {
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    let offset = 0;
    while (offset < size) {
      const length = Math.min(buffer.length, size - offset);
      const { bytesRead } = await handle.read(buffer, 0, length, position + offset);
      if (!bytesRead) throw new Error("A protected file is truncated.");
      await consume(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
  } finally {
    buffer.fill(0);
  }
}

async function readExact(handle, length, position) {
  const value = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await handle.read(value, offset, length - offset, position + offset);
    if (!bytesRead) throw new Error("The backup custody package is truncated.");
    offset += bytesRead;
  }
  return value;
}

async function syncDirectory(directory) {
  const handle = await open(directory, fsConstants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function assertMissing(target, message) {
  const details = await lstat(target).catch((error) => {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  });
  if (details) throw new Error(message);
}

function assertObjectKeys(value, expected, label) {
  if (!value || Array.isArray(value) || typeof value !== "object") throw new Error(`The ${label} is invalid.`);
  if (Object.keys(value).sort().join("\0") !== [...expected].sort().join("\0")) {
    throw new Error(`The ${label} fields are unsupported.`);
  }
}

function decodeBase64Url(value, expectedBytes, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`The ${label} is invalid.`);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== expectedBytes || decoded.toString("base64url") !== value) throw new Error(`The ${label} is invalid.`);
  return decoded;
}

function validKeyId(value) {
  if (typeof value !== "string" || !KEY_ID.test(value)) {
    throw new Error("Backup custody key IDs must be opaque 1-64 character tokens using letters, numbers, dot, dash, or underscore.");
  }
  return value;
}

function validDate(value, label) {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value;
}

function validIsoTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`The ${label} is invalid.`);
  const parsed = validDate(new Date(value), label);
  if (parsed.toISOString() !== value) throw new Error(`The ${label} is invalid.`);
  return parsed;
}

function boundedInteger(value, label, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`The ${label} must be between ${minimum} and ${maximum}.`);
}

function boundedNumber(value, label, minimum, maximum) {
  if (!Number.isFinite(value) || value < minimum || value > maximum) throw new Error(`The ${label} must be between ${minimum} and ${maximum}.`);
}

function rounded(value) {
  return Number(value.toFixed(3));
}

function custodyTimestamp(date) {
  return date.toISOString().slice(0, 19).replaceAll("-", "").replaceAll(":", "") + "Z";
}

function custodyPackageName(sourceCreatedAt, digest) {
  return `vasi-custody-${custodyTimestamp(sourceCreatedAt)}-${digest}.vbc`;
}

function backupDirectoryName(date) {
  return `vasi-${custodyTimestamp(date)}`;
}

function normalizeAuthenticationError(error) {
  if (
    error?.code === "ERR_OSSL_EVP_BAD_DECRYPT" ||
    /authenticate data|bad decrypt|unable to authenticate|Unsupported state/i.test(error?.message || "")
  ) return new Error("The backup custody package or selected recipient key could not be authenticated.");
  return error;
}
