import {
  createDecipheriv,
  createCipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createReadStream, createWriteStream } from "node:fs";
import path from "node:path";
import process from "node:process";
import { createInterface } from "node:readline";
import { finished } from "node:stream/promises";

import {
  canonicalJSON,
  decryptJSONEnvelope,
  encryptJSONEnvelope,
  sha256Hex,
} from "../packages/engine-crypto/index.mjs";
import {
  createSettingsPool,
  loadBootstrapSettings,
  readRuntimeSettings,
} from "./settings-core.mjs";

const ARCHIVE_SCHEMA = "vasi-encrypted-tenant-archive/v1";
const PAGE_SIZE = 100;
const TABLES = Object.freeze([
  direct("tenant", '"id"', '"id"'),
  direct("tenant_profile_revision", '"tenantId"', '"revision"'),
  direct("tenant_profile_pointer", '"tenantId"', '"tenantId"'),
  direct("tenant_admission_revision", '"tenantId"', '"revision"'),
  direct("tenant_admission_pointer", '"tenantId"', '"tenantId"'),
  direct("tenant_membership", '"tenantId"', '"principalId"'),
  direct("tenant_membership_grant", '"tenantId"', '"createdAt", "id"'),
  direct("retention_policy_revision", '"tenantId"', '"name", "revision"'),
  direct("retention_policy_pointer", '"tenantId"', '"name"'),
  direct("workflow_definition", '"tenantId"', '"createdAt", "id"'),
  direct("workflow_draft", '"tenantId"', '"definitionId"'),
  direct("workflow_revision", '"tenantId"', '"publishedAt", "revision", "id"'),
  direct("document_artifact", '"tenantId"', '"createdAt", "revision", "id"'),
  dependent("document_artifact_chunk", `join "vasi_engine"."document_artifact" p on p."id" = t."artifactId" where p."tenantId" = $1`, 't."artifactId", t."sequence"'),
  direct("workflow_artifact_binding", '"tenantId"', '"workflowRevisionId", "activityId", "artifactId"'),
  direct("external_media_descriptor", '"tenantId"', '"boundAt", "id"'),
  direct("request_instance", '"tenantId"', '"issuedAt", "id"'),
  direct("participant_assignment", '"tenantId"', '"issuedAt", "id"'),
  dependent("interaction_session", `join "vasi_engine"."participant_assignment" p on p."id" = t."assignmentId" where p."tenantId" = $1`, 't."startedAt", t."id"'),
  direct("activity_instance", '"tenantId"', '"ordinal", "id"'),
  direct("participant_context_snapshot", '"tenantId"', '"receivedAt", "id"'),
  direct("activity_interaction_event_batch", '"tenantId"', '"receivedAt", "id"'),
  direct("activity_interaction_event", '"tenantId"', '"receivedAt", "batchId", "sequence", "id"'),
  direct("activity_interaction_summary_revision", '"tenantId"', '"calculatedAt", "revision", "id"'),
  dependent("participant_response", `join "vasi_engine"."participant_assignment" p on p."id" = t."assignmentId" where p."tenantId" = $1`, 't."respondedAt", t."id"'),
  direct("activity_response_revision", '"tenantId"', '"recordedAt", "revision", "id"'),
  direct("activity_response", '"tenantId"', '"respondedAt", "id"'),
  direct("external_media_metadata_snapshot", '"tenantId"', '"capturedAt", "id"'),
  direct("media_event_batch", '"tenantId"', '"receivedAt", "id"'),
  direct("media_event", '"tenantId"', '"receivedAt", "batchId", "sequence", "id"'),
  direct("media_activity_summary_revision", '"tenantId"', '"calculatedAt", "revision", "id"'),
  dependent("evidence_chain_head", `join "vasi_engine"."participant_assignment" p on p."id" = t."assignmentId" where p."tenantId" = $1`, 't."assignmentId"'),
  direct("evidence_event", '"tenantId"', '"assignmentId", "sequence"'),
  direct("evidence_manifest", '"tenantId"', '"createdAt", "id"'),
  dependent("evidence_seal", `join "vasi_engine"."evidence_manifest" p on p."id" = t."manifestId" where p."tenantId" = $1`, 't."createdAt", t."id"'),
  direct("outbox_job", '"tenantId"', '"createdAt", "id"'),
  dependent("notification_delivery_attempt", `join "vasi_engine"."outbox_job" p on p."id" = t."jobId" where p."tenantId" = $1`, 't."startedAt", t."attempt", t."id"'),
  direct("request_lifecycle_event", '"tenantId"', '"createdAt", "id"'),
  direct("document_artifact_access_event", '"tenantId"', '"createdAt", "id"'),
  direct("evidence_export_artifact", '"tenantId"', '"createdAt", "id"'),
  dependent("evidence_export_chunk", `join "vasi_engine"."evidence_export_artifact" p on p."id" = t."exportArtifactId" where p."tenantId" = $1`, 't."exportArtifactId", t."sequence"'),
  direct("evidence_access_event", '"tenantId"', '"createdAt", "id"'),
  direct("record_lifecycle_state", '"tenantId"', '"assignmentId"'),
  dependent("record_lifecycle_chain_head", `join "vasi_engine"."participant_assignment" p on p."id" = t."assignmentId" where p."tenantId" = $1`, 't."assignmentId"'),
  direct("record_lifecycle_event", '"tenantId"', '"assignmentId", "sequence"'),
  direct("legal_hold", '"tenantId"', '"placedAt", "id"'),
  dependent("legal_hold_release", `join "vasi_engine"."legal_hold" p on p."id" = t."holdId" where p."tenantId" = $1`, 't."releasedAt", t."id"'),
  direct("retention_purge_tombstone", '"tenantId"', '"purgedAt", "assignmentId"'),
  custom("product_configuration_chain_head", `where (t."scopeType" = 'tenant' and t."scopeId" = $1) or (t."scopeType" = 'integration' and t."scopeId" like $1 || ':%')`, 't."scopeType", t."scopeId"'),
  direct("product_configuration_event", '"tenantId"', '"createdAt", "scopeType", "scopeId", "sequence"'),
  direct("integration_binding_revision", '"tenantId"', '"capability", "revision"'),
  direct("integration_binding_pointer", '"tenantId"', '"capability"'),
  direct("document_artifact_scan_attempt", '"tenantId"', '"startedAt", "id"'),
  direct("integration_gateway_attempt", '"tenantId"', '"startedAt", "attempt", "id"'),
]);

try {
  const { command, first, passphraseFile, second } = parseArguments(process.argv.slice(2));
  if (command === "export") await exportTenant(first, second, passphraseFile);
  else if (command === "import") await importTenant(first, second, passphraseFile);
  else usage();
} catch (error) {
  console.error(error instanceof Error ? error.message : "Tenant transfer failed.");
  process.exitCode = 1;
}

async function exportTenant(tenantId, destination, passphraseFile) {
  requiredToken(tenantId, "tenant ID");
  if (!destination) throw new Error("An archive directory is required.");
  const target = path.resolve(destination);
  await assertMissing(target);
  const passphrase = passphraseFile
    ? await readPassphraseFile(passphraseFile)
    : await confirmedPassphrase();
  const bootstrap = loadBootstrapSettings();
  const settings = await readRuntimeSettings({ bootstrap, scope: "engine" });
  const database = createSettingsPool(bootstrap);
  const temporary = `${target}.partial-${randomUUID()}`;
  await mkdir(temporary, { mode: 0o700, recursive: false });
  let client;
  try {
    client = await database.connect();
    await client.query("begin isolation level repeatable read read only");
    const tenant = await client.query(`select "id" from "vasi_engine"."tenant" where "id" = $1`, [tenantId]);
    if (!tenant.rowCount) throw new Error("The tenant does not exist.");
    await assertTransferReady(client, tenantId);
    const migrations = await migrationLedger(client);
    const salt = randomBytes(16);
    const masterKey = deriveKey(passphrase, salt);
    const manifest = {
      createdAt: new Date().toISOString(),
      migrations,
      salt: salt.toString("base64url"),
      schema: ARCHIVE_SCHEMA,
      sourceInstallationFingerprint: sha256Hex(bootstrap.installationId),
      tables: [],
      tenantFingerprint: sha256Hex(tenantId),
    };
    for (const [index, specification] of TABLES.entries()) {
      const filename = `${String(index + 1).padStart(3, "0")}-${specification.table}.bin`;
      const metadata = await exportTable({
        database: client,
        filename,
        masterKey,
        outputPath: path.join(temporary, filename),
        settings,
        specification,
        tenantId,
      });
      manifest.tables.push(metadata);
    }
    const manifestHmac = createHmac("sha256", masterKey).update(canonicalJSON(manifest)).digest("base64url");
    await writeFile(path.join(temporary, "manifest.json"), `${JSON.stringify({ ...manifest, manifestHmac }, null, 2)}\n`, { mode: 0o600 });
    await client.query("commit");
    await rename(temporary, target);
    console.info(`Encrypted tenant archive created with ${manifest.tables.reduce((sum, table) => sum + table.rows, 0)} rows.`);
  } catch (error) {
    await client?.query("rollback").catch(() => undefined);
    await rm(temporary, { force: true, recursive: true }).catch(() => undefined);
    throw error;
  } finally {
    client?.release();
    await database.end();
  }
}

async function importTenant(source, ownerEmail, passphraseFile) {
  if (!source) throw new Error("An archive directory is required.");
  const normalizedOwnerEmail = requiredEmail(ownerEmail);
  const directory = path.resolve(source);
  const manifest = JSON.parse(await readFile(path.join(directory, "manifest.json"), "utf8"));
  if (manifest.schema !== ARCHIVE_SCHEMA || !Array.isArray(manifest.tables)) throw new Error("The tenant archive manifest is unsupported.");
  const passphrase = passphraseFile
    ? await readPassphraseFile(passphraseFile)
    : await hiddenQuestion("Archive passphrase: ");
  const masterKey = deriveKey(passphrase, Buffer.from(manifest.salt, "base64url"));
  const { manifestHmac, ...unsigned } = manifest;
  const expectedHmac = createHmac("sha256", masterKey).update(canonicalJSON(unsigned)).digest();
  const suppliedHmac = Buffer.from(String(manifestHmac || ""), "base64url");
  if (expectedHmac.length !== suppliedHmac.length || !timingSafeEqual(expectedHmac, suppliedHmac)) {
    throw new Error("The archive passphrase or manifest authentication is invalid.");
  }
  const bootstrap = loadBootstrapSettings();
  const settings = await readRuntimeSettings({ bootstrap, scope: "engine" });
  const database = createSettingsPool(bootstrap);
  try {
    await assertMigrationCompatibility(database, manifest.migrations);
    const adapters = await database.query(`select count(*)::integer as "count" from "vasi_engine"."integration_adapter_registry" where "conformanceStatus" = 'built_in_verified'`);
    if (Number(adapters.rows[0].count) < 3) {
      throw new Error("Start the destination engine once before import so its verified adapter registry is initialized.");
    }
    const tenantMetadata = tableMetadata(manifest, "tenant");
    const tenantRows = await collectRows(directory, tenantMetadata, masterKey, settings);
    if (tenantRows.length !== 1) throw new Error("The archive tenant root is invalid.");
    const tenantId = requiredToken(tenantRows[0].id, "archived tenant ID");
    if (sha256Hex(tenantId) !== manifest.tenantFingerprint) throw new Error("The archive tenant fingerprint is invalid.");
    const conflicts = await database.query(
      `select 1 from "vasi_engine"."tenant" where "id" = $1 or "slug" = $2`,
      [tenantId, tenantRows[0].slug],
    );
    if (conflicts.rowCount) throw new Error("The destination already contains this tenant ID or slug.");
    const client = await database.connect();
    try {
      await client.query("begin");
      await client.query("set local vasi.tenant_import = 'on'");
      await insertRows(client, "tenant", tenantRows);
      for (const metadata of manifest.tables) {
        if (metadata.table === "tenant") continue;
        let batch = [];
        for await (const row of encryptedRows(directory, metadata, masterKey)) {
          batch.push(importTransform(metadata.table, row, settings));
          if (batch.length >= PAGE_SIZE) {
            await insertRows(client, metadata.table, batch);
            batch = [];
          }
        }
        if (batch.length) await insertRows(client, metadata.table, batch);
      }
      await client.query(
        `insert into "vasi_engine"."tenant_membership_grant"
          ("id", "tenantId", "email", "roles", "status", "createdByPrincipalId")
         values ($1, $2, $3, '{owner}', 'active', 'vasi-tenant-import')
         on conflict ("tenantId", "email") do update
           set "roles" = '{owner}', "status" = 'active', "updatedAt" = CURRENT_TIMESTAMP`,
        [randomUUID(), tenantId, normalizedOwnerEmail],
      );
      await client.query("commit");
      console.info("Tenant archive imported and an owner email grant was created.");
    } catch (error) {
      await client.query("rollback").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  } finally {
    await database.end();
  }
}

async function exportTable({ database, filename, masterKey, outputPath, settings, specification, tenantId }) {
  const iv = randomBytes(12);
  const key = tableKey(masterKey, specification.table);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const output = createWriteStream(outputPath, { flags: "wx", mode: 0o600 });
  const digest = createHash("sha256");
  cipher.on("data", (chunk) => digest.update(chunk));
  cipher.pipe(output);
  let offset = 0;
  let rows = 0;
  while (true) {
    const result = await database.query(`${specification.query} limit $2 offset $3`, [tenantId, PAGE_SIZE, offset]);
    if (!result.rowCount) break;
    for (const selected of result.rows) {
      const row = exportTransform(specification.table, selected.row, settings);
      if (!cipher.write(`${JSON.stringify(row)}\n`)) await new Promise((resolve) => cipher.once("drain", resolve));
      rows += 1;
    }
    offset += result.rowCount;
  }
  cipher.end();
  await finished(output);
  await chmod(outputPath, 0o600);
  return {
    ciphertextSha256: digest.digest("hex"),
    filename,
    iv: iv.toString("base64url"),
    rows,
    table: specification.table,
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

async function* encryptedRows(directory, metadata, masterKey) {
  const sourcePath = safeArchivePath(directory, metadata.filename);
  if (await hashFile(sourcePath) !== metadata.ciphertextSha256) throw new Error(`Archive table ${metadata.table} failed its ciphertext checksum.`);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    tableKey(masterKey, metadata.table),
    Buffer.from(metadata.iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(metadata.tag, "base64url"));
  const input = createReadStream(sourcePath);
  const lines = createInterface({ input: input.pipe(decipher), crlfDelay: Infinity });
  let count = 0;
  try {
    for await (const line of lines) {
      if (!line) continue;
      count += 1;
      yield JSON.parse(line);
    }
    await finished(decipher);
  } catch {
    throw new Error(`Archive table ${metadata.table} could not be authenticated.`);
  }
  if (count !== metadata.rows) throw new Error(`Archive table ${metadata.table} row count is invalid.`);
}

async function collectRows(directory, metadata, masterKey, settings) {
  const rows = [];
  for await (const row of encryptedRows(directory, metadata, masterKey)) rows.push(importTransform(metadata.table, row, settings));
  return rows;
}

function exportTransform(table, row, settings) {
  if (table !== "integration_binding_revision") return row;
  const credentials = decryptJSONEnvelope(row.credentialEnvelope, settings.ENGINE_INTEGRATION_CONFIG_ENCRYPTION_SECRET);
  return { ...row, credentialEnvelope: null, transferCredentials: credentials };
}

function importTransform(table, row, settings) {
  if (table !== "integration_binding_revision") return row;
  const { transferCredentials, ...record } = row;
  return {
    ...record,
    credentialEnvelope: encryptJSONEnvelope(transferCredentials, settings.ENGINE_INTEGRATION_CONFIG_ENCRYPTION_SECRET),
  };
}

async function insertRows(client, table, rows) {
  if (!rows.length) return;
  if (!TABLES.some((entry) => entry.table === table)) throw new Error("The archive contains an unsupported table.");
  await client.query(
    `insert into "vasi_engine"."${table}"
     select * from jsonb_populate_recordset(null::"vasi_engine"."${table}", $1::jsonb)`,
    [JSON.stringify(rows)],
  );
}

async function assertTransferReady(database, tenantId) {
  const [dataRequests, jobs] = await Promise.all([
    database.query(`select 1 from "vasi_engine"."participant_data_request_scope" where "tenantId" = $1 limit 1`, [tenantId]),
    database.query(`select 1 from "vasi_engine"."outbox_job" where "tenantId" = $1 and "status" in ('pending', 'running') limit 1`, [tenantId]),
  ]);
  if (dataRequests.rowCount) throw new Error("Complete or expire participant data-request scopes before tenant transfer.");
  if (jobs.rowCount) throw new Error("Drain pending and running tenant outbox jobs before tenant transfer.");
}

async function migrationLedger(database) {
  const result = await database.query(`select "name", "checksum" from public."_vasi_engine_migrations" order by "name"`);
  return result.rows;
}

async function assertMigrationCompatibility(database, sourceMigrations) {
  const target = new Map((await migrationLedger(database)).map((entry) => [entry.name, entry.checksum]));
  for (const migration of sourceMigrations || []) {
    if (target.get(migration.name) !== migration.checksum) {
      throw new Error(`Destination migration ${migration.name} is missing or incompatible.`);
    }
  }
}

function direct(table, tenantColumn, order) {
  return { table, query: `select to_jsonb(t) as "row" from "vasi_engine"."${table}" t where t.${tenantColumn} = $1 order by t.${order}` };
}

function dependent(table, join, order) {
  return { table, query: `select to_jsonb(t) as "row" from "vasi_engine"."${table}" t ${join} order by ${order}` };
}

function custom(table, where, order) {
  return { table, query: `select to_jsonb(t) as "row" from "vasi_engine"."${table}" t ${where} order by ${order}` };
}

function tableMetadata(manifest, table) {
  const metadata = manifest.tables.find((entry) => entry.table === table);
  if (!metadata) throw new Error(`The archive is missing ${table}.`);
  return metadata;
}

function tableKey(masterKey, table) {
  return createHmac("sha256", masterKey).update(`vasi-tenant-table:${table}`).digest();
}

function deriveKey(passphrase, salt) {
  if (typeof passphrase !== "string" || passphrase.length < 16) throw new Error("The archive passphrase must contain at least 16 characters.");
  return scryptSync(passphrase, salt, 32, { N: 65_536, maxmem: 128 * 1024 * 1024, p: 1, r: 8 });
}

async function hashFile(filePath) {
  const digest = createHash("sha256");
  const input = createReadStream(filePath);
  for await (const chunk of input) digest.update(chunk);
  return digest.digest("hex");
}

function safeArchivePath(directory, filename) {
  if (typeof filename !== "string" || !/^\d{3}-[a-z0-9_]+\.bin$/.test(filename)) throw new Error("The archive filename is invalid.");
  return path.join(directory, filename);
}

async function assertMissing(target) {
  try {
    await stat(target);
    throw new Error("The archive destination already exists.");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  await mkdir(path.dirname(target), { recursive: true });
}

async function confirmedPassphrase() {
  const first = await hiddenQuestion("New archive passphrase: ");
  const second = await hiddenQuestion("Confirm archive passphrase: ");
  if (first !== second) throw new Error("Archive passphrases do not match.");
  return first;
}

async function readPassphraseFile(source) {
  const filePath = path.resolve(source);
  const metadata = await stat(filePath);
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) {
    throw new Error("The archive passphrase file must be a regular file with mode 0600 or stricter.");
  }
  const value = (await readFile(filePath, "utf8")).replace(/\r?\n$/, "");
  if (value.length < 16) throw new Error("The archive passphrase must contain at least 16 characters.");
  return value;
}

async function hiddenQuestion(prompt) {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) throw new Error("A terminal is required for hidden archive passphrase input.");
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");
  return new Promise((resolve, reject) => {
    let value = "";
    const finish = () => {
      process.stdin.off("data", onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write("\n");
    };
    const onData = (character) => {
      if (character === "\u0003") { finish(); reject(new Error("Input cancelled.")); }
      else if (character === "\r" || character === "\n") { finish(); resolve(value); }
      else if (character === "\u007f" || character === "\b") value = value.slice(0, -1);
      else if (character >= " ") value += character;
    };
    process.stdin.on("data", onData);
  });
}

function requiredEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+$/.test(email) || email.length > 320) {
    throw new Error("Import requires a destination owner email as its second argument.");
  }
  return email;
}

function requiredToken(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._:-]{1,512}$/.test(value)) throw new Error(`The ${name} is invalid.`);
  return value;
}

function parseArguments(argumentsList) {
  const args = [...argumentsList];
  let passphraseFile;
  const option = args.indexOf("--passphrase-file");
  if (option >= 0) {
    passphraseFile = args[option + 1];
    if (!passphraseFile || args.indexOf("--passphrase-file", option + 1) >= 0) {
      throw new Error("The --passphrase-file option is invalid.");
    }
    args.splice(option, 2);
  }
  if (args.length > 3 || args.some((entry) => entry.startsWith("--"))) {
    throw new Error("The tenant transfer arguments are invalid.");
  }
  const [command, first, second] = args;
  return { command, first, passphraseFile, second };
}

function usage() {
  console.info(`VASI encrypted tenant transfer:
  node scripts/tenant-transfer.mjs export TENANT_ID ARCHIVE_DIRECTORY [--passphrase-file FILE]
  node scripts/tenant-transfer.mjs import ARCHIVE_DIRECTORY DESTINATION_OWNER_EMAIL [--passphrase-file FILE]`);
  process.exitCode = 1;
}
