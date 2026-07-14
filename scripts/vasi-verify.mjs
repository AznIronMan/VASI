#!/usr/bin/env node

import { readFile, stat } from "node:fs/promises";

import {
  verifyEvidenceBundle,
  verifyEvidenceRecord,
} from "../packages/evidence-verifier/index.mjs";

const args = process.argv.slice(2);
const jsonOutput = args.includes("--json");
const path = args.find((argument) => argument !== "--json");

if (!path || args.some((argument) => argument.startsWith("-") && argument !== "--json")) {
  console.error("Usage: node scripts/vasi-verify.mjs [--json] <bundle.zip|record.json>");
  process.exitCode = 2;
} else {
  try {
    const metadata = await stat(path);
    if (!metadata.isFile() || metadata.size < 2 || metadata.size > 1_073_741_824) {
      throw new Error("The evidence input must be a file between 2 bytes and 1 GiB.");
    }
    const bytes = await readFile(path);
    const result = isZip(bytes)
      ? verifyEvidenceBundle(bytes)
      : verifyEvidenceRecord(JSON.parse(bytes.toString("utf8")));
    if (jsonOutput) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      printHumanResult(result, isZip(bytes));
    }
    if (!result.verified) process.exitCode = 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown verification failure.";
    if (jsonOutput) {
      process.stdout.write(`${JSON.stringify({ errors: [message], verified: false }, null, 2)}\n`);
    } else {
      console.error(`VASI verification failed: ${message}`);
    }
    process.exitCode = 1;
  }
}

function isZip(bytes) {
  return bytes.length >= 4 && bytes.readUInt32LE(0) === 0x04034b50;
}

function printHumanResult(result, bundle) {
  console.log(result.verified ? "VASI verification: VALID" : "VASI verification: INVALID");
  console.log(`Input: ${bundle ? "portable evidence bundle" : "evidence record"}`);
  if (bundle && result.index) {
    console.log(`Manifest fingerprint: ${result.index.sourceManifestHash}`);
    console.log(`Bundle root hash: ${result.index.rootHash}`);
    console.log(`Declared entries: ${result.index.entries?.length || 0}`);
  }
  for (const seal of result.seals || []) {
    console.log(`Seal ${seal.keyId || "unknown"}: ${seal.verified ? "valid" : "invalid"} (${seal.profile})`);
  }
  if (result.errors?.length) {
    console.log("Errors:");
    for (const error of result.errors) console.log(`- ${error}`);
  }
}
