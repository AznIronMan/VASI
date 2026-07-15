import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  MAXIMUM_READINESS_DOSSIER_BYTES,
  readinessExportJSON,
  ReadinessDossierVerificationError,
  renderReadinessDossierHTML,
  validateReadinessExport,
  verifyReadinessDossierBytes,
  verifyReadinessDossierFile,
} from "./index.mjs";
import { createReadinessExportFixture } from "./test-fixture.mjs";

const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })
  ));
});

describe("offline pilot-readiness dossier verification", () => {
  it("verifies authoritative JSON and exact script-free HTML with one digest", () => {
    const json = createReadinessExportFixture("json");
    const html = createReadinessExportFixture("html");
    const jsonResult = verifyReadinessDossierBytes(Buffer.from(readinessExportJSON(json)), {
      expectedDigest: json.dossierHash,
      expectedKeyFingerprint: json.attestation.signingKeys[0].fingerprint,
    });
    const htmlResult = verifyReadinessDossierBytes(Buffer.from(renderReadinessDossierHTML(html)), {
      expectedDigest: html.dossierHash,
      expectedKeyFingerprint: html.attestation.signingKeys[0].fingerprint,
    });

    expect(validateReadinessExport(json)).toBe(json);
    expect(jsonResult).toEqual({
      certificateSeal: "not_present",
      dossierSha256: json.dossierHash,
      expectedDigest: "matched",
      expectedKeyFingerprint: "matched",
      format: "json",
      integrityKeyFingerprint: json.attestation.signingKeys[0].fingerprint,
      integritySeal: "verified",
      presentation: "not_applicable",
      schema: "vasi-readiness-dossier-verification/v2",
      status: "pass",
    });
    expect(htmlResult).toMatchObject({
      dossierSha256: html.dossierHash,
      expectedDigest: "matched",
      expectedKeyFingerprint: "matched",
      format: "html",
      integritySeal: "verified",
      presentation: "exact",
      status: "pass",
    });
  });

  it("preserves exact 0.47.0 exports as explicitly unsigned legacy evidence", () => {
    const legacyJSON = createReadinessExportFixture("json", { legacy: true });
    const legacyHTML = createReadinessExportFixture("html", { legacy: true });
    expect(verifyReadinessDossierBytes(Buffer.from(readinessExportJSON(legacyJSON)))).toMatchObject({
      certificateSeal: "not_present",
      integrityKeyFingerprint: null,
      integritySeal: "not_present",
      schema: "vasi-readiness-dossier-verification/v2",
      status: "pass",
    });
    const rendered = renderReadinessDossierHTML(legacyHTML);
    expect(createHash("sha256").update(rendered).digest("hex"))
      .toBe("3d2476682bd8f2dcf1e723b9eb1b8167fd670dfb378322c2d6f95eeffa2f55d5");
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(rendered), {
      expectedKeyFingerprint: "0".repeat(64),
    }));
  });

  it("rejects covered-data, declared-hash, wrapper, and readiness inconsistencies", () => {
    const exported = createReadinessExportFixture("json");
    const tampered = structuredClone(exported);
    tampered.dossier.tenant.name = "Changed Company";
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(`${JSON.stringify(tampered, null, 2)}\n`)));

    const unknown = structuredClone(exported);
    unknown.dossier.unexpected = true;
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(`${JSON.stringify(unknown, null, 2)}\n`)));

    const inconsistent = structuredClone(exported);
    inconsistent.dossier.readiness.pendingGateIds = [];
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(`${JSON.stringify(inconsistent, null, 2)}\n`)));

    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(readinessExportJSON(exported)), {
      expectedDigest: "0".repeat(64),
    }));
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(readinessExportJSON(exported)), {
      expectedKeyFingerprint: "0".repeat(64),
    }));
  });

  it("rejects attestation, signature, signing-key, event, and seal-role tampering", () => {
    const exported = createReadinessExportFixture("json");
    for (const mutate of [
      (value) => { value.attestation.capturedAt = "2026-07-15T20:00:01.000Z"; },
      (value) => { value.attestation.signingKeys[0].fingerprint = "0".repeat(64); },
      (value) => { value.seals[0].role = "certificate"; },
      (value) => {
        value.seals[0].signature = `${value.seals[0].signature.startsWith("A") ? "B" : "A"}${
          value.seals[0].signature.slice(1)
        }`;
      },
      (value) => {
        value.auditEventHash = "0".repeat(64);
        value.attestation.auditEventHash = value.auditEventHash;
      },
    ]) {
      const tampered = structuredClone(exported);
      mutate(tampered);
      expectFailure(() => verifyReadinessDossierBytes(
        Buffer.from(`${JSON.stringify(tampered, null, 2)}\n`),
      ));
    }
  });

  it("verifies an optional certificate leaf seal and binds its exact public metadata", async () => {
    const temporary = await mkdtemp(path.join(tmpdir(), "vasi-readiness-certificate-"));
    temporaryDirectories.push(temporary);
    const certificateFile = path.join(temporary, "certificate.pem");
    const privateKeyFile = path.join(temporary, "private-key.pem");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ed25519", "-keyout", privateKeyFile,
      "-out", certificateFile, "-nodes", "-subj", "/CN=VASI Readiness Test", "-days", "1",
    ], { stdio: "ignore" });
    const exported = createReadinessExportFixture("json", {
      certificateChainPEM: await readFile(certificateFile, "utf8"),
      certificatePrivateKeyPEM: await readFile(privateKeyFile, "utf8"),
    });
    const result = verifyReadinessDossierBytes(Buffer.from(readinessExportJSON(exported)));
    expect(result).toMatchObject({ certificateSeal: "verified", integritySeal: "verified", status: "pass" });
    expect(JSON.stringify(result)).not.toContain("VASI Readiness Test");

    for (const mutate of [
      (value) => { value.seals[1].certificate.subject = "CN=Changed"; },
      (value) => { value.seals[1].publicJWK.x = `${value.seals[1].publicJWK.x.slice(0, -1)}A`; },
    ]) {
      const tampered = structuredClone(exported);
      mutate(tampered);
      expectFailure(() => verifyReadinessDossierBytes(
        Buffer.from(`${JSON.stringify(tampered, null, 2)}\n`),
      ));
    }
  });

  it("rejects presentation edits, executable additions, duplicate embeddings, and noncanonical JSON", () => {
    const exported = createReadinessExportFixture("html");
    const html = renderReadinessDossierHTML(exported);
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(
      html.replace("A privacy-bounded technical snapshot", "A certified technical snapshot"),
    )));
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(
      html.replace("</body>", "<script>alert(1)</script></body>"),
    )));
    const embedding = html.match(/<script type="application\/json" id="vasi-readiness-export">[^<]*<\/script>/)?.[0];
    expect(embedding).toBeTruthy();
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(html.replace("</body>", `${embedding}</body>`))));

    const json = readinessExportJSON(createReadinessExportFixture("json"));
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from(json.replace(/^\{\n/, "{\r\n"))));
  });

  it("bounds bytes and requires one physical regular UTF-8 file", async () => {
    expectFailure(() => verifyReadinessDossierBytes(Buffer.alloc(MAXIMUM_READINESS_DOSSIER_BYTES + 1)));
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from([0xff])));
    expectFailure(() => verifyReadinessDossierBytes(Buffer.from("{\0}")));

    const temporary = await mkdtemp(path.join(tmpdir(), "vasi-readiness-verifier-"));
    temporaryDirectories.push(temporary);
    const file = path.join(temporary, "dossier.json");
    const link = path.join(temporary, "dossier-link.json");
    const exported = createReadinessExportFixture("json");
    await writeFile(file, readinessExportJSON(exported), { mode: 0o600 });
    await symlink(file, link);

    await expect(verifyReadinessDossierFile(file)).resolves.toMatchObject({
      dossierSha256: exported.dossierHash,
      status: "pass",
    });
    await expect(verifyReadinessDossierFile(link)).rejects.toBeInstanceOf(ReadinessDossierVerificationError);
    await expect(verifyReadinessDossierFile(path.join(temporary, "missing")))
      .rejects.toBeInstanceOf(ReadinessDossierVerificationError);
  });
});

function expectFailure(operation) {
  expect(operation).toThrow(ReadinessDossierVerificationError);
}
