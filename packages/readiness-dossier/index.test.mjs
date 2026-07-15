import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
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
    const html = { ...createReadinessExportFixture("html"), dossier: json.dossier, dossierHash: json.dossierHash };
    const jsonResult = verifyReadinessDossierBytes(Buffer.from(readinessExportJSON(json)));
    const htmlResult = verifyReadinessDossierBytes(Buffer.from(renderReadinessDossierHTML(html)), {
      expectedDigest: json.dossierHash,
    });

    expect(validateReadinessExport(json)).toBe(json);
    expect(jsonResult).toEqual({
      dossierSha256: json.dossierHash,
      expectedDigest: "not_supplied",
      format: "json",
      presentation: "not_applicable",
      schema: "vasi-readiness-dossier-verification/v1",
      status: "pass",
    });
    expect(htmlResult).toMatchObject({
      dossierSha256: json.dossierHash,
      expectedDigest: "matched",
      format: "html",
      presentation: "exact",
      status: "pass",
    });
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
