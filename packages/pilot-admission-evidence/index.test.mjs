import {
  chmod,
  link,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  PilotAdmissionEvidenceVerificationError,
  verifyPilotAdmissionEvidenceSet,
} from "./index.mjs";
import { createPilotAdmissionEvidenceFixture } from "./test-fixture.mjs";

const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })
  ));
});

describe("complete pilot-admission evidence verification", () => {
  it("binds exactly eight canonical manifests to signed JSON and HTML dossiers", async () => {
    for (const format of ["json", "html"]) {
      const fixture = await trackedFixture({ format });
      const result = await verifyPilotAdmissionEvidenceSet(
        fixture.dossierFile,
        fixture.manifestDirectory,
        {
          expectedDigest: fixture.exported.dossierHash,
          expectedKeyFingerprint: fixture.exported.attestation.signingKeys[0].fingerprint,
        },
      );
      expect(result).toEqual({
        admissionEvidence: "matched",
        artifactVerification: "not_performed",
        certificateSeal: "not_present",
        dossierSha256: fixture.exported.dossierHash,
        evidencePackages: 8,
        expectedDigest: "matched",
        expectedKeyFingerprint: "matched",
        format,
        integrityKeyFingerprint: fixture.exported.attestation.signingKeys[0].fingerprint,
        integritySeal: "verified",
        presentation: format === "html" ? "exact" : "not_applicable",
        schema: "vasi-pilot-admission-evidence-verification/v1",
        scopeBinding: "consistent",
        status: "pass",
        temporalBinding: "ordered",
      });
      const disclosed = JSON.stringify(result);
      expect(disclosed).not.toContain(fixture.exported.dossier.tenant.name);
      expect(disclosed).not.toContain(fixture.exported.dossier.tenant.id);
      expect(disclosed).not.toContain("review-package:");
      expect(disclosed).not.toContain("reviewer:");
      expect(disclosed).not.toContain("scope:pilot-001");
    }
  });

  it("rejects every signed dossier-to-manifest reference or digest mismatch", async () => {
    for (const mutate of [
      (evidence) => { evidence[0].evidenceDigest = "0".repeat(64); },
      (evidence) => { evidence[1].evidenceReference = "review-package:changed"; },
      (evidence) => { evidence[2].reviewerReference = "reviewer:changed"; },
    ]) {
      const fixture = await trackedFixture({ dossierEvidenceMutator: mutate });
      await expectFailure(fixture);
    }
  });

  it("rejects mixed review scopes and impossible review, decision, or capture ordering", async () => {
    const mixedScope = await trackedFixture({
      manifestOverrides: { accessibility: { scopeReference: "scope:other-pilot" } },
    });
    await expectFailure(mixedScope);

    const reviewAfterDecision = await trackedFixture({
      manifestOverrides: { exact_release: { reviewedAt: "2026-07-15T19:31:00.000Z" } },
    });
    await expectFailure(reviewAfterDecision);

    const decisionAfterRevision = await trackedFixture({
      decisionOverrides: { exact_release: "2026-07-15T19:50:00.000Z" },
    });
    await expectFailure(decisionAfterRevision);
  });

  it("requires a signed dossier whose immutable technical admission is complete", async () => {
    const pending = await trackedFixture({ admitted: false });
    await expectFailure(pending);

    const unsigned = await trackedFixture({ legacy: true });
    await expectFailure(unsigned);
  });

  it("rejects missing, extra, renamed, linked, or gate-substituted manifests", async () => {
    const extra = await trackedFixture();
    await writeFile(path.join(extra.manifestDirectory, "extra.json"), "{}\n", { mode: 0o600 });
    await expectFailure(extra);

    const missing = await trackedFixture();
    await rm(path.join(missing.manifestDirectory, "accessibility.json"));
    await expectFailure(missing);

    const linked = await trackedFixture();
    const manifest = path.join(linked.manifestDirectory, "exact_release.json");
    await link(manifest, path.join(linked.root, "second-link.json"));
    await expectFailure(linked);

    const substituted = await trackedFixture();
    await writeFile(
      path.join(substituted.manifestDirectory, "exact_release.json"),
      await readFile(path.join(substituted.manifestDirectory, "accessibility.json")),
      { mode: 0o600 },
    );
    await expectFailure(substituted);
  });

  it("requires private physical inputs and exact canonical UTF-8 presentation", async () => {
    const permissiveDirectory = await trackedFixture();
    await chmod(permissiveDirectory.manifestDirectory, 0o750);
    await expectFailure(permissiveDirectory);

    const permissiveDossier = await trackedFixture();
    await chmod(permissiveDossier.dossierFile, 0o640);
    await expectFailure(permissiveDossier);

    const linkedDossier = await trackedFixture();
    const dossierLink = path.join(linkedDossier.dossierDirectory, "linked.json");
    await symlink(linkedDossier.dossierFile, dossierLink);
    await expect(
      verifyPilotAdmissionEvidenceSet(dossierLink, linkedDossier.manifestDirectory),
    ).rejects.toBeInstanceOf(PilotAdmissionEvidenceVerificationError);

    const noncanonical = await trackedFixture();
    const manifestFile = path.join(noncanonical.manifestDirectory, "exact_release.json");
    await writeFile(
      manifestFile,
      (await readFile(manifestFile, "utf8")).replace("\n", "\r\n"),
      { mode: 0o600 },
    );
    await expectFailure(noncanonical);
  });

  it("uses one generic error type for nested dossier, manifest, and filesystem failures", async () => {
    const fixture = await trackedFixture();
    await expect(verifyPilotAdmissionEvidenceSet(
      fixture.dossierFile,
      fixture.manifestDirectory,
      { expectedKeyFingerprint: "0".repeat(64) },
    )).rejects.toMatchObject({
      message: "VASI pilot-admission evidence verification failed.",
      name: "PilotAdmissionEvidenceVerificationError",
    });
    await expect(
      verifyPilotAdmissionEvidenceSet("", fixture.manifestDirectory),
    ).rejects.toBeInstanceOf(PilotAdmissionEvidenceVerificationError);
    await expect(
      verifyPilotAdmissionEvidenceSet(fixture.dossierFile, `${fixture.manifestDirectory}\0changed`),
    ).rejects.toBeInstanceOf(PilotAdmissionEvidenceVerificationError);
  });
});

async function trackedFixture(options) {
  const fixture = await createPilotAdmissionEvidenceFixture(options);
  temporaryDirectories.push(fixture.root);
  return fixture;
}

async function expectFailure(fixture) {
  await expect(
    verifyPilotAdmissionEvidenceSet(fixture.dossierFile, fixture.manifestDirectory),
  ).rejects.toBeInstanceOf(PilotAdmissionEvidenceVerificationError);
}
