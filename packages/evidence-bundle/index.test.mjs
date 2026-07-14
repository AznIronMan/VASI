import { describe, expect, it } from "vitest";

import { createDetachedIntegritySeal, sha256Hex } from "../engine-crypto/index.mjs";
import { assertEvidenceBundle } from "../evidence-verifier/index.mjs";
import { sealedTestRecord } from "../evidence-verifier/test-fixture.mjs";
import { buildEvidenceBundle, parseStoredZip } from "./index.mjs";

describe("portable evidence bundles", () => {
  it("builds a deterministic, sealed, offline-verifiable ZIP with authoritative artifacts", () => {
    const { privateJWK, record } = sealedTestRecord();
    const artifactBytes = Buffer.from("exact document bytes", "utf8");
    const build = () => buildEvidenceBundle({
      artifacts: [{
        bytes: artifactBytes,
        id: "artifact-1",
        mediaType: "text/plain",
        originalFilename: "terms.txt",
        revision: 1,
        role: "source_document",
        sha256: sha256Hex(artifactBytes),
      }],
      record,
      signIndex(index) {
        return createDetachedIntegritySeal({
          keyId: "test-seal-key",
          payload: index,
          privateJWK,
          profile: "vasi-bundle-seal/v1",
        });
      },
    });
    const one = build();
    const two = build();
    expect(one.bytes.equals(two.bytes)).toBe(true);
    const entries = parseStoredZip(one.bytes);
    expect(entries.get("artifacts/artifact-1/terms.txt")).toEqual(artifactBytes);
    expect(entries.has("reports/nontechnical.html")).toBe(true);
    expect(assertEvidenceBundle(one.bytes).verified).toBe(true);

    const tampered = Buffer.from(one.bytes);
    tampered[80] ^= 1;
    expect(() => assertEvidenceBundle(tampered)).toThrow(/verification failed/);
  });
});
