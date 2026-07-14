import { describe, expect, it } from "vitest";

import {
  normalizedMediaType,
  validateArtifactChunkInput,
  validateArtifactCreateInput,
} from "./artifacts.mjs";

const limits = { chunkBytes: 262_144, maxBytes: 26_214_400, maxChunks: 100 };

describe("document artifact contracts", () => {
  it("accepts a bounded PostgreSQL source artifact", () => {
    expect(validateArtifactCreateInput({
      expectedByteLength: 12,
      mediaType: "application/pdf; charset=binary",
      originalFilename: "policy.pdf",
      tenantId: "tenant-one",
    }, limits)).toMatchObject({
      mediaType: "application/pdf",
      originalFilename: "policy.pdf",
      role: "source_document",
    });
  });

  it("rejects media, executable, path, and oversize inputs", () => {
    expect(() => normalizedMediaType("video/mp4")).toThrow(/unsupported/);
    expect(() => normalizedMediaType("text/html")).toThrow(/unsupported/);
    expect(() => validateArtifactCreateInput({
      expectedByteLength: 1,
      mediaType: "text/plain",
      originalFilename: "../secret.txt",
      tenantId: "tenant-one",
    }, limits)).toThrow(/filename/);
    expect(() => validateArtifactCreateInput({
      expectedByteLength: limits.maxBytes + 1,
      mediaType: "text/plain",
      originalFilename: "large.txt",
      tenantId: "tenant-one",
    }, limits)).toThrow(/whole number/);
  });

  it("accepts only canonical bounded base64 chunks", () => {
    expect(validateArtifactChunkInput({
      artifactId: "artifact-one",
      data: Buffer.from("bounded bytes").toString("base64"),
      sequence: 0,
      tenantId: "tenant-one",
    }, limits).sequence).toBe(0);
    expect(() => validateArtifactChunkInput({
      artifactId: "artifact-one",
      data: "***",
      sequence: 0,
      tenantId: "tenant-one",
    }, limits)).toThrow(/encoding/);
  });
});
