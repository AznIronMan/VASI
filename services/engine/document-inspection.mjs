const EICAR_MARKER = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE";
const TEXT_MEDIA_TYPES = new Set([
  "application/json",
  "application/xml",
  "text/csv",
  "text/markdown",
  "text/plain",
]);
const ZIP_MEDIA_TYPES = new Set([
  "application/vnd.oasis.opendocument.presentation",
  "application/vnd.oasis.opendocument.spreadsheet",
  "application/vnd.oasis.opendocument.text",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
]);

export function createDocumentInspector(mediaType) {
  let prefix = Buffer.alloc(0);
  let signatureTail = "";
  let containsEicar = false;
  let containsNul = false;
  let utf8Valid = true;
  const decoder = TEXT_MEDIA_TYPES.has(mediaType) ? new TextDecoder("utf-8", { fatal: true }) : undefined;

  return Object.freeze({
    update(chunk) {
      if (!Buffer.isBuffer(chunk) || !chunk.length) throw new Error("A non-empty document chunk is required.");
      if (prefix.length < 8_192) prefix = Buffer.concat([prefix, chunk.subarray(0, 8_192 - prefix.length)]);
      const signatureWindow = signatureTail + chunk.toString("latin1");
      if (signatureWindow.includes(EICAR_MARKER)) containsEicar = true;
      signatureTail = signatureWindow.slice(-128);
      if (TEXT_MEDIA_TYPES.has(mediaType)) {
        if (chunk.includes(0)) containsNul = true;
        try {
          decoder.decode(chunk, { stream: true });
        } catch {
          utf8Valid = false;
        }
      }
    },
    finalize() {
      if (decoder) {
        try {
          decoder.decode();
        } catch {
          utf8Valid = false;
        }
      }
      const contentValidation = validateContent(mediaType, prefix, { containsNul, utf8Valid });
      const malwareStatus = containsEicar ? "test_signature_detected" : "no_test_signature_detected";
      const passed = !containsEicar && contentValidation === "passed";
      return Object.freeze({
        adapter: "vasi-bounded-document-inspector",
        adapterVersion: "1",
        contentValidation,
        limitation: "Built-in inspection validates bounded type signatures, UTF-8 where applicable, and the EICAR test marker; it is not a comprehensive antivirus signature service.",
        malwareSignatureProfile: "eicar-test-marker/v1",
        malwareStatus,
        passed,
        rejectionCode: containsEicar
          ? "malware_test_signature_detected"
          : contentValidation === "passed" ? undefined : contentValidation,
      });
    },
  });
}

function validateContent(mediaType, prefix, { containsNul, utf8Valid }) {
  if (mediaType === "application/pdf") {
    return prefix.subarray(0, 5).toString("ascii") === "%PDF-" ? "passed" : "pdf_signature_mismatch";
  }
  if (ZIP_MEDIA_TYPES.has(mediaType)) {
    const signature = prefix.subarray(0, 4);
    const zip = signature.equals(Buffer.from([0x50, 0x4b, 0x03, 0x04])) ||
      signature.equals(Buffer.from([0x50, 0x4b, 0x05, 0x06])) ||
      signature.equals(Buffer.from([0x50, 0x4b, 0x07, 0x08]));
    return zip ? "passed" : "zip_container_signature_mismatch";
  }
  if (TEXT_MEDIA_TYPES.has(mediaType)) {
    if (containsNul) return "text_contains_nul";
    if (!utf8Valid) return "invalid_utf8";
    const start = prefix.toString("utf8").replace(/^\uFEFF/, "").trimStart();
    if (mediaType === "application/json" && !["{", "["].includes(start[0])) return "json_shape_mismatch";
    if (mediaType === "application/xml" && start[0] !== "<") return "xml_shape_mismatch";
    return "passed";
  }
  return "unsupported_media_type";
}
