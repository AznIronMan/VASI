import { describe, expect, it } from "vitest";

import { createDocumentInspector } from "./document-inspection.mjs";

describe("bounded document inspection", () => {
  it("validates PDF signatures across bounded chunks", () => {
    const inspector = createDocumentInspector("application/pdf");
    inspector.update(Buffer.from("%PD"));
    inspector.update(Buffer.from("F-1.7\nbody"));
    expect(inspector.finalize()).toMatchObject({ contentValidation: "passed", passed: true });
  });

  it("rejects a type mismatch", () => {
    const inspector = createDocumentInspector("application/pdf");
    inspector.update(Buffer.from("plain text"));
    expect(inspector.finalize()).toMatchObject({ passed: false, rejectionCode: "pdf_signature_mismatch" });
  });

  it("detects the EICAR test marker even when split between chunks", () => {
    const inspector = createDocumentInspector("text/plain");
    inspector.update(Buffer.from("EICAR-STANDARD-ANTI"));
    inspector.update(Buffer.from("VIRUS-TEST-FILE"));
    expect(inspector.finalize()).toMatchObject({ passed: false, rejectionCode: "malware_test_signature_detected" });
  });
});
