"use client";

import { useState, type FormEvent } from "react";

type VerificationResult = {
  completedAt?: string;
  error?: string;
  eventCount?: number;
  fingerprint?: string;
  known?: boolean;
  seals?: Array<{ algorithm: string; keyId: string; profile: string; role: string; verified: boolean }>;
  verified?: boolean;
};

export function EvidenceVerifier({ initialFingerprint = "" }: { initialFingerprint?: string }) {
  const [fingerprint, setFingerprint] = useState(
    /^[a-f0-9]{64}$/.test(initialFingerprint) ? initialFingerprint : "",
  );
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<VerificationResult>();

  async function verify(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setResult(undefined);
    try {
      const response = await fetch("/api/verify", {
        body: JSON.stringify({ fingerprint }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      const body = await response.json() as VerificationResult;
      setResult(response.ok ? body : { error: body.error || "Verification failed." });
    } catch {
      setResult({ error: "Verification is temporarily unavailable." });
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="verification-card">
      <p className="eyebrow">INDEPENDENT RECORD CHECK</p>
      <h1>Verify VASI evidence</h1>
      <p>Enter the 64-character manifest fingerprint shown on a VASI receipt or report. The lookup reveals no participant identity, answers, document content, or requesting company.</p>
      <form onSubmit={verify}>
        <label htmlFor="manifest-fingerprint">Manifest fingerprint</label>
        <textarea
          autoCapitalize="none"
          autoComplete="off"
          id="manifest-fingerprint"
          maxLength={64}
          minLength={64}
          onChange={(event) => setFingerprint(event.target.value.replace(/\s/g, "").toLowerCase())}
          placeholder="64-character SHA-256 fingerprint"
          required
          rows={3}
          spellCheck={false}
          value={fingerprint}
        />
        <button className="button button--primary" disabled={pending || fingerprint.length !== 64} type="submit">
          {pending ? "Verifying…" : "Verify fingerprint"}
        </button>
      </form>
      {result?.error && <p className="verification-result verification-result--error" role="alert">{result.error}</p>}
      {result && !result.error && !result.known && (
        <section className="verification-result verification-result--unknown" aria-live="polite">
          <h2>No matching record</h2>
          <p>VASI does not recognize that exact fingerprint. Check every character against the source receipt or report.</p>
        </section>
      )}
      {result?.known && (
        <section className="verification-result verification-result--verified" aria-live="polite">
          <h2>{result.verified ? "Record integrity verified" : "Record verification failed"}</h2>
          <dl>
            <div><dt>Fingerprint</dt><dd>{result.fingerprint}</dd></div>
            <div><dt>Completed</dt><dd>{result.completedAt ? new Date(result.completedAt).toLocaleString() : "Recorded"}</dd></div>
            <div><dt>Evidence events</dt><dd>{result.eventCount}</dd></div>
          </dl>
          {result.seals?.map((seal) => (
            <p key={`${seal.role}:${seal.keyId}`}><strong>{seal.role.replaceAll("_", " ")}</strong> · {seal.algorithm} · {seal.verified ? "valid" : "invalid"}</p>
          ))}
        </section>
      )}
    </section>
  );
}
