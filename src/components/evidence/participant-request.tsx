"use client";

import { FormEvent, useRef, useState } from "react";

import type { OpenParticipantAssignment } from "@/lib/evidence-types";

export function ParticipantRequest({
  assignment,
  handle,
}: {
  assignment: OpenParticipantAssignment;
  handle: string;
}) {
  const clientStartedAt = useRef(new Date().toISOString());
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string>();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setPending(true);
    setMessage(undefined);
    try {
      const response = await fetch("/api/evidence/respond", {
        body: JSON.stringify({
          clientContext: {
            clientStartedAt: clientStartedAt.current,
            clientSubmittedAt: new Date().toISOString(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          },
          commandId: crypto.randomUUID(),
          handle,
          interactionId: assignment.interaction.id,
          response: form.get("response"),
        }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      const result = await response.json() as { error?: string };
      if (!response.ok) throw new Error(result.error || "Your response could not be recorded.");
      window.location.assign(`/r/${handle}/receipt`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Your response could not be recorded.");
      setPending(false);
    }
  }

  return (
    <article className="participant-card">
      <p className="eyebrow eyebrow--green">{assignment.tenant.name}</p>
      <h1>{assignment.title}</h1>
      <p className="participant-purpose">{assignment.purpose}</p>
      <section className="participant-terms" aria-labelledby="terms-heading">
        <h2 id="terms-heading">Terms presented to you</h2>
        <div>{assignment.content.terms}</div>
        <small>Content fingerprint: {assignment.contentHash}</small>
      </section>
      <form className="participant-response" onSubmit={submit}>
        <fieldset disabled={pending}>
          <legend>{assignment.content.prompt}</legend>
          {assignment.responseMode === "acknowledgement" ? (
            <label><input type="checkbox" name="accepted" required /><span>I acknowledge these terms.</span><input type="hidden" name="response" value="acknowledged" /></label>
          ) : (
            <div className="participant-choices">
              <label><input type="radio" name="response" value="yes" required /><span>Yes</span></label>
              <label><input type="radio" name="response" value="no" required /><span>No</span></label>
            </div>
          )}
        </fieldset>
        <p>Submitting records your authenticated account, response, server timing, available browser/network context, and the exact content shown above in a tamper-evident VASI record.</p>
        {message && <p className="form-message form-message--error" role="alert">{message}</p>}
        <button className="primary-button" disabled={pending} type="submit">{pending ? "Sealing your response…" : "Submit and seal response"}</button>
      </form>
      <footer>Request expires {new Date(assignment.expiresAt).toLocaleString()}.</footer>
    </article>
  );
}
