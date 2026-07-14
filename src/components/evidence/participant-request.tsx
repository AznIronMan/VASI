"use client";

import { FormEvent, PointerEvent, useRef, useState } from "react";

import { ExternalMediaActivity } from "@/components/evidence/external-media-activity";
import type { OpenParticipantAssignment } from "@/lib/evidence-types";
import type { WorkflowActivityContent } from "@/lib/owner-types";

type SignaturePoint = { t: number; x: number; y: number };
type SignatureStroke = SignaturePoint[];

export function ParticipantRequest({ assignment, handle }: {
  assignment: OpenParticipantAssignment;
  handle: string;
}) {
  const clientStartedAt = useRef(new Date().toISOString());
  const [pending, setPending] = useState<"save" | "submit">();
  const [message, setMessage] = useState<string>();
  const [strokes, setStrokes] = useState<SignatureStroke[]>([]);
  const type = assignment.type || "terms_response";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
    const intent = submitter?.value === "save" ? "save" : "submit";
    const form = new FormData(event.currentTarget);
    let response: unknown;
    try {
      response = responseFromForm(type, assignment.content, form, strokes);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Complete the required response.");
      return;
    }
    setPending(intent);
    setMessage(undefined);
    try {
      const request = await fetch("/api/evidence/respond", {
        body: JSON.stringify({
          activityId: assignment.activityId,
          clientContext: {
            clientStartedAt: clientStartedAt.current,
            clientSubmittedAt: new Date().toISOString(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          },
          commandId: crypto.randomUUID(),
          handle,
          intent,
          interactionId: assignment.interaction.id,
          response,
        }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      const result = await request.json() as { completed?: boolean; error?: string; saved?: boolean };
      if (!request.ok) throw new Error(result.error || "Your response could not be recorded.");
      if (intent === "save") {
        setMessage("Your response was saved as an append-only revision. It has not been submitted.");
        setPending(undefined);
        return;
      }
      window.location.assign(result.completed === false ? `/r/${handle}` : `/r/${handle}/receipt`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Your response could not be recorded.");
      setPending(undefined);
    }
  }

  return (
    <article className="participant-card">
      <p className="eyebrow eyebrow--green">{assignment.tenant.name}</p>
      {assignment.progress && <p className="participant-progress">Step {assignment.progress.current} of {assignment.progress.total}{assignment.workflowTitle ? ` · ${assignment.workflowTitle}` : ""}</p>}
      <h1>{assignment.title}</h1>
      <p className="participant-purpose">{assignment.purpose}</p>
      {assignment.instructions && <p className="participant-purpose">{assignment.instructions}</p>}
      <ActivityPresentation assignment={assignment} handle={handle} />
      <form className="participant-response" onSubmit={submit}>
        <fieldset disabled={Boolean(pending)}>
          <ActivityResponseFields
            assignment={assignment}
            handle={handle}
            strokes={strokes}
            setStrokes={setStrokes}
          />
        </fieldset>
        <p>Submitting records your authenticated account, exact response and labels, server timing, available browser/network context, and the immutable activity revision in a tamper-evident VASI record.</p>
        {assignment.savedResponseLabel && <p className="form-message">Last saved revision: {assignment.savedResponseLabel}</p>}
        {message && <p className={message.includes("could not") ? "form-message form-message--error" : "form-message"} role="status">{message}</p>}
        <div className="participant-actions">
          <button className="secondary-button" disabled={Boolean(pending)} name="intent" type="submit" value="save">{pending === "save" ? "Saving…" : "Save progress"}</button>
          <button className="primary-button" disabled={Boolean(pending)} name="intent" type="submit" value="submit">{pending === "submit" ? "Recording…" : assignment.progress && assignment.progress.current < assignment.progress.total ? "Submit and continue" : "Submit and seal response"}</button>
        </div>
      </form>
      <footer>Request expires {new Date(assignment.expiresAt).toLocaleString()}.</footer>
    </article>
  );
}

function ActivityPresentation({ assignment, handle }: {
  assignment: OpenParticipantAssignment;
  handle: string;
}) {
  const content = assignment.content;
  const type = assignment.type || "terms_response";
  if (type === "terms_response") return <section className="participant-terms" aria-labelledby="content-heading"><h2 id="content-heading">Terms presented to you</h2><div>{content.terms}</div><small>Activity fingerprint: {assignment.contentHash}</small></section>;
  if (type === "approval" || type === "electronic_signature") return <section className="participant-terms" aria-labelledby="content-heading"><h2 id="content-heading">Statement presented to you</h2><div>{content.statement}</div>{type === "electronic_signature" && <p><strong>Consent language:</strong> {content.consentText}</p>}<small>Activity fingerprint: {assignment.contentHash}</small></section>;
  if (type === "document_review" && content.artifact) {
    const disposition = "inline";
    const url = `/r/${handle}/artifacts/${content.artifact.id}?activityId=${encodeURIComponent(assignment.activityId || "")}&disposition=${disposition}`;
    const downloadable = `/r/${handle}/artifacts/${content.artifact.id}?activityId=${encodeURIComponent(assignment.activityId || "")}&disposition=attachment`;
    const inline = content.artifact.mediaType === "application/pdf" || content.artifact.mediaType.startsWith("text/");
    return <section className="participant-document"><h2>{content.displayName}</h2><dl><div><dt>Revision</dt><dd>{content.artifact.revision}</dd></div><div><dt>Fingerprint</dt><dd>{content.artifact.sha256}</dd></div></dl><div className="participant-document-actions"><a href={url} target="_blank" rel="noreferrer">Open document</a><a href={downloadable}>Download original</a></div>{inline && <iframe src={url} title={content.displayName || content.artifact.originalFilename} />}</section>;
  }
  if (type === "external_media") return null;
  return <section className="participant-terms"><h2>Activity presented to you</h2><p>{content.instructions || content.prompt}</p><small>Activity fingerprint: {assignment.contentHash}</small></section>;
}

function ActivityResponseFields({ assignment, handle, strokes, setStrokes }: {
  assignment: OpenParticipantAssignment;
  handle: string;
  strokes: SignatureStroke[];
  setStrokes: (strokes: SignatureStroke[]) => void;
}) {
  const content = assignment.content;
  const type = assignment.type || "terms_response";
  if (type === "terms_response") return <><legend>{content.prompt}</legend>{assignment.responseMode === "acknowledgement" ? <label><input type="checkbox" name="accepted" defaultChecked={assignment.savedResponse === "acknowledged"} required /><span>{content.acknowledgementLabel || "I acknowledge these terms."}</span><input type="hidden" name="response" value="acknowledged" /></label> : <div className="participant-choices"><label><input type="radio" name="response" value="yes" defaultChecked={assignment.savedResponse === "yes"} required /><span>{content.yesLabel || "Yes"}</span></label><label><input type="radio" name="response" value="no" defaultChecked={assignment.savedResponse === "no"} required /><span>{content.noLabel || "No"}</span></label></div>}</>;
  if (type === "approval") return <><legend>{content.prompt}</legend><div className="participant-choices"><label><input type="radio" name="response" value="approved" defaultChecked={assignment.savedResponse === "approved"} required /><span>{content.labels?.approved || "Approve"}</span></label><label><input type="radio" name="response" value="disapproved" defaultChecked={assignment.savedResponse === "disapproved"} required /><span>{content.labels?.disapproved || "Disapprove"}</span></label><label><input type="radio" name="response" value="declined" defaultChecked={assignment.savedResponse === "declined"} required /><span>{content.labels?.declined || "Decline to decide"}</span></label></div></>;
  if (type === "single_choice" || type === "multiple_choice") return <><legend>{content.prompt}</legend><div className="participant-choices">{content.choices?.map((choice) => <label key={choice.id}><input type={type === "single_choice" ? "radio" : "checkbox"} name="response" value={choice.id} defaultChecked={type === "single_choice" ? assignment.savedResponse === choice.id : Array.isArray(assignment.savedResponse) && assignment.savedResponse.includes(choice.id)} required={type === "single_choice"} /><span>{choice.label}{choice.description ? <small>{choice.description}</small> : null}</span></label>)}</div></>;
  if (type === "free_form") return <><legend>{content.prompt}</legend>{content.multiline !== false ? <textarea name="response" minLength={content.minLength} maxLength={content.maxLength} defaultValue={typeof assignment.savedResponse === "string" ? assignment.savedResponse : ""} required={(content.minLength || 0) > 0} rows={8} /> : <input name="response" minLength={content.minLength} maxLength={content.maxLength} defaultValue={typeof assignment.savedResponse === "string" ? assignment.savedResponse : ""} required={(content.minLength || 0) > 0} />}</>;
  if (type === "document_review") return <><legend>{content.prompt}</legend><label><input type="checkbox" name="reviewed" required /><span>{content.responseLabel || "I reviewed this document."}</span><input type="hidden" name="response" value="reviewed" /></label><p className="participant-limit">VASI records presentation/download access, but does not claim that route access alone proves every page was read.</p></>;
  if (type === "electronic_signature") return <SignatureFields content={content} setStrokes={setStrokes} strokes={strokes} />;
  if (type === "questionnaire") return <><legend>{content.instructions || "Complete the questionnaire."}</legend><div className="participant-questionnaire">{content.questions?.map((question, index) => <fieldset key={question.id}><legend>{index + 1}. {question.prompt}</legend>{question.choices.map((choice) => { const saved = assignment.savedResponse && typeof assignment.savedResponse === "object" && !Array.isArray(assignment.savedResponse) ? (assignment.savedResponse as Record<string, unknown>)[question.id] : undefined; return <label key={choice.id}><input type={question.type === "single_choice" ? "radio" : "checkbox"} name={`question:${question.id}`} value={choice.id} defaultChecked={question.type === "single_choice" ? saved === choice.id : Array.isArray(saved) && saved.includes(choice.id)} required={question.required && question.type === "single_choice"} /><span>{choice.label}</span></label>; })}</fieldset>)}</div></>;
  if (type === "external_media") return <ExternalMediaActivity assignment={assignment} handle={handle} />;
  return <legend>Complete this activity.</legend>;
}

function SignatureFields({ content, strokes, setStrokes }: {
  content: WorkflowActivityContent;
  strokes: SignatureStroke[];
  setStrokes: (strokes: SignatureStroke[]) => void;
}) {
  const methods = content.methods || ["typed", "drawn"];
  const [method, setMethod] = useState<"typed" | "drawn">(methods[0]);
  return <><legend>{content.prompt}</legend>{methods.length > 1 && <label><span>Signature method</span><select name="signatureMethod" value={method} onChange={(event) => setMethod(event.target.value as "typed" | "drawn")}><option value="typed">Type my name</option><option value="drawn">Draw my signature</option></select></label>}{methods.length === 1 && <input type="hidden" name="signatureMethod" value={method} />}{method === "typed" ? <label><span>{content.typedNameLabel || "Type your full legal name"}</span><input name="signatureName" minLength={2} maxLength={160} autoComplete="name" required /></label> : <SignaturePad strokes={strokes} setStrokes={setStrokes} label={content.drawnSignatureLabel || "Draw your signature"} />}<label><input type="checkbox" name="signatureConsent" required /><span>{content.consentText}</span></label></>;
}

function SignaturePad({ label, strokes, setStrokes }: {
  label: string;
  strokes: SignatureStroke[];
  setStrokes: (strokes: SignatureStroke[]) => void;
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const active = useRef<SignatureStroke | undefined>(undefined);
  const start = useRef(0);
  const point = (event: PointerEvent<HTMLCanvasElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    return {
      t: Math.max(0, Date.now() - start.current),
      x: Math.min(1, Math.max(0, (event.clientX - bounds.left) / bounds.width)),
      y: Math.min(1, Math.max(0, (event.clientY - bounds.top) / bounds.height)),
    };
  };
  const redraw = (next: SignatureStroke[]) => {
    const context = canvas.current?.getContext("2d");
    if (!context || !canvas.current) return;
    context.clearRect(0, 0, canvas.current.width, canvas.current.height);
    context.strokeStyle = "#101916";
    context.lineWidth = 2;
    context.lineCap = "round";
    for (const stroke of next) {
      if (stroke.length < 2) continue;
      context.beginPath();
      context.moveTo(stroke[0].x * canvas.current.width, stroke[0].y * canvas.current.height);
      for (const item of stroke.slice(1)) context.lineTo(item.x * canvas.current.width, item.y * canvas.current.height);
      context.stroke();
    }
  };
  return <div className="signature-pad"><span>{label}</span><canvas ref={canvas} width="700" height="220" onPointerDown={(event) => { start.current = Date.now(); active.current = [point(event)]; event.currentTarget.setPointerCapture(event.pointerId); }} onPointerMove={(event) => { if (!active.current) return; active.current.push(point(event)); redraw([...strokes, active.current]); }} onPointerUp={(event) => { if (!active.current) return; active.current.push(point(event)); const next = [...strokes, active.current]; active.current = undefined; setStrokes(next); redraw(next); }} aria-label={label} /><button type="button" onClick={() => { setStrokes([]); redraw([]); }}>Clear drawing</button></div>;
}

function responseFromForm(type: string, content: WorkflowActivityContent, form: FormData, strokes: SignatureStroke[]) {
  if (["terms_response", "approval", "single_choice", "document_review"].includes(type)) return String(form.get("response") || "");
  if (type === "multiple_choice") return form.getAll("response").map(String);
  if (type === "free_form") return String(form.get("response") || "");
  if (type === "electronic_signature") {
    if (form.get("signatureConsent") !== "on") throw new Error("Electronic-signature consent is required.");
    const method = String(form.get("signatureMethod"));
    if (method === "typed") return { consent: true, method, name: String(form.get("signatureName") || "") };
    if (!strokes.length) throw new Error("Draw your signature before saving or submitting.");
    return { consent: true, method: "drawn", strokes };
  }
  if (type === "questionnaire") {
    return Object.fromEntries((content.questions || []).flatMap((question) => {
      const values = form.getAll(`question:${question.id}`).map(String);
      if (!values.length) return [];
      return [[question.id, question.type === "single_choice" ? values[0] : values]];
    }));
  }
  if (type === "external_media") {
    const method = String(form.get("mediaMethod") || "");
    if (method === "playback") return { method };
    if (method === "acknowledgement" && form.get("mediaAcknowledged") === "on") {
      return { acknowledged: true, method };
    }
    throw new Error("Choose a completion method and provide the required acknowledgement.");
  }
  return String(form.get("response") || "");
}
