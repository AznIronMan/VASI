import type { Metadata } from "next";
import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";

import { SignOutButton } from "@/components/auth/sign-out-button";
import { BrandMark } from "@/components/brand-mark";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { friendlyEngineError } from "@/lib/engine-response";
import type { EngineErrorResponse, ParticipantReceipt } from "@/lib/evidence-types";
import { authorizeParticipantHeaders } from "@/lib/participant-access";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { referrer: "no-referrer", title: "Evidence receipt" };

export default async function ReceiptPage({ params }: { params: Promise<{ handle: string }> }) {
  const { handle } = await params;
  if (!/^[A-Za-z0-9_-]{43}$/.test(handle)) notFound();
  const requestHeaders = await headers();
  const authorization = await authorizeParticipantHeaders(requestHeaders);
  if (!authorization.ok) {
    if (authorization.response.status === 404) notFound();
    if (authorization.response.status === 403) {
      return <ReceiptError message="Verify your email address before viewing this receipt." />;
    }
    redirect(`/?returnTo=${encodeURIComponent(`/r/${handle}`)}`);
  }
  const result = await requestEngineAction<ParticipantReceipt>(
    await buildEngineActor(authorization.session, requestHeaders),
    { body: { handle }, method: "POST", path: "/v1/participant/receipt" },
  );
  if (result.status === 404) notFound();
  if (result.status !== 200 || !result.body) {
    return <ReceiptError message={friendlyEngineError((result.body as EngineErrorResponse | undefined)?.error)} />;
  }
  const receipt = result.body;
  return (
    <main className="participant-shell">
      <header><BrandMark compact /><SignOutButton /></header>
      <article className="receipt-card">
        <span className="receipt-seal" aria-hidden="true">✓</span>
        <p className="eyebrow eyebrow--green">VASI INTEGRITY VERIFIED</p>
        <h1>Response recorded</h1>
        <p>{receipt.tenant.profile?.branding?.displayName || receipt.tenant.name} received your response to <strong>{receipt.request.title}</strong>.</p>
        <dl>
          <div><dt>Response</dt><dd>{receipt.request.response}</dd></div>
          <div><dt>Purpose</dt><dd>{receipt.request.purpose}</dd></div>
          <div><dt>Completed</dt><dd>{new Date(receipt.completedAt).toLocaleString()}</dd></div>
          <div><dt>Seal</dt><dd>{receipt.integrity.profile} · {receipt.integrity.algorithm}</dd></div>
          <div><dt>Manifest fingerprint</dt><dd className="receipt-hash">{receipt.integrity.manifestHash}</dd></div>
        </dl>
        {receipt.request.responses && <section className="receipt-content"><h2>Recorded activity outcomes</h2>{receipt.request.responses.map((response) => <article key={response.activityId}><h3>{response.activityId}</h3><p>{response.responseLabel || formatReceiptValue(response.response)}</p>{response.outcome && <small>Outcome: {response.outcome}</small>}</article>)}</section>}
        {receipt.request.contentAccess?.available && receipt.request.activities && (
          <section className="receipt-content">
            <h2>Completed content</h2>
            {receipt.request.activities.map((activity) => (
              <ReceiptActivity activity={activity} handle={handle} key={activity.id} />
            ))}
          </section>
        )}
        {receipt.request.contentAccess && !receipt.request.contentAccess.available && (
          <p className="receipt-note">The company’s post-completion policy makes the original content unavailable here. Your receipt and transaction history remain available.</p>
        )}
        <p className="receipt-note">This receipt is a participant-readable summary. The company’s authorized record includes the detailed event chain and available authentication, timing, browser, and network context.</p>
        <div className="participant-actions">
          <a className="button button--primary" href={`/r/${handle}/report?format=html`}>Download participant report</a>
          <a className="button button--secondary" href={`/verify?fingerprint=${receipt.integrity.manifestHash}`}>Verify fingerprint</a>
        </div>
      </article>
    </main>
  );
}

function ReceiptActivity({ activity, handle }: {
  activity: NonNullable<ParticipantReceipt["request"]["activities"]>[number];
  handle: string;
}) {
  const content = activity.content;
  if (activity.type === "document_review" && content.artifact) {
    const url = `/r/${handle}/artifacts/${content.artifact.id}?activityId=${encodeURIComponent(activity.id)}`;
    return <article><h3>{activity.title}</h3><p>{content.displayName}</p><a href={url} target="_blank" rel="noreferrer">Open retained document revision {content.artifact.revision}</a><small className="receipt-hash">{content.artifact.sha256}</small></article>;
  }
  if (activity.type === "external_media" && content.descriptor) {
    const descriptor = content.descriptor;
    const version = descriptor.version?.checksum || descriptor.version?.eTag || descriptor.version?.cTag || descriptor.version?.id;
    return <article><h3>{activity.title}</h3><p>{descriptor.title} · {descriptor.provider.replaceAll("_", " ")}</p><a href={descriptor.sourceUrl} target="_blank" rel="noreferrer">Open retained provider reference</a>{version && <small className="receipt-hash">Provider version: {version}</small>}<small>External provider availability and current bytes can change independently of the immutable VASI descriptor.</small></article>;
  }
  if (activity.type === "terms_response") return <article><h3>{activity.title}</h3><div>{content.terms}</div><p><strong>Prompt:</strong> {content.prompt}</p></article>;
  if (activity.type === "approval" || activity.type === "electronic_signature") return <article><h3>{activity.title}</h3><div>{content.statement}</div><p><strong>Prompt:</strong> {content.prompt}</p></article>;
  if (activity.type === "questionnaire") return <article><h3>{activity.title}</h3><p>{content.instructions}</p><p>{content.questions?.length} question(s) in the immutable revision.</p></article>;
  return <article><h3>{activity.title}</h3><p>{content.prompt}</p></article>;
}

function formatReceiptValue(value: unknown) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.join(", ");
  return JSON.stringify(value);
}

function ReceiptError({ message }: { message: string }) {
  return <main className="participant-shell"><section className="participant-error"><h1>Receipt unavailable</h1><p>{message}</p></section></main>;
}
