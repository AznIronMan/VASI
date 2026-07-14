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
        <p>{receipt.tenant.name} received your response to <strong>{receipt.request.title}</strong>.</p>
        <dl>
          <div><dt>Response</dt><dd>{receipt.request.response}</dd></div>
          <div><dt>Purpose</dt><dd>{receipt.request.purpose}</dd></div>
          <div><dt>Completed</dt><dd>{new Date(receipt.completedAt).toLocaleString()}</dd></div>
          <div><dt>Seal</dt><dd>{receipt.integrity.profile} · {receipt.integrity.algorithm}</dd></div>
          <div><dt>Manifest fingerprint</dt><dd className="receipt-hash">{receipt.integrity.manifestHash}</dd></div>
        </dl>
        {receipt.request.contentAccess?.available && receipt.request.activities && (
          <section className="receipt-content">
            <h2>Completed content</h2>
            {receipt.request.activities.map((activity) => (
              <article key={activity.id}>
                <h3>{activity.title}</h3>
                <div>{activity.content.terms}</div>
                <p><strong>Prompt:</strong> {activity.content.prompt}</p>
              </article>
            ))}
          </section>
        )}
        {receipt.request.contentAccess && !receipt.request.contentAccess.available && (
          <p className="receipt-note">The company’s post-completion policy makes the original content unavailable here. Your receipt and transaction history remain available.</p>
        )}
        <p className="receipt-note">This receipt is a participant-readable summary. The company’s authorized record includes the detailed event chain and available authentication, timing, browser, and network context.</p>
      </article>
    </main>
  );
}

function ReceiptError({ message }: { message: string }) {
  return <main className="participant-shell"><section className="participant-error"><h1>Receipt unavailable</h1><p>{message}</p></section></main>;
}
