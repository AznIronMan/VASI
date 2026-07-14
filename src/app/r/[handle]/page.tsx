import type { Metadata } from "next";
import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";

import { SignOutButton } from "@/components/auth/sign-out-button";
import { BrandMark } from "@/components/brand-mark";
import { ParticipantRequest } from "@/components/evidence/participant-request";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { friendlyEngineError } from "@/lib/engine-response";
import type {
  EngineErrorResponse,
  OpenParticipantAssignment,
  ParticipantAssignment,
} from "@/lib/evidence-types";
import { authorizeParticipantHeaders } from "@/lib/participant-access";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { referrer: "no-referrer", title: "Evidence request" };

export default async function ParticipantRequestPage({
  params,
}: {
  params: Promise<{ handle: string }>;
}) {
  const { handle } = await params;
  if (!/^[A-Za-z0-9_-]{43}$/.test(handle)) notFound();
  const requestHeaders = await headers();
  const authorization = await authorizeParticipantHeaders(requestHeaders);
  if (!authorization.ok) {
    if (authorization.response.status === 404) notFound();
    if (authorization.response.status === 401) redirect(`/?returnTo=${encodeURIComponent(`/r/${handle}`)}`);
    return <ParticipantError message="Verify your email address before opening this evidence request." />;
  }
  const result = await requestEngineAction<ParticipantAssignment>(
    await buildEngineActor(authorization.session, requestHeaders),
    { body: { handle }, method: "POST", path: "/v1/participant/open" },
  );
  if (result.status === 404) notFound();
  if (result.status !== 200 || !result.body) {
    return <ParticipantError message={friendlyEngineError((result.body as EngineErrorResponse | undefined)?.error)} />;
  }
  if (result.body.completed) redirect(`/r/${handle}/receipt`);
  if (!isCompleteAssignment(result.body)) {
    return <ParticipantError message="This evidence request is incomplete." />;
  }
  return (
    <main className="participant-shell">
      <header><BrandMark compact /><SignOutButton /></header>
      <ParticipantRequest assignment={result.body} handle={handle} />
    </main>
  );
}

function isCompleteAssignment(value: ParticipantAssignment): value is OpenParticipantAssignment {
  return Boolean(
    value.assignmentId && value.content && value.contentHash && value.expiresAt &&
    value.interaction && value.purpose && value.responseMode && value.tenant && value.title,
  );
}

function ParticipantError({ message }: { message: string }) {
  return <main className="participant-shell"><section className="participant-error"><h1>Request unavailable</h1><p>{message}</p></section></main>;
}
