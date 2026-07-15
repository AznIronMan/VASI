import type { Metadata } from "next";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { ParticipantWorkspace } from "@/components/evidence/participant-workspace";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import type { ParticipantDataRequest, ParticipantHistoryRecord } from "@/lib/evidence-types";
import { authorizeParticipantHeaders } from "@/lib/participant-access";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Workspace",
};

export default async function WorkspacePage({
  searchParams,
}: {
  searchParams: Promise<{ privacyReauthentication?: string }>;
}) {
  const query = await searchParams;
  const requestHeaders = await headers();
  const authorization = await authorizeParticipantHeaders(requestHeaders);
  if (!authorization.ok) redirect("/");
  const actor = await buildEngineActor(authorization.session, requestHeaders);
  const [history, dataRequests] = await Promise.all([
    requestEngineAction<ParticipantHistoryRecord[]>(actor, { method: "GET", path: "/v1/participant/history" }),
    requestEngineAction<ParticipantDataRequest[]>(actor, { method: "GET", path: "/v1/participant/data-requests" }),
  ]);
  if (history.status !== 200 || !history.body || dataRequests.status !== 200 || !dataRequests.body) {
    throw new Error("The private VASI participant workspace is unavailable.");
  }
  return <ParticipantWorkspace
    email={authorization.session.user.email}
    initialAuthenticationRequired={query.privacyReauthentication === "required"
      ? "reauthentication_required"
      : undefined}
    initialDataRequests={dataRequests.body}
    initialHistory={history.body}
    name={authorization.session.user.name}
    sessionExpiresAt={new Date(authorization.session.session.expiresAt).toISOString()}
  />;
}
