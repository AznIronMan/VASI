import type { Metadata } from "next";
import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";

import { EvidenceConsole } from "@/components/admin/evidence-console";
import { authorizeAdminHeaders } from "@/lib/admin-access";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import type { EvidenceTenant } from "@/lib/evidence-types";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Sealed evidence requests" };

export default async function EvidenceAdminPage() {
  const requestHeaders = await headers();
  const authorization = await authorizeAdminHeaders(requestHeaders);
  if (!authorization.ok) {
    if (authorization.reason === "host") notFound();
    if (authorization.reason === "session") redirect("/");
    redirect("/admin");
  }
  const result = await requestEngineAction<EvidenceTenant[]>(
    await buildEngineActor(authorization.session, requestHeaders),
    { method: "GET", path: "/v1/owner/tenants" },
  );
  if (result.status !== 200 || !result.body) {
    throw new Error("The private VASI engine tenant list is unavailable.");
  }
  const { baseURL } = resolveServerSettings(await getRuntimeSettings());
  return <EvidenceConsole baseURL={baseURL} initialTenants={result.body} />;
}
