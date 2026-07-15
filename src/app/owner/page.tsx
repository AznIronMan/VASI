import { headers } from "next/headers";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { OwnerConsole } from "@/components/owner/owner-console";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { authorizeOwnerHeaders } from "@/lib/owner-access";
import type { OwnerTenant } from "@/lib/owner-types";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

export const dynamic = "force-dynamic";
export default async function OwnerPage() {
  const requestHeaders = await headers();
  const authorization = await authorizeOwnerHeaders(requestHeaders);
  if (!authorization.ok) {
    if (authorization.reason === "host") notFound();
    if (authorization.reason === "session") redirect("/");
    return (
      <main className="admin-denied"><section>
        <p className="eyebrow eyebrow--green">COMPANY ACCESS</p>
        <h1>A verified account is required</h1>
        <p>Verify or reactivate this account before using company workflows.</p>
        <Link href="/">Return to sign in</Link>
      </section></main>
    );
  }
  const result = await requestEngineAction<OwnerTenant[]>(
    await buildEngineActor(authorization.session, requestHeaders),
    { method: "GET", path: "/v1/owner/tenants" },
  );
  if (result.status !== 200 || !result.body) throw new Error("Company access is unavailable.");
  const { baseURL } = resolveServerSettings(await getRuntimeSettings());
  return <OwnerConsole baseURL={baseURL} initialTenants={result.body} />;
}
