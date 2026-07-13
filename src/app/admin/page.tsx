import type { Metadata } from "next";
import { headers } from "next/headers";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { AdminConsole } from "@/components/admin/admin-console";
import { authorizeAdminHeaders } from "@/lib/admin-access";
import { loadAdminDashboard } from "@/lib/admin-users";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Identity administration",
};

export default async function AdminPage() {
  const authorization = await authorizeAdminHeaders(await headers());
  if (!authorization.ok) {
    if (authorization.reason === "host") notFound();
    if (authorization.reason === "session") redirect("/");

    return (
      <main className="admin-denied">
        <section>
          <p className="eyebrow eyebrow--green">ACCESS RESTRICTED</p>
          <h1>Administrator access is required</h1>
          <p>This signed-in account is not on the authorized operator list.</p>
          <Link href="/">Use a different account</Link>
        </section>
      </main>
    );
  }

  const dashboard = await loadAdminDashboard();
  return (
    <AdminConsole
      invitations={dashboard.invitations}
      operatorId={authorization.session.user.id}
      users={dashboard.users}
    />
  );
}
