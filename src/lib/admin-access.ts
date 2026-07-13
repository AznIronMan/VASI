import { auth } from "@/lib/auth";
import {
  hasExpectedMutationOrigin,
  isRequestForOrigin,
} from "@/lib/host-policy";
import { resolveServerEnvironment } from "@/lib/server-environment";

type AdminSession = Awaited<ReturnType<typeof auth.api.getSession>>;

export type AuthorizedAdmin = {
  ok: true;
  session: NonNullable<AdminSession>;
};

export type DeniedAdmin = {
  ok: false;
  response: Response;
  reason: "host" | "origin" | "session" | "role";
};

export async function authorizeAdminHeaders(headers: Headers): Promise<
  AuthorizedAdmin | DeniedAdmin
> {
  const { adminEmails, adminOrigin } = resolveServerEnvironment();

  if (!isRequestForOrigin(headers, adminOrigin)) {
    return {
      ok: false,
      reason: "host",
      response: new Response(null, { status: 404 }),
    };
  }

  const session = await auth.api.getSession({ headers });
  if (!session) {
    return {
      ok: false,
      reason: "session",
      response: Response.json({ error: "Authentication required." }, { status: 401 }),
    };
  }

  const user = session.user as typeof session.user & {
    banned?: boolean | null;
    role?: string | null;
  };
  const roles = user.role?.split(",").map((role) => role.trim()) ?? [];
  if (
    user.banned ||
    !roles.includes("admin") ||
    !adminEmails.includes(user.email.toLowerCase())
  ) {
    return {
      ok: false,
      reason: "role",
      response: Response.json({ error: "Administrator access required." }, { status: 403 }),
    };
  }

  return { ok: true, session };
}

export async function authorizeAdminMutation(request: Request) {
  const authorization = await authorizeAdminHeaders(request.headers);
  if (!authorization.ok) return authorization;

  const { adminOrigin } = resolveServerEnvironment();
  if (!hasExpectedMutationOrigin(request.headers, adminOrigin)) {
    return {
      ok: false as const,
      reason: "origin" as const,
      response: Response.json({ error: "Invalid request origin." }, { status: 403 }),
    };
  }

  return authorization;
}
