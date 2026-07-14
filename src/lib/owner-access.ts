import { getAuth } from "@/lib/auth";
import { hasExpectedMutationOrigin, isRequestForOrigin } from "@/lib/host-policy";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

type AuthInstance = Awaited<ReturnType<typeof getAuth>>;
type OwnerSession = Awaited<ReturnType<AuthInstance["api"]["getSession"]>>;

export async function authorizeOwnerHeaders(headers: Headers) {
  const [auth, settings] = await Promise.all([getAuth(), getRuntimeSettings()]);
  const { adminOrigin } = resolveServerSettings(settings);
  if (!isRequestForOrigin(headers, adminOrigin)) {
    return { ok: false as const, reason: "host" as const, response: new Response(null, { status: 404 }) };
  }
  const session = await auth.api.getSession({ headers });
  if (!session) {
    return {
      ok: false as const,
      reason: "session" as const,
      response: Response.json({ error: "Authentication required." }, { status: 401 }),
    };
  }
  const user = session.user as typeof session.user & { banned?: boolean | null };
  if (user.banned || !user.emailVerified) {
    return {
      ok: false as const,
      reason: "identity" as const,
      response: Response.json({ error: "An active, verified V·Sign account is required." }, { status: 403 }),
    };
  }
  return { ok: true as const, session: session as NonNullable<OwnerSession> };
}

export async function authorizeOwnerMutation(request: Request) {
  const authorization = await authorizeOwnerHeaders(request.headers);
  if (!authorization.ok) return authorization;
  const { adminOrigin } = resolveServerSettings(await getRuntimeSettings());
  if (!hasExpectedMutationOrigin(request.headers, adminOrigin)) {
    return {
      ok: false as const,
      reason: "origin" as const,
      response: Response.json({ error: "Invalid request origin." }, { status: 403 }),
    };
  }
  return authorization;
}
