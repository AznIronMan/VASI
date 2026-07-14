import { getAuth } from "@/lib/auth";
import { hasExpectedMutationOrigin, isRequestForOrigin } from "@/lib/host-policy";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

export async function authorizeParticipantHeaders(headers: Headers) {
  const [auth, settings] = await Promise.all([getAuth(), getRuntimeSettings()]);
  const { baseURL } = resolveServerSettings(settings);
  if (!isRequestForOrigin(headers, baseURL)) {
    return { ok: false as const, response: new Response(null, { status: 404 }) };
  }
  const session = await auth.api.getSession({ headers });
  if (!session) {
    return {
      ok: false as const,
      response: Response.json({ error: "Authentication required." }, { status: 401 }),
    };
  }
  if (!session.user.emailVerified) {
    return {
      ok: false as const,
      response: Response.json({ error: "Email verification required." }, { status: 403 }),
    };
  }
  return { ok: true as const, session };
}

export async function authorizeParticipantMutation(request: Request) {
  const authorization = await authorizeParticipantHeaders(request.headers);
  if (!authorization.ok) return authorization;
  const { baseURL } = resolveServerSettings(await getRuntimeSettings());
  if (!hasExpectedMutationOrigin(request.headers, baseURL)) {
    return {
      ok: false as const,
      response: Response.json({ error: "Invalid request origin." }, { status: 403 }),
    };
  }
  return authorization;
}
