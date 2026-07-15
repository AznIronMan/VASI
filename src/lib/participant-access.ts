import { getAuth } from "@/lib/auth";
import { accessDenialResponse, hiddenResourceResponse } from "@/lib/access-denial";
import { hasExpectedMutationOrigin, isRequestForOrigin } from "@/lib/host-policy";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

export async function authorizeParticipantHeaders(headers: Headers) {
  const [auth, settings] = await Promise.all([getAuth(), getRuntimeSettings()]);
  const { baseURL } = resolveServerSettings(settings);
  if (!isRequestForOrigin(headers, baseURL)) {
    return { ok: false as const, response: hiddenResourceResponse() };
  }
  const session = await auth.api.getSession({ headers });
  if (!session) {
    return {
      ok: false as const,
      response: accessDenialResponse("Authentication required.", 401),
    };
  }
  if (!session.user.emailVerified) {
    return {
      ok: false as const,
      response: accessDenialResponse("Email verification required.", 403),
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
      response: accessDenialResponse("Invalid request origin.", 403),
    };
  }
  return authorization;
}
