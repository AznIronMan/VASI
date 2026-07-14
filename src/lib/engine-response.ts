import type { EngineErrorResponse } from "@/lib/evidence-types";

export function gatewayEngineResponse<T>(result: { body?: T | EngineErrorResponse; status: number }) {
  if (result.status >= 200 && result.status < 300) {
    return Response.json(result.body ?? {});
  }
  const body = result.body as EngineErrorResponse | undefined;
  return Response.json(
    { error: friendlyEngineError(body?.error) },
    { status: result.status >= 400 && result.status <= 599 ? result.status : 502 },
  );
}

export function friendlyEngineError(code?: string) {
  switch (code) {
    case "tenant_slug_exists": return "That company identifier is already in use.";
    case "assignment_expired": return "This request has expired.";
    case "assignment_revoked": return "This request is no longer available.";
    case "response_replayed": return "This request has already been completed.";
    case "receipt_unavailable": return "The completed receipt is not available yet.";
    case "not_found": return "The requested record was not found or is not available to this account.";
    case "forbidden": return "This account is not authorized for that company or record.";
    case "integrity_check_failed": return "The evidence record did not pass integrity verification.";
    default: return "The private VASI engine could not complete the request.";
  }
}
