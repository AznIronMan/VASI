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
    case "assignment_not_yet_available": return "This request is scheduled but is not available yet.";
    case "response_replayed": return "This request has already been completed.";
    case "receipt_unavailable": return "The completed receipt is not available yet.";
    case "activity_state_conflict": return "This workflow step changed state. Reload the request before responding again.";
    case "activity_unavailable": return "The next workflow step is not available.";
    case "draft_version_conflict": return "This draft changed after it was loaded. Refresh before saving or publishing.";
    case "last_owner_required": return "A company must retain at least one active owner.";
    case "request_state_conflict": return "That request action is not allowed in its current state.";
    case "action_replayed": return "That request action was already processed.";
    case "workflow_archived": return "That workflow is archived and cannot be published.";
    case "invalid_workflow": return "The workflow or activity definition is invalid.";
    case "invalid_activity_response": return "The response does not satisfy this activity’s requirements.";
    case "invalid_artifact": return "The document type, filename, size, or artifact command is invalid.";
    case "artifact_rejected": return "The document failed integrity, content-type, or bounded safety inspection.";
    case "artifact_chunk_too_large": return "A document chunk exceeded the configured limit.";
    case "artifact_length_exceeded": return "The document exceeded its declared size.";
    case "artifact_chunk_sequence_conflict": return "The document upload sequence was interrupted; upload it again.";
    case "artifact_finalized": return "That document artifact has already been finalized.";
    case "document_not_presented": return "Open or download the document before acknowledging its review.";
    case "content_unavailable": return "The company’s access policy no longer makes this document available.";
    case "not_found": return "The requested record was not found or is not available to this account.";
    case "forbidden": return "This account is not authorized for that company or record.";
    case "integrity_check_failed": return "The evidence record did not pass integrity verification.";
    default: return "The private VASI engine could not complete the request.";
  }
}
