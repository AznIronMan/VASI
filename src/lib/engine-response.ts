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
    case "media_playback_incomplete": return "The configured playback threshold has not been met yet. Continue the media and wait for evidence to synchronize.";
    case "media_activity_unavailable": return "This hosted-media activity is no longer available.";
    case "media_event_limit_reached": return "The hosted-media evidence limit was reached. Contact the requesting company before continuing.";
    case "media_event_sequence_conflict": return "Playback evidence arrived out of order. Reload the request before continuing.";
    case "media_batch_replay_conflict": return "A playback evidence batch was replayed with different content and was rejected.";
    case "activity_interaction_unavailable": return "Activity-presence evidence is no longer available for this step.";
    case "activity_interaction_event_limit_reached": return "The activity-presence evidence limit was reached. Contact the requesting company before continuing.";
    case "activity_interaction_event_sequence_conflict": return "Activity-presence evidence arrived out of order. Reload the request before continuing.";
    case "activity_interaction_batch_replay_conflict": return "An activity-presence evidence batch was replayed with different content and was rejected.";
    case "activity_interaction_state_conflict": return "The activity-presence session no longer matches this workflow step.";
    case "content_unavailable": return "The company’s access policy no longer makes this document available.";
    case "participant_history_unavailable": return "This record is no longer available in participant history.";
    case "retention_policy_version_conflict": return "That retention policy changed after it was loaded. Refresh before saving.";
    case "retention_policy_not_found": return "The workflow names a retention profile that has not been configured for this company.";
    case "legal_hold_already_released": return "That legal hold has already been released.";
    case "data_request_review_pending": return "Your data request is awaiting review by one or more requesting organizations.";
    case "data_request_already_reviewed": return "That organization has already reviewed this data request.";
    case "data_request_expired": return "That participant data request has expired.";
    case "data_request_denied": return "The reviewed participant data request was denied.";
    case "participant_data_export_expired": return "That participant data export has expired. Submit a new data request if needed.";
    case "not_found": return "The requested record was not found or is not available to this account.";
    case "forbidden": return "This account is not authorized for that company or record.";
    case "integrity_check_failed": return "The evidence record did not pass integrity verification.";
    default: return "The private VASI engine could not complete the request.";
  }
}
