-- Engine-owned participant-data export preparation and controller-scoped status
-- delivery. Message payloads remain encrypted in the outbox and immutable audit
-- rows bind only bounded operational state.

alter table "vasi_engine"."participant_data_request"
  drop constraint "participant_data_request_status_check";

alter table "vasi_engine"."participant_data_request"
  add constraint "participant_data_request_status_check_v2"
  check ("status" in (
    'pending_review', 'approved', 'partially_approved', 'preparation_failed',
    'denied', 'ready', 'expired', 'cancelled'
  ));

alter table "vasi_engine"."outbox_job"
  add column "participantDataRequestId" text
    references "vasi_engine"."participant_data_request" ("id"),
  add constraint "outbox_job_request_purpose_check"
    check ("requestId" is null or "participantDataRequestId" is null);

alter table "vasi_engine"."outbox_job"
  drop constraint "outbox_job_status_check";

alter table "vasi_engine"."outbox_job"
  add constraint "outbox_job_status_check_v2"
  check ("status" in ('pending', 'participant_pending', 'running', 'completed', 'failed'));

alter table "vasi_engine"."outbox_job"
  drop constraint "outbox_job_notification_type_check";

alter table "vasi_engine"."outbox_job"
  add constraint "outbox_job_notification_type_check_v2"
  check (
    "notificationType" is null or
    "notificationType" in (
      'request.issued', 'request.reminder', 'request.completed',
      'participant_data.ready', 'participant_data.denied',
      'participant_data.preparation_failed', 'participant_data.expired'
    )
  );

create index "outbox_job_participant_data_notification_idx"
  on "vasi_engine"."outbox_job"
    ("participantDataRequestId", "tenantId", "notificationType", "createdAt" desc)
  where "jobType" = 'notification' and "participantDataRequestId" is not null;

create index "outbox_job_participant_claim_idx"
  on "vasi_engine"."outbox_job" ("availableAt", "createdAt", "id")
  where "status" = 'participant_pending';

alter table "vasi_engine"."participant_data_request_event"
  drop constraint "participant_data_request_event_eventType_check";

alter table "vasi_engine"."participant_data_request_event"
  add constraint "participant_data_request_event_event_type_check_v2"
  check ("eventType" in (
    'request.created', 'scope.approved', 'scope.denied', 'export.created',
    'export.preparation_failed', 'export.opened', 'export.downloaded',
    'export.expired', 'request.expired', 'request.cancelled',
    'notification.queued', 'notification.provider_accepted',
    'notification.suppressed', 'notification.failed'
  ));

create index "participant_data_request_preparation_idx"
  on "vasi_engine"."participant_data_request" ("updatedAt", "id")
  where "status" in ('approved', 'partially_approved');

revoke all on all tables in schema "vasi_engine" from PUBLIC;
