\set ON_ERROR_STOP on

DO $$
BEGIN
  IF current_database() NOT LIKE 'restorecheck\_%' ESCAPE '\' THEN
    RAISE EXCEPTION 'Refusing to inspect a database outside the restorecheck_ namespace';
  END IF;
END
$$;

DO $$
DECLARE
  expected_table text;
BEGIN
  FOREACH expected_table IN ARRAY ARRAY[
    'User',
    'Envelope',
    'EnvelopeItem',
    'DocumentData',
    'DocumentAuditLog',
    'Recipient',
    'Field',
    'Signature',
    'EnvelopeAttachment',
    'BackgroundJob'
  ]
  LOOP
    IF to_regclass(format('public.%I', expected_table)) IS NULL THEN
      RAISE EXCEPTION 'Expected VASI table is missing: %', expected_table;
    END IF;
  END LOOP;
END
$$;

DO $$
DECLARE
  completed_migrations integer;
  incomplete_migrations integer;
BEGIN
  SELECT count(*) INTO completed_migrations
  FROM public._prisma_migrations
  WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL;

  SELECT count(*) INTO incomplete_migrations
  FROM public._prisma_migrations
  WHERE finished_at IS NULL OR rolled_back_at IS NOT NULL;

  IF completed_migrations <> 163 OR incomplete_migrations <> 0 THEN
    RAISE EXCEPTION 'Unexpected migration state: completed=%, incomplete_or_rolled_back=%',
      completed_migrations, incomplete_migrations;
  END IF;
END
$$;

SELECT 'users' AS data_class, count(*) AS row_count, 0::bigint AS stored_characters
FROM public."User"
UNION ALL
SELECT 'envelopes', count(*), 0
FROM public."Envelope"
UNION ALL
SELECT 'document_data', count(*), coalesce(sum(length(data) + length("initialData")), 0)
FROM public."DocumentData"
UNION ALL
SELECT 'attachments', count(*), coalesce(sum(length(data)), 0)
FROM public."EnvelopeAttachment"
UNION ALL
SELECT 'recipients', count(*), 0
FROM public."Recipient"
UNION ALL
SELECT 'signatures', count(*), coalesce(sum(length(coalesce("signatureImageAsBase64", ''))), 0)
FROM public."Signature"
UNION ALL
SELECT 'document_audit_logs', count(*), 0
FROM public."DocumentAuditLog"
UNION ALL
SELECT 'background_jobs', count(*), 0
FROM public."BackgroundJob"
ORDER BY data_class;

SELECT count(*) AS orphaned_envelope_items
FROM public."EnvelopeItem" item
LEFT JOIN public."DocumentData" data ON data.id = item."documentDataId"
WHERE data.id IS NULL;
