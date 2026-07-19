BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $verify_repair$
DECLARE
    missing_digest sentinelflow.sha256_digest :=
        sentinelflow.analysis_sha256(convert_to('analysis_incident_missing', 'UTF8'));
    expected_correction sentinelflow.sha256_digest;
BEGIN
    expected_correction := sentinelflow.analysis_sha256(convert_to(
        'queued-analysis-superseded-reconciliation-v1' || chr(10) ||
        '019b3300-0000-7000-8000-000000000201' || chr(10) ||
        '019b3300-0000-7000-8000-000000000101' || chr(10) ||
        '1' || chr(10) || '2' || chr(10) || missing_digest::text || chr(10),
        'UTF8'
    ));

    IF (SELECT state FROM outbox_jobs
        WHERE job_id = '019b3300-0000-7000-8000-000000000201') <> 'completed' OR
       NOT EXISTS (
           SELECT 1 FROM dead_letter_jobs dead
           WHERE dead.job_id = '019b3300-0000-7000-8000-000000000201'
             AND dead.resolution_state = 'resolved'
             AND dead.resolution_actor = 'sentinelflow_migration'
             AND dead.resolution_digest = expected_correction
       ) OR (SELECT count(*) FROM audit_events audit
             WHERE audit.action = 'analysis_superseded_reconciled'
               AND audit.object_id = '019b3300-0000-7000-8000-000000000201'
               AND audit.incident_id = '019b3300-0000-7000-8000-000000000101'
               AND audit.primary_digest = expected_correction
               AND audit.secondary_digest = missing_digest
               AND audit.outcome = 'rejected') <> 1 THEN
        RAISE EXCEPTION 'exact stale missing repair was not digest-bound';
    END IF;

    IF EXISTS (
        SELECT 1 FROM outbox_jobs job
        WHERE job.job_id IN (
            '019b3300-0000-7000-8000-000000000202',
            '019b3300-0000-7000-8000-000000000203'
        ) AND job.state <> 'dead'
    ) OR EXISTS (
        SELECT 1 FROM dead_letter_jobs dead
        WHERE dead.job_id IN (
            '019b3300-0000-7000-8000-000000000202',
            '019b3300-0000-7000-8000-000000000203'
        ) AND dead.resolution_state <> 'unresolved'
    ) OR EXISTS (
        SELECT 1 FROM audit_events audit
        WHERE audit.object_id IN (
            '019b3300-0000-7000-8000-000000000202',
            '019b3300-0000-7000-8000-000000000203'
        ) AND audit.action = 'analysis_superseded_reconciled'
    ) THEN
        RAISE EXCEPTION 'claimed or mismatched stale dead letter was repaired';
    END IF;
END
$verify_repair$;

ROLLBACK;
