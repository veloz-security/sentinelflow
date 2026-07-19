-- This file runs only in the disposable version-33 repair database.

BEGIN;
CREATE EXTENSION IF NOT EXISTS dblink;
SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Commit this synthetic row so the independent dblink backend can lock it.
INSERT INTO incidents (
    incident_id, kind, state, source_ip, service_label, first_seen,
    last_seen, deterministic_score, version, evidence_version,
    created_at, updated_at
) VALUES (
    '019b3300-0000-7000-8000-000000000111', 'path_scan', 'open',
    '198.51.100.42/32', 'demo', clock_timestamp(), clock_timestamp(),
    0.90000, 2, 2, clock_timestamp(), clock_timestamp()
);
INSERT INTO incident_version_history (
    incident_id, incident_version, state, kind, source_ip, service_label,
    first_seen, last_seen, deterministic_score, mutation_kind,
    mutation_digest, evidence_digest, signal_count, recorded_at
) VALUES (
    '019b3300-0000-7000-8000-000000000111', 1, 'open', 'path_scan',
    '198.51.100.42/32', 'demo', clock_timestamp(), clock_timestamp(),
    0.90000, 'created',
    'sha256:3311000000000000000000000000000000000000000000000000000000000011',
    'sha256:3311000000000000000000000000000000000000000000000000000000000012',
    1, clock_timestamp()
);
INSERT INTO outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    operation, idempotency_key, state, available_at, lease_token,
    lease_owner, lease_expires_at, attempts, max_attempts,
    created_at, updated_at
) VALUES (
    '019b3300-0000-7000-8000-000000000211', 'analyze', 'incident',
    '019b3300-0000-7000-8000-000000000111', 1, NULL,
    'sha256:3311000000000000000000000000000000000000000000000000000000000021',
    'leased', clock_timestamp(),
    '019b3300-0000-4000-8000-000000000311', 'lock-expiry-test',
    clock_timestamp() + interval '350 milliseconds', 1, 2,
    clock_timestamp(), clock_timestamp()
);
COMMIT;

BEGIN;
SELECT public.dblink_connect(
    'analysis_lock_wait',
    'host=127.0.0.1 port=5432 dbname=' || current_database() ||
    ' user=postgres password=sentinelflow-test-only'
);
SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $lock_wait_expiry$
DECLARE
    locked boolean;
    remote_result text;
BEGIN
    PERFORM public.dblink_send_query('analysis_lock_wait',
        $remote$
        WITH locked AS (
            SELECT job_id FROM sentinelflow.outbox_jobs
            WHERE job_id = '019b3300-0000-7000-8000-000000000211'::uuid
            FOR UPDATE
        ), waited AS (
            SELECT pg_sleep(0.60) FROM locked
        )
        SELECT count(*)::text FROM waited
        $remote$);
    PERFORM pg_sleep(0.10);

    SELECT sentinelflow.resolve_queued_stale_analysis_000033(
        '019b3300-0000-7000-8000-000000000211',
        '019b3300-0000-4000-8000-000000000311'
    ) INTO locked;
    SELECT result INTO remote_result
    FROM public.dblink_get_result('analysis_lock_wait') AS completed(result text);
    PERFORM public.dblink_disconnect('analysis_lock_wait');

    IF locked OR remote_result <> '1' OR
       (SELECT state FROM sentinelflow.outbox_jobs
        WHERE job_id = '019b3300-0000-7000-8000-000000000211') <> 'leased' OR
       EXISTS (
           SELECT 1 FROM sentinelflow.audit_events
           WHERE object_id = '019b3300-0000-7000-8000-000000000211'
             AND action = 'analysis_superseded'
       ) THEN
        RAISE EXCEPTION 'lock-wait lease expiry crossed supersession boundary';
    END IF;
END
$lock_wait_expiry$;
COMMIT;

BEGIN;
SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Isolate the wrapper's activation/use ordering. The immutable dataset binding
-- itself is exhaustively tested by migration 30; this local replacement lets
-- the version-33 test exercise a real activation row and the real append-only
-- runtime-use recorder without reproducing the entire signed dataset.
ALTER FUNCTION sentinelflow.verify_demo_history_runtime_activation_000030(
    bytea, text, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz,
    timestamptz, text, text
) RENAME TO verify_demo_history_runtime_activation_test_original_000033;

CREATE FUNCTION sentinelflow.verify_demo_history_runtime_activation_000030(
    bytea, text, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz,
    timestamptz, text, text
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT true
$function$;

INSERT INTO demo_history_imports (
    import_id, schema_version, manifest_id, profile, dataset_id,
    dataset_schema_version, dataset_locator, raw_file_byte_sha256,
    manifest_dataset_jcs_digest, imported_rows_jcs_digest,
    imported_record_count, source_health_jcs_digest, manifest_digest,
    run_scope_digest, public_key_digest, signature_verification_digest,
    path_catalog_version, clock_at, issued_at, coverage_start, coverage_end,
    status, failure_code, attempt_count, started_at
) VALUES (
    '019b3300-0000-7000-8000-000000000401', 'demo-history-import-v1',
    '019b3300-0000-7000-8000-000000000402', 'isolated-demo',
    '019b0000-0000-7000-8000-000000000100',
    'demo-history-dataset-v1',
    'contracts/fixtures/demo_history_dataset_v1.json',
    'sha256:fe1b9e9ed59c74b1522acb63e1c0239cc3defb53f56fbe6125894403b3d341f9',
    'sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00',
    'sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807',
    4,
    'sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe',
    'sha256:3340000000000000000000000000000000000000000000000000000000000001',
    'sha256:3340000000000000000000000000000000000000000000000000000000000002',
    'sha256:3340000000000000000000000000000000000000000000000000000000000003',
    'sha256:3340000000000000000000000000000000000000000000000000000000000004',
    'path-catalog-v1', '2026-07-19 00:00:00+00',
    '2026-07-19 00:00:00+00', '2026-07-18 00:00:00+00',
    '2026-07-19 00:00:00+00', 'importing', NULL, 1,
    '2026-07-19 00:00:00+00'
);

INSERT INTO demo_history_runtime_activations (
    activation_secret_digest, activation_id, consumer, claims_digest,
    import_id, manifest_id, dataset_id, raw_file_digest,
    dataset_jcs_digest, imported_rows_digest, imported_record_count,
    manifest_source_health_digest, manifest_digest, run_scope_digest,
    public_key_digest, signature_verification_digest, clock_at, issued_at,
    coverage_start, coverage_end, impact_source_health_digest,
    activated_at, expires_at
) VALUES (
    sentinelflow.validation_sha256(decode(repeat('11', 32), 'hex')),
    '019b3300-0000-7000-8000-000000000403', 'analysis',
    'sha256:3340000000000000000000000000000000000000000000000000000000000005',
    '019b3300-0000-7000-8000-000000000401',
    '019b3300-0000-7000-8000-000000000402',
    '019b0000-0000-7000-8000-000000000100',
    'sha256:fe1b9e9ed59c74b1522acb63e1c0239cc3defb53f56fbe6125894403b3d341f9',
    'sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00',
    'sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807',
    4,
    'sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe',
    'sha256:3340000000000000000000000000000000000000000000000000000000000001',
    'sha256:3340000000000000000000000000000000000000000000000000000000000002',
    'sha256:3340000000000000000000000000000000000000000000000000000000000003',
    'sha256:3340000000000000000000000000000000000000000000000000000000000004',
    '2026-07-19 00:00:00+00', '2026-07-19 00:00:00+00',
    '2026-07-18 00:00:00+00', '2026-07-19 00:00:00+00',
    'sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3',
    clock_timestamp(), clock_timestamp() + interval '1 hour'
);

CREATE OR REPLACE FUNCTION pg_temp.make_demo_stale_job(
    p_incident_id uuid, p_job_id uuid, p_token uuid, p_seed text
)
RETURNS void
LANGUAGE plpgsql
SET search_path = sentinelflow, pg_catalog
AS $fixture$
BEGIN
    INSERT INTO incidents (
        incident_id, kind, state, source_ip, service_label, first_seen,
        last_seen, deterministic_score, version, evidence_version,
        created_at, updated_at
    ) VALUES (
        p_incident_id, 'path_scan', 'open', '198.51.100.42/32', 'demo',
        clock_timestamp(), clock_timestamp(), 0.90000, 2, 2,
        clock_timestamp(), clock_timestamp()
    );
    INSERT INTO incident_version_history (
        incident_id, incident_version, state, kind, source_ip, service_label,
        first_seen, last_seen, deterministic_score, mutation_kind,
        mutation_digest, evidence_digest, signal_count, recorded_at
    ) VALUES (
        p_incident_id, 1, 'open', 'path_scan', '198.51.100.42/32', 'demo',
        clock_timestamp(), clock_timestamp(), 0.90000, 'created',
        sentinelflow.analysis_sha256(convert_to('mutation-' || p_seed, 'UTF8')),
        sentinelflow.analysis_sha256(convert_to('evidence-' || p_seed, 'UTF8')),
        1, clock_timestamp()
    );
    INSERT INTO outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        operation, idempotency_key, state, available_at, lease_token,
        lease_owner, lease_expires_at, attempts, max_attempts,
        created_at, updated_at
    ) VALUES (
        p_job_id, 'analyze', 'incident', p_incident_id, 1, NULL,
        sentinelflow.analysis_sha256(convert_to('job-' || p_seed, 'UTF8')),
        'leased', clock_timestamp(), p_token, 'demo-stale-test',
        clock_timestamp() + interval '30 seconds', 1, 2,
        clock_timestamp(), clock_timestamp()
    );
END
$fixture$;

SELECT pg_temp.make_demo_stale_job(
    '019b3300-0000-7000-8000-000000000121',
    '019b3300-0000-7000-8000-000000000221',
    '019b3300-0000-4000-8000-000000000321', 'success'
);
SELECT pg_temp.make_demo_stale_job(
    '019b3300-0000-7000-8000-000000000122',
    '019b3300-0000-7000-8000-000000000222',
    '019b3300-0000-4000-8000-000000000322', 'rollback'
);

DO $verified_demo_use_and_rollback$
DECLARE
    prepared record;
    rejected boolean := false;
BEGIN
    SELECT * INTO prepared
    FROM sentinelflow.prepare_analysis_attempt_verified_demo_000030(
        '019b3300-0000-7000-8000-000000000221',
        '019b3300-0000-4000-8000-000000000321',
        decode(repeat('11', 32), 'hex'),
        '019b3300-0000-7000-8000-000000000401',
        '019b3300-0000-7000-8000-000000000402',
        '019b0000-0000-7000-8000-000000000100',
        'sha256:fe1b9e9ed59c74b1522acb63e1c0239cc3defb53f56fbe6125894403b3d341f9',
        'sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00',
        'sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807',
        4,
        'sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe',
        'sha256:3340000000000000000000000000000000000000000000000000000000000001',
        'sha256:3340000000000000000000000000000000000000000000000000000000000002',
        'sha256:3340000000000000000000000000000000000000000000000000000000000003',
        'sha256:3340000000000000000000000000000000000000000000000000000000000004',
        '2026-07-19 00:00:00+00', '2026-07-19 00:00:00+00',
        '2026-07-18 00:00:00+00', '2026-07-19 00:00:00+00',
        'sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3',
        'sha256:3340000000000000000000000000000000000000000000000000000000000005'
    );
    IF prepared.status <> 'terminal' OR prepared.snapshot IS NOT NULL OR
       NOT EXISTS (
           SELECT 1 FROM demo_history_runtime_uses runtime_use
           WHERE runtime_use.consumer = 'analysis'
             AND runtime_use.job_id = '019b3300-0000-7000-8000-000000000221'
             AND runtime_use.aggregate_id = '019b3300-0000-7000-8000-000000000121'
             AND runtime_use.aggregate_version = 1
       ) THEN
        RAISE EXCEPTION 'verified demo stale success lacked exact use receipt';
    END IF;

    INSERT INTO demo_history_runtime_uses (
        consumer, job_id, aggregate_id, aggregate_version,
        activation_secret_digest, used_at
    ) VALUES (
        'analysis', '019b3300-0000-7000-8000-000000000222',
        '019b3300-0000-7000-8000-000000000199', 1,
        sentinelflow.validation_sha256(decode(repeat('11', 32), 'hex')),
        clock_timestamp()
    );

    BEGIN
        PERFORM *
        FROM sentinelflow.prepare_analysis_attempt_verified_demo_000030(
            '019b3300-0000-7000-8000-000000000222',
            '019b3300-0000-4000-8000-000000000322',
            decode(repeat('11', 32), 'hex'),
            '019b3300-0000-7000-8000-000000000401',
            '019b3300-0000-7000-8000-000000000402',
            '019b0000-0000-7000-8000-000000000100',
            'sha256:fe1b9e9ed59c74b1522acb63e1c0239cc3defb53f56fbe6125894403b3d341f9',
            'sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00',
            'sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807',
            4,
            'sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe',
            'sha256:3340000000000000000000000000000000000000000000000000000000000001',
            'sha256:3340000000000000000000000000000000000000000000000000000000000002',
            'sha256:3340000000000000000000000000000000000000000000000000000000000003',
            'sha256:3340000000000000000000000000000000000000000000000000000000000004',
            '2026-07-19 00:00:00+00', '2026-07-19 00:00:00+00',
            '2026-07-18 00:00:00+00', '2026-07-19 00:00:00+00',
            'sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3',
            'sha256:3340000000000000000000000000000000000000000000000000000000000005'
        );
    EXCEPTION WHEN SQLSTATE 'SF006' THEN
        rejected := true;
    END;

    IF NOT rejected OR
       (SELECT state FROM outbox_jobs
        WHERE job_id = '019b3300-0000-7000-8000-000000000222') <> 'leased' OR
       EXISTS (
           SELECT 1 FROM audit_events audit
           WHERE audit.object_id = '019b3300-0000-7000-8000-000000000222'
             AND audit.action = 'analysis_superseded'
       ) OR EXISTS (
           SELECT 1 FROM demo_history_runtime_uses runtime_use
           WHERE runtime_use.consumer = 'analysis'
             AND runtime_use.job_id = '019b3300-0000-7000-8000-000000000222'
             AND runtime_use.aggregate_id = '019b3300-0000-7000-8000-000000000122'
       ) THEN
        RAISE EXCEPTION 'failed demo use did not roll back stale resolution';
    END IF;
END
$verified_demo_use_and_rollback$;

ROLLBACK;
