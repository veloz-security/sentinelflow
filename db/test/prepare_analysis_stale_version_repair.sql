BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

CREATE OR REPLACE FUNCTION pg_temp.make_stale_dead_fixture(
    p_incident_id uuid,
    p_job_id uuid,
    p_mutation_digest sentinelflow.sha256_digest,
    p_dead_attempts integer DEFAULT 1
)
RETURNS void
LANGUAGE plpgsql
SET search_path = sentinelflow, pg_catalog
AS $fixture$
DECLARE
    observed_at timestamptz := clock_timestamp() - interval '1 minute';
    missing_digest sentinelflow.sha256_digest :=
        sentinelflow.analysis_sha256(convert_to('analysis_incident_missing', 'UTF8'));
BEGIN
    INSERT INTO incidents (
        incident_id, kind, state, source_ip, service_label, first_seen,
        last_seen, deterministic_score, version, evidence_version,
        created_at, updated_at
    ) VALUES (
        p_incident_id, 'path_scan', 'open', '198.51.100.42/32', 'demo',
        observed_at, observed_at, 0.90000, 2, 2, observed_at, observed_at
    );
    INSERT INTO incident_version_history (
        incident_id, incident_version, state, kind, source_ip, service_label,
        first_seen, last_seen, deterministic_score, mutation_kind,
        mutation_digest, evidence_digest, signal_count, recorded_at
    ) VALUES (
        p_incident_id, 1, 'open', 'path_scan', '198.51.100.42/32',
        'demo', observed_at, observed_at, 0.90000, 'created',
        p_mutation_digest,
        sentinelflow.analysis_sha256(convert_to(p_incident_id::text, 'UTF8')),
        1, observed_at
    );
    INSERT INTO outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        operation, idempotency_key, state, available_at, attempts,
        max_attempts, last_error_code, last_error_digest,
        created_at, updated_at
    ) VALUES (
        p_job_id, 'analyze', 'incident', p_incident_id, 1, NULL,
        sentinelflow.analysis_sha256(convert_to(p_job_id::text, 'UTF8')),
        'dead', observed_at, 1, 2, 'analysis_incident_missing',
        missing_digest, observed_at, observed_at
    );
    INSERT INTO dead_letter_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        attempts, failure_code, failure_digest, dead_at
    ) VALUES (
        p_job_id, 'analyze', 'incident', p_incident_id, 1,
        p_dead_attempts, 'analysis_incident_missing', missing_digest,
        observed_at
    );
END
$fixture$;

-- Exact copied identity and no provider claim: this row must be repaired.
SELECT pg_temp.make_stale_dead_fixture(
    '019b3300-0000-7000-8000-000000000101',
    '019b3300-0000-7000-8000-000000000201',
    'sha256:3301000000000000000000000000000000000000000000000000000000000001'
);

-- A claim is immutable provider-bound evidence, even when the old missing
-- classification is present. Migration 33 must leave it untouched.
SELECT pg_temp.make_stale_dead_fixture(
    '019b3300-0000-7000-8000-000000000102',
    '019b3300-0000-7000-8000-000000000202',
    'sha256:3302000000000000000000000000000000000000000000000000000000000002'
);
INSERT INTO analysis_attempt_claims (
    analysis_id, job_id, incident_id, incident_version, outbox_attempt,
    state, no_call_code, generated_at, terminal_at,
    terminal_incident_version
) VALUES (
    '019b3300-0000-7000-8000-000000000302',
    '019b3300-0000-7000-8000-000000000202',
    '019b3300-0000-7000-8000-000000000102', 1, 1,
    'no_call', 'input_too_large', clock_timestamp(), clock_timestamp(), 2
);

-- The dead-letter attempts field is not an exact copy of the outbox row.
-- This anomaly must remain unresolved for operator review.
SELECT pg_temp.make_stale_dead_fixture(
    '019b3300-0000-7000-8000-000000000103',
    '019b3300-0000-7000-8000-000000000203',
    'sha256:3303000000000000000000000000000000000000000000000000000000000003',
    2
);

COMMIT;
