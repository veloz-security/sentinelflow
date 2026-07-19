BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

CREATE UNIQUE INDEX IF NOT EXISTS outbox_jobs_business_effect_idx
    ON outbox_jobs (
        kind, aggregate_type, aggregate_id, aggregate_version, operation
    ) NULLS NOT DISTINCT;

CREATE OR REPLACE FUNCTION sentinelflow.lease_worker_outbox_job(
    p_now timestamptz,
    p_lease_token uuid,
    p_lease_owner text,
    p_lease_expires_at timestamptz
)
RETURNS SETOF sentinelflow.outbox_jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    leased sentinelflow.outbox_jobs%ROWTYPE;
    exhausted sentinelflow.outbox_jobs%ROWTYPE;
    server_now timestamptz := clock_timestamp();
    requested_lease_duration interval;
BEGIN
    requested_lease_duration := p_lease_expires_at - p_now;

    IF p_now IS NULL OR p_lease_token IS NULL OR p_lease_owner IS NULL OR
       p_lease_expires_at IS NULL OR
       NOT isfinite(p_now) OR NOT isfinite(p_lease_expires_at) OR
       p_lease_owner !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       requested_lease_duration <= interval '0 seconds' OR
       requested_lease_duration > interval '60 seconds' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid worker lease request';
    END IF;

    -- A crashed final attempt cannot remain leased forever. Transition it and
    -- its dead-letter evidence together before selecting new work.
    FOR exhausted IN
        WITH exhausted_candidates AS (
            SELECT candidate.job_id
            FROM sentinelflow.outbox_jobs candidate
            WHERE candidate.kind NOT IN (
                'dispatch_add', 'dispatch_revoke', 'dispatch_inspect'
            )
              AND candidate.state = 'leased'
              AND candidate.lease_expires_at <= server_now
              AND candidate.attempts >= candidate.max_attempts
            ORDER BY candidate.lease_expires_at, candidate.job_id
            FOR UPDATE SKIP LOCKED
            LIMIT 100
        )
        UPDATE sentinelflow.outbox_jobs job
        SET state = 'dead',
            lease_token = NULL,
            lease_owner = NULL,
            lease_expires_at = NULL,
            last_error_code = 'lease_expired',
            last_error_digest =
                'sha256:7ab6162a99777850888eb96ce59cf7bc74357fb33821a16030a07d1af3932804',
            updated_at = server_now
        FROM exhausted_candidates candidate
        WHERE job.job_id = candidate.job_id
        RETURNING job.*
    LOOP
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest, dead_at
        ) VALUES (
            exhausted.job_id, exhausted.kind, exhausted.aggregate_type,
            exhausted.aggregate_id, exhausted.aggregate_version,
            exhausted.attempts, exhausted.last_error_code,
            exhausted.last_error_digest, server_now
        );
    END LOOP;

    SELECT candidate.*
    INTO leased
    FROM sentinelflow.outbox_jobs candidate
    WHERE candidate.kind NOT IN ('dispatch_add', 'dispatch_revoke', 'dispatch_inspect')
      AND candidate.attempts < candidate.max_attempts
      AND (
          (candidate.state IN ('pending', 'retry') AND candidate.available_at <= server_now) OR
          (candidate.state = 'leased' AND candidate.lease_expires_at <= server_now)
      )
    ORDER BY candidate.available_at, candidate.created_at, candidate.job_id
    FOR UPDATE SKIP LOCKED
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    UPDATE sentinelflow.outbox_jobs job
    SET state = 'leased',
        lease_token = p_lease_token,
        lease_owner = p_lease_owner,
        lease_expires_at = server_now + requested_lease_duration,
        attempts = job.attempts + 1,
        last_error_code = NULL,
        last_error_digest = NULL,
        updated_at = server_now
    WHERE job.job_id = leased.job_id
    RETURNING job.* INTO leased;

    RETURN NEXT leased;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finish_worker_outbox_job(
    p_state text,
    p_retry_at timestamptz,
    p_error_code text,
    p_error_digest text,
    p_now timestamptz,
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS SETOF sentinelflow.outbox_jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    finished sentinelflow.outbox_jobs%ROWTYPE;
    server_now timestamptz := clock_timestamp();
    requested_retry_delay interval;
BEGIN
    requested_retry_delay := p_retry_at - p_now;

    IF p_state IS NULL OR p_state NOT IN ('completed', 'retry', 'dead') OR
       p_now IS NULL OR p_job_id IS NULL OR p_lease_token IS NULL OR
       NOT isfinite(p_now) OR
       (p_retry_at IS NOT NULL AND NOT isfinite(p_retry_at)) OR
       (p_state = 'retry' AND (p_retry_at IS NULL OR p_retry_at < p_now)) OR
       (p_state <> 'retry' AND p_retry_at IS NOT NULL) OR
       (p_state = 'completed' AND (p_error_code IS NOT NULL OR p_error_digest IS NOT NULL)) OR
       (p_state <> 'completed' AND (
           p_error_code IS NULL OR p_error_digest IS NULL OR
           p_error_code !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
           p_error_digest !~ '^sha256:[0-9a-f]{64}$'
       )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid worker lease completion';
    END IF;

    UPDATE sentinelflow.outbox_jobs job
    SET state = p_state,
        available_at = CASE
            WHEN p_state = 'retry' THEN server_now + requested_retry_delay
            ELSE job.available_at
        END,
        lease_token = NULL,
        lease_owner = NULL,
        lease_expires_at = NULL,
        last_error_code = CASE WHEN p_state = 'completed' THEN NULL ELSE p_error_code END,
        last_error_digest = CASE WHEN p_state = 'completed' THEN NULL ELSE p_error_digest END,
        updated_at = server_now
    WHERE job.job_id = p_job_id
      AND job.state = 'leased'
      AND job.lease_token = p_lease_token
      AND job.lease_expires_at > server_now
      AND job.updated_at <= server_now
      AND (p_state <> 'retry' OR job.attempts < job.max_attempts)
    RETURNING job.* INTO finished;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF finished.state = 'dead' THEN
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest, dead_at
        ) VALUES (
            finished.job_id, finished.kind, finished.aggregate_type,
            finished.aggregate_id, finished.aggregate_version,
            finished.attempts, finished.last_error_code,
            finished.last_error_digest, server_now
        );
    END IF;

    RETURN NEXT finished;
END
$function$;

REVOKE UPDATE (
    state, available_at, lease_token, lease_owner, lease_expires_at, attempts,
    last_error_code, last_error_digest, updated_at
) ON sentinelflow.outbox_jobs FROM sentinelflow_api, sentinelflow_worker;

REVOKE INSERT ON sentinelflow.dead_letter_jobs FROM sentinelflow_worker;

REVOKE ALL ON FUNCTION sentinelflow.lease_worker_outbox_job(
    timestamptz, uuid, text, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.lease_worker_outbox_job(
    timestamptz, uuid, text, timestamptz
) TO sentinelflow_worker;

REVOKE ALL ON FUNCTION sentinelflow.finish_worker_outbox_job(
    text, timestamptz, text, text, timestamptz, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finish_worker_outbox_job(
    text, timestamptz, text, text, timestamptz, uuid, uuid
) TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (6, 'outbox_lease_fencing')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
