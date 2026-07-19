BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

INSERT INTO outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    operation, idempotency_key, state, available_at, max_attempts,
    created_at, updated_at
) VALUES (
    '019b0000-0000-7000-8000-000000007001', 'detect', 'incident',
    '019b0000-0000-7000-8000-000000007101', 1, NULL,
    'sha256:0101010101010101010101010101010101010101010101010101010101010101',
    'pending', clock_timestamp() - interval '1 hour', 2,
    clock_timestamp() - interval '1 hour', clock_timestamp() - interval '1 hour'
);

DO $lease_expiry_and_dead_letter_fencing$
DECLARE
    client_now timestamptz;
    leased outbox_jobs%ROWTYPE;
    none outbox_jobs%ROWTYPE;
    finished outbox_jobs%ROWTYPE;
BEGIN
    client_now := clock_timestamp();
    SELECT * INTO leased FROM lease_worker_outbox_job(
        client_now,
        '019b0000-0000-7000-8000-000000007201',
        'worker-one',
        client_now + interval '10 seconds'
    );
    IF leased.job_id IS NULL OR leased.attempts <> 1 OR leased.state <> 'leased' OR
       leased.lease_expires_at - leased.updated_at <> interval '10 seconds' THEN
        RAISE EXCEPTION 'pending job was not leased exactly once with a server-timed lease';
    END IF;

    -- A caller-supplied future clock must not make a live lease reclaimable.
    client_now := clock_timestamp() + interval '1 hour';
    SELECT * INTO none FROM lease_worker_outbox_job(
        client_now,
        '019b0000-0000-7000-8000-000000007202',
        'worker-two',
        client_now + interval '10 seconds'
    );
    IF none.job_id IS NOT NULL THEN
        RAISE EXCEPTION 'caller clock bypassed authoritative server lease time';
    END IF;

    -- Simulate expiry without a wall-clock wait, then prove a stale caller clock
    -- cannot complete work after the authoritative database lease has expired.
    UPDATE outbox_jobs
    SET updated_at = clock_timestamp() - interval '2 seconds',
        lease_expires_at = clock_timestamp() - interval '1 second'
    WHERE job_id = leased.job_id;

    SELECT * INTO finished FROM finish_worker_outbox_job(
        'completed', NULL, NULL, NULL,
        clock_timestamp() - interval '1 hour', leased.job_id, leased.lease_token
    );
    IF finished.job_id IS NOT NULL THEN
        RAISE EXCEPTION 'stale caller clock bypassed authoritative lease expiry';
    END IF;

    client_now := clock_timestamp();
    SELECT * INTO leased FROM lease_worker_outbox_job(
        client_now,
        '019b0000-0000-7000-8000-000000007203',
        'worker-three',
        client_now + interval '10 seconds'
    );
    IF leased.job_id IS NULL OR leased.attempts <> 2 OR
       leased.lease_token <> '019b0000-0000-7000-8000-000000007203' THEN
        RAISE EXCEPTION 'expired lease was not reclaimed with a fenced token';
    END IF;

    SELECT * INTO finished FROM finish_worker_outbox_job(
        'dead', NULL, 'detector_failed',
        'sha256:0202020202020202020202020202020202020202020202020202020202020202',
        clock_timestamp(), leased.job_id,
        '019b0000-0000-7000-8000-000000007299'
    );
    IF finished.job_id IS NOT NULL THEN
        RAISE EXCEPTION 'wrong lease token completed a job';
    END IF;

    SELECT * INTO finished FROM finish_worker_outbox_job(
        'dead', NULL, 'detector_failed',
        'sha256:0202020202020202020202020202020202020202020202020202020202020202',
        clock_timestamp(), leased.job_id, leased.lease_token
    );
    IF finished.state <> 'dead' OR NOT EXISTS (
        SELECT 1 FROM dead_letter_jobs dead
        WHERE dead.job_id = leased.job_id
          AND dead.attempts = 2
          AND dead.failure_code = 'detector_failed'
          AND dead.failure_digest =
              'sha256:0202020202020202020202020202020202020202020202020202020202020202'
    ) THEN
        RAISE EXCEPTION 'dead state and dead-letter evidence were not atomic';
    END IF;
END
$lease_expiry_and_dead_letter_fencing$;

DO $business_effect_is_unique$
BEGIN
    BEGIN
        INSERT INTO outbox_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            operation, idempotency_key, state, available_at
        ) VALUES (
            '019b0000-0000-7000-8000-000000007002', 'detect', 'incident',
            '019b0000-0000-7000-8000-000000007101', 1, NULL,
            'sha256:0303030303030303030303030303030303030303030303030303030303030303',
            'pending', clock_timestamp()
        );
        RAISE EXCEPTION 'duplicate business effect was accepted';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;
END
$business_effect_is_unique$;

INSERT INTO outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    operation, idempotency_key, state, available_at, max_attempts,
    created_at, updated_at
) VALUES (
    '019b0000-0000-7000-8000-000000007003', 'analyze', 'incident',
    '019b0000-0000-7000-8000-000000007103', 1, NULL,
    'sha256:0404040404040404040404040404040404040404040404040404040404040404',
    'pending', clock_timestamp() - interval '1 hour', 1,
    clock_timestamp() - interval '1 hour', clock_timestamp() - interval '1 hour'
);

DO $crashed_final_attempt_becomes_dead$
DECLARE
    client_now timestamptz;
    leased outbox_jobs%ROWTYPE;
    none outbox_jobs%ROWTYPE;
BEGIN
    client_now := clock_timestamp();
    SELECT * INTO leased FROM lease_worker_outbox_job(
        client_now,
        '019b0000-0000-7000-8000-000000007204',
        'worker-four',
        client_now + interval '10 seconds'
    );
    IF leased.job_id <> '019b0000-0000-7000-8000-000000007003' OR leased.attempts <> 1 THEN
        RAISE EXCEPTION 'final attempt was not leased';
    END IF;

    UPDATE outbox_jobs
    SET updated_at = clock_timestamp() - interval '2 seconds',
        lease_expires_at = clock_timestamp() - interval '1 second'
    WHERE job_id = leased.job_id;

    client_now := clock_timestamp();
    SELECT * INTO none FROM lease_worker_outbox_job(
        client_now,
        '019b0000-0000-7000-8000-000000007205',
        'worker-five',
        client_now + interval '10 seconds'
    );
    IF none.job_id IS NOT NULL OR NOT EXISTS (
        SELECT 1 FROM outbox_jobs job
        JOIN dead_letter_jobs dead USING (job_id)
        WHERE job.job_id = leased.job_id
          AND job.state = 'dead'
          AND job.last_error_code = 'lease_expired'
          AND dead.failure_code = 'lease_expired'
    ) THEN
        RAISE EXCEPTION 'crashed final attempt remained stranded or unaudited';
    END IF;
END
$crashed_final_attempt_becomes_dead$;

INSERT INTO outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    operation, idempotency_key, state, available_at, max_attempts,
    created_at, updated_at
) VALUES (
    '019b0000-0000-7000-8000-000000007004', 'correlate', 'incident',
    '019b0000-0000-7000-8000-000000007104', 1, NULL,
    'sha256:0505050505050505050505050505050505050505050505050505050505050505',
    'pending', clock_timestamp() - interval '1 hour', 2,
    clock_timestamp() - interval '1 hour', clock_timestamp() - interval '1 hour'
);

DO $retry_availability_and_completion_are_fenced$
DECLARE
    client_now timestamptz;
    leased outbox_jobs%ROWTYPE;
    retried outbox_jobs%ROWTYPE;
    none outbox_jobs%ROWTYPE;
    completed outbox_jobs%ROWTYPE;
BEGIN
    client_now := clock_timestamp();
    SELECT * INTO leased FROM lease_worker_outbox_job(
        client_now,
        '019b0000-0000-7000-8000-000000007206',
        'worker-six',
        client_now + interval '10 seconds'
    );

    client_now := clock_timestamp();
    SELECT * INTO retried FROM finish_worker_outbox_job(
        'retry', client_now + interval '250 milliseconds', 'temporary_failure',
        'sha256:0606060606060606060606060606060606060606060606060606060606060606',
        client_now, leased.job_id, leased.lease_token
    );
    IF retried.state <> 'retry' THEN
        RAISE EXCEPTION 'valid retry was not recorded';
    END IF;

    -- A future caller clock cannot make server-scheduled retry work available.
    client_now := clock_timestamp() + interval '1 hour';
    SELECT * INTO none FROM lease_worker_outbox_job(
        client_now,
        '019b0000-0000-7000-8000-000000007207',
        'worker-seven',
        client_now + interval '10 seconds'
    );
    IF none.job_id IS NOT NULL THEN
        RAISE EXCEPTION 'caller clock leased retry before authoritative available_at';
    END IF;

    PERFORM pg_sleep(0.3);
    client_now := clock_timestamp();
    SELECT * INTO leased FROM lease_worker_outbox_job(
        client_now,
        '019b0000-0000-7000-8000-000000007208',
        'worker-eight',
        client_now + interval '10 seconds'
    );
    SELECT * INTO completed FROM finish_worker_outbox_job(
        'completed', NULL, NULL, NULL,
        clock_timestamp(), leased.job_id, leased.lease_token
    );
    IF completed.state <> 'completed' OR completed.attempts <> 2 THEN
        RAISE EXCEPTION 'retried job did not complete under the second lease';
    END IF;
END
$retry_availability_and_completion_are_fenced$;

ROLLBACK;
