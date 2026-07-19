BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- The original bootstrap schema deliberately kept the detector projection
-- small. These columns bind every newly persisted signal to the exact frozen
-- configuration and deterministic signal bytes. They remain nullable only so
-- a deployment with pre-000016 historical rows can migrate without inventing
-- provenance for those rows.
ALTER TABLE signals
    ADD COLUMN IF NOT EXISTS configuration_version ascii_id NULL,
    ADD COLUMN IF NOT EXISTS configuration_digest sha256_digest NULL,
    ADD COLUMN IF NOT EXISTS signal_digest sha256_digest NULL;

CREATE UNIQUE INDEX IF NOT EXISTS signals_signal_digest_idx
    ON signals (signal_digest)
    WHERE signal_digest IS NOT NULL;

ALTER TABLE auth_events
    ADD COLUMN IF NOT EXISTS binding_resolved_at timestamptz NULL;

UPDATE auth_events
SET binding_resolved_at = received_at
WHERE binding_state <> 'pending' AND binding_resolved_at IS NULL;

ALTER TABLE auth_events DROP CONSTRAINT IF EXISTS auth_event_binding_resolution;
ALTER TABLE auth_events ADD CONSTRAINT auth_event_binding_resolution CHECK (
    (binding_state = 'pending' AND binding_resolved_at IS NULL) OR
    (binding_state <> 'pending' AND binding_resolved_at IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS detector_runs (
    job_id uuid PRIMARY KEY REFERENCES outbox_jobs (job_id) ON DELETE RESTRICT,
    aggregate_type ascii_id NOT NULL CHECK (aggregate_type IN ('ingest_batch', 'auth_binding')),
    aggregate_id uuid NOT NULL,
    aggregate_version integer NOT NULL CHECK (aggregate_version = 1),
    configuration_version ascii_id NOT NULL,
    configuration_digest sha256_digest NOT NULL,
    evaluated_at timestamptz NOT NULL,
    input_digest sha256_digest NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('complete', 'incomplete', 'no_candidates')),
    signal_count integer NOT NULL CHECK (signal_count BETWEEN 0 AND 10000),
    incident_mutation_count integer NOT NULL CHECK (incident_mutation_count BETWEEN 0 AND 10000),
    completed_at timestamptz NOT NULL,
    UNIQUE (aggregate_type, aggregate_id, aggregate_version),
    CONSTRAINT detector_run_outcome CHECK (
        outcome = 'complete' OR
        (signal_count = 0 AND incident_mutation_count = 0)
    )
);

CREATE TABLE IF NOT EXISTS detector_run_signals (
    job_id uuid NOT NULL REFERENCES detector_runs (job_id) ON DELETE CASCADE,
    signal_id uuid NOT NULL REFERENCES signals (signal_id) ON DELETE RESTRICT,
    disposition text NOT NULL CHECK (disposition IN ('created', 'duplicate')),
    incident_id uuid NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    incident_version integer NOT NULL CHECK (incident_version >= 1),
    PRIMARY KEY (job_id, signal_id)
);

-- incidents is the current mutable projection. These two append-only tables
-- preserve every evidence/state version and its complete signal membership.
CREATE TABLE IF NOT EXISTS incident_version_history (
    incident_id uuid NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    incident_version integer NOT NULL CHECK (incident_version >= 1),
    state text NOT NULL CHECK (state IN ('open', 'analyzing', 'review_ready', 'analysis_failed', 'closed')),
    kind text NOT NULL CHECK (kind IN (
        'credential_stuffing', 'brute_force', 'path_scan', 'request_burst', 'mixed', 'unknown'
    )),
    source_ip canonical_ipv4 NOT NULL,
    service_label event_label NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    closed_at timestamptz NULL,
    reopen_until timestamptz NULL,
    deterministic_score numeric(6,5) NOT NULL CHECK (deterministic_score BETWEEN 0 AND 1),
    mutation_kind text NOT NULL CHECK (mutation_kind IN (
        'created', 'signal_added', 'reopened', 'closed', 'state_changed'
    )),
    mutation_digest sha256_digest NOT NULL UNIQUE,
    evidence_digest sha256_digest NOT NULL,
    signal_count integer NOT NULL CHECK (signal_count BETWEEN 1 AND 10000),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (incident_id, incident_version),
    CONSTRAINT incident_version_time_order CHECK (last_seen >= first_seen),
    CONSTRAINT incident_version_closed_shape CHECK (
        (state = 'closed' AND closed_at IS NOT NULL AND reopen_until IS NOT NULL AND reopen_until >= closed_at) OR
        (state <> 'closed' AND closed_at IS NULL AND reopen_until IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS incident_version_signals (
    incident_id uuid NOT NULL,
    incident_version integer NOT NULL,
    signal_id uuid NOT NULL REFERENCES signals (signal_id) ON DELETE RESTRICT,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 10000),
    PRIMARY KEY (incident_id, incident_version, signal_id),
    UNIQUE (incident_id, incident_version, ordinal),
    FOREIGN KEY (incident_id, incident_version)
        REFERENCES incident_version_history (incident_id, incident_version)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS incident_version_history_source_time_idx
    ON incident_version_history (source_ip, last_seen, incident_id, incident_version);

CREATE OR REPLACE FUNCTION sentinelflow.reject_detection_history_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'detector evidence and incident version history are immutable';
END
$function$;

DO $immutable_projection_triggers$
DECLARE
    table_name text;
    trigger_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'signals', 'signal_evidence', 'detector_runs', 'detector_run_signals',
        'incident_version_history', 'incident_version_signals'
    ]
    LOOP
        trigger_name := table_name || '_reject_update';
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgrelid = ('sentinelflow.' || table_name)::regclass
              AND tgname = trigger_name AND NOT tgisinternal
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER %I BEFORE UPDATE ON sentinelflow.%I '
                'FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_detection_history_update()',
                trigger_name, table_name
            );
        END IF;
    END LOOP;
END
$immutable_projection_triggers$;

CREATE OR REPLACE FUNCTION sentinelflow.detection_sha256(p_bytes bytea)
RETURNS sentinelflow.sha256_digest
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT ('sha256:' || encode(sha256(p_bytes), 'hex'))::sentinelflow.sha256_digest;
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.detection_uuid_v8(p_bytes bytea)
RETURNS uuid
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
DECLARE
    digest_bytes bytea := sha256(p_bytes);
    uuid_bytes bytea;
    encoded text;
BEGIN
    uuid_bytes := substring(digest_bytes FROM 1 FOR 16);
    uuid_bytes := set_byte(uuid_bytes, 6, (get_byte(uuid_bytes, 6) & 15) | 128);
    uuid_bytes := set_byte(uuid_bytes, 8, (get_byte(uuid_bytes, 8) & 63) | 128);
    encoded := encode(uuid_bytes, 'hex');
    RETURN (
        substring(encoded FROM 1 FOR 8) || '-' ||
        substring(encoded FROM 9 FOR 4) || '-' ||
        substring(encoded FROM 13 FOR 4) || '-' ||
        substring(encoded FROM 17 FOR 4) || '-' ||
        substring(encoded FROM 21 FOR 12)
    )::uuid;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.stamp_auth_binding_resolution()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF OLD.binding_state = 'pending' AND NEW.binding_state <> 'pending' THEN
        NEW.binding_resolved_at := clock_timestamp();
    ELSIF NEW.binding_state = 'pending' THEN
        NEW.binding_resolved_at := NULL;
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS auth_events_binding_resolution_stamp ON auth_events;
CREATE TRIGGER auth_events_binding_resolution_stamp
BEFORE UPDATE OF binding_state ON auth_events
FOR EACH ROW EXECUTE FUNCTION sentinelflow.stamp_auth_binding_resolution();

CREATE OR REPLACE FUNCTION sentinelflow.enqueue_auth_binding_detection()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    canonical bytea;
    digest_value sentinelflow.sha256_digest;
    job_id_value uuid;
    existing sentinelflow.outbox_jobs%ROWTYPE;
BEGIN
    IF OLD.binding_state <> 'pending' OR NEW.binding_state = 'pending' THEN
        RETURN NULL;
    END IF;
    canonical := convert_to(
        'sentinelflow auth-binding detect v1' || chr(10) ||
        NEW.event_id::text || chr(10) || NEW.binding_state || chr(10) ||
        NEW.binding_reason || chr(10), 'UTF8');
    digest_value := sentinelflow.detection_sha256(canonical);
    job_id_value := sentinelflow.detection_uuid_v8(canonical);

    SELECT * INTO existing FROM sentinelflow.outbox_jobs job
    WHERE job.job_id = job_id_value OR job.idempotency_key = digest_value
    FOR UPDATE;
    IF FOUND THEN
        IF existing.job_id <> job_id_value OR existing.kind <> 'detect' OR
           existing.aggregate_type <> 'auth_binding' OR existing.aggregate_id <> NEW.event_id OR
           existing.aggregate_version <> 1 OR existing.idempotency_key <> digest_value THEN
            RAISE EXCEPTION USING ERRCODE = '23505',
                MESSAGE = 'auth binding detection identity conflict';
        END IF;
        RETURN NULL;
    END IF;
    INSERT INTO sentinelflow.outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        idempotency_key, state, available_at, max_attempts
    ) VALUES (
        job_id_value, 'detect', 'auth_binding', NEW.event_id, 1,
        digest_value, 'pending', NEW.binding_resolved_at, 8
    );
    RETURN NULL;
END
$function$;

DROP TRIGGER IF EXISTS auth_events_enqueue_detection ON auth_events;
CREATE TRIGGER auth_events_enqueue_detection
AFTER UPDATE OF binding_state, binding_reason, bound_gateway_event_id ON auth_events
FOR EACH ROW EXECUTE FUNCTION sentinelflow.enqueue_auth_binding_detection();

-- Only one detection lease may be live. This intentionally favors stable
-- arrival-order convergence over speculative parallel processing of the same
-- source. The rest of the worker fleet remains independently concurrent.
CREATE OR REPLACE FUNCTION sentinelflow.lease_detection_outbox_job(
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
    IF p_now IS NULL OR p_lease_token IS NULL OR p_lease_owner IS NULL OR
       p_lease_expires_at IS NULL OR NOT isfinite(p_now) OR NOT isfinite(p_lease_expires_at) OR
       p_lease_owner !~ '^[a-z0-9][a-z0-9._-]{0,63}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid detection lease request';
    END IF;
    requested_lease_duration := p_lease_expires_at - p_now;
    IF requested_lease_duration <= interval '0 seconds' OR
       requested_lease_duration > interval '60 seconds' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid detection lease request';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('detection-worker-serial-v1', 0));

    FOR exhausted IN
        WITH candidates AS (
            SELECT candidate.job_id
            FROM sentinelflow.outbox_jobs candidate
            WHERE candidate.kind = 'detect' AND candidate.state = 'leased'
              AND candidate.lease_expires_at <= server_now
              AND candidate.attempts >= candidate.max_attempts
            ORDER BY candidate.lease_expires_at, candidate.job_id
            FOR UPDATE SKIP LOCKED LIMIT 100
        )
        UPDATE sentinelflow.outbox_jobs job
        SET state = 'dead', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = 'lease_expired',
            last_error_digest = sentinelflow.detection_sha256(convert_to('lease_expired', 'UTF8')),
            updated_at = server_now
        FROM candidates candidate
        WHERE job.job_id = candidate.job_id
        RETURNING job.*
    LOOP
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest, dead_at
        ) VALUES (
            exhausted.job_id, exhausted.kind, exhausted.aggregate_type,
            exhausted.aggregate_id, exhausted.aggregate_version, exhausted.attempts,
            exhausted.last_error_code, exhausted.last_error_digest, server_now
        ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
    END LOOP;

    IF EXISTS (
        SELECT 1 FROM sentinelflow.outbox_jobs active
        WHERE active.kind = 'detect' AND active.state = 'leased'
          AND active.lease_expires_at > server_now
    ) THEN
        RETURN;
    END IF;

    SELECT candidate.* INTO leased
    FROM sentinelflow.outbox_jobs candidate
    WHERE candidate.kind = 'detect'
      AND candidate.aggregate_type IN ('ingest_batch', 'auth_binding')
      AND candidate.attempts < candidate.max_attempts
      AND (
          (candidate.state IN ('pending', 'retry') AND candidate.available_at <= server_now) OR
          (candidate.state = 'leased' AND candidate.lease_expires_at <= server_now)
      )
    ORDER BY candidate.available_at, candidate.created_at, candidate.job_id
    FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    UPDATE sentinelflow.outbox_jobs job
    SET state = 'leased', lease_token = p_lease_token, lease_owner = p_lease_owner,
        lease_expires_at = server_now + requested_lease_duration,
        attempts = job.attempts + 1, last_error_code = NULL,
        last_error_digest = NULL, updated_at = server_now
    WHERE job.job_id = leased.job_id
    RETURNING job.* INTO leased;
    RETURN NEXT leased;
END
$function$;

-- Returns the start of the current complete coverage segment shared by every
-- active expected source for an endpoint/service. A binding rotation or health
-- reset starts a new segment, so no window can silently bridge it.
CREATE OR REPLACE FUNCTION sentinelflow.detection_coverage_start(
    p_endpoint_kind text,
    p_service_label text,
    p_evaluated_at timestamptz
)
RETURNS timestamptz
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
    WITH active AS MATERIALIZED (
        SELECT binding.binding_id
        FROM sentinelflow.expected_source_bindings binding
        WHERE binding.endpoint_kind = p_endpoint_kind
          AND binding.service_label = p_service_label
          AND binding.effective_at <= p_evaluated_at
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.expected_source_binding_retirements retirement
              WHERE retirement.binding_id = binding.binding_id
                AND retirement.retired_at <= p_evaluated_at
          )
    ), segments AS MATERIALIZED (
        SELECT coverage.binding_id, coverage.sender_epoch, coverage.segment_id,
               min(coverage.coverage_start) AS segment_start,
               max(coverage.coverage_end) AS segment_end
        FROM sentinelflow.source_coverage_attestations coverage
        JOIN active ON active.binding_id = coverage.binding_id
        WHERE coverage.trust_state = 'trusted'
        GROUP BY coverage.binding_id, coverage.sender_epoch, coverage.segment_id
        HAVING max(coverage.coverage_end) >= p_evaluated_at
    ), selected AS MATERIALIZED (
        SELECT DISTINCT ON (segment.binding_id)
               segment.binding_id, segment.segment_start, segment.segment_end
        FROM segments segment
        ORDER BY segment.binding_id, segment.segment_end DESC,
                 segment.segment_start DESC, segment.segment_id
    ), counts AS (
        SELECT (SELECT count(*) FROM active) AS active_count,
               count(*) AS selected_count,
               max(selected.segment_start) AS common_start
        FROM selected
    )
    SELECT CASE
        WHEN active_count > 0 AND selected_count = active_count THEN common_start
        ELSE NULL
    END
    FROM counts;
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.prepare_detection_job(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE(status text, snapshot jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    job sentinelflow.outbox_jobs%ROWTYPE;
    batch sentinelflow.ingest_batches%ROWTYPE;
    auth sentinelflow.auth_events%ROWTYPE;
    coverage sentinelflow.source_coverage_attestations%ROWTYPE;
    service_value text;
    evaluation_time timestamptz;
    gateway_coverage_start timestamptz;
    auth_coverage_start timestamptz;
    candidate_ids jsonb;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid detection prepare request';
    END IF;
    SELECT * INTO job FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id AND current_job.kind = 'detect'
      AND current_job.aggregate_type IN ('ingest_batch', 'auth_binding')
      AND current_job.state = 'leased' AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now AND current_job.updated_at <= server_now
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM sentinelflow.detector_runs run WHERE run.job_id = job.job_id) THEN
        UPDATE sentinelflow.outbox_jobs SET state = 'completed', lease_token = NULL,
            lease_owner = NULL, lease_expires_at = NULL, last_error_code = NULL,
            last_error_digest = NULL, updated_at = server_now
        WHERE job_id = job.job_id;
        status := 'terminal'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    IF job.aggregate_type = 'ingest_batch' THEN
        SELECT candidate.* INTO batch
        FROM sentinelflow.ingest_batches candidate
        WHERE candidate.batch_id = job.aggregate_id
          AND job.idempotency_key = sentinelflow.detection_sha256(convert_to(
              'sentinelflow ingest detect outbox v1' || chr(10) ||
              candidate.sender_id || chr(10) || candidate.sender_epoch || chr(10) ||
              candidate.batch_id::text || chr(10), 'UTF8'))
        FOR KEY SHARE;
        IF NOT FOUND THEN
            status := 'missing'; snapshot := NULL; RETURN NEXT; RETURN;
        END IF;
        SELECT candidate.* INTO coverage
        FROM sentinelflow.source_coverage_attestations candidate
        WHERE candidate.sender_id = batch.sender_id
          AND candidate.endpoint_kind = batch.endpoint_kind
          AND candidate.sender_epoch = batch.sender_epoch
          AND candidate.covered_through_batch_id = batch.batch_id
          AND candidate.covered_through_sequence = batch.sequence
          AND candidate.trust_state = 'trusted'
        LIMIT 1;
        evaluation_time := COALESCE(coverage.coverage_end,
            date_trunc('milliseconds', batch.received_at));
        SELECT COALESCE(
            (SELECT event.service_label::text FROM sentinelflow.gateway_events event
             WHERE event.sender_id = batch.sender_id AND event.sender_epoch = batch.sender_epoch
               AND event.batch_id = batch.batch_id ORDER BY event.event_id LIMIT 1),
            (SELECT event.service_label::text FROM sentinelflow.auth_events event
             WHERE event.sender_id = batch.sender_id AND event.sender_epoch = batch.sender_epoch
               AND event.batch_id = batch.batch_id ORDER BY event.event_id LIMIT 1),
            (SELECT binding.service_label::text
             FROM sentinelflow.expected_source_bindings binding
             WHERE binding.binding_id = coverage.binding_id)
        ) INTO service_value;
        SELECT COALESCE(jsonb_agg(source_ip ORDER BY source_ip), '[]'::jsonb)
        INTO candidate_ids
        FROM (
            SELECT host(event.source_ip) AS source_ip FROM sentinelflow.gateway_events event
            WHERE event.sender_id = batch.sender_id AND event.sender_epoch = batch.sender_epoch
              AND event.batch_id = batch.batch_id
            UNION
            SELECT host(event.source_ip) AS source_ip FROM sentinelflow.auth_events event
            WHERE event.sender_id = batch.sender_id AND event.sender_epoch = batch.sender_epoch
              AND event.batch_id = batch.batch_id
        ) candidates;
    ELSE
        SELECT event.* INTO auth FROM sentinelflow.auth_events event
        WHERE event.event_id = job.aggregate_id AND event.binding_state <> 'pending'
        FOR KEY SHARE;
        IF NOT FOUND THEN
            status := 'missing'; snapshot := NULL; RETURN NEXT; RETURN;
        END IF;
        SELECT candidate.* INTO batch FROM sentinelflow.ingest_batches candidate
        WHERE candidate.sender_id = auth.sender_id AND candidate.sender_epoch = auth.sender_epoch
          AND candidate.batch_id = auth.batch_id FOR KEY SHARE;
        evaluation_time := date_trunc('milliseconds', job.created_at);
        service_value := auth.service_label::text;
        candidate_ids := jsonb_build_array(host(auth.source_ip));
    END IF;

    IF service_value IS NULL OR evaluation_time IS NULL THEN
        status := 'missing'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;
    gateway_coverage_start := sentinelflow.detection_coverage_start(
        'gateway', service_value, evaluation_time);
    auth_coverage_start := sentinelflow.detection_coverage_start(
        'auth', service_value, evaluation_time);

    status := 'prepared';
    snapshot := jsonb_build_object(
        'job_id', job.job_id::text,
        'aggregate_type', job.aggregate_type::text,
        'aggregate_id', job.aggregate_id::text,
        'aggregate_version', job.aggregate_version,
        'batch_id', batch.batch_id::text,
        'endpoint_kind', batch.endpoint_kind,
        'service_label', service_value,
        'evaluated_at', evaluation_time,
        'gateway_coverage_start', gateway_coverage_start,
        'auth_coverage_start', auth_coverage_start,
        'candidate_source_ips', candidate_ids
    );
    RETURN NEXT;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finish_detection_job(
    p_job_id uuid,
    p_lease_token uuid,
    p_configuration_version text,
    p_configuration_digest text,
    p_evaluated_at timestamptz,
    p_input_digest text,
    p_outcome text,
    p_signal_count integer,
    p_incident_mutation_count integer
)
RETURNS SETOF sentinelflow.outbox_jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    job sentinelflow.outbox_jobs%ROWTYPE;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL OR
       p_configuration_version !~ '^[a-z][a-z0-9._-]{0,63}$' OR
       p_configuration_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_evaluated_at IS NULL OR NOT isfinite(p_evaluated_at) OR
       p_input_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_outcome NOT IN ('complete', 'incomplete', 'no_candidates') OR
       p_signal_count NOT BETWEEN 0 AND 10000 OR
       p_incident_mutation_count NOT BETWEEN 0 AND 10000 OR
       (p_outcome <> 'complete' AND (p_signal_count <> 0 OR p_incident_mutation_count <> 0)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid detection completion';
    END IF;
    SELECT * INTO job FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id AND current_job.kind = 'detect'
      AND current_job.aggregate_type IN ('ingest_batch', 'auth_binding')
      AND current_job.state = 'leased' AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    INSERT INTO sentinelflow.detector_runs (
        job_id, aggregate_type, aggregate_id, aggregate_version,
        configuration_version, configuration_digest, evaluated_at,
        input_digest, outcome, signal_count, incident_mutation_count, completed_at
    ) VALUES (
        job.job_id, job.aggregate_type, job.aggregate_id, job.aggregate_version,
        p_configuration_version, p_configuration_digest, p_evaluated_at,
        p_input_digest, p_outcome, p_signal_count, p_incident_mutation_count, server_now
    );
    UPDATE sentinelflow.outbox_jobs current_job
    SET state = 'completed', lease_token = NULL, lease_owner = NULL,
        lease_expires_at = NULL, last_error_code = NULL, last_error_digest = NULL,
        updated_at = server_now
    WHERE current_job.job_id = job.job_id
    RETURNING current_job.* INTO job;
    RETURN NEXT job;
END
$function$;

REVOKE ALL ON detector_runs, detector_run_signals,
    incident_version_history, incident_version_signals FROM PUBLIC;
REVOKE ALL ON detector_runs, detector_run_signals,
    incident_version_history, incident_version_signals FROM
    sentinelflow_api, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
GRANT SELECT, INSERT ON detector_runs, detector_run_signals,
    incident_version_history, incident_version_signals TO sentinelflow_worker;
GRANT SELECT ON detector_runs, detector_run_signals,
    incident_version_history, incident_version_signals TO sentinelflow_api, sentinelflow_read;

GRANT UPDATE (incident_version) ON incident_signals TO sentinelflow_worker;
GRANT UPDATE (incident_version) ON incident_events TO sentinelflow_worker;
GRANT UPDATE (
    kind, state, first_seen, last_seen, closed_at, reopen_until,
    deterministic_score, version, analysis_failure_reason, updated_at
) ON incidents TO sentinelflow_worker;

GRANT SELECT (binding_resolved_at) ON auth_events TO sentinelflow_worker, sentinelflow_read;

REVOKE ALL ON FUNCTION sentinelflow.detection_sha256(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.detection_uuid_v8(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.stamp_auth_binding_resolution() FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.enqueue_auth_binding_detection() FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.reject_detection_history_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.lease_detection_outbox_job(
    timestamptz, uuid, text, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.lease_detection_outbox_job(
    timestamptz, uuid, text, timestamptz
) TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.detection_coverage_start(
    text, text, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.detection_coverage_start(
    text, text, timestamptz
) TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_detection_job(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_detection_job(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finish_detection_job(
    uuid, uuid, text, text, timestamptz, text, text, integer, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finish_detection_job(
    uuid, uuid, text, text, timestamptz, text, text, integer, integer
) TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (16, 'detection_correlation')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
