BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- A validation attempt owns one immutable database-clock projection. A lease
-- recovery resumes these exact bytes; it never recaptures a more favorable
-- 24-hour history window or refreshes the five-minute validation lifetime.
CREATE TABLE IF NOT EXISTS validation_attempt_claims (
    validation_attempt_id uuid PRIMARY KEY,
    job_id uuid NOT NULL UNIQUE REFERENCES outbox_jobs (job_id) ON DELETE RESTRICT,
    analysis_id uuid NOT NULL UNIQUE REFERENCES analysis_output_staging (analysis_id) ON DELETE RESTRICT,
    incident_id uuid NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    incident_version integer NOT NULL CHECK (incident_version >= 1),
    evidence_snapshot_id uuid NOT NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE RESTRICT,
    evidence_snapshot_digest sha256_digest NOT NULL,
    policy_id uuid NOT NULL UNIQUE,
    command_candidate_id uuid NOT NULL UNIQUE,
    validation_snapshot_id uuid NOT NULL UNIQUE,
    outbox_attempt integer NOT NULL CHECK (outbox_attempt >= 1),
    state text NOT NULL CHECK (state IN ('started', 'valid', 'invalid', 'interrupted')),
    failure_code ascii_id NULL,
    prepared_snapshot jsonb NOT NULL,
    prepared_snapshot_digest sha256_digest NOT NULL,
    generated_at timestamptz NOT NULL,
    terminal_at timestamptz NULL,
    CONSTRAINT validation_attempt_claim_state CHECK (
        (state = 'started' AND failure_code IS NULL AND terminal_at IS NULL) OR
        (state = 'valid' AND failure_code IS NULL AND terminal_at IS NOT NULL) OR
        (state IN ('invalid', 'interrupted') AND failure_code IS NOT NULL AND terminal_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS validation_attempt_claims_state_generated_idx
    ON validation_attempt_claims (state, generated_at);

-- These gates are the immutable evaluated prefix, including the first failed
-- gate. The core validation_gates table remains reserved for complete valid
-- validation snapshots, while rejected attempts retain equally auditable
-- failure evidence here.
CREATE TABLE IF NOT EXISTS validation_attempt_gates (
    validation_attempt_id uuid NOT NULL REFERENCES validation_attempt_claims (validation_attempt_id) ON DELETE RESTRICT,
    gate_order smallint NOT NULL CHECK (gate_order BETWEEN 1 AND 6),
    gate_name text NOT NULL CHECK (gate_name IN (
        'structured_output', 'command_grammar', 'policy_evidence_command_consistency',
        'protected_network', 'owned_schema_syntax', 'historical_impact'
    )),
    passed boolean NOT NULL,
    result_code ascii_id NOT NULL,
    input_digest sha256_digest NOT NULL,
    result_digest sha256_digest NOT NULL,
    checked_at timestamptz NOT NULL,
    PRIMARY KEY (validation_attempt_id, gate_order),
    UNIQUE (validation_attempt_id, gate_name),
    CONSTRAINT validation_attempt_gate_order_name CHECK (
        (gate_order = 1 AND gate_name = 'structured_output') OR
        (gate_order = 2 AND gate_name = 'command_grammar') OR
        (gate_order = 3 AND gate_name = 'policy_evidence_command_consistency') OR
        (gate_order = 4 AND gate_name = 'protected_network') OR
        (gate_order = 5 AND gate_name = 'owned_schema_syntax') OR
        (gate_order = 6 AND gate_name = 'historical_impact')
    ),
    CONSTRAINT validation_attempt_gate_result CHECK (
        (passed AND result_code = 'ok') OR (NOT passed AND result_code <> 'ok')
    )
);

CREATE TABLE IF NOT EXISTS validation_attempt_results (
    validation_attempt_id uuid PRIMARY KEY REFERENCES validation_attempt_claims (validation_attempt_id) ON DELETE RESTRICT,
    result_state text NOT NULL CHECK (result_state IN ('valid', 'invalid', 'interrupted')),
    failure_code ascii_id NULL,
    failed_gate text NULL CHECK (failed_gate IS NULL OR failed_gate IN (
        'structured_output', 'command_grammar', 'policy_evidence_command_consistency',
        'protected_network', 'owned_schema_syntax', 'historical_impact'
    )),
    prepared_snapshot_digest sha256_digest NOT NULL,
    terminal_mutation jsonb NULL,
    terminal_mutation_digest sha256_digest NULL,
    completed_at timestamptz NOT NULL,
    CONSTRAINT validation_attempt_result_shape CHECK (
        (result_state = 'valid' AND failure_code IS NULL AND failed_gate IS NULL AND
            terminal_mutation IS NOT NULL AND terminal_mutation_digest IS NOT NULL) OR
        (result_state = 'invalid' AND failure_code IS NOT NULL AND failed_gate IS NOT NULL AND
            terminal_mutation IS NOT NULL AND terminal_mutation_digest IS NOT NULL) OR
        (result_state = 'interrupted' AND failure_code IS NOT NULL AND failed_gate IS NULL AND
            terminal_mutation IS NULL AND terminal_mutation_digest IS NULL)
    )
);

CREATE OR REPLACE FUNCTION sentinelflow.validation_sha256(p_bytes bytea)
RETURNS sentinelflow.sha256_digest
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT ('sha256:' || encode(sha256(p_bytes), 'hex'))::sentinelflow.sha256_digest;
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.validation_jsonb_exact_keys(
    p_document jsonb,
    p_expected text[]
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT jsonb_typeof(p_document) = 'object'
       AND ARRAY(SELECT key FROM jsonb_object_keys(p_document) AS key ORDER BY key)
           = ARRAY(SELECT value FROM unnest(p_expected) AS value ORDER BY value);
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.validation_json_no_duplicate_keys(p_document json)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    child record;
BEGIN
    IF json_typeof(p_document) = 'object' THEN
        IF (SELECT count(*) FROM json_each(p_document)) <>
           (SELECT count(DISTINCT key) FROM json_each(p_document)) THEN
            RETURN false;
        END IF;
        FOR child IN SELECT value FROM json_each(p_document)
        LOOP
            IF NOT sentinelflow.validation_json_no_duplicate_keys(child.value) THEN
                RETURN false;
            END IF;
        END LOOP;
    ELSIF json_typeof(p_document) = 'array' THEN
        FOR child IN SELECT value FROM json_array_elements(p_document)
        LOOP
            IF NOT sentinelflow.validation_json_no_duplicate_keys(child.value) THEN
                RETURN false;
            END IF;
        END LOOP;
    END IF;
    RETURN true;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.lease_validation_outbox_job(
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
    exhausted_claim sentinelflow.validation_attempt_claims%ROWTYPE;
    server_now timestamptz := clock_timestamp();
    requested_lease_duration interval;
BEGIN
    IF p_now IS NULL OR p_lease_expires_at IS NULL OR
       NOT isfinite(p_now) OR NOT isfinite(p_lease_expires_at) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation lease request';
    END IF;
    requested_lease_duration := p_lease_expires_at - p_now;
    IF p_lease_token IS NULL OR p_lease_owner IS NULL OR
       p_lease_owner !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       requested_lease_duration <= interval '0 seconds' OR
       requested_lease_duration > interval '60 seconds' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation lease request';
    END IF;

    FOR exhausted IN
        WITH candidates AS (
            SELECT candidate.job_id
            FROM sentinelflow.outbox_jobs candidate
            WHERE candidate.kind = 'validate'
              AND candidate.aggregate_type = 'analysis_staging'
              AND candidate.state = 'leased'
              AND candidate.lease_expires_at <= server_now
              AND candidate.attempts >= candidate.max_attempts
            ORDER BY candidate.lease_expires_at, candidate.job_id
            FOR UPDATE SKIP LOCKED
            LIMIT 100
        )
        UPDATE sentinelflow.outbox_jobs job
        SET state = 'dead', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = 'lease_expired',
            last_error_digest = sentinelflow.validation_sha256(convert_to('lease_expired', 'UTF8')),
            updated_at = server_now
        FROM candidates candidate
        WHERE job.job_id = candidate.job_id
        RETURNING job.*
    LOOP
        SELECT * INTO exhausted_claim
        FROM sentinelflow.validation_attempt_claims claim
        WHERE claim.job_id = exhausted.job_id AND claim.state = 'started'
        FOR UPDATE;
        IF FOUND THEN
            UPDATE sentinelflow.validation_attempt_claims
            SET state = 'interrupted', failure_code = 'lease_expired', terminal_at = server_now
            WHERE validation_attempt_id = exhausted_claim.validation_attempt_id;
            INSERT INTO sentinelflow.validation_attempt_results (
                validation_attempt_id, result_state, failure_code,
                prepared_snapshot_digest, completed_at
            ) VALUES (
                exhausted_claim.validation_attempt_id, 'interrupted', 'lease_expired',
                exhausted_claim.prepared_snapshot_digest, server_now
            ) ON CONFLICT ON CONSTRAINT validation_attempt_results_pkey DO NOTHING;
        END IF;
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest, dead_at
        ) VALUES (
            exhausted.job_id, exhausted.kind, exhausted.aggregate_type,
            exhausted.aggregate_id, exhausted.aggregate_version, exhausted.attempts,
            exhausted.last_error_code, exhausted.last_error_digest, server_now
        ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
    END LOOP;

    SELECT candidate.* INTO leased
    FROM sentinelflow.outbox_jobs candidate
    WHERE candidate.kind = 'validate'
      AND candidate.aggregate_type = 'analysis_staging'
      AND candidate.aggregate_version = 1
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
    SET state = 'leased', lease_token = p_lease_token, lease_owner = p_lease_owner,
        lease_expires_at = server_now + requested_lease_duration,
        attempts = job.attempts + 1, last_error_code = NULL,
        last_error_digest = NULL, updated_at = server_now
    WHERE job.job_id = leased.job_id
    RETURNING job.* INTO leased;
    RETURN NEXT leased;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.prepare_validation_attempt(
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
    history_start timestamptz := server_now - interval '24 hours';
    job sentinelflow.outbox_jobs%ROWTYPE;
    prior sentinelflow.validation_attempt_claims%ROWTYPE;
    source_claim sentinelflow.analysis_attempt_claims%ROWTYPE;
    source_result sentinelflow.analysis_attempt_results%ROWTYPE;
    staged sentinelflow.analysis_output_staging%ROWTYPE;
    analysis sentinelflow.ai_analyses%ROWTYPE;
    evidence sentinelflow.evidence_snapshots%ROWTYPE;
    attempt_id uuid := gen_random_uuid();
    policy_id_value uuid := gen_random_uuid();
    candidate_id uuid := gen_random_uuid();
    validation_id uuid := gen_random_uuid();
    signals_json jsonb;
    signal_ids_json jsonb;
    event_ids_json jsonb;
    gateway_json jsonb;
    auth_json jsonb;
    source_health_digest sentinelflow.sha256_digest;
    prepared jsonb;
    prepared_digest sentinelflow.sha256_digest;
    signal_total integer;
    gateway_total bigint;
    auth_total bigint;
    coverage_complete boolean;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation prepare request';
    END IF;

    SELECT * INTO job
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
      AND current_job.kind = 'validate'
      AND current_job.aggregate_type = 'analysis_staging'
      AND current_job.aggregate_version = 1
      AND current_job.state = 'leased'
      AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now
      AND current_job.updated_at <= server_now
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT * INTO prior
    FROM sentinelflow.validation_attempt_claims claim
    WHERE claim.analysis_id = job.aggregate_id
    FOR UPDATE;
    IF FOUND THEN
        IF prior.state = 'started' THEN
            status := 'prepared'; snapshot := prior.prepared_snapshot; RETURN NEXT; RETURN;
        END IF;
        UPDATE sentinelflow.outbox_jobs
        SET state = 'completed', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = NULL, last_error_digest = NULL,
            updated_at = server_now
        WHERE job_id = job.job_id;
        status := 'terminal'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    SELECT * INTO staged
    FROM sentinelflow.analysis_output_staging item
    WHERE item.analysis_id = job.aggregate_id;
    SELECT * INTO source_claim
    FROM sentinelflow.analysis_attempt_claims item
    WHERE item.analysis_id = job.aggregate_id;
    SELECT * INTO source_result
    FROM sentinelflow.analysis_attempt_results item
    WHERE item.analysis_id = job.aggregate_id;
    SELECT * INTO analysis
    FROM sentinelflow.ai_analyses item
    WHERE item.analysis_id = job.aggregate_id;
    IF staged.analysis_id IS NULL OR source_claim.analysis_id IS NULL OR
       source_result.analysis_id IS NULL OR analysis.analysis_id IS NULL OR
       source_claim.state <> 'succeeded' OR source_result.result_state <> 'succeeded' OR
       analysis.result_state <> 'succeeded' OR staged.state <> 'pre_validation' OR
       source_result.output_digest <> staged.output_digest OR
       source_result.generated_command_digest <> staged.generated_command_digest OR
       analysis.output_digest <> staged.output_digest OR
       source_result.input_digest <> analysis.input_digest OR
       source_result.output_schema_digest <> analysis.output_schema_digest OR
       source_result.prompt_digest <> analysis.prompt_digest THEN
        UPDATE sentinelflow.outbox_jobs
        SET state = 'dead', lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = 'validation_prerequisite_missing',
            last_error_digest = sentinelflow.validation_sha256(convert_to('validation_prerequisite_missing', 'UTF8')),
            updated_at = server_now
        WHERE job_id = job.job_id;
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest, dead_at
        ) VALUES (
            job.job_id, job.kind, job.aggregate_type, job.aggregate_id, job.aggregate_version,
            job.attempts, 'validation_prerequisite_missing',
            sentinelflow.validation_sha256(convert_to('validation_prerequisite_missing', 'UTF8')), server_now
        ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
        status := 'interrupted'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    SELECT * INTO evidence
    FROM sentinelflow.evidence_snapshots item
    WHERE item.evidence_snapshot_id = source_claim.evidence_snapshot_id
      AND item.snapshot_digest = source_claim.evidence_snapshot_digest
      AND item.evidence_snapshot_id = analysis.evidence_snapshot_id
      AND item.snapshot_digest = analysis.evidence_snapshot_digest
      AND item.incident_id = source_claim.incident_id
      AND item.incident_version = source_claim.incident_version;
    IF NOT FOUND THEN
        UPDATE sentinelflow.outbox_jobs
        SET state = 'dead', lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = 'validation_evidence_missing',
            last_error_digest = sentinelflow.validation_sha256(convert_to('validation_evidence_missing', 'UTF8')),
            updated_at = server_now
        WHERE job_id = job.job_id;
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest, dead_at
        ) VALUES (
            job.job_id, job.kind, job.aggregate_type, job.aggregate_id, job.aggregate_version,
            job.attempts, 'validation_evidence_missing',
            sentinelflow.validation_sha256(convert_to('validation_evidence_missing', 'UTF8')), server_now
        ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
        status := 'interrupted'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    SELECT count(*) INTO signal_total
    FROM sentinelflow.evidence_snapshot_signals link
    WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id;
    IF signal_total <> evidence.signal_count OR signal_total NOT BETWEEN 1 AND 50 OR
       (SELECT count(*) FROM sentinelflow.analysis_evidence ae
        WHERE ae.analysis_id = analysis.analysis_id
          AND ae.evidence_snapshot_id = evidence.evidence_snapshot_id) <> signal_total THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'validation evidence membership mismatch';
    END IF;

    SELECT to_jsonb(ARRAY(
        SELECT link.evidence_id
        FROM sentinelflow.evidence_snapshot_signals link
        WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id
        ORDER BY link.ordinal
    )) INTO signal_ids_json;
    SELECT to_jsonb(ARRAY(
        SELECT event_id
        FROM (
            SELECT DISTINCT COALESCE(item.gateway_event_id, item.auth_event_id, item.source_health_event_id)::text AS event_id
            FROM sentinelflow.evidence_snapshot_events item
            WHERE item.evidence_snapshot_id = evidence.evidence_snapshot_id
        ) expanded
        ORDER BY event_id
    )) INTO event_ids_json;

    SELECT jsonb_agg(jsonb_build_object(
        'signal_id', link.evidence_id,
        'signal_digest', link.evidence_digest,
        'source_ipv4', host(signal.source_ip),
        'event_ids', to_jsonb(ARRAY(
            SELECT COALESCE(item.gateway_event_id, item.auth_event_id, item.source_health_event_id)::text
            FROM sentinelflow.evidence_snapshot_events item
            WHERE item.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND item.signal_id = signal.signal_id
            ORDER BY COALESCE(item.gateway_event_id, item.auth_event_id, item.source_health_event_id)::text
        )),
        'threshold_reproduced', signal.observed_count >= signal.threshold_count AND
            (signal.threshold_distinct IS NULL OR COALESCE(signal.distinct_count, 0) >= signal.threshold_distinct),
        'source_health_status', signal.source_health_status
    ) ORDER BY link.ordinal)
    INTO signals_json
    FROM sentinelflow.evidence_snapshot_signals link
    JOIN sentinelflow.signals signal ON signal.signal_id = link.signal_id
    WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id;

    SELECT count(*) INTO gateway_total
    FROM sentinelflow.gateway_events item
    WHERE item.source_ip = evidence.source_ip
      AND item.completed_at BETWEEN history_start AND server_now;
    SELECT count(*) INTO auth_total
    FROM sentinelflow.auth_events item
    WHERE item.source_ip = evidence.source_ip
      AND item.occurred_at BETWEEN history_start AND server_now;

    SELECT COALESCE(jsonb_agg(row_value ORDER BY row_value->>'event_id'), '[]'::jsonb)
    INTO gateway_json
    FROM (
        SELECT jsonb_build_object(
            'event_id', item.event_id::text, 'occurred_at', item.completed_at,
            'source_ipv4', host(item.source_ip), 'status_code', item.status_code,
            'timestamp_trust', item.trust_state
        ) AS row_value
        FROM sentinelflow.gateway_events item
        WHERE item.source_ip = evidence.source_ip
          AND item.completed_at BETWEEN history_start AND server_now
        ORDER BY item.event_id
        LIMIT 100000
    ) rows;
    SELECT COALESCE(jsonb_agg(row_value ORDER BY row_value->>'event_id'), '[]'::jsonb)
    INTO auth_json
    FROM (
        SELECT jsonb_build_object(
            'event_id', item.event_id::text, 'occurred_at', item.occurred_at,
            'source_ipv4', host(item.source_ip), 'outcome', item.outcome,
            'timestamp_trust', item.trust_state, 'binding', item.binding_state
        ) AS row_value
        FROM sentinelflow.auth_events item
        WHERE item.source_ip = evidence.source_ip
          AND item.occurred_at BETWEEN history_start AND server_now
        ORDER BY item.event_id
        LIMIT 100000
    ) rows;

    coverage_complete := gateway_total <= 100000 AND auth_total <= 100000
        AND EXISTS (
            SELECT 1 FROM sentinelflow.sender_checkpoints checkpoint
            WHERE checkpoint.endpoint_kind = 'gateway' AND NOT checkpoint.unknown_loss
              AND checkpoint.updated_at >= server_now - interval '5 minutes'
        )
        AND EXISTS (
            SELECT 1 FROM sentinelflow.sender_checkpoints checkpoint
            WHERE checkpoint.endpoint_kind = 'auth' AND NOT checkpoint.unknown_loss
              AND checkpoint.updated_at >= server_now - interval '5 minutes'
        )
        AND EXISTS (
            SELECT 1 FROM sentinelflow.ingest_batches batch
            WHERE batch.endpoint_kind = 'gateway' AND batch.received_at <= history_start
        )
        AND EXISTS (
            SELECT 1 FROM sentinelflow.ingest_batches batch
            WHERE batch.endpoint_kind = 'auth' AND batch.received_at <= history_start
        )
        AND NOT EXISTS (
            SELECT 1 FROM sentinelflow.sender_checkpoints checkpoint
            WHERE checkpoint.endpoint_kind IN ('gateway', 'auth') AND checkpoint.unknown_loss
        )
        AND NOT EXISTS (
            SELECT 1 FROM sentinelflow.ingest_sequence_gaps gap
            WHERE gap.endpoint_kind IN ('gateway', 'auth')
        )
        AND NOT EXISTS (
            SELECT 1 FROM sentinelflow.source_health_intervals health
            WHERE health.received_at <= server_now
              AND COALESCE(health.interval_end, server_now) >= history_start
              AND health.state IN ('degraded', 'lost')
        )
        AND NOT EXISTS (
            SELECT 1 FROM sentinelflow.gateway_events item
            WHERE item.source_ip = evidence.source_ip
              AND item.completed_at BETWEEN history_start AND server_now
              AND item.trust_state <> 'trusted'
        )
        AND NOT EXISTS (
            SELECT 1 FROM sentinelflow.auth_events item
            WHERE item.source_ip = evidence.source_ip
              AND item.occurred_at BETWEEN history_start AND server_now
              AND item.trust_state <> 'trusted'
        );

    source_health_digest := sentinelflow.validation_sha256(convert_to(jsonb_build_object(
        'schema_version', 'validation-source-health-v1',
        'cutoff', server_now, 'window_start', history_start,
        'coverage_complete', coverage_complete,
        'checkpoint_count', (SELECT count(*) FROM sentinelflow.sender_checkpoints
            WHERE endpoint_kind IN ('gateway', 'auth')),
        'gap_count', (SELECT count(*) FROM sentinelflow.ingest_sequence_gaps
            WHERE endpoint_kind IN ('gateway', 'auth')),
        'health_interval_count', (SELECT count(*) FROM sentinelflow.source_health_intervals
            WHERE received_at <= server_now AND COALESCE(interval_end, server_now) >= history_start)
    )::text, 'UTF8'));

    prepared := jsonb_build_object(
        'validation_attempt_id', attempt_id, 'policy_id', policy_id_value,
        'validation_id', validation_id, 'command_candidate_id', candidate_id,
        'analysis_id', analysis.analysis_id, 'incident_id', source_claim.incident_id,
        'incident_version', source_claim.incident_version, 'generated_at', server_now,
        'evidence_snapshot_id', evidence.evidence_snapshot_id,
        'evidence_snapshot_digest', evidence.snapshot_digest,
        'analysis_input_digest', analysis.input_digest,
        'output_schema_digest', analysis.output_schema_digest,
        'prompt_digest', analysis.prompt_digest,
        'analysis_output_digest', staged.output_digest,
        'generated_command_digest', staged.generated_command_digest,
        'structured_output_hex', encode(staged.structured_output, 'hex'),
        'policy_output_hex', encode(staged.policy_output, 'hex'),
        'command_candidate_output_hex', encode(staged.command_candidate_output, 'hex'),
        'evidence', jsonb_build_object(
            'source_ipv4', host(evidence.source_ip), 'service_label', evidence.service_label,
            'source_health_digest', source_health_digest,
            'source_health_status', evidence.source_health_status,
            'signal_ids', signal_ids_json, 'event_ids', event_ids_json, 'signals', signals_json
        ),
        'history', jsonb_build_object(
            'cutoff', server_now, 'window_start', history_start,
            'coverage_complete', coverage_complete,
            'gateway_records', gateway_json, 'auth_records', auth_json
        )
    );
    prepared_digest := sentinelflow.validation_sha256(convert_to(prepared::text, 'UTF8'));

    INSERT INTO sentinelflow.validation_attempt_claims (
        validation_attempt_id, job_id, analysis_id, incident_id, incident_version,
        evidence_snapshot_id, evidence_snapshot_digest, policy_id, command_candidate_id,
        validation_snapshot_id, outbox_attempt, state, prepared_snapshot,
        prepared_snapshot_digest, generated_at
    ) VALUES (
        attempt_id, job.job_id, analysis.analysis_id, source_claim.incident_id,
        source_claim.incident_version, evidence.evidence_snapshot_id, evidence.snapshot_digest,
        policy_id_value, candidate_id, validation_id, job.attempts, 'started', prepared,
        prepared_digest, server_now
    );
    status := 'prepared'; snapshot := prepared; RETURN NEXT;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finalize_validation_attempt(
    p_job_id uuid,
    p_lease_token uuid,
    p_finish_state text,
    p_retry_at timestamptz,
    p_client_now timestamptz,
    p_error_code text,
    p_error_digest text,
    p_mutation json
)
RETURNS TABLE(job_id uuid, state text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    requested_retry_delay interval;
    job sentinelflow.outbox_jobs%ROWTYPE;
    claim sentinelflow.validation_attempt_claims%ROWTYPE;
    mutation jsonb;
    candidate jsonb;
    policy_value jsonb;
    validation_value jsonb;
    gate jsonb;
    gate_index integer;
    gate_count integer;
    expected_gate text;
    failed_gate text;
    candidate_generated bytea;
    candidate_canonical bytea;
    policy_canonical bytea;
    validation_canonical bytea;
    mutation_digest sentinelflow.sha256_digest;
    terminal_state text;
BEGIN
    IF p_client_now IS NULL OR NOT isfinite(p_client_now) OR
       p_job_id IS NULL OR p_lease_token IS NULL OR
       p_finish_state NOT IN ('completed', 'retry', 'dead') OR
       (p_retry_at IS NOT NULL AND NOT isfinite(p_retry_at)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation finalize request';
    END IF;
    requested_retry_delay := p_retry_at - p_client_now;
    IF (p_finish_state = 'retry' AND
            (p_retry_at IS NULL OR requested_retry_delay < interval '0 seconds')) OR
       (p_finish_state <> 'retry' AND p_retry_at IS NOT NULL) OR
       (p_finish_state = 'completed' AND (p_error_code IS NOT NULL OR p_error_digest IS NOT NULL)) OR
       (p_finish_state <> 'completed' AND (
            p_error_code IS NULL OR p_error_digest IS NULL OR
            p_error_code !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
            p_error_digest !~ '^sha256:[0-9a-f]{64}$')) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation finalize request';
    END IF;

    SELECT * INTO job
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
      AND current_job.kind = 'validate'
      AND current_job.aggregate_type = 'analysis_staging'
      AND current_job.aggregate_version = 1
      AND current_job.state = 'leased'
      AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now
      AND current_job.updated_at <= server_now
    FOR UPDATE;
    IF NOT FOUND OR (p_finish_state = 'retry' AND job.attempts >= job.max_attempts) THEN
        RETURN;
    END IF;

    IF p_mutation IS NOT NULL AND p_mutation::text <> 'null' THEN
        IF p_finish_state <> 'completed' OR
           NOT sentinelflow.validation_json_no_duplicate_keys(p_mutation) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation mutation';
        END IF;
        mutation := p_mutation::jsonb;
        IF NOT sentinelflow.validation_jsonb_exact_keys(mutation, ARRAY[
            'analysis_id', 'audit_action', 'candidate', 'failure_code', 'gates',
            'incident_id', 'incident_version', 'policy', 'state', 'validation',
            'validation_attempt_id'
        ]) OR mutation->>'validation_attempt_id' !~
                '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
           mutation->>'analysis_id' !~
                '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
           mutation->>'incident_id' !~
                '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
           mutation->>'failure_code' !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
           jsonb_typeof(mutation->'incident_version') <> 'number' OR
           jsonb_typeof(mutation->'gates') <> 'array' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation mutation';
        END IF;

        SELECT * INTO claim
        FROM sentinelflow.validation_attempt_claims current_claim
        WHERE current_claim.validation_attempt_id = (mutation->>'validation_attempt_id')::uuid
          AND current_claim.job_id = job.job_id
          AND current_claim.analysis_id = job.aggregate_id
          AND current_claim.analysis_id = (mutation->>'analysis_id')::uuid
          AND current_claim.incident_id = (mutation->>'incident_id')::uuid
          AND current_claim.incident_version = (mutation->>'incident_version')::integer
          AND current_claim.state = 'started'
        FOR UPDATE;
        IF NOT FOUND THEN
            RETURN;
        END IF;

        gate_count := jsonb_array_length(mutation->'gates');
        IF gate_count NOT BETWEEN 1 AND 6 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation gate count';
        END IF;
        FOR gate_index IN 1..gate_count LOOP
            gate := mutation->'gates'->(gate_index - 1);
            expected_gate := CASE gate_index
                WHEN 1 THEN 'structured_output'
                WHEN 2 THEN 'command_grammar'
                WHEN 3 THEN 'policy_evidence_command_consistency'
                WHEN 4 THEN 'protected_network'
                WHEN 5 THEN 'owned_schema_syntax'
                WHEN 6 THEN 'historical_impact'
            END;
            IF NOT sentinelflow.validation_jsonb_exact_keys(gate, ARRAY[
                'input_digest', 'name', 'order', 'passed', 'result_code', 'result_digest'
            ]) OR (gate->>'order')::integer <> gate_index OR gate->>'name' <> expected_gate OR
               jsonb_typeof(gate->'passed') <> 'boolean' OR
               gate->>'result_code' !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
               gate->>'input_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               gate->>'result_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               (gate_index < gate_count AND (
                    NOT (gate->>'passed')::boolean OR gate->>'result_code' <> 'ok')) THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation gate';
            END IF;
        END LOOP;

        gate := mutation->'gates'->(gate_count - 1);
        candidate := mutation->'candidate';
        policy_value := mutation->'policy';
        validation_value := mutation->'validation';
        IF mutation->>'state' = 'valid' THEN
            IF gate_count <> 6 OR NOT (gate->>'passed')::boolean OR
               gate->>'result_code' <> 'ok' OR mutation->>'failure_code' <> 'none' OR
               mutation->>'audit_action' <> 'validation_succeeded' OR
               candidate IS NULL OR candidate = 'null'::jsonb OR
               policy_value IS NULL OR policy_value = 'null'::jsonb OR
               validation_value IS NULL OR validation_value = 'null'::jsonb THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid valid validation mutation';
            END IF;
            terminal_state := 'valid'; failed_gate := NULL;
        ELSIF mutation->>'state' = 'invalid' THEN
            IF (gate->>'passed')::boolean OR gate->>'result_code' = 'ok' OR
               mutation->>'failure_code' <> gate->>'result_code' OR
               mutation->>'audit_action' <> 'validation_rejected' OR
               validation_value IS NOT NULL AND validation_value <> 'null'::jsonb OR
               ((gate_count <= 2) AND (
                    candidate IS NOT NULL AND candidate <> 'null'::jsonb OR
                    policy_value IS NOT NULL AND policy_value <> 'null'::jsonb)) OR
               ((gate_count >= 3) AND (
                    candidate IS NULL OR candidate = 'null'::jsonb OR
                    policy_value IS NULL OR policy_value = 'null'::jsonb)) THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid rejected validation mutation';
            END IF;
            terminal_state := 'invalid'; failed_gate := gate->>'name';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation state';
        END IF;

        IF candidate IS NOT NULL AND candidate <> 'null'::jsonb THEN
            IF NOT sentinelflow.validation_jsonb_exact_keys(candidate, ARRAY[
                'canonical_digest', 'canonical_hex', 'generated_digest', 'generated_hex',
                'schema_version', 'target_ipv4', 'timeout_token', 'ttl_seconds'
            ]) OR candidate->>'schema_version' <> 'nft-blacklist-v1' OR
               candidate->>'target_ipv4' !~ '^([0-9]{1,3}\.){3}[0-9]{1,3}$' OR
               candidate->>'timeout_token' !~ '^[1-9][0-9]{0,4}[smh]$' OR
               (candidate->>'ttl_seconds')::integer NOT BETWEEN 60 AND 86400 OR
               candidate->>'generated_hex' !~ '^[0-9a-f]+$' OR length(candidate->>'generated_hex') % 2 <> 0 OR
               candidate->>'canonical_hex' !~ '^[0-9a-f]+$' OR length(candidate->>'canonical_hex') % 2 <> 0 OR
               candidate->>'generated_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               candidate->>'canonical_digest' !~ '^sha256:[0-9a-f]{64}$' THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid command candidate';
            END IF;
            candidate_generated := decode(candidate->>'generated_hex', 'hex');
            candidate_canonical := decode(candidate->>'canonical_hex', 'hex');
            IF octet_length(candidate_generated) NOT BETWEEN 1 AND 256 OR
               octet_length(candidate_canonical) NOT BETWEEN 1 AND 256 OR
               sentinelflow.validation_sha256(candidate_generated) <> candidate->>'generated_digest' OR
               sentinelflow.validation_sha256(candidate_canonical) <> candidate->>'canonical_digest' OR
               candidate->>'generated_digest' <> claim.prepared_snapshot->>'generated_command_digest' OR
               candidate->>'target_ipv4' <> claim.prepared_snapshot->'evidence'->>'source_ipv4' THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'command candidate binding mismatch';
            END IF;

            IF NOT sentinelflow.validation_jsonb_exact_keys(policy_value, ARRAY[
                'canonical_hex', 'policy_digest', 'policy_id', 'policy_version', 'rationale',
                'schema_version', 'target_ipv4', 'ttl_seconds'
            ]) OR policy_value->>'schema_version' <> 'response-policy-v1' OR
               (policy_value->>'policy_id')::uuid <> claim.policy_id OR
               (policy_value->>'policy_version')::integer <> 1 OR
               policy_value->>'policy_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               policy_value->>'canonical_hex' !~ '^[0-9a-f]+$' OR length(policy_value->>'canonical_hex') % 2 <> 0 OR
               policy_value->>'target_ipv4' <> candidate->>'target_ipv4' OR
               (policy_value->>'ttl_seconds')::integer <> (candidate->>'ttl_seconds')::integer OR
               length(policy_value->>'rationale') NOT BETWEEN 1 AND 800 THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid policy proposal';
            END IF;
            policy_canonical := decode(policy_value->>'canonical_hex', 'hex');
            IF octet_length(policy_canonical) NOT BETWEEN 1 AND 8192 OR
               sentinelflow.validation_sha256(policy_canonical) <> policy_value->>'policy_digest' THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'policy digest mismatch';
            END IF;

            INSERT INTO sentinelflow.command_candidates (
                command_candidate_id, schema_version, analysis_id, evidence_snapshot_id,
                evidence_snapshot_digest, target_ipv4, timeout_token, ttl_seconds,
                generated_command, generated_artifact_digest, parse_state,
                canonical_artifact, canonical_artifact_digest, created_at, updated_at
            ) VALUES (
                claim.command_candidate_id, candidate->>'schema_version', claim.analysis_id,
                claim.evidence_snapshot_id, claim.evidence_snapshot_digest,
                (candidate->>'target_ipv4')::inet, candidate->>'timeout_token',
                (candidate->>'ttl_seconds')::integer, convert_from(candidate_generated, 'UTF8'),
                candidate->>'generated_digest', 'canonical', candidate_canonical,
                candidate->>'canonical_digest', claim.generated_at, server_now
            );
            INSERT INTO sentinelflow.policy_proposals (
                policy_id, version, schema_version, incident_id, incident_version,
                analysis_id, command_candidate_id, evidence_snapshot_id,
                evidence_snapshot_digest, policy_digest, generated_artifact_digest,
                canonical_artifact_digest, target_ipv4, action, ttl_seconds,
                rationale, state, state_revision, created_at, updated_at
            ) VALUES (
                claim.policy_id, 1, policy_value->>'schema_version', claim.incident_id,
                claim.incident_version, claim.analysis_id, claim.command_candidate_id,
                claim.evidence_snapshot_id, claim.evidence_snapshot_digest,
                policy_value->>'policy_digest', candidate->>'generated_digest',
                candidate->>'canonical_digest', (candidate->>'target_ipv4')::inet,
                'block_ip', (candidate->>'ttl_seconds')::integer,
                policy_value->>'rationale', 'draft', 1, claim.generated_at, claim.generated_at
            );
            UPDATE sentinelflow.policy_proposals
            SET state = 'validating', state_revision = 2, updated_at = server_now
            WHERE policy_id = claim.policy_id AND version = 1 AND state = 'draft';
        END IF;

        FOR gate_index IN 1..gate_count LOOP
            gate := mutation->'gates'->(gate_index - 1);
            INSERT INTO sentinelflow.validation_attempt_gates (
                validation_attempt_id, gate_order, gate_name, passed,
                result_code, input_digest, result_digest, checked_at
            ) VALUES (
                claim.validation_attempt_id, gate_index, gate->>'name',
                (gate->>'passed')::boolean, gate->>'result_code',
                gate->>'input_digest', gate->>'result_digest', server_now
            );
        END LOOP;

        IF terminal_state = 'valid' THEN
            IF NOT sentinelflow.validation_jsonb_exact_keys(validation_value, ARRAY[
                'analysis_input_digest', 'analysis_output_schema_digest',
                'base_chain_contract_raw_digest', 'canonical_artifact_digest', 'canonical_hex',
                'created_at', 'evidence_snapshot_digest', 'generated_candidate_digest',
                'grammar_version', 'historical_impact_digest', 'live_owned_schema_digest',
                'nft_binary_digest', 'nft_version', 'parser_version', 'policy_digest',
                'prompt_digest', 'protected_ipv4_effective_config_digest',
                'protected_ipv4_static_digest', 'snapshot_digest', 'source_health_status',
                'target_ipv4', 'ttl_seconds', 'valid_until', 'validator_version'
            ]) OR validation_value->>'snapshot_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               validation_value->>'canonical_hex' !~ '^[0-9a-f]+$' OR
               length(validation_value->>'canonical_hex') % 2 <> 0 OR
               validation_value->>'policy_digest' <> policy_value->>'policy_digest' OR
               validation_value->>'evidence_snapshot_digest' <> claim.evidence_snapshot_digest OR
               validation_value->>'analysis_input_digest' <> claim.prepared_snapshot->>'analysis_input_digest' OR
               validation_value->>'analysis_output_schema_digest' <> claim.prepared_snapshot->>'output_schema_digest' OR
               validation_value->>'prompt_digest' <> claim.prepared_snapshot->>'prompt_digest' OR
               validation_value->>'generated_candidate_digest' <> candidate->>'generated_digest' OR
               validation_value->>'canonical_artifact_digest' <> candidate->>'canonical_digest' OR
               validation_value->>'grammar_version' <> 'nft-blacklist-v1' OR
               validation_value->>'parser_version' <> 'nft-blacklist-parser-v1' OR
               validation_value->>'validator_version' <> 'owned-schema-validator-v1' OR
               validation_value->>'source_health_status' <> 'complete' OR
               validation_value->>'target_ipv4' <> candidate->>'target_ipv4' OR
               (validation_value->>'ttl_seconds')::integer <> (candidate->>'ttl_seconds')::integer OR
               (validation_value->>'created_at')::timestamptz <> claim.generated_at OR
               (validation_value->>'valid_until')::timestamptz <> claim.generated_at + interval '5 minutes' OR
               (validation_value->>'valid_until')::timestamptz < server_now OR
               validation_value->>'nft_version' !~ '^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9._-]+)?$' THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation snapshot';
            END IF;
            IF validation_value->>'base_chain_contract_raw_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               validation_value->>'live_owned_schema_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               validation_value->>'protected_ipv4_static_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               validation_value->>'protected_ipv4_effective_config_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               validation_value->>'nft_binary_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               validation_value->>'historical_impact_digest' !~ '^sha256:[0-9a-f]{64}$' THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid validation provenance';
            END IF;
            validation_canonical := decode(validation_value->>'canonical_hex', 'hex');
            IF octet_length(validation_canonical) NOT BETWEEN 1 AND 65536 OR
               sentinelflow.validation_sha256(validation_canonical) <> validation_value->>'snapshot_digest' THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'validation snapshot digest mismatch';
            END IF;

            INSERT INTO sentinelflow.validation_snapshots (
                validation_snapshot_id, schema_version, policy_id, policy_version,
                command_candidate_id, evidence_snapshot_id, snapshot_digest,
                policy_digest, evidence_snapshot_digest, analysis_input_digest,
                analysis_output_schema_digest, prompt_digest, generated_candidate_digest,
                canonical_artifact_digest, grammar_version, parser_version, validator_version,
                base_chain_contract_raw_digest, live_owned_schema_digest,
                protected_ipv4_static_digest, protected_ipv4_effective_config_digest,
                nft_binary_digest, nft_version, historical_impact_digest,
                target_ipv4, ttl_seconds, historical_impact_lookback_seconds,
                state, failure_code, source_health_status, created_at, valid_until
            ) VALUES (
                claim.validation_snapshot_id, 'validation-snapshot-v1', claim.policy_id, 1,
                claim.command_candidate_id, claim.evidence_snapshot_id,
                validation_value->>'snapshot_digest', validation_value->>'policy_digest',
                validation_value->>'evidence_snapshot_digest', validation_value->>'analysis_input_digest',
                validation_value->>'analysis_output_schema_digest', validation_value->>'prompt_digest',
                validation_value->>'generated_candidate_digest', validation_value->>'canonical_artifact_digest',
                validation_value->>'grammar_version', validation_value->>'parser_version',
                validation_value->>'validator_version', validation_value->>'base_chain_contract_raw_digest',
                validation_value->>'live_owned_schema_digest', validation_value->>'protected_ipv4_static_digest',
                validation_value->>'protected_ipv4_effective_config_digest', validation_value->>'nft_binary_digest',
                validation_value->>'nft_version', validation_value->>'historical_impact_digest',
                (validation_value->>'target_ipv4')::inet, (validation_value->>'ttl_seconds')::integer,
                86400, 'draft', NULL, validation_value->>'source_health_status',
                (validation_value->>'created_at')::timestamptz,
                (validation_value->>'valid_until')::timestamptz
            );
            INSERT INTO sentinelflow.validation_gates (
                validation_snapshot_id, gate_order, gate_name, passed,
                result_code, input_digest, result_digest, checked_at
            )
            SELECT claim.validation_snapshot_id, item.gate_order, item.gate_name,
                   item.passed, item.result_code, item.input_digest, item.result_digest, item.checked_at
            FROM sentinelflow.validation_attempt_gates item
            WHERE item.validation_attempt_id = claim.validation_attempt_id
            ORDER BY item.gate_order;
            UPDATE sentinelflow.validation_snapshots
            SET state = 'valid'
            WHERE validation_snapshot_id = claim.validation_snapshot_id AND state = 'draft';
            UPDATE sentinelflow.command_candidates
            SET parse_state = 'valid', updated_at = server_now
            WHERE command_candidate_id = claim.command_candidate_id AND parse_state = 'canonical';
            UPDATE sentinelflow.policy_proposals
            SET state = 'valid', state_revision = 3, updated_at = server_now
            WHERE policy_id = claim.policy_id AND version = 1 AND state = 'validating';
        ELSIF candidate IS NOT NULL AND candidate <> 'null'::jsonb THEN
            UPDATE sentinelflow.policy_proposals
            SET state = 'invalid', state_revision = 3, updated_at = server_now
            WHERE policy_id = claim.policy_id AND version = 1 AND state = 'validating';
        END IF;

        mutation_digest := sentinelflow.validation_sha256(convert_to(mutation::text, 'UTF8'));
        INSERT INTO sentinelflow.validation_attempt_results (
            validation_attempt_id, result_state, failure_code, failed_gate,
            prepared_snapshot_digest, terminal_mutation, terminal_mutation_digest, completed_at
        ) VALUES (
            claim.validation_attempt_id, terminal_state,
            CASE WHEN terminal_state = 'invalid' THEN mutation->>'failure_code' ELSE NULL END,
            failed_gate, claim.prepared_snapshot_digest, mutation, mutation_digest, server_now
        );
        UPDATE sentinelflow.validation_attempt_claims
        SET state = terminal_state,
            failure_code = CASE WHEN terminal_state = 'invalid' THEN mutation->>'failure_code' ELSE NULL END,
            terminal_at = server_now
        WHERE validation_attempt_id = claim.validation_attempt_id;
        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            incident_id, policy_id, policy_version, primary_digest,
            secondary_digest, outcome, occurred_at
        ) VALUES (
            gen_random_uuid(), 'system', 'validation-worker', mutation->>'audit_action',
            'validation_attempt', claim.validation_attempt_id, claim.incident_id,
            CASE WHEN candidate IS NULL OR candidate = 'null'::jsonb THEN NULL ELSE claim.policy_id END,
            CASE WHEN candidate IS NULL OR candidate = 'null'::jsonb THEN NULL ELSE 1 END,
            claim.prepared_snapshot_digest, mutation_digest,
            CASE WHEN terminal_state = 'valid' THEN 'succeeded' ELSE 'rejected' END, server_now
        );
    ELSIF p_finish_state = 'completed' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'completed validation requires mutation';
    ELSE
        SELECT * INTO claim
        FROM sentinelflow.validation_attempt_claims current_claim
        WHERE current_claim.job_id = job.job_id AND current_claim.state = 'started'
        FOR UPDATE;
        IF FOUND AND p_finish_state = 'dead' THEN
            UPDATE sentinelflow.validation_attempt_claims
            SET state = 'interrupted', failure_code = p_error_code, terminal_at = server_now
            WHERE validation_attempt_id = claim.validation_attempt_id;
            INSERT INTO sentinelflow.validation_attempt_results (
                validation_attempt_id, result_state, failure_code,
                prepared_snapshot_digest, completed_at
            ) VALUES (
                claim.validation_attempt_id, 'interrupted', p_error_code,
                claim.prepared_snapshot_digest, server_now
            );
            INSERT INTO sentinelflow.audit_events (
                event_id, actor_type, actor_id, action, object_type, object_id,
                incident_id, primary_digest, outcome, occurred_at
            ) VALUES (
                gen_random_uuid(), 'system', 'validation-worker', 'validation_interrupted',
                'validation_attempt', claim.validation_attempt_id, claim.incident_id,
                claim.prepared_snapshot_digest, 'indeterminate', server_now
            );
        END IF;
    END IF;

    UPDATE sentinelflow.outbox_jobs current_job
    SET state = p_finish_state,
        available_at = CASE WHEN p_finish_state = 'retry'
            THEN server_now + requested_retry_delay ELSE current_job.available_at END,
        lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
        last_error_code = CASE WHEN p_finish_state = 'completed' THEN NULL ELSE p_error_code END,
        last_error_digest = CASE WHEN p_finish_state = 'completed' THEN NULL ELSE p_error_digest END,
        updated_at = server_now
    WHERE current_job.job_id = job.job_id;
    IF p_finish_state = 'dead' THEN
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest, dead_at
        ) VALUES (
            job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
            job.aggregate_version, job.attempts, p_error_code, p_error_digest, server_now
        ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
    END IF;
    job_id := job.job_id; state := p_finish_state; RETURN NEXT;
END
$function$;

REVOKE ALL ON sentinelflow.validation_attempt_claims,
    sentinelflow.validation_attempt_gates,
    sentinelflow.validation_attempt_results
FROM PUBLIC;
GRANT SELECT ON sentinelflow.validation_attempt_claims,
    sentinelflow.validation_attempt_gates,
    sentinelflow.validation_attempt_results
TO sentinelflow_read;

-- Validation publication and outbox completion are one fenced transaction.
-- Remove the broad legacy table mutation grants from the worker role.
REVOKE INSERT, UPDATE, DELETE ON sentinelflow.command_candidates,
    sentinelflow.policy_proposals,
    sentinelflow.validation_snapshots,
    sentinelflow.validation_gates
FROM sentinelflow_worker;
REVOKE INSERT, UPDATE, DELETE ON sentinelflow.validation_attempt_claims,
    sentinelflow.validation_attempt_gates,
    sentinelflow.validation_attempt_results
FROM sentinelflow_worker;

REVOKE ALL ON FUNCTION sentinelflow.validation_sha256(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.validation_jsonb_exact_keys(jsonb, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.validation_json_no_duplicate_keys(json) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.lease_validation_outbox_job(
    timestamptz, uuid, text, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.lease_validation_outbox_job(
    timestamptz, uuid, text, timestamptz
) TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_validation_attempt(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_validation_attempt(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_validation_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_validation_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json
) TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (9, 'validation_worker')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
