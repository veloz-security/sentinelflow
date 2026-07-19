BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- The pre-provider marker is separate from ai_analyses because the latter's
-- accepted schema intentionally requires post-call input/provenance fields.
-- One incident version can cross the provider boundary at most once.
CREATE TABLE IF NOT EXISTS analysis_attempt_claims (
    analysis_id uuid PRIMARY KEY,
    job_id uuid NOT NULL UNIQUE REFERENCES outbox_jobs (job_id) ON DELETE RESTRICT,
    incident_id uuid NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    incident_version integer NOT NULL CHECK (incident_version >= 1),
    evidence_snapshot_id uuid NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE SET NULL,
    evidence_snapshot_digest sha256_digest NULL,
    outbox_attempt integer NOT NULL CHECK (outbox_attempt >= 1),
    state text NOT NULL CHECK (state IN ('started', 'succeeded', 'failed', 'interrupted', 'no_call')),
    no_call_code ascii_id NULL,
    generated_at timestamptz NOT NULL,
    terminal_at timestamptz NULL,
    CONSTRAINT analysis_attempt_claim_snapshot CHECK (
        (evidence_snapshot_id IS NULL AND evidence_snapshot_digest IS NULL) OR
        (evidence_snapshot_id IS NOT NULL AND evidence_snapshot_digest IS NOT NULL)
    ),
    CONSTRAINT analysis_attempt_claim_state CHECK (
        (state = 'started' AND terminal_at IS NULL AND no_call_code IS NULL) OR
        (state IN ('succeeded', 'failed') AND terminal_at IS NOT NULL AND no_call_code IS NULL) OR
        (state IN ('interrupted', 'no_call') AND terminal_at IS NOT NULL AND no_call_code IS NOT NULL)
    ),
    UNIQUE (incident_id, incident_version)
);

CREATE INDEX IF NOT EXISTS analysis_attempt_claims_state_generated_idx
    ON analysis_attempt_claims (state, generated_at);

CREATE TABLE IF NOT EXISTS analysis_attempt_results (
    analysis_id uuid PRIMARY KEY REFERENCES analysis_attempt_claims (analysis_id) ON DELETE RESTRICT,
    result_state text NOT NULL CHECK (result_state IN ('succeeded', 'failed', 'interrupted', 'no_call')),
    failure_reason text NULL CHECK (failure_reason IS NULL OR failure_reason IN (
        'budget_exhausted', 'input_too_large', 'network_error', 'http_408', 'http_409',
        'rate_limited', 'server_error', 'timeout', 'refused', 'incomplete', 'schema_invalid',
        'evidence_invalid', 'cancelled', 'configuration_error', 'analysis_interrupted',
        'source_health_incomplete', 'history_incomplete', 'snapshot_incomplete'
    )),
    retry_eligible boolean NOT NULL DEFAULT false,
    provider_attempts smallint NOT NULL DEFAULT 0 CHECK (provider_attempts BETWEEN 0 AND 2),
    provider_response_id varchar(128) NULL CHECK (
        provider_response_id IS NULL OR
        (length(provider_response_id) BETWEEN 1 AND 128 AND provider_response_id !~ '[[:cntrl:]]')
    ),
    model ascii_id NULL,
    reasoning_effort text NULL CHECK (reasoning_effort IS NULL OR reasoning_effort = 'medium'),
    rate_card_version ascii_id NULL,
    input_bytes integer NOT NULL DEFAULT 0 CHECK (input_bytes BETWEEN 0 AND 12288),
    input_digest sha256_digest NULL,
    input_schema_digest sha256_digest NULL,
    prompt_digest sha256_digest NULL,
    output_schema_digest sha256_digest NULL,
    output_digest sha256_digest NULL,
    generated_command_digest sha256_digest NULL,
    input_tokens integer NULL CHECK (input_tokens IS NULL OR input_tokens BETWEEN 1 AND 12288),
    cached_input_tokens integer NULL CHECK (
        cached_input_tokens IS NULL OR cached_input_tokens BETWEEN 0 AND 12288
    ),
    output_tokens integer NULL CHECK (output_tokens IS NULL OR output_tokens BETWEEN 1 AND 2048),
    completed_at timestamptz NOT NULL,
    CONSTRAINT analysis_attempt_result_shape CHECK (
        (result_state = 'succeeded' AND failure_reason IS NULL AND retry_eligible = false AND
            provider_attempts BETWEEN 1 AND 2 AND provider_response_id IS NOT NULL AND
            model IS NOT NULL AND reasoning_effort IS NOT NULL AND rate_card_version IS NOT NULL AND
            input_bytes >= 2 AND input_digest IS NOT NULL AND input_schema_digest IS NOT NULL AND
            prompt_digest IS NOT NULL AND output_schema_digest IS NOT NULL AND
            output_digest IS NOT NULL AND generated_command_digest IS NOT NULL) OR
        (result_state = 'failed' AND failure_reason IS NOT NULL AND
            provider_response_id IS NULL AND model IS NULL AND reasoning_effort IS NULL AND
            rate_card_version IS NULL AND input_schema_digest IS NULL AND prompt_digest IS NULL AND
            output_schema_digest IS NULL AND output_digest IS NULL AND generated_command_digest IS NULL AND
            input_tokens IS NULL AND cached_input_tokens IS NULL AND output_tokens IS NULL AND
            ((input_bytes = 0 AND input_digest IS NULL) OR (input_bytes >= 2 AND input_digest IS NOT NULL))) OR
        (result_state IN ('interrupted', 'no_call') AND failure_reason IS NOT NULL AND
            retry_eligible = false AND provider_attempts = 0 AND provider_response_id IS NULL AND
            model IS NULL AND reasoning_effort IS NULL AND rate_card_version IS NULL AND
            input_bytes = 0 AND input_digest IS NULL AND input_schema_digest IS NULL AND
            prompt_digest IS NULL AND output_schema_digest IS NULL AND output_digest IS NULL AND
            generated_command_digest IS NULL AND input_tokens IS NULL AND
            cached_input_tokens IS NULL AND output_tokens IS NULL)
    ),
    CONSTRAINT analysis_attempt_usage_shape CHECK (
        (input_tokens IS NULL AND cached_input_tokens IS NULL AND output_tokens IS NULL) OR
        (input_tokens IS NOT NULL AND cached_input_tokens IS NOT NULL AND output_tokens IS NOT NULL AND
            cached_input_tokens <= input_tokens)
    )
);

-- Raw strict model output and its policy/command children remain explicitly
-- pre-validation data. They never satisfy policy_proposals or command_candidates.
CREATE TABLE IF NOT EXISTS analysis_output_staging (
    analysis_id uuid PRIMARY KEY REFERENCES analysis_attempt_claims (analysis_id) ON DELETE RESTRICT,
    state text NOT NULL DEFAULT 'pre_validation' CHECK (state = 'pre_validation'),
    structured_output bytea NOT NULL CHECK (octet_length(structured_output) BETWEEN 2 AND 1048576),
    policy_output bytea NOT NULL CHECK (octet_length(policy_output) BETWEEN 2 AND 65536),
    command_candidate_output bytea NOT NULL CHECK (octet_length(command_candidate_output) BETWEEN 2 AND 65536),
    output_digest sha256_digest NOT NULL,
    generated_command_digest sha256_digest NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE OR REPLACE FUNCTION sentinelflow.analysis_jsonb_exact_keys(
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

CREATE OR REPLACE FUNCTION sentinelflow.analysis_sha256(p_bytes bytea)
RETURNS sentinelflow.sha256_digest
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT ('sha256:' || encode(sha256(p_bytes), 'hex'))::sentinelflow.sha256_digest;
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.analysis_json_no_duplicate_keys(p_document json)
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
            IF NOT sentinelflow.analysis_json_no_duplicate_keys(child.value) THEN
                RETURN false;
            END IF;
        END LOOP;
    ELSIF json_typeof(p_document) = 'array' THEN
        FOR child IN SELECT value FROM json_array_elements(p_document)
        LOOP
            IF NOT sentinelflow.analysis_json_no_duplicate_keys(child.value) THEN
                RETURN false;
            END IF;
        END LOOP;
    END IF;
    RETURN true;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.lease_analysis_outbox_job(
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
    IF p_now IS NULL OR p_lease_expires_at IS NULL OR
       NOT isfinite(p_now) OR NOT isfinite(p_lease_expires_at) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis lease request';
    END IF;
    requested_lease_duration := p_lease_expires_at - p_now;
    IF p_lease_token IS NULL OR p_lease_owner IS NULL OR
       p_lease_owner !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       requested_lease_duration <= interval '0 seconds' OR
       requested_lease_duration > interval '60 seconds' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis lease request';
    END IF;

    FOR exhausted IN
        WITH candidates AS (
            SELECT candidate.job_id
            FROM sentinelflow.outbox_jobs candidate
            WHERE candidate.kind = 'analyze'
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
            last_error_digest = 'sha256:7ab6162a99777850888eb96ce59cf7bc74357fb33821a16030a07d1af3932804',
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

    SELECT candidate.* INTO leased
    FROM sentinelflow.outbox_jobs candidate
    WHERE candidate.kind = 'analyze'
      AND candidate.aggregate_type = 'incident'
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

CREATE OR REPLACE FUNCTION sentinelflow.prepare_analysis_attempt(
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
    incident sentinelflow.incidents%ROWTYPE;
    evidence sentinelflow.evidence_snapshots%ROWTYPE;
    prior sentinelflow.analysis_attempt_claims%ROWTYPE;
    analysis_id_value uuid := gen_random_uuid();
    no_call_code text;
    failure_reason text;
    signal_total integer;
    expanded_total integer;
    signals_json jsonb;
    impact_digest sentinelflow.sha256_digest;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis prepare request';
    END IF;

    SELECT * INTO job
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
      AND current_job.kind = 'analyze'
      AND current_job.aggregate_type = 'incident'
      AND current_job.state = 'leased'
      AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now
      AND current_job.updated_at <= server_now
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT * INTO incident
    FROM sentinelflow.incidents current_incident
    WHERE current_incident.incident_id = job.aggregate_id
      AND current_incident.version = job.aggregate_version
    FOR UPDATE;
    IF NOT FOUND THEN
        UPDATE sentinelflow.outbox_jobs
        SET state = 'dead', lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = 'analysis_incident_missing',
            last_error_digest = sentinelflow.analysis_sha256(convert_to('analysis_incident_missing', 'UTF8')),
            updated_at = server_now
        WHERE job_id = job.job_id;
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest, dead_at
        ) VALUES (
            job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
            job.aggregate_version, job.attempts, 'analysis_incident_missing',
            sentinelflow.analysis_sha256(convert_to('analysis_incident_missing', 'UTF8')), server_now
        ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            incident_id, primary_digest, outcome, occurred_at
        ) VALUES (
            gen_random_uuid(), 'system', 'analysis-worker', 'analysis_incident_missing',
            'outbox_job', job.job_id, job.aggregate_id,
            sentinelflow.analysis_sha256(convert_to('analysis_incident_missing', 'UTF8')),
            'failed', server_now
        );
        status := 'no_call'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    SELECT * INTO prior
    FROM sentinelflow.analysis_attempt_claims claim
    WHERE claim.incident_id = incident.incident_id
      AND claim.incident_version = incident.version
    FOR UPDATE;
    IF FOUND THEN
        IF prior.state = 'started' THEN
            UPDATE sentinelflow.analysis_attempt_claims
            SET state = 'interrupted', no_call_code = 'analysis_interrupted', terminal_at = server_now
            WHERE analysis_id = prior.analysis_id;
            INSERT INTO sentinelflow.analysis_attempt_results (
                analysis_id, result_state, failure_reason, completed_at
            ) VALUES (prior.analysis_id, 'interrupted', 'analysis_interrupted', server_now);
            UPDATE sentinelflow.incidents
            SET state = 'analysis_failed', analysis_failure_reason = 'incomplete', updated_at = server_now
            WHERE incident_id = incident.incident_id AND version = incident.version;
            UPDATE sentinelflow.outbox_jobs
            SET state = 'dead', lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
                last_error_code = 'analysis_interrupted',
                last_error_digest = sentinelflow.analysis_sha256(convert_to('analysis_interrupted', 'UTF8')),
                updated_at = server_now
            WHERE job_id = job.job_id;
            INSERT INTO sentinelflow.dead_letter_jobs (
                job_id, kind, aggregate_type, aggregate_id, aggregate_version,
                attempts, failure_code, failure_digest, dead_at
            ) VALUES (
                job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
                job.aggregate_version, job.attempts, 'analysis_interrupted',
                sentinelflow.analysis_sha256(convert_to('analysis_interrupted', 'UTF8')), server_now
            ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
            INSERT INTO sentinelflow.audit_events (
                event_id, actor_type, actor_id, action, object_type, object_id,
                incident_id, primary_digest, outcome, occurred_at
            ) VALUES (
                gen_random_uuid(), 'system', 'analysis-worker', 'analysis_interrupted',
                'analysis', prior.analysis_id, incident.incident_id,
                prior.evidence_snapshot_digest, 'indeterminate', server_now
            );
            status := 'interrupted'; snapshot := NULL; RETURN NEXT; RETURN;
        END IF;
        UPDATE sentinelflow.outbox_jobs
        SET state = 'completed', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = NULL, last_error_digest = NULL,
            updated_at = server_now
        WHERE job_id = job.job_id;
        status := 'terminal'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    SELECT * INTO evidence
    FROM sentinelflow.evidence_snapshots candidate
    WHERE candidate.incident_id = incident.incident_id
      AND candidate.incident_version = incident.version
    ORDER BY candidate.created_at DESC, candidate.evidence_snapshot_id
    FOR UPDATE
    LIMIT 1;
    IF NOT FOUND THEN
        no_call_code := 'snapshot_incomplete';
    ELSIF evidence.source_health_status <> 'complete' THEN
        no_call_code := 'source_health_incomplete';
    ELSIF evidence.expires_at <= server_now OR
          evidence.source_ip <> incident.source_ip OR evidence.service_label <> incident.service_label OR
          evidence.signal_count > 16 OR evidence.window_start <> incident.first_seen OR
          evidence.window_end <> incident.last_seen THEN
        no_call_code := 'snapshot_incomplete';
    END IF;

    IF no_call_code IS NULL AND EXISTS (
        SELECT 1
        FROM sentinelflow.evidence_snapshot_signals link
        JOIN sentinelflow.signals signal USING (signal_id)
        WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id
          AND signal.source_health_status <> 'complete'
    ) THEN
        no_call_code := 'source_health_incomplete';
    END IF;

    IF no_call_code IS NULL THEN
        SELECT count(*)::integer,
               COALESCE(sum(link.expanded_event_count), 0)::integer
        INTO signal_total, expanded_total
        FROM sentinelflow.evidence_snapshot_signals link
        WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id;

        IF signal_total <> evidence.signal_count OR expanded_total <> evidence.expanded_event_count OR
           NOT EXISTS (
               SELECT 1 FROM sentinelflow.evidence_snapshot_signals link
               WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id AND link.ordinal = 1
           ) OR EXISTS (
               SELECT 1
               FROM sentinelflow.evidence_snapshot_signals link
               JOIN sentinelflow.signals signal USING (signal_id)
               WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id
                 AND (link.evidence_id <> signal.signal_id::text OR
                      link.evidence_digest <> signal.evidence_digest OR
                      link.expanded_event_count <> signal.observed_count OR
                      signal.source_ip <> incident.source_ip OR
                      signal.service_label <> incident.service_label OR
                      signal.observed_count < signal.threshold_count OR
                      (signal.threshold_distinct IS NOT NULL AND
                          (signal.distinct_count IS NULL OR signal.distinct_count < signal.threshold_distinct)) OR
                      signal.window_start < evidence.window_start OR signal.window_end > evidence.window_end OR
                      signal.rule_id NOT IN ('path_scan.v1', 'request_burst.v1',
                          'login_bruteforce.v1', 'credential_stuffing.v1'))
           ) OR EXISTS (
               SELECT 1
               FROM (
                   SELECT link.ordinal,
                          row_number() OVER (ORDER BY link.signal_id::text) AS sorted_ordinal
                   FROM sentinelflow.evidence_snapshot_signals link
                   WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id
               ) ordering
               WHERE ordering.ordinal <> ordering.sorted_ordinal
           ) OR EXISTS (
               SELECT 1
               FROM sentinelflow.incident_signals incident_link
               WHERE incident_link.incident_id = incident.incident_id
                 AND incident_link.incident_version = incident.version
                 AND NOT EXISTS (
                     SELECT 1 FROM sentinelflow.evidence_snapshot_signals snapshot_link
                     WHERE snapshot_link.evidence_snapshot_id = evidence.evidence_snapshot_id
                       AND snapshot_link.signal_id = incident_link.signal_id
                 )
           ) OR EXISTS (
               SELECT 1
               FROM sentinelflow.evidence_snapshot_signals snapshot_link
               WHERE snapshot_link.evidence_snapshot_id = evidence.evidence_snapshot_id
                 AND NOT EXISTS (
                     SELECT 1 FROM sentinelflow.incident_signals incident_link
                     WHERE incident_link.incident_id = incident.incident_id
                       AND incident_link.incident_version = incident.version
                       AND incident_link.signal_id = snapshot_link.signal_id
                 )
           ) THEN
            no_call_code := 'snapshot_incomplete';
        END IF;
    END IF;

    IF no_call_code IS NULL AND (
        (SELECT count(*) FROM sentinelflow.evidence_snapshot_events event
         WHERE event.evidence_snapshot_id = evidence.evidence_snapshot_id) <> evidence.expanded_event_count OR
        EXISTS (
            SELECT 1
            FROM sentinelflow.evidence_snapshot_events event
            LEFT JOIN sentinelflow.signal_evidence source
              ON source.signal_id = event.signal_id
             AND source.event_kind = event.event_kind
             AND source.gateway_event_id IS NOT DISTINCT FROM event.gateway_event_id
             AND source.auth_event_id IS NOT DISTINCT FROM event.auth_event_id
             AND source.source_health_event_id IS NOT DISTINCT FROM event.source_health_event_id
             AND source.event_time = event.event_time
            WHERE event.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND source.evidence_link_id IS NULL
        ) OR EXISTS (
            SELECT 1
            FROM sentinelflow.evidence_snapshot_signals snapshot_signal
            JOIN sentinelflow.signal_evidence source ON source.signal_id = snapshot_signal.signal_id
            LEFT JOIN sentinelflow.evidence_snapshot_events event
              ON event.evidence_snapshot_id = snapshot_signal.evidence_snapshot_id
             AND event.signal_id = source.signal_id
             AND event.event_kind = source.event_kind
             AND event.gateway_event_id IS NOT DISTINCT FROM source.gateway_event_id
             AND event.auth_event_id IS NOT DISTINCT FROM source.auth_event_id
             AND event.source_health_event_id IS NOT DISTINCT FROM source.source_health_event_id
             AND event.event_time = source.event_time
            WHERE snapshot_signal.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND event.evidence_snapshot_event_id IS NULL
        ) OR EXISTS (
            SELECT 1
            FROM sentinelflow.evidence_snapshot_events snapshot_event
            LEFT JOIN sentinelflow.gateway_events gateway
              ON snapshot_event.event_kind = 'gateway'
             AND gateway.event_id = snapshot_event.gateway_event_id
             AND gateway.trust_state = 'trusted'
             AND gateway.source_ip = incident.source_ip
             AND gateway.service_label = incident.service_label
            LEFT JOIN sentinelflow.auth_events auth
              ON snapshot_event.event_kind = 'auth'
             AND auth.event_id = snapshot_event.auth_event_id
             AND auth.trust_state = 'trusted'
             AND auth.binding_state = 'verified'
             AND auth.source_ip = incident.source_ip
             AND auth.service_label = incident.service_label
            LEFT JOIN sentinelflow.source_health_intervals health
              ON snapshot_event.event_kind = 'source_health'
             AND health.event_id = snapshot_event.source_health_event_id
             AND health.trust_state = 'trusted'
             AND health.state = 'recovered'
             AND health.dropped_count = 0
            WHERE snapshot_event.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND ((snapshot_event.event_kind = 'gateway' AND gateway.event_id IS NULL) OR
                   (snapshot_event.event_kind = 'auth' AND auth.event_id IS NULL) OR
                   (snapshot_event.event_kind = 'source_health' AND health.event_id IS NULL))
        )
    ) THEN
        no_call_code := 'snapshot_incomplete';
    END IF;

    -- Complete 24-hour production history requires at least one known Gateway
    -- and auth producer, boundary receipts for each producer, healthy current
    -- checkpoints, and no unresolved transport/source-health loss. This is
    -- deliberately stricter than assuming absence of rows means no success.
    IF no_call_code IS NULL AND (
        (SELECT count(DISTINCT checkpoint.endpoint_kind)
         FROM sentinelflow.sender_checkpoints checkpoint
         WHERE checkpoint.endpoint_kind IN ('gateway', 'auth')) <> 2 OR
        EXISTS (
            SELECT 1 FROM sentinelflow.sender_checkpoints checkpoint
            WHERE checkpoint.endpoint_kind IN ('gateway', 'auth')
              AND (checkpoint.unknown_loss OR checkpoint.last_acknowledged_sequence < 1 OR
                   NOT EXISTS (
                       SELECT 1 FROM sentinelflow.ingest_batches early
                       WHERE early.sender_id = checkpoint.sender_id
                         AND early.endpoint_kind = checkpoint.endpoint_kind
                         AND early.received_at <= history_start
                   ) OR NOT EXISTS (
                       SELECT 1 FROM sentinelflow.ingest_batches recent
                       WHERE recent.sender_id = checkpoint.sender_id
                         AND recent.endpoint_kind = checkpoint.endpoint_kind
                         AND recent.received_at >= server_now - interval '5 minutes'
                   ) OR EXISTS (
                       SELECT 1 FROM sentinelflow.ingest_sequence_gaps gap
                       WHERE gap.sender_id = checkpoint.sender_id
                         AND gap.endpoint_kind = checkpoint.endpoint_kind
                   ))
        ) OR EXISTS (
            SELECT 1 FROM sentinelflow.source_health_intervals health
            WHERE (health.trust_state <> 'trusted' OR health.state IN ('degraded', 'lost') OR
                   health.dropped_count > 0)
              AND (health.interval_start IS NULL OR health.interval_end IS NULL OR
                   tstzrange(health.interval_start, health.interval_end, '[]') &&
                       tstzrange(history_start, server_now, '[]'))
        ) OR EXISTS (
            SELECT 1 FROM sentinelflow.gateway_events gateway
            WHERE gateway.source_ip = incident.source_ip
              AND gateway.service_label = incident.service_label
              AND gateway.started_at BETWEEN history_start AND server_now
              AND gateway.trust_state <> 'trusted'
        ) OR EXISTS (
            SELECT 1 FROM sentinelflow.auth_events auth
            WHERE auth.source_ip = incident.source_ip
              AND auth.service_label = incident.service_label
              AND auth.occurred_at BETWEEN history_start AND server_now
              AND auth.trust_state <> 'trusted'
        )
    ) THEN
        no_call_code := 'history_incomplete';
    END IF;

    IF no_call_code IS NULL AND EXISTS (
        SELECT 1 FROM sentinelflow.auth_events auth
        WHERE auth.source_ip = incident.source_ip
          AND auth.service_label = incident.service_label
          AND auth.occurred_at BETWEEN history_start AND server_now
          AND auth.outcome = 'succeeded'
    ) THEN
        no_call_code := 'history_success_seen';
    END IF;

    IF no_call_code IS NOT NULL THEN
        failure_reason := CASE
            WHEN no_call_code = 'snapshot_incomplete' THEN 'snapshot_incomplete'
            WHEN no_call_code IN ('history_incomplete', 'history_success_seen') THEN 'history_incomplete'
            ELSE 'source_health_incomplete'
        END;
        INSERT INTO sentinelflow.analysis_attempt_claims (
            analysis_id, job_id, incident_id, incident_version,
            evidence_snapshot_id, evidence_snapshot_digest, outbox_attempt,
            state, no_call_code, generated_at, terminal_at
        ) VALUES (
            analysis_id_value, job.job_id, incident.incident_id, incident.version,
            evidence.evidence_snapshot_id, evidence.snapshot_digest, job.attempts,
            'no_call', no_call_code, server_now, server_now
        );
        INSERT INTO sentinelflow.analysis_attempt_results (
            analysis_id, result_state, failure_reason, completed_at
        ) VALUES (analysis_id_value, 'no_call', failure_reason, server_now);
        UPDATE sentinelflow.incidents
        SET state = 'analysis_failed',
            analysis_failure_reason = CASE
                WHEN no_call_code = 'snapshot_incomplete' THEN 'evidence_invalid'
                ELSE 'incomplete'
            END,
            updated_at = server_now
        WHERE incident_id = incident.incident_id AND version = incident.version;
        UPDATE sentinelflow.outbox_jobs
        SET state = 'completed', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = NULL, last_error_digest = NULL,
            updated_at = server_now
        WHERE job_id = job.job_id;
        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            incident_id, primary_digest, outcome, occurred_at
        ) VALUES (
            gen_random_uuid(), 'system', 'analysis-worker', 'analysis_no_call',
            'analysis', analysis_id_value, incident.incident_id,
            evidence.snapshot_digest, 'rejected', server_now
        );
        status := 'no_call'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    impact_digest := sentinelflow.analysis_sha256(convert_to(
        'historical-impact-v1' || chr(10) || incident.incident_id::text || chr(10) ||
        incident.source_ip::text || chr(10) || incident.service_label::text || chr(10) ||
        to_char(history_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || chr(10) ||
        to_char(server_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || chr(10) ||
        'complete' || chr(10) || 'successful_auth_seen=false' || chr(10), 'UTF8'));

    INSERT INTO sentinelflow.analysis_attempt_claims (
        analysis_id, job_id, incident_id, incident_version,
        evidence_snapshot_id, evidence_snapshot_digest, outbox_attempt,
        state, generated_at
    ) VALUES (
        analysis_id_value, job.job_id, incident.incident_id, incident.version,
        evidence.evidence_snapshot_id, evidence.snapshot_digest, job.attempts,
        'started', server_now
    );
    UPDATE sentinelflow.incidents
    SET state = 'analyzing', analysis_failure_reason = NULL, updated_at = server_now
    WHERE incident_id = incident.incident_id AND version = incident.version;

    SELECT jsonb_agg(jsonb_build_object(
        'signal_id', signal.signal_id::text,
        'rule_id', signal.rule_id::text,
        'classification', CASE signal.rule_id::text
            WHEN 'path_scan.v1' THEN 'path_scan'
            WHEN 'request_burst.v1' THEN 'request_burst'
            WHEN 'login_bruteforce.v1' THEN 'brute_force'
            WHEN 'credential_stuffing.v1' THEN 'credential_stuffing'
        END,
        'window_start', signal.window_start,
        'window_end', signal.window_end,
        'event_count', signal.observed_count,
        'distinct_account_count', (
            SELECT count(DISTINCT auth.account_hash)
            FROM sentinelflow.evidence_snapshot_events event
            JOIN sentinelflow.auth_events auth ON auth.event_id = event.auth_event_id
            WHERE event.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND event.signal_id = signal.signal_id
              AND event.event_kind = 'auth'
              AND auth.outcome = 'failed' AND auth.binding_state = 'verified'
        ),
        'distinct_suspicious_path_count', (
            SELECT count(DISTINCT gateway.suspicious_path_id)
            FROM sentinelflow.evidence_snapshot_events event
            JOIN sentinelflow.gateway_events gateway ON gateway.event_id = event.gateway_event_id
            WHERE event.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND event.signal_id = signal.signal_id
              AND event.event_kind = 'gateway'
              AND gateway.suspicious_path_id <> 'none'
        ),
        'evidence_digest', signal.evidence_digest::text
    ) ORDER BY signal.signal_id::text)
    INTO signals_json
    FROM sentinelflow.evidence_snapshot_signals link
    JOIN sentinelflow.signals signal ON signal.signal_id = link.signal_id
    WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id;

    status := 'prepared';
    snapshot := jsonb_build_object(
        'incident_id', incident.incident_id::text,
        'incident_version', incident.version,
        'analysis_id', analysis_id_value::text,
        'generated_at', server_now,
        'evidence_snapshot_id', evidence.evidence_snapshot_id::text,
        'evidence_snapshot_digest', evidence.snapshot_digest::text,
        'source_ip', host(incident.source_ip),
        'service_label', incident.service_label::text,
        'window_start', evidence.window_start,
        'window_end', evidence.window_end,
        'detector_config_version', 'detector-config-v1',
        'signals', signals_json,
        'historical_impact', jsonb_build_object(
            'lookback_start', history_start,
            'lookback_end', server_now,
            'impact_digest', impact_digest::text
        )
    );
    RETURN NEXT;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finalize_analysis_attempt(
    p_job_id uuid,
    p_lease_token uuid,
    p_finish_state text,
    p_retry_at timestamptz,
    p_client_now timestamptz,
    p_error_code text,
    p_error_digest text,
    p_mutation jsonb
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
    claim sentinelflow.analysis_attempt_claims%ROWTYPE;
    success jsonb;
    failure jsonb;
    usage_document jsonb;
    analysis_bytes bytea;
    policy_bytes bytea;
    candidate_bytes bytea;
    analysis_document jsonb;
    policy_document jsonb;
    candidate_document jsonb;
    evidence_ids text[];
    snapshot_evidence_ids text[];
    signal_total integer;
    false_positive_factors jsonb;
    provider_attempts integer;
    input_bytes_value integer;
    input_tokens_value integer;
    cached_input_tokens_value integer;
    output_tokens_value integer;
    usage_trusted boolean;
    analysis_state text;
    validation_job_id uuid;
    validation_idempotency sentinelflow.sha256_digest;
    factor record;
BEGIN
    IF p_client_now IS NULL OR NOT isfinite(p_client_now) OR
       p_job_id IS NULL OR p_lease_token IS NULL OR
       p_finish_state NOT IN ('completed', 'retry', 'dead') OR
       (p_retry_at IS NOT NULL AND NOT isfinite(p_retry_at)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis finalize request';
    END IF;
    requested_retry_delay := p_retry_at - p_client_now;
    IF (p_finish_state = 'retry' AND
            (p_retry_at IS NULL OR requested_retry_delay < interval '0 seconds')) OR
       (p_finish_state <> 'retry' AND p_retry_at IS NOT NULL) OR
       (p_finish_state = 'completed' AND
            (p_error_code IS NOT NULL OR p_error_digest IS NOT NULL)) OR
       (p_finish_state <> 'completed' AND
            (p_error_code IS NULL OR p_error_digest IS NULL OR
             p_error_code !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
             p_error_digest !~ '^sha256:[0-9a-f]{64}$')) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis finalize request';
    END IF;

    SELECT * INTO job
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
      AND current_job.kind = 'analyze'
      AND current_job.aggregate_type = 'incident'
      AND current_job.state = 'leased'
      AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now
      AND current_job.updated_at <= server_now
    FOR UPDATE;
    IF NOT FOUND OR (p_finish_state = 'retry' AND job.attempts >= job.max_attempts) THEN
        RETURN;
    END IF;

    IF p_mutation IS NOT NULL AND p_mutation <> 'null'::jsonb THEN
        IF p_finish_state <> 'completed' OR NOT sentinelflow.analysis_jsonb_exact_keys(
            p_mutation, ARRAY[
                'analysis_id', 'audit_action', 'evidence_snapshot_digest',
                'evidence_snapshot_id', 'failure', 'incident_id', 'incident_version',
                'state', 'success', 'validation_requested'
            ]
        ) OR p_mutation->>'incident_id' !~
                '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
           p_mutation->>'analysis_id' !~
                '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
           p_mutation->>'evidence_snapshot_id' !~
                '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
           p_mutation->>'evidence_snapshot_digest' !~ '^sha256:[0-9a-f]{64}$' OR
           p_mutation->>'audit_action' !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
           jsonb_typeof(p_mutation->'incident_version') <> 'number' OR
           jsonb_typeof(p_mutation->'state') <> 'string' OR
           jsonb_typeof(p_mutation->'audit_action') <> 'string' OR
           jsonb_typeof(p_mutation->'validation_requested') <> 'boolean' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis mutation';
        END IF;

        SELECT * INTO claim
        FROM sentinelflow.analysis_attempt_claims current_claim
        WHERE current_claim.analysis_id = (p_mutation->>'analysis_id')::uuid
          AND current_claim.job_id = job.job_id
          AND current_claim.incident_id = job.aggregate_id
          AND current_claim.incident_version = job.aggregate_version
          AND current_claim.incident_id = (p_mutation->>'incident_id')::uuid
          AND current_claim.incident_version = (p_mutation->>'incident_version')::integer
          AND current_claim.evidence_snapshot_id = (p_mutation->>'evidence_snapshot_id')::uuid
          AND current_claim.evidence_snapshot_digest = p_mutation->>'evidence_snapshot_digest'
          AND current_claim.state = 'started'
        FOR UPDATE;
        IF NOT FOUND THEN
            RETURN;
        END IF;

        success := p_mutation->'success';
        failure := p_mutation->'failure';
        IF p_mutation->>'state' = 'analysis_failed' AND
           p_mutation->>'audit_action' = 'analysis_failed' AND
           (success IS NULL OR success = 'null'::jsonb) AND
           failure IS NOT NULL AND failure <> 'null'::jsonb AND
           (p_mutation->>'validation_requested')::boolean = false THEN
            IF NOT sentinelflow.analysis_jsonb_exact_keys(
                failure, ARRAY['attempts', 'input_bytes', 'input_digest', 'reason', 'retry_eligible']
            ) OR jsonb_typeof(failure->'retry_eligible') <> 'boolean' OR
               jsonb_typeof(failure->'attempts') <> 'number' OR
               jsonb_typeof(failure->'input_bytes') <> 'number' OR
               failure->>'reason' NOT IN (
                'budget_exhausted', 'input_too_large', 'network_error', 'http_408', 'http_409',
                'rate_limited', 'server_error', 'timeout', 'refused', 'incomplete',
                'schema_invalid', 'evidence_invalid', 'cancelled', 'configuration_error'
            ) OR (failure->>'attempts')::integer NOT BETWEEN 0 AND 2 OR
               (failure->>'input_bytes')::integer NOT BETWEEN 0 AND 12288 OR
               ((failure->>'input_bytes')::integer = 0 AND failure->>'input_digest' <> '') OR
               ((failure->>'input_bytes')::integer > 0 AND
                    failure->>'input_digest' !~ '^sha256:[0-9a-f]{64}$') OR
               (failure->>'retry_eligible')::boolean <>
                    (failure->>'reason' IN (
                        'network_error', 'http_408', 'http_409', 'rate_limited',
                        'server_error', 'timeout'
                    )) THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis failure';
            END IF;
            INSERT INTO sentinelflow.analysis_attempt_results (
                analysis_id, result_state, failure_reason, retry_eligible,
                provider_attempts, input_bytes, input_digest, completed_at
            ) VALUES (
                claim.analysis_id, 'failed', failure->>'reason',
                (failure->>'retry_eligible')::boolean,
                (failure->>'attempts')::integer, (failure->>'input_bytes')::integer,
                NULLIF(failure->>'input_digest', ''), server_now
            );
            UPDATE sentinelflow.analysis_attempt_claims
            SET state = 'failed', terminal_at = server_now
            WHERE analysis_id = claim.analysis_id;
            UPDATE sentinelflow.incidents
            SET state = 'analysis_failed', analysis_failure_reason = failure->>'reason',
                updated_at = server_now
            WHERE incident_id = claim.incident_id AND version = claim.incident_version;
            INSERT INTO sentinelflow.audit_events (
                event_id, actor_type, actor_id, action, object_type, object_id,
                incident_id, primary_digest, secondary_digest, outcome, occurred_at
            ) VALUES (
                gen_random_uuid(), 'system', 'analysis-worker', p_mutation->>'audit_action',
                'analysis', claim.analysis_id, claim.incident_id,
                NULLIF(failure->>'input_digest', ''), claim.evidence_snapshot_digest,
                'failed', server_now
            );
            analysis_state := 'failed';
        ELSIF p_mutation->>'state' = 'review_ready' AND
              p_mutation->>'audit_action' = 'analysis_succeeded' AND
              success IS NOT NULL AND success <> 'null'::jsonb AND
              (failure IS NULL OR failure = 'null'::jsonb) AND
              (p_mutation->>'validation_requested')::boolean = true THEN
            IF NOT sentinelflow.analysis_jsonb_exact_keys(success, ARRAY[
                'analysis_hex', 'attempts', 'command_candidate_hex', 'evidence_ids',
                'generated_command_digest', 'input_bytes', 'input_digest',
                'input_schema_digest', 'model', 'output_digest', 'output_schema_digest',
                'policy_hex', 'prompt_digest', 'rate_card_version', 'reasoning_effort',
                'response_id', 'usage'
            ]) OR success->>'model' <> 'gpt-5.6-sol' OR
               success->>'reasoning_effort' <> 'medium' OR
               success->>'rate_card_version' !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
               success->>'response_id' = '' OR length(success->>'response_id') > 128 OR
               btrim(success->>'response_id') <> success->>'response_id' OR
               success->>'response_id' ~ '[[:cntrl:]]' OR
               (success->>'attempts')::integer NOT BETWEEN 1 AND 2 OR
               (success->>'input_bytes')::integer NOT BETWEEN 2 AND 12288 OR
               success->>'input_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               success->>'input_schema_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               success->>'prompt_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               success->>'output_schema_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               success->>'output_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               success->>'generated_command_digest' !~ '^sha256:[0-9a-f]{64}$' OR
               success->>'analysis_hex' !~ '^[0-9a-f]+$' OR length(success->>'analysis_hex') % 2 <> 0 OR
               success->>'policy_hex' !~ '^[0-9a-f]+$' OR length(success->>'policy_hex') % 2 <> 0 OR
               success->>'command_candidate_hex' !~ '^[0-9a-f]+$' OR
                    length(success->>'command_candidate_hex') % 2 <> 0 OR
               jsonb_typeof(success->'evidence_ids') <> 'array' OR
               NOT sentinelflow.analysis_jsonb_exact_keys(
                    success->'usage', ARRAY['cached_input_tokens', 'input_tokens', 'output_tokens', 'trusted']
               ) THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis success';
            END IF;

            provider_attempts := (success->>'attempts')::integer;
            input_bytes_value := (success->>'input_bytes')::integer;
            analysis_bytes := decode(success->>'analysis_hex', 'hex');
            policy_bytes := decode(success->>'policy_hex', 'hex');
            candidate_bytes := decode(success->>'command_candidate_hex', 'hex');
            IF octet_length(analysis_bytes) NOT BETWEEN 2 AND 1048576 OR
               octet_length(policy_bytes) NOT BETWEEN 2 AND 65536 OR
               octet_length(candidate_bytes) NOT BETWEEN 2 AND 65536 OR
               sentinelflow.analysis_sha256(analysis_bytes) <> success->>'output_digest' THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'analysis output digest mismatch';
            END IF;
            BEGIN
                analysis_document := convert_from(analysis_bytes, 'UTF8')::jsonb;
                policy_document := convert_from(policy_bytes, 'UTF8')::jsonb;
                candidate_document := convert_from(candidate_bytes, 'UTF8')::jsonb;
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'analysis output is not strict UTF-8 JSON';
            END;

            IF NOT sentinelflow.analysis_json_no_duplicate_keys(
                    convert_from(analysis_bytes, 'UTF8')::json
               ) OR NOT sentinelflow.analysis_json_no_duplicate_keys(
                    convert_from(policy_bytes, 'UTF8')::json
               ) OR NOT sentinelflow.analysis_json_no_duplicate_keys(
                    convert_from(candidate_bytes, 'UTF8')::json
               ) THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'analysis output has duplicate JSON keys';
            END IF;

            IF NOT sentinelflow.analysis_jsonb_exact_keys(analysis_document, ARRAY[
                    'classification', 'confidence', 'evidence_ids', 'false_positive_factors',
                    'incident_summary', 'nftables_command_candidate', 'policy',
                    'schema_version', 'uncertainty'
               ]) OR analysis_document->>'schema_version' <> 'sentinelflow_analysis_v1' OR
               analysis_document->>'classification' NOT IN (
                    'credential_stuffing', 'brute_force', 'path_scan', 'request_burst', 'mixed', 'unknown'
               ) OR char_length(analysis_document->>'incident_summary') NOT BETWEEN 1 AND 1600 OR
               char_length(analysis_document->>'uncertainty') > 800 OR
               (analysis_document->>'confidence')::numeric NOT BETWEEN 0 AND 1 OR
               jsonb_typeof(analysis_document->'false_positive_factors') <> 'array' OR
               jsonb_array_length(analysis_document->'false_positive_factors') > 5 OR
               policy_document <> analysis_document->'policy' OR
               candidate_document <> analysis_document->'nftables_command_candidate' OR
               NOT sentinelflow.analysis_jsonb_exact_keys(policy_document, ARRAY[
                    'action', 'evidence_ids', 'rationale', 'schema_version', 'target_ip', 'ttl_seconds'
               ]) OR policy_document->>'schema_version' <> 'response-policy-v1' OR
               policy_document->>'action' <> 'block_ip' OR
               policy_document->>'target_ip' <> host((
                    SELECT source_ip FROM sentinelflow.incidents
                    WHERE incident_id = claim.incident_id AND version = claim.incident_version
               )) OR (policy_document->>'ttl_seconds')::integer NOT BETWEEN 60 AND 86400 OR
               char_length(policy_document->>'rationale') NOT BETWEEN 1 AND 800 OR
               NOT sentinelflow.analysis_jsonb_exact_keys(candidate_document, ARRAY[
                    'command', 'evidence_ids', 'schema_version', 'target_ip', 'timeout'
               ]) OR candidate_document->>'schema_version' <> 'nft-blacklist-v1' OR
               candidate_document->>'target_ip' <> policy_document->>'target_ip' OR
               candidate_document->>'timeout' !~ '^[1-9][0-9]{0,4}[smh]$' OR
               char_length(candidate_document->>'command') NOT BETWEEN 1 AND 256 OR
               sentinelflow.analysis_sha256(convert_to(candidate_document->>'command', 'UTF8')) <>
                    success->>'generated_command_digest' OR
               analysis_document->'evidence_ids' <> success->'evidence_ids' OR
               policy_document->'evidence_ids' <> success->'evidence_ids' OR
               candidate_document->'evidence_ids' <> success->'evidence_ids' THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'analysis structured output mismatch';
            END IF;

            SELECT array_agg(value ORDER BY ordinal), count(*)::integer
            INTO evidence_ids, signal_total
            FROM jsonb_array_elements_text(success->'evidence_ids') WITH ORDINALITY AS item(value, ordinal);
            SELECT array_agg(link.evidence_id ORDER BY link.ordinal)
            INTO snapshot_evidence_ids
            FROM sentinelflow.evidence_snapshot_signals link
            WHERE link.evidence_snapshot_id = claim.evidence_snapshot_id;
            IF signal_total < 1 OR signal_total > 50 OR evidence_ids IS DISTINCT FROM snapshot_evidence_ids OR
               EXISTS (
                   SELECT 1 FROM unnest(evidence_ids) WITH ORDINALITY AS item(value, ordinal)
                   WHERE ordinal > 1 AND value <= evidence_ids[ordinal - 1]
               ) THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'analysis evidence mismatch';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM jsonb_array_elements_text(analysis_document->'false_positive_factors') AS item(value)
                WHERE char_length(value) NOT BETWEEN 1 AND 240
            ) THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'analysis factor mismatch';
            END IF;

            usage_document := success->'usage';
            usage_trusted := (usage_document->>'trusted')::boolean;
            input_tokens_value := (usage_document->>'input_tokens')::integer;
            cached_input_tokens_value := (usage_document->>'cached_input_tokens')::integer;
            output_tokens_value := (usage_document->>'output_tokens')::integer;
            IF (usage_trusted AND (
                    input_tokens_value NOT BETWEEN 1 AND 12288 OR
                    cached_input_tokens_value NOT BETWEEN 0 AND input_tokens_value OR
                    output_tokens_value NOT BETWEEN 1 AND 2048
                )) OR (NOT usage_trusted AND (
                    input_tokens_value <> 0 OR cached_input_tokens_value <> 0 OR output_tokens_value <> 0
                )) THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'analysis usage mismatch';
            END IF;

            INSERT INTO sentinelflow.ai_analyses (
                analysis_id, incident_id, incident_version, evidence_snapshot_id,
                evidence_snapshot_digest, attempt, model, reasoning_effort, store_enabled,
                input_schema_digest, prompt_digest, output_schema_digest, input_digest,
                input_bytes, result_state, output_digest, incident_summary, classification,
                confidence, uncertainty, input_tokens, cached_input_tokens, output_tokens,
                started_at, completed_at
            ) VALUES (
                claim.analysis_id, claim.incident_id, claim.incident_version,
                claim.evidence_snapshot_id, claim.evidence_snapshot_digest,
                provider_attempts, success->>'model', success->>'reasoning_effort', false,
                success->>'input_schema_digest', success->>'prompt_digest',
                success->>'output_schema_digest', success->>'input_digest', input_bytes_value,
                'succeeded', success->>'output_digest', analysis_document->>'incident_summary',
                analysis_document->>'classification', (analysis_document->>'confidence')::numeric,
                analysis_document->>'uncertainty',
                CASE WHEN usage_trusted THEN input_tokens_value ELSE NULL END,
                CASE WHEN usage_trusted THEN cached_input_tokens_value ELSE NULL END,
                CASE WHEN usage_trusted THEN output_tokens_value ELSE NULL END,
                claim.generated_at, server_now
            );

            false_positive_factors := analysis_document->'false_positive_factors';
            FOR factor IN
                SELECT value, ordinal
                FROM jsonb_array_elements_text(false_positive_factors)
                    WITH ORDINALITY AS item(value, ordinal)
            LOOP
                INSERT INTO sentinelflow.analysis_false_positive_factors (
                    analysis_id, ordinal, factor
                ) VALUES (claim.analysis_id, factor.ordinal, factor.value);
            END LOOP;
            INSERT INTO sentinelflow.analysis_evidence (
                analysis_id, ordinal, evidence_snapshot_id, signal_id, evidence_id
            )
            SELECT claim.analysis_id, link.ordinal, claim.evidence_snapshot_id,
                   link.signal_id, link.evidence_id
            FROM sentinelflow.evidence_snapshot_signals link
            WHERE link.evidence_snapshot_id = claim.evidence_snapshot_id
            ORDER BY link.ordinal;

            INSERT INTO sentinelflow.analysis_attempt_results (
                analysis_id, result_state, provider_attempts, provider_response_id,
                model, reasoning_effort, rate_card_version, input_bytes, input_digest,
                input_schema_digest, prompt_digest, output_schema_digest, output_digest,
                generated_command_digest, input_tokens, cached_input_tokens, output_tokens,
                completed_at
            ) VALUES (
                claim.analysis_id, 'succeeded', provider_attempts, success->>'response_id',
                success->>'model', success->>'reasoning_effort', success->>'rate_card_version',
                input_bytes_value, success->>'input_digest', success->>'input_schema_digest',
                success->>'prompt_digest', success->>'output_schema_digest', success->>'output_digest',
                success->>'generated_command_digest',
                CASE WHEN usage_trusted THEN input_tokens_value ELSE NULL END,
                CASE WHEN usage_trusted THEN cached_input_tokens_value ELSE NULL END,
                CASE WHEN usage_trusted THEN output_tokens_value ELSE NULL END,
                server_now
            );
            INSERT INTO sentinelflow.analysis_output_staging (
                analysis_id, structured_output, policy_output, command_candidate_output,
                output_digest, generated_command_digest, created_at
            ) VALUES (
                claim.analysis_id, analysis_bytes, policy_bytes, candidate_bytes,
                success->>'output_digest', success->>'generated_command_digest', server_now
            );
            UPDATE sentinelflow.analysis_attempt_claims
            SET state = 'succeeded', terminal_at = server_now
            WHERE analysis_id = claim.analysis_id;
            UPDATE sentinelflow.incidents
            SET state = 'review_ready', analysis_failure_reason = NULL, updated_at = server_now
            WHERE incident_id = claim.incident_id AND version = claim.incident_version;

            validation_job_id := gen_random_uuid();
            validation_idempotency := sentinelflow.analysis_sha256(convert_to(
                'analysis-validation-outbox-v1' || chr(10) || claim.analysis_id::text || chr(10), 'UTF8'));
            INSERT INTO sentinelflow.outbox_jobs (
                job_id, kind, aggregate_type, aggregate_id, aggregate_version,
                operation, idempotency_key, state, available_at, max_attempts,
                created_at, updated_at
            ) VALUES (
                validation_job_id, 'validate', 'analysis_staging', claim.analysis_id, 1,
                NULL, validation_idempotency, 'pending', server_now, 8, server_now, server_now
            );
            INSERT INTO sentinelflow.audit_events (
                event_id, actor_type, actor_id, action, object_type, object_id,
                incident_id, primary_digest, secondary_digest, outcome, occurred_at
            ) VALUES (
                gen_random_uuid(), 'system', 'analysis-worker', p_mutation->>'audit_action',
                'analysis', claim.analysis_id, claim.incident_id,
                success->>'output_digest', claim.evidence_snapshot_digest, 'succeeded', server_now
            );
            analysis_state := 'succeeded';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis mutation shape';
        END IF;
    ELSE
        IF p_finish_state = 'completed' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'completed analysis requires mutation';
        END IF;
        SELECT * INTO claim
        FROM sentinelflow.analysis_attempt_claims current_claim
        WHERE current_claim.job_id = job.job_id AND current_claim.state = 'started'
        FOR UPDATE;
        IF FOUND THEN
            -- A claim means the provider boundary might have been crossed.
            -- Never schedule a second call from an uncommitted terminal result.
            UPDATE sentinelflow.analysis_attempt_claims
            SET state = 'interrupted', no_call_code = 'analysis_interrupted', terminal_at = server_now
            WHERE analysis_id = claim.analysis_id;
            INSERT INTO sentinelflow.analysis_attempt_results (
                analysis_id, result_state, failure_reason, completed_at
            ) VALUES (claim.analysis_id, 'interrupted', 'analysis_interrupted', server_now);
            UPDATE sentinelflow.incidents
            SET state = 'analysis_failed', analysis_failure_reason = 'incomplete', updated_at = server_now
            WHERE incident_id = claim.incident_id AND version = claim.incident_version;
            p_finish_state := 'dead';
            p_retry_at := NULL;
            p_error_code := 'analysis_interrupted';
            p_error_digest := sentinelflow.analysis_sha256(convert_to('analysis_interrupted', 'UTF8'));
            INSERT INTO sentinelflow.audit_events (
                event_id, actor_type, actor_id, action, object_type, object_id,
                incident_id, primary_digest, outcome, occurred_at
            ) VALUES (
                gen_random_uuid(), 'system', 'analysis-worker', 'analysis_interrupted',
                'analysis', claim.analysis_id, claim.incident_id,
                claim.evidence_snapshot_digest, 'indeterminate', server_now
            );
        END IF;
    END IF;

    UPDATE sentinelflow.outbox_jobs current_job
    SET state = p_finish_state,
        available_at = CASE
            WHEN p_finish_state = 'retry' THEN server_now + requested_retry_delay
            ELSE current_job.available_at
        END,
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

    job_id := job.job_id;
    state := p_finish_state;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON sentinelflow.analysis_attempt_claims,
    sentinelflow.analysis_attempt_results,
    sentinelflow.analysis_output_staging
FROM PUBLIC;
GRANT SELECT ON sentinelflow.analysis_attempt_claims,
    sentinelflow.analysis_attempt_results,
    sentinelflow.analysis_output_staging
TO sentinelflow_read;

-- Analysis writes and its incident/outbox transitions are owned by the atomic
-- functions. The worker retains read access needed by other bounded packages.
REVOKE INSERT, UPDATE, DELETE ON sentinelflow.ai_analyses,
    sentinelflow.analysis_false_positive_factors,
    sentinelflow.analysis_evidence
FROM sentinelflow_worker;
REVOKE UPDATE ON sentinelflow.incidents FROM sentinelflow_worker;

REVOKE ALL ON FUNCTION sentinelflow.analysis_jsonb_exact_keys(jsonb, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.analysis_sha256(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.analysis_json_no_duplicate_keys(json) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.lease_analysis_outbox_job(
    timestamptz, uuid, text, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.lease_analysis_outbox_job(
    timestamptz, uuid, text, timestamptz
) TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (8, 'analysis_worker')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
