BEGIN;

DO $metrics_role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinelflow_metrics') THEN
        CREATE ROLE sentinelflow_metrics
            NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles role
        WHERE role.rolname = 'sentinelflow_metrics'
          AND (role.rolinherit OR role.rolsuper OR role.rolcreatedb OR
               role.rolcreaterole OR role.rolreplication OR role.rolbypassrls)
    ) OR EXISTS (
        SELECT 1 FROM pg_auth_members membership
        JOIN pg_roles member ON member.oid = membership.member
        JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
        WHERE member.rolname = 'sentinelflow_metrics'
           OR granted_role.rolname = 'sentinelflow_metrics'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'metrics role has inherited or elevated authority';
    END IF;
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO sentinelflow_metrics', current_database()
    );
    EXECUTE format(
        'ALTER ROLE sentinelflow_metrics IN DATABASE %I '
        'SET search_path = sentinelflow, pg_catalog', current_database()
    );
END
$metrics_role$;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- A lease is deliberately not an administrator/session record. It contains
-- only a random connection identity, a bounded process identity, and database
-- timestamps required to expire a crashed API process without coordination.
CREATE TABLE IF NOT EXISTS sentinelflow.sse_client_leases (
    lease_id uuid PRIMARY KEY,
    process_instance sentinelflow.ascii_id NOT NULL
        CHECK (length(process_instance) <= 64),
    connected_at timestamptz NOT NULL,
    touched_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT sse_client_lease_time_order CHECK (
        connected_at <= touched_at AND
        expires_at = touched_at + interval '45 seconds'
    )
);

CREATE INDEX IF NOT EXISTS sse_client_leases_expiry_idx
    ON sentinelflow.sse_client_leases (expires_at);

CREATE OR REPLACE FUNCTION sentinelflow.register_sse_client_lease_000024(
    p_lease_id uuid,
    p_process_instance text
)
RETURNS timestamptz
LANGUAGE plpgsql
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    lease_expiry timestamptz;
BEGIN
    IF p_lease_id = '00000000-0000-0000-0000-000000000000'::uuid OR
       p_process_instance !~ '^[a-z0-9][a-z0-9._-]{0,63}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid SSE client lease registration';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('sse-client-lease-cap-v1', 0));
    DELETE FROM sentinelflow.sse_client_leases
    WHERE expires_at <= server_now;
    IF EXISTS (
        SELECT 1 FROM sentinelflow.sse_client_leases
        WHERE lease_id = p_lease_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23505',
            MESSAGE = 'SSE client lease identity already exists';
    END IF;
    IF (SELECT count(*) FROM sentinelflow.sse_client_leases) >= 256 THEN
        RAISE EXCEPTION USING ERRCODE = '53300',
            MESSAGE = 'SSE client lease capacity exhausted';
    END IF;

    INSERT INTO sentinelflow.sse_client_leases (
        lease_id, process_instance, connected_at, touched_at, expires_at
    ) VALUES (
        p_lease_id, p_process_instance, server_now, server_now,
        server_now + interval '45 seconds'
    )
    RETURNING expires_at INTO lease_expiry;
    RETURN lease_expiry;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.touch_sse_client_lease_000024(
    p_lease_id uuid,
    p_process_instance text
)
RETURNS timestamptz
LANGUAGE plpgsql
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    lease_expiry timestamptz;
BEGIN
    IF p_lease_id = '00000000-0000-0000-0000-000000000000'::uuid OR
       p_process_instance !~ '^[a-z0-9][a-z0-9._-]{0,63}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid SSE client lease touch';
    END IF;
    UPDATE sentinelflow.sse_client_leases
    SET touched_at = server_now,
        expires_at = server_now + interval '45 seconds'
    WHERE lease_id = p_lease_id
      AND process_instance = p_process_instance
      AND expires_at > server_now
    RETURNING expires_at INTO lease_expiry;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'SSE client lease is missing or expired';
    END IF;
    RETURN lease_expiry;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.unregister_sse_client_lease_000024(
    p_lease_id uuid,
    p_process_instance text
)
RETURNS boolean
LANGUAGE plpgsql
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF p_lease_id = '00000000-0000-0000-0000-000000000000'::uuid OR
       p_process_instance !~ '^[a-z0-9][a-z0-9._-]{0,63}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid SSE client lease unregister';
    END IF;
    DELETE FROM sentinelflow.sse_client_leases
    WHERE lease_id = p_lease_id
      AND process_instance = p_process_instance;
    RETURN FOUND;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.control_observability_utc_date_000024(
    p_observed_at timestamptz
)
RETURNS date
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT (p_observed_at AT TIME ZONE 'UTC')::date;
$function$;

-- This SECURITY DEFINER boundary is the only database query used by the
-- control metrics exporter. It emits aggregate numbers over closed dimensions;
-- identifiers, addresses, paths, actors, digests, and free-form error values
-- never cross the boundary.
CREATE OR REPLACE FUNCTION sentinelflow.control_observability_samples_000024()
RETURNS TABLE (
    metric_name text,
    label_1_name text,
    label_1_value text,
    label_2_name text,
    label_2_value text,
    sample_value double precision
)
LANGUAGE sql
STABLE
SECURITY DEFINER
ROWS 512
SET search_path = pg_catalog, sentinelflow
AS $function$
WITH
clock AS (
    SELECT statement_timestamp() AS observed_at
),
source_dimensions(state, cause) AS (
    VALUES
        ('degraded', 'queue_overflow'), ('degraded', 'delivery_outage'),
        ('degraded', 'rejected_batch'), ('degraded', 'sequence_gap'),
        ('degraded', 'permanent_loss'), ('degraded', 'unclean_restart'),
        ('degraded', 'unknown_loss'), ('degraded', 'recovered'),
        ('lost', 'queue_overflow'), ('lost', 'delivery_outage'),
        ('lost', 'rejected_batch'), ('lost', 'sequence_gap'),
        ('lost', 'permanent_loss'), ('lost', 'unclean_restart'),
        ('lost', 'unknown_loss'), ('lost', 'recovered'),
        ('recovered', 'queue_overflow'), ('recovered', 'delivery_outage'),
        ('recovered', 'rejected_batch'), ('recovered', 'sequence_gap'),
        ('recovered', 'permanent_loss'), ('recovered', 'unclean_restart'),
        ('recovered', 'unknown_loss'), ('recovered', 'recovered')
),
source_counts AS (
    SELECT state, cause, count(*)::double precision AS value
    FROM source_health_intervals
    GROUP BY state, cause
),
source_drop_counts AS (
    SELECT cause, sum(dropped_count)::double precision AS value
    FROM source_health_intervals
    GROUP BY cause
),
latest_source AS (
    SELECT DISTINCT ON (health.sender_id, batch.endpoint_kind, health.source_id)
           health.sender_id, batch.endpoint_kind, health.source_id, health.state
    FROM source_health_intervals health
    JOIN ingest_batches batch
      ON batch.sender_id = health.sender_id
     AND batch.sender_epoch = health.sender_epoch
     AND batch.batch_id = health.batch_id
    WHERE health.trust_state = 'trusted'
    ORDER BY health.sender_id, batch.endpoint_kind, health.source_id,
        health.occurred_at DESC, health.received_at DESC,
        CASE health.state WHEN 'lost' THEN 0 WHEN 'degraded' THEN 1 ELSE 2 END
),
source_states(state) AS (
    VALUES ('degraded'), ('lost'), ('recovered')
),
source_trust_reasons(reason) AS (
    VALUES ('timestamp_skew'), ('batch_conflict')
),
source_untrusted_counts AS (
    SELECT trust_reason AS reason, count(*)::double precision AS value
    FROM source_health_intervals
    WHERE trust_state = 'untrusted'
    GROUP BY trust_reason
),
endpoint_dimensions(endpoint) AS (
    VALUES ('gateway'), ('auth')
),
expected_source_states(state) AS (
    VALUES ('healthy'), ('missing_report'), ('open_gap'), ('checkpoint_stale'),
        ('degraded'), ('lost')
),
active_source_bindings AS (
    SELECT binding.binding_id, binding.sender_id, binding.endpoint_kind
    FROM expected_source_bindings binding CROSS JOIN clock
    WHERE binding.effective_at <= clock.observed_at
      AND NOT EXISTS (
          SELECT 1 FROM expected_source_binding_retirements retirement
          WHERE retirement.binding_id = binding.binding_id
            AND retirement.retired_at <= clock.observed_at
      )
),
latest_binding_coverage AS (
    SELECT binding.binding_id,
           bool_and(
               coverage.trust_state = 'trusted' AND
               coverage.sender_id = binding.sender_id AND
               coverage.endpoint_kind = binding.endpoint_kind AND
               checkpoint.sender_id IS NOT NULL AND
               coverage.sender_epoch = checkpoint.sender_epoch AND
               coverage.covered_through_sequence = checkpoint.last_acknowledged_sequence AND
               coverage.received_at >= clock.observed_at - interval '5 minutes' AND
               coverage.received_at <= clock.observed_at
           ) AS current_trusted
    FROM active_source_bindings binding
    CROSS JOIN clock
    LEFT JOIN sender_checkpoints checkpoint
      ON checkpoint.sender_id = binding.sender_id
     AND checkpoint.endpoint_kind = binding.endpoint_kind
    JOIN source_coverage_attestations coverage
      ON coverage.binding_id = binding.binding_id
     AND coverage.received_at = (
         SELECT max(candidate.received_at)
         FROM source_coverage_attestations candidate
         WHERE candidate.binding_id = binding.binding_id
     )
    GROUP BY binding.binding_id
),
latest_trusted_binding_health AS (
    SELECT DISTINCT ON (health.sender_id, batch.endpoint_kind)
           health.sender_id, batch.endpoint_kind, health.state
    FROM source_health_intervals health
    JOIN ingest_batches batch
      ON batch.sender_id = health.sender_id
     AND batch.sender_epoch = health.sender_epoch
     AND batch.batch_id = health.batch_id
    WHERE health.trust_state = 'trusted'
    ORDER BY health.sender_id, batch.endpoint_kind, health.occurred_at DESC,
        health.received_at DESC,
        CASE health.state WHEN 'lost' THEN 0 WHEN 'degraded' THEN 1 ELSE 2 END
),
expected_source_status AS (
    SELECT binding.binding_id, binding.endpoint_kind,
           NOT COALESCE(coverage.current_trusted, false) AS missing_report,
           EXISTS (
               SELECT 1 FROM ingest_sequence_gaps gap
               WHERE gap.sender_id = binding.sender_id
                 AND gap.endpoint_kind = binding.endpoint_kind
                 AND EXISTS (
                     SELECT 1 FROM ingest_gap_lifecycle lifecycle
                     WHERE lifecycle.lifecycle_state = 'opened'
                       AND lifecycle.sender_id = gap.sender_id
                       AND lifecycle.endpoint_kind = gap.endpoint_kind
                       AND lifecycle.sender_epoch = gap.sender_epoch
                       AND lifecycle.sequence_start = gap.sequence_start
                       AND lifecycle.sequence_end = gap.sequence_end
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM ingest_gap_lifecycle lifecycle
                     WHERE lifecycle.lifecycle_state IN ('late_closed', 'lost')
                       AND lifecycle.sender_id = gap.sender_id
                       AND lifecycle.endpoint_kind = gap.endpoint_kind
                       AND lifecycle.sender_epoch = gap.sender_epoch
                       AND lifecycle.sequence_start = gap.sequence_start
                       AND lifecycle.sequence_end = gap.sequence_end
                 )
           ) AS open_gap,
           checkpoint.sender_id IS NULL OR
               checkpoint.updated_at < clock.observed_at - interval '5 minutes' OR
               checkpoint.updated_at > clock.observed_at
               AS checkpoint_stale,
           COALESCE(health.state, 'recovered') AS health_state
    FROM active_source_bindings binding
    CROSS JOIN clock
    LEFT JOIN sender_checkpoints checkpoint
      ON checkpoint.sender_id = binding.sender_id
     AND checkpoint.endpoint_kind = binding.endpoint_kind
    LEFT JOIN latest_trusted_binding_health health
      ON health.sender_id = binding.sender_id
     AND health.endpoint_kind = binding.endpoint_kind
    LEFT JOIN latest_binding_coverage coverage
      ON coverage.binding_id = binding.binding_id
),
latest_batch_by_endpoint AS (
    SELECT endpoint_kind, max(received_at) AS received_at
    FROM ingest_batches
    GROUP BY endpoint_kind
),
auth_binding_states(state) AS (
    VALUES ('pending'), ('verified'), ('untrusted')
),
auth_binding_counts AS (
    SELECT binding_state AS state, count(*)::double precision AS value
    FROM auth_events
    GROUP BY binding_state
),
signal_kinds(kind) AS (
    VALUES ('path_scan'), ('request_burst'), ('brute_force'), ('credential_stuffing')
),
source_health_completeness(status) AS (
    VALUES ('complete'), ('incomplete')
),
signal_counts AS (
    SELECT kind, source_health_status AS status, count(*)::double precision AS value
    FROM signals
    GROUP BY kind, source_health_status
),
incident_kinds(kind) AS (
    VALUES ('credential_stuffing'), ('brute_force'), ('path_scan'),
        ('request_burst'), ('mixed'), ('unknown')
),
incident_states(state) AS (
    VALUES ('open'), ('analyzing'), ('review_ready'), ('analysis_failed'), ('closed')
),
incident_counts AS (
    SELECT kind, state, count(*)::double precision AS value
    FROM incidents
    GROUP BY kind, state
),
outbox_kinds(kind) AS (
    VALUES ('detect'), ('correlate'), ('analyze'), ('validate'),
        ('dispatch_add'), ('dispatch_revoke'), ('dispatch_inspect'),
        ('reconcile'), ('retention'), ('audit_recovery')
),
outbox_states(state) AS (
    VALUES ('pending'), ('leased'), ('retry'), ('completed'), ('dead')
),
outbox_counts AS (
    SELECT kind, state, count(*)::double precision AS value
    FROM outbox_jobs
    GROUP BY kind, state
),
outbox_oldest AS (
    SELECT job.kind,
           greatest(0, extract(epoch FROM (clock.observed_at - min(job.available_at))))::double precision AS value
    FROM outbox_jobs job CROSS JOIN clock
    WHERE job.state IN ('pending', 'retry') AND job.available_at <= clock.observed_at
    GROUP BY job.kind, clock.observed_at
),
outbox_lease_lag AS (
    SELECT job.kind,
           greatest(0, extract(epoch FROM (clock.observed_at - min(job.lease_expires_at))))::double precision AS value
    FROM outbox_jobs job CROSS JOIN clock
    WHERE job.state = 'leased' AND job.lease_expires_at <= clock.observed_at
    GROUP BY job.kind, clock.observed_at
),
dead_letter_counts AS (
    SELECT job.kind, count(*)::double precision AS value
    FROM dead_letter_jobs dead
    JOIN outbox_jobs job ON job.job_id = dead.job_id
    WHERE dead.resolution_state = 'unresolved'
    GROUP BY job.kind
),
analysis_states(state) AS (
    VALUES ('started'), ('succeeded'), ('failed'), ('interrupted'), ('no_call')
),
analysis_counts AS (
    SELECT state, count(*)::double precision AS value
    FROM analysis_attempt_claims
    GROUP BY state
),
provider_dimensions(provider_kind) AS (
    VALUES ('openai_responses'), ('deterministic_stub')
),
provider_counts AS (
    SELECT provider_kind, count(*)::double precision AS value
    FROM analysis_attempt_results
    WHERE result_state = 'succeeded'
    GROUP BY provider_kind
),
reservation_states(state) AS (
    VALUES ('active'), ('settled'), ('expired')
),
reservation_counts AS (
    SELECT state, count(*)::double precision AS value
    FROM ai_budget_reservations
    GROUP BY state
),
latency_statistics(statistic) AS (
    VALUES ('average'), ('p95'), ('maximum')
),
analysis_latency AS (
    SELECT COALESCE(avg(extract(epoch FROM (result.completed_at - claim.generated_at))), 0)::double precision AS average,
           COALESCE(percentile_cont(0.95) WITHIN GROUP (
               ORDER BY extract(epoch FROM (result.completed_at - claim.generated_at))
           ), 0)::double precision AS p95,
           COALESCE(max(extract(epoch FROM (result.completed_at - claim.generated_at))), 0)::double precision AS maximum
    FROM analysis_attempt_results result
    JOIN analysis_attempt_claims claim USING (analysis_id)
),
token_kinds(kind) AS (
    VALUES ('input'), ('cached_input'), ('output')
),
analysis_tokens AS (
    SELECT COALESCE(sum(input_tokens), 0)::double precision AS input,
           COALESCE(sum(cached_input_tokens), 0)::double precision AS cached_input,
           COALESCE(sum(output_tokens), 0)::double precision AS output
    FROM analysis_attempt_results
),
analysis_failure_reasons(reason) AS (
    VALUES ('budget_exhausted'), ('input_too_large'), ('network_error'),
        ('http_408'), ('http_409'), ('rate_limited'), ('server_error'),
        ('timeout'), ('refused'), ('incomplete'), ('schema_invalid'),
        ('evidence_invalid'), ('cancelled'), ('configuration_error'),
        ('analysis_interrupted'), ('source_health_incomplete'),
        ('history_incomplete'), ('snapshot_incomplete')
),
analysis_failure_counts AS (
    SELECT failure_reason AS reason, count(*)::double precision AS value
    FROM analysis_attempt_results
    WHERE failure_reason IS NOT NULL
    GROUP BY failure_reason
),
validation_states(state) AS (
    VALUES ('started'), ('valid'), ('invalid'), ('interrupted')
),
validation_counts AS (
    SELECT state, count(*)::double precision AS value
    FROM validation_attempt_claims
    GROUP BY state
),
validation_gate_names(gate_name) AS (
    VALUES ('structured_output'), ('command_grammar'),
        ('policy_evidence_command_consistency'), ('protected_network'),
        ('owned_schema_syntax'), ('historical_impact')
),
boolean_values(result) AS (
    VALUES ('passed'), ('failed')
),
validation_gate_counts AS (
    SELECT gate_name, CASE WHEN passed THEN 'passed' ELSE 'failed' END AS result,
           count(*)::double precision AS value
    FROM validation_attempt_gates
    GROUP BY gate_name, passed
),
validation_failure_reasons(reason) AS (
    VALUES ('structured_output'), ('command_grammar'),
        ('policy_evidence_command_consistency'), ('protected_network'),
        ('owned_schema_syntax'), ('historical_impact'), ('interrupted')
),
validation_failure_counts AS (
    SELECT COALESCE(failed_gate, 'interrupted') AS reason,
           count(*)::double precision AS value
    FROM validation_attempt_results
    WHERE result_state IN ('invalid', 'interrupted')
    GROUP BY COALESCE(failed_gate, 'interrupted')
),
challenge_operations(operation) AS (
    VALUES ('approve'), ('reject'), ('revoke')
),
challenge_states(state) AS (
    VALUES ('pending'), ('expired'), ('consumed')
),
challenge_counts AS (
    SELECT operation,
           CASE WHEN consumed_at IS NOT NULL THEN 'consumed'
                WHEN expires_at <= clock.observed_at THEN 'expired'
                ELSE 'pending' END AS state,
           count(*)::double precision AS value
    FROM decision_challenges CROSS JOIN clock
    GROUP BY operation, state
),
decision_values(decision) AS (
    VALUES ('approved'), ('rejected'), ('revoked')
),
decision_counts AS (
    SELECT decision, count(*)::double precision AS value
    FROM approval_decisions
    GROUP BY decision
),
approval_latency AS (
    SELECT COALESCE(avg(extract(epoch FROM (decision.decided_at - challenge.issued_at))), 0)::double precision AS average,
           COALESCE(percentile_cont(0.95) WITHIN GROUP (
               ORDER BY extract(epoch FROM (decision.decided_at - challenge.issued_at))
           ), 0)::double precision AS p95,
           COALESCE(max(extract(epoch FROM (decision.decided_at - challenge.issued_at))), 0)::double precision AS maximum
    FROM approval_decisions decision
    JOIN decision_challenges challenge USING (challenge_id)
),
revocation_states(state) AS (
    VALUES ('authorized'), ('queued'), ('revoked'), ('failed'), ('indeterminate')
),
revocation_counts AS (
    SELECT state, count(*)::double precision AS value
    FROM revocation_operations
    GROUP BY state
),
enforcement_states(state) AS (
    VALUES ('approved'), ('queued'), ('active'), ('expired'), ('failed'),
        ('revoked'), ('indeterminate')
),
enforcement_counts AS (
    SELECT state, count(*)::double precision AS value
    FROM enforcement_actions
    GROUP BY state
),
dispatch_operation_dimensions(operation) AS (
    VALUES ('add'), ('revoke'), ('inspect')
),
dispatch_counts AS (
    SELECT operation.operation, job.state, count(*)::double precision AS value
    FROM dispatch_operations operation
    JOIN outbox_jobs job ON job.job_id = operation.job_id
    GROUP BY operation.operation, job.state
),
capability_states(state) AS (
    VALUES ('consumed'), ('unconsumed_valid'), ('unconsumed_expired')
),
capability_counts AS (
    SELECT operation,
           CASE WHEN consumed_at IS NOT NULL THEN 'consumed'
                WHEN expires_at <= clock.observed_at THEN 'unconsumed_expired'
                ELSE 'unconsumed_valid' END AS state,
           count(*)::double precision AS value
    FROM execution_capabilities CROSS JOIN clock
    GROUP BY operation, state
),
execution_classifications(classification) AS (
    VALUES ('applied'), ('recovered_active'), ('revoked'), ('inspect_active'),
        ('inspect_absent'), ('inspect_mismatch'), ('failed'), ('indeterminate')
),
execution_result_counts AS (
    SELECT operation, classification, count(*)::double precision AS value
    FROM execution_results
    GROUP BY operation, classification
),
latest_inspection AS (
    SELECT DISTINCT ON (action_id) action_id, classification
    FROM execution_results
    WHERE operation = 'inspect'
    ORDER BY action_id, persisted_at DESC, completed_at DESC, journal_sequence DESC,
        CASE classification
            WHEN 'inspect_absent' THEN 0 WHEN 'inspect_mismatch' THEN 1
            WHEN 'indeterminate' THEN 2 WHEN 'failed' THEN 3 ELSE 4
        END
),
audit_outcomes(outcome) AS (
    VALUES ('accepted'), ('rejected'), ('succeeded'), ('failed'), ('indeterminate')
),
audit_counts AS (
    SELECT outcome, count(*)::double precision AS value
    FROM audit_events
    GROUP BY outcome
)
SELECT 'sentinelflow_control_source_health_events_retained', 'state', dimension.state,
       'cause', dimension.cause, COALESCE(counts.value, 0)
FROM source_dimensions dimension
LEFT JOIN source_counts counts USING (state, cause)
UNION ALL
SELECT 'sentinelflow_control_source_dropped_records_retained', 'cause', dimension.cause,
       NULL, NULL, COALESCE(counts.value, 0)
FROM (SELECT DISTINCT cause FROM source_dimensions) dimension
LEFT JOIN source_drop_counts counts USING (cause)
UNION ALL
SELECT 'sentinelflow_control_sources_current', 'state', dimension.state,
       NULL, NULL, count(source.source_id)::double precision
FROM source_states dimension
LEFT JOIN latest_source source USING (state)
GROUP BY dimension.state
UNION ALL
SELECT 'sentinelflow_control_source_health_untrusted_retained', 'reason', reason.reason,
       NULL, NULL, COALESCE(counts.value, 0)
FROM source_trust_reasons reason
LEFT JOIN source_untrusted_counts counts USING (reason)
UNION ALL
SELECT 'sentinelflow_control_expected_sources', 'endpoint', endpoint.endpoint,
       'state', state.state,
       count(status.binding_id) FILTER (WHERE
           (state.state = 'missing_report' AND status.missing_report) OR
           (state.state = 'open_gap' AND status.open_gap) OR
           (state.state = 'checkpoint_stale' AND status.checkpoint_stale) OR
           (state.state = 'degraded' AND status.health_state = 'degraded') OR
           (state.state = 'lost' AND status.health_state = 'lost') OR
           (state.state = 'healthy' AND NOT status.missing_report AND NOT status.open_gap
               AND NOT status.checkpoint_stale AND status.health_state = 'recovered')
       )::double precision
FROM endpoint_dimensions endpoint CROSS JOIN expected_source_states state
LEFT JOIN expected_source_status status ON status.endpoint_kind = endpoint.endpoint
GROUP BY endpoint.endpoint, state.state
UNION ALL
SELECT 'sentinelflow_control_event_last_seen_available', 'endpoint', endpoint.endpoint,
       NULL, NULL, CASE WHEN latest.received_at IS NULL THEN 0 ELSE 1 END::double precision
FROM endpoint_dimensions endpoint
LEFT JOIN latest_batch_by_endpoint latest ON latest.endpoint_kind = endpoint.endpoint
UNION ALL
SELECT 'sentinelflow_control_event_lag_seconds', 'endpoint', endpoint.endpoint,
       NULL, NULL,
       COALESCE(greatest(0, extract(epoch FROM (clock.observed_at - latest.received_at))), 0)::double precision
FROM endpoint_dimensions endpoint CROSS JOIN clock
LEFT JOIN latest_batch_by_endpoint latest ON latest.endpoint_kind = endpoint.endpoint
UNION ALL
SELECT 'sentinelflow_control_auth_bindings_retained', 'state', state.state,
       NULL, NULL, COALESCE(counts.value, 0)
FROM auth_binding_states state LEFT JOIN auth_binding_counts counts USING (state)
UNION ALL
SELECT 'sentinelflow_control_auth_binding_overdue', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM auth_events event CROSS JOIN clock
WHERE event.binding_state = 'pending' AND event.binding_deadline < clock.observed_at
UNION ALL
SELECT 'sentinelflow_control_signals_retained', 'kind', kind.kind,
       'source_health', completeness.status, COALESCE(counts.value, 0)
FROM signal_kinds kind CROSS JOIN source_health_completeness completeness
LEFT JOIN signal_counts counts
  ON counts.kind = kind.kind AND counts.status = completeness.status
UNION ALL
SELECT 'sentinelflow_control_incidents_current', 'kind', kind.kind,
       'state', state.state, COALESCE(counts.value, 0)
FROM incident_kinds kind CROSS JOIN incident_states state
LEFT JOIN incident_counts counts
  ON counts.kind = kind.kind AND counts.state = state.state
UNION ALL
SELECT 'sentinelflow_control_ingest_gaps_open', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM ingest_sequence_gaps gap
WHERE EXISTS (
    SELECT 1 FROM ingest_gap_lifecycle lifecycle
    WHERE lifecycle.lifecycle_state = 'opened'
      AND lifecycle.sender_id = gap.sender_id
      AND lifecycle.endpoint_kind = gap.endpoint_kind
      AND lifecycle.sender_epoch = gap.sender_epoch
      AND lifecycle.sequence_start = gap.sequence_start
      AND lifecycle.sequence_end = gap.sequence_end
) AND NOT EXISTS (
    SELECT 1 FROM ingest_gap_lifecycle lifecycle
    WHERE lifecycle.lifecycle_state IN ('late_closed', 'lost')
      AND lifecycle.sender_id = gap.sender_id
      AND lifecycle.endpoint_kind = gap.endpoint_kind
      AND lifecycle.sender_epoch = gap.sender_epoch
      AND lifecycle.sequence_start = gap.sequence_start
      AND lifecycle.sequence_end = gap.sequence_end
)
UNION ALL
SELECT 'sentinelflow_control_sender_checkpoint_stale_seconds', NULL, NULL, NULL, NULL,
       COALESCE(greatest(0, extract(epoch FROM (clock.observed_at - min(checkpoint.updated_at)))), 0)::double precision
FROM clock LEFT JOIN sender_checkpoints checkpoint ON true
GROUP BY clock.observed_at
UNION ALL
SELECT 'sentinelflow_control_outbox_jobs', 'kind', kind.kind, 'state', state.state,
       COALESCE(counts.value, 0)
FROM outbox_kinds kind CROSS JOIN outbox_states state
LEFT JOIN outbox_counts counts ON counts.kind = kind.kind AND counts.state = state.state
UNION ALL
SELECT 'sentinelflow_control_outbox_oldest_ready_age_seconds', 'kind', kind.kind,
       NULL, NULL, COALESCE(oldest.value, 0)
FROM outbox_kinds kind LEFT JOIN outbox_oldest oldest USING (kind)
UNION ALL
SELECT 'sentinelflow_control_outbox_lease_expiry_lag_seconds', 'kind', kind.kind,
       NULL, NULL, COALESCE(lag.value, 0)
FROM outbox_kinds kind LEFT JOIN outbox_lease_lag lag USING (kind)
UNION ALL
SELECT 'sentinelflow_control_dead_letters_unresolved', 'kind', kind.kind,
       NULL, NULL, COALESCE(dead.value, 0)
FROM outbox_kinds kind LEFT JOIN dead_letter_counts dead USING (kind)
UNION ALL
SELECT 'sentinelflow_control_analysis_attempts_retained', 'state', state.state,
       NULL, NULL, COALESCE(counts.value, 0)
FROM analysis_states state LEFT JOIN analysis_counts counts USING (state)
UNION ALL
SELECT 'sentinelflow_control_analysis_success_retained', 'provider', provider.provider_kind,
       NULL, NULL, COALESCE(counts.value, 0)
FROM provider_dimensions provider LEFT JOIN provider_counts counts USING (provider_kind)
UNION ALL
SELECT 'sentinelflow_control_ai_reservations', 'state', state.state,
       NULL, NULL, COALESCE(counts.value, 0)
FROM reservation_states state LEFT JOIN reservation_counts counts USING (state)
UNION ALL
SELECT 'sentinelflow_control_ai_latency_seconds', 'statistic', statistic.statistic,
       NULL, NULL,
       CASE statistic.statistic WHEN 'average' THEN latency.average
            WHEN 'p95' THEN latency.p95 ELSE latency.maximum END
FROM latency_statistics statistic CROSS JOIN analysis_latency latency
UNION ALL
SELECT 'sentinelflow_control_ai_tokens_retained', 'kind', kind.kind,
       NULL, NULL,
       CASE kind.kind WHEN 'input' THEN token.input
            WHEN 'cached_input' THEN token.cached_input ELSE token.output END
FROM token_kinds kind CROSS JOIN analysis_tokens token
UNION ALL
SELECT 'sentinelflow_control_ai_errors_retained', 'reason', reason.reason,
       NULL, NULL, COALESCE(counts.value, 0)
FROM analysis_failure_reasons reason LEFT JOIN analysis_failure_counts counts USING (reason)
UNION ALL
SELECT 'sentinelflow_control_ai_failures_5m', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM analysis_attempt_results result CROSS JOIN clock
WHERE result.result_state IN ('failed', 'interrupted')
  AND result.completed_at >= clock.observed_at - interval '5 minutes'
UNION ALL
SELECT 'sentinelflow_control_ai_started_stale', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM analysis_attempt_claims claim CROSS JOIN clock
WHERE claim.state = 'started'
  AND claim.generated_at < clock.observed_at - interval '45 seconds'
UNION ALL
SELECT 'sentinelflow_control_ai_budget_micro_usd', 'kind', budget.kind,
       NULL, NULL, budget.value
FROM (
    SELECT 'limit'::text AS kind, COALESCE(sum(limit_micro_usd), 0)::double precision AS value
    FROM ai_budget_ledger CROSS JOIN clock WHERE budget_date = sentinelflow.control_observability_utc_date_000024(clock.observed_at)
    UNION ALL SELECT 'reserved', COALESCE(sum(reserved_micro_usd), 0)::double precision
    FROM ai_budget_ledger CROSS JOIN clock WHERE budget_date = sentinelflow.control_observability_utc_date_000024(clock.observed_at)
    UNION ALL SELECT 'consumed', COALESCE(sum(consumed_micro_usd), 0)::double precision
    FROM ai_budget_ledger CROSS JOIN clock WHERE budget_date = sentinelflow.control_observability_utc_date_000024(clock.observed_at)
    UNION ALL SELECT 'remaining', COALESCE(sum(limit_micro_usd - reserved_micro_usd - consumed_micro_usd), 0)::double precision
    FROM ai_budget_ledger CROSS JOIN clock WHERE budget_date = sentinelflow.control_observability_utc_date_000024(clock.observed_at)
) budget
UNION ALL
SELECT 'sentinelflow_control_validation_attempts_retained', 'state', state.state,
       NULL, NULL, COALESCE(counts.value, 0)
FROM validation_states state LEFT JOIN validation_counts counts USING (state)
UNION ALL
SELECT 'sentinelflow_control_validation_gates_retained', 'gate', gate.gate_name,
       'result', result.result, COALESCE(counts.value, 0)
FROM validation_gate_names gate CROSS JOIN boolean_values result
LEFT JOIN validation_gate_counts counts
  ON counts.gate_name = gate.gate_name AND counts.result = result.result
UNION ALL
SELECT 'sentinelflow_control_validation_started_stale', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM validation_attempt_claims claim CROSS JOIN clock
WHERE claim.state = 'started'
  AND claim.generated_at < clock.observed_at - interval '60 seconds'
UNION ALL
SELECT 'sentinelflow_control_validation_failures_5m', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM validation_attempt_results result CROSS JOIN clock
WHERE result.result_state IN ('invalid', 'interrupted')
  AND result.completed_at >= clock.observed_at - interval '5 minutes'
UNION ALL
SELECT 'sentinelflow_control_validation_failures_retained', 'reason', reason.reason,
       NULL, NULL, COALESCE(counts.value, 0)
FROM validation_failure_reasons reason
LEFT JOIN validation_failure_counts counts USING (reason)
UNION ALL
SELECT 'sentinelflow_control_hil_challenges', 'operation', operation.operation,
       'state', state.state, COALESCE(counts.value, 0)
FROM challenge_operations operation CROSS JOIN challenge_states state
LEFT JOIN challenge_counts counts
  ON counts.operation = operation.operation AND counts.state = state.state
UNION ALL
SELECT 'sentinelflow_control_hil_decisions_retained', 'decision', decision.decision,
       NULL, NULL, COALESCE(counts.value, 0)
FROM decision_values decision LEFT JOIN decision_counts counts USING (decision)
UNION ALL
SELECT 'sentinelflow_control_approval_latency_seconds', 'statistic', statistic.statistic,
       NULL, NULL,
       CASE statistic.statistic WHEN 'average' THEN latency.average
            WHEN 'p95' THEN latency.p95 ELSE latency.maximum END
FROM latency_statistics statistic CROSS JOIN approval_latency latency
UNION ALL
SELECT 'sentinelflow_control_hil_expired_recent_5m', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM decision_challenges challenge CROSS JOIN clock
WHERE challenge.consumed_at IS NULL
  AND challenge.expires_at <= clock.observed_at
  AND challenge.expires_at >= clock.observed_at - interval '5 minutes'
UNION ALL
SELECT 'sentinelflow_control_revocations', 'state', state.state,
       NULL, NULL, COALESCE(counts.value, 0)
FROM revocation_states state LEFT JOIN revocation_counts counts USING (state)
UNION ALL
SELECT 'sentinelflow_control_dispatch_jobs', 'operation', operation.operation,
       'state', state.state, COALESCE(counts.value, 0)
FROM dispatch_operation_dimensions operation CROSS JOIN outbox_states state
LEFT JOIN dispatch_counts counts
  ON counts.operation = operation.operation AND counts.state = state.state
UNION ALL
SELECT 'sentinelflow_control_execution_capabilities', 'operation', operation.operation,
       'state', state.state, COALESCE(counts.value, 0)
FROM dispatch_operation_dimensions operation CROSS JOIN capability_states state
LEFT JOIN capability_counts counts
  ON counts.operation = operation.operation AND counts.state = state.state
UNION ALL
SELECT 'sentinelflow_control_execution_results_retained', 'operation', operation.operation,
       'classification', classification.classification, COALESCE(counts.value, 0)
FROM dispatch_operation_dimensions operation CROSS JOIN execution_classifications classification
LEFT JOIN execution_result_counts counts
  ON counts.operation = operation.operation
 AND counts.classification = classification.classification
UNION ALL
SELECT 'sentinelflow_control_execution_replay_conflicts_retained', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM execution_results
WHERE error_code = 'replay_conflict'
UNION ALL
SELECT 'sentinelflow_control_enforcement_actions', 'state', state.state,
       NULL, NULL, COALESCE(counts.value, 0)
FROM enforcement_states state LEFT JOIN enforcement_counts counts USING (state)
UNION ALL
SELECT 'sentinelflow_control_enforcement_expiry_lag_seconds', NULL, NULL, NULL, NULL,
       COALESCE(max(greatest(0, extract(epoch FROM (clock.observed_at - action.expected_expires_at)))), 0)::double precision
FROM enforcement_actions action CROSS JOIN clock
WHERE action.state = 'active' AND action.expected_expires_at <= clock.observed_at
UNION ALL
SELECT 'sentinelflow_control_enforcement_early_missing', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM enforcement_actions action
JOIN latest_inspection inspection USING (action_id)
CROSS JOIN clock
WHERE action.state = 'active'
  AND action.expected_expires_at > clock.observed_at
  AND inspection.classification = 'inspect_absent'
UNION ALL
SELECT 'sentinelflow_control_dispatch_failures_5m', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM execution_results result CROSS JOIN clock
WHERE result.classification IN ('failed', 'indeterminate')
  AND result.persisted_at >= clock.observed_at - interval '5 minutes'
UNION ALL
SELECT 'sentinelflow_control_audit_events_retained', 'outcome', outcome.outcome,
       NULL, NULL, COALESCE(counts.value, 0)
FROM audit_outcomes outcome LEFT JOIN audit_counts counts USING (outcome)
UNION ALL
SELECT 'sentinelflow_control_audit_latest_age_seconds', NULL, NULL, NULL, NULL,
       COALESCE(greatest(0, extract(epoch FROM (clock.observed_at - max(event.recorded_at)))), 0)::double precision
FROM clock LEFT JOIN audit_events event ON true GROUP BY clock.observed_at
UNION ALL
SELECT 'sentinelflow_control_audit_recovery_jobs', 'state', state.state,
       NULL, NULL, COALESCE(counts.value, 0)
FROM outbox_states state
LEFT JOIN outbox_counts counts ON counts.kind = 'audit_recovery' AND counts.state = state.state
UNION ALL
SELECT 'sentinelflow_control_sse_latest_age_seconds', NULL, NULL, NULL, NULL,
       COALESCE(greatest(0, extract(epoch FROM (clock.observed_at - max(event.occurred_at)))), 0)::double precision
FROM clock LEFT JOIN sse_notification_ledger event ON true GROUP BY clock.observed_at
UNION ALL
SELECT 'sentinelflow_control_sse_replay_span', NULL, NULL, NULL, NULL,
       greatest(0, watermark - replay_floor)::double precision
FROM sse_notification_replay_state
WHERE singleton
UNION ALL
SELECT 'sentinelflow_control_sse_watermark_lag', NULL, NULL, NULL, NULL,
       greatest(0, state.watermark - COALESCE(ledger.cursor, state.replay_floor))::double precision
FROM sse_notification_replay_state state
CROSS JOIN LATERAL (SELECT max(cursor) AS cursor FROM sse_notification_ledger) ledger
WHERE state.singleton
UNION ALL
SELECT 'sentinelflow_control_sse_clients', NULL, NULL, NULL, NULL,
       count(*)::double precision
FROM sse_client_leases lease CROSS JOIN clock
WHERE lease.expires_at > clock.observed_at
UNION ALL
SELECT 'sentinelflow_control_sse_clients_observable', NULL, NULL, NULL, NULL, 1::double precision;
$function$;

REVOKE ALL ON sentinelflow.sse_client_leases FROM PUBLIC, sentinelflow_api,
    sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher,
    sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA sentinelflow
FROM PUBLIC, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.control_observability_samples_000024()
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
    sentinelflow_dispatcher, sentinelflow_retention, sentinelflow_metrics;
GRANT EXECUTE ON FUNCTION sentinelflow.control_observability_samples_000024()
TO sentinelflow_metrics;

REVOKE ALL ON FUNCTION sentinelflow.control_observability_utc_date_000024(timestamptz)
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
    sentinelflow_dispatcher, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.register_sse_client_lease_000024(uuid, text)
FROM PUBLIC, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher,
    sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.touch_sse_client_lease_000024(uuid, text)
FROM PUBLIC, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher,
    sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.unregister_sse_client_lease_000024(uuid, text)
FROM PUBLIC, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher,
    sentinelflow_retention, sentinelflow_metrics;
GRANT EXECUTE ON FUNCTION sentinelflow.register_sse_client_lease_000024(uuid, text),
    sentinelflow.touch_sse_client_lease_000024(uuid, text),
    sentinelflow.unregister_sse_client_lease_000024(uuid, text)
TO sentinelflow_api;
GRANT USAGE ON SCHEMA sentinelflow TO sentinelflow_metrics;

INSERT INTO schema_migrations (version, name)
VALUES (24, 'control_observability')
ON CONFLICT (version) DO NOTHING;

COMMIT;
