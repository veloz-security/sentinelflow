BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Validation and HIL authority must remain bound to the deterministic
-- evidence-bearing incident version D. Aggregate lifecycle revisions A/T are
-- deliberately ignored; a later deterministic signal changes evidence_version
-- and makes every D-bound validation/challenge stale.
CREATE OR REPLACE FUNCTION sentinelflow.incident_evidence_is_current_000019(
    p_incident_id uuid,
    p_incident_version integer,
    p_evidence_snapshot_id uuid,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_lock_incident boolean
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    incident sentinelflow.incidents%ROWTYPE;
    history sentinelflow.incident_version_history%ROWTYPE;
    evidence sentinelflow.evidence_snapshots%ROWTYPE;
    signal_row record;
    canonical text := '';
    calculated_digest sentinelflow.sha256_digest;
BEGIN
    IF p_incident_id IS NULL OR p_incident_version IS NULL OR
       p_incident_version < 1 OR p_evidence_snapshot_id IS NULL OR
       p_evidence_snapshot_digest IS NULL OR p_lock_incident IS NULL THEN
        RETURN false;
    END IF;

    IF p_lock_incident THEN
        SELECT * INTO incident
        FROM sentinelflow.incidents current_incident
        WHERE current_incident.incident_id = p_incident_id
        FOR UPDATE;
    ELSE
        SELECT * INTO incident
        FROM sentinelflow.incidents current_incident
        WHERE current_incident.incident_id = p_incident_id;
    END IF;
    IF NOT FOUND OR incident.evidence_version IS DISTINCT FROM p_incident_version THEN
        RETURN false;
    END IF;

    SELECT * INTO history
    FROM sentinelflow.incident_version_history historical
    WHERE historical.incident_id = p_incident_id
      AND historical.incident_version = p_incident_version;
    IF NOT FOUND OR history.mutation_kind NOT IN ('created', 'signal_added', 'reopened') OR
       history.source_ip <> incident.source_ip OR
       history.service_label <> incident.service_label THEN
        RETURN false;
    END IF;

    SELECT * INTO evidence
    FROM sentinelflow.evidence_snapshots snapshot
    WHERE snapshot.evidence_snapshot_id = p_evidence_snapshot_id
      AND snapshot.incident_id = p_incident_id
      AND snapshot.incident_version = p_incident_version
      AND snapshot.snapshot_digest = p_evidence_snapshot_digest;
    IF NOT FOUND OR evidence.source_ip <> incident.source_ip OR
       evidence.service_label <> incident.service_label OR
       evidence.signal_count <> history.signal_count THEN
        RETURN false;
    END IF;

    -- History and the exact analysis snapshot must contain the same sorted
    -- signal membership. A lifecycle-only A/T row cannot substitute for D.
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.incident_version_signals historical_signal
        LEFT JOIN sentinelflow.evidence_snapshot_signals snapshot_signal
          ON snapshot_signal.evidence_snapshot_id = p_evidence_snapshot_id
         AND snapshot_signal.signal_id = historical_signal.signal_id
         AND snapshot_signal.ordinal = historical_signal.ordinal
        LEFT JOIN sentinelflow.signals signal
          ON signal.signal_id = historical_signal.signal_id
        WHERE historical_signal.incident_id = p_incident_id
          AND historical_signal.incident_version = p_incident_version
          AND (
              snapshot_signal.signal_id IS NULL OR signal.signal_id IS NULL OR
              signal.signal_digest IS NULL OR
              snapshot_signal.evidence_digest <> signal.evidence_digest
          )
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.evidence_snapshot_signals snapshot_signal
        LEFT JOIN sentinelflow.incident_version_signals historical_signal
          ON historical_signal.incident_id = p_incident_id
         AND historical_signal.incident_version = p_incident_version
         AND historical_signal.signal_id = snapshot_signal.signal_id
         AND historical_signal.ordinal = snapshot_signal.ordinal
        WHERE snapshot_signal.evidence_snapshot_id = p_evidence_snapshot_id
          AND historical_signal.signal_id IS NULL
    ) OR EXISTS (
        SELECT 1
        FROM (
            SELECT link.signal_id
            FROM sentinelflow.incident_signals link
            WHERE link.incident_id = p_incident_id
        ) current_signal
        FULL JOIN (
            SELECT link.signal_id
            FROM sentinelflow.incident_version_signals link
            WHERE link.incident_id = p_incident_id
              AND link.incident_version = p_incident_version
        ) historical_signal USING (signal_id)
        WHERE current_signal.signal_id IS NULL OR historical_signal.signal_id IS NULL
    ) THEN
        RETURN false;
    END IF;

    canonical := canonical || octet_length('incident-evidence-v1')::text ||
        ':incident-evidence-v1' || chr(10);
    canonical := canonical || octet_length(p_incident_id::text)::text || ':' ||
        p_incident_id::text || chr(10);
    canonical := canonical || octet_length(p_incident_version::text)::text || ':' ||
        p_incident_version::text || chr(10);
    FOR signal_row IN
        SELECT historical_signal.signal_id::text AS signal_id,
               signal.signal_digest::text AS signal_digest
        FROM sentinelflow.incident_version_signals historical_signal
        JOIN sentinelflow.signals signal USING (signal_id)
        WHERE historical_signal.incident_id = p_incident_id
          AND historical_signal.incident_version = p_incident_version
        ORDER BY historical_signal.signal_id
    LOOP
        IF signal_row.signal_digest IS NULL THEN
            RETURN false;
        END IF;
        canonical := canonical || octet_length(signal_row.signal_id)::text || ':' ||
            signal_row.signal_id || chr(10);
        canonical := canonical || octet_length(signal_row.signal_digest)::text || ':' ||
            signal_row.signal_digest || chr(10);
    END LOOP;
    calculated_digest := sentinelflow.validation_sha256(convert_to(canonical, 'UTF8'));
    RETURN calculated_digest = history.evidence_digest;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.policy_evidence_is_current_000019(
    p_policy_id uuid,
    p_policy_version integer,
    p_lock_incident boolean
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    policy sentinelflow.policy_proposals%ROWTYPE;
BEGIN
    SELECT * INTO policy
    FROM sentinelflow.policy_proposals current_policy
    WHERE current_policy.policy_id = p_policy_id
      AND current_policy.version = p_policy_version;
    IF NOT FOUND OR policy.evidence_snapshot_id IS NULL OR NOT EXISTS (
        SELECT 1
        FROM sentinelflow.ai_analyses analysis
        WHERE analysis.analysis_id = policy.analysis_id
          AND analysis.incident_id = policy.incident_id
          AND analysis.incident_version = policy.incident_version
          AND analysis.evidence_snapshot_id = policy.evidence_snapshot_id
          AND analysis.evidence_snapshot_digest = policy.evidence_snapshot_digest
          AND analysis.result_state = 'succeeded'
    ) THEN
        RETURN false;
    END IF;
    RETURN sentinelflow.incident_evidence_is_current_000019(
        policy.incident_id, policy.incident_version,
        policy.evidence_snapshot_id, policy.evidence_snapshot_digest,
        p_lock_incident
    );
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.interrupt_stale_validation_000019(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE(job_id uuid, state text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    job sentinelflow.outbox_jobs%ROWTYPE;
    claim sentinelflow.validation_attempt_claims%ROWTYPE;
    failure_digest sentinelflow.sha256_digest;
BEGIN
    SELECT * INTO job
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
      AND current_job.kind = 'validate'
      AND current_job.aggregate_type = 'analysis_staging'
      AND current_job.state = 'leased'
      AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    failure_digest := sentinelflow.validation_sha256(
        convert_to('evidence_version_stale', 'UTF8')
    );
    SELECT * INTO claim
    FROM sentinelflow.validation_attempt_claims current_claim
    WHERE current_claim.job_id = p_job_id
    FOR UPDATE;
    IF FOUND AND claim.state = 'started' THEN
        UPDATE sentinelflow.validation_attempt_claims
        SET state = 'interrupted', failure_code = 'evidence_version_stale',
            terminal_at = server_now
        WHERE validation_attempt_id = claim.validation_attempt_id;
        INSERT INTO sentinelflow.validation_attempt_results (
            validation_attempt_id, result_state, failure_code, failed_gate,
            prepared_snapshot_digest, terminal_mutation,
            terminal_mutation_digest, completed_at
        ) VALUES (
            claim.validation_attempt_id, 'interrupted',
            'evidence_version_stale', NULL, claim.prepared_snapshot_digest,
            NULL, NULL, server_now
        ) ON CONFLICT ON CONSTRAINT validation_attempt_results_pkey DO NOTHING;
    ELSIF FOUND AND claim.state <> 'interrupted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'terminal validation cannot become stale';
    END IF;
    UPDATE sentinelflow.outbox_jobs current_job
    SET state = 'dead', lease_token = NULL, lease_owner = NULL,
        lease_expires_at = NULL, last_error_code = 'evidence_version_stale',
        last_error_digest = failure_digest, updated_at = server_now
    WHERE current_job.job_id = p_job_id;
    INSERT INTO sentinelflow.dead_letter_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        attempts, failure_code, failure_digest, dead_at
    ) VALUES (
        job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
        job.aggregate_version, job.attempts, 'evidence_version_stale',
        failure_digest, server_now
    ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
    job_id := job.job_id;
    state := 'dead';
    RETURN NEXT;
END
$function$;

-- Preserve the exact 000014 entry points. Only the wrappers below remain
-- executable by the worker.
DO $rename_validation_functions$
BEGIN
    IF to_regprocedure(
        'sentinelflow.prepare_validation_attempt_exact_pre_000019(uuid,uuid)'
    ) IS NULL THEN
        ALTER FUNCTION sentinelflow.prepare_validation_attempt_exact(uuid, uuid)
            RENAME TO prepare_validation_attempt_exact_pre_000019;
    END IF;
    IF to_regprocedure(
        'sentinelflow.finalize_validation_attempt_exact_pre_000019('
        'uuid,uuid,text,timestamptz,timestamptz,text,text,json,bytea)'
    ) IS NULL THEN
        ALTER FUNCTION sentinelflow.finalize_validation_attempt_exact(
            uuid, uuid, text, timestamptz, timestamptz,
            text, text, json, bytea
        ) RENAME TO finalize_validation_attempt_exact_pre_000019;
    END IF;
END
$rename_validation_functions$;

CREATE OR REPLACE FUNCTION sentinelflow.prepare_validation_attempt_exact(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE(status text, snapshot jsonb, evidence_canonical bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    source_record record;
    base_status text;
    base_snapshot jsonb;
    base_evidence bytea;
    stale_result record;
BEGIN
    -- Job then incident is the validation lock order. Detection owns a
    -- different job/advisory lock before incident and never waits on this job.
    SELECT analysis.incident_id, analysis.incident_version,
           analysis.evidence_snapshot_id, analysis.evidence_snapshot_digest
    INTO source_record
    FROM sentinelflow.outbox_jobs job
    JOIN sentinelflow.ai_analyses analysis
      ON analysis.analysis_id = job.aggregate_id
    WHERE job.job_id = p_job_id
      AND job.kind = 'validate'
      AND job.aggregate_type = 'analysis_staging'
      AND job.state = 'leased'
      AND job.lease_token = p_lease_token
      AND job.lease_expires_at > server_now
      AND analysis.result_state = 'succeeded'
    FOR UPDATE OF job;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF NOT sentinelflow.incident_evidence_is_current_000019(
        source_record.incident_id, source_record.incident_version,
        source_record.evidence_snapshot_id,
        source_record.evidence_snapshot_digest, true
    ) THEN
        SELECT result.job_id, result.state INTO stale_result
        FROM sentinelflow.interrupt_stale_validation_000019(
            p_job_id, p_lease_token
        ) result;
        IF FOUND THEN
            status := 'interrupted';
            snapshot := NULL;
            evidence_canonical := NULL;
            RETURN NEXT;
        END IF;
        RETURN;
    END IF;

    SELECT result.status, result.snapshot, result.evidence_canonical
    INTO base_status, base_snapshot, base_evidence
    FROM sentinelflow.prepare_validation_attempt_exact_pre_000019(
        p_job_id, p_lease_token
    ) result;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    status := base_status;
    snapshot := base_snapshot;
    evidence_canonical := base_evidence;
    RETURN NEXT;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finalize_validation_attempt_exact(
    p_job_id uuid,
    p_lease_token uuid,
    p_finish_state text,
    p_retry_at timestamptz,
    p_client_now timestamptz,
    p_error_code text,
    p_error_digest text,
    p_mutation json,
    p_evidence_canonical bytea
)
RETURNS TABLE(job_id uuid, state text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    claim sentinelflow.validation_attempt_claims%ROWTYPE;
    locked_job uuid;
BEGIN
    IF p_finish_state = 'completed' THEN
        SELECT current_job.job_id INTO locked_job
        FROM sentinelflow.outbox_jobs current_job
        WHERE current_job.job_id = p_job_id
          AND current_job.kind = 'validate'
          AND current_job.state = 'leased'
          AND current_job.lease_token = p_lease_token
          AND current_job.lease_expires_at > server_now
        FOR UPDATE;
        IF NOT FOUND THEN
            RETURN;
        END IF;
        SELECT * INTO claim
        FROM sentinelflow.validation_attempt_claims current_claim
        WHERE current_claim.job_id = p_job_id
        FOR UPDATE;
        IF NOT FOUND OR NOT sentinelflow.incident_evidence_is_current_000019(
            claim.incident_id, claim.incident_version,
            claim.evidence_snapshot_id, claim.evidence_snapshot_digest, true
        ) THEN
            RETURN QUERY
            SELECT result.job_id, result.state
            FROM sentinelflow.interrupt_stale_validation_000019(
                p_job_id, p_lease_token
            ) result;
            RETURN;
        END IF;
    END IF;
    RETURN QUERY
    SELECT result.job_id, result.state
    FROM sentinelflow.finalize_validation_attempt_exact_pre_000019(
        p_job_id, p_lease_token, p_finish_state, p_retry_at, p_client_now,
        p_error_code, p_error_digest, p_mutation, p_evidence_canonical
    ) result;
END
$function$;

-- Preserve the HIL coordinators. Their wrappers call the existing complete
-- atomic mutation first, then lock/re-read D before the statement can commit.
-- Any SF005 abort rolls every challenge/decision/authorization mutation back.
DO $rename_hil_functions$
BEGIN
    IF to_regprocedure(
        'sentinelflow.issue_hil_policy_challenge_pre_000019('
        'uuid,sentinelflow.sha256_digest,uuid,sentinelflow.ascii_id,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,timestamptz,'
        'timestamptz,text,uuid,integer,sentinelflow.canonical_ipv4,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,text,bytea,'
        'timestamptz,timestamptz,integer)'
    ) IS NULL THEN
        ALTER FUNCTION sentinelflow.issue_hil_policy_challenge(
            uuid, sentinelflow.sha256_digest, uuid, sentinelflow.ascii_id,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            timestamptz, timestamptz, text, uuid, integer,
            sentinelflow.canonical_ipv4, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, text, bytea, timestamptz,
            timestamptz, integer
        ) RENAME TO issue_hil_policy_challenge_pre_000019;
    END IF;
    IF to_regprocedure(
        'sentinelflow.commit_hil_policy_decision_with_session_rotation_pre_000019('
        'uuid,sentinelflow.ascii_id,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,timestamptz,timestamptz,uuid,bytea,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,text,uuid,integer,'
        'sentinelflow.canonical_ipv4,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,text,bytea,'
        'timestamptz,timestamptz,integer,uuid,text,text,bytea,'
        'sentinelflow.sha256_digest,uuid,timestamptz,timestamptz,bytea,'
        'sentinelflow.sha256_digest,uuid,uuid,uuid,bytea,'
        'sentinelflow.sha256_digest,uuid,timestamptz,timestamptz,uuid,'
        'timestamptz,uuid,sentinelflow.ascii_id,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,timestamptz,timestamptz,timestamptz,'
        'timestamptz,uuid)'
    ) IS NULL THEN
        ALTER FUNCTION sentinelflow.commit_hil_policy_decision_with_session_rotation(
            uuid, sentinelflow.ascii_id, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, timestamptz, timestamptz, uuid, bytea,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, text, uuid, integer,
            sentinelflow.canonical_ipv4, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest, text, bytea,
            timestamptz, timestamptz, integer, uuid, text, text, bytea,
            sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, bytea,
            sentinelflow.sha256_digest, uuid, uuid, uuid, bytea,
            sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, uuid,
            timestamptz, uuid, sentinelflow.ascii_id,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            timestamptz, timestamptz, timestamptz, timestamptz, uuid
        ) RENAME TO commit_hil_policy_decision_with_session_rotation_pre_000019;
    END IF;
END
$rename_hil_functions$;

CREATE OR REPLACE FUNCTION sentinelflow.issue_hil_policy_challenge(
    p_challenge_id uuid,
    p_nonce_digest sentinelflow.sha256_digest,
    p_session_id uuid,
    p_actor_id sentinelflow.ascii_id,
    p_session_digest sentinelflow.sha256_digest,
    p_csrf_digest sentinelflow.sha256_digest,
    p_authenticated_at timestamptz,
    p_session_expires_at timestamptz,
    p_operation text,
    p_policy_id uuid,
    p_policy_version integer,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_policy_digest sentinelflow.sha256_digest,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_generated_artifact_digest sentinelflow.sha256_digest,
    p_canonical_artifact_digest sentinelflow.sha256_digest,
    p_validation_snapshot_digest sentinelflow.sha256_digest,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_generated_command text,
    p_canonical_artifact bytea,
    p_validation_created_at timestamptz,
    p_validation_valid_until timestamptz,
    p_ttl_seconds integer
)
RETURNS TABLE (
    challenge_id text, schema_version text, nonce_digest text,
    session_id text, session_digest text, actor_id text, operation text,
    resource_type text, resource_id text, resource_version integer,
    target_ipv4 text, policy_digest text, evidence_snapshot_digest text,
    generated_artifact_digest text, canonical_artifact_digest text,
    original_add_digest text, validation_snapshot_digest text,
    validation_valid_until timestamptz, idempotency_key_digest text,
    authenticated_at timestamptz, reauth_required_after_seconds integer,
    issued_at timestamptz, expires_at timestamptz,
    challenge_jcs bytea, challenge_digest text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    RETURN QUERY
    SELECT *
    FROM sentinelflow.issue_hil_policy_challenge_pre_000019(
        p_challenge_id, p_nonce_digest, p_session_id, p_actor_id,
        p_session_digest, p_csrf_digest, p_authenticated_at,
        p_session_expires_at, p_operation, p_policy_id, p_policy_version,
        p_target_ipv4, p_policy_digest, p_evidence_snapshot_digest,
        p_generated_artifact_digest, p_canonical_artifact_digest,
        p_validation_snapshot_digest, p_idempotency_key_digest,
        p_generated_command, p_canonical_artifact, p_validation_created_at,
        p_validation_valid_until, p_ttl_seconds
    );
    IF FOUND AND NOT sentinelflow.policy_evidence_is_current_000019(
        p_policy_id, p_policy_version, true
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF005',
            MESSAGE = 'validation stale';
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.commit_hil_policy_decision_with_session_rotation(
    p_session_id uuid,
    p_actor_id sentinelflow.ascii_id,
    p_session_digest sentinelflow.sha256_digest,
    p_csrf_digest sentinelflow.sha256_digest,
    p_authenticated_at timestamptz,
    p_session_expires_at timestamptz,
    p_challenge_id uuid,
    p_challenge_jcs bytea,
    p_challenge_digest sentinelflow.sha256_digest,
    p_nonce_digest sentinelflow.sha256_digest,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_operation text,
    p_policy_id uuid,
    p_policy_version integer,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_policy_digest sentinelflow.sha256_digest,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_generated_artifact_digest sentinelflow.sha256_digest,
    p_canonical_artifact_digest sentinelflow.sha256_digest,
    p_validation_snapshot_digest sentinelflow.sha256_digest,
    p_generated_command text,
    p_canonical_artifact bytea,
    p_validation_created_at timestamptz,
    p_validation_valid_until timestamptz,
    p_ttl_seconds integer,
    p_reason_id uuid,
    p_reason_code text,
    p_reason_text text,
    p_reason_jcs bytea,
    p_reason_digest sentinelflow.sha256_digest,
    p_decision_id uuid,
    p_decided_at timestamptz,
    p_decision_valid_until timestamptz,
    p_decision_jcs bytea,
    p_decision_digest sentinelflow.sha256_digest,
    p_authorization_id uuid,
    p_action_id uuid,
    p_outbox_job_id uuid,
    p_authorization_jcs bytea,
    p_authorization_digest sentinelflow.sha256_digest,
    p_audit_event_id uuid,
    p_expected_created_at timestamptz,
    p_expected_last_seen_at timestamptz,
    p_expected_rotation_parent_id uuid,
    p_rotation_at timestamptz,
    p_replacement_session_id uuid,
    p_replacement_actor_id sentinelflow.ascii_id,
    p_replacement_token_digest sentinelflow.sha256_digest,
    p_replacement_csrf_digest sentinelflow.sha256_digest,
    p_replacement_authenticated_at timestamptz,
    p_replacement_created_at timestamptz,
    p_replacement_last_seen_at timestamptz,
    p_replacement_expires_at timestamptz,
    p_replacement_rotation_parent_id uuid
)
RETURNS TABLE (
    committed_decision_id uuid,
    replayed boolean,
    session_rotated boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    result_id uuid;
    result_replayed boolean;
    result_rotated boolean;
BEGIN
    SELECT result.committed_decision_id, result.replayed,
           result.session_rotated
    INTO result_id, result_replayed, result_rotated
    FROM sentinelflow.commit_hil_policy_decision_with_session_rotation_pre_000019(
        p_session_id, p_actor_id, p_session_digest, p_csrf_digest,
        p_authenticated_at, p_session_expires_at, p_challenge_id,
        p_challenge_jcs, p_challenge_digest, p_nonce_digest,
        p_idempotency_key_digest, p_operation, p_policy_id,
        p_policy_version, p_target_ipv4, p_policy_digest,
        p_evidence_snapshot_digest, p_generated_artifact_digest,
        p_canonical_artifact_digest, p_validation_snapshot_digest,
        p_generated_command, p_canonical_artifact, p_validation_created_at,
        p_validation_valid_until, p_ttl_seconds, p_reason_id,
        p_reason_code, p_reason_text, p_reason_jcs, p_reason_digest,
        p_decision_id, p_decided_at, p_decision_valid_until,
        p_decision_jcs, p_decision_digest, p_authorization_id,
        p_action_id, p_outbox_job_id, p_authorization_jcs,
        p_authorization_digest, p_audit_event_id, p_expected_created_at,
        p_expected_last_seen_at, p_expected_rotation_parent_id,
        p_rotation_at, p_replacement_session_id, p_replacement_actor_id,
        p_replacement_token_digest, p_replacement_csrf_digest,
        p_replacement_authenticated_at, p_replacement_created_at,
        p_replacement_last_seen_at, p_replacement_expires_at,
        p_replacement_rotation_parent_id
    ) result;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    -- Exact idempotent replay is historical and read-only. It must remain
    -- observable after later evidence, but can never mint fresh authority.
    IF NOT result_replayed AND NOT sentinelflow.policy_evidence_is_current_000019(
        p_policy_id, p_policy_version, true
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF005',
            MESSAGE = 'validation stale';
    END IF;
    RETURN QUERY SELECT result_id, result_replayed, result_rotated;
END
$function$;

-- An approval is immutable history, not permanent dispatch authority. Hide a
-- stale add immediately, then repeat the locked check at claim and capability
-- persistence so both sides of the evidence/dispatcher race fail closed.
CREATE OR REPLACE VIEW sentinelflow.dispatcher_approved_outbox
WITH (security_barrier = true)
AS
SELECT
    job.job_id, job.kind, job.state, job.available_at, job.attempts,
    job.max_attempts, operation.operation, operation.action_id,
    operation.policy_id, operation.policy_version, operation.target_ipv4,
    operation.artifact, operation.artifact_digest,
    operation.original_add_digest, operation.evidence_snapshot_digest,
    operation.validation_snapshot_digest, operation.authorization_digest,
    operation.actor_id, operation.reason_digest, operation.owned_schema_digest,
    operation.not_before, operation.valid_until
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.dispatch_operations operation USING (job_id)
JOIN sentinelflow.validation_snapshots validation
  ON validation.validation_snapshot_id = operation.validation_snapshot_id
JOIN sentinelflow.enforcement_actions action
  ON action.action_id = operation.action_id
JOIN sentinelflow.policy_proposals policy
  ON policy.policy_id = operation.policy_id
 AND policy.version = operation.policy_version
JOIN sentinelflow.incidents incident
  ON incident.incident_id = policy.incident_id
WHERE job.kind IN ('dispatch_add', 'dispatch_revoke', 'dispatch_inspect')
  AND job.kind = 'dispatch_' || operation.operation
  AND job.operation = operation.operation
  AND job.aggregate_type = 'enforcement_action'
  AND job.aggregate_id = action.action_id
  AND job.aggregate_version = action.version
  AND (
      (job.state IN ('pending', 'retry') AND job.available_at <= clock_timestamp()) OR
      (job.state = 'leased' AND job.lease_expires_at <= clock_timestamp())
  )
  AND job.attempts < job.max_attempts
  AND operation.not_before <= clock_timestamp()
  AND operation.valid_until >= clock_timestamp()
  AND (
      (operation.operation = 'add' AND action.state IN ('approved', 'queued') AND
          validation.state = 'valid' AND validation.valid_until >= clock_timestamp() AND
          incident.evidence_version = policy.incident_version) OR
      (operation.operation IN ('revoke', 'inspect') AND
          action.state IN ('active', 'expired', 'failed', 'indeterminate'))
  )
  AND (
      (operation.operation IN ('add', 'revoke') AND EXISTS (
          SELECT 1 FROM sentinelflow.enforcement_authorizations authz
          WHERE authz.authorization_id = operation.enforcement_authorization_id
            AND authz.authorization_digest = operation.authorization_digest
            AND authz.valid_until >= clock_timestamp()
      )) OR
      (operation.operation = 'inspect' AND EXISTS (
          SELECT 1 FROM sentinelflow.inspection_authorizations authz
          WHERE authz.authorization_id = operation.inspection_authorization_id
            AND authz.authorization_digest = operation.authorization_digest
            AND authz.valid_until >= clock_timestamp()
      ))
  );

DO $rename_dispatch_functions$
BEGIN
    IF to_regprocedure(
        'sentinelflow.claim_dispatch_job_pre_000019('
        'uuid,uuid,sentinelflow.ascii_id,timestamptz)'
    ) IS NULL THEN
        ALTER FUNCTION sentinelflow.claim_dispatch_job(
            uuid, uuid, sentinelflow.ascii_id, timestamptz
        ) RENAME TO claim_dispatch_job_pre_000019;
    END IF;
    IF to_regprocedure(
        'sentinelflow.record_execution_capability_pre_000019('
        'uuid,uuid,uuid,text,uuid,uuid,integer,'
        'sentinelflow.canonical_ipv4,bytea,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,'
        'sentinelflow.ascii_id,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest,'
        'bytea,sentinelflow.sha256_digest,timestamptz,timestamptz,timestamptz)'
    ) IS NULL THEN
        ALTER FUNCTION sentinelflow.record_execution_capability(
            uuid, uuid, uuid, text, uuid, uuid, integer,
            sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.ascii_id, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
            bytea, sentinelflow.sha256_digest, timestamptz, timestamptz,
            timestamptz
        ) RENAME TO record_execution_capability_pre_000019;
    END IF;
END
$rename_dispatch_functions$;

CREATE OR REPLACE FUNCTION sentinelflow.claim_dispatch_job(
    p_job_id uuid,
    p_lease_token uuid,
    p_lease_owner sentinelflow.ascii_id,
    p_lease_until timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    claimed boolean;
    add_policy_id uuid;
    add_policy_version integer;
BEGIN
    claimed := sentinelflow.claim_dispatch_job_pre_000019(
        p_job_id, p_lease_token, p_lease_owner, p_lease_until
    );
    IF NOT claimed THEN
        RETURN false;
    END IF;
    SELECT operation.policy_id, operation.policy_version
    INTO add_policy_id, add_policy_version
    FROM sentinelflow.dispatch_operations operation
    WHERE operation.job_id = p_job_id
      AND operation.operation = 'add';
    IF FOUND AND NOT sentinelflow.policy_evidence_is_current_000019(
        add_policy_id, add_policy_version, true
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'dispatch evidence stale';
    END IF;
    RETURN true;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.record_execution_capability(
    p_capability_id uuid,
    p_job_id uuid,
    p_lease_token uuid,
    p_operation text,
    p_action_id uuid,
    p_policy_id uuid,
    p_policy_version integer,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_artifact bytea,
    p_artifact_digest sentinelflow.sha256_digest,
    p_original_add_digest sentinelflow.sha256_digest,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_validation_snapshot_digest sentinelflow.sha256_digest,
    p_authorization_digest sentinelflow.sha256_digest,
    p_actor_id sentinelflow.ascii_id,
    p_reason_digest sentinelflow.sha256_digest,
    p_owned_schema_digest sentinelflow.sha256_digest,
    p_capability_jcs bytea,
    p_capability_digest sentinelflow.sha256_digest,
    p_capability_signature bytea,
    p_nonce_digest sentinelflow.sha256_digest,
    p_issued_at timestamptz,
    p_not_before timestamptz,
    p_expires_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM sentinelflow.record_execution_capability_pre_000019(
        p_capability_id, p_job_id, p_lease_token, p_operation, p_action_id,
        p_policy_id, p_policy_version, p_target_ipv4, p_artifact,
        p_artifact_digest, p_original_add_digest, p_evidence_snapshot_digest,
        p_validation_snapshot_digest, p_authorization_digest, p_actor_id,
        p_reason_digest, p_owned_schema_digest, p_capability_jcs,
        p_capability_digest, p_capability_signature, p_nonce_digest,
        p_issued_at, p_not_before, p_expires_at
    );
    IF p_operation = 'add' AND NOT sentinelflow.policy_evidence_is_current_000019(
        p_policy_id, p_policy_version, true
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'dispatch evidence stale';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION sentinelflow.incident_evidence_is_current_000019(
    uuid, integer, uuid, sentinelflow.sha256_digest, boolean
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.policy_evidence_is_current_000019(
    uuid, integer, boolean
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.interrupt_stale_validation_000019(uuid, uuid)
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
         sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.prepare_validation_attempt_exact_pre_000019(
    uuid, uuid
) FROM PUBLIC, sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_validation_attempt_exact_pre_000019(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json, bytea
) FROM PUBLIC, sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.issue_hil_policy_challenge_pre_000019(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, timestamptz,
    timestamptz, text, uuid, integer, sentinelflow.canonical_ipv4,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    text, bytea, timestamptz, timestamptz, integer
) FROM PUBLIC, sentinelflow_api;
REVOKE ALL ON FUNCTION sentinelflow.commit_hil_policy_decision_with_session_rotation_pre_000019(
    uuid, sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, uuid, bytea,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, text, uuid, integer,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, text, bytea,
    timestamptz, timestamptz, integer, uuid, text, text, bytea,
    sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, bytea,
    sentinelflow.sha256_digest, uuid, uuid, uuid, bytea,
    sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, uuid,
    timestamptz, uuid, sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz,
    timestamptz, uuid
) FROM PUBLIC, sentinelflow_api;
REVOKE ALL ON FUNCTION sentinelflow.claim_dispatch_job_pre_000019(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) FROM PUBLIC, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_capability_pre_000019(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_dispatcher;

REVOKE ALL ON FUNCTION sentinelflow.prepare_validation_attempt_exact(uuid, uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_validation_attempt_exact(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_validation_attempt_exact(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_validation_attempt_exact(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json, bytea
) TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.issue_hil_policy_challenge(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, timestamptz,
    timestamptz, text, uuid, integer, sentinelflow.canonical_ipv4,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    text, bytea, timestamptz, timestamptz, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.issue_hil_policy_challenge(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, timestamptz,
    timestamptz, text, uuid, integer, sentinelflow.canonical_ipv4,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    text, bytea, timestamptz, timestamptz, integer
) TO sentinelflow_api;
REVOKE ALL ON FUNCTION sentinelflow.commit_hil_policy_decision_with_session_rotation(
    uuid, sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, uuid, bytea,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, text, uuid, integer,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, text, bytea,
    timestamptz, timestamptz, integer, uuid, text, text, bytea,
    sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, bytea,
    sentinelflow.sha256_digest, uuid, uuid, uuid, bytea,
    sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, uuid,
    timestamptz, uuid, sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz,
    timestamptz, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.commit_hil_policy_decision_with_session_rotation(
    uuid, sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, uuid, bytea,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, text, uuid, integer,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, text, bytea,
    timestamptz, timestamptz, integer, uuid, text, text, bytea,
    sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, bytea,
    sentinelflow.sha256_digest, uuid, uuid, uuid, bytea,
    sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, uuid,
    timestamptz, uuid, sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz,
    timestamptz, uuid
) TO sentinelflow_api;
REVOKE ALL ON FUNCTION sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) TO sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) TO sentinelflow_dispatcher;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (19, 'evidence_bound_validation_hil')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
