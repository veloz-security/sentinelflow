BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- The pre-000010 tables retained digests but not every canonical byte string
-- needed to reconstruct an exact HIL record.  Never invent those bytes during
-- upgrade.  A first application with legacy HIL rows must stop for an explicit
-- evidence migration; a repeated application after 000010 is safe.
DO $hil_evidence_preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'sentinelflow'
          AND table_name = 'decision_challenges'
          AND column_name = 'challenge_jcs'
    ) AND (
        EXISTS (SELECT 1 FROM sentinelflow.decision_challenges) OR
        EXISTS (SELECT 1 FROM sentinelflow.hil_reasons) OR
        EXISTS (SELECT 1 FROM sentinelflow.approval_decisions) OR
        EXISTS (SELECT 1 FROM sentinelflow.enforcement_authorizations)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy HIL rows require an explicit canonical-evidence migration';
    END IF;
END
$hil_evidence_preflight$;

ALTER TABLE sentinelflow.decision_challenges
    ADD COLUMN IF NOT EXISTS challenge_jcs bytea,
    ADD COLUMN IF NOT EXISTS challenge_digest sentinelflow.sha256_digest;
ALTER TABLE sentinelflow.hil_reasons
    ADD COLUMN IF NOT EXISTS reason_code text,
    ADD COLUMN IF NOT EXISTS reason_jcs bytea;
ALTER TABLE sentinelflow.approval_decisions
    ADD COLUMN IF NOT EXISTS decision_jcs bytea,
    ADD COLUMN IF NOT EXISTS decision_digest sentinelflow.sha256_digest;
ALTER TABLE sentinelflow.enforcement_authorizations
    ADD COLUMN IF NOT EXISTS authorization_jcs bytea;

ALTER TABLE sentinelflow.decision_challenges
    ALTER COLUMN challenge_jcs SET NOT NULL,
    ALTER COLUMN challenge_digest SET NOT NULL;
ALTER TABLE sentinelflow.hil_reasons
    ALTER COLUMN reason_code SET NOT NULL,
    ALTER COLUMN reason_jcs SET NOT NULL;
ALTER TABLE sentinelflow.approval_decisions
    ALTER COLUMN decision_jcs SET NOT NULL,
    ALTER COLUMN decision_digest SET NOT NULL;
ALTER TABLE sentinelflow.enforcement_authorizations
    ALTER COLUMN authorization_jcs SET NOT NULL;

DO $hil_evidence_constraints$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.decision_challenges'::regclass
          AND conname = 'decision_challenge_jcs_evidence'
    ) THEN
        ALTER TABLE sentinelflow.decision_challenges
            ADD CONSTRAINT decision_challenge_jcs_evidence CHECK (
                octet_length(challenge_jcs) BETWEEN 2 AND 8192 AND
                challenge_digest = (
                    'sha256:' || encode(sha256(challenge_jcs), 'hex')
                )::sentinelflow.sha256_digest
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.hil_reasons'::regclass
          AND conname = 'hil_reason_jcs_evidence'
    ) THEN
        ALTER TABLE sentinelflow.hil_reasons
            ADD CONSTRAINT hil_reason_jcs_evidence CHECK (
                reason_code IN (
                    'threat_confirmed', 'false_positive', 'business_exception',
                    'emergency_revoke', 'operator_request', 'other'
                ) AND
                octet_length(reason_jcs) BETWEEN 2 AND 4096 AND
                reason_digest = (
                    'sha256:' || encode(sha256(reason_jcs), 'hex')
                )::sentinelflow.sha256_digest
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.approval_decisions'::regclass
          AND conname = 'approval_decision_jcs_evidence'
    ) THEN
        ALTER TABLE sentinelflow.approval_decisions
            ADD CONSTRAINT approval_decision_jcs_evidence CHECK (
                octet_length(decision_jcs) BETWEEN 2 AND 8192 AND
                decision_digest = (
                    'sha256:' || encode(sha256(decision_jcs), 'hex')
                )::sentinelflow.sha256_digest
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.enforcement_authorizations'::regclass
          AND conname = 'enforcement_authorization_jcs_evidence'
    ) THEN
        ALTER TABLE sentinelflow.enforcement_authorizations
            ADD CONSTRAINT enforcement_authorization_jcs_evidence CHECK (
                octet_length(authorization_jcs) BETWEEN 2 AND 8192 AND
                authorization_digest = (
                    'sha256:' || encode(sha256(authorization_jcs), 'hex')
                )::sentinelflow.sha256_digest
            );
    END IF;
END
$hil_evidence_constraints$;

-- The owned list-set contract has no per-element handle.  Reject a set handle
-- substituted into either the signed result projection or durable action.
DO $list_set_handle_constraints$
BEGIN
    IF EXISTS (
        SELECT 1 FROM sentinelflow.execution_results
        WHERE element_handle IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.enforcement_actions
        WHERE nft_element_handle IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'list-set rows contain unsupported per-element handles';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.execution_results'::regclass
          AND conname = 'execution_result_list_set_has_no_handle'
    ) THEN
        ALTER TABLE sentinelflow.execution_results
            ADD CONSTRAINT execution_result_list_set_has_no_handle
            CHECK (element_handle IS NULL);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.enforcement_actions'::regclass
          AND conname = 'enforcement_action_list_set_has_no_handle'
    ) THEN
        ALTER TABLE sentinelflow.enforcement_actions
            ADD CONSTRAINT enforcement_action_list_set_has_no_handle
            CHECK (nft_element_handle IS NULL);
    END IF;
END
$list_set_handle_constraints$;

CREATE OR REPLACE FUNCTION sentinelflow.hil_sha256(p_bytes bytea)
RETURNS sentinelflow.sha256_digest
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT ('sha256:' || encode(sha256(p_bytes), 'hex'))::sentinelflow.sha256_digest;
$function$;

-- The sole final-policy mutation entry point.  Callers provide exact checked
-- JCS bytes, but the function reconstructs them from locked database state and
-- rejects any byte/digest substitution.  All expected failures are stable
-- custom SQLSTATEs; no partial write can escape the surrounding statement.
CREATE OR REPLACE FUNCTION sentinelflow.commit_hil_policy_decision(
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
    p_audit_event_id uuid
)
RETURNS TABLE (committed_decision_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    session_row sentinelflow.admin_sessions%ROWTYPE;
    policy_row sentinelflow.policy_proposals%ROWTYPE;
    validation_row sentinelflow.validation_snapshots%ROWTYPE;
    challenge_row sentinelflow.decision_challenges%ROWTYPE;
    existing_decision sentinelflow.approval_decisions%ROWTYPE;
    existing_reason sentinelflow.hil_reasons%ROWTYPE;
    existing_authorization sentinelflow.enforcement_authorizations%ROWTYPE;
    lock_session_id uuid := p_session_id;
    lock_policy_id uuid := p_policy_id;
    lock_policy_version integer := p_policy_version;
    lock_validation_id uuid;
    lock_challenge_id uuid := p_challenge_id;
    server_now timestamptz;
    expected_decision text;
    expected_reason_jcs bytea;
    expected_decision_jcs bytea;
    expected_authorization_jcs bytea;
    effective_reason_id uuid;
    gate_names text[];
    gate_passed boolean;
    changed_count integer;
    dispatch_count integer;
BEGIN
    IF p_session_id IS NULL OR p_actor_id IS NULL OR
       p_session_digest IS NULL OR p_csrf_digest IS NULL OR
       p_authenticated_at IS NULL OR p_session_expires_at IS NULL OR
       p_challenge_id IS NULL OR p_challenge_digest IS NULL OR
       p_nonce_digest IS NULL OR p_idempotency_key_digest IS NULL OR
       p_policy_id IS NULL OR p_target_ipv4 IS NULL OR
       p_policy_digest IS NULL OR p_evidence_snapshot_digest IS NULL OR
       p_generated_artifact_digest IS NULL OR
       p_canonical_artifact_digest IS NULL OR
       p_validation_snapshot_digest IS NULL OR
       p_generated_command IS NULL OR p_canonical_artifact IS NULL OR
       p_validation_created_at IS NULL OR p_validation_valid_until IS NULL OR
       p_reason_id IS NULL OR p_reason_digest IS NULL OR
       p_decision_id IS NULL OR p_decision_digest IS NULL OR
       p_audit_event_id IS NULL OR
       NOT isfinite(p_authenticated_at) OR
       NOT isfinite(p_session_expires_at) OR
       NOT isfinite(p_validation_created_at) OR
       NOT isfinite(p_validation_valid_until) OR
       octet_length(p_generated_command) NOT BETWEEN 1 AND 256 OR
       octet_length(p_canonical_artifact) NOT BETWEEN 1 AND 257 OR
       p_operation NOT IN ('approve', 'reject') OR
       p_policy_version IS NULL OR p_policy_version < 1 OR
       p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 60 AND 86400 OR
       p_reason_code NOT IN (
           'threat_confirmed', 'false_positive', 'business_exception',
           'emergency_revoke', 'operator_request', 'other'
       ) OR p_reason_text IS NULL OR length(p_reason_text) NOT BETWEEN 1 AND 500 OR
       p_reason_text ~ '[[:cntrl:]]' OR NOT (p_reason_text IS NFC NORMALIZED) OR
       p_challenge_jcs IS NULL OR octet_length(p_challenge_jcs) NOT BETWEEN 2 AND 8192 OR
       p_reason_jcs IS NULL OR octet_length(p_reason_jcs) NOT BETWEEN 2 AND 4096 OR
       p_decision_jcs IS NULL OR octet_length(p_decision_jcs) NOT BETWEEN 2 AND 8192 OR
       p_decided_at IS NULL OR p_decision_valid_until IS NULL OR
       NOT isfinite(p_decided_at) OR NOT isfinite(p_decision_valid_until) OR
       (p_operation = 'approve' AND (
           p_authorization_id IS NULL OR p_action_id IS NULL OR
           p_outbox_job_id IS NULL OR p_authorization_jcs IS NULL OR
           p_authorization_digest IS NULL OR
           octet_length(p_authorization_jcs) NOT BETWEEN 2 AND 8192
       )) OR
       (p_operation = 'reject' AND (
           p_authorization_id IS NOT NULL OR p_action_id IS NOT NULL OR
           p_outbox_job_id IS NOT NULL OR p_authorization_jcs IS NOT NULL OR
           p_authorization_digest IS NOT NULL
       )) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF001', MESSAGE = 'invalid_input';
    END IF;

    -- A retry may arrive with newly generated proposed row IDs.  Read only the
    -- existing session identity first, then acquire every row lock in the fixed
    -- session -> policy -> validation -> challenge order.
    SELECT challenge.session_id
    INTO lock_session_id
    FROM sentinelflow.approval_decisions decision
    JOIN sentinelflow.decision_challenges challenge
      ON challenge.challenge_id = decision.challenge_id
    WHERE decision.idempotency_key_digest = p_idempotency_key_digest;
    IF NOT FOUND THEN lock_session_id := p_session_id; END IF;

    SELECT * INTO session_row
    FROM sentinelflow.admin_sessions current_session
    WHERE current_session.session_id = lock_session_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF002', MESSAGE = 'authentication_invalid';
    END IF;

    SELECT decision.* INTO existing_decision
    FROM sentinelflow.approval_decisions decision
    WHERE decision.idempotency_key_digest = p_idempotency_key_digest;
    IF FOUND THEN
        lock_policy_id := existing_decision.policy_id;
        lock_policy_version := existing_decision.policy_version;
        lock_validation_id := existing_decision.validation_snapshot_id;
        lock_challenge_id := existing_decision.challenge_id;
    END IF;

    SELECT * INTO policy_row
    FROM sentinelflow.policy_proposals current_policy
    WHERE current_policy.policy_id = lock_policy_id
      AND current_policy.version = lock_policy_version
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF004', MESSAGE = 'validation_failed';
    END IF;

    IF lock_validation_id IS NULL THEN
        SELECT current_validation.validation_snapshot_id
        INTO lock_validation_id
        FROM sentinelflow.validation_snapshots current_validation
        WHERE current_validation.policy_id = p_policy_id
          AND current_validation.policy_version = p_policy_version
          AND current_validation.snapshot_digest = p_validation_snapshot_digest;
    END IF;
    SELECT * INTO validation_row
    FROM sentinelflow.validation_snapshots current_validation
    WHERE current_validation.validation_snapshot_id = lock_validation_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF004', MESSAGE = 'validation_failed';
    END IF;

    SELECT * INTO challenge_row
    FROM sentinelflow.decision_challenges current_challenge
    WHERE current_challenge.challenge_id = lock_challenge_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF007', MESSAGE = 'not_found';
    END IF;

    -- Freshness is sampled only after every row is locked.
    server_now := clock_timestamp();

    IF existing_decision.decision_id IS NOT NULL THEN
        SELECT * INTO existing_reason
        FROM sentinelflow.hil_reasons reason
        WHERE reason.reason_id = existing_decision.reason_id;

        IF session_row.session_id <> p_session_id OR
           session_row.actor_id <> p_actor_id OR
           session_row.token_digest <> p_session_digest OR
           session_row.csrf_digest <> p_csrf_digest OR
           session_row.authenticated_at <> p_authenticated_at OR
           session_row.expires_at <> p_session_expires_at OR
           challenge_row.session_id <> p_session_id OR
           challenge_row.challenge_id <> p_challenge_id OR
           challenge_row.challenge_jcs <> p_challenge_jcs OR
           challenge_row.challenge_digest <> p_challenge_digest OR
           challenge_row.nonce_digest <> p_nonce_digest OR
           challenge_row.idempotency_key_digest <> p_idempotency_key_digest OR
           existing_decision.session_digest <> p_session_digest OR
           existing_decision.operation <> p_operation OR
           existing_decision.decision <> (CASE p_operation
               WHEN 'approve' THEN 'approved' ELSE 'rejected' END) OR
           existing_decision.resource_type <> 'policy' OR
           existing_decision.resource_id <> p_policy_id OR
           existing_decision.resource_version <> p_policy_version OR
           existing_decision.policy_id <> p_policy_id OR
           existing_decision.policy_version <> p_policy_version OR
           existing_decision.target_ipv4 <> p_target_ipv4 OR
           existing_decision.policy_digest <> p_policy_digest OR
           existing_decision.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
           existing_decision.generated_artifact_digest <> p_generated_artifact_digest OR
           existing_decision.canonical_artifact_digest <> p_canonical_artifact_digest OR
           existing_decision.original_add_digest IS NOT NULL OR
           existing_decision.validation_snapshot_digest <> p_validation_snapshot_digest OR
           existing_decision.actor_id <> p_actor_id OR
           existing_decision.reason_digest <> p_reason_digest OR
           existing_decision.challenge_nonce_digest <> p_nonce_digest OR
           existing_reason.reason_id IS NULL OR
           existing_reason.actor_id <> p_actor_id OR
           existing_reason.operation <> p_operation OR
           existing_reason.reason_code <> p_reason_code OR
           existing_reason.normalized_reason <> p_reason_text OR
           existing_reason.reason_jcs <> p_reason_jcs OR
           existing_reason.reason_digest <> p_reason_digest OR
           policy_row.target_ipv4 <> p_target_ipv4 OR
           policy_row.policy_digest <> p_policy_digest OR
           policy_row.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
           policy_row.generated_artifact_digest <> p_generated_artifact_digest OR
           policy_row.canonical_artifact_digest <> p_canonical_artifact_digest OR
           policy_row.ttl_seconds <> p_ttl_seconds OR
           policy_row.state <> (CASE p_operation
               WHEN 'approve' THEN 'approved' ELSE 'rejected' END) OR
           validation_row.policy_id <> p_policy_id OR
           validation_row.policy_version <> p_policy_version OR
           validation_row.snapshot_digest <> p_validation_snapshot_digest OR
           validation_row.policy_digest <> p_policy_digest OR
           validation_row.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
           validation_row.generated_candidate_digest <> p_generated_artifact_digest OR
           validation_row.canonical_artifact_digest <> p_canonical_artifact_digest OR
           validation_row.target_ipv4 <> p_target_ipv4 OR
           validation_row.ttl_seconds <> p_ttl_seconds OR
           validation_row.created_at <> p_validation_created_at OR
           validation_row.valid_until <> p_validation_valid_until OR
           NOT EXISTS (
               SELECT 1
               FROM sentinelflow.command_candidates candidate
               WHERE candidate.command_candidate_id = validation_row.command_candidate_id
                 AND candidate.generated_command = p_generated_command
                 AND candidate.generated_artifact_digest = p_generated_artifact_digest
                 AND candidate.canonical_artifact = p_canonical_artifact
                 AND candidate.canonical_artifact_digest = p_canonical_artifact_digest
                 AND candidate.target_ipv4 = p_target_ipv4
                 AND candidate.ttl_seconds = p_ttl_seconds
           ) THEN
            RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
        END IF;

        IF p_operation = 'approve' THEN
            SELECT * INTO existing_authorization
            FROM sentinelflow.enforcement_authorizations authz
            WHERE authz.approval_decision_id = existing_decision.decision_id
              AND authz.authorization_kind = 'add';
            SELECT count(*)::integer INTO dispatch_count
            FROM sentinelflow.enforcement_actions action
            JOIN sentinelflow.outbox_jobs job
              ON job.aggregate_type = 'enforcement_action'
             AND job.aggregate_id = action.action_id
             AND job.aggregate_version = action.version
             AND job.kind = 'dispatch_add' AND job.operation = 'add'
            JOIN sentinelflow.dispatch_operations operation
              ON operation.job_id = job.job_id
             AND operation.operation = 'add'
             AND operation.action_id = action.action_id
             AND operation.enforcement_authorization_id = existing_authorization.authorization_id
            WHERE action.add_authorization_id = existing_authorization.authorization_id;
            IF existing_authorization.authorization_id IS NULL OR
               existing_authorization.action_id IS NULL OR
               existing_authorization.policy_id <> p_policy_id OR
               existing_authorization.policy_version <> p_policy_version OR
               existing_authorization.decision <> 'approve' OR
               existing_authorization.target_ipv4 <> p_target_ipv4 OR
               existing_authorization.policy_digest <> p_policy_digest OR
               existing_authorization.generated_artifact_digest <> p_generated_artifact_digest OR
               existing_authorization.canonical_artifact_digest <> p_canonical_artifact_digest OR
               existing_authorization.original_add_digest IS NOT NULL OR
               existing_authorization.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
               existing_authorization.validation_snapshot_digest <> p_validation_snapshot_digest OR
               existing_authorization.actor_id <> p_actor_id OR
               existing_authorization.hil_reason_digest <> p_reason_digest OR
               existing_authorization.decision_nonce_digest <> p_nonce_digest OR
               existing_authorization.idempotency_key_digest <> p_idempotency_key_digest OR
               existing_authorization.decided_at <> existing_decision.decided_at OR
               existing_authorization.valid_until <> existing_decision.decision_valid_until OR
               existing_authorization.authorization_jcs <>
                   sentinelflow.hil_authorization_jcs(
                       existing_authorization.action_id, p_actor_id,
                       existing_authorization.authorization_id,
                       p_canonical_artifact_digest, existing_decision.decided_at,
                       p_nonce_digest, p_evidence_snapshot_digest,
                       p_generated_artifact_digest, p_reason_digest,
                       p_idempotency_key_digest, p_policy_digest, p_policy_id,
                       p_policy_version, p_target_ipv4,
                       existing_decision.decision_valid_until
                   ) OR
               existing_authorization.authorization_digest <>
                   sentinelflow.hil_sha256(existing_authorization.authorization_jcs) OR
               dispatch_count <> 1 THEN
                RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
            END IF;
        ELSE
            IF EXISTS (
                SELECT 1 FROM sentinelflow.enforcement_authorizations authz
                WHERE authz.approval_decision_id = existing_decision.decision_id
            ) OR EXISTS (
                SELECT 1 FROM sentinelflow.enforcement_actions action
                WHERE action.policy_id = p_policy_id
                  AND action.policy_version = p_policy_version
            ) THEN
                RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
            END IF;
        END IF;

        committed_decision_id := existing_decision.decision_id;
        replayed := true;
        RETURN NEXT;
        RETURN;
    END IF;

    IF session_row.session_id <> p_session_id OR
       session_row.actor_id <> p_actor_id OR
       session_row.token_digest <> p_session_digest OR
       session_row.csrf_digest <> p_csrf_digest OR
       session_row.authenticated_at <> p_authenticated_at OR
       session_row.expires_at <> p_session_expires_at OR
       session_row.revoked_at IS NOT NULL OR
       session_row.expires_at <= server_now OR
       session_row.last_seen_at + interval '30 minutes' <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF002', MESSAGE = 'authentication_invalid';
    END IF;
    IF server_now > session_row.authenticated_at + interval '15 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = 'SF003', MESSAGE = 'step_up_required';
    END IF;

    IF challenge_row.challenge_id <> p_challenge_id OR
       challenge_row.session_id <> p_session_id OR
       challenge_row.session_digest <> p_session_digest OR
       challenge_row.actor_id <> p_actor_id OR
       challenge_row.operation <> p_operation OR
       challenge_row.resource_type <> 'policy' OR
       challenge_row.resource_id <> p_policy_id OR
       challenge_row.resource_version <> p_policy_version OR
       challenge_row.policy_id <> p_policy_id OR
       challenge_row.policy_version <> p_policy_version OR
       challenge_row.action_id IS NOT NULL OR
       challenge_row.target_ipv4 <> p_target_ipv4 OR
       challenge_row.policy_digest <> p_policy_digest OR
       challenge_row.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
       challenge_row.generated_artifact_digest <> p_generated_artifact_digest OR
       challenge_row.canonical_artifact_digest <> p_canonical_artifact_digest OR
       challenge_row.original_add_digest IS NOT NULL OR
       challenge_row.validation_snapshot_digest <> p_validation_snapshot_digest OR
       challenge_row.validation_valid_until <> p_validation_valid_until OR
       challenge_row.idempotency_key_digest <> p_idempotency_key_digest OR
       challenge_row.authenticated_at <> p_authenticated_at OR
       challenge_row.nonce_digest <> p_nonce_digest OR
       challenge_row.challenge_jcs <> p_challenge_jcs OR
       challenge_row.challenge_digest <> p_challenge_digest THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    IF challenge_row.consumed_at IS NOT NULL OR challenge_row.consumed_decision_id IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    IF challenge_row.expires_at <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006', MESSAGE = 'challenge_expired';
    END IF;

    SELECT array_agg(gate_name ORDER BY gate_order), bool_and(passed)
    INTO gate_names, gate_passed
    FROM sentinelflow.validation_gates
    WHERE validation_snapshot_id = validation_row.validation_snapshot_id;

    IF policy_row.policy_id <> p_policy_id OR
       policy_row.version <> p_policy_version OR policy_row.state <> 'valid' OR
       policy_row.target_ipv4 <> p_target_ipv4 OR
       policy_row.policy_digest <> p_policy_digest OR
       policy_row.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
       policy_row.generated_artifact_digest <> p_generated_artifact_digest OR
       policy_row.canonical_artifact_digest <> p_canonical_artifact_digest OR
       policy_row.ttl_seconds <> p_ttl_seconds OR
       validation_row.policy_id <> p_policy_id OR
       validation_row.policy_version <> p_policy_version OR
       validation_row.command_candidate_id <> policy_row.command_candidate_id OR
       validation_row.evidence_snapshot_id IS DISTINCT FROM policy_row.evidence_snapshot_id OR
       validation_row.snapshot_digest <> p_validation_snapshot_digest OR
       validation_row.policy_digest <> p_policy_digest OR
       validation_row.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
       validation_row.generated_candidate_digest <> p_generated_artifact_digest OR
       validation_row.canonical_artifact_digest <> p_canonical_artifact_digest OR
       validation_row.target_ipv4 <> p_target_ipv4 OR
       validation_row.ttl_seconds <> p_ttl_seconds OR
       validation_row.source_health_status <> 'complete' OR
       validation_row.created_at <> p_validation_created_at OR
       validation_row.valid_until <> p_validation_valid_until OR
       validation_row.state <> 'valid' OR
       gate_names IS DISTINCT FROM ARRAY[
           'structured_output', 'command_grammar',
           'policy_evidence_command_consistency', 'protected_network',
           'owned_schema_syntax', 'historical_impact'
       ]::text[] OR gate_passed IS DISTINCT FROM true OR
       NOT EXISTS (
           SELECT 1
           FROM sentinelflow.command_candidates candidate
           JOIN sentinelflow.evidence_snapshots evidence
             ON evidence.evidence_snapshot_id = policy_row.evidence_snapshot_id
           WHERE candidate.command_candidate_id = policy_row.command_candidate_id
             AND candidate.analysis_id = policy_row.analysis_id
             AND candidate.evidence_snapshot_id IS NOT DISTINCT FROM policy_row.evidence_snapshot_id
             AND candidate.evidence_snapshot_digest = p_evidence_snapshot_digest
             AND candidate.target_ipv4 = p_target_ipv4
             AND candidate.ttl_seconds = p_ttl_seconds
             AND candidate.generated_command = p_generated_command
             AND candidate.generated_artifact_digest = p_generated_artifact_digest
             AND candidate.parse_state = 'valid'
             AND candidate.canonical_artifact = p_canonical_artifact
             AND candidate.canonical_artifact_digest = p_canonical_artifact_digest
             AND evidence.snapshot_digest = p_evidence_snapshot_digest
             AND evidence.source_ip = p_target_ipv4
             AND evidence.source_health_status = 'complete'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF004', MESSAGE = 'validation_failed';
    END IF;
    IF validation_row.valid_until <= server_now OR
       validation_row.created_at > server_now OR
       challenge_row.validation_valid_until <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF005', MESSAGE = 'validation_stale';
    END IF;

    IF p_decided_at > server_now OR
       p_decided_at < server_now - interval '2 seconds' OR
       p_decided_at < challenge_row.issued_at OR
       p_decision_valid_until <= server_now OR
       p_decision_valid_until > p_decided_at + interval '5 minutes' OR
       p_decision_valid_until > challenge_row.expires_at OR
       p_decision_valid_until > validation_row.valid_until OR
       p_decision_valid_until > session_row.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006', MESSAGE = 'challenge_expired';
    END IF;

    expected_reason_jcs := sentinelflow.hil_reason_jcs(p_reason_code, p_reason_text);
    IF p_reason_jcs <> expected_reason_jcs OR
       p_reason_digest <> sentinelflow.hil_sha256(expected_reason_jcs) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    expected_decision := CASE p_operation WHEN 'approve' THEN 'approved' ELSE 'rejected' END;
    expected_decision_jcs := sentinelflow.hil_decision_jcs(
        p_actor_id, p_canonical_artifact_digest, p_challenge_id,
        p_decided_at, expected_decision, p_decision_id,
        p_decision_valid_until, p_evidence_snapshot_digest,
        p_generated_artifact_digest, p_idempotency_key_digest,
        p_nonce_digest, p_operation, p_policy_digest, p_reason_digest,
        p_policy_id, p_policy_version, p_session_digest, p_target_ipv4,
        p_validation_snapshot_digest
    );
    IF p_decision_jcs <> expected_decision_jcs OR
       p_decision_digest <> sentinelflow.hil_sha256(expected_decision_jcs) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    IF p_operation = 'approve' THEN
        expected_authorization_jcs := sentinelflow.hil_authorization_jcs(
            p_action_id, p_actor_id, p_authorization_id,
            p_canonical_artifact_digest, p_decided_at, p_nonce_digest,
            p_evidence_snapshot_digest, p_generated_artifact_digest,
            p_reason_digest, p_idempotency_key_digest, p_policy_digest,
            p_policy_id, p_policy_version, p_target_ipv4,
            p_decision_valid_until
        );
        IF p_authorization_jcs <> expected_authorization_jcs OR
           p_authorization_digest <> sentinelflow.hil_sha256(expected_authorization_jcs) THEN
            RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
        END IF;
    END IF;

    INSERT INTO sentinelflow.hil_reasons (
        reason_id, schema_version, actor_id, operation, reason_code,
        normalized_reason, reason_jcs, reason_digest, created_at
    ) VALUES (
        p_reason_id, 'hil-reason-v1', p_actor_id, p_operation, p_reason_code,
        p_reason_text, p_reason_jcs, p_reason_digest, p_decided_at
    ) ON CONFLICT (reason_digest) DO NOTHING;
    SELECT * INTO existing_reason
    FROM sentinelflow.hil_reasons reason
    WHERE reason.reason_digest = p_reason_digest;
    IF existing_reason.reason_id IS NULL OR
       existing_reason.actor_id <> p_actor_id OR
       existing_reason.operation <> p_operation OR
       existing_reason.reason_code <> p_reason_code OR
       existing_reason.normalized_reason <> p_reason_text OR
       existing_reason.reason_jcs <> p_reason_jcs THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    effective_reason_id := existing_reason.reason_id;

    INSERT INTO sentinelflow.approval_decisions (
        decision_id, schema_version, challenge_id, session_digest,
        operation, decision, resource_type, resource_id, resource_version,
        policy_id, policy_version, action_id, target_ipv4,
        validation_snapshot_id, policy_digest, evidence_snapshot_digest,
        generated_artifact_digest, canonical_artifact_digest,
        original_add_digest, validation_snapshot_digest, actor_id,
        reason_id, reason_digest, challenge_nonce_digest,
        idempotency_key_digest, decided_at, decision_valid_until,
        decision_jcs, decision_digest
    ) VALUES (
        p_decision_id, 'hil-decision-v1', p_challenge_id, p_session_digest,
        p_operation, expected_decision, 'policy', p_policy_id,
        p_policy_version, p_policy_id, p_policy_version, NULL,
        p_target_ipv4, validation_row.validation_snapshot_id,
        p_policy_digest, p_evidence_snapshot_digest,
        p_generated_artifact_digest, p_canonical_artifact_digest, NULL,
        p_validation_snapshot_digest, p_actor_id, effective_reason_id,
        p_reason_digest, p_nonce_digest, p_idempotency_key_digest,
        p_decided_at, p_decision_valid_until, p_decision_jcs,
        p_decision_digest
    );

    UPDATE sentinelflow.decision_challenges
    SET consumed_at = server_now, consumed_decision_id = p_decision_id
    WHERE challenge_id = p_challenge_id
      AND consumed_at IS NULL AND consumed_decision_id IS NULL;
    GET DIAGNOSTICS changed_count = ROW_COUNT;
    IF changed_count <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    IF p_operation = 'approve' THEN
        INSERT INTO sentinelflow.enforcement_authorizations (
            authorization_id, schema_version, authorization_kind, action_id,
            policy_id, policy_version, approval_decision_id, decision,
            target_ipv4, policy_digest, generated_artifact_digest,
            canonical_artifact_digest, original_add_digest,
            evidence_snapshot_digest, validation_snapshot_digest, actor_id,
            hil_reason_digest, decision_nonce_digest, idempotency_key_digest,
            authorization_jcs, authorization_digest, decided_at, valid_until
        ) VALUES (
            p_authorization_id, 'enforcement-authorization-v1', 'add',
            p_action_id, p_policy_id, p_policy_version, p_decision_id,
            'approve', p_target_ipv4, p_policy_digest,
            p_generated_artifact_digest, p_canonical_artifact_digest, NULL,
            p_evidence_snapshot_digest, p_validation_snapshot_digest,
            p_actor_id, p_reason_digest, p_nonce_digest,
            p_idempotency_key_digest, p_authorization_jcs,
            p_authorization_digest, p_decided_at, p_decision_valid_until
        );
    END IF;

    UPDATE sentinelflow.policy_proposals
    SET state = CASE p_operation WHEN 'approve' THEN 'approved' ELSE 'rejected' END,
        state_revision = state_revision + 1,
        updated_at = server_now
    WHERE policy_id = p_policy_id AND version = p_policy_version
      AND state = 'valid' AND state_revision = policy_row.state_revision;
    GET DIAGNOSTICS changed_count = ROW_COUNT;
    IF changed_count <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    IF p_operation = 'approve' THEN
        INSERT INTO sentinelflow.enforcement_actions (
            action_id, policy_id, policy_version, validation_snapshot_id,
            evidence_snapshot_id, evidence_snapshot_digest,
            command_candidate_id, add_authorization_id, target_ipv4,
            canonical_artifact, canonical_artifact_digest, ttl_seconds,
            state, nft_element_handle, approved_at, version,
            created_at, updated_at
        ) VALUES (
            p_action_id, p_policy_id, p_policy_version,
            validation_row.validation_snapshot_id,
            validation_row.evidence_snapshot_id,
            p_evidence_snapshot_digest, validation_row.command_candidate_id,
            p_authorization_id, p_target_ipv4, p_canonical_artifact,
            p_canonical_artifact_digest, p_ttl_seconds, 'approved', NULL,
            p_decided_at, 1, server_now, server_now
        );

        INSERT INTO sentinelflow.outbox_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            operation, idempotency_key, state, available_at, max_attempts,
            created_at, updated_at
        ) VALUES (
            p_outbox_job_id, 'dispatch_add', 'enforcement_action', p_action_id,
            1, 'add', p_authorization_digest, 'pending', server_now, 8,
            server_now, server_now
        );

        INSERT INTO sentinelflow.dispatch_operations (
            job_id, operation, action_id, policy_id, policy_version,
            target_ipv4, artifact, artifact_digest, original_add_digest,
            evidence_snapshot_digest, validation_snapshot_id,
            validation_snapshot_digest, enforcement_authorization_id,
            inspection_authorization_id, authorization_digest, actor_id,
            reason_digest, owned_schema_digest, not_before, valid_until,
            created_at
        ) VALUES (
            p_outbox_job_id, 'add', p_action_id, p_policy_id,
            p_policy_version, p_target_ipv4, p_canonical_artifact,
            p_canonical_artifact_digest, NULL, p_evidence_snapshot_digest,
            validation_row.validation_snapshot_id,
            p_validation_snapshot_digest, p_authorization_id, NULL,
            p_authorization_digest, p_actor_id, p_reason_digest,
            validation_row.live_owned_schema_digest, p_decided_at,
            p_decision_valid_until, server_now
        );
    END IF;

    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        incident_id, policy_id, policy_version, enforcement_action_id,
        primary_digest, secondary_digest, outcome, occurred_at
    ) VALUES (
        p_audit_event_id, 'administrator', p_actor_id,
        CASE p_operation WHEN 'approve' THEN 'policy_approved' ELSE 'policy_rejected' END,
        'policy', p_policy_id, policy_row.incident_id, p_policy_id,
        p_policy_version, p_action_id, p_decision_digest,
        CASE p_operation WHEN 'approve' THEN p_authorization_digest ELSE p_reason_digest END,
        CASE p_operation WHEN 'approve' THEN 'accepted' ELSE 'rejected' END,
        server_now
    );

    committed_decision_id := p_decision_id;
    replayed := false;
    RETURN NEXT;
END
$function$;

-- Preserve the public dispatcher contract while making result recording
-- exact-idempotent and separating fresh mutation authority from later signed
-- read-only/recovery attestation.
CREATE OR REPLACE FUNCTION sentinelflow.record_execution_result(
    p_result_id uuid,
    p_job_id uuid,
    p_lease_token uuid,
    p_capability_id uuid,
    p_capability_digest sentinelflow.sha256_digest,
    p_operation text,
    p_action_id uuid,
    p_artifact_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_classification text,
    p_nft_exit_class text,
    p_readback_state text,
    p_element_handle bigint,
    p_remaining_ttl_seconds integer,
    p_owned_schema_digest sentinelflow.sha256_digest,
    p_started_at timestamptz,
    p_completed_at timestamptz,
    p_journal_sequence bigint,
    p_error_code text,
    p_result_jcs bytea,
    p_result_digest sentinelflow.sha256_digest,
    p_result_signature bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    capability sentinelflow.execution_capabilities%ROWTYPE;
    existing sentinelflow.execution_results%ROWTYPE;
    server_now timestamptz;
    mutation_invoked boolean;
    semantic_shape boolean := false;
BEGIN
    -- The list-set schema never exposes a per-element handle.  This check is
    -- intentionally before the idempotent replay path.
    IF p_element_handle IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'list-set execution result cannot contain an element handle';
    END IF;

    IF p_result_id IS NULL OR p_capability_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid execution result';
    END IF;

    -- Serialize the no-row/replay boundary.  Without this lock two concurrent
    -- deliveries could both observe no result, after which the loser would see
    -- only a consumed capability instead of the original exact result.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'sentinelflow.execution-result:' || p_capability_id::text, 0
    ));

    SELECT result.* INTO existing
    FROM sentinelflow.execution_results result
    WHERE result.capability_id = p_capability_id
       OR result.result_id = p_result_id
    ORDER BY (result.capability_id = p_capability_id) DESC
    LIMIT 1;
    IF FOUND THEN
        IF existing.result_id = p_result_id AND
           existing.capability_id = p_capability_id AND
           existing.capability_digest = p_capability_digest AND
           existing.operation = p_operation AND
           existing.action_id = p_action_id AND
           existing.artifact_digest = p_artifact_digest AND
           existing.target_ipv4 = p_target_ipv4 AND
           existing.classification = p_classification AND
           existing.nft_exit_class IS NOT DISTINCT FROM p_nft_exit_class AND
           existing.readback_state = p_readback_state AND
           existing.element_handle IS NULL AND
           existing.remaining_ttl_seconds IS NOT DISTINCT FROM p_remaining_ttl_seconds AND
           existing.owned_schema_digest = p_owned_schema_digest AND
           existing.started_at = p_started_at AND
           existing.completed_at = p_completed_at AND
           existing.journal_sequence = p_journal_sequence AND
           existing.error_code = p_error_code AND
           existing.result_jcs = p_result_jcs AND
           existing.result_digest = p_result_digest AND
           existing.result_signature = p_result_signature AND
           EXISTS (
               SELECT 1 FROM sentinelflow.execution_capabilities exact_capability
               WHERE exact_capability.capability_id = existing.capability_id
                 AND exact_capability.job_id = p_job_id
           ) THEN
            RETURN;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'conflicting execution result replay';
    END IF;

    IF p_started_at IS NULL OR p_completed_at IS NULL OR
       NOT isfinite(p_started_at) OR NOT isfinite(p_completed_at) OR
       date_trunc('milliseconds', p_started_at) <> p_started_at OR
       date_trunc('milliseconds', p_completed_at) <> p_completed_at OR
       p_completed_at < p_started_at OR
       p_completed_at > p_started_at + interval '2 seconds' OR
       p_journal_sequence IS NULL OR p_journal_sequence < 1 OR
       p_result_jcs IS NULL OR octet_length(p_result_jcs) NOT BETWEEN 2 AND 16384 OR
       p_result_digest <> sentinelflow.hil_sha256(p_result_jcs) OR
       p_result_signature IS NULL OR octet_length(p_result_signature) <> 64 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid execution result';
    END IF;

    SELECT current_capability.* INTO capability
    FROM sentinelflow.outbox_jobs job
    JOIN sentinelflow.execution_capabilities current_capability USING (job_id)
    WHERE job.job_id = p_job_id
      AND job.state = 'leased'
      AND job.lease_token = p_lease_token
      AND current_capability.capability_id = p_capability_id
      AND current_capability.capability_digest = p_capability_digest
      AND current_capability.operation = p_operation
      AND current_capability.action_id = p_action_id
      AND current_capability.artifact_digest = p_artifact_digest
      AND current_capability.target_ipv4 = p_target_ipv4
      AND current_capability.owned_schema_digest = p_owned_schema_digest
      AND current_capability.consumed_at IS NULL
    FOR UPDATE OF job, current_capability;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'result does not match claimed capability';
    END IF;
    -- The lease clock is sampled only after the job and capability are locked;
    -- lock wait time can never turn an expired lease into accepted authority.
    server_now := clock_timestamp();
    IF p_started_at < capability.not_before OR NOT EXISTS (
        SELECT 1 FROM sentinelflow.outbox_jobs exact_job
        WHERE exact_job.job_id = p_job_id
          AND exact_job.state = 'leased'
          AND exact_job.lease_token = p_lease_token
          AND exact_job.lease_expires_at > server_now
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'result does not match claimed capability';
    END IF;

    semantic_shape := CASE p_classification
        WHEN 'applied' THEN
            p_operation = 'add' AND p_nft_exit_class = 'success' AND
            p_readback_state = 'active' AND p_remaining_ttl_seconds IS NOT NULL
        WHEN 'recovered_active' THEN
            p_operation = 'add' AND p_nft_exit_class = 'not_invoked' AND
            p_readback_state = 'active' AND p_remaining_ttl_seconds IS NOT NULL
        WHEN 'revoked' THEN
            p_operation = 'revoke' AND
            p_nft_exit_class IN ('success', 'not_invoked') AND
            p_readback_state = 'absent' AND p_remaining_ttl_seconds IS NULL
        WHEN 'inspect_active' THEN
            p_operation = 'inspect' AND p_nft_exit_class = 'success' AND
            p_readback_state = 'active' AND p_remaining_ttl_seconds IS NOT NULL
        WHEN 'inspect_absent' THEN
            p_operation = 'inspect' AND
            p_nft_exit_class IN ('success', 'not_invoked') AND
            p_readback_state = 'absent' AND p_remaining_ttl_seconds IS NULL
        WHEN 'inspect_mismatch' THEN
            p_operation = 'inspect' AND p_nft_exit_class = 'success' AND
            p_readback_state = 'mismatch'
        WHEN 'failed' THEN
            p_operation IN ('add', 'revoke', 'inspect') AND p_error_code <> 'none'
        WHEN 'indeterminate' THEN
            p_operation IN ('add', 'revoke', 'inspect') AND p_error_code <> 'none'
        ELSE false
    END;
    IF NOT semantic_shape OR
       ((p_classification NOT IN ('failed', 'indeterminate')) <> (p_error_code = 'none')) OR
       (p_remaining_ttl_seconds IS NOT NULL AND
           p_remaining_ttl_seconds NOT BETWEEN 1 AND 86400) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid execution result shape';
    END IF;

    mutation_invoked :=
        (p_operation = 'add' AND p_classification = 'applied') OR
        (p_operation = 'revoke' AND p_classification = 'revoked' AND
            p_nft_exit_class = 'success') OR
        (p_operation IN ('add', 'revoke') AND
            p_classification IN ('failed', 'indeterminate') AND
            p_nft_exit_class IS DISTINCT FROM 'not_invoked');

    IF mutation_invoked AND p_started_at >= capability.expires_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'expired capability cannot attest a mutation';
    END IF;
    IF NOT mutation_invoked AND p_started_at >= capability.expires_at AND
       NOT (
           (p_operation = 'inspect') OR
           (p_operation = 'add' AND
               p_classification IN ('recovered_active', 'failed', 'indeterminate') AND
               p_nft_exit_class = 'not_invoked') OR
           (p_operation = 'revoke' AND
               p_classification IN ('revoked', 'failed', 'indeterminate') AND
               p_nft_exit_class = 'not_invoked')
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'expired capability result is not read-only recovery';
    END IF;

    INSERT INTO sentinelflow.execution_results (
        result_id, schema_version, capability_id, capability_digest, operation,
        action_id, artifact_digest, target_ipv4, classification, nft_exit_class,
        readback_state, element_handle, remaining_ttl_seconds, owned_schema_digest,
        started_at, completed_at, journal_sequence, error_code, result_jcs,
        result_digest, result_signature
    ) VALUES (
        p_result_id, 'execution-result-v1', p_capability_id, p_capability_digest, p_operation,
        p_action_id, p_artifact_digest, p_target_ipv4, p_classification, p_nft_exit_class,
        p_readback_state, NULL, p_remaining_ttl_seconds, p_owned_schema_digest,
        p_started_at, p_completed_at, p_journal_sequence, p_error_code, p_result_jcs,
        p_result_digest, p_result_signature
    );

    UPDATE sentinelflow.execution_capabilities
    SET consumed_at = p_completed_at
    WHERE capability_id = p_capability_id AND consumed_at IS NULL;
END
$function$;

-- hil-reason-v1 forbids controls.  For that domain, escaping quote and
-- backslash while retaining NFC UTF-8 (including U+2028/U+2029) is exactly the
-- RFC 8785 string representation used by the Go contract package.
CREATE OR REPLACE FUNCTION sentinelflow.hil_jcs_string(p_value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT '"' || replace(replace(p_value, E'\\', E'\\\\'), '"', E'\\"') || '"';
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.hil_rfc3339(p_value timestamptz)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT CASE WHEN isfinite(p_value) THEN
        to_char(p_value AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS') ||
        CASE
            WHEN (extract(microseconds FROM p_value)::bigint % 1000000) = 0 THEN ''
            ELSE '.' || rtrim(
                lpad(((extract(microseconds FROM p_value)::bigint % 1000000))::text, 6, '0'),
                '0'
            )
        END || 'Z'
    ELSE NULL END;
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.hil_challenge_jcs(
    p_authenticated_at timestamptz,
    p_canonical_artifact_digest sentinelflow.sha256_digest,
    p_challenge_id uuid,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_expires_at timestamptz,
    p_generated_artifact_digest sentinelflow.sha256_digest,
    p_issued_at timestamptz,
    p_nonce_digest sentinelflow.sha256_digest,
    p_operation text,
    p_policy_digest sentinelflow.sha256_digest,
    p_resource_id uuid,
    p_resource_version integer,
    p_session_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_validation_snapshot_digest sentinelflow.sha256_digest,
    p_validation_valid_until timestamptz
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"authenticated_at":' || hil_jcs_string(hil_rfc3339(p_authenticated_at)) ||
        ',"canonical_artifact_digest":' || hil_jcs_string(p_canonical_artifact_digest::text) ||
        ',"challenge_id":' || hil_jcs_string(p_challenge_id::text) ||
        ',"evidence_snapshot_digest":' || hil_jcs_string(p_evidence_snapshot_digest::text) ||
        ',"expires_at":' || hil_jcs_string(hil_rfc3339(p_expires_at)) ||
        ',"generated_artifact_digest":' || hil_jcs_string(p_generated_artifact_digest::text) ||
        ',"issued_at":' || hil_jcs_string(hil_rfc3339(p_issued_at)) ||
        ',"nonce_digest":' || hil_jcs_string(p_nonce_digest::text) ||
        ',"operation":' || hil_jcs_string(p_operation) ||
        ',"original_add_digest":null' ||
        ',"policy_digest":' || hil_jcs_string(p_policy_digest::text) ||
        ',"reauth_required_after_seconds":900' ||
        ',"resource_id":' || hil_jcs_string(p_resource_id::text) ||
        ',"resource_type":"policy"' ||
        ',"resource_version":' || p_resource_version::text ||
        ',"schema_version":"hil-challenge-v1"' ||
        ',"session_digest":' || hil_jcs_string(p_session_digest::text) ||
        ',"target_ipv4":' || hil_jcs_string(host(p_target_ipv4)) ||
        ',"validation_snapshot_digest":' || hil_jcs_string(p_validation_snapshot_digest::text) ||
        ',"validation_valid_until":' || hil_jcs_string(hil_rfc3339(p_validation_valid_until)) ||
        '}',
        'UTF8'
    );
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.hil_reason_jcs(
    p_reason_code text,
    p_reason_text text
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"reason_code":' || hil_jcs_string(p_reason_code) ||
        ',"reason_text":' || hil_jcs_string(p_reason_text) ||
        ',"schema_version":"hil-reason-v1"}',
        'UTF8'
    );
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.hil_decision_jcs(
    p_actor_id sentinelflow.ascii_id,
    p_canonical_artifact_digest sentinelflow.sha256_digest,
    p_challenge_id uuid,
    p_decided_at timestamptz,
    p_decision text,
    p_decision_id uuid,
    p_decision_valid_until timestamptz,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_generated_artifact_digest sentinelflow.sha256_digest,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_nonce_digest sentinelflow.sha256_digest,
    p_operation text,
    p_policy_digest sentinelflow.sha256_digest,
    p_reason_digest sentinelflow.sha256_digest,
    p_resource_id uuid,
    p_resource_version integer,
    p_session_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_validation_snapshot_digest sentinelflow.sha256_digest
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"actor_id":' || hil_jcs_string(p_actor_id::text) ||
        ',"canonical_artifact_digest":' || hil_jcs_string(p_canonical_artifact_digest::text) ||
        ',"challenge_id":' || hil_jcs_string(p_challenge_id::text) ||
        ',"decided_at":' || hil_jcs_string(hil_rfc3339(p_decided_at)) ||
        ',"decision":' || hil_jcs_string(p_decision) ||
        ',"decision_id":' || hil_jcs_string(p_decision_id::text) ||
        ',"decision_valid_until":' || hil_jcs_string(hil_rfc3339(p_decision_valid_until)) ||
        ',"evidence_snapshot_digest":' || hil_jcs_string(p_evidence_snapshot_digest::text) ||
        ',"generated_artifact_digest":' || hil_jcs_string(p_generated_artifact_digest::text) ||
        ',"idempotency_key_digest":' || hil_jcs_string(p_idempotency_key_digest::text) ||
        ',"nonce_digest":' || hil_jcs_string(p_nonce_digest::text) ||
        ',"operation":' || hil_jcs_string(p_operation) ||
        ',"original_add_digest":null' ||
        ',"policy_digest":' || hil_jcs_string(p_policy_digest::text) ||
        ',"reason_digest":' || hil_jcs_string(p_reason_digest::text) ||
        ',"resource_id":' || hil_jcs_string(p_resource_id::text) ||
        ',"resource_type":"policy"' ||
        ',"resource_version":' || p_resource_version::text ||
        ',"schema_version":"hil-decision-v1"' ||
        ',"session_digest":' || hil_jcs_string(p_session_digest::text) ||
        ',"target_ipv4":' || hil_jcs_string(host(p_target_ipv4)) ||
        ',"validation_snapshot_digest":' || hil_jcs_string(p_validation_snapshot_digest::text) ||
        '}',
        'UTF8'
    );
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.hil_authorization_jcs(
    p_action_id uuid,
    p_actor_id sentinelflow.ascii_id,
    p_authorization_id uuid,
    p_canonical_artifact_digest sentinelflow.sha256_digest,
    p_decided_at timestamptz,
    p_decision_nonce_digest sentinelflow.sha256_digest,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_generated_artifact_digest sentinelflow.sha256_digest,
    p_hil_reason_digest sentinelflow.sha256_digest,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_policy_digest sentinelflow.sha256_digest,
    p_policy_id uuid,
    p_policy_version integer,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_valid_until timestamptz
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"action_id":' || hil_jcs_string(p_action_id::text) ||
        ',"actor_id":' || hil_jcs_string(p_actor_id::text) ||
        ',"authorization_id":' || hil_jcs_string(p_authorization_id::text) ||
        ',"authorization_kind":"add"' ||
        ',"canonical_artifact_digest":' || hil_jcs_string(p_canonical_artifact_digest::text) ||
        ',"decided_at":' || hil_jcs_string(hil_rfc3339(p_decided_at)) ||
        ',"decision":"approve"' ||
        ',"decision_nonce_digest":' || hil_jcs_string(p_decision_nonce_digest::text) ||
        ',"evidence_snapshot_digest":' || hil_jcs_string(p_evidence_snapshot_digest::text) ||
        ',"generated_artifact_digest":' || hil_jcs_string(p_generated_artifact_digest::text) ||
        ',"hil_reason_digest":' || hil_jcs_string(p_hil_reason_digest::text) ||
        ',"idempotency_key_digest":' || hil_jcs_string(p_idempotency_key_digest::text) ||
        ',"original_add_digest":null' ||
        ',"policy_digest":' || hil_jcs_string(p_policy_digest::text) ||
        ',"policy_id":' || hil_jcs_string(p_policy_id::text) ||
        ',"policy_version":' || p_policy_version::text ||
        ',"schema_version":"enforcement-authorization-v1"' ||
        ',"target_ipv4":' || hil_jcs_string(host(p_target_ipv4)) ||
        ',"valid_until":' || hil_jcs_string(hil_rfc3339(p_valid_until)) ||
        '}',
        'UTF8'
    );
$function$;

-- Narrow database-clock challenge issuance.  The API role can execute this
-- function but cannot directly insert a challenge or fabricate its JCS.
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
DECLARE
    session_row sentinelflow.admin_sessions%ROWTYPE;
    policy_row sentinelflow.policy_proposals%ROWTYPE;
    validation_row sentinelflow.validation_snapshots%ROWTYPE;
    server_now timestamptz;
    challenge_expires_at timestamptz;
    challenge_bytes bytea;
    challenge_hash sentinelflow.sha256_digest;
    gate_names text[];
    gate_passed boolean;
BEGIN
    IF p_operation NOT IN ('approve', 'reject') THEN
        RETURN;
    END IF;

    SELECT * INTO session_row
    FROM sentinelflow.admin_sessions current_session
    WHERE current_session.session_id = p_session_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT * INTO policy_row
    FROM sentinelflow.policy_proposals current_policy
    WHERE current_policy.policy_id = p_policy_id
      AND current_policy.version = p_policy_version
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT * INTO validation_row
    FROM sentinelflow.validation_snapshots current_validation
    WHERE current_validation.policy_id = p_policy_id
      AND current_validation.policy_version = p_policy_version
      AND current_validation.snapshot_digest = p_validation_snapshot_digest
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    server_now := clock_timestamp();

    SELECT array_agg(gate_name ORDER BY gate_order), bool_and(passed)
    INTO gate_names, gate_passed
    FROM sentinelflow.validation_gates
    WHERE validation_snapshot_id = validation_row.validation_snapshot_id;

    IF session_row.actor_id <> p_actor_id OR
       session_row.token_digest <> p_session_digest OR
       session_row.csrf_digest <> p_csrf_digest OR
       session_row.authenticated_at <> p_authenticated_at OR
       session_row.expires_at <> p_session_expires_at OR
       session_row.revoked_at IS NOT NULL OR
       session_row.expires_at <= server_now OR
       session_row.last_seen_at + interval '30 minutes' <= server_now OR
       server_now > session_row.authenticated_at + interval '15 minutes' OR
       policy_row.state <> 'valid' OR
       policy_row.target_ipv4 <> p_target_ipv4 OR
       policy_row.policy_digest <> p_policy_digest OR
       policy_row.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
       policy_row.generated_artifact_digest <> p_generated_artifact_digest OR
       policy_row.canonical_artifact_digest <> p_canonical_artifact_digest OR
       policy_row.ttl_seconds <> p_ttl_seconds OR
       validation_row.command_candidate_id <> policy_row.command_candidate_id OR
       validation_row.evidence_snapshot_id IS DISTINCT FROM policy_row.evidence_snapshot_id OR
       validation_row.policy_digest <> p_policy_digest OR
       validation_row.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
       validation_row.generated_candidate_digest <> p_generated_artifact_digest OR
       validation_row.canonical_artifact_digest <> p_canonical_artifact_digest OR
       validation_row.target_ipv4 <> p_target_ipv4 OR
       validation_row.ttl_seconds <> p_ttl_seconds OR
       validation_row.state <> 'valid' OR
       validation_row.source_health_status <> 'complete' OR
       validation_row.created_at <> p_validation_created_at OR
       validation_row.valid_until <> p_validation_valid_until OR
       validation_row.created_at > server_now OR
       validation_row.valid_until <= server_now OR
       gate_names IS DISTINCT FROM ARRAY[
           'structured_output', 'command_grammar',
           'policy_evidence_command_consistency', 'protected_network',
           'owned_schema_syntax', 'historical_impact'
       ]::text[] OR gate_passed IS DISTINCT FROM true OR
       NOT EXISTS (
           SELECT 1
           FROM sentinelflow.command_candidates candidate
           JOIN sentinelflow.evidence_snapshots evidence
             ON evidence.evidence_snapshot_id = policy_row.evidence_snapshot_id
           WHERE candidate.command_candidate_id = policy_row.command_candidate_id
             AND candidate.analysis_id = policy_row.analysis_id
             AND candidate.evidence_snapshot_id IS NOT DISTINCT FROM policy_row.evidence_snapshot_id
             AND candidate.evidence_snapshot_digest = p_evidence_snapshot_digest
             AND candidate.target_ipv4 = p_target_ipv4
             AND candidate.ttl_seconds = p_ttl_seconds
             AND candidate.generated_command = p_generated_command
             AND candidate.generated_artifact_digest = p_generated_artifact_digest
             AND candidate.parse_state = 'valid'
             AND candidate.canonical_artifact = p_canonical_artifact
             AND candidate.canonical_artifact_digest = p_canonical_artifact_digest
             AND evidence.snapshot_digest = p_evidence_snapshot_digest
             AND evidence.source_ip = p_target_ipv4
             AND evidence.source_health_status = 'complete'
       ) THEN
        RETURN;
    END IF;

    challenge_expires_at := LEAST(
        server_now + interval '5 minutes',
        validation_row.valid_until,
        session_row.expires_at
    );
    IF challenge_expires_at <= server_now THEN RETURN; END IF;

    challenge_bytes := sentinelflow.hil_challenge_jcs(
        session_row.authenticated_at, p_canonical_artifact_digest,
        p_challenge_id, p_evidence_snapshot_digest, challenge_expires_at,
        p_generated_artifact_digest, server_now, p_nonce_digest,
        p_operation, p_policy_digest, p_policy_id, p_policy_version,
        p_session_digest, p_target_ipv4, p_validation_snapshot_digest,
        validation_row.valid_until
    );
    challenge_hash := sentinelflow.hil_sha256(challenge_bytes);

    INSERT INTO sentinelflow.decision_challenges (
        challenge_id, schema_version, nonce_digest, session_id, session_digest,
        actor_id, operation, resource_type, resource_id, resource_version,
        policy_id, policy_version, action_id, target_ipv4, policy_digest,
        evidence_snapshot_digest, generated_artifact_digest,
        canonical_artifact_digest, original_add_digest,
        validation_snapshot_digest, validation_valid_until,
        idempotency_key_digest, authenticated_at,
        reauth_required_after_seconds, issued_at, expires_at,
        challenge_jcs, challenge_digest
    ) VALUES (
        p_challenge_id, 'hil-challenge-v1', p_nonce_digest, p_session_id,
        p_session_digest, p_actor_id, p_operation, 'policy', p_policy_id,
        p_policy_version, p_policy_id, p_policy_version, NULL,
        p_target_ipv4, p_policy_digest, p_evidence_snapshot_digest,
        p_generated_artifact_digest, p_canonical_artifact_digest, NULL,
        p_validation_snapshot_digest, validation_row.valid_until,
        p_idempotency_key_digest, session_row.authenticated_at, 900,
        server_now, challenge_expires_at, challenge_bytes, challenge_hash
    ) ON CONFLICT DO NOTHING;

    RETURN QUERY
    SELECT
        challenge.challenge_id::text, challenge.schema_version,
        challenge.nonce_digest::text, challenge.session_id::text,
        challenge.session_digest::text, challenge.actor_id::text,
        challenge.operation, challenge.resource_type,
        challenge.resource_id::text, challenge.resource_version,
        host(challenge.target_ipv4), challenge.policy_digest::text,
        challenge.evidence_snapshot_digest::text,
        challenge.generated_artifact_digest::text,
        challenge.canonical_artifact_digest::text,
        challenge.original_add_digest::text,
        challenge.validation_snapshot_digest::text,
        challenge.validation_valid_until,
        challenge.idempotency_key_digest::text,
        challenge.authenticated_at, challenge.reauth_required_after_seconds,
        challenge.issued_at, challenge.expires_at,
        challenge.challenge_jcs, challenge.challenge_digest::text
    FROM sentinelflow.decision_challenges challenge
    WHERE challenge.challenge_id = p_challenge_id
      AND challenge.idempotency_key_digest = p_idempotency_key_digest
      AND challenge.nonce_digest = p_nonce_digest;
END
$function$;

-- Expose only currently eligible dispatch rows, including an expired lease
-- that may be reclaimed.  An unexpired lease is never visible as claimable.
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
          validation.state = 'valid' AND validation.valid_until >= clock_timestamp()) OR
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
    server_now timestamptz := clock_timestamp();
    claimed boolean;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL OR p_lease_owner IS NULL OR
       p_lease_until IS NULL OR NOT isfinite(p_lease_until) OR
       p_lease_until <= server_now OR
       p_lease_until > server_now + interval '60 seconds' THEN
        RETURN false;
    END IF;

    WITH eligible AS MATERIALIZED (
        SELECT job.job_id
        FROM sentinelflow.outbox_jobs job
        JOIN sentinelflow.dispatch_operations operation USING (job_id)
        JOIN sentinelflow.validation_snapshots validation
          ON validation.validation_snapshot_id = operation.validation_snapshot_id
        JOIN sentinelflow.enforcement_actions action
          ON action.action_id = operation.action_id
        WHERE job.job_id = p_job_id
          AND job.kind = 'dispatch_' || operation.operation
          AND job.operation = operation.operation
          AND job.aggregate_type = 'enforcement_action'
          AND job.aggregate_id = action.action_id
          AND job.aggregate_version = action.version
          AND (
              (job.state IN ('pending', 'retry') AND job.available_at <= server_now) OR
              (job.state = 'leased' AND job.lease_expires_at <= server_now)
          )
          AND job.attempts < job.max_attempts
          AND operation.not_before <= server_now
          AND operation.valid_until >= server_now
          AND (
              (operation.operation = 'add' AND
                  action.state IN ('approved', 'queued') AND
                  validation.state = 'valid' AND validation.valid_until >= server_now) OR
              (operation.operation IN ('revoke', 'inspect') AND
                  action.state IN ('active', 'expired', 'failed', 'indeterminate'))
          )
          AND (
              (operation.operation IN ('add', 'revoke') AND EXISTS (
                  SELECT 1 FROM sentinelflow.enforcement_authorizations authz
                  WHERE authz.authorization_id = operation.enforcement_authorization_id
                    AND authz.authorization_digest = operation.authorization_digest
                    AND authz.valid_until >= server_now
              )) OR
              (operation.operation = 'inspect' AND EXISTS (
                  SELECT 1 FROM sentinelflow.inspection_authorizations authz
                  WHERE authz.authorization_id = operation.inspection_authorization_id
                    AND authz.authorization_digest = operation.authorization_digest
                    AND authz.valid_until >= server_now
              ))
          )
        FOR UPDATE OF job
    )
    UPDATE sentinelflow.outbox_jobs job
    SET state = 'leased', lease_token = p_lease_token,
        lease_owner = p_lease_owner, lease_expires_at = p_lease_until,
        attempts = job.attempts + 1, last_error_code = NULL,
        last_error_digest = NULL, updated_at = server_now
    FROM eligible
    WHERE job.job_id = eligible.job_id
      AND (
          (job.state IN ('pending', 'retry') AND job.available_at <= server_now) OR
          (job.state = 'leased' AND job.lease_expires_at <= server_now)
      )
      AND job.attempts < job.max_attempts
    RETURNING true INTO claimed;

    RETURN coalesce(claimed, false);
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finish_dispatch_job(
    p_job_id uuid,
    p_lease_token uuid,
    p_outcome text,
    p_error_code sentinelflow.ascii_id,
    p_error_digest sentinelflow.sha256_digest,
    p_next_available_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    finished boolean;
BEGIN
    IF p_outcome NOT IN ('completed', 'retry', 'dead') OR
       (p_outcome = 'retry' AND (
           p_next_available_at IS NULL OR NOT isfinite(p_next_available_at) OR
           p_next_available_at < server_now
       )) OR
       (p_outcome <> 'retry' AND p_next_available_at IS NOT NULL) OR
       (p_outcome IN ('retry', 'dead') AND
           (p_error_code IS NULL OR p_error_digest IS NULL)) OR
       (p_outcome = 'completed' AND
           (p_error_code IS NOT NULL OR p_error_digest IS NOT NULL)) THEN
        RETURN false;
    END IF;
    IF p_outcome = 'completed' AND NOT EXISTS (
        SELECT 1
        FROM sentinelflow.execution_results result
        JOIN sentinelflow.execution_capabilities capability USING (capability_id)
        WHERE capability.job_id = p_job_id
    ) THEN
        RETURN false;
    END IF;

    UPDATE sentinelflow.outbox_jobs job
    SET state = p_outcome,
        available_at = CASE WHEN p_outcome = 'retry'
            THEN p_next_available_at ELSE job.available_at END,
        lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
        last_error_code = CASE WHEN p_outcome = 'completed' THEN NULL ELSE p_error_code END,
        last_error_digest = CASE WHEN p_outcome = 'completed' THEN NULL ELSE p_error_digest END,
        updated_at = server_now
    WHERE job.job_id = p_job_id
      AND job.state = 'leased'
      AND job.lease_token = p_lease_token
      AND job.lease_expires_at > server_now
      AND (p_outcome <> 'retry' OR job.attempts < job.max_attempts)
    RETURNING true INTO finished;

    IF coalesce(finished, false) AND p_outcome = 'dead' THEN
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest
        )
        SELECT job_id, kind, aggregate_type, aggregate_id, aggregate_version,
               attempts, p_error_code, p_error_digest
        FROM sentinelflow.outbox_jobs
        WHERE job_id = p_job_id
        ON CONFLICT (job_id) DO NOTHING;
    END IF;
    RETURN coalesce(finished, false);
END
$function$;

-- Remove every direct API mutation path involved in final HIL commitment.
-- Challenge insertion is also replaced by the narrow issue function.
REVOKE INSERT, UPDATE, DELETE ON sentinelflow.decision_challenges
    FROM sentinelflow_api;
REVOKE INSERT, UPDATE, DELETE ON
    sentinelflow.hil_reasons,
    sentinelflow.approval_decisions,
    sentinelflow.enforcement_authorizations,
    sentinelflow.enforcement_actions,
    sentinelflow.outbox_jobs,
    sentinelflow.dispatch_operations
FROM sentinelflow_api;

REVOKE ALL ON FUNCTION sentinelflow.hil_sha256(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.hil_jcs_string(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.hil_rfc3339(timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.hil_challenge_jcs(
    timestamptz, sentinelflow.sha256_digest, uuid,
    sentinelflow.sha256_digest, timestamptz, sentinelflow.sha256_digest,
    timestamptz, sentinelflow.sha256_digest, text,
    sentinelflow.sha256_digest, uuid, integer,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4,
    sentinelflow.sha256_digest, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.hil_reason_jcs(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.hil_decision_jcs(
    sentinelflow.ascii_id, sentinelflow.sha256_digest, uuid, timestamptz,
    text, uuid, timestamptz, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, text, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, uuid, integer, sentinelflow.sha256_digest,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest
) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.hil_authorization_jcs(
    uuid, sentinelflow.ascii_id, uuid, sentinelflow.sha256_digest,
    timestamptz, sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, uuid, integer,
    sentinelflow.canonical_ipv4, timestamptz
) FROM PUBLIC;
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
REVOKE ALL ON FUNCTION sentinelflow.commit_hil_policy_decision(
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
    sentinelflow.sha256_digest, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.commit_hil_policy_decision(
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
    sentinelflow.sha256_digest, uuid
) TO sentinelflow_api;

-- The record function was replaced after migration 000004; preserve its only
-- authorized caller and deny every other role explicitly.
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read;
GRANT EXECUTE ON FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) TO sentinelflow_dispatcher;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (10, 'control_plane_hardening')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
