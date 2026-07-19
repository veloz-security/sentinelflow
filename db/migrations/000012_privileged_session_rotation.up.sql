BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- This function is called immediately after commit_hil_policy_decision in the
-- same transaction. A fresh decision rotates exactly once. A replay performs
-- an exact, read-only comparison with the already-created replacement.
CREATE OR REPLACE FUNCTION sentinelflow.commit_privileged_session_rotation(
    p_replayed boolean,
    p_decision_id uuid,
    p_challenge_id uuid,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_expected_session_id uuid,
    p_expected_actor_id sentinelflow.ascii_id,
    p_expected_token_digest sentinelflow.sha256_digest,
    p_expected_csrf_digest sentinelflow.sha256_digest,
    p_expected_authenticated_at timestamptz,
    p_expected_created_at timestamptz,
    p_expected_last_seen_at timestamptz,
    p_expected_expires_at timestamptz,
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
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    decision_row sentinelflow.approval_decisions%ROWTYPE;
    challenge_row sentinelflow.decision_challenges%ROWTYPE;
    expected_row sentinelflow.admin_sessions%ROWTYPE;
    replacement_row sentinelflow.admin_sessions%ROWTYPE;
    server_now timestamptz;
    changed_count integer;
BEGIN
    IF p_replayed IS NULL OR p_decision_id IS NULL OR p_challenge_id IS NULL OR
       p_idempotency_key_digest IS NULL OR p_expected_session_id IS NULL OR
       p_expected_actor_id IS NULL OR p_expected_token_digest IS NULL OR
       p_expected_csrf_digest IS NULL OR p_expected_authenticated_at IS NULL OR
       p_expected_created_at IS NULL OR p_expected_last_seen_at IS NULL OR
       p_expected_expires_at IS NULL OR p_rotation_at IS NULL OR
       p_replacement_session_id IS NULL OR p_replacement_actor_id IS NULL OR
       p_replacement_token_digest IS NULL OR p_replacement_csrf_digest IS NULL OR
       p_replacement_authenticated_at IS NULL OR p_replacement_created_at IS NULL OR
       p_replacement_last_seen_at IS NULL OR p_replacement_expires_at IS NULL OR
       p_replacement_rotation_parent_id IS NULL OR
       NOT isfinite(p_expected_authenticated_at) OR
       NOT isfinite(p_expected_created_at) OR
       NOT isfinite(p_expected_last_seen_at) OR
       NOT isfinite(p_expected_expires_at) OR NOT isfinite(p_rotation_at) OR
       NOT isfinite(p_replacement_authenticated_at) OR
       NOT isfinite(p_replacement_created_at) OR
       NOT isfinite(p_replacement_last_seen_at) OR
       NOT isfinite(p_replacement_expires_at) OR
       p_expected_session_id = p_replacement_session_id OR
       p_expected_token_digest = p_expected_csrf_digest OR
       p_expected_actor_id <> p_replacement_actor_id OR
       p_expected_token_digest = p_replacement_token_digest OR
       p_expected_csrf_digest = p_replacement_csrf_digest OR
       p_replacement_token_digest = p_replacement_csrf_digest OR
       p_expected_authenticated_at <> p_replacement_authenticated_at OR
       p_replacement_rotation_parent_id <> p_expected_session_id OR
       p_rotation_at <> p_replacement_created_at OR
       p_replacement_created_at <> p_replacement_last_seen_at OR
       p_replacement_expires_at <> p_replacement_created_at + interval '8 hours' OR
       p_expected_authenticated_at > p_expected_created_at OR
       p_expected_created_at > p_expected_last_seen_at OR
       p_expected_expires_at <= p_expected_created_at OR
       p_expected_expires_at > p_expected_created_at + interval '8 hours' OR
       p_rotation_at < p_expected_last_seen_at OR
       p_rotation_at >= p_expected_expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'SF001', MESSAGE = 'invalid_input';
    END IF;

    SELECT * INTO decision_row
    FROM sentinelflow.approval_decisions current_decision
    WHERE current_decision.decision_id = p_decision_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF007', MESSAGE = 'not_found';
    END IF;

    SELECT * INTO challenge_row
    FROM sentinelflow.decision_challenges current_challenge
    WHERE current_challenge.challenge_id = p_challenge_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF007', MESSAGE = 'not_found';
    END IF;

    IF decision_row.challenge_id <> p_challenge_id OR
       decision_row.idempotency_key_digest <> p_idempotency_key_digest OR
       decision_row.session_digest <> p_expected_token_digest OR
       decision_row.actor_id <> p_expected_actor_id OR
       challenge_row.session_id <> p_expected_session_id OR
       challenge_row.session_digest <> p_expected_token_digest OR
       challenge_row.authenticated_at <> p_expected_authenticated_at OR
       challenge_row.idempotency_key_digest <> p_idempotency_key_digest OR
       challenge_row.consumed_decision_id IS DISTINCT FROM p_decision_id OR
       challenge_row.consumed_at IS NULL OR
       p_rotation_at < challenge_row.issued_at THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    SELECT * INTO expected_row
    FROM sentinelflow.admin_sessions current_session
    WHERE current_session.session_id = p_expected_session_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF002', MESSAGE = 'authentication_invalid';
    END IF;

    IF expected_row.actor_id <> p_expected_actor_id OR
       expected_row.token_digest <> p_expected_token_digest OR
       expected_row.csrf_digest <> p_expected_csrf_digest OR
       expected_row.authenticated_at <> p_expected_authenticated_at OR
       expected_row.created_at <> p_expected_created_at OR
       expected_row.last_seen_at <> p_expected_last_seen_at OR
       expected_row.expires_at <> p_expected_expires_at OR
       expected_row.rotation_parent_id IS DISTINCT FROM p_expected_rotation_parent_id THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    IF p_replayed THEN
        IF expected_row.revoked_at IS NULL OR expected_row.revoked_at < p_rotation_at THEN
            RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
        END IF;
        SELECT * INTO replacement_row
        FROM sentinelflow.admin_sessions replacement
        WHERE replacement.session_id = p_replacement_session_id
        FOR SHARE;
        IF NOT FOUND OR replacement_row.actor_id <> p_replacement_actor_id OR
           replacement_row.token_digest <> p_replacement_token_digest OR
           replacement_row.csrf_digest <> p_replacement_csrf_digest OR
           replacement_row.authenticated_at <> p_replacement_authenticated_at OR
           replacement_row.created_at <> p_replacement_created_at OR
           replacement_row.last_seen_at <> p_replacement_last_seen_at OR
           replacement_row.expires_at <> p_replacement_expires_at OR
           replacement_row.rotation_parent_id IS DISTINCT FROM p_replacement_rotation_parent_id THEN
            RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
        END IF;
        RETURN false;
    END IF;

    server_now := clock_timestamp();
    IF expected_row.revoked_at IS NOT NULL OR
       expected_row.authenticated_at > server_now OR
       expected_row.created_at > server_now OR
       expected_row.last_seen_at > server_now OR
       expected_row.expires_at <= server_now OR
       expected_row.last_seen_at + interval '30 minutes' <= server_now OR
       p_rotation_at > server_now OR
       p_replacement_expires_at <= server_now OR
       p_replacement_last_seen_at + interval '30 minutes' <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF002', MESSAGE = 'authentication_invalid';
    END IF;

    -- revoked_at is database-authoritative and therefore may be later than the
    -- Boundary candidate's p_rotation_at. The replacement timestamps remain
    -- the exact checked candidate bytes; replay binds both by requiring the
    -- persisted revoke to be no earlier than that candidate and the child row
    -- to match exactly.
    UPDATE sentinelflow.admin_sessions current_session
    SET revoked_at = server_now
    WHERE current_session.session_id = p_expected_session_id
      AND current_session.actor_id = p_expected_actor_id
      AND current_session.token_digest = p_expected_token_digest
      AND current_session.csrf_digest = p_expected_csrf_digest
      AND current_session.authenticated_at = p_expected_authenticated_at
      AND current_session.created_at = p_expected_created_at
      AND current_session.last_seen_at = p_expected_last_seen_at
      AND current_session.expires_at = p_expected_expires_at
      AND current_session.rotation_parent_id IS NOT DISTINCT FROM p_expected_rotation_parent_id
      AND current_session.revoked_at IS NULL;
    GET DIAGNOSTICS changed_count = ROW_COUNT;
    IF changed_count <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    INSERT INTO sentinelflow.admin_sessions (
        session_id, actor_id, token_digest, csrf_digest, authenticated_at,
        created_at, last_seen_at, expires_at, rotation_parent_id
    ) VALUES (
        p_replacement_session_id, p_replacement_actor_id,
        p_replacement_token_digest, p_replacement_csrf_digest,
        p_replacement_authenticated_at, p_replacement_created_at,
        p_replacement_last_seen_at, p_replacement_expires_at,
        p_replacement_rotation_parent_id
    );

    RETURN true;
END
$function$;

-- The API receives only this combined coordinator. The pre-000012 decision
-- function and the inner rotation function remain owner-only so a compromised
-- API connection cannot commit either half independently.
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
    committed_id uuid;
    was_replayed boolean;
    rotated boolean;
BEGIN
    SELECT result.committed_decision_id, result.replayed
    INTO committed_id, was_replayed
    FROM sentinelflow.commit_hil_policy_decision(
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
        p_authorization_digest, p_audit_event_id
    ) AS result;

    IF committed_id IS NULL OR was_replayed IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    rotated := sentinelflow.commit_privileged_session_rotation(
        was_replayed, committed_id, p_challenge_id,
        p_idempotency_key_digest, p_session_id, p_actor_id,
        p_session_digest, p_csrf_digest, p_authenticated_at,
        p_expected_created_at, p_expected_last_seen_at,
        p_session_expires_at, p_expected_rotation_parent_id,
        p_rotation_at, p_replacement_session_id, p_replacement_actor_id,
        p_replacement_token_digest, p_replacement_csrf_digest,
        p_replacement_authenticated_at, p_replacement_created_at,
        p_replacement_last_seen_at, p_replacement_expires_at,
        p_replacement_rotation_parent_id
    );

    IF rotated = was_replayed THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    RETURN QUERY SELECT committed_id, was_replayed, rotated;
END
$function$;

REVOKE ALL ON FUNCTION sentinelflow.commit_privileged_session_rotation(
    boolean, uuid, uuid, sentinelflow.sha256_digest, uuid,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz,
    timestamptz, uuid, timestamptz, uuid, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, timestamptz,
    timestamptz, timestamptz, timestamptz, uuid
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker,
       sentinelflow_read, sentinelflow_dispatcher;

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
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker,
       sentinelflow_read, sentinelflow_dispatcher;

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
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker,
       sentinelflow_read, sentinelflow_dispatcher;
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

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (12, 'privileged_session_rotation')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
