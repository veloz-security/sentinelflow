BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 26 AND name = 'enforcement_lifecycle'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'revocation HIL requires enforcement lifecycle migration 26';
    END IF;
    IF EXISTS (SELECT 1 FROM sentinelflow.revocation_operations) OR
       EXISTS (SELECT 1 FROM sentinelflow.decision_challenges WHERE operation = 'revoke') OR
       EXISTS (SELECT 1 FROM sentinelflow.approval_decisions WHERE operation = 'revoke') OR
       EXISTS (SELECT 1 FROM sentinelflow.hil_reasons WHERE operation = 'revoke') OR
       EXISTS (SELECT 1 FROM sentinelflow.enforcement_authorizations WHERE authorization_kind = 'revoke') OR
       EXISTS (SELECT 1 FROM sentinelflow.outbox_jobs WHERE operation = 'revoke') OR
       EXISTS (SELECT 1 FROM sentinelflow.dispatch_operations WHERE operation = 'revoke') OR
       EXISTS (SELECT 1 FROM sentinelflow.execution_capabilities WHERE operation = 'revoke') OR
       EXISTS (SELECT 1 FROM sentinelflow.execution_results WHERE operation = 'revoke') OR
       EXISTS (
           SELECT 1 FROM sentinelflow.audit_events
           WHERE action LIKE 'enforcement_revoke%'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'legacy revoke-domain evidence requires an explicit evidence-preserving migration';
    END IF;
END
$preflight$;

-- A revoke authorization belongs to one exact action version. The delete
-- bytes are deterministic for an IPv4 address, so neither those bytes nor
-- their digest are globally unique authority.
ALTER TABLE sentinelflow.revocation_operations
    DROP CONSTRAINT revocation_operations_action_id_key,
    DROP CONSTRAINT revocation_operations_artifact_digest_key,
    ADD COLUMN action_version integer;
ALTER TABLE sentinelflow.revocation_operations
    ALTER COLUMN action_version SET NOT NULL,
    ADD CONSTRAINT revocation_operations_action_version_check
        CHECK (action_version >= 1),
    ADD CONSTRAINT revocation_operations_artifact_digest_exact CHECK (
        artifact_digest = (
            'sha256:' || encode(sha256(artifact), 'hex')
        )::sentinelflow.sha256_digest
    );
CREATE UNIQUE INDEX revocation_operations_action_version_000027_idx
    ON sentinelflow.revocation_operations (action_id, action_version);

-- Add authority remains once-only for an action. Revoke authority is instead
-- fenced by revocation_operations(action_id, action_version).
DROP INDEX sentinelflow.enforcement_authorizations_action_kind_idx;
CREATE UNIQUE INDEX enforcement_authorizations_add_action_000027_idx
    ON sentinelflow.enforcement_authorizations (action_id)
    WHERE authorization_kind = 'add';

-- The same canonical reason text is not an identity shared by administrators
-- or operations. Keep exact reuse scoped to its actor and operation.
ALTER TABLE sentinelflow.hil_reasons
    DROP CONSTRAINT hil_reasons_reason_digest_key;
CREATE UNIQUE INDEX hil_reasons_actor_operation_digest_000027_idx
    ON sentinelflow.hil_reasons (actor_id, operation, reason_digest);

-- The frozen policy coordinator predates scoped reason identity. Patch only
-- its two exact reason lookup clauses and fail stop if the predecessor body is
-- not the reviewed shape; all other bytes and authority remain unchanged.
DO $scope_policy_reason_identity$
DECLARE
    function_definition text;
    patched_definition text;
    signature regprocedure;
BEGIN
    signature := (
        'sentinelflow.commit_hil_policy_decision(uuid,sentinelflow.ascii_id,' ||
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,timestamptz,' ||
        'timestamptz,uuid,bytea,sentinelflow.sha256_digest,' ||
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,text,uuid,' ||
        'integer,sentinelflow.canonical_ipv4,sentinelflow.sha256_digest,' ||
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,' ||
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,text,bytea,' ||
        'timestamptz,timestamptz,integer,uuid,text,text,bytea,' ||
        'sentinelflow.sha256_digest,uuid,timestamptz,timestamptz,bytea,' ||
        'sentinelflow.sha256_digest,uuid,uuid,uuid,bytea,' ||
        'sentinelflow.sha256_digest,uuid)'
    )::regprocedure;
    function_definition := pg_get_functiondef(signature);
    IF function_definition NOT LIKE '%ON CONFLICT (reason_digest) DO NOTHING%' OR
       function_definition NOT LIKE '%WHERE reason.reason_digest = p_reason_digest;%' OR
       function_definition LIKE '%ON CONFLICT (actor_id, operation, reason_digest)%' THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'policy HIL coordinator reason clauses are not the reviewed predecessor';
    END IF;
    patched_definition := replace(
        function_definition,
        'ON CONFLICT (reason_digest) DO NOTHING',
        'ON CONFLICT (actor_id, operation, reason_digest) DO NOTHING'
    );
    patched_definition := replace(
        patched_definition,
        'WHERE reason.reason_digest = p_reason_digest;',
        'WHERE reason.actor_id = p_actor_id AND reason.operation = p_operation ' ||
        'AND reason.reason_digest = p_reason_digest;'
    );
    EXECUTE patched_definition;
END
$scope_policy_reason_identity$;

CREATE OR REPLACE FUNCTION sentinelflow.revocation_artifact_000027(
    p_target_ipv4 sentinelflow.canonical_ipv4
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog
AS $function$
    SELECT convert_to(
        'delete element inet sentinelflow blacklist_ipv4 { ' ||
        host(p_target_ipv4) || ' }' || chr(10), 'UTF8'
    );
$function$;

-- lifecycleartifact intentionally freezes whole-second timestamps as .000Z.
-- Global HIL uses ordinary RFC3339Nano and must remain unchanged.
CREATE OR REPLACE FUNCTION sentinelflow.lifecycle_rfc3339_000027(
    p_value timestamptz
)
RETURNS text
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog
AS $function$
    SELECT CASE WHEN isfinite(p_value) THEN
        to_char(p_value AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS') ||
        CASE
            WHEN (extract(microseconds FROM p_value)::bigint % 1000000) = 0 THEN '.000'
            ELSE '.' || rtrim(
                lpad((extract(microseconds FROM p_value)::bigint % 1000000)::text, 6, '0'),
                '0'
            )
        END || 'Z'
    ELSE NULL END;
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.lifecycle_inspection_authorization_jcs_000026(
    p_action_id uuid,
    p_artifact_digest sentinelflow.sha256_digest,
    p_authorization_id uuid,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_original_add_digest sentinelflow.sha256_digest,
    p_original_authorization_digest sentinelflow.sha256_digest,
    p_owned_schema_digest sentinelflow.sha256_digest,
    p_policy_id uuid,
    p_policy_version integer,
    p_purpose text,
    p_requested_at timestamptz,
    p_scheduler_id sentinelflow.ascii_id,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_valid_until timestamptz,
    p_validation_snapshot_digest sentinelflow.sha256_digest
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"action_id":' || sentinelflow.hil_jcs_string(p_action_id::text) ||
        ',"artifact_digest":' || sentinelflow.hil_jcs_string(p_artifact_digest::text) ||
        ',"authorization_id":' || sentinelflow.hil_jcs_string(p_authorization_id::text) ||
        ',"evidence_snapshot_digest":' || sentinelflow.hil_jcs_string(p_evidence_snapshot_digest::text) ||
        ',"idempotency_key_digest":' || sentinelflow.hil_jcs_string(p_idempotency_key_digest::text) ||
        ',"original_add_digest":' || sentinelflow.hil_jcs_string(p_original_add_digest::text) ||
        ',"original_authorization_digest":' ||
            sentinelflow.hil_jcs_string(p_original_authorization_digest::text) ||
        ',"owned_schema_digest":' || sentinelflow.hil_jcs_string(p_owned_schema_digest::text) ||
        ',"policy_id":' || sentinelflow.hil_jcs_string(p_policy_id::text) ||
        ',"policy_version":' || p_policy_version::text ||
        ',"purpose":' || sentinelflow.hil_jcs_string(p_purpose) ||
        ',"requested_at":' ||
            sentinelflow.hil_jcs_string(sentinelflow.lifecycle_rfc3339_000027(p_requested_at)) ||
        ',"scheduler_id":' || sentinelflow.hil_jcs_string(p_scheduler_id::text) ||
        ',"schema_version":"inspection-authorization-v1","target_ipv4":' ||
            sentinelflow.hil_jcs_string(host(p_target_ipv4)) ||
        ',"valid_until":' ||
            sentinelflow.hil_jcs_string(sentinelflow.lifecycle_rfc3339_000027(p_valid_until)) ||
        ',"validation_snapshot_digest":' ||
            sentinelflow.hil_jcs_string(p_validation_snapshot_digest::text) || '}',
        'UTF8'
    );
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.revocation_challenge_jcs_000027(
    p_authenticated_at timestamptz,
    p_artifact_digest sentinelflow.sha256_digest,
    p_challenge_id uuid,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_expires_at timestamptz,
    p_issued_at timestamptz,
    p_nonce_digest sentinelflow.sha256_digest,
    p_original_add_digest sentinelflow.sha256_digest,
    p_policy_digest sentinelflow.sha256_digest,
    p_action_id uuid,
    p_action_version integer,
    p_session_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_validation_snapshot_digest sentinelflow.sha256_digest,
    p_eligibility_valid_until timestamptz
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"authenticated_at":' || hil_jcs_string(hil_rfc3339(p_authenticated_at)) ||
        ',"canonical_artifact_digest":' || hil_jcs_string(p_artifact_digest::text) ||
        ',"challenge_id":' || hil_jcs_string(p_challenge_id::text) ||
        ',"evidence_snapshot_digest":' || hil_jcs_string(p_evidence_snapshot_digest::text) ||
        ',"expires_at":' || hil_jcs_string(hil_rfc3339(p_expires_at)) ||
        ',"generated_artifact_digest":' || hil_jcs_string(p_artifact_digest::text) ||
        ',"issued_at":' || hil_jcs_string(hil_rfc3339(p_issued_at)) ||
        ',"nonce_digest":' || hil_jcs_string(p_nonce_digest::text) ||
        ',"operation":"revoke"' ||
        ',"original_add_digest":' || hil_jcs_string(p_original_add_digest::text) ||
        ',"policy_digest":' || hil_jcs_string(p_policy_digest::text) ||
        ',"reauth_required_after_seconds":900' ||
        ',"resource_id":' || hil_jcs_string(p_action_id::text) ||
        ',"resource_type":"enforcement_action"' ||
        ',"resource_version":' || p_action_version::text ||
        ',"schema_version":"hil-challenge-v1"' ||
        ',"session_digest":' || hil_jcs_string(p_session_digest::text) ||
        ',"target_ipv4":' || hil_jcs_string(host(p_target_ipv4)) ||
        ',"validation_snapshot_digest":' ||
            hil_jcs_string(p_validation_snapshot_digest::text) ||
        ',"validation_valid_until":' ||
            hil_jcs_string(hil_rfc3339(p_eligibility_valid_until)) || '}',
        'UTF8'
    );
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.revocation_decision_jcs_000027(
    p_actor_id sentinelflow.ascii_id,
    p_artifact_digest sentinelflow.sha256_digest,
    p_challenge_id uuid,
    p_decided_at timestamptz,
    p_decision_id uuid,
    p_decision_valid_until timestamptz,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_nonce_digest sentinelflow.sha256_digest,
    p_original_add_digest sentinelflow.sha256_digest,
    p_policy_digest sentinelflow.sha256_digest,
    p_reason_digest sentinelflow.sha256_digest,
    p_action_id uuid,
    p_action_version integer,
    p_session_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_validation_snapshot_digest sentinelflow.sha256_digest
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"actor_id":' || hil_jcs_string(p_actor_id::text) ||
        ',"canonical_artifact_digest":' || hil_jcs_string(p_artifact_digest::text) ||
        ',"challenge_id":' || hil_jcs_string(p_challenge_id::text) ||
        ',"decided_at":' || hil_jcs_string(hil_rfc3339(p_decided_at)) ||
        ',"decision":"revoked"' ||
        ',"decision_id":' || hil_jcs_string(p_decision_id::text) ||
        ',"decision_valid_until":' || hil_jcs_string(hil_rfc3339(p_decision_valid_until)) ||
        ',"evidence_snapshot_digest":' || hil_jcs_string(p_evidence_snapshot_digest::text) ||
        ',"generated_artifact_digest":' || hil_jcs_string(p_artifact_digest::text) ||
        ',"idempotency_key_digest":' || hil_jcs_string(p_idempotency_key_digest::text) ||
        ',"nonce_digest":' || hil_jcs_string(p_nonce_digest::text) ||
        ',"operation":"revoke"' ||
        ',"original_add_digest":' || hil_jcs_string(p_original_add_digest::text) ||
        ',"policy_digest":' || hil_jcs_string(p_policy_digest::text) ||
        ',"reason_digest":' || hil_jcs_string(p_reason_digest::text) ||
        ',"resource_id":' || hil_jcs_string(p_action_id::text) ||
        ',"resource_type":"enforcement_action"' ||
        ',"resource_version":' || p_action_version::text ||
        ',"schema_version":"hil-decision-v1"' ||
        ',"session_digest":' || hil_jcs_string(p_session_digest::text) ||
        ',"target_ipv4":' || hil_jcs_string(host(p_target_ipv4)) ||
        ',"validation_snapshot_digest":' ||
            hil_jcs_string(p_validation_snapshot_digest::text) || '}',
        'UTF8'
    );
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.revocation_authorization_jcs_000027(
    p_action_id uuid,
    p_actor_id sentinelflow.ascii_id,
    p_authorization_id uuid,
    p_artifact_digest sentinelflow.sha256_digest,
    p_decided_at timestamptz,
    p_nonce_digest sentinelflow.sha256_digest,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_reason_digest sentinelflow.sha256_digest,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_original_add_digest sentinelflow.sha256_digest,
    p_policy_digest sentinelflow.sha256_digest,
    p_policy_id uuid,
    p_policy_version integer,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_valid_until timestamptz
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"action_id":' || hil_jcs_string(p_action_id::text) ||
        ',"actor_id":' || hil_jcs_string(p_actor_id::text) ||
        ',"authorization_id":' || hil_jcs_string(p_authorization_id::text) ||
        ',"authorization_kind":"revoke"' ||
        ',"canonical_artifact_digest":' || hil_jcs_string(p_artifact_digest::text) ||
        ',"decided_at":' || hil_jcs_string(hil_rfc3339(p_decided_at)) ||
        ',"decision":"revoke"' ||
        ',"decision_nonce_digest":' || hil_jcs_string(p_nonce_digest::text) ||
        ',"evidence_snapshot_digest":' || hil_jcs_string(p_evidence_snapshot_digest::text) ||
        ',"generated_artifact_digest":' || hil_jcs_string(p_artifact_digest::text) ||
        ',"hil_reason_digest":' || hil_jcs_string(p_reason_digest::text) ||
        ',"idempotency_key_digest":' || hil_jcs_string(p_idempotency_key_digest::text) ||
        ',"original_add_digest":' || hil_jcs_string(p_original_add_digest::text) ||
        ',"policy_digest":' || hil_jcs_string(p_policy_digest::text) ||
        ',"policy_id":' || hil_jcs_string(p_policy_id::text) ||
        ',"policy_version":' || p_policy_version::text ||
        ',"schema_version":"enforcement-authorization-v1"' ||
        ',"target_ipv4":' || hil_jcs_string(host(p_target_ipv4)) ||
        ',"valid_until":' || hil_jcs_string(hil_rfc3339(p_valid_until)) || '}',
        'UTF8'
    );
$function$;

-- Preserve the add/reject decision invariant while allowing a fresh revoke
-- eligibility horizon to bind an immutable historical add validation digest.
CREATE OR REPLACE FUNCTION sentinelflow.require_hil_decision_match()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.decision_challenges challenge
        JOIN sentinelflow.admin_sessions admin_session
          ON admin_session.session_id = challenge.session_id
        JOIN sentinelflow.hil_reasons reason ON reason.reason_id = NEW.reason_id
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = NEW.policy_id AND policy.version = NEW.policy_version
        JOIN sentinelflow.validation_snapshots validation
          ON validation.validation_snapshot_id = NEW.validation_snapshot_id
        JOIN sentinelflow.evidence_snapshots evidence
          ON evidence.evidence_snapshot_id = validation.evidence_snapshot_id
        LEFT JOIN sentinelflow.enforcement_actions action ON action.action_id = NEW.action_id
        WHERE challenge.challenge_id = NEW.challenge_id
          AND challenge.consumed_at IS NULL
          AND challenge.session_digest = NEW.session_digest
          AND challenge.session_digest = admin_session.token_digest
          AND challenge.actor_id = NEW.actor_id
          AND challenge.authenticated_at = admin_session.authenticated_at
          AND admin_session.actor_id = NEW.actor_id
          AND admin_session.revoked_at IS NULL
          AND admin_session.expires_at >= NEW.decided_at
          AND challenge.operation = NEW.operation
          AND challenge.resource_type = NEW.resource_type
          AND challenge.resource_id = NEW.resource_id
          AND challenge.resource_version = NEW.resource_version
          AND challenge.policy_id = NEW.policy_id
          AND challenge.policy_version = NEW.policy_version
          AND challenge.action_id IS NOT DISTINCT FROM NEW.action_id
          AND challenge.target_ipv4 = NEW.target_ipv4
          AND challenge.policy_digest = NEW.policy_digest
          AND challenge.generated_artifact_digest = NEW.generated_artifact_digest
          AND challenge.canonical_artifact_digest = NEW.canonical_artifact_digest
          AND challenge.original_add_digest IS NOT DISTINCT FROM NEW.original_add_digest
          AND challenge.evidence_snapshot_digest = NEW.evidence_snapshot_digest
          AND challenge.validation_snapshot_digest = NEW.validation_snapshot_digest
          AND challenge.nonce_digest = NEW.challenge_nonce_digest
          AND NEW.decided_at >= challenge.issued_at
          AND NEW.decided_at <= challenge.expires_at
          AND NEW.decision_valid_until <= challenge.validation_valid_until
          AND reason.actor_id = NEW.actor_id
          AND reason.operation = NEW.operation
          AND reason.reason_digest = NEW.reason_digest
          AND policy.policy_digest = NEW.policy_digest
          AND policy.target_ipv4 = NEW.target_ipv4
          AND evidence.snapshot_digest = NEW.evidence_snapshot_digest
          AND validation.policy_id = NEW.policy_id
          AND validation.policy_version = NEW.policy_version
          AND validation.snapshot_digest = NEW.validation_snapshot_digest
          AND (
              (NEW.operation IN ('approve', 'reject') AND
                  action.action_id IS NULL AND policy.state = 'valid' AND
                  validation.state = 'valid' AND
                  challenge.validation_valid_until = validation.valid_until AND
                  validation.valid_until >= NEW.decision_valid_until AND
                  policy.generated_artifact_digest = NEW.generated_artifact_digest AND
                  policy.canonical_artifact_digest = NEW.canonical_artifact_digest) OR
              (NEW.operation = 'revoke' AND action.action_id = NEW.action_id AND
                  action.version = NEW.resource_version AND action.state = 'active' AND
                  action.expected_expires_at IS NOT NULL AND
                  action.expected_expires_at >= NEW.decision_valid_until AND
                  challenge.validation_valid_until <= action.expected_expires_at AND
                  challenge.validation_valid_until <= challenge.issued_at + interval '5 minutes' AND
                  action.policy_id = NEW.policy_id AND
                  action.policy_version = NEW.policy_version AND
                  action.validation_snapshot_id = NEW.validation_snapshot_id AND
                  action.target_ipv4 = NEW.target_ipv4 AND
                  action.canonical_artifact_digest = NEW.original_add_digest AND
                  NEW.generated_artifact_digest = NEW.canonical_artifact_digest)
          )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'HIL decision does not match its exact challenge and artifacts';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.require_revocation_operation_match_000027()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'UPDATE' AND
       (to_jsonb(NEW) - 'state' - 'completed_at') <>
       (to_jsonb(OLD) - 'state' - 'completed_at') THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'revocation immutable authority fields changed';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.enforcement_actions action
        JOIN sentinelflow.enforcement_authorizations authz
          ON authz.authorization_id = NEW.authorization_id
        JOIN sentinelflow.approval_decisions decision
          ON decision.decision_id = NEW.approval_decision_id
        JOIN sentinelflow.hil_reasons reason ON reason.reason_id = NEW.reason_id
        WHERE action.action_id = NEW.action_id
          AND authz.authorization_kind = 'revoke'
          AND authz.action_id = NEW.action_id
          AND authz.approval_decision_id = NEW.approval_decision_id
          AND decision.action_id = NEW.action_id
          AND decision.resource_version = NEW.action_version
          AND decision.operation = 'revoke' AND decision.decision = 'revoked'
          AND decision.actor_id = NEW.actor_id
          AND decision.reason_id = NEW.reason_id
          AND decision.reason_digest = NEW.reason_digest
          AND reason.actor_id = NEW.actor_id AND reason.operation = 'revoke'
          AND reason.reason_digest = NEW.reason_digest
          AND action.target_ipv4 = NEW.target_ipv4
          AND action.canonical_artifact_digest = NEW.original_add_digest
          AND (TG_OP <> 'INSERT' OR (
              action.version = NEW.action_version AND action.state = 'active' AND
              action.expected_expires_at IS NOT NULL AND
              action.expected_expires_at > clock_timestamp()
          ))
          AND authz.target_ipv4 = NEW.target_ipv4
          AND authz.original_add_digest = NEW.original_add_digest
          AND authz.canonical_artifact_digest = NEW.artifact_digest
          AND NEW.artifact = sentinelflow.revocation_artifact_000027(NEW.target_ipv4)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'revocation operation does not match exact HIL authority';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER revocation_operations_require_exact_hil_000027
BEFORE INSERT OR UPDATE ON sentinelflow.revocation_operations
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_revocation_operation_match_000027();

-- 000004 granted the API direct revocation DML. From 000027 onward only the
-- SECURITY DEFINER HIL and signed-result coordinators may mutate this ledger.
REVOKE INSERT, UPDATE, DELETE ON TABLE sentinelflow.revocation_operations
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
     sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;

CREATE OR REPLACE FUNCTION sentinelflow.issue_hil_revocation_challenge_000027(
    p_challenge_id uuid,
    p_nonce_digest sentinelflow.sha256_digest,
    p_session_id uuid,
    p_actor_id sentinelflow.ascii_id,
    p_session_digest sentinelflow.sha256_digest,
    p_csrf_digest sentinelflow.sha256_digest,
    p_authenticated_at timestamptz,
    p_session_expires_at timestamptz,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_action_id uuid,
    p_action_version integer,
    p_expected_target_ipv4 sentinelflow.canonical_ipv4,
    p_expected_original_add_digest sentinelflow.sha256_digest
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
    challenge_jcs bytea, challenge_digest text, revoke_artifact bytea,
    policy_id text, policy_version integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    session_row sentinelflow.admin_sessions%ROWTYPE;
    action_row sentinelflow.enforcement_actions%ROWTYPE;
    validation_row sentinelflow.validation_snapshots%ROWTYPE;
    policy_row sentinelflow.policy_proposals%ROWTYPE;
    server_now timestamptz;
    eligibility_until timestamptz;
    artifact_bytes bytea;
    artifact_hash sentinelflow.sha256_digest;
    challenge_bytes bytea;
    challenge_hash sentinelflow.sha256_digest;
BEGIN
    IF p_challenge_id IS NULL OR p_nonce_digest IS NULL OR p_session_id IS NULL OR
       p_actor_id IS NULL OR p_session_digest IS NULL OR p_csrf_digest IS NULL OR
       p_authenticated_at IS NULL OR p_session_expires_at IS NULL OR
       p_idempotency_key_digest IS NULL OR p_action_id IS NULL OR
       p_action_version IS NULL OR p_action_version < 1 OR
       p_expected_target_ipv4 IS NULL OR p_expected_original_add_digest IS NULL OR
       NOT isfinite(p_authenticated_at) OR NOT isfinite(p_session_expires_at) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF001', MESSAGE = 'invalid_input';
    END IF;

    SELECT * INTO session_row FROM sentinelflow.admin_sessions current_session
    WHERE current_session.session_id = p_session_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF002', MESSAGE = 'authentication_invalid';
    END IF;
    SELECT * INTO action_row FROM sentinelflow.enforcement_actions current_action
    WHERE current_action.action_id = p_action_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF007', MESSAGE = 'not_found';
    END IF;
    SELECT * INTO validation_row FROM sentinelflow.validation_snapshots current_validation
    WHERE current_validation.validation_snapshot_id = action_row.validation_snapshot_id
    FOR SHARE;
    SELECT * INTO policy_row FROM sentinelflow.policy_proposals current_policy
    WHERE current_policy.policy_id = action_row.policy_id
      AND current_policy.version = action_row.policy_version FOR SHARE;
    server_now := clock_timestamp();

    IF session_row.actor_id <> p_actor_id OR
       session_row.token_digest <> p_session_digest OR
       session_row.csrf_digest <> p_csrf_digest OR
       session_row.authenticated_at <> p_authenticated_at OR
       session_row.expires_at <> p_session_expires_at OR
       session_row.revoked_at IS NOT NULL OR session_row.expires_at <= server_now OR
       session_row.last_seen_at + interval '30 minutes' <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF002', MESSAGE = 'authentication_invalid';
    END IF;
    IF server_now > session_row.authenticated_at + interval '15 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = 'SF003', MESSAGE = 'step_up_required';
    END IF;
    IF action_row.version <> p_action_version OR
       action_row.target_ipv4 <> p_expected_target_ipv4 OR
       action_row.canonical_artifact_digest <> p_expected_original_add_digest THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    IF EXISTS (
        SELECT 1 FROM sentinelflow.revocation_operations revoke
        WHERE revoke.action_id = p_action_id
          AND revoke.action_version = p_action_version
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    IF action_row.state <> 'active' OR
       action_row.expected_expires_at IS NULL OR action_row.expected_expires_at <= server_now OR
       validation_row.validation_snapshot_id IS NULL OR policy_row.policy_id IS NULL OR
       validation_row.snapshot_digest IS NULL OR
       validation_row.policy_id <> action_row.policy_id OR
       validation_row.policy_version <> action_row.policy_version OR
       validation_row.evidence_snapshot_digest <> action_row.evidence_snapshot_digest OR
       validation_row.canonical_artifact_digest <> action_row.canonical_artifact_digest OR
       policy_row.policy_digest IS NULL OR policy_row.target_ipv4 <> action_row.target_ipv4 THEN
        RAISE EXCEPTION USING ERRCODE = 'SF005', MESSAGE = 'validation_stale';
    END IF;
    IF EXISTS (
        SELECT 1 FROM sentinelflow.decision_challenges challenge
        WHERE challenge.idempotency_key_digest = p_idempotency_key_digest
           OR challenge.challenge_id = p_challenge_id
           OR challenge.nonce_digest = p_nonce_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    eligibility_until := LEAST(
        server_now + interval '5 minutes', session_row.expires_at,
        action_row.expected_expires_at
    );
    IF eligibility_until <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF005', MESSAGE = 'validation_stale';
    END IF;
    artifact_bytes := sentinelflow.revocation_artifact_000027(action_row.target_ipv4);
    artifact_hash := sentinelflow.hil_sha256(artifact_bytes);
    challenge_bytes := sentinelflow.revocation_challenge_jcs_000027(
        session_row.authenticated_at, artifact_hash, p_challenge_id,
        action_row.evidence_snapshot_digest, eligibility_until, server_now,
        p_nonce_digest, action_row.canonical_artifact_digest,
        policy_row.policy_digest, action_row.action_id, action_row.version,
        session_row.token_digest, action_row.target_ipv4,
        validation_row.snapshot_digest, eligibility_until
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
        p_session_digest, p_actor_id, 'revoke', 'enforcement_action',
        action_row.action_id, action_row.version, action_row.policy_id,
        action_row.policy_version, action_row.action_id, action_row.target_ipv4,
        policy_row.policy_digest, action_row.evidence_snapshot_digest,
        artifact_hash, artifact_hash, action_row.canonical_artifact_digest,
        validation_row.snapshot_digest, eligibility_until,
        p_idempotency_key_digest, session_row.authenticated_at, 900,
        server_now, eligibility_until, challenge_bytes, challenge_hash
    );

    RETURN QUERY SELECT
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
        challenge.challenge_jcs, challenge.challenge_digest::text,
        artifact_bytes, challenge.policy_id::text, challenge.policy_version
    FROM sentinelflow.decision_challenges challenge
    WHERE challenge.challenge_id = p_challenge_id;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.commit_hil_revocation_with_session_rotation_000027(
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
    p_action_id uuid,
    p_action_version integer,
    p_policy_id uuid,
    p_policy_version integer,
    p_artifact bytea,
    p_artifact_digest sentinelflow.sha256_digest,
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
    p_authorization_jcs bytea,
    p_authorization_digest sentinelflow.sha256_digest,
    p_revocation_id uuid,
    p_outbox_job_id uuid,
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
    committed_decision_id text, committed_revocation_id text,
    committed_authorization_id text, committed_authorization_digest text,
    committed_outbox_job_id text, replayed boolean, session_rotated boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    session_row sentinelflow.admin_sessions%ROWTYPE;
    action_row sentinelflow.enforcement_actions%ROWTYPE;
    validation_row sentinelflow.validation_snapshots%ROWTYPE;
    challenge_row sentinelflow.decision_challenges%ROWTYPE;
    policy_row sentinelflow.policy_proposals%ROWTYPE;
    existing_decision sentinelflow.approval_decisions%ROWTYPE;
    existing_reason sentinelflow.hil_reasons%ROWTYPE;
    existing_auth sentinelflow.enforcement_authorizations%ROWTYPE;
    existing_revoke sentinelflow.revocation_operations%ROWTYPE;
    existing_job sentinelflow.outbox_jobs%ROWTYPE;
    existing_dispatch sentinelflow.dispatch_operations%ROWTYPE;
    existing_audit sentinelflow.audit_events%ROWTYPE;
    schedule_row sentinelflow.lifecycle_inspection_schedules_000026%ROWTYPE;
    server_now timestamptz;
    expected_artifact bytea;
    expected_artifact_digest sentinelflow.sha256_digest;
    expected_reason_jcs bytea;
    expected_decision_jcs bytea;
    expected_authorization_jcs bytea;
    effective_reason_id uuid;
    rotated boolean;
    changed_count integer;
BEGIN
    IF p_session_id IS NULL OR p_actor_id IS NULL OR p_session_digest IS NULL OR
       p_csrf_digest IS NULL OR p_authenticated_at IS NULL OR
       p_session_expires_at IS NULL OR p_challenge_id IS NULL OR
       p_challenge_jcs IS NULL OR p_challenge_digest IS NULL OR
       p_nonce_digest IS NULL OR p_idempotency_key_digest IS NULL OR
       p_action_id IS NULL OR p_action_version IS NULL OR p_action_version < 1 OR
       p_policy_id IS NULL OR p_policy_version IS NULL OR p_policy_version < 1 OR
       p_artifact IS NULL OR p_artifact_digest IS NULL OR p_reason_id IS NULL OR
       p_reason_code IS NULL OR p_reason_text IS NULL OR p_reason_jcs IS NULL OR
       p_reason_digest IS NULL OR p_decision_id IS NULL OR p_decided_at IS NULL OR
       p_decision_valid_until IS NULL OR p_decision_jcs IS NULL OR
       p_decision_digest IS NULL OR p_authorization_id IS NULL OR
       p_authorization_jcs IS NULL OR p_authorization_digest IS NULL OR
       p_revocation_id IS NULL OR p_outbox_job_id IS NULL OR p_audit_event_id IS NULL OR
       NOT isfinite(p_authenticated_at) OR NOT isfinite(p_session_expires_at) OR
       NOT isfinite(p_decided_at) OR NOT isfinite(p_decision_valid_until) OR
       octet_length(p_artifact) NOT BETWEEN 1 AND 257 OR
       octet_length(p_challenge_jcs) NOT BETWEEN 2 AND 8192 OR
       octet_length(p_reason_jcs) NOT BETWEEN 2 AND 4096 OR
       octet_length(p_decision_jcs) NOT BETWEEN 2 AND 8192 OR
       octet_length(p_authorization_jcs) NOT BETWEEN 2 AND 8192 OR
       p_reason_code NOT IN ('emergency_revoke', 'operator_request', 'other') OR
       length(p_reason_text) NOT BETWEEN 1 AND 500 OR
       p_reason_text ~ '[[:cntrl:]]' OR NOT (p_reason_text IS NFC NORMALIZED) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF001', MESSAGE = 'invalid_input';
    END IF;

    -- Global lock order: session -> action -> original validation -> challenge.
    SELECT * INTO session_row FROM sentinelflow.admin_sessions current_session
    WHERE current_session.session_id = p_session_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF002', MESSAGE = 'authentication_invalid';
    END IF;
    SELECT * INTO action_row FROM sentinelflow.enforcement_actions current_action
    WHERE current_action.action_id = p_action_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'SF007', MESSAGE = 'not_found'; END IF;
    SELECT * INTO validation_row FROM sentinelflow.validation_snapshots current_validation
    WHERE current_validation.validation_snapshot_id = action_row.validation_snapshot_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'SF004', MESSAGE = 'validation_failed'; END IF;
    SELECT * INTO challenge_row FROM sentinelflow.decision_challenges current_challenge
    WHERE current_challenge.challenge_id = p_challenge_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'SF007', MESSAGE = 'not_found'; END IF;
    SELECT * INTO policy_row FROM sentinelflow.policy_proposals current_policy
    WHERE current_policy.policy_id = action_row.policy_id
      AND current_policy.version = action_row.policy_version FOR SHARE;
    server_now := clock_timestamp();
    expected_artifact := sentinelflow.revocation_artifact_000027(action_row.target_ipv4);
    expected_artifact_digest := sentinelflow.hil_sha256(expected_artifact);

    -- A consumed challenge is durable replay evidence. A caller cannot evade
    -- byte-exact replay comparison by changing the idempotency digest and
    -- falling through to the fresh path after the parent session was rotated.
    IF challenge_row.consumed_at IS NOT NULL AND
       challenge_row.idempotency_key_digest <> p_idempotency_key_digest THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    -- Exact response-loss replay remains readable after action transition and
    -- parent-session revocation. It cannot mint a second child or authority.
    SELECT * INTO existing_decision FROM sentinelflow.approval_decisions decision
    WHERE decision.idempotency_key_digest = p_idempotency_key_digest;
    IF FOUND THEN
        SELECT * INTO existing_reason FROM sentinelflow.hil_reasons reason
        WHERE reason.reason_id = existing_decision.reason_id;
        SELECT * INTO existing_auth FROM sentinelflow.enforcement_authorizations authz
        WHERE authz.authorization_id = p_authorization_id
          AND authz.approval_decision_id = existing_decision.decision_id
          AND authz.authorization_kind = 'revoke';
        SELECT * INTO existing_revoke FROM sentinelflow.revocation_operations revoke
        WHERE revoke.revocation_id = p_revocation_id
          AND revoke.approval_decision_id = existing_decision.decision_id;
        SELECT * INTO existing_job FROM sentinelflow.outbox_jobs job
        WHERE job.job_id = p_outbox_job_id;
        SELECT * INTO existing_dispatch FROM sentinelflow.dispatch_operations operation
        WHERE operation.job_id = existing_job.job_id;
        SELECT * INTO existing_audit FROM sentinelflow.audit_events audit
        WHERE audit.event_id = p_audit_event_id;

        expected_reason_jcs := sentinelflow.hil_reason_jcs(p_reason_code, p_reason_text);
        expected_decision_jcs := sentinelflow.revocation_decision_jcs_000027(
            p_actor_id, expected_artifact_digest, p_challenge_id, p_decided_at,
            p_decision_id, p_decision_valid_until, action_row.evidence_snapshot_digest,
            p_idempotency_key_digest, p_nonce_digest, action_row.canonical_artifact_digest,
            policy_row.policy_digest, p_reason_digest, p_action_id, p_action_version,
            p_session_digest, action_row.target_ipv4, validation_row.snapshot_digest
        );
        expected_authorization_jcs := sentinelflow.revocation_authorization_jcs_000027(
            p_action_id, p_actor_id, p_authorization_id, expected_artifact_digest,
            p_decided_at, p_nonce_digest, action_row.evidence_snapshot_digest,
            p_reason_digest, p_idempotency_key_digest, action_row.canonical_artifact_digest,
            policy_row.policy_digest, p_policy_id, p_policy_version, action_row.target_ipv4,
            p_decision_valid_until
        );
        IF existing_decision.challenge_id <> p_challenge_id OR
           existing_decision.decision_id <> p_decision_id OR
           existing_decision.session_digest <> p_session_digest OR
           existing_decision.operation <> 'revoke' OR
           existing_decision.decision <> 'revoked' OR
           existing_decision.resource_type <> 'enforcement_action' OR
           existing_decision.resource_id <> p_action_id OR
           existing_decision.resource_version <> p_action_version OR
           existing_decision.policy_id <> p_policy_id OR
           existing_decision.policy_version <> p_policy_version OR
           existing_decision.actor_id <> p_actor_id OR
           existing_decision.reason_digest <> p_reason_digest OR
           existing_decision.challenge_nonce_digest <> p_nonce_digest OR
           existing_decision.decided_at <> p_decided_at OR
           existing_decision.decision_valid_until <> p_decision_valid_until OR
           existing_decision.decision_jcs <> p_decision_jcs OR
           existing_decision.decision_digest <> p_decision_digest OR
           p_decision_jcs <> expected_decision_jcs OR
           p_decision_digest <> sentinelflow.hil_sha256(expected_decision_jcs) OR
           challenge_row.challenge_jcs <> p_challenge_jcs OR
           challenge_row.challenge_digest <> p_challenge_digest OR
           challenge_row.idempotency_key_digest <> p_idempotency_key_digest OR
           challenge_row.nonce_digest <> p_nonce_digest OR
           challenge_row.resource_id <> p_action_id OR
           challenge_row.resource_version <> p_action_version OR
           challenge_row.policy_id <> p_policy_id OR
           challenge_row.policy_version <> p_policy_version OR
           existing_reason.reason_id <> p_reason_id OR
           existing_reason.actor_id <> p_actor_id OR
           existing_reason.operation <> 'revoke' OR
           existing_reason.reason_code <> p_reason_code OR
           existing_reason.normalized_reason <> p_reason_text OR
           existing_reason.reason_jcs <> p_reason_jcs OR
           existing_reason.reason_digest <> p_reason_digest OR
           p_reason_jcs <> expected_reason_jcs OR
           p_reason_digest <> sentinelflow.hil_sha256(expected_reason_jcs) OR
           existing_auth.authorization_id IS NULL OR
           existing_auth.authorization_id <> p_authorization_id OR
           existing_auth.authorization_kind <> 'revoke' OR
           existing_auth.action_id <> p_action_id OR
           existing_auth.policy_id <> p_policy_id OR
           existing_auth.policy_version <> p_policy_version OR
           existing_auth.approval_decision_id <> p_decision_id OR
           existing_auth.decision <> 'revoke' OR
           existing_auth.target_ipv4 <> action_row.target_ipv4 OR
           existing_auth.policy_digest <> policy_row.policy_digest OR
           existing_auth.generated_artifact_digest <> expected_artifact_digest OR
           existing_auth.canonical_artifact_digest <> expected_artifact_digest OR
           existing_auth.original_add_digest <> action_row.canonical_artifact_digest OR
           existing_auth.evidence_snapshot_digest <> action_row.evidence_snapshot_digest OR
           existing_auth.validation_snapshot_digest <> validation_row.snapshot_digest OR
           existing_auth.actor_id <> p_actor_id OR
           existing_auth.hil_reason_digest <> p_reason_digest OR
           existing_auth.decision_nonce_digest <> p_nonce_digest OR
           existing_auth.idempotency_key_digest <> p_idempotency_key_digest OR
           existing_auth.decided_at <> p_decided_at OR
           existing_auth.valid_until <> p_decision_valid_until OR
           existing_auth.authorization_jcs <> p_authorization_jcs OR
           existing_auth.authorization_digest <> p_authorization_digest OR
           p_authorization_jcs <> expected_authorization_jcs OR
           p_authorization_digest <> sentinelflow.hil_sha256(expected_authorization_jcs) OR
           existing_revoke.revocation_id IS NULL OR
           existing_revoke.revocation_id <> p_revocation_id OR
           existing_revoke.action_id <> p_action_id OR
           existing_revoke.action_version <> p_action_version OR
           existing_revoke.authorization_id <> p_authorization_id OR
           existing_revoke.approval_decision_id <> p_decision_id OR
           existing_revoke.actor_id <> p_actor_id OR
           existing_revoke.reason_id <> p_reason_id OR
           existing_revoke.reason_digest <> p_reason_digest OR
           existing_revoke.target_ipv4 <> action_row.target_ipv4 OR
           existing_revoke.original_add_digest <> action_row.canonical_artifact_digest OR
           existing_revoke.artifact <> p_artifact OR
           existing_revoke.artifact_digest <> p_artifact_digest OR
           p_artifact <> expected_artifact OR p_artifact_digest <> expected_artifact_digest OR
           existing_job.job_id IS NULL OR existing_job.job_id <> p_outbox_job_id OR
           existing_job.kind <> 'dispatch_revoke' OR
           existing_job.aggregate_type <> 'enforcement_action' OR
           existing_job.aggregate_id <> p_action_id OR
           existing_job.aggregate_version <> p_action_version OR
           existing_job.operation <> 'revoke' OR
           existing_job.idempotency_key <> p_authorization_digest OR
           existing_dispatch.job_id IS NULL OR existing_dispatch.operation <> 'revoke' OR
           existing_dispatch.action_id <> p_action_id OR
           existing_dispatch.policy_id <> p_policy_id OR
           existing_dispatch.policy_version <> p_policy_version OR
           existing_dispatch.target_ipv4 <> action_row.target_ipv4 OR
           existing_dispatch.artifact <> p_artifact OR
           existing_dispatch.artifact_digest <> p_artifact_digest OR
           existing_dispatch.original_add_digest <> action_row.canonical_artifact_digest OR
           existing_dispatch.evidence_snapshot_digest <> action_row.evidence_snapshot_digest OR
           existing_dispatch.validation_snapshot_id <> validation_row.validation_snapshot_id OR
           existing_dispatch.validation_snapshot_digest <> validation_row.snapshot_digest OR
           existing_dispatch.enforcement_authorization_id <> p_authorization_id OR
           existing_dispatch.inspection_authorization_id IS NOT NULL OR
           existing_dispatch.authorization_digest <> p_authorization_digest OR
           existing_dispatch.actor_id <> p_actor_id OR
           existing_dispatch.reason_digest <> p_reason_digest OR
           existing_dispatch.owned_schema_digest <> validation_row.live_owned_schema_digest OR
           existing_dispatch.not_before <> p_decided_at OR
           existing_dispatch.valid_until <> p_decision_valid_until OR
           existing_audit.event_id IS NULL OR existing_audit.event_id <> p_audit_event_id OR
           existing_audit.actor_type <> 'administrator' OR
           existing_audit.actor_id <> p_actor_id OR
           existing_audit.action <> 'enforcement_revoke_authorized' OR
           existing_audit.object_type <> 'revocation' OR
           existing_audit.object_id <> p_revocation_id OR
           existing_audit.policy_id <> p_policy_id OR
           existing_audit.policy_version <> p_policy_version OR
           existing_audit.enforcement_action_id <> p_action_id OR
           existing_audit.primary_digest <> p_decision_digest OR
           existing_audit.secondary_digest <> p_authorization_digest OR
           existing_audit.outcome <> 'accepted' THEN
            RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
        END IF;
        rotated := sentinelflow.commit_privileged_session_rotation(
            true, existing_decision.decision_id, p_challenge_id,
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
        IF rotated THEN RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict'; END IF;
        RETURN QUERY SELECT existing_decision.decision_id::text,
            existing_revoke.revocation_id::text, existing_auth.authorization_id::text,
            existing_auth.authorization_digest::text, existing_job.job_id::text,
            true, false;
        RETURN;
    END IF;

    IF session_row.actor_id <> p_actor_id OR session_row.token_digest <> p_session_digest OR
       session_row.csrf_digest <> p_csrf_digest OR
       session_row.authenticated_at <> p_authenticated_at OR
       session_row.expires_at <> p_session_expires_at OR
       session_row.revoked_at IS NOT NULL OR session_row.expires_at <= server_now OR
       session_row.last_seen_at + interval '30 minutes' <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF002', MESSAGE = 'authentication_invalid';
    END IF;
    IF server_now > session_row.authenticated_at + interval '15 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = 'SF003', MESSAGE = 'step_up_required';
    END IF;
    IF action_row.version <> p_action_version OR
       action_row.policy_id <> p_policy_id OR action_row.policy_version <> p_policy_version OR
       action_row.state <> 'active' OR
       action_row.expected_expires_at IS NULL OR action_row.expected_expires_at <= server_now OR
       policy_row.policy_id IS NULL OR validation_row.policy_id <> action_row.policy_id OR
       validation_row.policy_version <> action_row.policy_version OR
       validation_row.snapshot_digest <> challenge_row.validation_snapshot_digest OR
       validation_row.evidence_snapshot_digest <> action_row.evidence_snapshot_digest OR
       validation_row.canonical_artifact_digest <> action_row.canonical_artifact_digest OR
       policy_row.policy_digest <> challenge_row.policy_digest THEN
        RAISE EXCEPTION USING ERRCODE = 'SF005', MESSAGE = 'validation_stale';
    END IF;
    IF challenge_row.session_id <> p_session_id OR challenge_row.session_digest <> p_session_digest OR
       challenge_row.actor_id <> p_actor_id OR challenge_row.operation <> 'revoke' OR
       challenge_row.resource_type <> 'enforcement_action' OR
       challenge_row.resource_id <> p_action_id OR
       challenge_row.resource_version <> p_action_version OR
       challenge_row.action_id <> p_action_id OR
       challenge_row.idempotency_key_digest <> p_idempotency_key_digest OR
       challenge_row.nonce_digest <> p_nonce_digest OR
       challenge_row.challenge_jcs <> p_challenge_jcs OR
       challenge_row.challenge_digest <> p_challenge_digest OR
       challenge_row.original_add_digest <> action_row.canonical_artifact_digest OR
       challenge_row.generated_artifact_digest <> expected_artifact_digest OR
       challenge_row.canonical_artifact_digest <> expected_artifact_digest OR
       challenge_row.validation_valid_until > action_row.expected_expires_at OR
       challenge_row.validation_valid_until > session_row.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    IF challenge_row.consumed_at IS NOT NULL OR challenge_row.expires_at <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006', MESSAGE = 'challenge_expired';
    END IF;
    IF p_artifact <> expected_artifact OR p_artifact_digest <> expected_artifact_digest OR
       p_decided_at > server_now OR p_decided_at < server_now - interval '2 seconds' OR
       p_decided_at < challenge_row.issued_at OR p_decision_valid_until <= server_now OR
       p_decision_valid_until > p_decided_at + interval '5 minutes' OR
       p_decision_valid_until > challenge_row.expires_at OR
       p_decision_valid_until > challenge_row.validation_valid_until OR
       p_decision_valid_until > session_row.expires_at OR
       p_decision_valid_until > action_row.expected_expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006', MESSAGE = 'challenge_expired';
    END IF;

    expected_reason_jcs := sentinelflow.hil_reason_jcs(p_reason_code, p_reason_text);
    IF p_reason_jcs <> expected_reason_jcs OR
       p_reason_digest <> sentinelflow.hil_sha256(expected_reason_jcs) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    expected_decision_jcs := sentinelflow.revocation_decision_jcs_000027(
        p_actor_id, expected_artifact_digest, p_challenge_id, p_decided_at,
        p_decision_id, p_decision_valid_until, action_row.evidence_snapshot_digest,
        p_idempotency_key_digest, p_nonce_digest, action_row.canonical_artifact_digest,
        policy_row.policy_digest, p_reason_digest, p_action_id, p_action_version,
        p_session_digest, action_row.target_ipv4, validation_row.snapshot_digest
    );
    IF p_decision_jcs <> expected_decision_jcs OR
       p_decision_digest <> sentinelflow.hil_sha256(expected_decision_jcs) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    expected_authorization_jcs := sentinelflow.revocation_authorization_jcs_000027(
        p_action_id, p_actor_id, p_authorization_id, expected_artifact_digest,
        p_decided_at, p_nonce_digest, action_row.evidence_snapshot_digest,
        p_reason_digest, p_idempotency_key_digest, action_row.canonical_artifact_digest,
        policy_row.policy_digest, action_row.policy_id, action_row.policy_version, action_row.target_ipv4,
        p_decision_valid_until
    );
    IF p_authorization_jcs <> expected_authorization_jcs OR
       p_authorization_digest <> sentinelflow.hil_sha256(expected_authorization_jcs) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;

    -- Serialize against inspect capability issuance. A capability without its
    -- terminal result is an in-flight observation and requires a retry.
    FOR schedule_row IN
        SELECT schedule.*
        FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
        WHERE schedule.action_id = p_action_id
          AND schedule.state IN ('pending', 'retry', 'leased', 'dispatched')
        ORDER BY schedule.dispatch_job_id
        FOR UPDATE
    LOOP
        PERFORM pg_advisory_xact_lock(hashtextextended(
            'sentinelflow.lifecycle-capability:' || schedule_row.dispatch_job_id::text, 0
        ));
        IF EXISTS (
            SELECT 1 FROM sentinelflow.execution_capabilities capability
            LEFT JOIN sentinelflow.execution_results result
              ON result.capability_id = capability.capability_id
            WHERE capability.job_id = schedule_row.dispatch_job_id
              AND result.result_id IS NULL
        ) OR EXISTS (
            SELECT 1 FROM sentinelflow.execution_capabilities capability
            WHERE capability.job_id = schedule_row.dispatch_job_id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
        END IF;
        UPDATE sentinelflow.outbox_jobs job
        SET state = 'dead', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = 'revoke_superseded',
            last_error_digest = p_decision_digest, updated_at = server_now
        WHERE job.job_id = schedule_row.dispatch_job_id
          AND job.state IN ('pending', 'retry', 'leased');
        IF NOT FOUND AND EXISTS (
            SELECT 1 FROM sentinelflow.outbox_jobs job
            WHERE job.job_id = schedule_row.dispatch_job_id AND job.state <> 'dead'
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
        END IF;
        UPDATE sentinelflow.lifecycle_inspection_schedules_000026 schedule
        SET state = 'dead', scheduler_id = NULL, lease_owner = NULL,
            lease_token = NULL, leased_at = NULL, lease_expires_at = NULL,
            authorization_requested_at = NULL, authorization_valid_until = NULL,
            last_error_code = 'revoke_superseded',
            last_error_digest = p_decision_digest, updated_at = server_now
        WHERE schedule.schedule_id = schedule_row.schedule_id;
    END LOOP;

    INSERT INTO sentinelflow.hil_reasons (
        reason_id, schema_version, actor_id, operation, reason_code,
        normalized_reason, reason_jcs, reason_digest, created_at
    ) VALUES (
        p_reason_id, 'hil-reason-v1', p_actor_id, 'revoke', p_reason_code,
        p_reason_text, p_reason_jcs, p_reason_digest, p_decided_at
    ) ON CONFLICT (actor_id, operation, reason_digest) DO NOTHING;
    SELECT * INTO existing_reason FROM sentinelflow.hil_reasons reason
    WHERE reason.actor_id = p_actor_id AND reason.operation = 'revoke'
      AND reason.reason_digest = p_reason_digest;
    IF existing_reason.reason_id IS NULL OR existing_reason.reason_id <> p_reason_id OR
       existing_reason.reason_code <> p_reason_code OR
       existing_reason.normalized_reason <> p_reason_text OR
       existing_reason.reason_jcs <> p_reason_jcs THEN
        RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict';
    END IF;
    effective_reason_id := existing_reason.reason_id;

    INSERT INTO sentinelflow.approval_decisions (
        decision_id, schema_version, challenge_id, session_digest, operation,
        decision, resource_type, resource_id, resource_version, policy_id,
        policy_version, action_id, target_ipv4, validation_snapshot_id,
        policy_digest, evidence_snapshot_digest, generated_artifact_digest,
        canonical_artifact_digest, original_add_digest,
        validation_snapshot_digest, actor_id, reason_id, reason_digest,
        challenge_nonce_digest, idempotency_key_digest, decided_at,
        decision_valid_until, decision_jcs, decision_digest
    ) VALUES (
        p_decision_id, 'hil-decision-v1', p_challenge_id, p_session_digest,
        'revoke', 'revoked', 'enforcement_action', p_action_id,
        p_action_version, action_row.policy_id, action_row.policy_version,
        p_action_id, action_row.target_ipv4, validation_row.validation_snapshot_id,
        policy_row.policy_digest, action_row.evidence_snapshot_digest,
        expected_artifact_digest, expected_artifact_digest,
        action_row.canonical_artifact_digest, validation_row.snapshot_digest,
        p_actor_id, effective_reason_id, p_reason_digest, p_nonce_digest,
        p_idempotency_key_digest, p_decided_at, p_decision_valid_until,
        p_decision_jcs, p_decision_digest
    );
    UPDATE sentinelflow.decision_challenges challenge
    SET consumed_at = server_now, consumed_decision_id = p_decision_id
    WHERE challenge.challenge_id = p_challenge_id AND challenge.consumed_at IS NULL;
    GET DIAGNOSTICS changed_count = ROW_COUNT;
    IF changed_count <> 1 THEN RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict'; END IF;

    INSERT INTO sentinelflow.enforcement_authorizations (
        authorization_id, schema_version, authorization_kind, action_id,
        policy_id, policy_version, approval_decision_id, decision, target_ipv4,
        policy_digest, generated_artifact_digest, canonical_artifact_digest,
        original_add_digest, evidence_snapshot_digest, validation_snapshot_digest,
        actor_id, hil_reason_digest, decision_nonce_digest,
        idempotency_key_digest, authorization_jcs, authorization_digest,
        decided_at, valid_until
    ) VALUES (
        p_authorization_id, 'enforcement-authorization-v1', 'revoke', p_action_id,
        action_row.policy_id, action_row.policy_version, p_decision_id, 'revoke',
        action_row.target_ipv4, policy_row.policy_digest, expected_artifact_digest,
        expected_artifact_digest, action_row.canonical_artifact_digest,
        action_row.evidence_snapshot_digest, validation_row.snapshot_digest,
        p_actor_id, p_reason_digest, p_nonce_digest, p_idempotency_key_digest,
        p_authorization_jcs, p_authorization_digest, p_decided_at,
        p_decision_valid_until
    );
    INSERT INTO sentinelflow.revocation_operations (
        revocation_id, schema_version, action_id, action_version,
        authorization_id, approval_decision_id, actor_id, reason_id,
        reason_digest, target_ipv4, original_add_digest, artifact,
        artifact_digest, state, created_at
    ) VALUES (
        p_revocation_id, 'nft-revoke-v1', p_action_id, p_action_version,
        p_authorization_id, p_decision_id, p_actor_id, effective_reason_id,
        p_reason_digest, action_row.target_ipv4, action_row.canonical_artifact_digest,
        expected_artifact, expected_artifact_digest, 'authorized', server_now
    );
    INSERT INTO sentinelflow.outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        operation, idempotency_key, state, available_at, max_attempts,
        created_at, updated_at
    ) VALUES (
        p_outbox_job_id, 'dispatch_revoke', 'enforcement_action', p_action_id,
        p_action_version, 'revoke', p_authorization_digest, 'pending',
        server_now, 8, server_now, server_now
    );
    INSERT INTO sentinelflow.dispatch_operations (
        job_id, operation, action_id, policy_id, policy_version, target_ipv4,
        artifact, artifact_digest, original_add_digest, evidence_snapshot_digest,
        validation_snapshot_id, validation_snapshot_digest,
        enforcement_authorization_id, inspection_authorization_id,
        authorization_digest, actor_id, reason_digest, owned_schema_digest,
        not_before, valid_until, created_at
    ) VALUES (
        p_outbox_job_id, 'revoke', p_action_id, action_row.policy_id,
        action_row.policy_version, action_row.target_ipv4, expected_artifact,
        expected_artifact_digest, action_row.canonical_artifact_digest,
        action_row.evidence_snapshot_digest, validation_row.validation_snapshot_id,
        validation_row.snapshot_digest, p_authorization_id, NULL,
        p_authorization_digest, p_actor_id, p_reason_digest,
        validation_row.live_owned_schema_digest, p_decided_at,
        p_decision_valid_until, server_now
    );
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        policy_id, policy_version, enforcement_action_id, primary_digest,
        secondary_digest, outcome, occurred_at
    ) VALUES (
        p_audit_event_id, 'administrator', p_actor_id,
        'enforcement_revoke_authorized', 'revocation', p_revocation_id,
        action_row.policy_id, action_row.policy_version, p_action_id,
        p_decision_digest, p_authorization_digest, 'accepted', server_now
    );

    rotated := sentinelflow.commit_privileged_session_rotation(
        false, p_decision_id, p_challenge_id, p_idempotency_key_digest,
        p_session_id, p_actor_id, p_session_digest, p_csrf_digest,
        p_authenticated_at, p_expected_created_at, p_expected_last_seen_at,
        p_session_expires_at, p_expected_rotation_parent_id, p_rotation_at,
        p_replacement_session_id, p_replacement_actor_id,
        p_replacement_token_digest, p_replacement_csrf_digest,
        p_replacement_authenticated_at, p_replacement_created_at,
        p_replacement_last_seen_at, p_replacement_expires_at,
        p_replacement_rotation_parent_id
    );
    IF NOT rotated THEN RAISE EXCEPTION USING ERRCODE = 'SF008', MESSAGE = 'conflict'; END IF;
    RETURN QUERY SELECT p_decision_id::text, p_revocation_id::text,
        p_authorization_id::text, p_authorization_digest::text,
        p_outbox_job_id::text, false, true;
END
$function$;

-- Extend the immutable dispatcher evidence boundary with the revoke operation
-- lifecycle. The delegated 000026 functions retain signature and cryptographic
-- verification ownership.
ALTER FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) RENAME TO record_execution_capability_pre_000027;

CREATE FUNCTION sentinelflow.record_execution_capability(
    p_capability_id uuid, p_job_id uuid, p_lease_token uuid,
    p_operation text, p_action_id uuid, p_policy_id uuid,
    p_policy_version integer, p_target_ipv4 sentinelflow.canonical_ipv4,
    p_artifact bytea, p_artifact_digest sentinelflow.sha256_digest,
    p_original_add_digest sentinelflow.sha256_digest,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_validation_snapshot_digest sentinelflow.sha256_digest,
    p_authorization_digest sentinelflow.sha256_digest,
    p_actor_id sentinelflow.ascii_id, p_reason_digest sentinelflow.sha256_digest,
    p_owned_schema_digest sentinelflow.sha256_digest, p_capability_jcs bytea,
    p_capability_digest sentinelflow.sha256_digest, p_capability_signature bytea,
    p_nonce_digest sentinelflow.sha256_digest, p_issued_at timestamptz,
    p_not_before timestamptz, p_expires_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    revoke sentinelflow.revocation_operations%ROWTYPE;
    action sentinelflow.enforcement_actions%ROWTYPE;
    operation sentinelflow.dispatch_operations%ROWTYPE;
BEGIN
    PERFORM sentinelflow.record_execution_capability_pre_000027(
        p_capability_id, p_job_id, p_lease_token, p_operation, p_action_id,
        p_policy_id, p_policy_version, p_target_ipv4, p_artifact,
        p_artifact_digest, p_original_add_digest, p_evidence_snapshot_digest,
        p_validation_snapshot_digest, p_authorization_digest, p_actor_id,
        p_reason_digest, p_owned_schema_digest, p_capability_jcs,
        p_capability_digest, p_capability_signature, p_nonce_digest,
        p_issued_at, p_not_before, p_expires_at
    );
    IF p_operation <> 'revoke' THEN RETURN; END IF;
    SELECT * INTO operation FROM sentinelflow.dispatch_operations current_operation
    WHERE current_operation.job_id = p_job_id;
    SELECT * INTO revoke FROM sentinelflow.revocation_operations current_revoke
    WHERE current_revoke.authorization_id = operation.enforcement_authorization_id FOR UPDATE;
    SELECT * INTO action FROM sentinelflow.enforcement_actions current_action
    WHERE current_action.action_id = p_action_id FOR UPDATE;
    IF revoke.revocation_id IS NULL OR action.action_id IS NULL OR
       revoke.action_id <> p_action_id OR revoke.action_version <> action.version OR
       revoke.artifact <> p_artifact OR revoke.artifact_digest <> p_artifact_digest OR
       revoke.original_add_digest <> p_original_add_digest OR
       action.state <> 'active' OR action.expected_expires_at IS NULL OR
       action.expected_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'revoke capability has no fresh exact revocation operation';
    END IF;
    IF revoke.state = 'authorized' THEN
        UPDATE sentinelflow.revocation_operations current_revoke
        SET state = 'queued'
        WHERE current_revoke.revocation_id = revoke.revocation_id;
    ELSIF revoke.state <> 'queued' THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'revoke capability cannot queue terminal revocation';
    END IF;
END
$function$;

ALTER FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) RENAME TO record_execution_result_pre_000027;

CREATE FUNCTION sentinelflow.record_execution_result(
    p_result_id uuid, p_job_id uuid, p_lease_token uuid, p_capability_id uuid,
    p_capability_digest sentinelflow.sha256_digest, p_operation text,
    p_action_id uuid, p_artifact_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4, p_classification text,
    p_nft_exit_class text, p_readback_state text, p_element_handle bigint,
    p_remaining_ttl_seconds integer, p_owned_schema_digest sentinelflow.sha256_digest,
    p_started_at timestamptz, p_completed_at timestamptz,
    p_journal_sequence bigint, p_error_code text, p_result_jcs bytea,
    p_result_digest sentinelflow.sha256_digest, p_result_signature bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    operation sentinelflow.dispatch_operations%ROWTYPE;
    revoke sentinelflow.revocation_operations%ROWTYPE;
    current_action sentinelflow.enforcement_actions%ROWTYPE;
    source_schedule sentinelflow.lifecycle_inspection_schedules_000026%ROWTYPE;
    persisted_result sentinelflow.execution_results%ROWTYPE;
    expected_state text;
BEGIN
    IF p_operation = 'inspect' THEN
        -- A persisted result_id is replay evidence, not new authority. Let the
        -- delegated 000026 function perform its complete byte-exact check even
        -- after a later lifecycle version exists.
        SELECT * INTO persisted_result
        FROM sentinelflow.execution_results result
        WHERE result.result_id = p_result_id;
        IF FOUND THEN
            PERFORM sentinelflow.record_execution_result_pre_000027(
                p_result_id, p_job_id, p_lease_token, p_capability_id,
                p_capability_digest, p_operation, p_action_id, p_artifact_digest,
                p_target_ipv4, p_classification, p_nft_exit_class, p_readback_state,
                p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
                p_started_at, p_completed_at, p_journal_sequence, p_error_code,
                p_result_jcs, p_result_digest, p_result_signature
            );
            RETURN;
        END IF;

        -- Fresh inspect results share the action -> schedule lock order with
        -- revoke commit. A schedule authorized for vN cannot reinterpret a
        -- vN+1 action or resurrect a later terminal/indeterminate state.
        SELECT * INTO current_action
        FROM sentinelflow.enforcement_actions action
        WHERE action.action_id = p_action_id
        FOR UPDATE;
        SELECT * INTO source_schedule
        FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
        WHERE schedule.dispatch_job_id = p_job_id
        FOR UPDATE;
        IF current_action.action_id IS NULL OR source_schedule.schedule_id IS NULL OR
           source_schedule.state <> 'dispatched' OR
           source_schedule.action_id <> p_action_id OR
           source_schedule.action_version <> current_action.version OR
           current_action.state NOT IN ('active', 'indeterminate') THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'stale inspection result cannot cross action version';
        END IF;
    END IF;

    PERFORM sentinelflow.record_execution_result_pre_000027(
        p_result_id, p_job_id, p_lease_token, p_capability_id,
        p_capability_digest, p_operation, p_action_id, p_artifact_digest,
        p_target_ipv4, p_classification, p_nft_exit_class, p_readback_state,
        p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
        p_started_at, p_completed_at, p_journal_sequence, p_error_code,
        p_result_jcs, p_result_digest, p_result_signature
    );
    IF p_operation <> 'revoke' THEN RETURN; END IF;
    expected_state := CASE p_classification
        WHEN 'revoked' THEN 'revoked'
        WHEN 'failed' THEN 'failed'
        WHEN 'indeterminate' THEN 'indeterminate'
        ELSE NULL
    END;
    IF expected_state IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid revoke result';
    END IF;
    SELECT * INTO operation FROM sentinelflow.dispatch_operations current_operation
    WHERE current_operation.job_id = p_job_id;
    SELECT * INTO revoke FROM sentinelflow.revocation_operations current_revoke
    WHERE current_revoke.authorization_id = operation.enforcement_authorization_id FOR UPDATE;
    IF revoke.revocation_id IS NULL OR revoke.action_id <> p_action_id OR
       revoke.artifact_digest <> p_artifact_digest THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'revoke result binding failed';
    END IF;
    IF revoke.state = 'queued' THEN
        UPDATE sentinelflow.revocation_operations current_revoke
        SET state = expected_state, completed_at = p_completed_at
        WHERE current_revoke.revocation_id = revoke.revocation_id;
    ELSIF revoke.state <> expected_state OR revoke.completed_at <> p_completed_at THEN
        RAISE EXCEPTION USING ERRCODE = '23505',
            MESSAGE = 'conflicting revocation result replay';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION sentinelflow.revocation_artifact_000027(
    sentinelflow.canonical_ipv4
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.lifecycle_rfc3339_000027(timestamptz)
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
         sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.revocation_challenge_jcs_000027(
    timestamptz, sentinelflow.sha256_digest, uuid,
    sentinelflow.sha256_digest, timestamptz, timestamptz,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, uuid, integer, sentinelflow.sha256_digest,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.revocation_decision_jcs_000027(
    sentinelflow.ascii_id, sentinelflow.sha256_digest, uuid, timestamptz,
    uuid, timestamptz, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, uuid, integer, sentinelflow.sha256_digest,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.revocation_authorization_jcs_000027(
    uuid, sentinelflow.ascii_id, uuid, sentinelflow.sha256_digest,
    timestamptz, sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, uuid, integer,
    sentinelflow.canonical_ipv4, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.require_revocation_operation_match_000027()
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
     sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.issue_hil_revocation_challenge_000027(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    timestamptz, timestamptz, sentinelflow.sha256_digest, uuid, integer,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.commit_hil_revocation_with_session_rotation_000027(
    uuid, sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, uuid, bytea,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, uuid, integer, uuid, integer, bytea,
    sentinelflow.sha256_digest, uuid, text, text, bytea,
    sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, bytea,
    sentinelflow.sha256_digest, uuid, bytea, sentinelflow.sha256_digest,
    uuid, uuid, uuid, timestamptz, timestamptz, uuid, timestamptz, uuid,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz,
    timestamptz, uuid
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_capability_pre_000027(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result_pre_000027(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;

GRANT EXECUTE ON FUNCTION sentinelflow.issue_hil_revocation_challenge_000027(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    timestamptz, timestamptz, sentinelflow.sha256_digest, uuid, integer,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest
) TO sentinelflow_api;
GRANT EXECUTE ON FUNCTION sentinelflow.commit_hil_revocation_with_session_rotation_000027(
    uuid, sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, uuid, bytea,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, uuid, integer, uuid, integer, bytea,
    sentinelflow.sha256_digest, uuid, text, text, bytea,
    sentinelflow.sha256_digest, uuid, timestamptz, timestamptz, bytea,
    sentinelflow.sha256_digest, uuid, bytea, sentinelflow.sha256_digest,
    uuid, uuid, uuid, timestamptz, timestamptz, uuid, timestamptz, uuid,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz,
    timestamptz, uuid
) TO sentinelflow_api;
GRANT EXECUTE ON FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) TO sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) TO sentinelflow_dispatcher;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (27, 'revocation_hil');

COMMIT;
