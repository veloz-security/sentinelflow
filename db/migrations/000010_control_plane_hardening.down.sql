BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Canonical HIL evidence is not derivable from the pre-000010 scalar schema.
-- Downgrade is therefore supported only before any 000010 HIL row exists.
DO $control_plane_downgrade_preflight$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'sentinelflow'
          AND table_name = 'decision_challenges'
          AND column_name = 'challenge_jcs'
    ) AND (
        EXISTS (SELECT 1 FROM sentinelflow.decision_challenges) OR
        EXISTS (SELECT 1 FROM sentinelflow.hil_reasons) OR
        EXISTS (SELECT 1 FROM sentinelflow.approval_decisions) OR
        EXISTS (SELECT 1 FROM sentinelflow.enforcement_authorizations) OR
        EXISTS (SELECT 1 FROM sentinelflow.execution_capabilities) OR
        EXISTS (SELECT 1 FROM sentinelflow.execution_results)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot discard canonical HIL or hardened execution evidence during downgrade';
    END IF;
END
$control_plane_downgrade_preflight$;

DROP FUNCTION IF EXISTS sentinelflow.commit_hil_policy_decision(
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
);
DROP FUNCTION IF EXISTS sentinelflow.issue_hil_policy_challenge(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, timestamptz,
    timestamptz, text, uuid, integer, sentinelflow.canonical_ipv4,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    text, bytea, timestamptz, timestamptz, integer
);
DROP FUNCTION IF EXISTS sentinelflow.hil_authorization_jcs(
    uuid, sentinelflow.ascii_id, uuid, sentinelflow.sha256_digest,
    timestamptz, sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, uuid, integer,
    sentinelflow.canonical_ipv4, timestamptz
);
DROP FUNCTION IF EXISTS sentinelflow.hil_decision_jcs(
    sentinelflow.ascii_id, sentinelflow.sha256_digest, uuid, timestamptz,
    text, uuid, timestamptz, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, text, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, uuid, integer, sentinelflow.sha256_digest,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest
);
DROP FUNCTION IF EXISTS sentinelflow.hil_reason_jcs(text, text);
DROP FUNCTION IF EXISTS sentinelflow.hil_challenge_jcs(
    timestamptz, sentinelflow.sha256_digest, uuid,
    sentinelflow.sha256_digest, timestamptz, sentinelflow.sha256_digest,
    timestamptz, sentinelflow.sha256_digest, text,
    sentinelflow.sha256_digest, uuid, integer,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4,
    sentinelflow.sha256_digest, timestamptz
);
DROP FUNCTION IF EXISTS sentinelflow.hil_rfc3339(timestamptz);
DROP FUNCTION IF EXISTS sentinelflow.hil_jcs_string(text);
DROP FUNCTION IF EXISTS sentinelflow.hil_sha256(bytea);

ALTER TABLE sentinelflow.execution_results
    DROP CONSTRAINT IF EXISTS execution_result_list_set_has_no_handle;
ALTER TABLE sentinelflow.enforcement_actions
    DROP CONSTRAINT IF EXISTS enforcement_action_list_set_has_no_handle;
ALTER TABLE sentinelflow.decision_challenges
    DROP CONSTRAINT IF EXISTS decision_challenge_jcs_evidence,
    DROP COLUMN IF EXISTS challenge_jcs,
    DROP COLUMN IF EXISTS challenge_digest;
ALTER TABLE sentinelflow.hil_reasons
    DROP CONSTRAINT IF EXISTS hil_reason_jcs_evidence,
    DROP COLUMN IF EXISTS reason_code,
    DROP COLUMN IF EXISTS reason_jcs;
ALTER TABLE sentinelflow.approval_decisions
    DROP CONSTRAINT IF EXISTS approval_decision_jcs_evidence,
    DROP COLUMN IF EXISTS decision_jcs,
    DROP COLUMN IF EXISTS decision_digest;
ALTER TABLE sentinelflow.enforcement_authorizations
    DROP CONSTRAINT IF EXISTS enforcement_authorization_jcs_evidence,
    DROP COLUMN IF EXISTS authorization_jcs;

-- Restore the pre-000010 dispatcher view and mutation functions exactly. The
-- downgrade deliberately re-establishes the former behavior, including the
-- absence of expired-lease reclamation and post-expiry recovery attestation.
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
  AND job.state IN ('pending', 'retry')
  AND job.available_at <= clock_timestamp()
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
    p_job_id uuid, p_lease_token uuid, p_lease_owner sentinelflow.ascii_id,
    p_lease_until timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE claimed boolean;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL OR p_lease_owner IS NULL OR
       p_lease_until IS NULL OR p_lease_until <= clock_timestamp() OR
       p_lease_until > clock_timestamp() + interval '60 seconds' THEN
        RETURN false;
    END IF;
    UPDATE sentinelflow.outbox_jobs job
    SET state = 'leased', lease_token = p_lease_token,
        lease_owner = p_lease_owner, lease_expires_at = p_lease_until,
        attempts = attempts + 1, updated_at = clock_timestamp()
    WHERE job.job_id = p_job_id
      AND job.job_id IN (
          SELECT approved.job_id FROM sentinelflow.dispatcher_approved_outbox approved
      )
    RETURNING true INTO claimed;
    RETURN coalesce(claimed, false);
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.record_execution_result(
    p_result_id uuid, p_job_id uuid, p_lease_token uuid, p_capability_id uuid,
    p_capability_digest sentinelflow.sha256_digest, p_operation text,
    p_action_id uuid, p_artifact_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4, p_classification text,
    p_nft_exit_class text, p_readback_state text, p_element_handle bigint,
    p_remaining_ttl_seconds integer,
    p_owned_schema_digest sentinelflow.sha256_digest,
    p_started_at timestamptz, p_completed_at timestamptz,
    p_journal_sequence bigint, p_error_code text, p_result_jcs bytea,
    p_result_digest sentinelflow.sha256_digest, p_result_signature bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.outbox_jobs job
        JOIN sentinelflow.execution_capabilities capability USING (job_id)
        WHERE job.job_id = p_job_id AND job.state = 'leased'
          AND job.lease_token = p_lease_token
          AND capability.capability_id = p_capability_id
          AND capability.capability_digest = p_capability_digest
          AND capability.operation = p_operation
          AND capability.action_id = p_action_id
          AND capability.artifact_digest = p_artifact_digest
          AND capability.target_ipv4 = p_target_ipv4
          AND capability.owned_schema_digest = p_owned_schema_digest
          AND capability.consumed_at IS NULL
          AND p_started_at >= capability.not_before
          AND p_started_at <= capability.expires_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501', MESSAGE = 'result does not match claimed capability';
    END IF;
    INSERT INTO sentinelflow.execution_results (
        result_id, schema_version, capability_id, capability_digest, operation,
        action_id, artifact_digest, target_ipv4, classification, nft_exit_class,
        readback_state, element_handle, remaining_ttl_seconds, owned_schema_digest,
        started_at, completed_at, journal_sequence, error_code, result_jcs,
        result_digest, result_signature
    ) VALUES (
        p_result_id, 'execution-result-v1', p_capability_id, p_capability_digest,
        p_operation, p_action_id, p_artifact_digest, p_target_ipv4,
        p_classification, p_nft_exit_class, p_readback_state, p_element_handle,
        p_remaining_ttl_seconds, p_owned_schema_digest, p_started_at,
        p_completed_at, p_journal_sequence, p_error_code, p_result_jcs,
        p_result_digest, p_result_signature
    );
    UPDATE sentinelflow.execution_capabilities
    SET consumed_at = p_completed_at
    WHERE capability_id = p_capability_id;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finish_dispatch_job(
    p_job_id uuid, p_lease_token uuid, p_outcome text,
    p_error_code sentinelflow.ascii_id,
    p_error_digest sentinelflow.sha256_digest,
    p_next_available_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE finished boolean;
BEGIN
    IF p_outcome NOT IN ('completed', 'retry', 'dead') THEN RETURN false; END IF;
    IF p_outcome = 'retry' AND
       (p_next_available_at IS NULL OR p_next_available_at < clock_timestamp()) THEN
        RETURN false;
    END IF;
    IF p_outcome IN ('retry', 'dead') AND
       (p_error_code IS NULL OR p_error_digest IS NULL) THEN RETURN false; END IF;
    IF p_outcome = 'completed' AND NOT EXISTS (
        SELECT 1 FROM sentinelflow.execution_results result
        JOIN sentinelflow.execution_capabilities capability USING (capability_id)
        WHERE capability.job_id = p_job_id
    ) THEN RETURN false; END IF;
    UPDATE sentinelflow.outbox_jobs job
    SET state = p_outcome,
        available_at = CASE WHEN p_outcome = 'retry'
            THEN p_next_available_at ELSE available_at END,
        lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
        last_error_code = CASE WHEN p_outcome = 'completed' THEN NULL ELSE p_error_code END,
        last_error_digest = CASE WHEN p_outcome = 'completed' THEN NULL ELSE p_error_digest END,
        updated_at = clock_timestamp()
    WHERE job.job_id = p_job_id AND job.state = 'leased'
      AND job.lease_token = p_lease_token
      AND (p_outcome <> 'retry' OR job.attempts < job.max_attempts)
    RETURNING true INTO finished;
    IF coalesce(finished, false) AND p_outcome = 'dead' THEN
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest
        ) SELECT job_id, kind, aggregate_type, aggregate_id, aggregate_version,
                 attempts, p_error_code, p_error_digest
          FROM sentinelflow.outbox_jobs WHERE job_id = p_job_id
        ON CONFLICT (job_id) DO NOTHING;
    END IF;
    RETURN coalesce(finished, false);
END
$function$;

-- Restore the direct grants present immediately before 000010.
GRANT SELECT, INSERT ON sentinelflow.decision_challenges TO sentinelflow_api;
GRANT UPDATE (consumed_at, consumed_decision_id)
    ON sentinelflow.decision_challenges TO sentinelflow_api;
GRANT SELECT, INSERT ON
    sentinelflow.hil_reasons,
    sentinelflow.approval_decisions,
    sentinelflow.enforcement_authorizations,
    sentinelflow.dispatch_operations
TO sentinelflow_api;
GRANT INSERT ON sentinelflow.enforcement_actions TO sentinelflow_api;
GRANT UPDATE (
    state, nft_element_handle, queued_at, applied_at, expected_expires_at,
    finished_at, version, updated_at
) ON sentinelflow.enforcement_actions TO sentinelflow_api;
GRANT SELECT, INSERT ON sentinelflow.outbox_jobs TO sentinelflow_api;

DELETE FROM sentinelflow.schema_migrations
WHERE version = 10 AND name = 'control_plane_hardening';

COMMIT;
