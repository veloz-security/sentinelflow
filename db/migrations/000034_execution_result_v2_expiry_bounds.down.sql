BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- A downgrade cannot truthfully project v2 bounds back into an exact v1
-- timestamp.  Refuse whenever any v2 result or bound is durable.
DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 34 AND name = 'execution_result_v2_expiry_bounds'
    ) OR to_regprocedure(
        'sentinelflow.record_execution_result_lifecycle_pre_000034(uuid,uuid,uuid,uuid,sentinelflow.sha256_digest,text,uuid,sentinelflow.sha256_digest,sentinelflow.canonical_ipv4,text,text,text,bigint,integer,sentinelflow.sha256_digest,timestamptz,timestamptz,bigint,text,bytea,sentinelflow.sha256_digest,bytea)'
    ) IS NULL OR to_regprocedure(
        'sentinelflow.record_execution_result_insert_pre_000034(uuid,uuid,uuid,uuid,sentinelflow.sha256_digest,text,uuid,sentinelflow.sha256_digest,sentinelflow.canonical_ipv4,text,text,text,bigint,integer,sentinelflow.sha256_digest,timestamptz,timestamptz,bigint,text,bytea,sentinelflow.sha256_digest,bytea)'
    ) IS NULL OR EXISTS (
        SELECT 1 FROM sentinelflow.execution_results WHERE schema_version = 'execution-result-v2'
    ) OR EXISTS (SELECT 1 FROM sentinelflow.execution_result_readback_bounds_000034) OR
       EXISTS (SELECT 1 FROM sentinelflow.enforcement_expiry_bounds_000034) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'execution-result v2 expiry-bounds downgrade is blocked by durable evidence';
    END IF;
END
$preflight$;

-- Restore the version-33 recovery definitions before removing the v2-only
-- bounds relation. The preflight above guarantees no v2 evidence can be
-- hidden by this rollback.
CREATE OR REPLACE VIEW sentinelflow.dispatcher_recovery_outbox_000025
WITH (security_barrier = true)
AS
SELECT job.job_id, job.kind, job.state, job.available_at, job.attempts,
       job.max_attempts, operation.operation, operation.action_id,
       operation.policy_id, operation.policy_version, operation.target_ipv4,
       operation.artifact, operation.artifact_digest, operation.original_add_digest,
       operation.evidence_snapshot_digest, operation.validation_snapshot_digest,
       operation.authorization_digest, operation.actor_id, operation.reason_digest,
       operation.owned_schema_digest, operation.not_before, operation.valid_until
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.dispatch_operations operation USING (job_id)
JOIN sentinelflow.execution_capabilities capability USING (job_id)
LEFT JOIN sentinelflow.execution_results result USING (capability_id)
LEFT JOIN sentinelflow.dead_letter_jobs dead_letter USING (job_id)
WHERE job.kind IN ('dispatch_add', 'dispatch_revoke', 'dispatch_inspect')
  AND job.kind = 'dispatch_' || operation.operation
  AND job.operation = operation.operation
  AND job.aggregate_type = 'enforcement_action'
  AND job.aggregate_id = operation.action_id
  AND (
      (job.state = 'retry' AND job.available_at <= clock_timestamp() AND
       job.last_error_code = 'recovery_started' AND
       job.available_at >= capability.expires_at AND
       dead_letter.resolution_state = 'requeued' AND
       isfinite(dead_letter.dead_at) AND
       isfinite(dead_letter.resolved_at) AND
       dead_letter.resolved_at <= clock_timestamp() AND
       dead_letter.resolved_at = job.updated_at AND
       dead_letter.resolution_actor = 'sentinelflow_recovery' AND
       dead_letter.job_id = job.job_id AND
       dead_letter.kind = job.kind AND
       dead_letter.aggregate_type = job.aggregate_type AND
       dead_letter.aggregate_id = job.aggregate_id AND
       dead_letter.aggregate_version = job.aggregate_version AND
       dead_letter.attempts = job.attempts AND
       dead_letter.dead_at <= dead_letter.resolved_at AND
       dead_letter.resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
           job.job_id, capability.capability_digest,
           dead_letter.failure_code, dead_letter.failure_digest
       ) AND
       job.last_error_digest = dead_letter.resolution_digest) OR
      (job.state = 'leased' AND job.lease_expires_at <= clock_timestamp() AND (
       (dead_letter.job_id IS NULL AND
        job.last_error_code IS NULL AND job.last_error_digest IS NULL AND (
          result.result_id IS NULL OR
          sentinelflow.dispatch_recovery_result_exact_000025(
              job.job_id, capability.capability_digest,
              job.aggregate_version, clock_timestamp()
          )
        )) OR
       (job.last_error_code = 'recovery_started' AND
        job.last_error_digest = dead_letter.resolution_digest AND
        job.available_at >= capability.expires_at AND
        dead_letter.resolution_state = 'requeued' AND
        isfinite(dead_letter.dead_at) AND
        isfinite(dead_letter.resolved_at) AND
        dead_letter.resolved_at <= clock_timestamp() AND
        dead_letter.resolution_actor = 'sentinelflow_recovery' AND
        dead_letter.job_id = job.job_id AND
        dead_letter.kind = job.kind AND
        dead_letter.aggregate_type = job.aggregate_type AND
        dead_letter.aggregate_id = job.aggregate_id AND
        dead_letter.attempts = job.attempts AND
        dead_letter.dead_at <= dead_letter.resolved_at AND
        dead_letter.resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
            job.job_id, capability.capability_digest,
            dead_letter.failure_code, dead_letter.failure_digest
        ) AND (
          (result.result_id IS NULL AND
           dead_letter.aggregate_version = job.aggregate_version) OR
          (result.result_id IS NOT NULL AND
           dead_letter.aggregate_version IN (
               job.aggregate_version, job.aggregate_version - 1
           ) AND sentinelflow.dispatch_recovery_result_exact_000025(
               job.job_id, capability.capability_digest,
               job.aggregate_version, clock_timestamp()
           ))
        ))
      )))
  AND capability.expires_at <= clock_timestamp()
  AND capability.schema_version = 'execution-capability-v1'
  AND capability.operation = operation.operation AND capability.action_id = operation.action_id
  AND capability.policy_id = operation.policy_id AND capability.policy_version = operation.policy_version
  AND capability.target_ipv4 = operation.target_ipv4 AND capability.artifact = operation.artifact
  AND capability.artifact_digest = operation.artifact_digest
  AND capability.original_add_digest IS NOT DISTINCT FROM operation.original_add_digest
  AND capability.evidence_snapshot_digest = operation.evidence_snapshot_digest
  AND capability.validation_snapshot_digest = operation.validation_snapshot_digest
  AND capability.authorization_digest = operation.authorization_digest
  AND capability.actor_id = operation.actor_id AND capability.reason_digest = operation.reason_digest
  AND capability.owned_schema_digest = operation.owned_schema_digest
  AND capability.artifact_digest =
      ('sha256:' || encode(sha256(capability.artifact), 'hex'))::sentinelflow.sha256_digest
  AND capability.capability_digest =
      ('sha256:' || encode(sha256(capability.capability_jcs), 'hex'))::sentinelflow.sha256_digest
  AND ((result.result_id IS NULL AND capability.consumed_at IS NULL) OR
       (result.result_id IS NOT NULL AND capability.consumed_at = result.completed_at AND
        result.schema_version = 'execution-result-v1' AND
        result.capability_digest = capability.capability_digest AND result.operation = capability.operation AND
        result.action_id = capability.action_id AND result.artifact_digest = capability.artifact_digest AND
        result.target_ipv4 = capability.target_ipv4 AND result.owned_schema_digest = capability.owned_schema_digest AND
        result.result_digest =
            ('sha256:' || encode(sha256(result.result_jcs), 'hex'))::sentinelflow.sha256_digest AND
        result.element_handle IS NULL));

CREATE OR REPLACE FUNCTION sentinelflow.recover_dispatch_execution(
    p_job_id uuid, p_lease_token uuid
)
RETURNS TABLE (
    recovery_state text, capability_id uuid, capability_jcs bytea,
    capability_digest sentinelflow.sha256_digest, capability_signature bytea,
    capability_artifact bytea, result_id uuid, result_jcs bytea,
    result_digest sentinelflow.sha256_digest, result_signature bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    job_row sentinelflow.outbox_jobs%ROWTYPE;
    operation_row sentinelflow.dispatch_operations%ROWTYPE;
    capability_row sentinelflow.execution_capabilities%ROWTYPE;
    result_row sentinelflow.execution_results%ROWTYPE;
    server_now timestamptz;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'SF101', MESSAGE = 'lease_lost';
    END IF;
    SELECT current_job.* INTO job_row FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'SF101', MESSAGE = 'lease_lost'; END IF;
    server_now := clock_timestamp();
    IF job_row.state <> 'leased' OR job_row.lease_token IS DISTINCT FROM p_lease_token OR
       job_row.lease_expires_at IS NULL OR job_row.lease_expires_at <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF101', MESSAGE = 'lease_lost';
    END IF;
    SELECT current_operation.* INTO operation_row FROM sentinelflow.dispatch_operations current_operation
    WHERE current_operation.job_id = p_job_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid'; END IF;
    SELECT current_capability.* INTO capability_row FROM sentinelflow.execution_capabilities current_capability
    WHERE current_capability.job_id = p_job_id FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'none'::text, NULL::uuid, NULL::bytea, NULL::sentinelflow.sha256_digest,
            NULL::bytea, NULL::bytea, NULL::uuid, NULL::bytea, NULL::sentinelflow.sha256_digest, NULL::bytea;
        RETURN;
    END IF;
    IF capability_row.schema_version <> 'execution-capability-v1' OR
       capability_row.operation <> operation_row.operation OR capability_row.action_id <> operation_row.action_id OR
       capability_row.policy_id <> operation_row.policy_id OR capability_row.policy_version <> operation_row.policy_version OR
       capability_row.target_ipv4 <> operation_row.target_ipv4 OR capability_row.artifact <> operation_row.artifact OR
       capability_row.artifact_digest <> operation_row.artifact_digest OR
       capability_row.original_add_digest IS DISTINCT FROM operation_row.original_add_digest OR
       capability_row.evidence_snapshot_digest <> operation_row.evidence_snapshot_digest OR
       capability_row.validation_snapshot_digest <> operation_row.validation_snapshot_digest OR
       capability_row.authorization_digest <> operation_row.authorization_digest OR
       capability_row.actor_id <> operation_row.actor_id OR capability_row.reason_digest <> operation_row.reason_digest OR
       capability_row.owned_schema_digest <> operation_row.owned_schema_digest OR
       capability_row.capability_digest <> sentinelflow.hil_sha256(capability_row.capability_jcs) OR
       capability_row.artifact_digest <> sentinelflow.hil_sha256(capability_row.artifact) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
    END IF;
    SELECT current_result.* INTO result_row FROM sentinelflow.execution_results current_result
    WHERE current_result.capability_id = capability_row.capability_id FOR SHARE;
    IF NOT FOUND THEN
        IF capability_row.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
        END IF;
        RETURN QUERY SELECT 'capability'::text, capability_row.capability_id, capability_row.capability_jcs,
            capability_row.capability_digest, capability_row.capability_signature, capability_row.artifact,
            NULL::uuid, NULL::bytea, NULL::sentinelflow.sha256_digest, NULL::bytea;
        RETURN;
    END IF;
    IF result_row.schema_version <> 'execution-result-v1' OR
       result_row.capability_id <> capability_row.capability_id OR
       result_row.capability_digest <> capability_row.capability_digest OR
       result_row.operation <> capability_row.operation OR result_row.action_id <> capability_row.action_id OR
       result_row.artifact_digest <> capability_row.artifact_digest OR result_row.target_ipv4 <> capability_row.target_ipv4 OR
       result_row.owned_schema_digest <> capability_row.owned_schema_digest OR result_row.element_handle IS NOT NULL OR
       capability_row.consumed_at IS NULL OR capability_row.consumed_at <> result_row.completed_at OR
       result_row.result_digest <> sentinelflow.hil_sha256(result_row.result_jcs) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
    END IF;
    RETURN QUERY SELECT 'result'::text, capability_row.capability_id, capability_row.capability_jcs,
        capability_row.capability_digest, capability_row.capability_signature, capability_row.artifact,
        result_row.result_id, result_row.result_jcs, result_row.result_digest, result_row.result_signature;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.dispatch_recovery_result_exact_000025(
    p_job_id uuid, p_capability_digest sentinelflow.sha256_digest,
    p_job_aggregate_version integer, p_server_now timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE exact boolean := false;
BEGIN
    IF p_job_id IS NULL OR p_capability_digest IS NULL OR p_job_aggregate_version IS NULL OR
       p_job_aggregate_version < 1 OR p_server_now IS NULL OR NOT isfinite(p_server_now) THEN
        RETURN false;
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM sentinelflow.execution_capabilities capability
        JOIN sentinelflow.execution_results result USING (capability_id)
        JOIN sentinelflow.dispatch_operations operation ON operation.job_id = capability.job_id
        JOIN sentinelflow.outbox_jobs job ON job.job_id = capability.job_id
        WHERE capability.job_id = p_job_id AND capability.capability_digest = p_capability_digest
          AND job.state = 'leased' AND job.operation = capability.operation
          AND job.kind = 'dispatch_' || capability.operation AND job.aggregate_type = 'enforcement_action'
          AND job.aggregate_id = capability.action_id AND job.aggregate_version = p_job_aggregate_version
          AND capability.schema_version = 'execution-capability-v1'
          AND octet_length(capability.capability_signature) = 64
          AND capability.consumed_at = result.completed_at AND result.schema_version = 'execution-result-v1'
          AND result.capability_digest = capability.capability_digest AND octet_length(result.result_signature) = 64
          AND capability.operation = result.operation AND capability.action_id = result.action_id
          AND capability.artifact_digest = result.artifact_digest AND capability.target_ipv4 = result.target_ipv4
          AND capability.owned_schema_digest = result.owned_schema_digest
          AND capability.capability_digest = sentinelflow.hil_sha256(capability.capability_jcs)
          AND capability.artifact_digest = sentinelflow.hil_sha256(capability.artifact)
          AND result.result_digest = sentinelflow.hil_sha256(result.result_jcs)
          AND result.element_handle IS NULL AND result.completed_at <= p_server_now
          AND operation.operation = capability.operation AND operation.action_id = capability.action_id
          AND operation.policy_id = capability.policy_id AND operation.policy_version = capability.policy_version
          AND operation.target_ipv4 = capability.target_ipv4 AND operation.artifact = capability.artifact
          AND operation.artifact_digest = capability.artifact_digest
          AND operation.original_add_digest IS NOT DISTINCT FROM capability.original_add_digest
          AND operation.evidence_snapshot_digest = capability.evidence_snapshot_digest
          AND operation.validation_snapshot_digest = capability.validation_snapshot_digest
          AND operation.authorization_digest = capability.authorization_digest
          AND operation.actor_id = capability.actor_id AND operation.reason_digest = capability.reason_digest
          AND operation.owned_schema_digest = capability.owned_schema_digest
    ) INTO exact;
    IF NOT exact THEN RETURN false; END IF;
    SELECT EXISTS (
        SELECT 1 FROM sentinelflow.lifecycle_result_applications_000026 application
        JOIN sentinelflow.execution_results result
          ON result.result_id = application.result_id AND result.result_digest = application.result_digest
        JOIN sentinelflow.execution_capabilities capability
          ON capability.capability_id = result.capability_id
         AND capability.capability_digest = result.capability_digest
        WHERE capability.job_id = p_job_id AND capability.capability_digest = p_capability_digest
          AND application.action_id = capability.action_id AND application.operation = capability.operation
          AND application.classification = result.classification
          AND application.resulting_action_version = p_job_aggregate_version
          AND isfinite(application.processed_at) AND application.processed_at >= result.completed_at
          AND application.processed_at <= p_server_now
          AND ((application.operation = 'add' AND (
                  (application.classification IN ('applied', 'recovered_active') AND application.resulting_state = 'active') OR
                  (application.classification = 'failed' AND application.resulting_state = 'failed') OR
                  (application.classification = 'indeterminate' AND application.resulting_state = 'indeterminate')
              )) OR (application.operation = 'revoke' AND (
                  (application.classification = 'revoked' AND application.resulting_state IN ('revoked', 'expired')) OR
                  (application.classification = 'failed' AND application.resulting_state = 'failed') OR
                  (application.classification = 'indeterminate' AND application.resulting_state = 'indeterminate')
              )) OR (application.operation = 'inspect' AND (
                  (application.classification = 'inspect_active' AND application.resulting_state IN ('active', 'failed')) OR
                  (application.classification = 'inspect_absent' AND application.resulting_state IN ('expired', 'failed')) OR
                  (application.classification IN ('inspect_mismatch', 'failed', 'indeterminate') AND application.resulting_state = 'indeterminate')
              )))
    ) INTO exact;
    RETURN coalesce(exact, false);
END
$function$;

DROP FUNCTION sentinelflow.record_execution_result_pre_000027(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
);
DROP FUNCTION sentinelflow.record_execution_result_v2(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea,
    timestamptz, timestamptz
);
ALTER FUNCTION sentinelflow.record_execution_result_lifecycle_pre_000034(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) RENAME TO record_execution_result_pre_000027;

DROP FUNCTION sentinelflow.record_execution_result_pre_000026(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
);
ALTER FUNCTION sentinelflow.record_execution_result_insert_pre_000034(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) RENAME TO record_execution_result_pre_000026;

DROP FUNCTION sentinelflow.record_execution_result_v2_000034(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
);
DROP TABLE sentinelflow.enforcement_expiry_bounds_000034;
DROP TABLE sentinelflow.execution_result_readback_bounds_000034;
ALTER TABLE sentinelflow.execution_results
    DROP CONSTRAINT execution_results_schema_version_check;
ALTER TABLE sentinelflow.execution_results
    ADD CONSTRAINT execution_results_schema_version_check
    CHECK (schema_version = 'execution-result-v1');

DELETE FROM sentinelflow.schema_migrations
WHERE version = 34 AND name = 'execution_result_v2_expiry_bounds';

COMMIT;
