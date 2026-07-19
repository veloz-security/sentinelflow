BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Return only the exact signed artifacts already attached to one currently
-- leased job.  This is a recovery read, never a mint/rewrite/sign operation.
CREATE OR REPLACE FUNCTION sentinelflow.recover_dispatch_execution(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE (
    recovery_state text,
    capability_id uuid,
    capability_jcs bytea,
    capability_digest sentinelflow.sha256_digest,
    capability_signature bytea,
    capability_artifact bytea,
    result_id uuid,
    result_jcs bytea,
    result_digest sentinelflow.sha256_digest,
    result_signature bytea
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

    -- Lock order is job -> immutable operation -> capability -> result.  The
    -- database clock is sampled only after the authority-bearing lease row is
    -- locked, so lock wait cannot preserve an expired lease.
    SELECT current_job.* INTO job_row
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF101', MESSAGE = 'lease_lost';
    END IF;

    server_now := clock_timestamp();
    IF job_row.state <> 'leased' OR
       job_row.lease_token IS DISTINCT FROM p_lease_token OR
       job_row.lease_expires_at IS NULL OR
       job_row.lease_expires_at <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF101', MESSAGE = 'lease_lost';
    END IF;

    SELECT current_operation.* INTO operation_row
    FROM sentinelflow.dispatch_operations current_operation
    WHERE current_operation.job_id = p_job_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
    END IF;

    SELECT current_capability.* INTO capability_row
    FROM sentinelflow.execution_capabilities current_capability
    WHERE current_capability.job_id = p_job_id
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'none'::text,
            NULL::uuid, NULL::bytea, NULL::sentinelflow.sha256_digest,
            NULL::bytea, NULL::bytea,
            NULL::uuid, NULL::bytea, NULL::sentinelflow.sha256_digest,
            NULL::bytea;
        RETURN;
    END IF;

    IF capability_row.schema_version <> 'execution-capability-v1' OR
       capability_row.operation <> operation_row.operation OR
       capability_row.action_id <> operation_row.action_id OR
       capability_row.policy_id <> operation_row.policy_id OR
       capability_row.policy_version <> operation_row.policy_version OR
       capability_row.target_ipv4 <> operation_row.target_ipv4 OR
       capability_row.artifact <> operation_row.artifact OR
       capability_row.artifact_digest <> operation_row.artifact_digest OR
       capability_row.original_add_digest IS DISTINCT FROM operation_row.original_add_digest OR
       capability_row.evidence_snapshot_digest <> operation_row.evidence_snapshot_digest OR
       capability_row.validation_snapshot_digest <> operation_row.validation_snapshot_digest OR
       capability_row.authorization_digest <> operation_row.authorization_digest OR
       capability_row.actor_id <> operation_row.actor_id OR
       capability_row.reason_digest <> operation_row.reason_digest OR
       capability_row.owned_schema_digest <> operation_row.owned_schema_digest OR
       capability_row.capability_digest <>
           sentinelflow.hil_sha256(capability_row.capability_jcs) OR
       capability_row.artifact_digest <>
           sentinelflow.hil_sha256(capability_row.artifact) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
    END IF;

    SELECT current_result.* INTO result_row
    FROM sentinelflow.execution_results current_result
    WHERE current_result.capability_id = capability_row.capability_id
    FOR SHARE;
    IF NOT FOUND THEN
        IF capability_row.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
        END IF;
        RETURN QUERY SELECT
            'capability'::text,
            capability_row.capability_id,
            capability_row.capability_jcs,
            capability_row.capability_digest,
            capability_row.capability_signature,
            capability_row.artifact,
            NULL::uuid, NULL::bytea, NULL::sentinelflow.sha256_digest,
            NULL::bytea;
        RETURN;
    END IF;

    IF result_row.schema_version <> 'execution-result-v1' OR
       result_row.capability_id <> capability_row.capability_id OR
       result_row.capability_digest <> capability_row.capability_digest OR
       result_row.operation <> capability_row.operation OR
       result_row.action_id <> capability_row.action_id OR
       result_row.artifact_digest <> capability_row.artifact_digest OR
       result_row.target_ipv4 <> capability_row.target_ipv4 OR
       result_row.owned_schema_digest <> capability_row.owned_schema_digest OR
       result_row.element_handle IS NOT NULL OR
       capability_row.consumed_at IS NULL OR
       capability_row.consumed_at <> result_row.completed_at OR
       result_row.result_digest <> sentinelflow.hil_sha256(result_row.result_jcs) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
    END IF;

    RETURN QUERY SELECT
        'result'::text,
        capability_row.capability_id,
        capability_row.capability_jcs,
        capability_row.capability_digest,
        capability_row.capability_signature,
        capability_row.artifact,
        result_row.result_id,
        result_row.result_jcs,
        result_row.result_digest,
        result_row.result_signature;
END
$function$;

REVOKE ALL ON FUNCTION sentinelflow.recover_dispatch_execution(uuid, uuid)
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read;
GRANT EXECUTE ON FUNCTION sentinelflow.recover_dispatch_execution(uuid, uuid)
TO sentinelflow_dispatcher;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (11, 'dispatch_recovery')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
