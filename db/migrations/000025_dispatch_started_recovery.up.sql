BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Ordinary dispatch must never claim a row that already owns capability
-- bytes. Such rows are visible only through the recovery-only view below.
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
  AND NOT EXISTS (
      SELECT 1 FROM sentinelflow.execution_capabilities capability
      WHERE capability.job_id = job.job_id
  )
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

ALTER FUNCTION sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) RENAME TO claim_dispatch_job_pre_000025;

CREATE FUNCTION sentinelflow.claim_dispatch_job(
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
    locked_job_id uuid;
BEGIN
    -- The legacy implementation predates the recovery-only path and repeats
    -- its own eligibility predicate. Close that boundary before delegating;
    -- the ordinary path can never win a race for persisted authority.
    SELECT job.job_id INTO locked_job_id
    FROM sentinelflow.outbox_jobs job
    WHERE job.job_id = p_job_id
    FOR UPDATE;
    IF NOT FOUND OR EXISTS (
        SELECT 1 FROM sentinelflow.execution_capabilities capability
        WHERE capability.job_id = p_job_id
    ) THEN
        RETURN false;
    END IF;
    RETURN sentinelflow.claim_dispatch_job_pre_000025(
        p_job_id, p_lease_token, p_lease_owner, p_lease_until
    );
END
$function$;

ALTER FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) RENAME TO record_execution_capability_pre_000025;

CREATE FUNCTION sentinelflow.record_execution_capability(
    p_capability_id uuid, p_job_id uuid, p_lease_token uuid,
    p_operation text, p_action_id uuid, p_policy_id uuid,
    p_policy_version integer, p_target_ipv4 sentinelflow.canonical_ipv4,
    p_artifact bytea, p_artifact_digest sentinelflow.sha256_digest,
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
    p_issued_at timestamptz, p_not_before timestamptz,
    p_expires_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    current_job sentinelflow.outbox_jobs%ROWTYPE;
BEGIN
    -- Serialize capability persistence with lease expiry/reclaim. The legacy
    -- function's unlocked EXISTS check is retained only behind this fence.
    SELECT job.* INTO current_job
    FROM sentinelflow.outbox_jobs job
    WHERE job.job_id = p_job_id
    FOR UPDATE;
    IF NOT FOUND OR current_job.state <> 'leased' OR
       current_job.lease_token IS DISTINCT FROM p_lease_token OR
       current_job.lease_expires_at IS NULL OR
       current_job.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'capability lease is not live';
    END IF;
    PERFORM sentinelflow.record_execution_capability_pre_000025(
        p_capability_id, p_job_id, p_lease_token, p_operation, p_action_id,
        p_policy_id, p_policy_version, p_target_ipv4, p_artifact,
        p_artifact_digest, p_original_add_digest,
        p_evidence_snapshot_digest, p_validation_snapshot_digest,
        p_authorization_digest, p_actor_id, p_reason_digest,
        p_owned_schema_digest, p_capability_jcs, p_capability_digest,
        p_capability_signature, p_nonce_digest, p_issued_at, p_not_before,
        p_expires_at
    );
END
$function$;

-- The pre-000025 finisher accepts any live lease. Keep it private so a
-- recovery lease cannot bypass exact dead-letter provenance and resolution.
ALTER FUNCTION sentinelflow.finish_dispatch_job(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
) RENAME TO finish_dispatch_job_pre_000025;

-- One versioned marker binds recovery provenance to the exact persisted job,
-- signed capability, and original dead-letter failure. State strings alone
-- never authorize recovery and the original failure is never overwritten.
CREATE OR REPLACE FUNCTION sentinelflow.dispatch_recovery_marker_000025(
    p_job_id uuid,
    p_capability_digest sentinelflow.sha256_digest,
    p_failure_code sentinelflow.ascii_id,
    p_failure_digest sentinelflow.sha256_digest
)
RETURNS sentinelflow.sha256_digest
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT sentinelflow.hil_sha256(convert_to(
        'sentinelflow-recovery-started-v1' || chr(10) ||
        p_job_id::text || chr(10) || p_capability_digest::text || chr(10) ||
        p_failure_code::text || chr(10) || p_failure_digest::text,
        'UTF8'
    ));
$function$;

-- Prove one persisted terminal result against the immutable capability,
-- operation, and job row. After 000026 is present, also require the exact
-- lifecycle application. Dynamic SQL keeps 000025 runnable before that table
-- exists without weakening upgraded databases.
CREATE FUNCTION sentinelflow.dispatch_recovery_result_exact_000025(
    p_job_id uuid,
    p_capability_digest sentinelflow.sha256_digest,
    p_job_aggregate_version integer,
    p_server_now timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    exact boolean := false;
BEGIN
    IF p_job_id IS NULL OR p_capability_digest IS NULL OR
       p_job_aggregate_version IS NULL OR p_job_aggregate_version < 1 OR
       p_server_now IS NULL OR NOT isfinite(p_server_now) THEN
        RETURN false;
    END IF;
    SELECT EXISTS (
        SELECT 1
        FROM sentinelflow.execution_capabilities capability
        JOIN sentinelflow.execution_results result USING (capability_id)
        JOIN sentinelflow.dispatch_operations operation
          ON operation.job_id = capability.job_id
        JOIN sentinelflow.outbox_jobs job ON job.job_id = capability.job_id
        WHERE capability.job_id = p_job_id
          AND capability.capability_digest = p_capability_digest
          AND job.state = 'leased'
          AND job.operation = capability.operation
          AND job.kind = 'dispatch_' || capability.operation
          AND job.aggregate_type = 'enforcement_action'
          AND job.aggregate_id = capability.action_id
          AND job.aggregate_version = p_job_aggregate_version
          AND capability.schema_version = 'execution-capability-v1'
          AND octet_length(capability.capability_signature) = 64
          AND capability.consumed_at = result.completed_at
          AND result.schema_version = 'execution-result-v1'
          AND result.capability_digest = capability.capability_digest
          AND octet_length(result.result_signature) = 64
          AND capability.operation = result.operation
          AND capability.action_id = result.action_id
          AND capability.artifact_digest = result.artifact_digest
          AND capability.target_ipv4 = result.target_ipv4
          AND capability.owned_schema_digest = result.owned_schema_digest
          AND capability.capability_digest =
              sentinelflow.hil_sha256(capability.capability_jcs)
          AND capability.artifact_digest = sentinelflow.hil_sha256(capability.artifact)
          AND result.result_digest = sentinelflow.hil_sha256(result.result_jcs)
          AND result.element_handle IS NULL
          AND result.completed_at <= p_server_now
          AND operation.operation = capability.operation
          AND operation.action_id = capability.action_id
          AND operation.policy_id = capability.policy_id
          AND operation.policy_version = capability.policy_version
          AND operation.target_ipv4 = capability.target_ipv4
          AND operation.artifact = capability.artifact
          AND operation.artifact_digest = capability.artifact_digest
          AND operation.original_add_digest IS NOT DISTINCT FROM
              capability.original_add_digest
          AND operation.evidence_snapshot_digest = capability.evidence_snapshot_digest
          AND operation.validation_snapshot_digest = capability.validation_snapshot_digest
          AND operation.authorization_digest = capability.authorization_digest
          AND operation.actor_id = capability.actor_id
          AND operation.reason_digest = capability.reason_digest
          AND operation.owned_schema_digest = capability.owned_schema_digest
    ) INTO exact;
    IF NOT exact THEN
        RETURN false;
    END IF;
    IF to_regclass('sentinelflow.lifecycle_result_applications_000026') IS NULL THEN
        RETURN true;
    END IF;
    EXECUTE $application_query$
        SELECT EXISTS (
            SELECT 1
            FROM sentinelflow.lifecycle_result_applications_000026 application
            JOIN sentinelflow.execution_results result
              ON result.result_id = application.result_id
             AND result.result_digest = application.result_digest
            JOIN sentinelflow.execution_capabilities capability
              ON capability.capability_id = result.capability_id
             AND capability.capability_digest = result.capability_digest
            WHERE capability.job_id = $1
              AND capability.capability_digest = $2
              AND application.action_id = capability.action_id
              AND application.operation = capability.operation
              AND application.classification = result.classification
              AND application.resulting_action_version = $3
              AND isfinite(application.processed_at)
              AND application.processed_at >= result.completed_at
              AND application.processed_at <= $4
              AND (
                  (application.operation = 'add' AND (
                      (application.classification IN ('applied', 'recovered_active') AND
                       application.resulting_state = 'active') OR
                      (application.classification = 'failed' AND
                       application.resulting_state = 'failed') OR
                      (application.classification = 'indeterminate' AND
                       application.resulting_state = 'indeterminate')
                  )) OR
                  (application.operation = 'revoke' AND (
                      (application.classification = 'revoked' AND
                       application.resulting_state IN ('revoked', 'expired')) OR
                      (application.classification = 'failed' AND
                       application.resulting_state = 'failed') OR
                      (application.classification = 'indeterminate' AND
                       application.resulting_state = 'indeterminate')
                  )) OR
                  (application.operation = 'inspect' AND (
                      (application.classification = 'inspect_active' AND
                       application.resulting_state IN ('active', 'failed')) OR
                      (application.classification = 'inspect_absent' AND
                       application.resulting_state IN ('expired', 'failed')) OR
                      (application.classification IN (
                          'inspect_mismatch', 'failed', 'indeterminate'
                       ) AND application.resulting_state = 'indeterminate')
                  ))
              )
        )
    $application_query$
    INTO exact
    USING p_job_id, p_capability_digest, p_job_aggregate_version, p_server_now;
    RETURN coalesce(exact, false);
END
$function$;

-- Ordinary dispatch retains the public function signature, but cannot finish
-- a restore-authorized recovery lease or manufacture its reserved marker.
CREATE FUNCTION sentinelflow.finish_dispatch_job(
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
    current_job sentinelflow.outbox_jobs%ROWTYPE;
BEGIN
    IF p_error_code IS NOT DISTINCT FROM 'recovery_started' THEN
        RETURN false;
    END IF;
    SELECT job.* INTO current_job
    FROM sentinelflow.outbox_jobs job
    WHERE job.job_id = p_job_id
    FOR UPDATE;
    IF NOT FOUND OR current_job.last_error_code = 'recovery_started' OR EXISTS (
        SELECT 1
        FROM sentinelflow.dead_letter_jobs dead
        JOIN sentinelflow.execution_capabilities capability USING (job_id)
        WHERE dead.job_id = p_job_id
          AND dead.resolution_state IN ('requeued', 'resolved')
          AND dead.resolution_actor = 'sentinelflow_recovery'
          AND dead.resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
              dead.job_id, capability.capability_digest,
              dead.failure_code, dead.failure_digest
          )
    ) THEN
        RETURN false;
    END IF;
    RETURN sentinelflow.finish_dispatch_job_pre_000025(
        p_job_id, p_lease_token, p_outcome,
        p_error_code, p_error_digest, p_next_available_at
    );
END
$function$;

-- This view is deliberately separate from dispatcher_approved_outbox. It can
-- never authorize a new capability: every row already owns one exact signed
-- capability, the capability is expired, and the database may only recover a
-- persisted result or ask the executor to resolve journal state read-only.
CREATE OR REPLACE VIEW sentinelflow.dispatcher_recovery_outbox_000025
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
  AND capability.operation = operation.operation
  AND capability.action_id = operation.action_id
  AND capability.policy_id = operation.policy_id
  AND capability.policy_version = operation.policy_version
  AND capability.target_ipv4 = operation.target_ipv4
  AND capability.artifact = operation.artifact
  AND capability.artifact_digest = operation.artifact_digest
  AND capability.original_add_digest IS NOT DISTINCT FROM operation.original_add_digest
  AND capability.evidence_snapshot_digest = operation.evidence_snapshot_digest
  AND capability.validation_snapshot_digest = operation.validation_snapshot_digest
  AND capability.authorization_digest = operation.authorization_digest
  AND capability.actor_id = operation.actor_id
  AND capability.reason_digest = operation.reason_digest
  AND capability.owned_schema_digest = operation.owned_schema_digest
  AND capability.artifact_digest =
      ('sha256:' || encode(sha256(capability.artifact), 'hex'))::sentinelflow.sha256_digest
  AND capability.capability_digest =
      ('sha256:' || encode(sha256(capability.capability_jcs), 'hex'))::sentinelflow.sha256_digest
  AND (
      (result.result_id IS NULL AND capability.consumed_at IS NULL) OR
      (result.result_id IS NOT NULL AND capability.consumed_at = result.completed_at AND
       result.schema_version = 'execution-result-v1' AND
       result.capability_digest = capability.capability_digest AND
       result.operation = capability.operation AND
       result.action_id = capability.action_id AND
       result.artifact_digest = capability.artifact_digest AND
       result.target_ipv4 = capability.target_ipv4 AND
       result.owned_schema_digest = capability.owned_schema_digest AND
       result.result_digest =
           ('sha256:' || encode(sha256(result.result_jcs), 'hex'))::sentinelflow.sha256_digest AND
       result.element_handle IS NULL)
  );

CREATE OR REPLACE FUNCTION sentinelflow.claim_dispatch_recovery_job_000025(
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
    server_now timestamptz;
    current_job sentinelflow.outbox_jobs%ROWTYPE;
    eligible boolean;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL OR p_lease_owner IS NULL OR
       p_lease_until IS NULL OR NOT isfinite(p_lease_until) THEN
        RETURN false;
    END IF;

    SELECT job.* INTO current_job
    FROM sentinelflow.outbox_jobs job
    WHERE job.job_id = p_job_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    server_now := clock_timestamp();
    IF p_lease_until <= server_now OR
       p_lease_until > server_now + interval '60 seconds' OR NOT (
           (current_job.state = 'retry' AND current_job.available_at <= server_now) OR
           (current_job.state = 'leased' AND current_job.lease_expires_at <= server_now)
       ) THEN
        RETURN false;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM sentinelflow.dispatcher_recovery_outbox_000025 recovery
        WHERE recovery.job_id = p_job_id
    ) INTO eligible;
    IF NOT eligible THEN
        RETURN false;
    END IF;

    UPDATE sentinelflow.outbox_jobs job
    SET state = 'leased', lease_token = p_lease_token,
        lease_owner = p_lease_owner, lease_expires_at = p_lease_until,
        -- Recovery consumes no ordinary dispatch attempt: it cannot mint or
        -- mutate and a transient transport failure must not strand history.
        -- Keep the restore-bound marker while the recovery lease is live so
        -- Finish can prove that the exact dead letter, rather than a later
        -- arbitrary lifecycle state, authorized this recovery attempt.
        attempts = job.attempts, updated_at = server_now
    WHERE job.job_id = p_job_id;
    RETURN true;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finish_dispatch_recovery_job_000025(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    finished boolean;
    server_now timestamptz := clock_timestamp();
    dead_state text;
    dead_resolved_at timestamptz;
    dead_actor text;
    dead_digest text;
    dead_kind text;
    dead_aggregate_type text;
    dead_aggregate_id uuid;
    dead_aggregate_version integer;
    dead_attempts integer;
    dead_failure_code text;
    dead_failure_digest text;
    dead_at timestamptz;
    job_kind text;
    job_aggregate_type text;
    job_aggregate_id uuid;
    job_aggregate_version integer;
    job_attempts integer;
    job_last_error_code text;
    job_last_error_digest text;
    capability_digest text;
    dead_found boolean := false;
    lifecycle_relation regclass;
    result_exact boolean := false;
    affected integer;
BEGIN
    SELECT job.kind, job.aggregate_type, job.aggregate_id,
           job.aggregate_version, job.attempts,
           job.last_error_code, job.last_error_digest,
           capability.capability_digest
    INTO job_kind, job_aggregate_type, job_aggregate_id,
         job_aggregate_version, job_attempts,
         job_last_error_code, job_last_error_digest, capability_digest
    FROM sentinelflow.outbox_jobs job
    JOIN sentinelflow.execution_capabilities capability USING (job_id)
    WHERE job.job_id = p_job_id
    FOR UPDATE OF job;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'dispatch recovery evidence is missing';
    END IF;

    SELECT dead.resolution_state, dead.resolved_at, dead.resolution_actor,
           dead.resolution_digest, dead.kind, dead.aggregate_type,
           dead.aggregate_id, dead.aggregate_version, dead.attempts,
           dead.failure_code, dead.failure_digest, dead.dead_at
    INTO dead_state, dead_resolved_at, dead_actor, dead_digest, dead_kind,
         dead_aggregate_type, dead_aggregate_id, dead_aggregate_version,
         dead_attempts, dead_failure_code, dead_failure_digest, dead_at
    FROM sentinelflow.dead_letter_jobs dead
    WHERE dead.job_id = p_job_id
    FOR UPDATE;
    dead_found := FOUND;

    lifecycle_relation := to_regclass(
        'sentinelflow.lifecycle_result_applications_000026'
    );
    IF dead_found THEN
        IF (
            dead_state <> 'requeued' OR dead_resolved_at IS NULL OR
            NOT isfinite(dead_resolved_at) OR dead_resolved_at > server_now OR
            NOT isfinite(dead_at) OR dead_at > dead_resolved_at OR
            dead_actor <> 'sentinelflow_recovery' OR
            dead_kind <> job_kind OR dead_aggregate_type <> job_aggregate_type OR
            dead_aggregate_id <> job_aggregate_id OR
            dead_attempts <> job_attempts OR
            job_last_error_code IS DISTINCT FROM 'recovery_started' OR
            job_last_error_digest IS DISTINCT FROM dead_digest OR
            dead_digest <> sentinelflow.dispatch_recovery_marker_000025(
                p_job_id, capability_digest::sentinelflow.sha256_digest,
                dead_failure_code::sentinelflow.ascii_id,
                dead_failure_digest::sentinelflow.sha256_digest
            ) OR
            (lifecycle_relation IS NULL AND
             dead_aggregate_version <> job_aggregate_version) OR
            (lifecycle_relation IS NOT NULL AND
             job_aggregate_version NOT IN (
                 dead_aggregate_version, dead_aggregate_version + 1
             ))
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'dispatch recovery dead-letter state is invalid';
        END IF;
    ELSIF job_last_error_code IS NOT NULL OR job_last_error_digest IS NOT NULL THEN
        -- No-dead runtime crash recovery is allowed only for the exact
        -- signed-result path. Restore-authorized provenance must always carry
        -- its dead letter and marker.
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'dispatch recovery no-dead state is invalid';
    END IF;

    result_exact := sentinelflow.dispatch_recovery_result_exact_000025(
        p_job_id, capability_digest::sentinelflow.sha256_digest,
        job_aggregate_version, server_now
    );
    IF NOT result_exact THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'dispatch recovery lifecycle binding is invalid';
    END IF;

    finished := sentinelflow.finish_dispatch_job_pre_000025(
        p_job_id, p_lease_token, 'completed', NULL, NULL, NULL
    );
    IF NOT finished THEN
        RETURN false;
    END IF;
    IF dead_found THEN
        UPDATE sentinelflow.dead_letter_jobs dead
        SET resolution_state = 'resolved', resolved_at = server_now,
            resolution_actor = 'sentinelflow_recovery',
            resolution_digest = dead_digest::sentinelflow.sha256_digest
        WHERE dead.job_id = p_job_id
          AND dead.resolution_state = 'requeued'
          AND dead.resolution_actor = 'sentinelflow_recovery'
          AND dead.resolution_digest = dead_digest::sentinelflow.sha256_digest
          AND dead.aggregate_version = dead_aggregate_version;
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'dispatch recovery dead-letter update failed';
        END IF;
    END IF;
    RETURN true;
END
$function$;

-- Retention may delete terminal result rows before their consumed capability,
-- but an unconsumed capability represents unresolved executor journal state.
-- Preserve it until recovery produces and persists a terminal result.
CREATE OR REPLACE FUNCTION sentinelflow.protect_unresolved_execution_capability_000025()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF OLD.consumed_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'unresolved execution capability is protected from retention';
    END IF;
    RETURN OLD;
END
$function$;

DROP TRIGGER IF EXISTS execution_capabilities_protect_unresolved_000025
    ON sentinelflow.execution_capabilities;
CREATE TRIGGER execution_capabilities_protect_unresolved_000025
BEFORE DELETE ON sentinelflow.execution_capabilities
FOR EACH ROW EXECUTE FUNCTION sentinelflow.protect_unresolved_execution_capability_000025();

REVOKE ALL ON sentinelflow.dispatcher_recovery_outbox_000025
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
         sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.claim_dispatch_recovery_job_000025(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.finish_dispatch_recovery_job_000025(
    uuid, uuid
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.protect_unresolved_execution_capability_000025()
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
         sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.claim_dispatch_job_pre_000025(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_capability_pre_000025(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.finish_dispatch_job_pre_000025(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.dispatch_recovery_marker_000025(
    uuid, sentinelflow.sha256_digest, sentinelflow.ascii_id,
    sentinelflow.sha256_digest
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.dispatch_recovery_result_exact_000025(
    uuid, sentinelflow.sha256_digest, integer, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE UPDATE ON sentinelflow.dead_letter_jobs FROM sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.finish_dispatch_job(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
GRANT SELECT ON sentinelflow.dispatcher_recovery_outbox_000025
    TO sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.dispatch_recovery_marker_000025(
    uuid, sentinelflow.sha256_digest, sentinelflow.ascii_id,
    sentinelflow.sha256_digest
) TO sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.dispatch_recovery_result_exact_000025(
    uuid, sentinelflow.sha256_digest, integer, timestamptz
) TO sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.claim_dispatch_recovery_job_000025(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) TO sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.finish_dispatch_recovery_job_000025(
    uuid, uuid
) TO sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) TO sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.finish_dispatch_job(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
) TO sentinelflow_dispatcher;
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
VALUES (25, 'dispatch_started_recovery')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
