BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $preflight$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.execution_capabilities capability
        JOIN sentinelflow.outbox_jobs job USING (job_id)
        LEFT JOIN sentinelflow.execution_results result USING (capability_id)
        LEFT JOIN sentinelflow.dead_letter_jobs dead USING (job_id)
        WHERE job.state <> 'completed'
           OR result.result_id IS NULL
           OR capability.consumed_at IS DISTINCT FROM result.completed_at
           OR capability.schema_version <> 'execution-capability-v1'
           OR capability.capability_digest <> sentinelflow.hil_sha256(capability.capability_jcs)
           OR capability.artifact_digest <> sentinelflow.hil_sha256(capability.artifact)
           OR result.schema_version <> 'execution-result-v1'
           OR result.capability_digest <> capability.capability_digest
           OR result.operation <> capability.operation
           OR result.action_id <> capability.action_id
           OR result.artifact_digest <> capability.artifact_digest
           OR result.target_ipv4 <> capability.target_ipv4
           OR result.owned_schema_digest <> capability.owned_schema_digest
           OR result.result_digest <> sentinelflow.hil_sha256(result.result_jcs)
           OR result.element_handle IS NOT NULL
           OR (dead.job_id IS NOT NULL AND (
               dead.resolution_state <> 'resolved' OR
               NOT isfinite(dead.dead_at) OR NOT isfinite(dead.resolved_at) OR
               dead.dead_at > dead.resolved_at OR dead.resolved_at > job.updated_at OR
               dead.resolution_actor <> 'sentinelflow_recovery' OR
               dead.kind <> job.kind OR
               dead.aggregate_type <> job.aggregate_type OR
               dead.aggregate_id <> job.aggregate_id OR
               dead.aggregate_version <> job.aggregate_version OR
               dead.attempts <> job.attempts OR
               dead.resolution_digest <> sentinelflow.dispatch_recovery_marker_000025(
                   job.job_id, capability.capability_digest,
                   dead.failure_code, dead.failure_digest
               )
           ))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'dispatch recovery downgrade blocked by unresolved execution capability';
    END IF;
END
$preflight$;

REVOKE ALL ON FUNCTION sentinelflow.claim_dispatch_recovery_job_000025(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.finish_dispatch_recovery_job_000025(
    uuid, uuid
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.finish_dispatch_job(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.finish_dispatch_job_pre_000025(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
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
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON sentinelflow.dispatcher_recovery_outbox_000025
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
         sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.dispatch_recovery_marker_000025(
    uuid, sentinelflow.sha256_digest, sentinelflow.ascii_id,
    sentinelflow.sha256_digest
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.dispatch_recovery_result_exact_000025(
    uuid, sentinelflow.sha256_digest, integer, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_dispatcher;
DROP FUNCTION sentinelflow.claim_dispatch_recovery_job_000025(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
);
DROP FUNCTION sentinelflow.finish_dispatch_recovery_job_000025(uuid, uuid);
DROP TRIGGER execution_capabilities_protect_unresolved_000025
    ON sentinelflow.execution_capabilities;
DROP FUNCTION sentinelflow.protect_unresolved_execution_capability_000025();
DROP FUNCTION sentinelflow.finish_dispatch_job(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
);
ALTER FUNCTION sentinelflow.finish_dispatch_job_pre_000025(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
) RENAME TO finish_dispatch_job;
DROP FUNCTION sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
);
ALTER FUNCTION sentinelflow.claim_dispatch_job_pre_000025(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) RENAME TO claim_dispatch_job;
DROP FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
);
ALTER FUNCTION sentinelflow.record_execution_capability_pre_000025(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) RENAME TO record_execution_capability;
GRANT EXECUTE ON FUNCTION sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
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
GRANT EXECUTE ON FUNCTION sentinelflow.finish_dispatch_job(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
) TO sentinelflow_dispatcher;
DROP VIEW sentinelflow.dispatcher_recovery_outbox_000025;
DROP FUNCTION sentinelflow.dispatch_recovery_result_exact_000025(
    uuid, sentinelflow.sha256_digest, integer, timestamptz
);
DROP FUNCTION sentinelflow.dispatch_recovery_marker_000025(
    uuid, sentinelflow.sha256_digest, sentinelflow.ascii_id,
    sentinelflow.sha256_digest
);

GRANT UPDATE ON sentinelflow.dead_letter_jobs TO sentinelflow_worker;

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
DELETE FROM sentinelflow.schema_migrations WHERE version = 25;

COMMIT;
