BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Once D-bound validation or HIL state exists, restoring coordinators that do
-- not re-check evidence_version would re-open stale authority. Require an
-- explicit offline reconciliation instead of silently weakening the fence.
DO $fail_stop$
BEGIN
    IF EXISTS (SELECT 1 FROM sentinelflow.validation_attempt_claims) OR
       EXISTS (SELECT 1 FROM sentinelflow.policy_proposals) OR
       EXISTS (SELECT 1 FROM sentinelflow.decision_challenges) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cannot discard durable evidence-bound validation or HIL state';
    END IF;
END
$fail_stop$;

DROP FUNCTION IF EXISTS sentinelflow.prepare_validation_attempt_exact(uuid, uuid);
DROP FUNCTION IF EXISTS sentinelflow.finalize_validation_attempt_exact(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json, bytea
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
DROP FUNCTION IF EXISTS sentinelflow.commit_hil_policy_decision_with_session_rotation(
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
);
DROP FUNCTION IF EXISTS sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
);
DROP FUNCTION IF EXISTS sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
);

DO $restore_functions$
BEGIN
    IF to_regprocedure(
        'sentinelflow.prepare_validation_attempt_exact_pre_000019(uuid,uuid)'
    ) IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.prepare_validation_attempt_exact_pre_000019(
            uuid, uuid
        ) RENAME TO prepare_validation_attempt_exact;
    END IF;
    IF to_regprocedure(
        'sentinelflow.finalize_validation_attempt_exact_pre_000019('
        'uuid,uuid,text,timestamptz,timestamptz,text,text,json,bytea)'
    ) IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.finalize_validation_attempt_exact_pre_000019(
            uuid, uuid, text, timestamptz, timestamptz,
            text, text, json, bytea
        ) RENAME TO finalize_validation_attempt_exact;
    END IF;
    IF to_regprocedure(
        'sentinelflow.issue_hil_policy_challenge_pre_000019('
        'uuid,sentinelflow.sha256_digest,uuid,sentinelflow.ascii_id,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,timestamptz,'
        'timestamptz,text,uuid,integer,sentinelflow.canonical_ipv4,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,'
        'sentinelflow.sha256_digest,sentinelflow.sha256_digest,text,bytea,'
        'timestamptz,timestamptz,integer)'
    ) IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.issue_hil_policy_challenge_pre_000019(
            uuid, sentinelflow.sha256_digest, uuid, sentinelflow.ascii_id,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            timestamptz, timestamptz, text, uuid, integer,
            sentinelflow.canonical_ipv4, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, text, bytea, timestamptz,
            timestamptz, integer
        ) RENAME TO issue_hil_policy_challenge;
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
    ) IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.commit_hil_policy_decision_with_session_rotation_pre_000019(
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
        ) RENAME TO commit_hil_policy_decision_with_session_rotation;
    END IF;
    IF to_regprocedure(
        'sentinelflow.claim_dispatch_job_pre_000019('
        'uuid,uuid,sentinelflow.ascii_id,timestamptz)'
    ) IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.claim_dispatch_job_pre_000019(
            uuid, uuid, sentinelflow.ascii_id, timestamptz
        ) RENAME TO claim_dispatch_job;
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
    ) IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.record_execution_capability_pre_000019(
            uuid, uuid, uuid, text, uuid, uuid, integer,
            sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, sentinelflow.sha256_digest,
            sentinelflow.ascii_id, sentinelflow.sha256_digest,
            sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
            bytea, sentinelflow.sha256_digest, timestamptz, timestamptz,
            timestamptz
        ) RENAME TO record_execution_capability;
    END IF;
END
$restore_functions$;

DROP FUNCTION IF EXISTS sentinelflow.interrupt_stale_validation_000019(uuid, uuid);
DROP FUNCTION IF EXISTS sentinelflow.policy_evidence_is_current_000019(
    uuid, integer, boolean
);
DROP FUNCTION IF EXISTS sentinelflow.incident_evidence_is_current_000019(
    uuid, integer, uuid, sentinelflow.sha256_digest, boolean
);

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

DELETE FROM sentinelflow.schema_migrations
WHERE version = 19 AND name = 'evidence_bound_validation_hil';

COMMIT;
