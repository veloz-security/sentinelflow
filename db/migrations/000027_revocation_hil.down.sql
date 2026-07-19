BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- There is no truthful projection from version-bound revoke evidence back to
-- the pre-000027 globally unique delete digest model. Never discard it.
DO $preflight$
BEGIN
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
            MESSAGE = 'revocation HIL downgrade blocked by durable revoke evidence';
    END IF;
    IF EXISTS (
        SELECT reason_digest FROM sentinelflow.hil_reasons
        GROUP BY reason_digest HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'revocation HIL downgrade blocked by scoped reason digest reuse';
    END IF;
END
$preflight$;

DO $restore_policy_reason_identity$
DECLARE
    function_definition text;
    restored_definition text;
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
    IF function_definition NOT LIKE
           '%ON CONFLICT (actor_id, operation, reason_digest) DO NOTHING%' OR
       function_definition NOT LIKE
           '%WHERE reason.actor_id = p_actor_id AND reason.operation = p_operation AND reason.reason_digest = p_reason_digest;%' THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'policy HIL coordinator scoped reason clauses are not restorable';
    END IF;
    restored_definition := replace(
        function_definition,
        'ON CONFLICT (actor_id, operation, reason_digest) DO NOTHING',
        'ON CONFLICT (reason_digest) DO NOTHING'
    );
    restored_definition := replace(
        restored_definition,
        'WHERE reason.actor_id = p_actor_id AND reason.operation = p_operation ' ||
        'AND reason.reason_digest = p_reason_digest;',
        'WHERE reason.reason_digest = p_reason_digest;'
    );
    EXECUTE restored_definition;
END
$restore_policy_reason_identity$;

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

DROP FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
);
ALTER FUNCTION sentinelflow.record_execution_capability_pre_000027(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) RENAME TO record_execution_capability;

DROP FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
);
ALTER FUNCTION sentinelflow.record_execution_result_pre_000027(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) RENAME TO record_execution_result;

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

DROP FUNCTION sentinelflow.commit_hil_revocation_with_session_rotation_000027(
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
);
DROP FUNCTION sentinelflow.issue_hil_revocation_challenge_000027(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    timestamptz, timestamptz, sentinelflow.sha256_digest, uuid, integer,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest
);

DROP TRIGGER revocation_operations_require_exact_hil_000027
    ON sentinelflow.revocation_operations;
DROP FUNCTION sentinelflow.require_revocation_operation_match_000027();

-- Do not restore the pre-000027 direct API mutation authority. There is no
-- downgrade-safe revocation coordinator to mediate it, so fail closed even
-- after an evidence-free downgrade.
REVOKE INSERT, UPDATE, DELETE ON TABLE sentinelflow.revocation_operations
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
     sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;

-- Restore the pre-000027 decision trigger byte-for-byte in behavior.
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
        JOIN sentinelflow.hil_reasons reason
          ON reason.reason_id = NEW.reason_id
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = NEW.policy_id
         AND policy.version = NEW.policy_version
        JOIN sentinelflow.validation_snapshots validation
          ON validation.validation_snapshot_id = NEW.validation_snapshot_id
        JOIN sentinelflow.evidence_snapshots evidence
          ON evidence.evidence_snapshot_id = validation.evidence_snapshot_id
        LEFT JOIN sentinelflow.enforcement_actions action
          ON action.action_id = NEW.action_id
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
          AND reason.actor_id = NEW.actor_id
          AND reason.operation = NEW.operation
          AND reason.reason_digest = NEW.reason_digest
          AND policy.policy_digest = NEW.policy_digest
          AND policy.target_ipv4 = NEW.target_ipv4
          AND evidence.snapshot_digest = NEW.evidence_snapshot_digest
          AND validation.policy_id = NEW.policy_id
          AND validation.policy_version = NEW.policy_version
          AND validation.snapshot_digest = NEW.validation_snapshot_digest
          AND challenge.validation_valid_until = validation.valid_until
          AND (
              (NEW.operation IN ('approve', 'reject') AND
                  action.action_id IS NULL AND
                  policy.state = 'valid' AND
                  validation.state = 'valid' AND
                  validation.valid_until >= NEW.decision_valid_until AND
                  policy.generated_artifact_digest = NEW.generated_artifact_digest AND
                  policy.canonical_artifact_digest = NEW.canonical_artifact_digest) OR
              (NEW.operation = 'revoke' AND
                  action.action_id = NEW.action_id AND
                  action.version = NEW.resource_version AND
                  action.policy_id = NEW.policy_id AND
                  action.policy_version = NEW.policy_version AND
                  action.target_ipv4 = NEW.target_ipv4 AND
                  action.canonical_artifact_digest = NEW.original_add_digest)
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'HIL decision does not match its exact challenge and artifacts';
    END IF;
    RETURN NEW;
END
$function$;

DROP FUNCTION sentinelflow.revocation_authorization_jcs_000027(
    uuid, sentinelflow.ascii_id, uuid, sentinelflow.sha256_digest,
    timestamptz, sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, uuid, integer,
    sentinelflow.canonical_ipv4, timestamptz
);
DROP FUNCTION sentinelflow.revocation_decision_jcs_000027(
    sentinelflow.ascii_id, sentinelflow.sha256_digest, uuid, timestamptz,
    uuid, timestamptz, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, uuid, integer, sentinelflow.sha256_digest,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest
);
DROP FUNCTION sentinelflow.revocation_challenge_jcs_000027(
    timestamptz, sentinelflow.sha256_digest, uuid,
    sentinelflow.sha256_digest, timestamptz, timestamptz,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, uuid, integer, sentinelflow.sha256_digest,
    sentinelflow.canonical_ipv4, sentinelflow.sha256_digest, timestamptz
);
DROP FUNCTION sentinelflow.revocation_artifact_000027(
    sentinelflow.canonical_ipv4
);

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
        ',"requested_at":' || sentinelflow.hil_jcs_string(sentinelflow.hil_rfc3339(p_requested_at)) ||
        ',"scheduler_id":' || sentinelflow.hil_jcs_string(p_scheduler_id::text) ||
        ',"schema_version":"inspection-authorization-v1","target_ipv4":' ||
            sentinelflow.hil_jcs_string(host(p_target_ipv4)) ||
        ',"valid_until":' || sentinelflow.hil_jcs_string(sentinelflow.hil_rfc3339(p_valid_until)) ||
        ',"validation_snapshot_digest":' ||
            sentinelflow.hil_jcs_string(p_validation_snapshot_digest::text) || '}',
        'UTF8'
    );
$function$;

DROP FUNCTION sentinelflow.lifecycle_rfc3339_000027(timestamptz);

DROP INDEX sentinelflow.hil_reasons_actor_operation_digest_000027_idx;
ALTER TABLE sentinelflow.hil_reasons
    ADD CONSTRAINT hil_reasons_reason_digest_key UNIQUE (reason_digest);

DROP INDEX sentinelflow.enforcement_authorizations_add_action_000027_idx;
CREATE UNIQUE INDEX enforcement_authorizations_action_kind_idx
    ON sentinelflow.enforcement_authorizations (action_id, authorization_kind);

DROP INDEX sentinelflow.revocation_operations_action_version_000027_idx;
ALTER TABLE sentinelflow.revocation_operations
    DROP CONSTRAINT revocation_operations_action_version_check,
    DROP CONSTRAINT revocation_operations_artifact_digest_exact,
    DROP COLUMN action_version,
    ADD CONSTRAINT revocation_operations_artifact_digest_key UNIQUE (artifact_digest),
    ADD CONSTRAINT revocation_operations_action_id_key UNIQUE (action_id);

DELETE FROM sentinelflow.schema_migrations WHERE version = 27;

COMMIT;
