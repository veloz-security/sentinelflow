BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $preflight$
BEGIN
    IF EXISTS (SELECT 1 FROM sentinelflow.lifecycle_inspection_schedules_000026) OR
       EXISTS (SELECT 1 FROM sentinelflow.lifecycle_inspection_artifacts_000026) OR
       EXISTS (SELECT 1 FROM sentinelflow.lifecycle_capability_applications_000026) OR
       EXISTS (SELECT 1 FROM sentinelflow.lifecycle_result_applications_000026) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'enforcement lifecycle downgrade blocked by durable lifecycle evidence';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.outbox_jobs
        WHERE kind = 'dispatch_inspect'
        GROUP BY kind, aggregate_type, aggregate_id, aggregate_version, operation
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'enforcement lifecycle downgrade blocked by repeated inspection jobs';
    END IF;
END
$preflight$;

REVOKE ALL ON FUNCTION sentinelflow.claim_lifecycle_inspection_schedule_000026(
    sentinelflow.ascii_id, sentinelflow.ascii_id, integer
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_retention, sentinelflow_lifecycle;
REVOKE ALL ON FUNCTION sentinelflow.commit_lifecycle_inspection_000026(
    uuid, uuid, integer, sentinelflow.ascii_id, uuid, bytea,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_retention, sentinelflow_lifecycle;
REVOKE ALL ON FUNCTION sentinelflow.finish_lifecycle_inspection_failure_000026(
    uuid, uuid, integer, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, integer
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_retention, sentinelflow_lifecycle;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_lifecycle, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_lifecycle, sentinelflow_dispatcher;

DROP FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
);
ALTER FUNCTION sentinelflow.record_execution_capability_pre_000026(
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
ALTER FUNCTION sentinelflow.record_execution_result_pre_000026(
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

DROP TRIGGER enforcement_actions_transition_000026
    ON sentinelflow.enforcement_actions;
DROP FUNCTION sentinelflow.enforce_action_transition_000026();
DROP FUNCTION sentinelflow.claim_lifecycle_inspection_schedule_000026(
    sentinelflow.ascii_id, sentinelflow.ascii_id, integer
);
DROP FUNCTION sentinelflow.commit_lifecycle_inspection_000026(
    uuid, uuid, integer, sentinelflow.ascii_id, uuid, bytea,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest
);
DROP FUNCTION sentinelflow.finish_lifecycle_inspection_failure_000026(
    uuid, uuid, integer, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, integer
);

DROP TABLE sentinelflow.lifecycle_result_applications_000026;
DROP TABLE sentinelflow.lifecycle_capability_applications_000026;
DROP TABLE sentinelflow.lifecycle_inspection_artifacts_000026;
DROP TABLE sentinelflow.lifecycle_inspection_schedules_000026;

DROP FUNCTION sentinelflow.lifecycle_inspection_authorization_jcs_000026(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, uuid, integer,
    text, timestamptz, sentinelflow.ascii_id, sentinelflow.canonical_ipv4,
    timestamptz, sentinelflow.sha256_digest
);
DROP FUNCTION sentinelflow.lifecycle_schedule_idempotency_000026(uuid);
DROP FUNCTION sentinelflow.lifecycle_inspect_jcs_000026(
    uuid, sentinelflow.canonical_ipv4, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, text
);

DROP INDEX sentinelflow.outbox_jobs_business_effect_idx;
CREATE UNIQUE INDEX outbox_jobs_business_effect_idx
    ON sentinelflow.outbox_jobs (
        kind, aggregate_type, aggregate_id, aggregate_version, operation
    ) NULLS NOT DISTINCT;

DELETE FROM sentinelflow.schema_migrations WHERE version = 26;

RESET ROLE;

DO $drop_lifecycle_role$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinelflow_lifecycle') THEN
        EXECUTE format(
            'REVOKE CONNECT ON DATABASE %I FROM sentinelflow_lifecycle', current_database()
        );
        EXECUTE format(
            'ALTER ROLE sentinelflow_lifecycle IN DATABASE %I RESET search_path',
            current_database()
        );
        REVOKE USAGE ON SCHEMA sentinelflow FROM sentinelflow_lifecycle;
        DROP ROLE sentinelflow_lifecycle;
    END IF;
END
$drop_lifecycle_role$;

COMMIT;
