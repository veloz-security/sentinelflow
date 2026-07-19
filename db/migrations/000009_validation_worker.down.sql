BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DROP FUNCTION IF EXISTS sentinelflow.finalize_validation_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json
);
DROP FUNCTION IF EXISTS sentinelflow.prepare_validation_attempt(uuid, uuid);
DROP FUNCTION IF EXISTS sentinelflow.lease_validation_outbox_job(
    timestamptz, uuid, text, timestamptz
);
DROP FUNCTION IF EXISTS sentinelflow.validation_json_no_duplicate_keys(json);
DROP FUNCTION IF EXISTS sentinelflow.validation_jsonb_exact_keys(jsonb, text[]);
DROP FUNCTION IF EXISTS sentinelflow.validation_sha256(bytea);

DROP TABLE IF EXISTS sentinelflow.validation_attempt_results;
DROP TABLE IF EXISTS sentinelflow.validation_attempt_gates;
DROP TABLE IF EXISTS sentinelflow.validation_attempt_claims;

-- Restore the grants present immediately before migration 000009.
GRANT SELECT, INSERT, UPDATE ON sentinelflow.command_candidates,
    sentinelflow.validation_snapshots,
    sentinelflow.validation_gates
TO sentinelflow_worker;
GRANT SELECT, INSERT ON sentinelflow.policy_proposals TO sentinelflow_worker;
GRANT UPDATE (state, state_revision, updated_at)
    ON sentinelflow.policy_proposals TO sentinelflow_worker;

DELETE FROM sentinelflow.schema_migrations
WHERE version = 9 AND name = 'validation_worker';

COMMIT;
