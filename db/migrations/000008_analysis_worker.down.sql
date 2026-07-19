BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DROP FUNCTION IF EXISTS sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
);
DROP FUNCTION IF EXISTS sentinelflow.prepare_analysis_attempt(uuid, uuid);
DROP FUNCTION IF EXISTS sentinelflow.lease_analysis_outbox_job(
    timestamptz, uuid, text, timestamptz
);
DROP FUNCTION IF EXISTS sentinelflow.analysis_sha256(bytea);
DROP FUNCTION IF EXISTS sentinelflow.analysis_json_no_duplicate_keys(json);
DROP FUNCTION IF EXISTS sentinelflow.analysis_jsonb_exact_keys(jsonb, text[]);

DROP TABLE IF EXISTS sentinelflow.analysis_output_staging;
DROP TABLE IF EXISTS sentinelflow.analysis_attempt_results;
DROP TABLE IF EXISTS sentinelflow.analysis_attempt_claims;

GRANT SELECT, INSERT, UPDATE ON sentinelflow.ai_analyses TO sentinelflow_worker;
GRANT SELECT, INSERT ON sentinelflow.analysis_false_positive_factors,
    sentinelflow.analysis_evidence TO sentinelflow_worker;
GRANT UPDATE ON sentinelflow.incidents TO sentinelflow_worker;

DELETE FROM sentinelflow.schema_migrations WHERE version = 8;

COMMIT;
