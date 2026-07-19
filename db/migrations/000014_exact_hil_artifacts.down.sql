BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $fail_stop$
BEGIN
    IF EXISTS (SELECT 1 FROM sentinelflow.evidence_snapshot_artifacts) OR
       EXISTS (SELECT 1 FROM sentinelflow.hil_exact_artifacts) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'refusing to discard canonical HIL authority artifacts';
    END IF;
END
$fail_stop$;

DROP FUNCTION IF EXISTS sentinelflow.read_hil_exact_artifact(uuid, integer);
DROP FUNCTION IF EXISTS sentinelflow.finalize_validation_attempt_exact(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json, bytea
);
DROP FUNCTION IF EXISTS sentinelflow.finalize_validation_attempt_normalized(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json
);
DROP FUNCTION IF EXISTS sentinelflow.insert_exact_evidence_snapshot(json, bytea);

DROP FUNCTION IF EXISTS sentinelflow.prepare_analysis_attempt(uuid, uuid);
DO $restore_analysis_prepare$
BEGIN
    IF to_regprocedure('sentinelflow.prepare_analysis_attempt_legacy(uuid,uuid)') IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.prepare_analysis_attempt_legacy(uuid, uuid)
            RENAME TO prepare_analysis_attempt;
    END IF;
END
$restore_analysis_prepare$;

DROP FUNCTION IF EXISTS sentinelflow.prepare_validation_attempt_exact(uuid, uuid);

DROP TRIGGER IF EXISTS hil_exact_artifacts_immutable
    ON sentinelflow.hil_exact_artifacts;
DROP TRIGGER IF EXISTS evidence_snapshot_artifacts_immutable
    ON sentinelflow.evidence_snapshot_artifacts;
DROP TABLE IF EXISTS sentinelflow.hil_exact_artifacts;
DROP TABLE IF EXISTS sentinelflow.evidence_snapshot_artifacts;
DROP FUNCTION IF EXISTS sentinelflow.reject_exact_artifact_mutation();

GRANT INSERT ON sentinelflow.evidence_snapshots,
    sentinelflow.evidence_snapshot_signals,
    sentinelflow.evidence_snapshot_events TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_validation_attempt(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_validation_attempt(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_validation_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_validation_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json
) TO sentinelflow_worker;

DELETE FROM sentinelflow.schema_migrations
WHERE version = 14 AND name = 'exact_hil_artifacts';

COMMIT;
