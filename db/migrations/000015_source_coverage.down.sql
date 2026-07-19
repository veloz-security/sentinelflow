BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $fail_stop$
BEGIN
    IF EXISTS (SELECT 1 FROM source_coverage_attestations) OR
       EXISTS (SELECT 1 FROM expected_source_bindings) OR
       EXISTS (SELECT 1 FROM expected_source_binding_retirements) OR
       EXISTS (SELECT 1 FROM ingest_gap_lifecycle) OR
       EXISTS (SELECT 1 FROM ingest_batches WHERE auth_key_id IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cannot discard live source coverage authority or evidence';
    END IF;
END
$fail_stop$;

DROP TRIGGER IF EXISTS ingest_sequence_gap_resolution_lifecycle
    ON sentinelflow.ingest_sequence_gap_resolutions;
DROP TRIGGER IF EXISTS ingest_sequence_gap_opened_lifecycle
    ON sentinelflow.ingest_sequence_gaps;
DROP FUNCTION IF EXISTS sentinelflow.record_ingest_gap_resolution();
DROP FUNCTION IF EXISTS sentinelflow.record_ingest_gap_opened();
DROP FUNCTION IF EXISTS sentinelflow.append_source_coverage_attestation(
    uuid, text, text, text, text, uuid, text, timestamptz, timestamptz,
    uuid, bigint, integer, text, text
);
DROP FUNCTION IF EXISTS sentinelflow.retire_expected_source_binding(uuid, uuid, text);
DROP FUNCTION IF EXISTS sentinelflow.register_expected_source_binding(
    uuid, text, text, text, text, text
);
DROP FUNCTION IF EXISTS sentinelflow.append_ingest_detect_outbox(
    text, uuid, text, uuid, text
);
DROP FUNCTION IF EXISTS sentinelflow.source_coverage_sha256(bytea);
DROP FUNCTION IF EXISTS sentinelflow.source_coverage_canonical(
    uuid, text, text, text, uuid, text, timestamptz, timestamptz, uuid, bigint
);

DROP TABLE IF EXISTS sentinelflow.ingest_gap_lifecycle;
DROP TABLE IF EXISTS sentinelflow.source_coverage_attestations;
DROP TABLE IF EXISTS sentinelflow.expected_source_binding_retirements;
DROP TABLE IF EXISTS sentinelflow.expected_source_bindings;
DROP FUNCTION IF EXISTS sentinelflow.reject_source_coverage_mutation();

ALTER TABLE sentinelflow.ingest_batches DROP COLUMN IF EXISTS auth_key_id;

DELETE FROM sentinelflow.schema_migrations WHERE version = 15;

COMMIT;
