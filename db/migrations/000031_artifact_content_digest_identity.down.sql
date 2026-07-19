BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 31 AND name = 'artifact_content_digest_identity'
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE (constraint_record.conrelid =
                   'sentinelflow.command_candidates'::regclass
               AND constraint_record.conname IN (
                   'command_candidates_generated_artifact_digest_key',
                   'command_candidates_canonical_artifact_digest_key'
               )) OR
              (constraint_record.conrelid =
                   'sentinelflow.enforcement_actions'::regclass
               AND constraint_record.conname =
                   'enforcement_actions_canonical_artifact_digest_key') OR
              (constraint_record.conrelid =
                   'sentinelflow.lifecycle_inspection_artifacts_000026'::regclass
               AND constraint_record.conname =
                   'lifecycle_inspection_artifacts_0000_inspect_artifact_digest_key')
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'artifact content digest downgrade preflight failed';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM sentinelflow.command_candidates candidate
        GROUP BY candidate.generated_artifact_digest
        HAVING count(*) > 1
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.command_candidates candidate
        WHERE candidate.canonical_artifact_digest IS NOT NULL
        GROUP BY candidate.canonical_artifact_digest
        HAVING count(*) > 1
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.enforcement_actions action_record
        GROUP BY action_record.canonical_artifact_digest
        HAVING count(*) > 1
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.lifecycle_inspection_artifacts_000026 artifact
        GROUP BY artifact.inspect_artifact_digest
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'shared artifact content digests prevent downgrade';
    END IF;
END
$preflight$;

DROP INDEX sentinelflow.command_candidates_generated_artifact_digest_idx;
DROP INDEX sentinelflow.command_candidates_canonical_artifact_digest_idx;
DROP INDEX sentinelflow.enforcement_actions_canonical_artifact_digest_idx;
DROP INDEX sentinelflow.lifecycle_inspection_artifact_digest_000031_idx;

ALTER TABLE sentinelflow.command_candidates
    ADD CONSTRAINT command_candidates_generated_artifact_digest_key
        UNIQUE (generated_artifact_digest),
    ADD CONSTRAINT command_candidates_canonical_artifact_digest_key
        UNIQUE (canonical_artifact_digest);

ALTER TABLE sentinelflow.enforcement_actions
    ADD CONSTRAINT enforcement_actions_canonical_artifact_digest_key
        UNIQUE (canonical_artifact_digest);

ALTER TABLE sentinelflow.lifecycle_inspection_artifacts_000026
    ADD CONSTRAINT lifecycle_inspection_artifacts_0000_inspect_artifact_digest_key
        UNIQUE (inspect_artifact_digest);

DELETE FROM sentinelflow.schema_migrations WHERE version = 31;

COMMIT;
