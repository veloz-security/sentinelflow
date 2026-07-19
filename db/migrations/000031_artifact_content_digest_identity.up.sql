BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Artifact digests attest immutable content; they do not identify an
-- evidence-bound candidate, enforcement action, or inspection schedule. The
-- same canonical bytes can legitimately recur under distinct exact bindings.
DO $preflight$
DECLARE
    generated_attnum smallint;
    canonical_attnum smallint;
    action_artifact_attnum smallint;
    inspect_artifact_attnum smallint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 30 AND name = 'demo_history_runtime_activation'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations WHERE version = 31
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'artifact content digest identity requires the exact version-30 prefix';
    END IF;

    SELECT attribute.attnum::smallint
    INTO generated_attnum
    FROM pg_catalog.pg_attribute attribute
    WHERE attribute.attrelid = 'sentinelflow.command_candidates'::regclass
      AND attribute.attname = 'generated_artifact_digest'
      AND NOT attribute.attisdropped;

    SELECT attribute.attnum::smallint
    INTO canonical_attnum
    FROM pg_catalog.pg_attribute attribute
    WHERE attribute.attrelid = 'sentinelflow.command_candidates'::regclass
      AND attribute.attname = 'canonical_artifact_digest'
      AND NOT attribute.attisdropped;

    SELECT attribute.attnum::smallint
    INTO action_artifact_attnum
    FROM pg_catalog.pg_attribute attribute
    WHERE attribute.attrelid = 'sentinelflow.enforcement_actions'::regclass
      AND attribute.attname = 'canonical_artifact_digest'
      AND NOT attribute.attisdropped;

    SELECT attribute.attnum::smallint
    INTO inspect_artifact_attnum
    FROM pg_catalog.pg_attribute attribute
    WHERE attribute.attrelid =
          'sentinelflow.lifecycle_inspection_artifacts_000026'::regclass
      AND attribute.attname = 'inspect_artifact_digest'
      AND NOT attribute.attisdropped;

    IF generated_attnum IS NULL OR canonical_attnum IS NULL OR
       action_artifact_attnum IS NULL OR inspect_artifact_attnum IS NULL OR
       NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE constraint_record.conrelid = 'sentinelflow.command_candidates'::regclass
          AND constraint_record.conname =
              'command_candidates_generated_artifact_digest_key'
          AND constraint_record.contype = 'u'
          AND constraint_record.conkey = ARRAY[generated_attnum]::smallint[]
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE constraint_record.conrelid = 'sentinelflow.command_candidates'::regclass
          AND constraint_record.conname =
              'command_candidates_canonical_artifact_digest_key'
          AND constraint_record.contype = 'u'
          AND constraint_record.conkey = ARRAY[canonical_attnum]::smallint[]
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE constraint_record.conrelid = 'sentinelflow.enforcement_actions'::regclass
          AND constraint_record.conname =
              'enforcement_actions_canonical_artifact_digest_key'
          AND constraint_record.contype = 'u'
          AND constraint_record.conkey = ARRAY[action_artifact_attnum]::smallint[]
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE constraint_record.conrelid =
              'sentinelflow.lifecycle_inspection_artifacts_000026'::regclass
          AND constraint_record.conname =
              'lifecycle_inspection_artifacts_0000_inspect_artifact_digest_key'
          AND constraint_record.contype = 'u'
          AND constraint_record.conkey = ARRAY[inspect_artifact_attnum]::smallint[]
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'content digest constraints are not canonical';
    END IF;
END
$preflight$;

ALTER TABLE sentinelflow.command_candidates
    DROP CONSTRAINT command_candidates_generated_artifact_digest_key,
    DROP CONSTRAINT command_candidates_canonical_artifact_digest_key;

ALTER TABLE sentinelflow.enforcement_actions
    DROP CONSTRAINT enforcement_actions_canonical_artifact_digest_key;

ALTER TABLE sentinelflow.lifecycle_inspection_artifacts_000026
    DROP CONSTRAINT lifecycle_inspection_artifacts_0000_inspect_artifact_digest_key;

-- Preserve forensic/content-address lookup access without assigning row
-- identity semantics to a digest.
CREATE INDEX command_candidates_generated_artifact_digest_idx
    ON sentinelflow.command_candidates (generated_artifact_digest);
CREATE INDEX command_candidates_canonical_artifact_digest_idx
    ON sentinelflow.command_candidates (canonical_artifact_digest);
CREATE INDEX enforcement_actions_canonical_artifact_digest_idx
    ON sentinelflow.enforcement_actions (canonical_artifact_digest);
CREATE INDEX lifecycle_inspection_artifact_digest_000031_idx
    ON sentinelflow.lifecycle_inspection_artifacts_000026
       (inspect_artifact_digest);

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (31, 'artifact_content_digest_identity');

COMMIT;
