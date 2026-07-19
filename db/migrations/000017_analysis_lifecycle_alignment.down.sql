BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $fail_stop$
BEGIN
    IF EXISTS (
        SELECT 1 FROM analysis_attempt_claims
        WHERE analyzing_incident_version IS NOT NULL
           OR terminal_incident_version IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM incident_version_history
        WHERE mutation_kind = 'state_changed'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cannot discard durable analysis lifecycle evidence';
    END IF;
END
$fail_stop$;

DROP TRIGGER IF EXISTS analysis_attempt_claim_lifecycle_000017
    ON analysis_attempt_claims;
DROP FUNCTION IF EXISTS sentinelflow.enforce_analysis_claim_lifecycle_000017();
DROP FUNCTION IF EXISTS sentinelflow.prepare_analysis_attempt(uuid, uuid);
DROP FUNCTION IF EXISTS sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
);
DROP FUNCTION IF EXISTS sentinelflow.interrupt_analysis_for_new_evidence_000017(
    uuid, integer
);
DROP FUNCTION IF EXISTS sentinelflow.advance_analysis_incident_lifecycle_000017(
    uuid, integer, text, text, text, uuid
);
DROP FUNCTION IF EXISTS sentinelflow.finalize_analysis_attempt_lifecycle_000017(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
);

DO $restore_analysis_functions$
BEGIN
    IF to_regprocedure(
        'sentinelflow.prepare_analysis_attempt_pre_000017(uuid,uuid)'
    ) IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.prepare_analysis_attempt_pre_000017(
            uuid, uuid
        ) RENAME TO prepare_analysis_attempt;
    END IF;
    IF to_regprocedure(
        'sentinelflow.finalize_analysis_attempt_pre_000017('
        'uuid,uuid,text,timestamptz,timestamptz,text,text,jsonb)'
    ) IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.finalize_analysis_attempt_pre_000017(
            uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
        ) RENAME TO finalize_analysis_attempt;
    END IF;
END
$restore_analysis_functions$;

DO $restore_analysis_signal_limit$
DECLARE
    definition text;
BEGIN
    SELECT pg_get_functiondef(
        'sentinelflow.prepare_analysis_attempt_legacy(uuid,uuid)'::regprocedure
    ) INTO definition;
    IF position('evidence.signal_count > 50' IN definition) > 0 THEN
        definition := replace(
            definition,
            'evidence.signal_count > 50',
            'evidence.signal_count > 16'
        );
        EXECUTE definition;
    ELSIF position('evidence.signal_count > 16' IN definition) = 0 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'analysis prepare signal-limit rollback source drift';
    END IF;
END
$restore_analysis_signal_limit$;

REVOKE UPDATE (evidence_version) ON incidents FROM sentinelflow_worker;

ALTER TABLE analysis_attempt_claims
    DROP CONSTRAINT IF EXISTS analysis_attempt_claim_lifecycle_order,
    DROP COLUMN IF EXISTS terminal_incident_version,
    DROP COLUMN IF EXISTS analyzing_incident_version;
ALTER TABLE incidents
    DROP CONSTRAINT IF EXISTS incident_evidence_version_order,
    DROP COLUMN IF EXISTS evidence_version;

REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) TO sentinelflow_worker;

DELETE FROM sentinelflow.schema_migrations
WHERE version = 17 AND name = 'analysis_lifecycle_alignment';

COMMIT;
