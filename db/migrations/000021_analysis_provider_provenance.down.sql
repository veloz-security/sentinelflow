BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $provider_rollback_fail_stop$
BEGIN
    IF EXISTS (
        SELECT 1 FROM ai_analyses WHERE provider_kind = 'deterministic_stub'
    ) OR EXISTS (
        SELECT 1 FROM analysis_attempt_results
        WHERE provider_kind = 'deterministic_stub'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cannot discard deterministic stub provenance';
    END IF;
END
$provider_rollback_fail_stop$;

DROP TRIGGER IF EXISTS analyses_provider_immutable_000021 ON ai_analyses;
DROP TRIGGER IF EXISTS analysis_results_provider_immutable_000021
    ON analysis_attempt_results;
DROP TRIGGER IF EXISTS analysis_result_provider_default_000021
    ON analysis_attempt_results;
DROP FUNCTION IF EXISTS sentinelflow.guard_analysis_provenance_update_000021();
DROP FUNCTION IF EXISTS sentinelflow.guard_analysis_result_provenance_update_000021();
DROP FUNCTION IF EXISTS sentinelflow.default_analysis_result_provider_000021();

DROP FUNCTION IF EXISTS sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
);
DO $restore_analysis_finalizer_000021$
BEGIN
    IF to_regprocedure(
        'sentinelflow.finalize_analysis_attempt_pre_000021('
        'uuid,uuid,text,timestamptz,timestamptz,text,text,jsonb)'
    ) IS NOT NULL THEN
        ALTER FUNCTION sentinelflow.finalize_analysis_attempt_pre_000021(
            uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
        ) RENAME TO finalize_analysis_attempt;
    END IF;
END
$restore_analysis_finalizer_000021$;

ALTER TABLE analysis_attempt_results
    DROP CONSTRAINT IF EXISTS analysis_attempt_result_shape,
    DROP CONSTRAINT IF EXISTS analysis_attempt_provider_usage_shape;
ALTER TABLE analysis_attempt_results
    ADD CONSTRAINT analysis_attempt_result_shape CHECK (
        (result_state = 'succeeded' AND failure_reason IS NULL AND retry_eligible = false AND
            provider_attempts BETWEEN 1 AND 2 AND provider_response_id IS NOT NULL AND
            model IS NOT NULL AND reasoning_effort IS NOT NULL AND rate_card_version IS NOT NULL AND
            input_bytes >= 2 AND input_digest IS NOT NULL AND input_schema_digest IS NOT NULL AND
            prompt_digest IS NOT NULL AND output_schema_digest IS NOT NULL AND
            output_digest IS NOT NULL AND generated_command_digest IS NOT NULL) OR
        (result_state = 'failed' AND failure_reason IS NOT NULL AND
            provider_response_id IS NULL AND model IS NULL AND reasoning_effort IS NULL AND
            rate_card_version IS NULL AND input_schema_digest IS NULL AND prompt_digest IS NULL AND
            output_schema_digest IS NULL AND output_digest IS NULL AND generated_command_digest IS NULL AND
            input_tokens IS NULL AND cached_input_tokens IS NULL AND output_tokens IS NULL AND
            ((input_bytes = 0 AND input_digest IS NULL) OR (input_bytes >= 2 AND input_digest IS NOT NULL))) OR
        (result_state IN ('interrupted', 'no_call') AND failure_reason IS NOT NULL AND
            retry_eligible = false AND provider_attempts = 0 AND provider_response_id IS NULL AND
            model IS NULL AND reasoning_effort IS NULL AND rate_card_version IS NULL AND
            input_bytes = 0 AND input_digest IS NULL AND input_schema_digest IS NULL AND
            prompt_digest IS NULL AND output_schema_digest IS NULL AND output_digest IS NULL AND
            generated_command_digest IS NULL AND input_tokens IS NULL AND
            cached_input_tokens IS NULL AND output_tokens IS NULL)
    );
ALTER TABLE analysis_attempt_results
    DROP COLUMN IF EXISTS adapter_id,
    DROP COLUMN IF EXISTS provider_kind;

ALTER TABLE ai_analyses
    DROP CONSTRAINT IF EXISTS ai_analysis_provider_shape,
    ALTER COLUMN model SET NOT NULL,
    ALTER COLUMN reasoning_effort SET NOT NULL,
    ADD CONSTRAINT ai_analyses_reasoning_effort_check CHECK (reasoning_effort = 'medium'),
    DROP COLUMN IF EXISTS rate_card_version,
    DROP COLUMN IF EXISTS adapter_id,
    DROP COLUMN IF EXISTS provider_kind;

REVOKE ALL ON FUNCTION sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) TO sentinelflow_worker;

DELETE FROM sentinelflow.schema_migrations
WHERE version = 21 AND name = 'analysis_provider_provenance';

COMMIT;
