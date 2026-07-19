BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

ALTER TABLE ai_analyses
    ADD COLUMN IF NOT EXISTS provider_kind text NULL,
    ADD COLUMN IF NOT EXISTS adapter_id ascii_id NULL,
    ADD COLUMN IF NOT EXISTS rate_card_version ascii_id NULL;
ALTER TABLE analysis_attempt_results
    ADD COLUMN IF NOT EXISTS provider_kind text NULL,
    ADD COLUMN IF NOT EXISTS adapter_id ascii_id NULL;

-- The old schema admitted only the frozen OpenAI model/reasoning pair. A row
-- that cannot also be tied to its successful attempt result is ambiguous and
-- must be reconciled offline instead of being guessed into a provider class.
DO $backfill_analysis_provider_provenance$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.ai_analyses analysis
        LEFT JOIN sentinelflow.analysis_attempt_results result
          ON result.analysis_id = analysis.analysis_id
        WHERE analysis.provider_kind IS NULL AND (
            analysis.model <> 'gpt-5.6-sol' OR
            analysis.reasoning_effort <> 'medium' OR
            result.analysis_id IS NULL OR result.result_state <> 'succeeded' OR
            result.model IS DISTINCT FROM analysis.model OR
            result.reasoning_effort IS DISTINCT FROM analysis.reasoning_effort OR
            result.rate_card_version IS NULL
        )
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.analysis_attempt_results result
        WHERE result.result_state = 'succeeded'
          AND result.provider_kind IS NULL
          AND (result.model <> 'gpt-5.6-sol' OR
               result.reasoning_effort <> 'medium' OR
               result.rate_card_version IS NULL)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'legacy analysis provider provenance is ambiguous';
    END IF;

    UPDATE sentinelflow.analysis_attempt_results
    SET provider_kind = 'openai_responses',
        adapter_id = 'openai-responses-v1'
    WHERE result_state = 'succeeded' AND provider_kind IS NULL;

    UPDATE sentinelflow.ai_analyses analysis
    SET provider_kind = 'openai_responses',
        adapter_id = 'openai-responses-v1',
        rate_card_version = result.rate_card_version
    FROM sentinelflow.analysis_attempt_results result
    WHERE result.analysis_id = analysis.analysis_id
      AND analysis.provider_kind IS NULL
      AND result.result_state = 'succeeded';

    IF EXISTS (
        SELECT 1 FROM sentinelflow.ai_analyses WHERE provider_kind IS NULL
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.analysis_attempt_results
        WHERE result_state = 'succeeded' AND provider_kind IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'analysis provider provenance backfill incomplete';
    END IF;
END
$backfill_analysis_provider_provenance$;

ALTER TABLE ai_analyses
    ALTER COLUMN model DROP NOT NULL,
    ALTER COLUMN reasoning_effort DROP NOT NULL,
    ALTER COLUMN provider_kind SET DEFAULT 'openai_responses',
    ALTER COLUMN adapter_id SET DEFAULT 'openai-responses-v1',
    ALTER COLUMN provider_kind SET NOT NULL,
    ALTER COLUMN adapter_id SET NOT NULL,
    DROP CONSTRAINT IF EXISTS ai_analyses_reasoning_effort_check,
    DROP CONSTRAINT IF EXISTS ai_analysis_provider_shape;
ALTER TABLE ai_analyses
    ADD CONSTRAINT ai_analysis_provider_shape CHECK (
        (provider_kind = 'openai_responses' AND
         adapter_id = 'openai-responses-v1' AND
         model = 'gpt-5.6-sol' AND reasoning_effort = 'medium') OR
        (provider_kind = 'deterministic_stub' AND
         adapter_id = 'sentinelflow-deterministic-ai-stub-v1' AND
         model IS NULL AND reasoning_effort IS NULL AND
         rate_card_version IS NULL AND input_tokens IS NULL AND
         cached_input_tokens IS NULL AND output_tokens IS NULL)
    );

-- Compatibility inserts made by the preserved finalizer do not yet carry the
-- two new fields. Classify only successful legacy-shaped rows; failure/no-call
-- rows remain provider-neutral because no successful analysis was persisted.
CREATE OR REPLACE FUNCTION sentinelflow.default_analysis_result_provider_000021()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NEW.result_state = 'succeeded' AND
       NEW.provider_kind IS NULL AND NEW.adapter_id IS NULL THEN
        NEW.provider_kind := 'openai_responses';
        NEW.adapter_id := 'openai-responses-v1';
    ELSIF (NEW.provider_kind IS NULL) <> (NEW.adapter_id IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'analysis result provider identity is incomplete';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS analysis_result_provider_default_000021
    ON analysis_attempt_results;
CREATE TRIGGER analysis_result_provider_default_000021
BEFORE INSERT ON analysis_attempt_results
FOR EACH ROW EXECUTE FUNCTION sentinelflow.default_analysis_result_provider_000021();

ALTER TABLE analysis_attempt_results
    DROP CONSTRAINT IF EXISTS analysis_attempt_result_shape,
    DROP CONSTRAINT IF EXISTS analysis_attempt_provider_usage_shape;
ALTER TABLE analysis_attempt_results
    ADD CONSTRAINT analysis_attempt_result_shape CHECK (
        (result_state = 'succeeded' AND failure_reason IS NULL AND
            retry_eligible = false AND provider_attempts BETWEEN 1 AND 2 AND
            provider_response_id IS NOT NULL AND provider_kind IS NOT NULL AND
            adapter_id IS NOT NULL AND input_bytes >= 2 AND input_digest IS NOT NULL AND
            input_schema_digest IS NOT NULL AND prompt_digest IS NOT NULL AND
            output_schema_digest IS NOT NULL AND output_digest IS NOT NULL AND
            generated_command_digest IS NOT NULL AND (
                (provider_kind = 'openai_responses' AND
                 adapter_id = 'openai-responses-v1' AND model = 'gpt-5.6-sol' AND
                 reasoning_effort = 'medium' AND rate_card_version IS NOT NULL) OR
                (provider_kind = 'deterministic_stub' AND
                 adapter_id = 'sentinelflow-deterministic-ai-stub-v1' AND
                 provider_response_id ~ '^stub_[0-9a-f]{64}$' AND
                 model IS NULL AND reasoning_effort IS NULL AND rate_card_version IS NULL)
            )) OR
        (result_state = 'failed' AND failure_reason IS NOT NULL AND
            provider_kind IS NULL AND adapter_id IS NULL AND
            provider_response_id IS NULL AND model IS NULL AND reasoning_effort IS NULL AND
            rate_card_version IS NULL AND input_schema_digest IS NULL AND prompt_digest IS NULL AND
            output_schema_digest IS NULL AND output_digest IS NULL AND generated_command_digest IS NULL AND
            input_tokens IS NULL AND cached_input_tokens IS NULL AND output_tokens IS NULL AND
            ((input_bytes = 0 AND input_digest IS NULL) OR
             (input_bytes >= 2 AND input_digest IS NOT NULL))) OR
        (result_state IN ('interrupted', 'no_call') AND failure_reason IS NOT NULL AND
            retry_eligible = false AND provider_attempts = 0 AND
            provider_kind IS NULL AND adapter_id IS NULL AND
            provider_response_id IS NULL AND model IS NULL AND reasoning_effort IS NULL AND
            rate_card_version IS NULL AND input_bytes = 0 AND input_digest IS NULL AND
            input_schema_digest IS NULL AND prompt_digest IS NULL AND
            output_schema_digest IS NULL AND output_digest IS NULL AND
            generated_command_digest IS NULL AND input_tokens IS NULL AND
            cached_input_tokens IS NULL AND output_tokens IS NULL)
    ),
    ADD CONSTRAINT analysis_attempt_provider_usage_shape CHECK (
        provider_kind IS DISTINCT FROM 'deterministic_stub' OR
        (input_tokens IS NULL AND cached_input_tokens IS NULL AND output_tokens IS NULL)
    );

-- Only the 000021 finalizer may complete the one-time provider seal after its
-- preserved compatibility call. Once sealed, provenance and every other row
-- field are immutable.
CREATE OR REPLACE FUNCTION sentinelflow.guard_analysis_provenance_update_000021()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF to_jsonb(NEW) - ARRAY[
        'provider_kind', 'adapter_id', 'model', 'reasoning_effort', 'rate_card_version'
    ] IS DISTINCT FROM to_jsonb(OLD) - ARRAY[
        'provider_kind', 'adapter_id', 'model', 'reasoning_effort', 'rate_card_version'
    ] THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'analysis row is immutable';
    END IF;
    IF OLD.provider_kind <> 'openai_responses' OR
       OLD.adapter_id <> 'openai-responses-v1' OR
       OLD.model <> 'gpt-5.6-sol' OR OLD.reasoning_effort <> 'medium' OR
       OLD.rate_card_version IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'analysis provider provenance is immutable';
    END IF;
    IF NOT (
        (NEW.provider_kind = 'openai_responses' AND
         NEW.adapter_id = 'openai-responses-v1' AND
         NEW.model = 'gpt-5.6-sol' AND NEW.reasoning_effort = 'medium' AND
         NEW.rate_card_version IS NOT NULL) OR
        (NEW.provider_kind = 'deterministic_stub' AND
         NEW.adapter_id = 'sentinelflow-deterministic-ai-stub-v1' AND
         NEW.model IS NULL AND NEW.reasoning_effort IS NULL AND
         NEW.rate_card_version IS NULL)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'invalid analysis provider seal';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.guard_analysis_result_provenance_update_000021()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF to_jsonb(NEW) - ARRAY[
        'provider_kind', 'adapter_id', 'model', 'reasoning_effort', 'rate_card_version'
    ] IS DISTINCT FROM to_jsonb(OLD) - ARRAY[
        'provider_kind', 'adapter_id', 'model', 'reasoning_effort', 'rate_card_version'
    ] OR OLD.result_state <> 'succeeded' OR
       OLD.provider_kind <> 'openai_responses' OR
       OLD.adapter_id <> 'openai-responses-v1' OR
       OLD.model <> 'gpt-5.6-sol' OR OLD.reasoning_effort <> 'medium' OR
       OLD.rate_card_version <> 'stub-internal-placeholder-v1' OR
       NEW.provider_kind <> 'deterministic_stub' OR
       NEW.adapter_id <> 'sentinelflow-deterministic-ai-stub-v1' OR
       NEW.model IS NOT NULL OR NEW.reasoning_effort IS NOT NULL OR
       NEW.rate_card_version IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'analysis result provider provenance is immutable';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS analyses_provider_immutable_000021 ON ai_analyses;
CREATE TRIGGER analyses_provider_immutable_000021
BEFORE UPDATE ON ai_analyses
FOR EACH ROW EXECUTE FUNCTION sentinelflow.guard_analysis_provenance_update_000021();
DROP TRIGGER IF EXISTS analysis_results_provider_immutable_000021
    ON analysis_attempt_results;
CREATE TRIGGER analysis_results_provider_immutable_000021
BEFORE UPDATE ON analysis_attempt_results
FOR EACH ROW EXECUTE FUNCTION sentinelflow.guard_analysis_result_provenance_update_000021();

-- Preserve the lifecycle-aware 000017 public finalizer. The new wrapper adds
-- provider validation, then passes a compatibility document to that exact
-- atomic implementation. Stub compatibility values exist only inside this
-- transaction and are replaced before the function can return successfully.
DO $preserve_analysis_finalizer_000021$
DECLARE
    definition text;
BEGIN
    IF to_regprocedure(
        'sentinelflow.finalize_analysis_attempt_pre_000021('
        'uuid,uuid,text,timestamptz,timestamptz,text,text,jsonb)'
    ) IS NULL THEN
        SELECT pg_get_functiondef(
            'sentinelflow.finalize_analysis_attempt('
            'uuid,uuid,text,timestamptz,timestamptz,text,text,jsonb)'::regprocedure
        ) INTO definition;
        IF regexp_count(definition, 'finalize_analysis_attempt_lifecycle_000017') <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'analysis finalizer provider-wrapper source drift';
        END IF;
        ALTER FUNCTION sentinelflow.finalize_analysis_attempt(
            uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
        ) RENAME TO finalize_analysis_attempt_pre_000021;
    END IF;
END
$preserve_analysis_finalizer_000021$;

CREATE OR REPLACE FUNCTION sentinelflow.finalize_analysis_attempt(
    p_job_id uuid,
    p_lease_token uuid,
    p_finish_state text,
    p_retry_at timestamptz,
    p_client_now timestamptz,
    p_error_code text,
    p_error_digest text,
    p_mutation jsonb
)
RETURNS TABLE(job_id uuid, state text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    success jsonb;
    usage_document jsonb;
    compatibility_success jsonb;
    compatibility_mutation jsonb := p_mutation;
    base_job_id uuid;
    base_state text;
    analysis_id_value uuid;
    changed_count integer;
    provider_kind_value text;
    adapter_id_value text;
BEGIN
    success := p_mutation->'success';
    IF success IS NOT NULL AND success <> 'null'::jsonb THEN
        IF NOT sentinelflow.analysis_jsonb_exact_keys(success, ARRAY[
            'adapter_id', 'analysis_hex', 'attempts', 'command_candidate_hex',
            'evidence_ids', 'generated_command_digest', 'input_bytes',
            'input_digest', 'input_schema_digest', 'model', 'output_digest',
            'output_schema_digest', 'policy_hex', 'prompt_digest',
            'provider_kind', 'rate_card_version', 'reasoning_effort',
            'response_id', 'usage'
        ]) THEN
            RAISE EXCEPTION USING ERRCODE = '22023',
                MESSAGE = 'invalid analysis provider mutation';
        END IF;
        provider_kind_value := success->>'provider_kind';
        adapter_id_value := success->>'adapter_id';
        usage_document := success->'usage';
        IF provider_kind_value = 'openai_responses' THEN
            IF adapter_id_value <> 'openai-responses-v1' OR
               success->>'model' <> 'gpt-5.6-sol' OR
               success->>'reasoning_effort' <> 'medium' OR
               success->>'rate_card_version' !~ '^[a-z0-9][a-z0-9._-]{0,63}$' THEN
                RAISE EXCEPTION USING ERRCODE = '22023',
                    MESSAGE = 'invalid OpenAI analysis provenance';
            END IF;
        ELSIF provider_kind_value = 'deterministic_stub' THEN
            IF adapter_id_value <> 'sentinelflow-deterministic-ai-stub-v1' OR
               success->>'model' <> '' OR success->>'reasoning_effort' <> '' OR
               success->>'rate_card_version' <> '' OR
               success->>'response_id' !~ '^stub_[0-9a-f]{64}$' OR
               NOT sentinelflow.analysis_jsonb_exact_keys(
                   usage_document,
                   ARRAY['cached_input_tokens', 'input_tokens', 'output_tokens', 'trusted']
               ) OR (usage_document->>'trusted')::boolean OR
               (usage_document->>'input_tokens')::integer <> 0 OR
               (usage_document->>'cached_input_tokens')::integer <> 0 OR
               (usage_document->>'output_tokens')::integer <> 0 THEN
                RAISE EXCEPTION USING ERRCODE = '22023',
                    MESSAGE = 'invalid deterministic stub provenance';
            END IF;
        ELSE
            RAISE EXCEPTION USING ERRCODE = '22023',
                MESSAGE = 'unknown analysis provider';
        END IF;

        compatibility_success := success - ARRAY['provider_kind', 'adapter_id'];
        IF provider_kind_value = 'deterministic_stub' THEN
            compatibility_success := jsonb_set(
                compatibility_success, '{model}', to_jsonb('gpt-5.6-sol'::text), false
            );
            compatibility_success := jsonb_set(
                compatibility_success, '{reasoning_effort}', to_jsonb('medium'::text), false
            );
            compatibility_success := jsonb_set(
                compatibility_success, '{rate_card_version}',
                to_jsonb('stub-internal-placeholder-v1'::text), false
            );
        END IF;
        compatibility_mutation := jsonb_set(
            p_mutation, '{success}', compatibility_success, false
        );
    END IF;

    SELECT finished.job_id, finished.state INTO base_job_id, base_state
    FROM sentinelflow.finalize_analysis_attempt_pre_000021(
        p_job_id, p_lease_token, p_finish_state, p_retry_at,
        p_client_now, p_error_code, p_error_digest, compatibility_mutation
    ) finished;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF success IS NOT NULL AND success <> 'null'::jsonb THEN
        analysis_id_value := (p_mutation->>'analysis_id')::uuid;
        IF provider_kind_value = 'openai_responses' THEN
            IF NOT EXISTS (
                SELECT 1 FROM sentinelflow.analysis_attempt_results result
                WHERE result.analysis_id = analysis_id_value
                  AND result.result_state = 'succeeded'
                  AND result.provider_kind = 'openai_responses'
                  AND result.adapter_id = 'openai-responses-v1'
                  AND result.model = 'gpt-5.6-sol'
                  AND result.reasoning_effort = 'medium'
                  AND result.rate_card_version = success->>'rate_card_version'
            ) THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'OpenAI analysis result provenance mismatch';
            END IF;
            UPDATE sentinelflow.ai_analyses
            SET rate_card_version = success->>'rate_card_version'
            WHERE analysis_id = analysis_id_value
              AND provider_kind = 'openai_responses'
              AND adapter_id = 'openai-responses-v1'
              AND model = 'gpt-5.6-sol' AND reasoning_effort = 'medium'
              AND rate_card_version IS NULL;
        ELSE
            UPDATE sentinelflow.analysis_attempt_results
            SET provider_kind = 'deterministic_stub',
                adapter_id = 'sentinelflow-deterministic-ai-stub-v1',
                model = NULL, reasoning_effort = NULL, rate_card_version = NULL
            WHERE analysis_id = analysis_id_value
              AND result_state = 'succeeded'
              AND provider_kind = 'openai_responses'
              AND adapter_id = 'openai-responses-v1'
              AND model = 'gpt-5.6-sol' AND reasoning_effort = 'medium'
              AND rate_card_version = 'stub-internal-placeholder-v1';
            GET DIAGNOSTICS changed_count = ROW_COUNT;
            IF changed_count <> 1 THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'stub analysis result provenance mismatch';
            END IF;
            UPDATE sentinelflow.ai_analyses
            SET provider_kind = 'deterministic_stub',
                adapter_id = 'sentinelflow-deterministic-ai-stub-v1',
                model = NULL, reasoning_effort = NULL, rate_card_version = NULL
            WHERE analysis_id = analysis_id_value
              AND provider_kind = 'openai_responses'
              AND adapter_id = 'openai-responses-v1'
              AND model = 'gpt-5.6-sol' AND reasoning_effort = 'medium'
              AND rate_card_version IS NULL;
        END IF;
        GET DIAGNOSTICS changed_count = ROW_COUNT;
        IF changed_count <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'analysis provider seal mismatch';
        END IF;
    END IF;

    job_id := base_job_id;
    state := base_state;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION sentinelflow.finalize_analysis_attempt_pre_000021(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) FROM PUBLIC, sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_analysis_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (21, 'analysis_provider_provenance')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
