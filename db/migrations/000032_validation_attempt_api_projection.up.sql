BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 31 AND name = 'artifact_content_digest_identity'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations WHERE version = 32
    ) OR to_regprocedure(
        'sentinelflow.read_policy_validation_attempt_000032(uuid)'
    ) IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'validation attempt API projection requires the exact version-31 prefix';
    END IF;
END
$preflight$;

-- The API needs terminal fail-closed evidence, but it must not receive the raw
-- prepared snapshot or terminal mutation JSON. Keep the policy identifier as
-- the only lookup key so an attempt identifier cannot become a cross-policy
-- oracle. One row is returned per evaluated gate in immutable ordinal order.
CREATE FUNCTION sentinelflow.read_policy_validation_attempt_000032(
    p_policy_id uuid
)
RETURNS TABLE (
    validation_attempt_id uuid,
    policy_id uuid,
    analysis_id uuid,
    incident_id uuid,
    incident_version integer,
    state text,
    failure_code sentinelflow.ascii_id,
    failed_gate text,
    prepared_snapshot_digest sentinelflow.sha256_digest,
    terminal_mutation_digest sentinelflow.sha256_digest,
    completed_at timestamptz,
    gate_order smallint,
    gate_name text,
    gate_state text,
    gate_result_code sentinelflow.ascii_id,
    gate_artifact_digest sentinelflow.sha256_digest
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
ROWS 6
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    claim_value sentinelflow.validation_attempt_claims%ROWTYPE;
    result_value sentinelflow.validation_attempt_results%ROWTYPE;
BEGIN
    SELECT claim.*
    INTO claim_value
    FROM sentinelflow.validation_attempt_claims AS claim
    WHERE claim.policy_id = p_policy_id;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT result.*
    INTO result_value
    FROM sentinelflow.validation_attempt_results AS result
    WHERE result.validation_attempt_id = claim_value.validation_attempt_id;

    IF NOT FOUND OR
       claim_value.state IS DISTINCT FROM result_value.result_state OR
       claim_value.failure_code IS DISTINCT FROM result_value.failure_code OR
       claim_value.prepared_snapshot_digest IS DISTINCT FROM
           result_value.prepared_snapshot_digest OR
       claim_value.terminal_at IS DISTINCT FROM result_value.completed_at THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'validation attempt terminal binding mismatch';
    END IF;

    RETURN QUERY
    SELECT
        claim_value.validation_attempt_id,
        claim_value.policy_id,
        claim_value.analysis_id,
        claim_value.incident_id,
        claim_value.incident_version,
        result_value.result_state,
        result_value.failure_code,
        result_value.failed_gate,
        result_value.prepared_snapshot_digest,
        result_value.terminal_mutation_digest,
        result_value.completed_at,
        gate.gate_order,
        gate.gate_name,
        CASE WHEN gate.passed THEN 'passed'
             WHEN gate.passed IS FALSE THEN 'failed'
             ELSE NULL
        END AS gate_state,
        gate.result_code AS gate_result_code,
        gate.result_digest AS gate_artifact_digest
    FROM (SELECT true AS one_row) AS seed
    LEFT JOIN sentinelflow.validation_attempt_gates AS gate
      ON gate.validation_attempt_id = claim_value.validation_attempt_id
    ORDER BY gate.gate_order ASC NULLS LAST;
END
$function$;

ALTER FUNCTION sentinelflow.read_policy_validation_attempt_000032(uuid)
    OWNER TO sentinelflow_migration;
REVOKE ALL ON FUNCTION
    sentinelflow.read_policy_validation_attempt_000032(uuid)
FROM PUBLIC, sentinelflow_worker, sentinelflow_read,
    sentinelflow_dispatcher, sentinelflow_retention,
    sentinelflow_lifecycle, sentinelflow_metrics,
    sentinelflow_demo_importer, sentinelflow_demo_activator;
GRANT EXECUTE ON FUNCTION
    sentinelflow.read_policy_validation_attempt_000032(uuid)
TO sentinelflow_api;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (32, 'validation_attempt_api_projection');

COMMIT;
