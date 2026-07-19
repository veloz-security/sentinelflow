BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Extend the closed, aggregate-only exporter contract without exposing the
-- lifecycle ledger.  The prior aggregate remains migration-owner internal so
-- its established metrics stay byte-for-byte compatible.
CREATE FUNCTION sentinelflow.control_observability_samples_000028()
RETURNS TABLE (
    metric_name text,
    label_1_name text,
    label_1_value text,
    label_2_name text,
    label_2_value text,
    sample_value double precision
)
LANGUAGE sql
STABLE
SECURITY DEFINER
ROWS 512
SET search_path = pg_catalog, sentinelflow
AS $function$
WITH
clock AS (
    SELECT statement_timestamp() AS observed_at
),
lifecycle_purposes(purpose) AS (
    VALUES ('reconciliation'), ('expiry_confirmation'), ('operator_status')
),
lifecycle_states(state) AS (
    VALUES ('pending'), ('leased'), ('retry'), ('dispatched'), ('completed'), ('dead')
),
lifecycle_counts AS (
    SELECT schedule.purpose, schedule.state, count(*)::double precision AS value
    FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
    GROUP BY schedule.purpose, schedule.state
),
lifecycle_oldest_due AS (
    SELECT schedule.purpose,
           greatest(
               0,
               extract(epoch FROM (clock.observed_at - min(schedule.due_at)))
           )::double precision AS value
    FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
    CROSS JOIN clock
    WHERE schedule.state IN ('pending', 'retry')
      AND schedule.due_at <= clock.observed_at
    GROUP BY schedule.purpose, clock.observed_at
),
lifecycle_lease_lag AS (
    SELECT schedule.purpose,
           greatest(
               0,
               extract(epoch FROM (clock.observed_at - min(schedule.lease_expires_at)))
           )::double precision AS value
    FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
    CROSS JOIN clock
    WHERE schedule.state = 'leased'
      AND schedule.lease_expires_at <= clock.observed_at
    GROUP BY schedule.purpose, clock.observed_at
)
SELECT previous.metric_name, previous.label_1_name, previous.label_1_value,
       previous.label_2_name, previous.label_2_value, previous.sample_value
FROM sentinelflow.control_observability_samples_000024() previous
UNION ALL
SELECT 'sentinelflow_control_lifecycle_schedules', 'purpose', purpose.purpose,
       'state', state.state, COALESCE(counts.value, 0)
FROM lifecycle_purposes purpose
CROSS JOIN lifecycle_states state
LEFT JOIN lifecycle_counts counts
  ON counts.purpose = purpose.purpose AND counts.state = state.state
UNION ALL
SELECT 'sentinelflow_control_lifecycle_oldest_due_age_seconds',
       'purpose', purpose.purpose, NULL, NULL, COALESCE(oldest.value, 0)
FROM lifecycle_purposes purpose
LEFT JOIN lifecycle_oldest_due oldest USING (purpose)
UNION ALL
SELECT 'sentinelflow_control_lifecycle_lease_expiry_lag_seconds',
       'purpose', purpose.purpose, NULL, NULL, COALESCE(lag.value, 0)
FROM lifecycle_purposes purpose
LEFT JOIN lifecycle_lease_lag lag USING (purpose);
$function$;

-- sentinelflow_metrics is a single-function runtime role.  It cannot inspect
-- identifiers, targets, digests, lease owners, or failure details directly.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA sentinelflow FROM sentinelflow_metrics;
REVOKE ALL ON TABLE
    sentinelflow.lifecycle_inspection_schedules_000026,
    sentinelflow.lifecycle_inspection_artifacts_000026,
    sentinelflow.lifecycle_capability_applications_000026,
    sentinelflow.lifecycle_result_applications_000026
FROM PUBLIC, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.lifecycle_inspect_jcs_000026(
    uuid, sentinelflow.canonical_ipv4, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, text
) FROM PUBLIC, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.lifecycle_schedule_idempotency_000026(uuid)
FROM PUBLIC, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.lifecycle_inspection_authorization_jcs_000026(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, uuid, integer,
    text, timestamptz, sentinelflow.ascii_id, sentinelflow.canonical_ipv4,
    timestamptz, sentinelflow.sha256_digest
) FROM PUBLIC, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.enforce_action_transition_000026()
FROM PUBLIC, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.claim_lifecycle_inspection_schedule_000026(
    sentinelflow.ascii_id, sentinelflow.ascii_id, integer
) FROM PUBLIC, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.commit_lifecycle_inspection_000026(
    uuid, uuid, integer, sentinelflow.ascii_id, uuid, bytea,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest
) FROM PUBLIC, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.finish_lifecycle_inspection_failure_000026(
    uuid, uuid, integer, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, integer
) FROM PUBLIC, sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.control_observability_samples_000028()
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
    sentinelflow_dispatcher, sentinelflow_retention, sentinelflow_lifecycle,
    sentinelflow_metrics;
GRANT EXECUTE ON FUNCTION sentinelflow.control_observability_samples_000028()
TO sentinelflow_metrics;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (28, 'lifecycle_observability')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
