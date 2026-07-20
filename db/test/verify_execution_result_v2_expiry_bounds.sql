\set ON_ERROR_STOP on

-- M34 execution-result-v2 expiry-bound integration coverage.  This fixture
-- deliberately seeds only the already-approved/queued control-plane boundary
-- under session_replication_role=replica, then restores normal trigger/FK
-- enforcement before exercising the dispatcher-facing function.  It avoids
-- duplicating the much larger HIL approval fixture while testing the actual
-- add -> signed read-back -> inspect lifecycle transitions.
BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $contract$
DECLARE
    v2_oid oid;
BEGIN
    SELECT proc.oid INTO v2_oid
    FROM pg_proc proc
    WHERE proc.oid = 'sentinelflow.record_execution_result_v2(uuid,uuid,uuid,uuid,sentinelflow.sha256_digest,text,uuid,sentinelflow.sha256_digest,sentinelflow.canonical_ipv4,text,text,text,bigint,integer,sentinelflow.sha256_digest,timestamptz,timestamptz,bigint,text,bytea,sentinelflow.sha256_digest,bytea,timestamptz,timestamptz)'::regprocedure;

    IF v2_oid IS NULL OR
       NOT has_function_privilege('sentinelflow_dispatcher', v2_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_api', v2_oid, 'EXECUTE') OR
       to_regclass('sentinelflow.execution_result_readback_bounds_000034') IS NULL OR
       to_regclass('sentinelflow.enforcement_expiry_bounds_000034') IS NULL THEN
        RAISE EXCEPTION 'execution-result-v2 expiry-bound authority or storage is missing';
    END IF;
END
$contract$;

CREATE TEMP TABLE v2_cases (
    label text PRIMARY KEY,
    target_ipv4 sentinelflow.canonical_ipv4 NOT NULL,
    base_at timestamptz NOT NULL,
    policy_id uuid NOT NULL,
    action_id uuid NOT NULL,
    add_job_id uuid NOT NULL,
    add_lease_token uuid NOT NULL,
    add_capability_id uuid NOT NULL,
    add_result_id uuid NOT NULL,
    inspect_job_id uuid NULL,
    inspect_lease_token uuid NULL,
    inspect_capability_id uuid NULL,
    inspect_result_id uuid NULL
) ON COMMIT DROP;

INSERT INTO v2_cases (
    label, target_ipv4, base_at, policy_id, action_id, add_job_id,
    add_lease_token, add_capability_id, add_result_id
)
SELECT label,
       target::sentinelflow.canonical_ipv4,
       date_trunc('milliseconds', clock_timestamp() - interval '1 hour') +
           row_number() OVER (ORDER BY label) * interval '2 minutes',
       gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
       gen_random_uuid(), gen_random_uuid()
FROM (VALUES
    ('ttl_minus_one', '8.8.8.11'),
    ('absent_early', '8.8.8.12'),
    ('absent_expired', '8.8.8.13'),
    ('boundary_overlap', '8.8.8.14')
) AS cases(label, target);

-- The result function needs only the immutable, already-queued records below.
-- These direct fixture inserts are never treated as an approval-flow test; the
-- M34's transition, read-back binding, scheduler, audit, and no-readd paths
-- remain the code under test.  The seed graph intentionally keeps replica
-- mode for the synthetic calls: ordinary FK enforcement would otherwise
-- require recreating every immutable incident, validation, HIL, and approval
-- artifact already covered by the dedicated HIL tests.
SET LOCAL session_replication_role = replica;

INSERT INTO sentinelflow.policy_proposals (
    policy_id, version, schema_version, incident_id, incident_version, analysis_id,
    command_candidate_id, evidence_snapshot_id, evidence_snapshot_digest,
    policy_digest, generated_artifact_digest, canonical_artifact_digest,
    target_ipv4, action, ttl_seconds, rationale, state, state_revision,
    created_at, updated_at
)
SELECT case_row.policy_id, 1, 'response-policy-v1', gen_random_uuid(), 1,
       gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
       sentinelflow.hil_sha256(convert_to('v2 evidence ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 policy ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 generated ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
       case_row.target_ipv4, 'block_ip', 60, 'Synthetic M34 expiry-bound fixture.',
       'queued', 2, clock_timestamp() - interval '10 seconds',
       clock_timestamp() - interval '2 seconds'
FROM v2_cases case_row;

INSERT INTO sentinelflow.enforcement_actions (
    action_id, policy_id, policy_version, validation_snapshot_id,
    evidence_snapshot_id, evidence_snapshot_digest, command_candidate_id,
    add_authorization_id, target_ipv4, canonical_artifact,
    canonical_artifact_digest, ttl_seconds, state, approved_at, queued_at,
    version, created_at, updated_at
)
SELECT case_row.action_id, case_row.policy_id, 1, gen_random_uuid(),
       gen_random_uuid(),
       sentinelflow.hil_sha256(convert_to('v2 evidence ' || case_row.label, 'UTF8')),
       gen_random_uuid(), gen_random_uuid(), case_row.target_ipv4,
       convert_to('x', 'UTF8'),
       sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
       60, 'queued', clock_timestamp() - interval '10 seconds',
       clock_timestamp() - interval '2 seconds', 2,
       clock_timestamp() - interval '10 seconds', clock_timestamp() - interval '2 seconds'
FROM v2_cases case_row;

INSERT INTO sentinelflow.outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version, operation,
    idempotency_key, state, available_at, lease_token, lease_owner,
    lease_expires_at, attempts, max_attempts, created_at, updated_at
)
SELECT case_row.add_job_id, 'dispatch_add', 'enforcement_action', case_row.action_id,
       2, 'add', sentinelflow.hil_sha256(convert_to('v2 add job ' || case_row.label, 'UTF8')),
       'leased', clock_timestamp() - interval '1 second', case_row.add_lease_token,
       'dispatcher-test', clock_timestamp() + interval '50 seconds', 1, 8,
       clock_timestamp() - interval '2 seconds', clock_timestamp()
FROM v2_cases case_row;

INSERT INTO sentinelflow.dispatch_operations (
    job_id, operation, action_id, policy_id, policy_version, target_ipv4,
    artifact, artifact_digest, original_add_digest, evidence_snapshot_digest,
    validation_snapshot_id, validation_snapshot_digest,
    enforcement_authorization_id, inspection_authorization_id,
    authorization_digest, actor_id, reason_digest, owned_schema_digest,
    not_before, valid_until
)
SELECT case_row.add_job_id, 'add', case_row.action_id, case_row.policy_id, 1,
       case_row.target_ipv4, convert_to('v2 artifact ' || case_row.label, 'UTF8'),
       sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
       NULL, sentinelflow.hil_sha256(convert_to('v2 evidence ' || case_row.label, 'UTF8')),
       (SELECT validation_snapshot_id FROM sentinelflow.enforcement_actions
         WHERE action_id = case_row.action_id),
       sentinelflow.hil_sha256(convert_to('v2 validation ' || case_row.label, 'UTF8')),
       (SELECT add_authorization_id FROM sentinelflow.enforcement_actions
         WHERE action_id = case_row.action_id),
       NULL, sentinelflow.hil_sha256(convert_to('v2 add authorization ' || case_row.label, 'UTF8')),
       'dispatcher-test', sentinelflow.hil_sha256(convert_to('v2 reason ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 owned ' || case_row.label, 'UTF8')),
       case_row.base_at - interval '1 second', case_row.base_at + interval '50 seconds'
FROM v2_cases case_row;

INSERT INTO sentinelflow.execution_capabilities (
    capability_id, schema_version, job_id, operation, action_id, policy_id,
    policy_version, target_ipv4, artifact, artifact_digest, original_add_digest,
    evidence_snapshot_digest, validation_snapshot_digest, authorization_digest,
    actor_id, reason_digest, owned_schema_digest, capability_jcs,
    capability_digest, capability_signature, nonce_digest, issued_at,
    not_before, expires_at
)
SELECT case_row.add_capability_id, 'execution-capability-v1', case_row.add_job_id,
       'add', case_row.action_id, case_row.policy_id, 1, case_row.target_ipv4,
       convert_to('v2 artifact ' || case_row.label, 'UTF8'),
       sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
       NULL, sentinelflow.hil_sha256(convert_to('v2 evidence ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 validation ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 add authorization ' || case_row.label, 'UTF8')),
       'dispatcher-test', sentinelflow.hil_sha256(convert_to('v2 reason ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 owned ' || case_row.label, 'UTF8')),
       convert_to('v2 add capability ' || case_row.label, 'UTF8'),
       sentinelflow.hil_sha256(convert_to('v2 add capability ' || case_row.label, 'UTF8')),
       decode(repeat('00', 64), 'hex'),
       sentinelflow.hil_sha256(convert_to('v2 add nonce ' || case_row.label, 'UTF8')),
       case_row.base_at - interval '1 second', case_row.base_at - interval '1 second',
       case_row.base_at + interval '50 seconds'
FROM v2_cases case_row;

-- Keep replica mode for the synthetic lifecycle rows.  Table CHECK constraints
-- and all M34 function branches remain active; only unrelated historical HIL
-- graph FK/trigger enforcement is omitted by this focused fixture.

CREATE FUNCTION pg_temp.v2_result_jcs(
    p_readback_started timestamptz,
    p_readback_completed timestamptz,
    p_remaining integer
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $function$
    SELECT convert_to(
        '{"readback_completed_at":"' ||
        to_char(p_readback_completed AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') ||
        '","readback_started_at":"' ||
        to_char(p_readback_started AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') ||
        '","remaining_ttl_seconds":' || COALESCE(p_remaining::text, 'null') ||
        ',"schema_version":"execution-result-v2"}',
        'UTF8'
    );
$function$;

DO $record_active_adds$
DECLARE
    case_row record;
    result_jcs bytea;
    started_at timestamptz;
    completed_at timestamptz;
BEGIN
    FOR case_row IN SELECT * FROM v2_cases ORDER BY label LOOP
        started_at := case_row.base_at;
        completed_at := case_row.base_at + interval '100 milliseconds';
        result_jcs := pg_temp.v2_result_jcs(started_at, completed_at, 60);
        PERFORM sentinelflow.record_execution_result_v2(
            case_row.add_result_id, case_row.add_job_id, case_row.add_lease_token,
            case_row.add_capability_id,
            sentinelflow.hil_sha256(convert_to('v2 add capability ' || case_row.label, 'UTF8')),
            'add', case_row.action_id,
            sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
            case_row.target_ipv4, 'applied', 'success', 'active', NULL, 60,
            sentinelflow.hil_sha256(convert_to('v2 owned ' || case_row.label, 'UTF8')),
            started_at, completed_at, 1, 'none', result_jcs,
            sentinelflow.hil_sha256(result_jcs), decode(repeat('00', 64), 'hex'),
            started_at, completed_at
        );
    END LOOP;
END
$record_active_adds$;

DO $add_bounds$
BEGIN
    IF (SELECT count(*) FROM sentinelflow.enforcement_actions action
        JOIN v2_cases case_row ON case_row.action_id = action.action_id
        JOIN sentinelflow.enforcement_expiry_bounds_000034 bounds
          ON bounds.action_id = action.action_id
        WHERE action.state = 'active'
          AND action.applied_at = case_row.base_at
          AND action.expected_expires_at = case_row.base_at + interval '60 seconds'
          AND bounds.expires_not_before = case_row.base_at + interval '60 seconds'
          AND bounds.expires_not_after = case_row.base_at + interval '61.1 seconds') <> 4 THEN
        RAISE EXCEPTION 'v2 active add did not persist the signed lower/upper expiry bounds';
    END IF;
END
$add_bounds$;

-- Convert each generated read-only schedule into a dispatched inspection
-- fixture, with an exact inspect capability and a live dispatcher lease.
SET LOCAL session_replication_role = replica;

UPDATE v2_cases case_row
SET inspect_job_id = schedule.dispatch_job_id,
    inspect_lease_token = gen_random_uuid(),
    inspect_capability_id = gen_random_uuid(),
    inspect_result_id = gen_random_uuid()
FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
WHERE schedule.action_id = case_row.action_id
  AND schedule.source_result_id = case_row.add_result_id
  AND schedule.state = 'pending';

WITH fixture_clock AS (SELECT clock_timestamp() AS observed_at)
UPDATE sentinelflow.lifecycle_inspection_schedules_000026 schedule
SET state = 'dispatched', scheduler_id = 'lifecycle-test', lease_owner = 'lifecycle-test',
    lease_token = case_row.inspect_lease_token, leased_at = fixture_clock.observed_at,
    lease_expires_at = fixture_clock.observed_at + interval '30 seconds',
    authorization_requested_at = fixture_clock.observed_at,
    authorization_valid_until = fixture_clock.observed_at + interval '4 minutes',
    dispatch_authorization_digest = sentinelflow.hil_sha256(
        convert_to('v2 inspect authorization ' || case_row.label, 'UTF8')
    ), updated_at = clock_timestamp()
FROM v2_cases case_row CROSS JOIN fixture_clock
WHERE schedule.dispatch_job_id = case_row.inspect_job_id;

INSERT INTO sentinelflow.outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version, operation,
    idempotency_key, state, available_at, lease_token, lease_owner,
    lease_expires_at, attempts, max_attempts, created_at, updated_at
)
SELECT case_row.inspect_job_id, 'dispatch_inspect', 'enforcement_action',
       case_row.action_id, 3, 'inspect',
       sentinelflow.hil_sha256(convert_to('v2 inspect job ' || case_row.label, 'UTF8')),
       'leased', clock_timestamp() - interval '1 second', case_row.inspect_lease_token,
       'dispatcher-test', clock_timestamp() + interval '50 seconds', 1, 8,
       clock_timestamp() - interval '2 seconds', clock_timestamp()
FROM v2_cases case_row;

INSERT INTO sentinelflow.dispatch_operations (
    job_id, operation, action_id, policy_id, policy_version, target_ipv4,
    artifact, artifact_digest, original_add_digest, evidence_snapshot_digest,
    validation_snapshot_id, validation_snapshot_digest,
    enforcement_authorization_id, inspection_authorization_id,
    authorization_digest, actor_id, reason_digest, owned_schema_digest,
    not_before, valid_until
)
SELECT case_row.inspect_job_id, 'inspect', case_row.action_id, case_row.policy_id,
       1, case_row.target_ipv4, convert_to('x', 'UTF8'),
       sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 evidence ' || case_row.label, 'UTF8')),
       action.validation_snapshot_id,
       sentinelflow.hil_sha256(convert_to('v2 validation ' || case_row.label, 'UTF8')),
       NULL, gen_random_uuid(),
       sentinelflow.hil_sha256(convert_to('v2 inspect authorization ' || case_row.label, 'UTF8')),
       'lifecycle-test', sentinelflow.hil_sha256(convert_to('v2 reason ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 owned ' || case_row.label, 'UTF8')),
       case_row.base_at - interval '1 second', case_row.base_at + interval '50 seconds'
FROM v2_cases case_row
JOIN sentinelflow.enforcement_actions action ON action.action_id = case_row.action_id;

INSERT INTO sentinelflow.execution_capabilities (
    capability_id, schema_version, job_id, operation, action_id, policy_id,
    policy_version, target_ipv4, artifact, artifact_digest, original_add_digest,
    evidence_snapshot_digest, validation_snapshot_digest, authorization_digest,
    actor_id, reason_digest, owned_schema_digest, capability_jcs,
    capability_digest, capability_signature, nonce_digest, issued_at,
    not_before, expires_at
)
SELECT case_row.inspect_capability_id, 'execution-capability-v1',
       case_row.inspect_job_id, 'inspect', case_row.action_id, case_row.policy_id,
       1, case_row.target_ipv4, convert_to('x', 'UTF8'),
       sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 evidence ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 validation ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 inspect authorization ' || case_row.label, 'UTF8')),
       'lifecycle-test', sentinelflow.hil_sha256(convert_to('v2 reason ' || case_row.label, 'UTF8')),
       sentinelflow.hil_sha256(convert_to('v2 owned ' || case_row.label, 'UTF8')),
       convert_to('{}', 'UTF8'),
       sentinelflow.hil_sha256(convert_to('v2 inspect capability ' || case_row.label, 'UTF8')),
       decode(repeat('00', 64), 'hex'),
       sentinelflow.hil_sha256(convert_to('v2 inspect nonce ' || case_row.label, 'UTF8')),
       case_row.base_at - interval '1 second', case_row.base_at - interval '1 second',
       case_row.base_at + interval '50 seconds'
FROM v2_cases case_row;

-- Keep the same narrow synthetic-fixture mode through the inspect calls.

DO $inspect_boundaries$
DECLARE
    case_row record;
    readback_started timestamptz;
    readback_completed timestamptz;
    remaining integer;
    result_jcs bytea;
    classification text;
    readback_state text;
BEGIN
    FOR case_row IN SELECT * FROM v2_cases ORDER BY label LOOP
        CASE case_row.label
            WHEN 'ttl_minus_one' THEN
                -- A native integer read-back of ttl-1 is still safely before U.
                readback_started := case_row.base_at + interval '1 second';
                readback_completed := readback_started + interval '100 milliseconds';
                remaining := 59; classification := 'inspect_active'; readback_state := 'active';
            WHEN 'absent_early' THEN
                -- Strictly before L is evidence of disappearance, never expiry.
                readback_started := case_row.base_at + interval '58 seconds';
                readback_completed := case_row.base_at + interval '59.999 seconds';
                remaining := NULL; classification := 'inspect_absent'; readback_state := 'absent';
            WHEN 'absent_expired' THEN
                -- At U is sufficient to attribute native expiry.
                readback_started := case_row.base_at + interval '61.1 seconds';
                readback_completed := readback_started + interval '100 milliseconds';
                remaining := NULL; classification := 'inspect_absent'; readback_state := 'absent';
            WHEN 'boundary_overlap' THEN
                -- An absent read-back that overlaps [L,U) must stay uncertain.
                readback_started := case_row.base_at + interval '59.5 seconds';
                readback_completed := case_row.base_at + interval '60.5 seconds';
                remaining := NULL; classification := 'inspect_absent'; readback_state := 'absent';
        END CASE;
        result_jcs := pg_temp.v2_result_jcs(readback_started, readback_completed, remaining);
        PERFORM sentinelflow.record_execution_result_v2(
            case_row.inspect_result_id, case_row.inspect_job_id,
            case_row.inspect_lease_token, case_row.inspect_capability_id,
            sentinelflow.hil_sha256(convert_to('v2 inspect capability ' || case_row.label, 'UTF8')),
            'inspect', case_row.action_id,
            sentinelflow.hil_sha256(convert_to('v2 artifact ' || case_row.label, 'UTF8')),
            case_row.target_ipv4, classification, 'success', readback_state, NULL, remaining,
            sentinelflow.hil_sha256(convert_to('v2 owned ' || case_row.label, 'UTF8')),
            readback_started, readback_completed, 1, 'none', result_jcs,
            sentinelflow.hil_sha256(result_jcs), decode(repeat('00', 64), 'hex'),
            readback_started, readback_completed
        );
    END LOOP;
END
$inspect_boundaries$;

DO $assert_boundaries$
DECLARE
    ttl_action uuid;
    early_action uuid;
    expired_action uuid;
    overlap_action uuid;
    overlap_result uuid;
BEGIN
    SELECT action_id INTO ttl_action FROM v2_cases WHERE label = 'ttl_minus_one';
    SELECT action_id INTO early_action FROM v2_cases WHERE label = 'absent_early';
    SELECT action_id INTO expired_action FROM v2_cases WHERE label = 'absent_expired';
    SELECT action_id, inspect_result_id INTO overlap_action, overlap_result
    FROM v2_cases WHERE label = 'boundary_overlap';

    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.enforcement_actions
        WHERE action_id = ttl_action AND state = 'active'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.audit_events
        WHERE enforcement_action_id = ttl_action AND action = 'enforcement_late_active'
    ) THEN
        RAISE EXCEPTION 'ttl-1 active inspection was treated as late active';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.enforcement_actions
        WHERE action_id = early_action AND state = 'failed'
    ) OR NOT EXISTS (
        SELECT 1 FROM sentinelflow.audit_events
        WHERE enforcement_action_id = early_action AND action = 'enforcement_missing_early'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
        JOIN v2_cases case_row ON case_row.action_id = early_action
        WHERE schedule.source_result_id = case_row.inspect_result_id
    ) THEN
        RAISE EXCEPTION 'strictly early absence did not fail closed without re-add/retry';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.enforcement_actions
        WHERE action_id = expired_action AND state = 'expired'
    ) OR NOT EXISTS (
        SELECT 1 FROM sentinelflow.audit_events
        WHERE enforcement_action_id = expired_action AND action = 'enforcement_expired'
    ) THEN
        RAISE EXCEPTION 'absence at or after upper bound was not recorded as expiry';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.enforcement_actions
        WHERE action_id = overlap_action AND state = 'indeterminate'
    ) OR NOT EXISTS (
        SELECT 1 FROM sentinelflow.lifecycle_inspection_schedules_000026
        WHERE action_id = overlap_action AND source_result_id = overlap_result
          AND state = 'pending' AND purpose = 'reconciliation'
    ) OR (SELECT count(*) FROM sentinelflow.dispatch_operations
          WHERE action_id = overlap_action AND operation = 'add') <> 1 OR
       (SELECT count(*) FROM sentinelflow.execution_capabilities
          WHERE action_id = overlap_action AND operation = 'add') <> 1 THEN
        RAISE EXCEPTION 'boundary overlap did not schedule read-only reinspection without re-add';
    END IF;
END
$assert_boundaries$;

-- A persisted v2 result is exact replay evidence, not a second add.  It must
-- survive the dispatcher's result-before-finish crash boundary and appear on
-- the recovery-only path without refreshing the original expiry interval.
DO $v2_replay_recovery$
DECLARE
    case_row record;
    result_row sentinelflow.execution_results%ROWTYPE;
    readback_bounds sentinelflow.execution_result_readback_bounds_000034%ROWTYPE;
    recovery_state text;
    recovery_exact boolean;
BEGIN
    FOR case_row IN
        SELECT * FROM v2_cases WHERE label = 'ttl_minus_one'
    LOOP
        SELECT * INTO result_row
        FROM sentinelflow.execution_results result
        WHERE result.result_id = case_row.add_result_id;
        SELECT * INTO readback_bounds
        FROM sentinelflow.execution_result_readback_bounds_000034 bounds
        WHERE bounds.result_id = case_row.add_result_id;
        PERFORM sentinelflow.record_execution_result_v2(
            result_row.result_id, case_row.add_job_id, case_row.add_lease_token,
            result_row.capability_id, result_row.capability_digest, result_row.operation,
            result_row.action_id, result_row.artifact_digest, result_row.target_ipv4,
            result_row.classification, result_row.nft_exit_class, result_row.readback_state,
            result_row.element_handle, result_row.remaining_ttl_seconds,
            result_row.owned_schema_digest, result_row.started_at, result_row.completed_at,
            result_row.journal_sequence, result_row.error_code, result_row.result_jcs,
            result_row.result_digest, result_row.result_signature,
            readback_bounds.readback_started_at, readback_bounds.readback_completed_at
        );
        SELECT recovered.recovery_state INTO recovery_state
        FROM sentinelflow.recover_dispatch_execution(
            case_row.add_job_id, case_row.add_lease_token
        ) recovered;
        SELECT sentinelflow.dispatch_recovery_result_exact_000025(
            case_row.add_job_id, result_row.capability_digest,
            (SELECT aggregate_version FROM sentinelflow.outbox_jobs
             WHERE job_id = case_row.add_job_id), clock_timestamp()
        ) INTO recovery_exact;
        IF recovery_state <> 'result' OR NOT recovery_exact OR
           (SELECT count(*) FROM sentinelflow.execution_results
            WHERE result_id = case_row.add_result_id) <> 1 OR
           NOT EXISTS (
               SELECT 1 FROM sentinelflow.enforcement_expiry_bounds_000034 action_bounds
               WHERE action_bounds.action_id = case_row.action_id
                 AND action_bounds.source_result_id = case_row.add_result_id
           ) THEN
            RAISE EXCEPTION 'v2 exact replay or pre-finish recovery is not idempotent';
        END IF;
    END LOOP;
END
$v2_replay_recovery$;

DO $jcs_binding$
DECLARE
    readback_started timestamptz := date_trunc('milliseconds', clock_timestamp());
    readback_completed timestamptz := date_trunc('milliseconds', clock_timestamp()) + interval '100 milliseconds';
    result_jcs bytea;
BEGIN
    result_jcs := pg_temp.v2_result_jcs(readback_started, readback_completed, NULL);
    BEGIN
        PERFORM sentinelflow.record_execution_result_v2(
            gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
            sentinelflow.hil_sha256(convert_to('v2 mismatch capability', 'UTF8')),
            'inspect', gen_random_uuid(),
            sentinelflow.hil_sha256(convert_to('v2 mismatch artifact', 'UTF8')),
            '8.8.4.4'::sentinelflow.canonical_ipv4,
            'inspect_absent', 'success', 'absent', NULL, NULL,
            sentinelflow.hil_sha256(convert_to('v2 mismatch owned', 'UTF8')),
            readback_started, readback_completed, 1, 'none', result_jcs,
            sentinelflow.hil_sha256(result_jcs), decode(repeat('00', 64), 'hex'),
            readback_started + interval '1 millisecond', readback_completed
        );
        RAISE EXCEPTION 'v2 wrapper accepted a timestamp that differs from signed JCS';
    EXCEPTION WHEN invalid_parameter_value THEN
        NULL;
    END;
END
$jcs_binding$;

SET LOCAL session_replication_role = origin;

ROLLBACK;
