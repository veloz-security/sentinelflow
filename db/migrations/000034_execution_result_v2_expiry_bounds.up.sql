BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- execution-result-v1 has only a whole-second nft JSON observation and one
-- broad executor interval.  It cannot prove an exact native expiry instant.
-- Keep those durable records and their lifecycle interpretation untouched.
-- New v2 records carry a signed read-back interval and are interpreted only
-- through the conservative interval below.
DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 33 AND name = 'analysis_stale_version_resolution'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations WHERE version = 34
    ) OR to_regprocedure(
        'sentinelflow.record_execution_result_pre_000026(uuid,uuid,uuid,uuid,sentinelflow.sha256_digest,text,uuid,sentinelflow.sha256_digest,sentinelflow.canonical_ipv4,text,text,text,bigint,integer,sentinelflow.sha256_digest,timestamptz,timestamptz,bigint,text,bytea,sentinelflow.sha256_digest,bytea)'
    ) IS NULL OR to_regprocedure(
        'sentinelflow.record_execution_result_pre_000027(uuid,uuid,uuid,uuid,sentinelflow.sha256_digest,text,uuid,sentinelflow.sha256_digest,sentinelflow.canonical_ipv4,text,text,text,bigint,integer,sentinelflow.sha256_digest,timestamptz,timestamptz,bigint,text,bytea,sentinelflow.sha256_digest,bytea)'
    ) IS NULL OR EXISTS (
        -- A nonterminal pre-v2 action has only v1 timing evidence. Do not
        -- synthesize a v2 upper bound or migrate an in-flight schedule.
        SELECT 1 FROM sentinelflow.enforcement_actions action
        WHERE action.state IN ('approved', 'queued', 'active', 'indeterminate')
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'execution-result v2 expiry bounds requires an idle version-33 lifecycle';
    END IF;
END
$preflight$;

ALTER TABLE sentinelflow.execution_results
    DROP CONSTRAINT IF EXISTS execution_results_schema_version_check;
ALTER TABLE sentinelflow.execution_results
    ADD CONSTRAINT execution_results_schema_version_check
    CHECK (schema_version IN ('execution-result-v1', 'execution-result-v2'));

-- The signed interval remains append-only and separate from the legacy
-- execution_results shape.  lower is the earliest lifecycle boundary that
-- may be inferred; upper includes the one-second integer nft projection
-- guard.  A missing upper/lower is valid only for a result whose read-back did
-- not report an active remaining timeout.
CREATE TABLE sentinelflow.execution_result_readback_bounds_000034 (
    result_id uuid PRIMARY KEY
        REFERENCES sentinelflow.execution_results (result_id) ON DELETE RESTRICT,
    readback_started_at timestamptz NOT NULL,
    readback_completed_at timestamptz NOT NULL,
    remaining_ttl_seconds integer NULL CHECK (remaining_ttl_seconds BETWEEN 1 AND 86400),
    expires_not_before timestamptz NULL,
    expires_not_after timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT execution_result_readback_bounds_interval CHECK (
        readback_completed_at >= readback_started_at
        AND readback_completed_at <= readback_started_at + interval '2 seconds'
        AND (
            (remaining_ttl_seconds IS NULL AND expires_not_before IS NULL AND expires_not_after IS NULL)
            OR
            (remaining_ttl_seconds IS NOT NULL AND expires_not_before IS NOT NULL AND
             expires_not_after IS NOT NULL AND
             expires_not_before = readback_started_at + make_interval(secs => remaining_ttl_seconds) AND
             expires_not_after = readback_completed_at +
                 make_interval(secs => remaining_ttl_seconds + 1) AND
             expires_not_after > expires_not_before)
        )
    )
);

-- This binds the original active read-back interval to an action.  It is not
-- updated by later active inspection: doing so could silently refresh a TTL.
CREATE TABLE sentinelflow.enforcement_expiry_bounds_000034 (
    action_id uuid PRIMARY KEY
        REFERENCES sentinelflow.enforcement_actions (action_id) ON DELETE RESTRICT,
    source_result_id uuid NOT NULL UNIQUE
        REFERENCES sentinelflow.execution_results (result_id) ON DELETE RESTRICT,
    expires_not_before timestamptz NOT NULL,
    expires_not_after timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT enforcement_expiry_bounds_interval CHECK (
        expires_not_after > expires_not_before
    )
);

ALTER FUNCTION sentinelflow.record_execution_result_pre_000026(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) RENAME TO record_execution_result_insert_pre_000034;

-- Parse only the two v2 read-back times that are needed for expiry safety.
-- The dispatcher has already verified the executor signature; this extra
-- parse binds the SQL lifecycle values to the exact persisted JCS bytes and
-- rejects ambiguity instead of accepting a timestamp approximation.
CREATE FUNCTION sentinelflow.record_execution_result_pre_000026(
    p_result_id uuid, p_job_id uuid, p_lease_token uuid, p_capability_id uuid,
    p_capability_digest sentinelflow.sha256_digest, p_operation text,
    p_action_id uuid, p_artifact_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4, p_classification text,
    p_nft_exit_class text, p_readback_state text, p_element_handle bigint,
    p_remaining_ttl_seconds integer, p_owned_schema_digest sentinelflow.sha256_digest,
    p_started_at timestamptz, p_completed_at timestamptz,
    p_journal_sequence bigint, p_error_code text, p_result_jcs bytea,
    p_result_digest sentinelflow.sha256_digest, p_result_signature bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    payload jsonb;
    schema_value text;
    raw_readback_started text;
    raw_readback_completed text;
    readback_started timestamptz;
    readback_completed timestamptz;
    payload_remaining integer;
    existing sentinelflow.execution_results%ROWTYPE;
    bounds sentinelflow.execution_result_readback_bounds_000034%ROWTYPE;
BEGIN
    BEGIN
        payload := convert_from(p_result_jcs, 'UTF8')::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'execution result JCS is not UTF-8 JSON';
    END;
    schema_value := payload ->> 'schema_version';
    IF schema_value = 'execution-result-v1' THEN
        -- v1 is deliberately delegated byte-for-byte to its original
        -- implementation.  No v1 action is reinterpreted by this migration.
        PERFORM sentinelflow.record_execution_result_insert_pre_000034(
            p_result_id, p_job_id, p_lease_token, p_capability_id,
            p_capability_digest, p_operation, p_action_id, p_artifact_digest,
            p_target_ipv4, p_classification, p_nft_exit_class, p_readback_state,
            p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
            p_started_at, p_completed_at, p_journal_sequence, p_error_code,
            p_result_jcs, p_result_digest, p_result_signature
        );
        RETURN;
    ELSIF schema_value <> 'execution-result-v2' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'unknown execution result schema version';
    END IF;

    IF jsonb_typeof(payload -> 'readback_started_at') <> 'string' OR
       jsonb_typeof(payload -> 'readback_completed_at') <> 'string' OR
       jsonb_typeof(payload -> 'remaining_ttl_seconds') NOT IN ('number', 'null') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'execution-result-v2 readback fields are invalid';
    END IF;
    raw_readback_started := payload ->> 'readback_started_at';
    raw_readback_completed := payload ->> 'readback_completed_at';
    IF raw_readback_started !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' OR
       raw_readback_completed !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'execution-result-v2 readback timestamps are not canonical milliseconds';
    END IF;
    BEGIN
        readback_started := raw_readback_started::timestamptz;
        readback_completed := raw_readback_completed::timestamptz;
        IF payload -> 'remaining_ttl_seconds' <> 'null'::jsonb THEN
            payload_remaining := (payload ->> 'remaining_ttl_seconds')::integer;
        END IF;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'execution-result-v2 readback fields are malformed';
    END;
    IF readback_started < p_started_at OR readback_completed < readback_started OR
       readback_completed > p_completed_at OR
       date_trunc('milliseconds', readback_started) <> readback_started OR
       date_trunc('milliseconds', readback_completed) <> readback_completed OR
       payload_remaining IS DISTINCT FROM p_remaining_ttl_seconds THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'execution-result-v2 readback binding is invalid';
    END IF;

    -- A duplicate result is recovery evidence, never a second mutation.  The
    -- original v1 inserter intentionally has no upsert path, so verify the
    -- complete durable v2 row and its signed read-back interval before
    -- returning to the lifecycle ledger below.  Any difference fails closed.
    SELECT * INTO existing
    FROM sentinelflow.execution_results result
    WHERE result.result_id = p_result_id;
    IF FOUND AND existing.schema_version = 'execution-result-v2' THEN
        SELECT * INTO bounds
        FROM sentinelflow.execution_result_readback_bounds_000034 result_bounds
        WHERE result_bounds.result_id = p_result_id;
        IF existing.capability_id = p_capability_id AND
           existing.capability_digest = p_capability_digest AND
           existing.operation = p_operation AND existing.action_id = p_action_id AND
           existing.artifact_digest = p_artifact_digest AND existing.target_ipv4 = p_target_ipv4 AND
           existing.classification = p_classification AND
           existing.nft_exit_class IS NOT DISTINCT FROM p_nft_exit_class AND
           existing.readback_state = p_readback_state AND
           existing.element_handle IS NOT DISTINCT FROM p_element_handle AND
           existing.remaining_ttl_seconds IS NOT DISTINCT FROM p_remaining_ttl_seconds AND
           existing.owned_schema_digest = p_owned_schema_digest AND
           existing.started_at = p_started_at AND existing.completed_at = p_completed_at AND
           existing.journal_sequence = p_journal_sequence AND existing.error_code = p_error_code AND
           existing.result_jcs = p_result_jcs AND existing.result_digest = p_result_digest AND
           existing.result_signature = p_result_signature AND
           bounds.result_id = p_result_id AND
           bounds.readback_started_at = readback_started AND
           bounds.readback_completed_at = readback_completed AND
           bounds.remaining_ttl_seconds IS NOT DISTINCT FROM p_remaining_ttl_seconds THEN
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'conflicting execution-result-v2 replay';
    ELSIF FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'execution result schema replay conflicts';
    END IF;

    PERFORM sentinelflow.record_execution_result_insert_pre_000034(
        p_result_id, p_job_id, p_lease_token, p_capability_id,
        p_capability_digest, p_operation, p_action_id, p_artifact_digest,
        p_target_ipv4, p_classification, p_nft_exit_class, p_readback_state,
        p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
        p_started_at, p_completed_at, p_journal_sequence, p_error_code,
        p_result_jcs, p_result_digest, p_result_signature
    );

    UPDATE sentinelflow.execution_results
    SET schema_version = 'execution-result-v2'
    WHERE result_id = p_result_id AND schema_version = 'execution-result-v1';
    INSERT INTO sentinelflow.execution_result_readback_bounds_000034 (
        result_id, readback_started_at, readback_completed_at, remaining_ttl_seconds,
        expires_not_before, expires_not_after
    ) VALUES (
        p_result_id, readback_started, readback_completed, p_remaining_ttl_seconds,
        CASE WHEN p_remaining_ttl_seconds IS NULL THEN NULL
             ELSE readback_started + make_interval(secs => p_remaining_ttl_seconds) END,
        CASE WHEN p_remaining_ttl_seconds IS NULL THEN NULL
             ELSE readback_completed + make_interval(secs => p_remaining_ttl_seconds + 1) END
    ) ON CONFLICT (result_id) DO NOTHING;
    SELECT * INTO bounds
    FROM sentinelflow.execution_result_readback_bounds_000034
    WHERE result_id = p_result_id;
    IF NOT FOUND OR bounds.readback_started_at <> readback_started OR
       bounds.readback_completed_at <> readback_completed OR
       bounds.remaining_ttl_seconds IS DISTINCT FROM p_remaining_ttl_seconds THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'conflicting execution-result-v2 readback replay';
    END IF;
END
$function$;

ALTER FUNCTION sentinelflow.record_execution_result_pre_000027(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) RENAME TO record_execution_result_lifecycle_pre_000034;

CREATE FUNCTION sentinelflow.record_execution_result_v2_000034(
    p_result_id uuid, p_job_id uuid, p_lease_token uuid, p_capability_id uuid,
    p_capability_digest sentinelflow.sha256_digest, p_operation text,
    p_action_id uuid, p_artifact_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4, p_classification text,
    p_nft_exit_class text, p_readback_state text, p_element_handle bigint,
    p_remaining_ttl_seconds integer, p_owned_schema_digest sentinelflow.sha256_digest,
    p_started_at timestamptz, p_completed_at timestamptz,
    p_journal_sequence bigint, p_error_code text, p_result_jcs bytea,
    p_result_digest sentinelflow.sha256_digest, p_result_signature bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    action sentinelflow.enforcement_actions%ROWTYPE;
    policy sentinelflow.policy_proposals%ROWTYPE;
    capability sentinelflow.execution_capabilities%ROWTYPE;
    operation sentinelflow.dispatch_operations%ROWTYPE;
    revoke sentinelflow.revocation_operations%ROWTYPE;
    source_schedule sentinelflow.lifecycle_inspection_schedules_000026%ROWTYPE;
    application sentinelflow.lifecycle_result_applications_000026%ROWTYPE;
    result_bounds sentinelflow.execution_result_readback_bounds_000034%ROWTYPE;
    action_bounds sentinelflow.enforcement_expiry_bounds_000034%ROWTYPE;
    next_state text;
    next_applied_at timestamptz;
    next_expires_at timestamptz;
    next_finished_at timestamptz;
    schedule_id uuid;
    schedule_purpose text;
    schedule_due_at timestamptz;
    audit_action sentinelflow.ascii_id;
    audit_outcome text;
    expected_revoke_state text;
BEGIN
    -- Always reach the persistence wrapper first: an existing result_id is
    -- replay authority only when its signed JCS and v2 read-back interval are
    -- still byte-for-byte identical.  The later ledger check prevents a
    -- second lifecycle transition or a TTL refresh.
    PERFORM sentinelflow.record_execution_result_pre_000026(
        p_result_id, p_job_id, p_lease_token, p_capability_id,
        p_capability_digest, p_operation, p_action_id, p_artifact_digest,
        p_target_ipv4, p_classification, p_nft_exit_class, p_readback_state,
        p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
        p_started_at, p_completed_at, p_journal_sequence, p_error_code,
        p_result_jcs, p_result_digest, p_result_signature
    );
    SELECT applied.* INTO application
    FROM sentinelflow.lifecycle_result_applications_000026 applied
    WHERE applied.result_id = p_result_id;
    IF FOUND THEN
        IF application.result_digest = p_result_digest AND application.action_id = p_action_id AND
           application.operation = p_operation AND application.classification = p_classification THEN
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'conflicting v2 lifecycle replay';
    END IF;

    SELECT * INTO result_bounds
    FROM sentinelflow.execution_result_readback_bounds_000034
    WHERE result_id = p_result_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 result lacks readback bounds';
    END IF;

    SELECT current_action.* INTO action
    FROM sentinelflow.enforcement_actions current_action
    WHERE current_action.action_id = p_action_id FOR UPDATE;
    SELECT current_policy.* INTO policy
    FROM sentinelflow.policy_proposals current_policy
    WHERE current_policy.policy_id = action.policy_id AND current_policy.version = action.policy_version
    FOR UPDATE;
    SELECT current_capability.* INTO capability
    FROM sentinelflow.execution_capabilities current_capability
    WHERE current_capability.capability_id = p_capability_id;
    SELECT current_operation.* INTO operation
    FROM sentinelflow.dispatch_operations current_operation
    WHERE current_operation.job_id = p_job_id;
    IF action.action_id IS NULL OR policy.policy_id IS NULL OR capability.capability_id IS NULL OR
       operation.job_id IS NULL OR action.state <> policy.state OR capability.job_id <> p_job_id OR
       capability.action_id <> p_action_id OR operation.action_id <> p_action_id THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 execution lifecycle binding failed';
    END IF;
    SELECT * INTO action_bounds FROM sentinelflow.enforcement_expiry_bounds_000034
    WHERE action_id = p_action_id;

    IF p_operation = 'add' THEN
        IF action.state = 'approved' THEN
            UPDATE sentinelflow.policy_proposals current_policy
            SET state = 'queued', state_revision = current_policy.state_revision + 1, updated_at = server_now
            WHERE current_policy.policy_id = policy.policy_id AND current_policy.version = policy.version
              AND current_policy.state = 'approved';
            UPDATE sentinelflow.enforcement_actions current_action
            SET state = 'queued', queued_at = server_now, version = current_action.version + 1, updated_at = server_now
            WHERE current_action.action_id = action.action_id
            RETURNING current_action.* INTO action;
        END IF;
        IF action.state <> 'queued' THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 add result action is not queued';
        END IF;
        IF p_classification IN ('applied', 'recovered_active') THEN
            IF result_bounds.remaining_ttl_seconds IS NULL OR result_bounds.expires_not_before IS NULL OR
               result_bounds.expires_not_after IS NULL OR result_bounds.remaining_ttl_seconds > action.ttl_seconds THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'v2 active result lacks valid TTL bounds';
            END IF;
            -- applied_at is a signed active observation, not an invented nft
            -- mutation instant. expected_expires_at records only the lower
            -- bound; the separate upper bound controls expiry attribution.
            next_state := 'active';
            next_applied_at := result_bounds.readback_started_at;
            next_expires_at := result_bounds.expires_not_before;
            next_finished_at := NULL;
            audit_action := 'enforcement_active'; audit_outcome := 'succeeded';
        ELSIF p_classification = 'failed' THEN
            next_state := 'failed'; next_applied_at := NULL; next_expires_at := NULL;
            next_finished_at := server_now; audit_action := 'enforcement_failed'; audit_outcome := 'failed';
        ELSIF p_classification = 'indeterminate' THEN
            next_state := 'indeterminate'; next_applied_at := NULL; next_expires_at := NULL;
            next_finished_at := NULL; audit_action := 'enforcement_indeterminate'; audit_outcome := 'indeterminate';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid v2 add lifecycle result';
        END IF;
    ELSIF p_operation = 'inspect' THEN
        SELECT schedule.* INTO source_schedule
        FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
        WHERE schedule.dispatch_job_id = p_job_id FOR UPDATE;
        IF NOT FOUND OR source_schedule.state <> 'dispatched' OR source_schedule.action_id <> p_action_id OR
           source_schedule.action_version <> action.version OR
           source_schedule.dispatch_authorization_digest <> operation.authorization_digest OR NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 inspection has no exact lifecycle schedule';
        END IF;
        IF action_bounds.action_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 inspection cannot reinterpret a v1 action';
        END IF;
        IF p_classification = 'inspect_active' THEN
            IF result_bounds.remaining_ttl_seconds IS NULL OR result_bounds.remaining_ttl_seconds > action.ttl_seconds THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid v2 inspection TTL';
            END IF;
            IF action.state NOT IN ('active', 'indeterminate') THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'active inspection cannot change terminal action';
            ELSIF result_bounds.readback_started_at >= action_bounds.expires_not_after THEN
                next_state := 'failed'; next_applied_at := action.applied_at;
                next_expires_at := action.expected_expires_at; next_finished_at := server_now;
                audit_action := 'enforcement_late_active'; audit_outcome := 'failed';
            ELSE
                next_state := 'active'; next_applied_at := action.applied_at;
                next_expires_at := action.expected_expires_at; next_finished_at := NULL;
                audit_action := CASE WHEN action.state = 'indeterminate'
                    THEN 'enforcement_recovered_active' ELSE 'enforcement_inspected_active' END;
                audit_outcome := 'succeeded';
            END IF;
        ELSIF p_classification = 'inspect_absent' THEN
            IF action.state NOT IN ('active', 'indeterminate') THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'absent inspection cannot change terminal action';
            ELSIF result_bounds.readback_started_at >= action_bounds.expires_not_after THEN
                next_state := 'expired'; next_applied_at := action.applied_at;
                next_expires_at := action.expected_expires_at; next_finished_at := server_now;
                audit_action := 'enforcement_expired'; audit_outcome := 'succeeded';
            ELSIF result_bounds.readback_completed_at < action_bounds.expires_not_before THEN
                next_state := 'failed'; next_applied_at := action.applied_at;
                next_expires_at := action.expected_expires_at; next_finished_at := server_now;
                audit_action := 'enforcement_missing_early'; audit_outcome := 'failed';
            ELSE
                -- The absent read-back overlaps the safe interval.  Neither
                -- native expiry nor early removal is proven; retry read-only.
                next_state := 'indeterminate'; next_applied_at := action.applied_at;
                next_expires_at := action.expected_expires_at; next_finished_at := NULL;
                audit_action := 'enforcement_expiry_indeterminate'; audit_outcome := 'indeterminate';
            END IF;
        ELSIF p_classification IN ('inspect_mismatch', 'failed', 'indeterminate') THEN
            IF action.state NOT IN ('active', 'indeterminate') THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'failed inspection cannot change terminal action';
            END IF;
            next_state := 'indeterminate'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := NULL;
            audit_action := 'enforcement_inspection_indeterminate'; audit_outcome := 'indeterminate';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid v2 inspect lifecycle result';
        END IF;
    ELSIF p_operation = 'revoke' THEN
        IF action_bounds.action_id IS NULL AND action.state IN ('active', 'indeterminate') THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 revoke cannot reinterpret a v1 action';
        END IF;
        IF p_classification = 'revoked' AND action.state IN ('active', 'indeterminate') AND
           result_bounds.readback_started_at >= action_bounds.expires_not_after THEN
            next_state := 'expired'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := server_now;
            audit_action := 'enforcement_revoke_after_expiry'; audit_outcome := 'succeeded';
        ELSIF p_classification = 'revoked' AND action.state IN ('active', 'indeterminate') THEN
            next_state := 'revoked'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := server_now;
            audit_action := 'enforcement_revoked'; audit_outcome := 'succeeded';
        ELSIF p_classification = 'revoked' AND action.state = 'expired' THEN
            next_state := 'expired'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := action.finished_at;
            audit_action := 'enforcement_revoke_after_expiry'; audit_outcome := 'succeeded';
        ELSIF p_classification = 'failed' AND action.state IN ('active', 'indeterminate') THEN
            next_state := 'failed'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := server_now;
            audit_action := 'enforcement_revoke_failed'; audit_outcome := 'failed';
        ELSIF p_classification = 'indeterminate' AND action.state IN ('active', 'indeterminate') THEN
            next_state := 'indeterminate'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := NULL;
            audit_action := 'enforcement_revoke_indeterminate'; audit_outcome := 'indeterminate';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 revoke cannot change current action';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid v2 lifecycle operation';
    END IF;

    IF next_state <> action.state THEN
        UPDATE sentinelflow.policy_proposals current_policy
        SET state = next_state, state_revision = current_policy.state_revision + 1, updated_at = server_now
        WHERE current_policy.policy_id = policy.policy_id AND current_policy.version = policy.version
          AND current_policy.state = action.state;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 policy lifecycle transition failed';
        END IF;
        UPDATE sentinelflow.enforcement_actions current_action
        SET state = next_state, applied_at = next_applied_at, expected_expires_at = next_expires_at,
            finished_at = next_finished_at, version = current_action.version + 1, updated_at = server_now
        WHERE current_action.action_id = action.action_id AND current_action.state = action.state
        RETURNING current_action.* INTO action;
    END IF;
    IF p_operation = 'add' AND next_state = 'active' THEN
        INSERT INTO sentinelflow.enforcement_expiry_bounds_000034 (
            action_id, source_result_id, expires_not_before, expires_not_after
        ) VALUES (
            action.action_id, p_result_id, result_bounds.expires_not_before, result_bounds.expires_not_after
        );
        SELECT * INTO action_bounds FROM sentinelflow.enforcement_expiry_bounds_000034 bounds
        WHERE bounds.action_id = action.action_id;
    END IF;

    UPDATE sentinelflow.outbox_jobs job
    SET aggregate_version = action.version, updated_at = server_now
    WHERE job.job_id = p_job_id AND job.state = 'leased' AND job.lease_token = p_lease_token;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'v2 result lease is not live';
    END IF;
    IF p_operation = 'inspect' THEN
        UPDATE sentinelflow.lifecycle_inspection_schedules_000026 current_schedule
        SET state = CASE WHEN audit_action = 'enforcement_late_active' THEN 'dead' ELSE 'completed' END,
            last_error_code = CASE WHEN audit_action = 'enforcement_late_active' THEN 'late_active' ELSE NULL END,
            last_error_digest = CASE WHEN audit_action = 'enforcement_late_active' THEN p_result_digest ELSE NULL END,
            updated_at = server_now
        WHERE current_schedule.schedule_id = source_schedule.schedule_id;
    END IF;
    IF p_operation = 'revoke' THEN
        expected_revoke_state := CASE p_classification
            WHEN 'revoked' THEN 'revoked'
            WHEN 'failed' THEN 'failed'
            WHEN 'indeterminate' THEN 'indeterminate'
            ELSE NULL
        END;
        IF expected_revoke_state IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid v2 revoke result';
        END IF;
        SELECT current_revoke.* INTO revoke
        FROM sentinelflow.revocation_operations current_revoke
        WHERE current_revoke.authorization_id = operation.enforcement_authorization_id
        FOR UPDATE;
        IF revoke.revocation_id IS NULL OR revoke.action_id <> p_action_id OR
           revoke.artifact_digest <> p_artifact_digest THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 revoke result binding failed';
        END IF;
        IF revoke.state = 'queued' THEN
            UPDATE sentinelflow.revocation_operations current_revoke
            SET state = expected_revoke_state, completed_at = p_completed_at
            WHERE current_revoke.revocation_id = revoke.revocation_id;
        ELSIF revoke.state <> expected_revoke_state OR revoke.completed_at <> p_completed_at THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'conflicting v2 revocation result replay';
        END IF;
    END IF;

    IF next_state IN ('active', 'indeterminate') AND p_operation <> 'revoke' AND
       audit_action <> 'enforcement_late_active' THEN
        schedule_id := p_result_id;
        IF next_state = 'active' THEN
            IF action_bounds.action_id IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'v2 active action lacks expiry upper bound';
            END IF;
            schedule_due_at := least(action_bounds.expires_not_after, p_completed_at + interval '30 seconds');
            schedule_purpose := CASE WHEN schedule_due_at = action_bounds.expires_not_after
                THEN 'expiry_confirmation' ELSE 'reconciliation' END;
        ELSE
            schedule_due_at := p_completed_at + interval '1 second'; schedule_purpose := 'reconciliation';
        END IF;
        INSERT INTO sentinelflow.lifecycle_inspection_schedules_000026 (
            schedule_id, authorization_id, dispatch_job_id, source_result_id,
            source_result_digest, action_id, action_version, policy_id, policy_version,
            target_ipv4, original_add_digest, original_authorization_digest,
            evidence_snapshot_digest, validation_snapshot_id, validation_snapshot_digest,
            owned_schema_digest, purpose, due_at, state, created_at, updated_at
        ) VALUES (
            schedule_id, gen_random_uuid(), gen_random_uuid(), p_result_id, p_result_digest,
            action.action_id, action.version, action.policy_id, action.policy_version,
            action.target_ipv4, action.canonical_artifact_digest,
            CASE WHEN p_operation = 'inspect' THEN source_schedule.original_authorization_digest
                 ELSE operation.authorization_digest END,
            action.evidence_snapshot_digest, action.validation_snapshot_id,
            operation.validation_snapshot_digest, p_owned_schema_digest, schedule_purpose,
            schedule_due_at, 'pending', server_now, server_now
        );
    ELSE
        schedule_id := NULL;
    END IF;
    INSERT INTO sentinelflow.lifecycle_result_applications_000026 (
        result_id, result_digest, action_id, operation, classification,
        resulting_state, resulting_action_version, schedule_id, processed_at
    ) VALUES (
        p_result_id, p_result_digest, p_action_id, p_operation, p_classification,
        next_state, action.version, schedule_id, server_now
    );
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        policy_id, policy_version, enforcement_action_id, primary_digest,
        secondary_digest, outcome, occurred_at
    ) VALUES (
        p_result_id, 'executor', 'sentinelflow_executor', audit_action,
        'enforcement_action', p_action_id, action.policy_id, action.policy_version,
        p_action_id, p_result_digest, p_capability_digest, audit_outcome, server_now
    );
END
$function$;

-- This is the dispatcher-facing v2 entry point. The redundant timestamps are
-- deliberately bound to the signed JCS so SQL cannot substitute an interval.
CREATE FUNCTION sentinelflow.record_execution_result_v2(
    p_result_id uuid, p_job_id uuid, p_lease_token uuid, p_capability_id uuid,
    p_capability_digest sentinelflow.sha256_digest, p_operation text,
    p_action_id uuid, p_artifact_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4, p_classification text,
    p_nft_exit_class text, p_readback_state text, p_element_handle bigint,
    p_remaining_ttl_seconds integer, p_owned_schema_digest sentinelflow.sha256_digest,
    p_started_at timestamptz, p_completed_at timestamptz,
    p_journal_sequence bigint, p_error_code text, p_result_jcs bytea,
    p_result_digest sentinelflow.sha256_digest, p_result_signature bytea,
    p_readback_started_at timestamptz, p_readback_completed_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    payload jsonb;
    jcs_readback_started timestamptz;
    jcs_readback_completed timestamptz;
BEGIN
    IF p_readback_started_at IS NULL OR p_readback_completed_at IS NULL OR
       NOT isfinite(p_readback_started_at) OR NOT isfinite(p_readback_completed_at) OR
       date_trunc('milliseconds', p_readback_started_at) <> p_readback_started_at OR
       date_trunc('milliseconds', p_readback_completed_at) <> p_readback_completed_at THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'v2 readback arguments are invalid';
    END IF;
    BEGIN
        payload := convert_from(p_result_jcs, 'UTF8')::jsonb;
        IF payload ->> 'schema_version' <> 'execution-result-v2' OR
           jsonb_typeof(payload -> 'readback_started_at') <> 'string' OR
           jsonb_typeof(payload -> 'readback_completed_at') <> 'string' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'v2 result JCS schema is invalid';
        END IF;
        jcs_readback_started := (payload ->> 'readback_started_at')::timestamptz;
        jcs_readback_completed := (payload ->> 'readback_completed_at')::timestamptz;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'v2 result JCS readback values are invalid';
    END;
    IF jcs_readback_started <> p_readback_started_at OR
       jcs_readback_completed <> p_readback_completed_at THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'v2 readback arguments do not bind signed JCS';
    END IF;
    PERFORM sentinelflow.record_execution_result_v2_000034(
        p_result_id, p_job_id, p_lease_token, p_capability_id,
        p_capability_digest, p_operation, p_action_id, p_artifact_digest,
        p_target_ipv4, p_classification, p_nft_exit_class, p_readback_state,
        p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
        p_started_at, p_completed_at, p_journal_sequence, p_error_code,
        p_result_jcs, p_result_digest, p_result_signature
    );
END
$function$;

CREATE FUNCTION sentinelflow.record_execution_result_pre_000027(
    p_result_id uuid, p_job_id uuid, p_lease_token uuid, p_capability_id uuid,
    p_capability_digest sentinelflow.sha256_digest, p_operation text,
    p_action_id uuid, p_artifact_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4, p_classification text,
    p_nft_exit_class text, p_readback_state text, p_element_handle bigint,
    p_remaining_ttl_seconds integer, p_owned_schema_digest sentinelflow.sha256_digest,
    p_started_at timestamptz, p_completed_at timestamptz,
    p_journal_sequence bigint, p_error_code text, p_result_jcs bytea,
    p_result_digest sentinelflow.sha256_digest, p_result_signature bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    payload jsonb;
    existing sentinelflow.execution_results%ROWTYPE;
BEGIN
    BEGIN
        payload := convert_from(p_result_jcs, 'UTF8')::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'execution result JCS is not UTF-8 JSON';
    END;
    IF payload ->> 'schema_version' = 'execution-result-v2' THEN
        PERFORM sentinelflow.record_execution_result_v2_000034(
            p_result_id, p_job_id, p_lease_token, p_capability_id,
            p_capability_digest, p_operation, p_action_id, p_artifact_digest,
            p_target_ipv4, p_classification, p_nft_exit_class, p_readback_state,
            p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
            p_started_at, p_completed_at, p_journal_sequence, p_error_code,
            p_result_jcs, p_result_digest, p_result_signature
        );
        RETURN;
    END IF;
    -- Existing v1 deliveries remain replayable.  A fresh v1 lifecycle result
    -- must not cross into a v2-bound action because it lacks the signed
    -- interval needed to decide expiry safely.
    SELECT * INTO existing FROM sentinelflow.execution_results WHERE result_id = p_result_id;
    IF NOT FOUND AND EXISTS (
        SELECT 1 FROM sentinelflow.enforcement_expiry_bounds_000034 bounds
        WHERE bounds.action_id = p_action_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'fresh execution-result-v1 cannot reinterpret a v2-bound action';
    END IF;
    PERFORM sentinelflow.record_execution_result_lifecycle_pre_000034(
        p_result_id, p_job_id, p_lease_token, p_capability_id,
        p_capability_digest, p_operation, p_action_id, p_artifact_digest,
        p_target_ipv4, p_classification, p_nft_exit_class, p_readback_state,
        p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
        p_started_at, p_completed_at, p_journal_sequence, p_error_code,
        p_result_jcs, p_result_digest, p_result_signature
    );
END
$function$;

-- Recovery is read-only and must be able to return the exact persisted v2
-- result after a dispatcher crash.  Keep the v1 checks intact; v2 additionally
-- requires the private, append-only read-back interval before exposing bytes
-- for the Go verifier to re-check the executor signature and JCS.
CREATE OR REPLACE FUNCTION sentinelflow.recover_dispatch_execution(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE (
    recovery_state text,
    capability_id uuid,
    capability_jcs bytea,
    capability_digest sentinelflow.sha256_digest,
    capability_signature bytea,
    capability_artifact bytea,
    result_id uuid,
    result_jcs bytea,
    result_digest sentinelflow.sha256_digest,
    result_signature bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    job_row sentinelflow.outbox_jobs%ROWTYPE;
    operation_row sentinelflow.dispatch_operations%ROWTYPE;
    capability_row sentinelflow.execution_capabilities%ROWTYPE;
    result_row sentinelflow.execution_results%ROWTYPE;
    result_bounds sentinelflow.execution_result_readback_bounds_000034%ROWTYPE;
    server_now timestamptz;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'SF101', MESSAGE = 'lease_lost';
    END IF;
    SELECT current_job.* INTO job_row
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF101', MESSAGE = 'lease_lost';
    END IF;
    server_now := clock_timestamp();
    IF job_row.state <> 'leased' OR job_row.lease_token IS DISTINCT FROM p_lease_token OR
       job_row.lease_expires_at IS NULL OR job_row.lease_expires_at <= server_now THEN
        RAISE EXCEPTION USING ERRCODE = 'SF101', MESSAGE = 'lease_lost';
    END IF;
    SELECT current_operation.* INTO operation_row
    FROM sentinelflow.dispatch_operations current_operation
    WHERE current_operation.job_id = p_job_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
    END IF;
    SELECT current_capability.* INTO capability_row
    FROM sentinelflow.execution_capabilities current_capability
    WHERE current_capability.job_id = p_job_id
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'none'::text, NULL::uuid, NULL::bytea,
            NULL::sentinelflow.sha256_digest, NULL::bytea, NULL::bytea,
            NULL::uuid, NULL::bytea, NULL::sentinelflow.sha256_digest, NULL::bytea;
        RETURN;
    END IF;
    IF capability_row.schema_version <> 'execution-capability-v1' OR
       capability_row.operation <> operation_row.operation OR
       capability_row.action_id <> operation_row.action_id OR
       capability_row.policy_id <> operation_row.policy_id OR
       capability_row.policy_version <> operation_row.policy_version OR
       capability_row.target_ipv4 <> operation_row.target_ipv4 OR
       capability_row.artifact <> operation_row.artifact OR
       capability_row.artifact_digest <> operation_row.artifact_digest OR
       capability_row.original_add_digest IS DISTINCT FROM operation_row.original_add_digest OR
       capability_row.evidence_snapshot_digest <> operation_row.evidence_snapshot_digest OR
       capability_row.validation_snapshot_digest <> operation_row.validation_snapshot_digest OR
       capability_row.authorization_digest <> operation_row.authorization_digest OR
       capability_row.actor_id <> operation_row.actor_id OR
       capability_row.reason_digest <> operation_row.reason_digest OR
       capability_row.owned_schema_digest <> operation_row.owned_schema_digest OR
       capability_row.capability_digest <> sentinelflow.hil_sha256(capability_row.capability_jcs) OR
       capability_row.artifact_digest <> sentinelflow.hil_sha256(capability_row.artifact) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
    END IF;
    SELECT current_result.* INTO result_row
    FROM sentinelflow.execution_results current_result
    WHERE current_result.capability_id = capability_row.capability_id
    FOR SHARE;
    IF NOT FOUND THEN
        IF capability_row.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
        END IF;
        RETURN QUERY SELECT 'capability'::text, capability_row.capability_id,
            capability_row.capability_jcs, capability_row.capability_digest,
            capability_row.capability_signature, capability_row.artifact,
            NULL::uuid, NULL::bytea, NULL::sentinelflow.sha256_digest, NULL::bytea;
        RETURN;
    END IF;
    IF result_row.schema_version = 'execution-result-v2' THEN
        SELECT * INTO result_bounds
        FROM sentinelflow.execution_result_readback_bounds_000034 bounds
        WHERE bounds.result_id = result_row.result_id;
        IF NOT FOUND OR result_bounds.remaining_ttl_seconds IS DISTINCT FROM result_row.remaining_ttl_seconds OR
           result_bounds.readback_started_at < result_row.started_at OR
           result_bounds.readback_completed_at < result_bounds.readback_started_at OR
           result_bounds.readback_completed_at > result_row.completed_at THEN
            RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
        END IF;
    ELSIF result_row.schema_version <> 'execution-result-v1' OR EXISTS (
        SELECT 1 FROM sentinelflow.execution_result_readback_bounds_000034 bounds
        WHERE bounds.result_id = result_row.result_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
    END IF;
    IF result_row.capability_id <> capability_row.capability_id OR
       result_row.capability_digest <> capability_row.capability_digest OR
       result_row.operation <> capability_row.operation OR result_row.action_id <> capability_row.action_id OR
       result_row.artifact_digest <> capability_row.artifact_digest OR
       result_row.target_ipv4 <> capability_row.target_ipv4 OR
       result_row.owned_schema_digest <> capability_row.owned_schema_digest OR
       result_row.element_handle IS NOT NULL OR capability_row.consumed_at IS NULL OR
       capability_row.consumed_at <> result_row.completed_at OR
       result_row.result_digest <> sentinelflow.hil_sha256(result_row.result_jcs) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF102', MESSAGE = 'recovery_state_invalid';
    END IF;
    RETURN QUERY SELECT 'result'::text, capability_row.capability_id,
        capability_row.capability_jcs, capability_row.capability_digest,
        capability_row.capability_signature, capability_row.artifact,
        result_row.result_id, result_row.result_jcs, result_row.result_digest,
        result_row.result_signature;
END
$function$;

-- Preserve the recovery-only completion fence for v1 and v2 results.  A v2
-- row is eligible only with its immutable read-back record; the dispatcher
-- subsequently re-verifies the signed JCS through recover_dispatch_execution.
CREATE OR REPLACE FUNCTION sentinelflow.dispatch_recovery_result_exact_000025(
    p_job_id uuid,
    p_capability_digest sentinelflow.sha256_digest,
    p_job_aggregate_version integer,
    p_server_now timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    exact boolean := false;
BEGIN
    IF p_job_id IS NULL OR p_capability_digest IS NULL OR
       p_job_aggregate_version IS NULL OR p_job_aggregate_version < 1 OR
       p_server_now IS NULL OR NOT isfinite(p_server_now) THEN
        RETURN false;
    END IF;
    SELECT EXISTS (
        SELECT 1
        FROM sentinelflow.execution_capabilities capability
        JOIN sentinelflow.execution_results result USING (capability_id)
        LEFT JOIN sentinelflow.execution_result_readback_bounds_000034 result_bounds
          ON result_bounds.result_id = result.result_id
        JOIN sentinelflow.dispatch_operations operation ON operation.job_id = capability.job_id
        JOIN sentinelflow.outbox_jobs job ON job.job_id = capability.job_id
        WHERE capability.job_id = p_job_id
          AND capability.capability_digest = p_capability_digest
          AND job.state = 'leased' AND job.operation = capability.operation
          AND job.kind = 'dispatch_' || capability.operation
          AND job.aggregate_type = 'enforcement_action'
          AND job.aggregate_id = capability.action_id
          AND job.aggregate_version = p_job_aggregate_version
          AND capability.schema_version = 'execution-capability-v1'
          AND octet_length(capability.capability_signature) = 64
          AND capability.consumed_at = result.completed_at
          AND result.schema_version IN ('execution-result-v1', 'execution-result-v2')
          AND (
              result.schema_version = 'execution-result-v1' AND result_bounds.result_id IS NULL OR
              result.schema_version = 'execution-result-v2' AND result_bounds.result_id = result.result_id
                AND result_bounds.remaining_ttl_seconds IS NOT DISTINCT FROM result.remaining_ttl_seconds
                AND result_bounds.readback_started_at >= result.started_at
                AND result_bounds.readback_completed_at >= result_bounds.readback_started_at
                AND result_bounds.readback_completed_at <= result.completed_at
          )
          AND result.capability_digest = capability.capability_digest
          AND octet_length(result.result_signature) = 64
          AND capability.operation = result.operation AND capability.action_id = result.action_id
          AND capability.artifact_digest = result.artifact_digest
          AND capability.target_ipv4 = result.target_ipv4
          AND capability.owned_schema_digest = result.owned_schema_digest
          AND capability.capability_digest = sentinelflow.hil_sha256(capability.capability_jcs)
          AND capability.artifact_digest = sentinelflow.hil_sha256(capability.artifact)
          AND result.result_digest = sentinelflow.hil_sha256(result.result_jcs)
          AND result.element_handle IS NULL AND result.completed_at <= p_server_now
          AND operation.operation = capability.operation AND operation.action_id = capability.action_id
          AND operation.policy_id = capability.policy_id AND operation.policy_version = capability.policy_version
          AND operation.target_ipv4 = capability.target_ipv4 AND operation.artifact = capability.artifact
          AND operation.artifact_digest = capability.artifact_digest
          AND operation.original_add_digest IS NOT DISTINCT FROM capability.original_add_digest
          AND operation.evidence_snapshot_digest = capability.evidence_snapshot_digest
          AND operation.validation_snapshot_digest = capability.validation_snapshot_digest
          AND operation.authorization_digest = capability.authorization_digest
          AND operation.actor_id = capability.actor_id AND operation.reason_digest = capability.reason_digest
          AND operation.owned_schema_digest = capability.owned_schema_digest
    ) INTO exact;
    IF NOT exact THEN RETURN false; END IF;
    IF to_regclass('sentinelflow.lifecycle_result_applications_000026') IS NULL THEN RETURN true; END IF;
    EXECUTE $application_query$
        SELECT EXISTS (
            SELECT 1
            FROM sentinelflow.lifecycle_result_applications_000026 application
            JOIN sentinelflow.execution_results result
              ON result.result_id = application.result_id AND result.result_digest = application.result_digest
            JOIN sentinelflow.execution_capabilities capability
              ON capability.capability_id = result.capability_id
             AND capability.capability_digest = result.capability_digest
            WHERE capability.job_id = $1 AND capability.capability_digest = $2
              AND application.action_id = capability.action_id
              AND application.operation = capability.operation
              AND application.classification = result.classification
              AND application.resulting_action_version = $3
              AND isfinite(application.processed_at)
              AND application.processed_at >= result.completed_at AND application.processed_at <= $4
              AND ((application.operation = 'add' AND (
                      (application.classification IN ('applied', 'recovered_active') AND application.resulting_state = 'active') OR
                      (application.classification = 'failed' AND application.resulting_state = 'failed') OR
                      (application.classification = 'indeterminate' AND application.resulting_state = 'indeterminate')
                  )) OR (application.operation = 'revoke' AND (
                      (application.classification = 'revoked' AND application.resulting_state IN ('revoked', 'expired')) OR
                      (application.classification = 'failed' AND application.resulting_state = 'failed') OR
                      (application.classification = 'indeterminate' AND application.resulting_state = 'indeterminate')
                  )) OR (application.operation = 'inspect' AND (
                      (application.classification = 'inspect_active' AND application.resulting_state IN ('active', 'failed')) OR
                      (application.classification = 'inspect_absent' AND application.resulting_state IN ('expired', 'failed')) OR
                      (application.classification IN ('inspect_mismatch', 'failed', 'indeterminate') AND application.resulting_state = 'indeterminate')
                  )))
        )
    $application_query$
    INTO exact USING p_job_id, p_capability_digest, p_job_aggregate_version, p_server_now;
    RETURN coalesce(exact, false);
END
$function$;

CREATE OR REPLACE VIEW sentinelflow.dispatcher_recovery_outbox_000025
WITH (security_barrier = true)
AS
SELECT
    job.job_id, job.kind, job.state, job.available_at, job.attempts,
    job.max_attempts, operation.operation, operation.action_id,
    operation.policy_id, operation.policy_version, operation.target_ipv4,
    operation.artifact, operation.artifact_digest,
    operation.original_add_digest, operation.evidence_snapshot_digest,
    operation.validation_snapshot_digest, operation.authorization_digest,
    operation.actor_id, operation.reason_digest, operation.owned_schema_digest,
    operation.not_before, operation.valid_until
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.dispatch_operations operation USING (job_id)
JOIN sentinelflow.execution_capabilities capability USING (job_id)
LEFT JOIN sentinelflow.execution_results result USING (capability_id)
LEFT JOIN sentinelflow.execution_result_readback_bounds_000034 result_bounds
  ON result_bounds.result_id = result.result_id
LEFT JOIN sentinelflow.dead_letter_jobs dead_letter USING (job_id)
WHERE job.kind IN ('dispatch_add', 'dispatch_revoke', 'dispatch_inspect')
  AND job.kind = 'dispatch_' || operation.operation
  AND job.operation = operation.operation
  AND job.aggregate_type = 'enforcement_action'
  AND job.aggregate_id = operation.action_id
  AND (
      (job.state = 'retry' AND job.available_at <= clock_timestamp() AND
       job.last_error_code = 'recovery_started' AND job.available_at >= capability.expires_at AND
       dead_letter.resolution_state = 'requeued' AND isfinite(dead_letter.dead_at) AND
       isfinite(dead_letter.resolved_at) AND dead_letter.resolved_at <= clock_timestamp() AND
       dead_letter.resolved_at = job.updated_at AND dead_letter.resolution_actor = 'sentinelflow_recovery' AND
       dead_letter.job_id = job.job_id AND dead_letter.kind = job.kind AND
       dead_letter.aggregate_type = job.aggregate_type AND dead_letter.aggregate_id = job.aggregate_id AND
       dead_letter.aggregate_version = job.aggregate_version AND dead_letter.attempts = job.attempts AND
       dead_letter.dead_at <= dead_letter.resolved_at AND
       dead_letter.resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
           job.job_id, capability.capability_digest, dead_letter.failure_code, dead_letter.failure_digest
       ) AND job.last_error_digest = dead_letter.resolution_digest) OR
      (job.state = 'leased' AND job.lease_expires_at <= clock_timestamp() AND (
       (dead_letter.job_id IS NULL AND job.last_error_code IS NULL AND job.last_error_digest IS NULL AND (
          result.result_id IS NULL OR sentinelflow.dispatch_recovery_result_exact_000025(
              job.job_id, capability.capability_digest, job.aggregate_version, clock_timestamp()
          ))) OR
       (job.last_error_code = 'recovery_started' AND job.last_error_digest = dead_letter.resolution_digest AND
        job.available_at >= capability.expires_at AND dead_letter.resolution_state = 'requeued' AND
        isfinite(dead_letter.dead_at) AND isfinite(dead_letter.resolved_at) AND
        dead_letter.resolved_at <= clock_timestamp() AND dead_letter.resolution_actor = 'sentinelflow_recovery' AND
        dead_letter.job_id = job.job_id AND dead_letter.kind = job.kind AND
        dead_letter.aggregate_type = job.aggregate_type AND dead_letter.aggregate_id = job.aggregate_id AND
        dead_letter.attempts = job.attempts AND dead_letter.dead_at <= dead_letter.resolved_at AND
        dead_letter.resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
            job.job_id, capability.capability_digest, dead_letter.failure_code, dead_letter.failure_digest
        ) AND ((result.result_id IS NULL AND dead_letter.aggregate_version = job.aggregate_version) OR
          (result.result_id IS NOT NULL AND dead_letter.aggregate_version IN (
              job.aggregate_version, job.aggregate_version - 1
          ) AND sentinelflow.dispatch_recovery_result_exact_000025(
              job.job_id, capability.capability_digest, job.aggregate_version, clock_timestamp()
          ))))
      )))
  AND capability.expires_at <= clock_timestamp()
  AND capability.schema_version = 'execution-capability-v1'
  AND capability.operation = operation.operation AND capability.action_id = operation.action_id
  AND capability.policy_id = operation.policy_id AND capability.policy_version = operation.policy_version
  AND capability.target_ipv4 = operation.target_ipv4 AND capability.artifact = operation.artifact
  AND capability.artifact_digest = operation.artifact_digest
  AND capability.original_add_digest IS NOT DISTINCT FROM operation.original_add_digest
  AND capability.evidence_snapshot_digest = operation.evidence_snapshot_digest
  AND capability.validation_snapshot_digest = operation.validation_snapshot_digest
  AND capability.authorization_digest = operation.authorization_digest
  AND capability.actor_id = operation.actor_id AND capability.reason_digest = operation.reason_digest
  AND capability.owned_schema_digest = operation.owned_schema_digest
  AND capability.artifact_digest =
      ('sha256:' || encode(sha256(capability.artifact), 'hex'))::sentinelflow.sha256_digest
  AND capability.capability_digest =
      ('sha256:' || encode(sha256(capability.capability_jcs), 'hex'))::sentinelflow.sha256_digest
  AND (
      (result.result_id IS NULL AND capability.consumed_at IS NULL) OR
      (result.result_id IS NOT NULL AND capability.consumed_at = result.completed_at AND
       result.schema_version IN ('execution-result-v1', 'execution-result-v2') AND
       (result.schema_version = 'execution-result-v1' AND result_bounds.result_id IS NULL OR
        result.schema_version = 'execution-result-v2' AND result_bounds.result_id = result.result_id AND
          result_bounds.remaining_ttl_seconds IS NOT DISTINCT FROM result.remaining_ttl_seconds AND
          result_bounds.readback_started_at >= result.started_at AND
          result_bounds.readback_completed_at >= result_bounds.readback_started_at AND
          result_bounds.readback_completed_at <= result.completed_at) AND
       result.capability_digest = capability.capability_digest AND result.operation = capability.operation AND
       result.action_id = capability.action_id AND result.artifact_digest = capability.artifact_digest AND
       result.target_ipv4 = capability.target_ipv4 AND result.owned_schema_digest = capability.owned_schema_digest AND
       result.result_digest =
           ('sha256:' || encode(sha256(result.result_jcs), 'hex'))::sentinelflow.sha256_digest AND
       result.element_handle IS NULL)
  );

ALTER FUNCTION sentinelflow.record_execution_result_pre_000026(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) OWNER TO sentinelflow_migration;
ALTER FUNCTION sentinelflow.record_execution_result_pre_000027(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) OWNER TO sentinelflow_migration;
ALTER FUNCTION sentinelflow.record_execution_result_v2_000034(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) OWNER TO sentinelflow_migration;
ALTER FUNCTION sentinelflow.record_execution_result_v2(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea,
    timestamptz, timestamptz
) OWNER TO sentinelflow_migration;
REVOKE ALL ON TABLE sentinelflow.execution_result_readback_bounds_000034,
    sentinelflow.enforcement_expiry_bounds_000034
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
     sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention,
     sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result_pre_000026(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention,
       sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result_pre_000027(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention,
       sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result_v2_000034(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention,
       sentinelflow_metrics;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result_v2(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea,
    timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_lifecycle, sentinelflow_retention, sentinelflow_metrics;
GRANT EXECUTE ON FUNCTION sentinelflow.record_execution_result_v2(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea,
    timestamptz, timestamptz
) TO sentinelflow_dispatcher;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (34, 'execution_result_v2_expiry_bounds');

COMMIT;
