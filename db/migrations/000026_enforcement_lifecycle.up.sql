BEGIN;

DO $lifecycle_role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinelflow_lifecycle') THEN
        CREATE ROLE sentinelflow_lifecycle
            LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles role
        WHERE role.rolname = 'sentinelflow_lifecycle'
          AND (NOT role.rolcanlogin OR role.rolinherit OR role.rolsuper OR
               role.rolcreatedb OR role.rolcreaterole OR role.rolreplication OR
               role.rolbypassrls OR role.rolconnlimit <> 4)
    ) OR EXISTS (
        SELECT 1
        FROM pg_auth_members membership
        JOIN pg_roles member ON member.oid = membership.member
        JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
        WHERE member.rolname = 'sentinelflow_lifecycle'
           OR granted_role.rolname = 'sentinelflow_lifecycle'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'lifecycle role has inherited or elevated authority';
    END IF;
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO sentinelflow_lifecycle', current_database()
    );
    EXECUTE format(
        'ALTER ROLE sentinelflow_lifecycle IN DATABASE %I '
        'SET search_path = sentinelflow, pg_catalog', current_database()
    );
END
$lifecycle_role$;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Pre-000026 execution rows have no trustworthy lifecycle application ledger.
-- Do not guess state or synthesize inspection schedules during upgrade.
DO $execution_evidence_preflight$
BEGIN
    IF EXISTS (SELECT 1 FROM sentinelflow.execution_capabilities) OR
       EXISTS (SELECT 1 FROM sentinelflow.execution_results) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'pre-000026 execution artifacts require explicit lifecycle migration';
    END IF;
END
$execution_evidence_preflight$;

-- Mutation jobs remain unique for one aggregate version. Read-only inspect is
-- intentionally repeatable and is instead fenced by its globally unique JCS
-- idempotency digest and immutable lifecycle schedule.
DROP INDEX sentinelflow.outbox_jobs_business_effect_idx;
CREATE UNIQUE INDEX outbox_jobs_business_effect_idx
    ON sentinelflow.outbox_jobs (
        kind, aggregate_type, aggregate_id, aggregate_version, operation
    ) NULLS NOT DISTINCT
    WHERE kind <> 'dispatch_inspect';

CREATE TABLE sentinelflow.lifecycle_inspection_schedules_000026 (
    schedule_id uuid PRIMARY KEY,
    authorization_id uuid NOT NULL UNIQUE,
    dispatch_job_id uuid NOT NULL UNIQUE,
    source_result_id uuid NOT NULL UNIQUE
        REFERENCES sentinelflow.execution_results (result_id) ON DELETE RESTRICT,
    source_result_digest sentinelflow.sha256_digest NOT NULL,
    action_id uuid NOT NULL
        REFERENCES sentinelflow.enforcement_actions (action_id) ON DELETE RESTRICT,
    action_version integer NOT NULL CHECK (action_version >= 1),
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version >= 1),
    target_ipv4 sentinelflow.canonical_ipv4 NOT NULL,
    original_add_digest sentinelflow.sha256_digest NOT NULL,
    original_authorization_digest sentinelflow.sha256_digest NOT NULL,
    evidence_snapshot_digest sentinelflow.sha256_digest NOT NULL,
    validation_snapshot_id uuid NOT NULL
        REFERENCES sentinelflow.validation_snapshots (validation_snapshot_id) ON DELETE RESTRICT,
    validation_snapshot_digest sentinelflow.sha256_digest NOT NULL,
    owned_schema_digest sentinelflow.sha256_digest NOT NULL,
    purpose text NOT NULL CHECK (
        purpose IN ('reconciliation', 'expiry_confirmation', 'operator_status')
    ),
    due_at timestamptz NOT NULL,
    state text NOT NULL CHECK (
        state IN ('pending', 'leased', 'retry', 'dispatched', 'completed', 'dead')
    ),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    max_attempts integer NOT NULL DEFAULT 8 CHECK (max_attempts = 8),
    scheduler_id sentinelflow.ascii_id NULL,
    lease_owner sentinelflow.ascii_id NULL,
    lease_token uuid NULL,
    leased_at timestamptz NULL,
    lease_expires_at timestamptz NULL,
    authorization_requested_at timestamptz NULL,
    authorization_valid_until timestamptz NULL,
    last_error_code sentinelflow.ascii_id NULL,
    last_error_digest sentinelflow.sha256_digest NULL,
    dispatch_authorization_digest sentinelflow.sha256_digest NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT lifecycle_schedule_policy_fk
        FOREIGN KEY (policy_id, policy_version)
        REFERENCES sentinelflow.policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT lifecycle_schedule_time_order CHECK (
        isfinite(due_at) AND isfinite(created_at) AND isfinite(updated_at) AND
        updated_at >= created_at
    ),
    CONSTRAINT lifecycle_schedule_lease_shape CHECK (
        (state = 'pending' AND scheduler_id IS NULL AND lease_owner IS NULL AND
            lease_token IS NULL AND leased_at IS NULL AND lease_expires_at IS NULL AND
            authorization_requested_at IS NULL AND authorization_valid_until IS NULL) OR
        (state = 'dead' AND scheduler_id IS NULL AND lease_owner IS NULL AND
            lease_token IS NULL AND leased_at IS NULL AND lease_expires_at IS NULL AND
            authorization_requested_at IS NULL AND authorization_valid_until IS NULL) OR
        (state <> 'pending' AND scheduler_id IS NOT NULL AND lease_owner IS NOT NULL AND
            lease_token IS NOT NULL AND leased_at IS NOT NULL AND lease_expires_at IS NOT NULL AND
            authorization_requested_at IS NOT NULL AND authorization_valid_until IS NOT NULL AND
            lease_expires_at > leased_at AND lease_expires_at <= leased_at + interval '60 seconds' AND
            authorization_requested_at = leased_at AND
            authorization_valid_until > authorization_requested_at AND
            authorization_valid_until <= authorization_requested_at + interval '5 minutes')
    ),
    CONSTRAINT lifecycle_schedule_outcome_shape CHECK (
        (state IN ('pending', 'leased') AND last_error_code IS NULL AND
            last_error_digest IS NULL AND dispatch_authorization_digest IS NULL) OR
        (state = 'retry' AND last_error_code IS NOT NULL AND
            last_error_digest IS NOT NULL AND dispatch_authorization_digest IS NULL AND
            due_at >= updated_at) OR
        (state IN ('dispatched', 'completed') AND last_error_code IS NULL AND
            last_error_digest IS NULL AND dispatch_authorization_digest IS NOT NULL) OR
        (state = 'dead' AND last_error_code IS NOT NULL AND last_error_digest IS NOT NULL)
    )
);

CREATE INDEX lifecycle_inspection_schedules_due_000026_idx
    ON sentinelflow.lifecycle_inspection_schedules_000026 (due_at, created_at, schedule_id)
    WHERE state IN ('pending', 'retry', 'leased');
CREATE INDEX lifecycle_inspection_schedules_action_000026_idx
    ON sentinelflow.lifecycle_inspection_schedules_000026
       (action_id, action_version, created_at);

CREATE TABLE sentinelflow.lifecycle_inspection_artifacts_000026 (
    schedule_id uuid PRIMARY KEY
        REFERENCES sentinelflow.lifecycle_inspection_schedules_000026 (schedule_id)
        ON DELETE RESTRICT,
    authorization_id uuid NOT NULL UNIQUE
        REFERENCES sentinelflow.inspection_authorizations (authorization_id) ON DELETE RESTRICT,
    dispatch_job_id uuid NOT NULL UNIQUE
        REFERENCES sentinelflow.outbox_jobs (job_id) ON DELETE RESTRICT,
    inspect_artifact bytea NOT NULL CHECK (octet_length(inspect_artifact) BETWEEN 2 AND 4096),
    inspect_artifact_digest sentinelflow.sha256_digest NOT NULL UNIQUE,
    authorization_jcs bytea NOT NULL CHECK (octet_length(authorization_jcs) BETWEEN 2 AND 8192),
    authorization_digest sentinelflow.sha256_digest NOT NULL UNIQUE,
    persisted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT lifecycle_inspect_artifact_digest_exact CHECK (
        inspect_artifact_digest = (
            'sha256:' || encode(sha256(inspect_artifact), 'hex')
        )::sentinelflow.sha256_digest
    ),
    CONSTRAINT lifecycle_inspect_authorization_digest_exact CHECK (
        authorization_digest = (
            'sha256:' || encode(sha256(authorization_jcs), 'hex')
        )::sentinelflow.sha256_digest
    )
);

CREATE TABLE sentinelflow.lifecycle_capability_applications_000026 (
    capability_id uuid PRIMARY KEY
        REFERENCES sentinelflow.execution_capabilities (capability_id) ON DELETE RESTRICT,
    capability_digest sentinelflow.sha256_digest NOT NULL UNIQUE,
    job_id uuid NOT NULL UNIQUE REFERENCES sentinelflow.outbox_jobs (job_id) ON DELETE RESTRICT,
    action_id uuid NOT NULL REFERENCES sentinelflow.enforcement_actions (action_id) ON DELETE RESTRICT,
    queued_action_version integer NOT NULL CHECK (queued_action_version >= 2),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE sentinelflow.lifecycle_result_applications_000026 (
    result_id uuid PRIMARY KEY
        REFERENCES sentinelflow.execution_results (result_id) ON DELETE RESTRICT,
    result_digest sentinelflow.sha256_digest NOT NULL UNIQUE,
    action_id uuid NOT NULL REFERENCES sentinelflow.enforcement_actions (action_id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('add', 'revoke', 'inspect')),
    classification text NOT NULL CHECK (classification IN (
        'applied', 'recovered_active', 'revoked', 'inspect_active', 'inspect_absent',
        'inspect_mismatch', 'failed', 'indeterminate'
    )),
    resulting_state text NOT NULL CHECK (resulting_state IN (
        'active', 'expired', 'failed', 'revoked', 'indeterminate'
    )),
    resulting_action_version integer NOT NULL CHECK (resulting_action_version >= 1),
    schedule_id uuid NULL REFERENCES sentinelflow.lifecycle_inspection_schedules_000026 (schedule_id)
        ON DELETE RESTRICT,
    processed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION sentinelflow.lifecycle_inspect_jcs_000026(
    p_action_id uuid,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_original_add_digest sentinelflow.sha256_digest,
    p_owned_schema_digest sentinelflow.sha256_digest,
    p_purpose text
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"action_id":' || sentinelflow.hil_jcs_string(p_action_id::text) ||
        ',"operation":"inspect","original_add_digest":' ||
            sentinelflow.hil_jcs_string(p_original_add_digest::text) ||
        ',"owned_schema_digest":' || sentinelflow.hil_jcs_string(p_owned_schema_digest::text) ||
        ',"purpose":' || sentinelflow.hil_jcs_string(p_purpose) ||
        ',"schema_version":"nft-inspect-v1","target_ipv4":' ||
            sentinelflow.hil_jcs_string(host(p_target_ipv4)) || '}',
        'UTF8'
    );
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.lifecycle_schedule_idempotency_000026(
    p_schedule_id uuid
)
RETURNS sentinelflow.sha256_digest
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog
AS $function$
    SELECT ('sha256:' || encode(sha256(convert_to(
        'sentinelflow inspection-schedule-idempotency-v1' || chr(10) ||
        p_schedule_id::text || chr(10), 'UTF8'
    )), 'hex'))::sentinelflow.sha256_digest;
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.lifecycle_inspection_authorization_jcs_000026(
    p_action_id uuid,
    p_artifact_digest sentinelflow.sha256_digest,
    p_authorization_id uuid,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_idempotency_key_digest sentinelflow.sha256_digest,
    p_original_add_digest sentinelflow.sha256_digest,
    p_original_authorization_digest sentinelflow.sha256_digest,
    p_owned_schema_digest sentinelflow.sha256_digest,
    p_policy_id uuid,
    p_policy_version integer,
    p_purpose text,
    p_requested_at timestamptz,
    p_scheduler_id sentinelflow.ascii_id,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_valid_until timestamptz,
    p_validation_snapshot_digest sentinelflow.sha256_digest
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT convert_to(
        '{"action_id":' || sentinelflow.hil_jcs_string(p_action_id::text) ||
        ',"artifact_digest":' || sentinelflow.hil_jcs_string(p_artifact_digest::text) ||
        ',"authorization_id":' || sentinelflow.hil_jcs_string(p_authorization_id::text) ||
        ',"evidence_snapshot_digest":' || sentinelflow.hil_jcs_string(p_evidence_snapshot_digest::text) ||
        ',"idempotency_key_digest":' || sentinelflow.hil_jcs_string(p_idempotency_key_digest::text) ||
        ',"original_add_digest":' || sentinelflow.hil_jcs_string(p_original_add_digest::text) ||
        ',"original_authorization_digest":' ||
            sentinelflow.hil_jcs_string(p_original_authorization_digest::text) ||
        ',"owned_schema_digest":' || sentinelflow.hil_jcs_string(p_owned_schema_digest::text) ||
        ',"policy_id":' || sentinelflow.hil_jcs_string(p_policy_id::text) ||
        ',"policy_version":' || p_policy_version::text ||
        ',"purpose":' || sentinelflow.hil_jcs_string(p_purpose) ||
        ',"requested_at":' || sentinelflow.hil_jcs_string(sentinelflow.hil_rfc3339(p_requested_at)) ||
        ',"scheduler_id":' || sentinelflow.hil_jcs_string(p_scheduler_id::text) ||
        ',"schema_version":"inspection-authorization-v1","target_ipv4":' ||
            sentinelflow.hil_jcs_string(host(p_target_ipv4)) ||
        ',"valid_until":' || sentinelflow.hil_jcs_string(sentinelflow.hil_rfc3339(p_valid_until)) ||
        ',"validation_snapshot_digest":' ||
            sentinelflow.hil_jcs_string(p_validation_snapshot_digest::text) || '}',
        'UTF8'
    );
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.enforce_action_transition_000026()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'approved' OR NEW.version <> 1 OR
           NEW.queued_at IS NOT NULL OR NEW.applied_at IS NOT NULL OR
           NEW.expected_expires_at IS NOT NULL OR NEW.finished_at IS NOT NULL OR
           NEW.nft_element_handle IS NOT NULL OR NOT EXISTS (
               SELECT 1 FROM sentinelflow.policy_proposals policy
               WHERE policy.policy_id = NEW.policy_id
                 AND policy.version = NEW.policy_version
                 AND policy.state = 'approved'
                 AND policy.target_ipv4 = NEW.target_ipv4
                 AND policy.canonical_artifact_digest = NEW.canonical_artifact_digest
                 AND policy.ttl_seconds = NEW.ttl_seconds
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'enforcement action must begin as an exact approved policy action';
        END IF;
        RETURN NEW;
    END IF;

    IF (to_jsonb(NEW) - 'state' - 'queued_at' - 'applied_at' -
            'expected_expires_at' - 'finished_at' - 'version' - 'updated_at') <>
       (to_jsonb(OLD) - 'state' - 'queued_at' - 'applied_at' -
            'expected_expires_at' - 'finished_at' - 'version' - 'updated_at') OR
       NEW.nft_element_handle IS NOT NULL OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'enforcement action immutable fields changed';
    END IF;

    IF NEW.state = OLD.state THEN
        IF NEW.version <> OLD.version OR NEW.queued_at IS DISTINCT FROM OLD.queued_at OR
           NEW.applied_at IS DISTINCT FROM OLD.applied_at OR
           NEW.expected_expires_at IS DISTINCT FROM OLD.expected_expires_at OR
           NEW.finished_at IS DISTINCT FROM OLD.finished_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'idempotent enforcement action write changed lifecycle data';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.version <> OLD.version + 1 OR NOT (
        (OLD.state = 'approved' AND NEW.state = 'queued') OR
        (OLD.state = 'queued' AND NEW.state IN ('active', 'failed', 'indeterminate')) OR
        (OLD.state = 'active' AND NEW.state IN ('expired', 'failed', 'revoked', 'indeterminate')) OR
        (OLD.state = 'indeterminate' AND NEW.state IN ('active', 'expired', 'failed', 'revoked'))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'enforcement action state transition is not allowed';
    END IF;

    IF NEW.state = 'queued' AND (
        NEW.queued_at IS NULL OR NEW.applied_at IS NOT NULL OR
        NEW.expected_expires_at IS NOT NULL OR NEW.finished_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid queued action shape';
    ELSIF NEW.state = 'active' AND (
        NEW.queued_at IS NULL OR NEW.applied_at IS NULL OR
        NEW.expected_expires_at IS NULL OR
        NEW.expected_expires_at <= NEW.applied_at OR NEW.finished_at IS NOT NULL OR
        NEW.expected_expires_at > NEW.applied_at + make_interval(secs => NEW.ttl_seconds)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid active action shape';
    ELSIF NEW.state IN ('expired', 'failed', 'revoked') AND NEW.finished_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'terminal action lacks finish time';
    ELSIF NEW.state = 'indeterminate' AND NEW.finished_at IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'indeterminate action cannot be terminal';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.policy_proposals policy
        WHERE policy.policy_id = NEW.policy_id
          AND policy.version = NEW.policy_version
          AND policy.state = NEW.state
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'policy and enforcement action lifecycle state diverged';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS enforcement_actions_transition_000026
    ON sentinelflow.enforcement_actions;
CREATE TRIGGER enforcement_actions_transition_000026
BEFORE INSERT OR UPDATE ON sentinelflow.enforcement_actions
FOR EACH ROW EXECUTE FUNCTION sentinelflow.enforce_action_transition_000026();

CREATE OR REPLACE FUNCTION sentinelflow.claim_lifecycle_inspection_schedule_000026(
    p_scheduler_id sentinelflow.ascii_id,
    p_lease_owner sentinelflow.ascii_id,
    p_lease_seconds integer
)
RETURNS TABLE (
    schedule_identity text,
    lease_identity text,
    authorization_id text,
    action_id text,
    action_version integer,
    policy_id text,
    policy_version integer,
    target_ipv4 text,
    original_add_digest text,
    original_authorization_digest text,
    evidence_snapshot_digest text,
    validation_snapshot_digest text,
    owned_schema_digest text,
    purpose text,
    requested_at timestamptz,
    valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    selected sentinelflow.lifecycle_inspection_schedules_000026%ROWTYPE;
    new_lease uuid;
BEGIN
    IF p_scheduler_id !~ '^[a-z0-9][a-z0-9._-]{0,127}$' OR
       p_lease_owner !~ '^[a-z0-9][a-z0-9._-]{0,127}$' OR
       p_lease_seconds NOT BETWEEN 1 AND 60 THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid lifecycle schedule claim';
    END IF;

    WITH exhausted AS (
        UPDATE sentinelflow.lifecycle_inspection_schedules_000026 schedule
        SET state = 'dead', last_error_code = 'lease_attempts_exhausted',
            last_error_digest = (
                'sha256:' || encode(sha256(convert_to(
                    'sentinelflow lifecycle-schedule-failure-v1' || chr(10) ||
                    'lease_attempts_exhausted' || chr(10), 'UTF8'
                )), 'hex')
            )::sentinelflow.sha256_digest,
            updated_at = server_now
        WHERE schedule.state = 'leased' AND schedule.lease_expires_at <= server_now
          AND schedule.attempts >= schedule.max_attempts
        RETURNING schedule.*
    )
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        policy_id, policy_version, enforcement_action_id, primary_digest,
        secondary_digest, outcome, occurred_at
    )
    SELECT exhausted.authorization_id, 'system',
        coalesce(exhausted.scheduler_id, 'sentinelflow_lifecycle')::sentinelflow.ascii_id,
        'inspection_schedule_dead', 'enforcement_action', exhausted.action_id,
        exhausted.policy_id, exhausted.policy_version, exhausted.action_id,
        exhausted.last_error_digest, exhausted.source_result_digest, 'failed', server_now
    FROM exhausted;

    -- A manual revoke, expiry transition, or another fenced result can make a
    -- not-yet-dispatched schedule obsolete. Persist that loss explicitly.
    WITH stale AS (
        UPDATE sentinelflow.lifecycle_inspection_schedules_000026 schedule
        SET state = 'dead', last_error_code = 'binding_stale',
            last_error_digest = (
                'sha256:' || encode(sha256(convert_to(
                    'sentinelflow lifecycle-schedule-failure-v1' || chr(10) ||
                    'binding_stale' || chr(10), 'UTF8'
                )), 'hex')
            )::sentinelflow.sha256_digest,
            updated_at = server_now
        WHERE schedule.state IN ('pending', 'retry', 'leased')
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.enforcement_actions action
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = action.policy_id
               AND policy.version = action.policy_version
               AND policy.state = action.state
              WHERE action.action_id = schedule.action_id
                AND action.version = schedule.action_version
                AND action.state IN ('active', 'indeterminate')
          )
        RETURNING schedule.*
    )
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        policy_id, policy_version, enforcement_action_id, primary_digest,
        secondary_digest, outcome, occurred_at
    )
    SELECT stale.authorization_id, 'system',
        coalesce(stale.scheduler_id, 'sentinelflow_lifecycle')::sentinelflow.ascii_id,
        'inspection_schedule_stale', 'enforcement_action', stale.action_id,
        stale.policy_id, stale.policy_version, stale.action_id,
        stale.last_error_digest, stale.source_result_digest, 'failed', server_now
    FROM stale;

    SELECT schedule.* INTO selected
    FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
    JOIN sentinelflow.enforcement_actions action
      ON action.action_id = schedule.action_id
     AND action.version = schedule.action_version
     AND action.state IN ('active', 'indeterminate')
    JOIN sentinelflow.policy_proposals policy
      ON policy.policy_id = schedule.policy_id
     AND policy.version = schedule.policy_version
     AND policy.state = action.state
    JOIN sentinelflow.execution_results source_result
      ON source_result.result_id = schedule.source_result_id
     AND source_result.result_digest = schedule.source_result_digest
     AND source_result.action_id = schedule.action_id
    WHERE schedule.attempts < schedule.max_attempts
      AND schedule.due_at <= server_now
      AND (
          schedule.state IN ('pending', 'retry') OR
          (schedule.state = 'leased' AND schedule.lease_expires_at <= server_now)
      )
    ORDER BY schedule.due_at, schedule.created_at, schedule.schedule_id
    FOR UPDATE OF schedule SKIP LOCKED
    LIMIT 1;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    new_lease := gen_random_uuid();
    UPDATE sentinelflow.lifecycle_inspection_schedules_000026 schedule
    SET state = 'leased', attempts = schedule.attempts + 1,
        scheduler_id = p_scheduler_id, lease_owner = p_lease_owner,
        lease_token = new_lease, leased_at = server_now,
        lease_expires_at = server_now + make_interval(secs => p_lease_seconds),
        authorization_requested_at = server_now,
        authorization_valid_until = server_now + interval '5 minutes',
        last_error_code = NULL, last_error_digest = NULL,
        updated_at = server_now
    WHERE schedule.schedule_id = selected.schedule_id
    RETURNING schedule.* INTO selected;

    schedule_identity := selected.schedule_id::text;
    lease_identity := selected.lease_token::text;
    authorization_id := selected.authorization_id::text;
    action_id := selected.action_id::text;
    action_version := selected.action_version;
    policy_id := selected.policy_id::text;
    policy_version := selected.policy_version;
    target_ipv4 := host(selected.target_ipv4);
    original_add_digest := selected.original_add_digest::text;
    original_authorization_digest := selected.original_authorization_digest::text;
    evidence_snapshot_digest := selected.evidence_snapshot_digest::text;
    validation_snapshot_digest := selected.validation_snapshot_digest::text;
    owned_schema_digest := selected.owned_schema_digest::text;
    purpose := selected.purpose;
    requested_at := selected.authorization_requested_at;
    valid_until := selected.authorization_valid_until;
    RETURN NEXT;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.commit_lifecycle_inspection_000026(
    p_schedule_id uuid,
    p_lease_token uuid,
    p_action_version integer,
    p_scheduler_id sentinelflow.ascii_id,
    p_authorization_id uuid,
    p_inspect_artifact bytea,
    p_inspect_artifact_digest sentinelflow.sha256_digest,
    p_authorization_jcs bytea,
    p_authorization_digest sentinelflow.sha256_digest
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    schedule sentinelflow.lifecycle_inspection_schedules_000026%ROWTYPE;
    expected_inspect bytea;
    expected_authorization bytea;
    expected_idempotency sentinelflow.sha256_digest;
    system_reason_digest sentinelflow.sha256_digest;
    existing sentinelflow.lifecycle_inspection_artifacts_000026%ROWTYPE;
BEGIN
    SELECT current_schedule.* INTO schedule
    FROM sentinelflow.lifecycle_inspection_schedules_000026 current_schedule
    WHERE current_schedule.schedule_id = p_schedule_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lifecycle lease is not live';
    END IF;

    IF schedule.state IN ('dispatched', 'completed') THEN
        SELECT artifact.* INTO existing
        FROM sentinelflow.lifecycle_inspection_artifacts_000026 artifact
        WHERE artifact.schedule_id = p_schedule_id;
        IF existing.schedule_id = p_schedule_id AND schedule.lease_token = p_lease_token AND
           schedule.action_version = p_action_version AND schedule.scheduler_id = p_scheduler_id AND
           schedule.authorization_id = p_authorization_id AND
           existing.authorization_id = p_authorization_id AND
           existing.inspect_artifact = p_inspect_artifact AND
           existing.inspect_artifact_digest = p_inspect_artifact_digest AND
           existing.authorization_jcs = p_authorization_jcs AND
           existing.authorization_digest = p_authorization_digest AND
           schedule.dispatch_authorization_digest = p_authorization_digest THEN
            RETURN 'replayed';
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505',
            MESSAGE = 'conflicting lifecycle inspection replay';
    END IF;

    IF schedule.state <> 'leased' OR schedule.lease_token <> p_lease_token OR
       schedule.lease_expires_at <= server_now OR schedule.action_version <> p_action_version OR
       schedule.scheduler_id <> p_scheduler_id OR schedule.authorization_id <> p_authorization_id OR
       NOT EXISTS (
           SELECT 1 FROM sentinelflow.enforcement_actions action
           JOIN sentinelflow.policy_proposals policy
             ON policy.policy_id = action.policy_id AND policy.version = action.policy_version
           WHERE action.action_id = schedule.action_id
             AND action.version = schedule.action_version
             AND action.state IN ('active', 'indeterminate')
             AND policy.state = action.state
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lifecycle lease is not live';
    END IF;

    expected_inspect := sentinelflow.lifecycle_inspect_jcs_000026(
        schedule.action_id, schedule.target_ipv4, schedule.original_add_digest,
        schedule.owned_schema_digest, schedule.purpose
    );
    expected_idempotency := sentinelflow.lifecycle_schedule_idempotency_000026(schedule.schedule_id);
    expected_authorization := sentinelflow.lifecycle_inspection_authorization_jcs_000026(
        schedule.action_id,
        ('sha256:' || encode(sha256(expected_inspect), 'hex'))::sentinelflow.sha256_digest,
        schedule.authorization_id, schedule.evidence_snapshot_digest,
        expected_idempotency, schedule.original_add_digest,
        schedule.original_authorization_digest, schedule.owned_schema_digest,
        schedule.policy_id, schedule.policy_version, schedule.purpose,
        schedule.authorization_requested_at, schedule.scheduler_id,
        schedule.target_ipv4, schedule.authorization_valid_until,
        schedule.validation_snapshot_digest
    );
    IF p_inspect_artifact <> expected_inspect OR
       p_inspect_artifact_digest <>
           ('sha256:' || encode(sha256(expected_inspect), 'hex'))::sentinelflow.sha256_digest OR
       p_authorization_jcs <> expected_authorization OR
       p_authorization_digest <>
           ('sha256:' || encode(sha256(expected_authorization), 'hex'))::sentinelflow.sha256_digest THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'lifecycle inspection artifact binding failed';
    END IF;

    system_reason_digest := (
        'sha256:' || encode(sha256(convert_to(
            'sentinelflow inspection system reason v1' || chr(10) || schedule.purpose || chr(10),
            'UTF8'
        )), 'hex')
    )::sentinelflow.sha256_digest;

    INSERT INTO sentinelflow.inspection_authorizations (
        authorization_id, schema_version, purpose, action_id, policy_id,
        policy_version, target_ipv4, original_add_digest,
        original_authorization_digest, evidence_snapshot_digest,
        validation_snapshot_digest, artifact_digest, owned_schema_digest,
        scheduler_id, requested_at, valid_until, idempotency_key_digest,
        authorization_digest
    ) VALUES (
        schedule.authorization_id, 'inspection-authorization-v1', schedule.purpose,
        schedule.action_id, schedule.policy_id, schedule.policy_version,
        schedule.target_ipv4, schedule.original_add_digest,
        schedule.original_authorization_digest, schedule.evidence_snapshot_digest,
        schedule.validation_snapshot_digest, p_inspect_artifact_digest,
        schedule.owned_schema_digest, schedule.scheduler_id,
        schedule.authorization_requested_at, schedule.authorization_valid_until,
        expected_idempotency, p_authorization_digest
    );

    INSERT INTO sentinelflow.outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        operation, idempotency_key, state, available_at, max_attempts,
        created_at, updated_at
    ) VALUES (
        schedule.dispatch_job_id, 'dispatch_inspect', 'enforcement_action',
        schedule.action_id, schedule.action_version, 'inspect', expected_idempotency,
        'pending', server_now, 8, server_now, server_now
    );

    INSERT INTO sentinelflow.dispatch_operations (
        job_id, operation, action_id, policy_id, policy_version, target_ipv4,
        artifact, artifact_digest, original_add_digest, evidence_snapshot_digest,
        validation_snapshot_id, validation_snapshot_digest,
        enforcement_authorization_id, inspection_authorization_id,
        authorization_digest, actor_id, reason_digest, owned_schema_digest,
        not_before, valid_until, created_at
    ) VALUES (
        schedule.dispatch_job_id, 'inspect', schedule.action_id, schedule.policy_id,
        schedule.policy_version, schedule.target_ipv4, p_inspect_artifact,
        p_inspect_artifact_digest, schedule.original_add_digest,
        schedule.evidence_snapshot_digest, schedule.validation_snapshot_id,
        schedule.validation_snapshot_digest, NULL, schedule.authorization_id,
        p_authorization_digest, schedule.scheduler_id, system_reason_digest,
        schedule.owned_schema_digest, schedule.authorization_requested_at,
        schedule.authorization_valid_until, server_now
    );

    INSERT INTO sentinelflow.lifecycle_inspection_artifacts_000026 (
        schedule_id, authorization_id, dispatch_job_id, inspect_artifact,
        inspect_artifact_digest, authorization_jcs, authorization_digest,
        persisted_at
    ) VALUES (
        schedule.schedule_id, schedule.authorization_id, schedule.dispatch_job_id,
        p_inspect_artifact, p_inspect_artifact_digest, p_authorization_jcs,
        p_authorization_digest, server_now
    );

    UPDATE sentinelflow.lifecycle_inspection_schedules_000026 current_schedule
    SET state = 'dispatched', dispatch_authorization_digest = p_authorization_digest,
        last_error_code = NULL, last_error_digest = NULL, updated_at = server_now
    WHERE current_schedule.schedule_id = schedule.schedule_id;

    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        policy_id, policy_version, enforcement_action_id, primary_digest,
        secondary_digest, outcome, occurred_at
    ) VALUES (
        schedule.authorization_id, 'system', schedule.scheduler_id,
        'inspection_authorized', 'enforcement_action', schedule.action_id,
        schedule.policy_id, schedule.policy_version, schedule.action_id,
        p_authorization_digest, p_inspect_artifact_digest, 'accepted', server_now
    );
    RETURN 'created';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finish_lifecycle_inspection_failure_000026(
    p_schedule_id uuid,
    p_lease_token uuid,
    p_action_version integer,
    p_failure_code sentinelflow.ascii_id,
    p_failure_digest sentinelflow.sha256_digest,
    p_retry_seconds integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    schedule sentinelflow.lifecycle_inspection_schedules_000026%ROWTYPE;
    outcome text;
    expected_failure_digest sentinelflow.sha256_digest;
BEGIN
    IF p_failure_code NOT IN (
        'projection_invalid', 'contract_rejected', 'context_cancelled'
    ) OR p_retry_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid lifecycle failure';
    END IF;
    expected_failure_digest := (
        'sha256:' || encode(sha256(convert_to(
            'sentinelflow lifecycle-runtime-failure-v1' || chr(10) ||
            p_failure_code::text || chr(10), 'UTF8'
        )), 'hex')
    )::sentinelflow.sha256_digest;
    IF p_failure_digest <> expected_failure_digest THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'lifecycle failure digest mismatch';
    END IF;
    SELECT current_schedule.* INTO schedule
    FROM sentinelflow.lifecycle_inspection_schedules_000026 current_schedule
    WHERE current_schedule.schedule_id = p_schedule_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lifecycle lease is not live';
    END IF;
    IF schedule.state IN ('retry', 'dead') THEN
        IF schedule.lease_token = p_lease_token AND
           schedule.action_version = p_action_version AND
           schedule.last_error_code = p_failure_code AND
           schedule.last_error_digest = p_failure_digest THEN
            RETURN schedule.state;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505',
            MESSAGE = 'conflicting lifecycle failure replay';
    END IF;
    IF schedule.state <> 'leased' OR schedule.lease_token <> p_lease_token OR
       schedule.lease_expires_at <= server_now OR schedule.action_version <> p_action_version THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lifecycle lease is not live';
    END IF;

    outcome := CASE
        WHEN schedule.attempts >= schedule.max_attempts OR
             p_failure_code IN ('projection_invalid', 'contract_rejected')
        THEN 'dead' ELSE 'retry' END;
    UPDATE sentinelflow.lifecycle_inspection_schedules_000026 current_schedule
    SET state = outcome,
        due_at = CASE WHEN outcome = 'retry'
            THEN server_now + make_interval(secs => p_retry_seconds)
            ELSE current_schedule.due_at END,
        last_error_code = p_failure_code,
        last_error_digest = p_failure_digest,
        updated_at = server_now
    WHERE current_schedule.schedule_id = p_schedule_id;

    IF outcome = 'dead' THEN
        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            policy_id, policy_version, enforcement_action_id, primary_digest,
            secondary_digest, outcome, occurred_at
        ) VALUES (
            schedule.authorization_id, 'system', schedule.scheduler_id,
            'inspection_schedule_dead', 'enforcement_action', schedule.action_id,
            schedule.policy_id, schedule.policy_version, schedule.action_id,
            p_failure_digest, schedule.source_result_digest, 'failed', server_now
        );
    END IF;
    RETURN outcome;
END
$function$;

-- Wrap the current 000025 capability boundary. The delegated function retains
-- its lease/recovery validation; this layer adds an exact replay ledger and
-- the atomic approved -> queued lifecycle transition.
ALTER FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) RENAME TO record_execution_capability_pre_000026;

CREATE FUNCTION sentinelflow.record_execution_capability(
    p_capability_id uuid, p_job_id uuid, p_lease_token uuid,
    p_operation text, p_action_id uuid, p_policy_id uuid,
    p_policy_version integer, p_target_ipv4 sentinelflow.canonical_ipv4,
    p_artifact bytea, p_artifact_digest sentinelflow.sha256_digest,
    p_original_add_digest sentinelflow.sha256_digest,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_validation_snapshot_digest sentinelflow.sha256_digest,
    p_authorization_digest sentinelflow.sha256_digest,
    p_actor_id sentinelflow.ascii_id, p_reason_digest sentinelflow.sha256_digest,
    p_owned_schema_digest sentinelflow.sha256_digest, p_capability_jcs bytea,
    p_capability_digest sentinelflow.sha256_digest, p_capability_signature bytea,
    p_nonce_digest sentinelflow.sha256_digest, p_issued_at timestamptz,
    p_not_before timestamptz, p_expires_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    existing sentinelflow.execution_capabilities%ROWTYPE;
    application sentinelflow.lifecycle_capability_applications_000026%ROWTYPE;
    action sentinelflow.enforcement_actions%ROWTYPE;
BEGIN
    IF p_capability_digest <>
           ('sha256:' || encode(sha256(p_capability_jcs), 'hex'))::sentinelflow.sha256_digest OR
       p_artifact_digest <>
           ('sha256:' || encode(sha256(p_artifact), 'hex'))::sentinelflow.sha256_digest THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'capability digest mismatch';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'sentinelflow.lifecycle-capability:' || p_job_id::text, 0
    ));
    SELECT capability.* INTO existing
    FROM sentinelflow.execution_capabilities capability
    WHERE capability.capability_id = p_capability_id OR capability.job_id = p_job_id
    ORDER BY (capability.capability_id = p_capability_id) DESC
    LIMIT 1;
    IF FOUND THEN
        IF existing.capability_id <> p_capability_id OR existing.job_id <> p_job_id OR
           existing.operation <> p_operation OR existing.action_id <> p_action_id OR
           existing.policy_id <> p_policy_id OR existing.policy_version <> p_policy_version OR
           existing.target_ipv4 <> p_target_ipv4 OR existing.artifact <> p_artifact OR
           existing.artifact_digest <> p_artifact_digest OR
           existing.original_add_digest IS DISTINCT FROM p_original_add_digest OR
           existing.evidence_snapshot_digest <> p_evidence_snapshot_digest OR
           existing.validation_snapshot_digest <> p_validation_snapshot_digest OR
           existing.authorization_digest <> p_authorization_digest OR
           existing.actor_id <> p_actor_id OR existing.reason_digest <> p_reason_digest OR
           existing.owned_schema_digest <> p_owned_schema_digest OR
           existing.capability_jcs <> p_capability_jcs OR
           existing.capability_digest <> p_capability_digest OR
           existing.capability_signature <> p_capability_signature OR
           existing.nonce_digest <> p_nonce_digest OR existing.issued_at <> p_issued_at OR
           existing.not_before <> p_not_before OR existing.expires_at <> p_expires_at THEN
            RAISE EXCEPTION USING ERRCODE = '23505',
                MESSAGE = 'conflicting execution capability replay';
        END IF;
        SELECT applied.* INTO application
        FROM sentinelflow.lifecycle_capability_applications_000026 applied
        WHERE applied.capability_id = p_capability_id;
        IF FOUND THEN
            IF application.capability_digest <> p_capability_digest OR
               application.job_id <> p_job_id OR application.action_id <> p_action_id THEN
                RAISE EXCEPTION USING ERRCODE = '23505',
                    MESSAGE = 'conflicting capability lifecycle replay';
            END IF;
            RETURN;
        END IF;
    ELSE
        PERFORM sentinelflow.record_execution_capability_pre_000026(
            p_capability_id, p_job_id, p_lease_token, p_operation, p_action_id,
            p_policy_id, p_policy_version, p_target_ipv4, p_artifact,
            p_artifact_digest, p_original_add_digest, p_evidence_snapshot_digest,
            p_validation_snapshot_digest, p_authorization_digest, p_actor_id,
            p_reason_digest, p_owned_schema_digest, p_capability_jcs,
            p_capability_digest, p_capability_signature, p_nonce_digest,
            p_issued_at, p_not_before, p_expires_at
        );
    END IF;

    IF p_operation <> 'add' THEN
        RETURN;
    END IF;
    SELECT current_action.* INTO action
    FROM sentinelflow.enforcement_actions current_action
    WHERE current_action.action_id = p_action_id
    FOR UPDATE;
    IF action.state = 'approved' THEN
        UPDATE sentinelflow.policy_proposals policy
        SET state = 'queued', state_revision = policy.state_revision + 1,
            updated_at = server_now
        WHERE policy.policy_id = p_policy_id AND policy.version = p_policy_version
          AND policy.state = 'approved';
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'policy and action queue transition diverged';
        END IF;
        UPDATE sentinelflow.enforcement_actions current_action
        SET state = 'queued', queued_at = server_now,
            version = current_action.version + 1, updated_at = server_now
        WHERE current_action.action_id = p_action_id AND current_action.state = 'approved'
        RETURNING current_action.* INTO action;
        UPDATE sentinelflow.outbox_jobs job
        SET aggregate_version = action.version, updated_at = server_now
        WHERE job.job_id = p_job_id AND job.state = 'leased'
          AND job.lease_token = p_lease_token;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'capability lease is not live';
        END IF;
    ELSIF action.state <> 'queued' THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'add capability cannot queue current action state';
    END IF;

    INSERT INTO sentinelflow.lifecycle_capability_applications_000026 (
        capability_id, capability_digest, job_id, action_id,
        queued_action_version, applied_at
    ) VALUES (
        p_capability_id, p_capability_digest, p_job_id, p_action_id,
        action.version, server_now
    );
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        policy_id, policy_version, enforcement_action_id, primary_digest,
        secondary_digest, outcome, occurred_at
    ) VALUES (
        p_capability_id, 'dispatcher', p_actor_id, 'enforcement_queued',
        'enforcement_action', p_action_id, p_policy_id, p_policy_version,
        p_action_id, p_capability_digest, p_authorization_digest,
        'accepted', server_now
    );
END
$function$;

ALTER FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) RENAME TO record_execution_result_pre_000026;

CREATE FUNCTION sentinelflow.record_execution_result(
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
    source_schedule sentinelflow.lifecycle_inspection_schedules_000026%ROWTYPE;
    application sentinelflow.lifecycle_result_applications_000026%ROWTYPE;
    existing_result sentinelflow.execution_results%ROWTYPE;
    next_state text;
    next_applied_at timestamptz;
    next_expires_at timestamptz;
    next_finished_at timestamptz;
    schedule_id uuid;
    schedule_purpose text;
    schedule_due_at timestamptz;
    audit_action sentinelflow.ascii_id;
    audit_outcome text;
BEGIN
    SELECT applied.* INTO application
    FROM sentinelflow.lifecycle_result_applications_000026 applied
    WHERE applied.result_id = p_result_id;
    IF FOUND THEN
        SELECT result.* INTO existing_result
        FROM sentinelflow.execution_results result
        WHERE result.result_id = p_result_id;
        IF existing_result.result_id = p_result_id AND
           existing_result.capability_id = p_capability_id AND
           existing_result.capability_digest = p_capability_digest AND
           existing_result.operation = p_operation AND
           existing_result.action_id = p_action_id AND
           existing_result.artifact_digest = p_artifact_digest AND
           existing_result.target_ipv4 = p_target_ipv4 AND
           existing_result.classification = p_classification AND
           existing_result.nft_exit_class IS NOT DISTINCT FROM p_nft_exit_class AND
           existing_result.readback_state = p_readback_state AND
           existing_result.element_handle IS NOT DISTINCT FROM p_element_handle AND
           existing_result.remaining_ttl_seconds IS NOT DISTINCT FROM p_remaining_ttl_seconds AND
           existing_result.owned_schema_digest = p_owned_schema_digest AND
           existing_result.started_at = p_started_at AND
           existing_result.completed_at = p_completed_at AND
           existing_result.journal_sequence = p_journal_sequence AND
           existing_result.error_code = p_error_code AND
           existing_result.result_jcs = p_result_jcs AND
           existing_result.result_digest = p_result_digest AND
           existing_result.result_signature = p_result_signature AND
           EXISTS (
               SELECT 1 FROM sentinelflow.execution_capabilities exact_capability
               WHERE exact_capability.capability_id = p_capability_id
                 AND exact_capability.job_id = p_job_id
           ) AND application.result_digest = p_result_digest AND
           application.action_id = p_action_id AND
           application.operation = p_operation AND
           application.classification = p_classification THEN
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505',
            MESSAGE = 'conflicting result lifecycle replay';
    END IF;

    PERFORM sentinelflow.record_execution_result_pre_000026(
        p_result_id, p_job_id, p_lease_token, p_capability_id,
        p_capability_digest, p_operation, p_action_id, p_artifact_digest,
        p_target_ipv4, p_classification, p_nft_exit_class, p_readback_state,
        p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
        p_started_at, p_completed_at, p_journal_sequence, p_error_code,
        p_result_jcs, p_result_digest, p_result_signature
    );

    SELECT current_action.* INTO action
    FROM sentinelflow.enforcement_actions current_action
    WHERE current_action.action_id = p_action_id
    FOR UPDATE;
    SELECT current_policy.* INTO policy
    FROM sentinelflow.policy_proposals current_policy
    WHERE current_policy.policy_id = action.policy_id
      AND current_policy.version = action.policy_version
    FOR UPDATE;
    SELECT current_capability.* INTO capability
    FROM sentinelflow.execution_capabilities current_capability
    WHERE current_capability.capability_id = p_capability_id;
    SELECT current_operation.* INTO operation
    FROM sentinelflow.dispatch_operations current_operation
    WHERE current_operation.job_id = p_job_id;
    IF action.action_id IS NULL OR policy.policy_id IS NULL OR capability.capability_id IS NULL OR
       operation.job_id IS NULL OR action.state <> policy.state OR
       capability.job_id <> p_job_id OR capability.action_id <> p_action_id OR
       operation.action_id <> p_action_id THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'execution result lifecycle binding failed';
    END IF;

    IF p_operation = 'add' THEN
        IF action.state = 'approved' THEN
            UPDATE sentinelflow.policy_proposals current_policy
            SET state = 'queued', state_revision = current_policy.state_revision + 1,
                updated_at = server_now
            WHERE current_policy.policy_id = policy.policy_id
              AND current_policy.version = policy.version AND current_policy.state = 'approved';
            UPDATE sentinelflow.enforcement_actions current_action
            SET state = 'queued', queued_at = server_now,
                version = current_action.version + 1, updated_at = server_now
            WHERE current_action.action_id = action.action_id
            RETURNING current_action.* INTO action;
        END IF;
        IF action.state <> 'queued' THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'add result action is not queued';
        END IF;
        IF p_classification IN ('applied', 'recovered_active') THEN
            IF p_remaining_ttl_seconds IS NULL OR
               p_remaining_ttl_seconds > action.ttl_seconds THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'remaining TTL exceeds approved action TTL';
            END IF;
            IF p_classification = 'applied' THEN
                next_applied_at := p_started_at;
                next_expires_at := least(
                    p_completed_at + make_interval(secs => p_remaining_ttl_seconds),
                    p_started_at + make_interval(secs => action.ttl_seconds)
                );
            ELSE
                -- Recovery proves only that the element was active at this
                -- observation. Never invent an earlier application instant.
                next_applied_at := p_started_at;
                next_expires_at := least(
                    p_completed_at + make_interval(secs => p_remaining_ttl_seconds),
                    p_started_at + make_interval(secs => action.ttl_seconds)
                );
            END IF;
            next_state := 'active';
            next_finished_at := NULL;
            audit_action := 'enforcement_active';
            audit_outcome := 'succeeded';
        ELSIF p_classification = 'failed' THEN
            next_state := 'failed'; next_applied_at := NULL; next_expires_at := NULL;
            next_finished_at := server_now; audit_action := 'enforcement_failed';
            audit_outcome := 'failed';
        ELSIF p_classification = 'indeterminate' THEN
            next_state := 'indeterminate'; next_applied_at := NULL; next_expires_at := NULL;
            next_finished_at := NULL; audit_action := 'enforcement_indeterminate';
            audit_outcome := 'indeterminate';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid add lifecycle result';
        END IF;
    ELSIF p_operation = 'inspect' THEN
        SELECT schedule.* INTO source_schedule
        FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
        WHERE schedule.dispatch_job_id = p_job_id
        FOR UPDATE;
        IF NOT FOUND OR source_schedule.state <> 'dispatched' OR
           source_schedule.action_id <> p_action_id OR
           source_schedule.dispatch_authorization_digest <> operation.authorization_digest THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'inspection result has no exact lifecycle schedule';
        END IF;
        IF p_classification = 'inspect_active' THEN
            IF p_remaining_ttl_seconds IS NULL OR
               p_remaining_ttl_seconds > action.ttl_seconds THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid inspection TTL';
            END IF;
            IF action.state = 'indeterminate' THEN
                IF action.expected_expires_at IS NOT NULL AND
                   p_completed_at >= action.expected_expires_at THEN
                    next_state := 'failed'; next_applied_at := action.applied_at;
                    next_expires_at := action.expected_expires_at;
                    next_finished_at := server_now;
                    audit_action := 'enforcement_late_active'; audit_outcome := 'failed';
                ELSE
                    next_applied_at := coalesce(action.applied_at, p_started_at);
                    next_expires_at := least(
                        p_completed_at + make_interval(secs => p_remaining_ttl_seconds),
                        coalesce(
                            action.expected_expires_at,
                            p_started_at + make_interval(secs => action.ttl_seconds)
                        )
                    );
                    next_state := 'active'; next_finished_at := NULL;
                    audit_action := 'enforcement_recovered_active'; audit_outcome := 'succeeded';
                END IF;
            ELSIF action.state = 'active' AND p_completed_at >= action.expected_expires_at THEN
                next_state := 'failed'; next_applied_at := action.applied_at;
                next_expires_at := action.expected_expires_at; next_finished_at := server_now;
                audit_action := 'enforcement_late_active'; audit_outcome := 'failed';
            ELSIF action.state = 'active' THEN
                next_state := 'active'; next_applied_at := action.applied_at;
                next_expires_at := action.expected_expires_at; next_finished_at := NULL;
                audit_action := 'enforcement_inspected_active'; audit_outcome := 'succeeded';
            ELSE
                RAISE EXCEPTION USING ERRCODE = '55000',
                    MESSAGE = 'active inspection cannot change terminal action';
            END IF;
        ELSIF p_classification = 'inspect_absent' THEN
            IF action.state = 'indeterminate' THEN
                next_state := 'failed'; next_applied_at := NULL; next_expires_at := NULL;
                next_finished_at := server_now; audit_action := 'enforcement_absent_unresolved';
                audit_outcome := 'failed';
            ELSIF action.state = 'active' AND p_completed_at >= action.expected_expires_at THEN
                next_state := 'expired'; next_applied_at := action.applied_at;
                next_expires_at := action.expected_expires_at; next_finished_at := server_now;
                audit_action := 'enforcement_expired'; audit_outcome := 'succeeded';
            ELSIF action.state = 'active' THEN
                next_state := 'failed'; next_applied_at := action.applied_at;
                next_expires_at := action.expected_expires_at; next_finished_at := server_now;
                audit_action := 'enforcement_missing_early'; audit_outcome := 'failed';
            ELSE
                RAISE EXCEPTION USING ERRCODE = '55000',
                    MESSAGE = 'absent inspection cannot change terminal action';
            END IF;
        ELSIF p_classification IN ('inspect_mismatch', 'failed', 'indeterminate') THEN
            IF action.state NOT IN ('active', 'indeterminate') THEN
                RAISE EXCEPTION USING ERRCODE = '55000',
                    MESSAGE = 'failed inspection cannot change terminal action';
            END IF;
            next_state := 'indeterminate'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := NULL;
            audit_action := 'enforcement_inspection_indeterminate';
            audit_outcome := 'indeterminate';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid inspect lifecycle result';
        END IF;
    ELSIF p_operation = 'revoke' THEN
        IF p_classification = 'revoked' AND
           action.state IN ('active', 'indeterminate') AND
           action.expected_expires_at IS NOT NULL AND
           p_completed_at >= action.expected_expires_at THEN
            -- Native expiry won while the revoke or a concurrent inspection
            -- was in flight.  The signed absent read-back is still exact
            -- evidence, but it cannot attribute removal to the revoke.
            next_state := 'expired'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := server_now;
            audit_action := 'enforcement_revoke_after_expiry'; audit_outcome := 'succeeded';
        ELSIF p_classification = 'revoked' AND
              action.state IN ('active', 'indeterminate') THEN
            -- An inspection may have moved active -> indeterminate after the
            -- executor deleted the element.  Persist the exact signed result
            -- and resolve that uncertainty without inventing new timing.
            next_state := 'revoked'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := server_now;
            audit_action := 'enforcement_revoked'; audit_outcome := 'succeeded';
        ELSIF p_classification = 'revoked' AND action.state = 'expired' THEN
            -- Native expiry won the race. Preserve the terminal expiry and
            -- record the exact revoke result without resurrecting state.
            next_state := 'expired'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := action.finished_at;
            audit_action := 'enforcement_revoke_after_expiry'; audit_outcome := 'succeeded';
        ELSIF p_classification = 'failed' AND
              action.state IN ('active', 'indeterminate') THEN
            next_state := 'failed'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := server_now;
            audit_action := 'enforcement_revoke_failed'; audit_outcome := 'failed';
        ELSIF p_classification = 'indeterminate' AND
              action.state IN ('active', 'indeterminate') THEN
            next_state := 'indeterminate'; next_applied_at := action.applied_at;
            next_expires_at := action.expected_expires_at; next_finished_at := NULL;
            audit_action := 'enforcement_revoke_indeterminate'; audit_outcome := 'indeterminate';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'revoke result cannot change current action';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid lifecycle operation';
    END IF;

    IF next_state <> action.state THEN
        UPDATE sentinelflow.policy_proposals current_policy
        SET state = next_state, state_revision = current_policy.state_revision + 1,
            updated_at = server_now
        WHERE current_policy.policy_id = policy.policy_id
          AND current_policy.version = policy.version AND current_policy.state = action.state;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'policy lifecycle transition failed';
        END IF;
        UPDATE sentinelflow.enforcement_actions current_action
        SET state = next_state, applied_at = next_applied_at,
            expected_expires_at = next_expires_at, finished_at = next_finished_at,
            version = current_action.version + 1, updated_at = server_now
        WHERE current_action.action_id = action.action_id AND current_action.state = action.state
        RETURNING current_action.* INTO action;
    END IF;
    UPDATE sentinelflow.outbox_jobs job
    SET aggregate_version = action.version, updated_at = server_now
    WHERE job.job_id = p_job_id AND job.state = 'leased'
      AND job.lease_token = p_lease_token;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'result lease is not live';
    END IF;

    IF p_operation = 'inspect' THEN
        UPDATE sentinelflow.lifecycle_inspection_schedules_000026 current_schedule
        SET state = CASE WHEN audit_action = 'enforcement_late_active' THEN 'dead' ELSE 'completed' END,
            last_error_code = CASE WHEN audit_action = 'enforcement_late_active'
                THEN 'late_active' ELSE NULL END,
            last_error_digest = CASE WHEN audit_action = 'enforcement_late_active'
                THEN p_result_digest ELSE NULL END,
            updated_at = server_now
        WHERE current_schedule.schedule_id = source_schedule.schedule_id;
    END IF;

    IF next_state IN ('active', 'indeterminate') AND
       NOT (p_operation = 'revoke') AND audit_action <> 'enforcement_late_active' THEN
        schedule_id := p_result_id;
        IF next_state = 'active' THEN
            schedule_due_at := least(action.expected_expires_at, p_completed_at + interval '30 seconds');
            schedule_purpose := CASE WHEN schedule_due_at = action.expected_expires_at
                THEN 'expiry_confirmation' ELSE 'reconciliation' END;
        ELSE
            schedule_due_at := p_completed_at + interval '1 second';
            schedule_purpose := 'reconciliation';
        END IF;
        INSERT INTO sentinelflow.lifecycle_inspection_schedules_000026 (
            schedule_id, authorization_id, dispatch_job_id, source_result_id,
            source_result_digest, action_id, action_version, policy_id,
            policy_version, target_ipv4, original_add_digest,
            original_authorization_digest, evidence_snapshot_digest,
            validation_snapshot_id, validation_snapshot_digest,
            owned_schema_digest, purpose, due_at, state, created_at, updated_at
        ) VALUES (
            schedule_id, gen_random_uuid(), gen_random_uuid(), p_result_id,
            p_result_digest, action.action_id, action.version, action.policy_id,
            action.policy_version, action.target_ipv4, action.canonical_artifact_digest,
            CASE WHEN p_operation = 'inspect'
                THEN source_schedule.original_authorization_digest
                ELSE operation.authorization_digest END,
            action.evidence_snapshot_digest,
            action.validation_snapshot_id, operation.validation_snapshot_digest,
            p_owned_schema_digest, schedule_purpose, schedule_due_at, 'pending',
            server_now, server_now
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

REVOKE ALL ON TABLE
    sentinelflow.lifecycle_inspection_schedules_000026,
    sentinelflow.lifecycle_inspection_artifacts_000026,
    sentinelflow.lifecycle_capability_applications_000026,
    sentinelflow.lifecycle_result_applications_000026
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
     sentinelflow_dispatcher, sentinelflow_lifecycle, sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.lifecycle_inspect_jcs_000026(
    uuid, sentinelflow.canonical_ipv4, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.lifecycle_schedule_idempotency_000026(uuid)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.lifecycle_inspection_authorization_jcs_000026(
    uuid, sentinelflow.sha256_digest, uuid, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, uuid, integer,
    text, timestamptz, sentinelflow.ascii_id, sentinelflow.canonical_ipv4,
    timestamptz, sentinelflow.sha256_digest
) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.enforce_action_transition_000026() FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.claim_lifecycle_inspection_schedule_000026(
    sentinelflow.ascii_id, sentinelflow.ascii_id, integer
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.commit_lifecycle_inspection_000026(
    uuid, uuid, integer, sentinelflow.ascii_id, uuid, bytea,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.finish_lifecycle_inspection_failure_000026(
    uuid, uuid, integer, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, integer
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_dispatcher, sentinelflow_retention;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_capability_pre_000026(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_lifecycle, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result_pre_000026(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_lifecycle, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_lifecycle;
REVOKE ALL ON FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
       sentinelflow_retention, sentinelflow_lifecycle;

GRANT USAGE ON SCHEMA sentinelflow TO sentinelflow_lifecycle;
GRANT EXECUTE ON FUNCTION sentinelflow.claim_lifecycle_inspection_schedule_000026(
    sentinelflow.ascii_id, sentinelflow.ascii_id, integer
) TO sentinelflow_lifecycle;
GRANT EXECUTE ON FUNCTION sentinelflow.commit_lifecycle_inspection_000026(
    uuid, uuid, integer, sentinelflow.ascii_id, uuid, bytea,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest
) TO sentinelflow_lifecycle;
GRANT EXECUTE ON FUNCTION sentinelflow.finish_lifecycle_inspection_failure_000026(
    uuid, uuid, integer, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, integer
) TO sentinelflow_lifecycle;
GRANT EXECUTE ON FUNCTION sentinelflow.record_execution_capability(
    uuid, uuid, uuid, text, uuid, uuid, integer,
    sentinelflow.canonical_ipv4, bytea, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest,
    sentinelflow.ascii_id, sentinelflow.sha256_digest,
    sentinelflow.sha256_digest, bytea, sentinelflow.sha256_digest,
    bytea, sentinelflow.sha256_digest, timestamptz, timestamptz, timestamptz
) TO sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.record_execution_result(
    uuid, uuid, uuid, uuid, sentinelflow.sha256_digest, text, uuid,
    sentinelflow.sha256_digest, sentinelflow.canonical_ipv4, text, text,
    text, bigint, integer, sentinelflow.sha256_digest, timestamptz,
    timestamptz, bigint, text, bytea, sentinelflow.sha256_digest, bytea
) TO sentinelflow_dispatcher;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (26, 'enforcement_lifecycle')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
