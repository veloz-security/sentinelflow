BEGIN;

DO $retention_role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinelflow_retention') THEN
        CREATE ROLE sentinelflow_retention
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_roles role
        WHERE role.rolname = 'sentinelflow_retention'
          AND (role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR
               role.rolreplication OR role.rolbypassrls)
    ) OR EXISTS (
        SELECT 1
        FROM pg_auth_members membership
        JOIN pg_roles retention_role
          ON retention_role.oid IN (membership.member, membership.roleid)
        WHERE retention_role.rolname = 'sentinelflow_retention'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'retention role has inherited or elevated authority';
    END IF;
    ALTER ROLE sentinelflow_retention NOINHERIT;
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO sentinelflow_retention',
        current_database()
    );
    EXECUTE format(
        'ALTER ROLE sentinelflow_retention IN DATABASE %I '
        'SET search_path = sentinelflow, pg_catalog',
        current_database()
    );
END
$retention_role$;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- The retained HIL row already owns an immutable byte-for-byte copy of the
-- exact evidence and its digest.  Runtime inserts must still prove that copy
-- against the normalized source rows, but the source artifact itself expires
-- after seven days while the HIL projection remains for thirty days.
ALTER TABLE hil_exact_artifacts
    DROP CONSTRAINT IF EXISTS hil_exact_artifacts_evidence_snapshot_id_fkey;

CREATE OR REPLACE FUNCTION sentinelflow.require_hil_source_evidence_000023()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM 1
    FROM sentinelflow.evidence_snapshot_artifacts artifact
    JOIN sentinelflow.evidence_snapshots snapshot
      ON snapshot.evidence_snapshot_id = artifact.evidence_snapshot_id
    WHERE artifact.evidence_snapshot_id = NEW.evidence_snapshot_id
      AND artifact.canonical_bytes = NEW.evidence_bytes
      AND artifact.canonical_digest = NEW.evidence_digest
      AND snapshot.snapshot_digest = NEW.evidence_digest
    FOR KEY SHARE OF artifact, snapshot;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'retained HIL evidence does not match normalized source';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS hil_exact_artifacts_require_source_000023
    ON hil_exact_artifacts;
CREATE TRIGGER hil_exact_artifacts_require_source_000023
BEFORE INSERT ON hil_exact_artifacts
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_hil_source_evidence_000023();

-- A decision challenge retains the opaque session digest and exact issued
-- authentication time.  Its source session can therefore expire promptly,
-- provided every new challenge is transactionally bound to a live session.
ALTER TABLE decision_challenges
    DROP CONSTRAINT IF EXISTS decision_challenges_session_id_fkey;

CREATE OR REPLACE FUNCTION sentinelflow.require_challenge_session_source_000023()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM 1
    FROM sentinelflow.admin_sessions session
    WHERE session.session_id = NEW.session_id
      AND session.token_digest = NEW.session_digest
      AND session.actor_id = NEW.actor_id
      AND session.authenticated_at = NEW.authenticated_at
      AND session.created_at <= NEW.issued_at
      AND session.expires_at > NEW.issued_at
      AND session.last_seen_at + interval '30 minutes' > NEW.issued_at
      AND (session.revoked_at IS NULL OR session.revoked_at > NEW.issued_at)
    FOR KEY SHARE OF session;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'decision challenge does not match a live source session';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS decision_challenges_require_session_source_000023
    ON decision_challenges;
CREATE TRIGGER decision_challenges_require_session_source_000023
BEFORE INSERT ON decision_challenges
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_challenge_session_source_000023();

ALTER TABLE admin_sessions
    DROP CONSTRAINT IF EXISTS admin_sessions_rotation_parent_id_fkey;
ALTER TABLE admin_sessions
    ADD CONSTRAINT admin_sessions_rotation_parent_id_fkey
    FOREIGN KEY (rotation_parent_id) REFERENCES admin_sessions (session_id)
    ON DELETE SET NULL;

-- A terminal analysis attempt keeps the digest after its normalized snapshot
-- expires.  Both NULL remains the no-call shape; NULL ID plus non-NULL digest
-- is the retention tombstone created only by the FK action.
ALTER TABLE analysis_attempt_claims
    DROP CONSTRAINT IF EXISTS analysis_attempt_claim_snapshot;
ALTER TABLE analysis_attempt_claims
    ADD CONSTRAINT analysis_attempt_claim_snapshot CHECK (
        evidence_snapshot_id IS NULL OR evidence_snapshot_digest IS NOT NULL
    );

-- Preserve the one-time provider seal while allowing exactly the FK-driven
-- non-NULL -> NULL snapshot reference transition.  Every other field,
-- including provider provenance, remains byte-equivalent.
CREATE OR REPLACE FUNCTION sentinelflow.guard_analysis_provenance_update_000021()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF OLD.evidence_snapshot_id IS NOT NULL AND
       NEW.evidence_snapshot_id IS NULL AND
       to_jsonb(NEW) - 'evidence_snapshot_id' IS NOT DISTINCT FROM
           to_jsonb(OLD) - 'evidence_snapshot_id' AND
       NOT EXISTS (
           SELECT 1
           FROM sentinelflow.evidence_snapshots snapshot
           WHERE snapshot.evidence_snapshot_id = OLD.evidence_snapshot_id
       ) THEN
        RETURN NEW;
    END IF;

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

-- Existing append-only/immutable projections may be deleted only while the
-- owner-only retention coordinator sets its transaction-local marker.  No
-- runtime role receives direct table DELETE privilege.
CREATE OR REPLACE FUNCTION sentinelflow.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'DELETE' AND
       current_setting('sentinelflow.retention_delete', true) =
           '000023-retention-v1' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'audit events are append-only';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.reject_exact_artifact_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'DELETE' AND
       current_setting('sentinelflow.retention_delete', true) =
           '000023-retention-v1' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'canonical artifact rows are immutable';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.reject_detection_history_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'DELETE' AND
       current_setting('sentinelflow.retention_delete', true) =
           '000023-retention-v1' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'detector evidence and incident version history are immutable';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.reject_source_coverage_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'DELETE' AND
       current_setting('sentinelflow.retention_delete', true) =
           '000023-retention-v1' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'source coverage evidence is append-only';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.guard_demo_history_import_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'DELETE' AND
       current_setting('sentinelflow.retention_delete', true) =
           '000023-retention-v1' THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'demo history import ledger is append-only';
    END IF;
    IF ROW(
        NEW.import_id, NEW.schema_version, NEW.manifest_id, NEW.profile,
        NEW.dataset_id, NEW.dataset_schema_version, NEW.dataset_locator,
        NEW.raw_file_byte_sha256,
        NEW.manifest_dataset_jcs_digest, NEW.imported_rows_jcs_digest,
        NEW.imported_record_count, NEW.source_health_jcs_digest,
        NEW.manifest_digest, NEW.run_scope_digest, NEW.public_key_digest,
        NEW.signature_verification_digest, NEW.path_catalog_version,
        NEW.clock_at, NEW.issued_at, NEW.coverage_start, NEW.coverage_end
    ) IS DISTINCT FROM ROW(
        OLD.import_id, OLD.schema_version, OLD.manifest_id, OLD.profile,
        OLD.dataset_id, OLD.dataset_schema_version, OLD.dataset_locator,
        OLD.raw_file_byte_sha256,
        OLD.manifest_dataset_jcs_digest, OLD.imported_rows_jcs_digest,
        OLD.imported_record_count, OLD.source_health_jcs_digest,
        OLD.manifest_digest, OLD.run_scope_digest, OLD.public_key_digest,
        OLD.signature_verification_digest, OLD.path_catalog_version,
        OLD.clock_at, OLD.issued_at, OLD.coverage_start, OLD.coverage_end
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'demo history import identity is immutable';
    END IF;
    IF OLD.status = 'completed' OR
       (OLD.status = 'importing' AND NEW.status NOT IN ('completed', 'failed')) OR
       (OLD.status = 'failed' AND NEW.status NOT IN ('failed', 'importing')) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'invalid demo history import state transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.reject_demo_history_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'DELETE' AND
       current_setting('sentinelflow.retention_delete', true) =
           '000023-retention-v1' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'demo history import evidence is append-only';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.protect_valid_validation_gates()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    snapshot_id uuid;
BEGIN
    IF TG_OP = 'DELETE' AND
       current_setting('sentinelflow.retention_delete', true) =
           '000023-retention-v1' THEN
        RETURN OLD;
    END IF;
    snapshot_id := CASE WHEN TG_OP = 'DELETE'
        THEN OLD.validation_snapshot_id
        ELSE NEW.validation_snapshot_id
    END;
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.validation_snapshots snapshot
        WHERE snapshot.validation_snapshot_id = snapshot_id
          AND snapshot.state = 'valid'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'gates of a valid validation snapshot are immutable';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$function$;

CREATE TABLE IF NOT EXISTS retention_runs (
    run_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'retention-run-v1'),
    as_of timestamptz NOT NULL,
    event_evidence_cutoff timestamptz NOT NULL,
    control_plane_cutoff timestamptz NOT NULL,
    audit_cutoff timestamptz NOT NULL,
    max_rows integer NOT NULL CHECK (max_rows BETWEEN 1 AND 10000),
    event_evidence_deleted bigint NOT NULL CHECK (event_evidence_deleted >= 0),
    control_plane_deleted bigint NOT NULL CHECK (control_plane_deleted >= 0),
    transient_deleted bigint NOT NULL CHECK (transient_deleted >= 0),
    audit_deleted bigint NOT NULL CHECK (audit_deleted >= 0),
    outcome text NOT NULL DEFAULT 'succeeded'
        CHECK (outcome IN ('succeeded', 'failed')),
    failure_code ascii_id NULL,
    anomaly_count bigint NOT NULL DEFAULT 0 CHECK (anomaly_count >= 0),
    run_digest sha256_digest NOT NULL UNIQUE,
    completed_at timestamptz NOT NULL,
    CONSTRAINT retention_run_fixed_windows CHECK (
        event_evidence_cutoff = as_of - interval '7 days' AND
        control_plane_cutoff = as_of - interval '30 days' AND
        audit_cutoff = as_of - interval '90 days'
    ),
    CONSTRAINT retention_run_global_limit CHECK (
        event_evidence_deleted + control_plane_deleted +
        transient_deleted + audit_deleted <= max_rows
    ),
    CONSTRAINT retention_run_outcome_shape CHECK (
        (outcome = 'succeeded' AND failure_code IS NULL AND anomaly_count = 0) OR
        (outcome = 'failed' AND failure_code IS NOT NULL AND anomaly_count >= 1 AND
         event_evidence_deleted = 0 AND control_plane_deleted = 0 AND
         transient_deleted = 0 AND audit_deleted = 0)
    )
);

-- Keep direct migration reapplication safe even if an earlier development
-- build created retention_runs before audited anomaly outcomes were added.
ALTER TABLE retention_runs
    ADD COLUMN IF NOT EXISTS outcome text NOT NULL DEFAULT 'succeeded',
    ADD COLUMN IF NOT EXISTS failure_code ascii_id NULL,
    ADD COLUMN IF NOT EXISTS anomaly_count bigint NOT NULL DEFAULT 0;
ALTER TABLE retention_runs
    DROP CONSTRAINT IF EXISTS retention_run_global_limit,
    DROP CONSTRAINT IF EXISTS retention_run_outcome_shape;
ALTER TABLE retention_runs
    ADD CONSTRAINT retention_run_global_limit CHECK (
        event_evidence_deleted + control_plane_deleted +
        transient_deleted + audit_deleted <= max_rows
    ),
    ADD CONSTRAINT retention_run_outcome_shape CHECK (
        (outcome = 'succeeded' AND failure_code IS NULL AND anomaly_count = 0) OR
        (outcome = 'failed' AND failure_code IS NOT NULL AND anomaly_count >= 1 AND
         event_evidence_deleted = 0 AND control_plane_deleted = 0 AND
         transient_deleted = 0 AND audit_deleted = 0)
    );

CREATE INDEX IF NOT EXISTS retention_runs_completed_at_idx
    ON retention_runs (completed_at, run_id);

-- A transaction-local trigger budget is the final backstop for every direct
-- and cascaded retention delete. Once the global cap is consumed, later row
-- deletes are suppressed; parent rows therefore remain until their children
-- have been removed by a later bounded run.
CREATE OR REPLACE FUNCTION sentinelflow.enforce_retention_delete_budget_000023()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    maximum integer;
    used integer;
    bucket text;
    bucket_used integer;
BEGIN
    IF current_setting('sentinelflow.retention_delete', true) IS DISTINCT FROM
       '000023-retention-v1' THEN
        RETURN OLD;
    END IF;
    BEGIN
        maximum := current_setting('sentinelflow.retention_max_rows', true)::integer;
        used := current_setting('sentinelflow.retention_deleted_rows', true)::integer;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'retention delete budget is unavailable';
    END;
    IF maximum NOT BETWEEN 1 AND 10000 OR used < 0 OR used > maximum THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'retention delete budget is invalid';
    END IF;
    IF used = maximum THEN
        RETURN NULL;
    END IF;

    bucket := CASE
        WHEN TG_TABLE_NAME = ANY (ARRAY[
            'analysis_evidence', 'auth_events', 'demo_history_import_batches',
            'demo_history_imports', 'demo_history_source_coverage',
            'evidence_snapshot_artifacts', 'evidence_snapshot_events',
            'evidence_snapshot_signals', 'evidence_snapshots', 'gateway_events',
            'incident_events', 'incident_signals', 'incident_version_signals',
            'ingest_batches', 'ingest_gap_lifecycle',
            'ingest_sequence_gap_resolutions', 'signal_evidence', 'signals',
            'source_coverage_attestations', 'source_health_intervals'
        ]) THEN 'event'
        WHEN TG_TABLE_NAME = ANY (ARRAY[
            'admin_sessions', 'analysis_attempt_claims',
            'analysis_attempt_results', 'analysis_output_staging',
            'dead_letter_jobs', 'detector_run_signals', 'detector_runs',
            'ingest_replay_nonces', 'outbox_jobs', 'sse_notification_ledger',
            'validation_attempt_claims', 'validation_attempt_gates',
            'validation_attempt_results'
        ]) THEN 'transient'
        WHEN TG_TABLE_NAME = ANY (ARRAY[
            'ai_analyses', 'ai_budget_ledger', 'ai_budget_reservations',
            'approval_decisions', 'command_candidates', 'decision_challenges',
            'dispatch_operations', 'enforcement_actions',
            'enforcement_authorizations', 'execution_capabilities',
            'execution_results', 'hil_exact_artifacts', 'hil_reasons',
            'incidents', 'incident_version_history',
            'inspection_authorizations', 'policy_proposals',
            'revocation_operations', 'validation_gates', 'validation_snapshots'
        ]) THEN 'control'
        WHEN TG_TABLE_NAME = ANY (ARRAY['audit_events', 'retention_runs'])
            THEN 'audit'
        ELSE NULL
    END;
    IF bucket IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'retention delete relation is unclassified';
    END IF;

    bucket_used := current_setting(
        'sentinelflow.retention_deleted_' || bucket, true
    )::integer;
    PERFORM set_config(
        'sentinelflow.retention_deleted_rows', (used + 1)::text, true
    );
    PERFORM set_config(
        'sentinelflow.retention_deleted_' || bucket,
        (bucket_used + 1)::text,
        true
    );
    RETURN OLD;
END
$function$;

DO $retention_delete_budget_triggers$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'admin_sessions', 'ai_analyses', 'ai_budget_ledger',
        'ai_budget_reservations', 'analysis_attempt_claims',
        'analysis_attempt_results', 'analysis_evidence',
        'analysis_output_staging', 'approval_decisions', 'audit_events',
        'auth_events', 'command_candidates', 'dead_letter_jobs',
        'decision_challenges', 'demo_history_import_batches',
        'demo_history_imports', 'demo_history_source_coverage',
        'detector_run_signals', 'detector_runs', 'dispatch_operations',
        'enforcement_actions', 'enforcement_authorizations',
        'evidence_snapshot_artifacts', 'evidence_snapshot_events',
        'evidence_snapshot_signals', 'evidence_snapshots',
        'execution_capabilities', 'execution_results', 'gateway_events',
        'hil_exact_artifacts', 'hil_reasons', 'incident_events',
        'incident_signals', 'incident_version_history',
        'incident_version_signals', 'incidents', 'ingest_batches',
        'ingest_gap_lifecycle', 'ingest_replay_nonces',
        'ingest_sequence_gap_resolutions', 'inspection_authorizations',
        'outbox_jobs', 'policy_proposals', 'retention_runs',
        'revocation_operations', 'signal_evidence', 'signals',
        'source_coverage_attestations', 'source_health_intervals',
        'sse_notification_ledger', 'validation_attempt_claims',
        'validation_attempt_gates', 'validation_attempt_results',
        'validation_gates', 'validation_snapshots'
    ]
    LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS aaa_retention_delete_budget_000023 '
            'ON sentinelflow.%I', table_name
        );
        EXECUTE format(
            'CREATE TRIGGER aaa_retention_delete_budget_000023 '
            'BEFORE DELETE ON sentinelflow.%I FOR EACH ROW '
            'EXECUTE FUNCTION sentinelflow.enforce_retention_delete_budget_000023()',
            table_name
        );
    END LOOP;
END
$retention_delete_budget_triggers$;

CREATE OR REPLACE FUNCTION sentinelflow.retention_runs_append_only_000023()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'DELETE' AND
       current_setting('sentinelflow.retention_delete', true) =
           '000023-retention-v1' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'retention run summaries are append-only';
END
$function$;

DROP TRIGGER IF EXISTS retention_runs_append_only_000023 ON retention_runs;
CREATE TRIGGER retention_runs_append_only_000023
BEFORE UPDATE OR DELETE ON retention_runs
FOR EACH ROW EXECUTE FUNCTION sentinelflow.retention_runs_append_only_000023();

DROP FUNCTION IF EXISTS sentinelflow.run_retention_000023(
    uuid, timestamptz, integer
);
CREATE FUNCTION sentinelflow.run_retention_000023(
    p_run_id uuid,
    p_as_of timestamptz,
    p_max_rows integer
)
RETURNS TABLE (
    run_id uuid,
    replayed boolean,
    outcome text,
    failure_code text,
    anomaly_count bigint,
    event_evidence_deleted bigint,
    control_plane_deleted bigint,
    transient_deleted bigint,
    audit_deleted bigint,
    run_digest sentinelflow.sha256_digest,
    completed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    event_cutoff timestamptz;
    control_cutoff timestamptz;
    audit_cutoff_value timestamptz;
    existing sentinelflow.retention_runs%ROWTYPE;
    target_snapshots uuid[] := ARRAY[]::uuid[];
    target_signals uuid[] := ARRAY[]::uuid[];
    target_gateway_events uuid[] := ARRAY[]::uuid[];
    target_auth_events uuid[] := ARRAY[]::uuid[];
    target_health_events uuid[] := ARRAY[]::uuid[];
    target_imports uuid[] := ARRAY[]::uuid[];
    target_incidents uuid[] := ARRAY[]::uuid[];
    affected bigint := 0;
    event_count bigint := 0;
    control_count bigint := 0;
    transient_count bigint := 0;
    audit_count bigint := 0;
    used_count bigint := 0;
    anomaly_count_value bigint := 0;
    digest_value sentinelflow.sha256_digest;
    completed_value timestamptz;
BEGIN
    IF session_user <> 'sentinelflow_retention' OR EXISTS (
        SELECT 1
        FROM pg_roles role
        WHERE role.rolname = 'sentinelflow_retention'
          AND (role.rolinherit OR role.rolsuper OR role.rolcreatedb OR
               role.rolcreaterole OR role.rolreplication OR role.rolbypassrls)
    ) OR EXISTS (
        SELECT 1
        FROM pg_auth_members membership
        JOIN pg_roles retention_role
          ON retention_role.oid IN (membership.member, membership.roleid)
        WHERE retention_role.rolname = 'sentinelflow_retention'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'retention caller authority rejected';
    END IF;
    IF p_run_id IS NULL OR p_as_of IS NULL OR NOT isfinite(p_as_of) OR
       p_as_of > server_now OR p_max_rows IS NULL OR
       p_max_rows NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid retention request';
    END IF;

    event_cutoff := p_as_of - interval '7 days';
    control_cutoff := p_as_of - interval '30 days';
    audit_cutoff_value := p_as_of - interval '90 days';

    IF NOT pg_try_advisory_xact_lock(1735289911, 23) THEN
        RAISE EXCEPTION USING ERRCODE = '55P03',
            MESSAGE = 'another retention transaction is active';
    END IF;
    SELECT * INTO existing
    FROM sentinelflow.retention_runs prior
    WHERE prior.run_id = p_run_id;
    IF FOUND THEN
        IF existing.as_of <> p_as_of OR existing.max_rows <> p_max_rows THEN
            RAISE EXCEPTION USING ERRCODE = '23505',
                MESSAGE = 'retention run replay conflict';
        END IF;
        RETURN QUERY SELECT existing.run_id, true, existing.outcome,
            COALESCE(existing.failure_code::text, ''), existing.anomaly_count,
            existing.event_evidence_deleted,
            existing.control_plane_deleted,
            existing.transient_deleted,
            existing.audit_deleted,
            existing.run_digest,
            existing.completed_at;
        RETURN;
    END IF;
    IF p_as_of < server_now - interval '1 minute' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'retention as-of is stale';
    END IF;

    -- A fixed retention window must not silently turn an abandoned live state
    -- into indefinite storage.  Count only a bounded, identifier-free summary,
    -- persist a digest-bound failed run and audit event, and leave every live
    -- authority and all otherwise eligible data untouched for operator repair.
    SELECT count(*)::bigint INTO anomaly_count_value
    FROM (
        SELECT 1 AS anomaly
        FROM sentinelflow.incidents incident
        WHERE incident.state <> 'closed'
          AND incident.updated_at < control_cutoff
        UNION ALL
        SELECT 1 FROM sentinelflow.analysis_attempt_claims claim
        WHERE claim.state = 'started' AND claim.generated_at < control_cutoff
        UNION ALL
        SELECT 1 FROM sentinelflow.validation_attempt_claims claim
        WHERE claim.state = 'started' AND claim.generated_at < control_cutoff
        UNION ALL
        SELECT 1 FROM sentinelflow.outbox_jobs job
        WHERE job.state IN ('pending', 'leased', 'retry')
          AND job.updated_at < control_cutoff
        UNION ALL
        SELECT 1 FROM sentinelflow.enforcement_actions action
        WHERE action.state IN ('approved', 'queued', 'active', 'indeterminate')
          AND action.updated_at < control_cutoff
        UNION ALL
        SELECT 1 FROM sentinelflow.revocation_operations operation
        WHERE operation.state IN ('authorized', 'queued', 'indeterminate')
          AND operation.created_at < control_cutoff
        UNION ALL
        SELECT 1 FROM sentinelflow.ai_budget_reservations reservation
        WHERE reservation.state = 'active' AND reservation.expires_at < p_as_of
        UNION ALL
        SELECT 1 FROM sentinelflow.demo_history_imports import
        WHERE import.status = 'importing' AND import.started_at < control_cutoff
        LIMIT p_max_rows
    ) stale_live;
    IF anomaly_count_value > 0 THEN
        completed_value := clock_timestamp();
        digest_value := (
            'sha256:' || encode(sha256(convert_to(
                'retention-run-v1' || chr(10) || p_run_id::text || chr(10) ||
                to_char(p_as_of AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || chr(10) ||
                p_max_rows::text || chr(10) || 'failed' || chr(10) ||
                'stale_live_state' || chr(10) || anomaly_count_value::text ||
                chr(10),
                'UTF8'
            )), 'hex')
        )::sentinelflow.sha256_digest;
        INSERT INTO sentinelflow.retention_runs (
            run_id, schema_version, as_of, event_evidence_cutoff,
            control_plane_cutoff, audit_cutoff, max_rows,
            event_evidence_deleted, control_plane_deleted,
            transient_deleted, audit_deleted, outcome, failure_code,
            anomaly_count, run_digest, completed_at
        ) VALUES (
            p_run_id, 'retention-run-v1', p_as_of, event_cutoff,
            control_cutoff, audit_cutoff_value, p_max_rows,
            0, 0, 0, 0, 'failed', 'stale_live_state',
            anomaly_count_value, digest_value, completed_value
        );
        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            primary_digest, outcome, occurred_at
        ) VALUES (
            gen_random_uuid(), 'system', 'retention-worker',
            'retention_run_failed', 'retention_run', p_run_id,
            digest_value, 'failed', completed_value
        );
        RETURN QUERY SELECT p_run_id, false, 'failed'::text,
            'stale_live_state'::text, anomaly_count_value,
            0::bigint, 0::bigint, 0::bigint, 0::bigint,
            digest_value, completed_value;
        RETURN;
    END IF;

    -- Recovery-ambiguous work is never erased.  These checks happen before
    -- the first mutation, so any ambiguity rolls the complete run back.
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.validation_attempt_claims claim
        JOIN sentinelflow.evidence_snapshots snapshot
          ON snapshot.evidence_snapshot_id = claim.evidence_snapshot_id
        WHERE snapshot.created_at < event_cutoff AND claim.state = 'started'
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.analysis_attempt_claims claim
        JOIN sentinelflow.evidence_snapshots snapshot
          ON snapshot.evidence_snapshot_id = claim.evidence_snapshot_id
        WHERE snapshot.created_at < event_cutoff AND claim.state = 'started'
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.validation_snapshots validation
        JOIN sentinelflow.evidence_snapshots snapshot
          ON snapshot.evidence_snapshot_id = validation.evidence_snapshot_id
        WHERE snapshot.created_at < event_cutoff
          AND validation.state = 'valid'
          AND validation.valid_until >= p_as_of
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF301',
            MESSAGE = 'retention blocked by live evidence authority';
    END IF;
    IF EXISTS (
        SELECT 1 FROM sentinelflow.ingest_sequence_gaps gap
        WHERE gap.detected_at < event_cutoff
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.demo_history_imports import
        WHERE import.started_at < event_cutoff AND import.status = 'importing'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF302',
            MESSAGE = 'retention blocked by incomplete source history';
    END IF;
    PERFORM set_config(
        'sentinelflow.retention_delete', '000023-retention-v1', true
    );
    PERFORM set_config('sentinelflow.retention_max_rows', p_max_rows::text, true);
    PERFORM set_config('sentinelflow.retention_deleted_rows', '0', true);
    PERFORM set_config('sentinelflow.retention_deleted_event', '0', true);
    PERFORM set_config('sentinelflow.retention_deleted_control', '0', true);
    PERFORM set_config('sentinelflow.retention_deleted_transient', '0', true);
    PERFORM set_config('sentinelflow.retention_deleted_audit', '0', true);
    SET CONSTRAINTS ALL DEFERRED;

    -- Security-window and bounded replay state.
    DELETE FROM sentinelflow.ingest_replay_nonces nonce
    WHERE (nonce.sender_id, nonce.endpoint_kind, nonce.nonce_digest) IN (
        SELECT candidate.sender_id, candidate.endpoint_kind, candidate.nonce_digest
        FROM sentinelflow.ingest_replay_nonces candidate
        WHERE candidate.expires_at < p_as_of
        ORDER BY candidate.expires_at, candidate.sender_id,
                 candidate.endpoint_kind, candidate.nonce_digest
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;

    DELETE FROM sentinelflow.admin_sessions session
    WHERE session.session_id IN (
        SELECT candidate.session_id
        FROM sentinelflow.admin_sessions candidate
        WHERE candidate.expires_at <= p_as_of OR
              candidate.last_seen_at + interval '30 minutes' <= p_as_of OR
              (candidate.revoked_at IS NOT NULL AND candidate.revoked_at <= p_as_of)
        ORDER BY LEAST(
                     candidate.expires_at,
                     candidate.last_seen_at + interval '30 minutes',
                     COALESCE(candidate.revoked_at, 'infinity'::timestamptz)
                 ),
                 candidate.session_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;

    SELECT pruned.pruned_count::bigint INTO affected
    FROM sentinelflow.prune_sse_notification_ledger(
        event_cutoff, p_max_rows
    ) pruned;
    transient_count := transient_count + COALESCE(affected, 0);

    -- Select bounded expired source snapshots.  Terminal validation claims are
    -- transient recovery material and must disappear before the source row.
    SELECT COALESCE(array_agg(candidate.evidence_snapshot_id), ARRAY[]::uuid[])
    INTO target_snapshots
    FROM (
        SELECT snapshot.evidence_snapshot_id
        FROM sentinelflow.evidence_snapshots snapshot
        WHERE snapshot.created_at < event_cutoff
          AND snapshot.expires_at < p_as_of
        ORDER BY snapshot.created_at, snapshot.evidence_snapshot_id
        LIMIT p_max_rows
    ) candidate;

    DELETE FROM sentinelflow.validation_attempt_gates gate
    WHERE gate.validation_attempt_id IN (
        SELECT claim.validation_attempt_id
        FROM sentinelflow.validation_attempt_claims claim
        WHERE claim.evidence_snapshot_id = ANY(target_snapshots)
          AND claim.state <> 'started'
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;
    DELETE FROM sentinelflow.validation_attempt_results result
    WHERE result.validation_attempt_id IN (
        SELECT claim.validation_attempt_id
        FROM sentinelflow.validation_attempt_claims claim
        WHERE claim.evidence_snapshot_id = ANY(target_snapshots)
          AND claim.state <> 'started'
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;
    DELETE FROM sentinelflow.validation_attempt_claims claim
    WHERE claim.evidence_snapshot_id = ANY(target_snapshots)
      AND claim.state <> 'started';
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;

    DELETE FROM sentinelflow.analysis_evidence link
    WHERE link.evidence_snapshot_id = ANY(target_snapshots);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.evidence_snapshot_events link
    WHERE link.evidence_snapshot_id = ANY(target_snapshots);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.evidence_snapshot_signals link
    WHERE link.evidence_snapshot_id = ANY(target_snapshots);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.evidence_snapshot_artifacts artifact
    WHERE artifact.evidence_snapshot_id = ANY(target_snapshots);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.evidence_snapshots snapshot
    WHERE snapshot.evidence_snapshot_id = ANY(target_snapshots);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;

    -- Signal membership is normalized evidence and expires independently of
    -- the retained incident aggregate/digests.
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.signals signal
        JOIN sentinelflow.evidence_snapshot_signals link
          ON link.signal_id = signal.signal_id
        JOIN sentinelflow.evidence_snapshots snapshot
          ON snapshot.evidence_snapshot_id = link.evidence_snapshot_id
        WHERE signal.created_at < event_cutoff
          AND snapshot.created_at >= event_cutoff
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF304',
            MESSAGE = 'expired signal is referenced by retained evidence';
    END IF;

    SELECT COALESCE(array_agg(candidate.signal_id), ARRAY[]::uuid[])
    INTO target_signals
    FROM (
        SELECT signal.signal_id
        FROM sentinelflow.signals signal
        WHERE signal.created_at < event_cutoff
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.evidence_snapshot_signals link
              WHERE link.signal_id = signal.signal_id
          )
        ORDER BY signal.created_at, signal.signal_id
        LIMIT p_max_rows
    ) candidate;

    DELETE FROM sentinelflow.analysis_evidence link
    WHERE link.signal_id = ANY(target_signals);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.detector_run_signals link
    WHERE link.signal_id = ANY(target_signals);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.incident_version_signals link
    WHERE link.signal_id = ANY(target_signals);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.incident_signals link
    WHERE link.signal_id = ANY(target_signals);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.signal_evidence link
    WHERE link.signal_id = ANY(target_signals);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.signals signal
    WHERE signal.signal_id = ANY(target_signals);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;

    SELECT COALESCE(array_agg(candidate.import_id), ARRAY[]::uuid[])
    INTO target_imports
    FROM (
        SELECT import.import_id
        FROM sentinelflow.demo_history_imports import
        WHERE import.completed_at < event_cutoff
          AND import.status IN ('completed', 'failed')
        ORDER BY import.completed_at, import.import_id
        LIMIT p_max_rows
    ) candidate;
    DELETE FROM sentinelflow.demo_history_import_batches link
    WHERE link.import_id = ANY(target_imports);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.demo_history_source_coverage coverage
    WHERE coverage.import_id = ANY(target_imports);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.demo_history_imports import
    WHERE import.import_id = ANY(target_imports);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;

    DELETE FROM sentinelflow.source_coverage_attestations coverage
    WHERE coverage.coverage_event_id IN (
        SELECT candidate.coverage_event_id
        FROM sentinelflow.source_coverage_attestations candidate
        WHERE candidate.received_at < event_cutoff
        ORDER BY candidate.received_at, candidate.coverage_event_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.ingest_gap_lifecycle lifecycle
    WHERE lifecycle.lifecycle_id IN (
        SELECT candidate.lifecycle_id
        FROM sentinelflow.ingest_gap_lifecycle candidate
        WHERE COALESCE(candidate.resolved_at, candidate.detected_at) < event_cutoff
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.ingest_sequence_gaps gap
              WHERE gap.sender_id = candidate.sender_id
                AND gap.endpoint_kind = candidate.endpoint_kind
                AND gap.sender_epoch = candidate.sender_epoch
                AND gap.sequence_start <= candidate.sequence_end
                AND gap.sequence_end >= candidate.sequence_start
          )
        ORDER BY COALESCE(candidate.resolved_at, candidate.detected_at),
                 candidate.lifecycle_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.ingest_sequence_gap_resolutions resolution
    WHERE resolution.resolution_id IN (
        SELECT candidate.resolution_id
        FROM sentinelflow.ingest_sequence_gap_resolutions candidate
        WHERE candidate.resolved_at < event_cutoff
        ORDER BY candidate.resolved_at, candidate.resolution_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;

    IF EXISTS (
        SELECT 1
        FROM sentinelflow.signal_evidence link
        LEFT JOIN sentinelflow.gateway_events gateway
          ON gateway.event_id = link.gateway_event_id
        LEFT JOIN sentinelflow.auth_events auth
          ON auth.event_id = link.auth_event_id
        LEFT JOIN sentinelflow.source_health_intervals health
          ON health.event_id = link.source_health_event_id
        JOIN sentinelflow.signals signal ON signal.signal_id = link.signal_id
        WHERE COALESCE(gateway.received_at, auth.received_at, health.received_at) < event_cutoff
          AND signal.created_at >= event_cutoff
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF305',
            MESSAGE = 'expired event is referenced by retained signal';
    END IF;

    SELECT COALESCE(array_agg(candidate.event_id), ARRAY[]::uuid[])
    INTO target_auth_events
    FROM (
        SELECT event.event_id
        FROM sentinelflow.auth_events event
        WHERE event.received_at < event_cutoff
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.signal_evidence link
              WHERE link.auth_event_id = event.event_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.evidence_snapshot_events link
              WHERE link.auth_event_id = event.event_id
          )
        ORDER BY event.received_at, event.event_id
        LIMIT p_max_rows
    ) candidate;
    SELECT COALESCE(array_agg(candidate.event_id), ARRAY[]::uuid[])
    INTO target_gateway_events
    FROM (
        SELECT event.event_id
        FROM sentinelflow.gateway_events event
        WHERE event.received_at < event_cutoff
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.signal_evidence link
              WHERE link.gateway_event_id = event.event_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.evidence_snapshot_events link
              WHERE link.gateway_event_id = event.event_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.auth_events auth
              WHERE auth.bound_gateway_event_id = event.event_id
                AND auth.event_id <> ALL(target_auth_events)
          )
        ORDER BY event.received_at, event.event_id
        LIMIT p_max_rows
    ) candidate;
    SELECT COALESCE(array_agg(candidate.event_id), ARRAY[]::uuid[])
    INTO target_health_events
    FROM (
        SELECT event.event_id
        FROM sentinelflow.source_health_intervals event
        WHERE event.received_at < event_cutoff
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.signal_evidence link
              WHERE link.source_health_event_id = event.event_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.evidence_snapshot_events link
              WHERE link.source_health_event_id = event.event_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.ingest_gap_lifecycle lifecycle
              WHERE lifecycle.source_health_event_id = event.event_id
          )
        ORDER BY event.received_at, event.event_id
        LIMIT p_max_rows
    ) candidate;

    DELETE FROM sentinelflow.incident_events link
    WHERE link.auth_event_id = ANY(target_auth_events)
       OR link.gateway_event_id = ANY(target_gateway_events)
       OR link.source_health_event_id = ANY(target_health_events);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.auth_events event
    WHERE event.event_id = ANY(target_auth_events);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.gateway_events event
    WHERE event.event_id = ANY(target_gateway_events);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.source_health_intervals event
    WHERE event.event_id = ANY(target_health_events);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;

    DELETE FROM sentinelflow.ingest_batches batch
    WHERE (batch.sender_id, batch.sender_epoch, batch.batch_id) IN (
        SELECT candidate.sender_id, candidate.sender_epoch, candidate.batch_id
        FROM sentinelflow.ingest_batches candidate
        WHERE candidate.received_at < event_cutoff
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.gateway_events event
              WHERE event.sender_id = candidate.sender_id
                AND event.sender_epoch = candidate.sender_epoch
                AND event.batch_id = candidate.batch_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.auth_events event
              WHERE event.sender_id = candidate.sender_id
                AND event.sender_epoch = candidate.sender_epoch
                AND event.batch_id = candidate.batch_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.source_health_intervals event
              WHERE event.sender_id = candidate.sender_id
                AND event.sender_epoch = candidate.sender_epoch
                AND event.batch_id = candidate.batch_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.ingest_sequence_gaps gap
              WHERE gap.sender_id = candidate.sender_id
                AND gap.sender_epoch = candidate.sender_epoch
                AND gap.detected_by_batch_id = candidate.batch_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.ingest_sequence_gap_resolutions resolution
              WHERE resolution.sender_id = candidate.sender_id
                AND resolution.sender_epoch = candidate.sender_epoch
                AND resolution.resolution_batch_id = candidate.batch_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.source_coverage_attestations coverage
              WHERE coverage.sender_id = candidate.sender_id
                AND coverage.sender_epoch = candidate.sender_epoch
                AND coverage.covered_through_batch_id = candidate.batch_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.ingest_gap_lifecycle lifecycle
              WHERE lifecycle.sender_id = candidate.sender_id
                AND lifecycle.sender_epoch = candidate.sender_epoch
                AND (lifecycle.detected_by_batch_id = candidate.batch_id OR
                     lifecycle.resolved_by_batch_id = candidate.batch_id))
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.demo_history_import_batches link
              WHERE link.sender_id = candidate.sender_id
                AND link.sender_epoch = candidate.sender_epoch
                AND link.batch_id = candidate.batch_id)
        ORDER BY candidate.received_at, candidate.sender_id,
                 candidate.sender_epoch, candidate.batch_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;

    -- Thirty-day control-plane graphs are removed as a single FK-consistent
    -- unit.  Five-minute authority and live/indeterminate mutations block the
    -- run instead of being shortened by retention.
    SELECT COALESCE(array_agg(candidate.incident_id), ARRAY[]::uuid[])
    INTO target_incidents
    FROM (
        SELECT incident.incident_id
        FROM sentinelflow.incidents incident
        WHERE incident.state = 'closed'
          AND incident.closed_at < control_cutoff
          AND incident.updated_at < control_cutoff
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.outbox_jobs job
              WHERE job.kind = 'analyze'
                AND job.aggregate_type = 'incident'
                AND job.aggregate_id = incident.incident_id
                AND job.state IN ('pending', 'leased', 'retry')
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.incident_version_history history
              WHERE history.incident_id = incident.incident_id
                AND history.recorded_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.incident_signals link
              WHERE link.incident_id = incident.incident_id
                AND link.linked_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.incident_events link
              WHERE link.incident_id = incident.incident_id
                AND link.linked_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.evidence_snapshots snapshot
              WHERE snapshot.incident_id = incident.incident_id
                AND snapshot.created_at >= event_cutoff
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.ai_analyses analysis
              WHERE analysis.incident_id = incident.incident_id
                AND COALESCE(analysis.completed_at, analysis.started_at) >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.analysis_attempt_claims claim
              WHERE claim.incident_id = incident.incident_id
                AND COALESCE(claim.terminal_at, claim.generated_at) >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.validation_attempt_claims claim
              WHERE claim.incident_id = incident.incident_id
                AND COALESCE(claim.terminal_at, claim.generated_at) >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.policy_proposals policy
              WHERE policy.incident_id = incident.incident_id
                AND policy.updated_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.command_candidates candidate
              JOIN sentinelflow.ai_analyses analysis
                ON analysis.analysis_id = candidate.analysis_id
              WHERE analysis.incident_id = incident.incident_id
                AND candidate.updated_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.validation_snapshots validation
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = validation.policy_id
               AND policy.version = validation.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND validation.created_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.hil_exact_artifacts artifact
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = artifact.policy_id
               AND policy.version = artifact.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND artifact.persisted_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.decision_challenges challenge
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = challenge.policy_id
               AND policy.version = challenge.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND challenge.issued_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.approval_decisions decision
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = decision.policy_id
               AND policy.version = decision.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND decision.decided_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.enforcement_actions action
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = action.policy_id
               AND policy.version = action.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND action.updated_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.enforcement_authorizations authz
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = authz.policy_id
               AND policy.version = authz.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND authz.decided_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.inspection_authorizations authz
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = authz.policy_id
               AND policy.version = authz.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND authz.requested_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.dispatch_operations operation
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = operation.policy_id
               AND policy.version = operation.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND operation.created_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.execution_capabilities capability
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = capability.policy_id
               AND policy.version = capability.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND capability.issued_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.execution_results result
              JOIN sentinelflow.enforcement_actions action
                ON action.action_id = result.action_id
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = action.policy_id
               AND policy.version = action.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND result.persisted_at >= control_cutoff
          )
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.revocation_operations operation
              JOIN sentinelflow.enforcement_actions action
                ON action.action_id = operation.action_id
              JOIN sentinelflow.policy_proposals policy
                ON policy.policy_id = action.policy_id
               AND policy.version = action.policy_version
              WHERE policy.incident_id = incident.incident_id
                AND COALESCE(operation.completed_at, operation.created_at) >= control_cutoff
          )
        ORDER BY incident.updated_at, incident.incident_id
        LIMIT p_max_rows
    ) candidate;

    IF EXISTS (
        SELECT 1
        FROM sentinelflow.analysis_attempt_claims claim
        WHERE claim.incident_id = ANY(target_incidents) AND claim.state = 'started'
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.validation_attempt_claims claim
        WHERE claim.incident_id = ANY(target_incidents) AND claim.state = 'started'
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.enforcement_actions action
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = action.policy_id
         AND policy.version = action.policy_version
        WHERE policy.incident_id = ANY(target_incidents)
          AND action.state IN ('approved', 'queued', 'active', 'indeterminate')
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.revocation_operations operation
        JOIN sentinelflow.enforcement_actions action
          ON action.action_id = operation.action_id
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = action.policy_id
         AND policy.version = action.policy_version
        WHERE policy.incident_id = ANY(target_incidents)
          AND operation.state IN ('authorized', 'queued', 'indeterminate')
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF306',
            MESSAGE = 'retention blocked by live control-plane authority';
    END IF;

    DELETE FROM sentinelflow.execution_results result
    WHERE result.action_id IN (
        SELECT action.action_id
        FROM sentinelflow.enforcement_actions action
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = action.policy_id
         AND policy.version = action.policy_version
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.execution_capabilities capability
    WHERE capability.action_id IN (
        SELECT action.action_id
        FROM sentinelflow.enforcement_actions action
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = action.policy_id
         AND policy.version = action.policy_version
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.dispatch_operations operation
    WHERE operation.policy_id IN (
        SELECT policy.policy_id FROM sentinelflow.policy_proposals policy
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.revocation_operations operation
    WHERE operation.action_id IN (
        SELECT action.action_id
        FROM sentinelflow.enforcement_actions action
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = action.policy_id
         AND policy.version = action.policy_version
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.inspection_authorizations authz
    WHERE authz.policy_id IN (
        SELECT policy.policy_id FROM sentinelflow.policy_proposals policy
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.enforcement_actions action
    WHERE action.policy_id IN (
        SELECT policy.policy_id FROM sentinelflow.policy_proposals policy
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.enforcement_authorizations authz
    WHERE authz.policy_id IN (
        SELECT policy.policy_id FROM sentinelflow.policy_proposals policy
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.approval_decisions decision
    WHERE decision.policy_id IN (
        SELECT policy.policy_id FROM sentinelflow.policy_proposals policy
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.decision_challenges challenge
    WHERE challenge.policy_id IN (
        SELECT policy.policy_id FROM sentinelflow.policy_proposals policy
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.hil_exact_artifacts artifact
    WHERE artifact.policy_id IN (
        SELECT policy.policy_id FROM sentinelflow.policy_proposals policy
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;

    DELETE FROM sentinelflow.validation_attempt_gates gate
    WHERE gate.validation_attempt_id IN (
        SELECT claim.validation_attempt_id
        FROM sentinelflow.validation_attempt_claims claim
        WHERE claim.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;
    DELETE FROM sentinelflow.validation_attempt_results result
    WHERE result.validation_attempt_id IN (
        SELECT claim.validation_attempt_id
        FROM sentinelflow.validation_attempt_claims claim
        WHERE claim.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;
    DELETE FROM sentinelflow.validation_attempt_claims claim
    WHERE claim.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;

    DELETE FROM sentinelflow.validation_gates gate
    WHERE gate.validation_snapshot_id IN (
        SELECT validation.validation_snapshot_id
        FROM sentinelflow.validation_snapshots validation
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = validation.policy_id
         AND policy.version = validation.policy_version
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.validation_snapshots validation
    WHERE validation.policy_id IN (
        SELECT policy.policy_id FROM sentinelflow.policy_proposals policy
        WHERE policy.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.policy_proposals policy
    WHERE policy.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;

    DELETE FROM sentinelflow.analysis_output_staging staging
    WHERE staging.analysis_id IN (
        SELECT claim.analysis_id
        FROM sentinelflow.analysis_attempt_claims claim
        WHERE claim.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;
    DELETE FROM sentinelflow.analysis_attempt_results result
    WHERE result.analysis_id IN (
        SELECT claim.analysis_id
        FROM sentinelflow.analysis_attempt_claims claim
        WHERE claim.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;
    DELETE FROM sentinelflow.analysis_attempt_claims claim
    WHERE claim.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;

    DELETE FROM sentinelflow.command_candidates candidate
    WHERE candidate.analysis_id IN (
        SELECT analysis.analysis_id FROM sentinelflow.ai_analyses analysis
        WHERE analysis.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.ai_analyses analysis
    WHERE analysis.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;

    DELETE FROM sentinelflow.detector_run_signals link
    WHERE link.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;
    DELETE FROM sentinelflow.detector_runs run
    WHERE run.job_id IN (
        SELECT candidate.job_id
        FROM sentinelflow.detector_runs candidate
        WHERE candidate.completed_at < control_cutoff
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.detector_run_signals link
              WHERE link.job_id = candidate.job_id
          )
        ORDER BY candidate.completed_at, candidate.job_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;

    DELETE FROM sentinelflow.analysis_evidence link
    WHERE link.evidence_snapshot_id IN (
        SELECT snapshot.evidence_snapshot_id
        FROM sentinelflow.evidence_snapshots snapshot
        WHERE snapshot.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.evidence_snapshot_events link
    WHERE link.evidence_snapshot_id IN (
        SELECT snapshot.evidence_snapshot_id
        FROM sentinelflow.evidence_snapshots snapshot
        WHERE snapshot.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.evidence_snapshot_signals link
    WHERE link.evidence_snapshot_id IN (
        SELECT snapshot.evidence_snapshot_id
        FROM sentinelflow.evidence_snapshots snapshot
        WHERE snapshot.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.evidence_snapshot_artifacts artifact
    WHERE artifact.evidence_snapshot_id IN (
        SELECT snapshot.evidence_snapshot_id
        FROM sentinelflow.evidence_snapshots snapshot
        WHERE snapshot.incident_id = ANY(target_incidents)
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.evidence_snapshots snapshot
    WHERE snapshot.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.incident_events link
    WHERE link.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    event_count := event_count + affected;
    DELETE FROM sentinelflow.incident_version_signals link
    WHERE link.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.incident_version_history history
    WHERE history.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.incident_signals link
    WHERE link.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.incidents incident
    WHERE incident.incident_id = ANY(target_incidents);
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;

    DELETE FROM sentinelflow.dead_letter_jobs dead
    WHERE dead.job_id IN (
        SELECT candidate.job_id
        FROM sentinelflow.dead_letter_jobs candidate
        WHERE candidate.dead_at < control_cutoff
          AND candidate.resolution_state <> 'unresolved'
        ORDER BY candidate.dead_at, candidate.job_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;
    DELETE FROM sentinelflow.outbox_jobs job
    WHERE job.job_id IN (
        SELECT candidate.job_id
        FROM sentinelflow.outbox_jobs candidate
        WHERE candidate.updated_at < control_cutoff
          AND candidate.state IN ('completed', 'dead')
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.dead_letter_jobs dead
                          WHERE dead.job_id = candidate.job_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.analysis_attempt_claims claim
                          WHERE claim.job_id = candidate.job_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.validation_attempt_claims claim
                          WHERE claim.job_id = candidate.job_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.detector_runs run
                          WHERE run.job_id = candidate.job_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.dispatch_operations operation
                          WHERE operation.job_id = candidate.job_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.execution_capabilities capability
                          WHERE capability.job_id = candidate.job_id)
        ORDER BY candidate.updated_at, candidate.job_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    transient_count := transient_count + affected;

    DELETE FROM sentinelflow.hil_reasons reason
    WHERE reason.reason_id IN (
        SELECT candidate.reason_id
        FROM sentinelflow.hil_reasons candidate
        WHERE candidate.created_at < control_cutoff
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.approval_decisions decision
                          WHERE decision.reason_id = candidate.reason_id)
          AND NOT EXISTS (SELECT 1 FROM sentinelflow.revocation_operations operation
                          WHERE operation.reason_id = candidate.reason_id)
        ORDER BY candidate.created_at, candidate.reason_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.ai_budget_reservations reservation
    WHERE reservation.reservation_id IN (
        SELECT candidate.reservation_id
        FROM sentinelflow.ai_budget_reservations candidate
        WHERE candidate.created_at < control_cutoff
          AND candidate.state <> 'active'
        ORDER BY candidate.created_at, candidate.reservation_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;
    DELETE FROM sentinelflow.ai_budget_ledger ledger
    WHERE (ledger.budget_date, ledger.model, ledger.rate_card_version) IN (
        SELECT candidate.budget_date, candidate.model, candidate.rate_card_version
        FROM sentinelflow.ai_budget_ledger candidate
        WHERE candidate.budget_date < control_cutoff::date
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.ai_budget_reservations reservation
              WHERE reservation.budget_date = candidate.budget_date
                AND reservation.model = candidate.model
                AND reservation.rate_card_version = candidate.rate_card_version
          )
        ORDER BY candidate.budget_date, candidate.model, candidate.rate_card_version
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    control_count := control_count + affected;

    -- Audit pruning is itself summarized by the new digest-only audit event.
    DELETE FROM sentinelflow.audit_events event
    WHERE event.sequence IN (
        SELECT candidate.sequence
        FROM sentinelflow.audit_events candidate
        WHERE candidate.recorded_at < audit_cutoff_value
        ORDER BY candidate.recorded_at, candidate.sequence
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    audit_count := audit_count + affected;
    DELETE FROM sentinelflow.retention_runs prior
    WHERE prior.run_id IN (
        SELECT candidate.run_id
        FROM sentinelflow.retention_runs candidate
        WHERE candidate.completed_at < audit_cutoff_value
        ORDER BY candidate.completed_at, candidate.run_id
        LIMIT p_max_rows
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    audit_count := audit_count + affected;

    used_count := current_setting(
        'sentinelflow.retention_deleted_rows', true
    )::bigint;
    event_count := current_setting(
        'sentinelflow.retention_deleted_event', true
    )::bigint;
    control_count := current_setting(
        'sentinelflow.retention_deleted_control', true
    )::bigint;
    transient_count := current_setting(
        'sentinelflow.retention_deleted_transient', true
    )::bigint;
    audit_count := current_setting(
        'sentinelflow.retention_deleted_audit', true
    )::bigint;
    IF used_count > p_max_rows OR
       used_count <> event_count + control_count + transient_count + audit_count THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'retention delete budget accounting mismatch';
    END IF;

    completed_value := clock_timestamp();
    digest_value := (
        'sha256:' || encode(sha256(convert_to(
            'retention-run-v1' || chr(10) || p_run_id::text || chr(10) ||
            to_char(p_as_of AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || chr(10) ||
            p_max_rows::text || chr(10) || 'succeeded' || chr(10) ||
            '0' || chr(10) ||
            event_count::text || chr(10) || control_count::text || chr(10) ||
            transient_count::text || chr(10) || audit_count::text || chr(10),
            'UTF8'
        )), 'hex')
    )::sentinelflow.sha256_digest;

    INSERT INTO sentinelflow.retention_runs (
        run_id, schema_version, as_of, event_evidence_cutoff,
        control_plane_cutoff, audit_cutoff, max_rows,
        event_evidence_deleted, control_plane_deleted,
        transient_deleted, audit_deleted, outcome, failure_code,
        anomaly_count, run_digest, completed_at
    ) VALUES (
        p_run_id, 'retention-run-v1', p_as_of, event_cutoff,
        control_cutoff, audit_cutoff_value, p_max_rows,
        event_count, control_count, transient_count, audit_count,
        'succeeded', NULL, 0,
        digest_value, completed_value
    );
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        primary_digest, outcome, occurred_at
    ) VALUES (
        gen_random_uuid(), 'system', 'retention-worker',
        'retention_run_completed', 'retention_run', p_run_id,
        digest_value, 'succeeded', completed_value
    );

    PERFORM set_config('sentinelflow.retention_delete', '', true);
    RETURN QUERY SELECT p_run_id, false, 'succeeded'::text, ''::text,
        0::bigint, event_count, control_count,
        transient_count, audit_count, digest_value, completed_value;
END
$function$;

REVOKE ALL ON TABLE retention_runs FROM PUBLIC, sentinelflow_api,
    sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher,
    sentinelflow_retention;
GRANT SELECT ON retention_runs TO sentinelflow_read;
GRANT USAGE ON SCHEMA sentinelflow TO sentinelflow_retention;

REVOKE ALL ON FUNCTION sentinelflow.require_hil_source_evidence_000023(),
    sentinelflow.require_challenge_session_source_000023(),
    sentinelflow.enforce_retention_delete_budget_000023(),
    sentinelflow.retention_runs_append_only_000023(),
    sentinelflow.run_retention_000023(uuid, timestamptz, integer)
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
     sentinelflow_dispatcher, sentinelflow_retention;
GRANT EXECUTE ON FUNCTION sentinelflow.run_retention_000023(
    uuid, timestamptz, integer
) TO sentinelflow_retention;

INSERT INTO schema_migrations (version, name)
VALUES (23, 'retention_runtime')
ON CONFLICT (version) DO NOTHING;

COMMIT;
