BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Rolling back after a successful retention mutation would require inventing
-- deleted evidence and restoring detached source rows. Refuse that unsafe
-- downgrade rather than leave a partially compatible schema.
DO $retention_down_guard$
BEGIN
    IF EXISTS (SELECT 1 FROM sentinelflow.retention_runs) OR EXISTS (
        SELECT 1
        FROM sentinelflow.hil_exact_artifacts artifact
        LEFT JOIN sentinelflow.evidence_snapshot_artifacts source
          ON source.evidence_snapshot_id = artifact.evidence_snapshot_id
        WHERE source.evidence_snapshot_id IS NULL
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.decision_challenges challenge
        LEFT JOIN sentinelflow.admin_sessions session
          ON session.session_id = challenge.session_id
        WHERE session.session_id IS NULL
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.analysis_attempt_claims claim
        WHERE claim.evidence_snapshot_id IS NULL
          AND claim.evidence_snapshot_digest IS NOT NULL
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.ai_analyses analysis
        WHERE analysis.evidence_snapshot_id IS NULL
          AND analysis.evidence_snapshot_digest IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'retention downgrade requires offline restore from backup';
    END IF;
END
$retention_down_guard$;

DROP FUNCTION IF EXISTS sentinelflow.run_retention_000023(
    uuid, timestamptz, integer
);
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
    END LOOP;
END
$retention_delete_budget_triggers$;
DROP TRIGGER IF EXISTS retention_runs_append_only_000023
    ON sentinelflow.retention_runs;
DROP FUNCTION IF EXISTS sentinelflow.enforce_retention_delete_budget_000023();
DROP FUNCTION IF EXISTS sentinelflow.retention_runs_append_only_000023();
DROP TABLE IF EXISTS sentinelflow.retention_runs;
REVOKE USAGE ON SCHEMA sentinelflow FROM sentinelflow_retention;

DROP TRIGGER IF EXISTS hil_exact_artifacts_require_source_000023
    ON sentinelflow.hil_exact_artifacts;
DROP FUNCTION IF EXISTS sentinelflow.require_hil_source_evidence_000023();
ALTER TABLE sentinelflow.hil_exact_artifacts
    ADD CONSTRAINT hil_exact_artifacts_evidence_snapshot_id_fkey
    FOREIGN KEY (evidence_snapshot_id)
    REFERENCES sentinelflow.evidence_snapshot_artifacts (evidence_snapshot_id)
    ON DELETE RESTRICT;

DROP TRIGGER IF EXISTS decision_challenges_require_session_source_000023
    ON sentinelflow.decision_challenges;
DROP FUNCTION IF EXISTS sentinelflow.require_challenge_session_source_000023();
ALTER TABLE sentinelflow.decision_challenges
    ADD CONSTRAINT decision_challenges_session_id_fkey
    FOREIGN KEY (session_id)
    REFERENCES sentinelflow.admin_sessions (session_id)
    ON DELETE RESTRICT;

ALTER TABLE sentinelflow.admin_sessions
    DROP CONSTRAINT IF EXISTS admin_sessions_rotation_parent_id_fkey;
ALTER TABLE sentinelflow.admin_sessions
    ADD CONSTRAINT admin_sessions_rotation_parent_id_fkey
    FOREIGN KEY (rotation_parent_id)
    REFERENCES sentinelflow.admin_sessions (session_id)
    ON DELETE RESTRICT;

ALTER TABLE sentinelflow.analysis_attempt_claims
    DROP CONSTRAINT IF EXISTS analysis_attempt_claim_snapshot;
ALTER TABLE sentinelflow.analysis_attempt_claims
    ADD CONSTRAINT analysis_attempt_claim_snapshot CHECK (
        (evidence_snapshot_id IS NULL AND evidence_snapshot_digest IS NULL) OR
        (evidence_snapshot_id IS NOT NULL AND evidence_snapshot_digest IS NOT NULL)
    );

-- Restore the exact provider provenance guard installed by migration 000021.
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

-- Restore each append-only function exactly as defined by its owning
-- migration. The triggers remain in place throughout the downgrade.
CREATE OR REPLACE FUNCTION sentinelflow.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'audit events are append-only';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.reject_exact_artifact_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'canonical artifact rows are immutable';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.reject_detection_history_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
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
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'gates of a valid validation snapshot are immutable';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$function$;

DELETE FROM sentinelflow.schema_migrations WHERE version = 23;

RESET ROLE;

DO $drop_retention_role$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinelflow_retention') THEN
        EXECUTE format(
            'REVOKE CONNECT ON DATABASE %I FROM sentinelflow_retention',
            current_database()
        );
        EXECUTE format(
            'ALTER ROLE sentinelflow_retention IN DATABASE %I RESET search_path',
            current_database()
        );
        DROP ROLE sentinelflow_retention;
    END IF;
END
$drop_retention_role$;

COMMIT;
