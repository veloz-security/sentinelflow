BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Aggregate lifecycle revisions and evidence revisions are deliberately
-- separate. Analysis state changes advance incidents.version, while the
-- immutable model input, analysis, and downstream policy remain bound to the
-- last deterministic evidence-bearing version.
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS evidence_version integer NULL;

UPDATE incidents incident
SET evidence_version = evidence.incident_version
FROM (
    SELECT history.incident_id, max(history.incident_version) AS incident_version
    FROM incident_version_history history
    WHERE history.mutation_kind IN ('created', 'signal_added', 'reopened')
    GROUP BY history.incident_id
) evidence
WHERE incident.incident_id = evidence.incident_id
  AND incident.evidence_version IS NULL;

DO $incident_evidence_version_constraint$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.incidents'::regclass
          AND conname = 'incident_evidence_version_order'
    ) THEN
        ALTER TABLE sentinelflow.incidents
            ADD CONSTRAINT incident_evidence_version_order CHECK (
                evidence_version IS NULL OR
                (evidence_version >= 1 AND evidence_version <= version)
            );
    END IF;
END
$incident_evidence_version_constraint$;

ALTER TABLE analysis_attempt_claims
    ADD COLUMN IF NOT EXISTS analyzing_incident_version integer NULL,
    ADD COLUMN IF NOT EXISTS terminal_incident_version integer NULL;

DO $analysis_claim_lifecycle_order_constraint$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.analysis_attempt_claims'::regclass
          AND conname = 'analysis_attempt_claim_lifecycle_order'
    ) THEN
        ALTER TABLE sentinelflow.analysis_attempt_claims
            ADD CONSTRAINT analysis_attempt_claim_lifecycle_order CHECK (
                (analyzing_incident_version IS NULL OR
                    analyzing_incident_version = incident_version + 1) AND
                (terminal_incident_version IS NULL OR
                    terminal_incident_version =
                        COALESCE(analyzing_incident_version, incident_version) + 1)
            );
    END IF;
END
$analysis_claim_lifecycle_order_constraint$;

-- The frozen contract is fifty complete signal references and twelve KiB.
-- Supersede the pre-contract hard-coded sixteen-reference check without
-- editing migration 000008. Source drift aborts instead of silently changing
-- an unreviewed function body.
DO $raise_analysis_signal_limit$
DECLARE
    definition text;
BEGIN
    SELECT pg_get_functiondef(
        'sentinelflow.prepare_analysis_attempt_legacy(uuid,uuid)'::regprocedure
    ) INTO definition;
    IF position('evidence.signal_count > 16' IN definition) > 0 THEN
        definition := replace(
            definition,
            'evidence.signal_count > 16',
            'evidence.signal_count > 50'
        );
        EXECUTE definition;
    ELSIF position('evidence.signal_count > 50' IN definition) = 0 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'analysis prepare signal-limit source drift';
    END IF;
END
$raise_analysis_signal_limit$;

-- Preserve the exact-evidence wrapper installed by 000014. The new wrapper
-- adds lifecycle fencing around it; callers cannot invoke the preserved name.
DO $rename_analysis_prepare$
BEGIN
    IF to_regprocedure(
        'sentinelflow.prepare_analysis_attempt_pre_000017(uuid,uuid)'
    ) IS NULL THEN
        ALTER FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
            RENAME TO prepare_analysis_attempt_pre_000017;
    END IF;
END
$rename_analysis_prepare$;

-- Preserve the original finalizer and build a private compatibility copy that
-- addresses the current lifecycle projection A while retaining D in every
-- immutable analysis/evidence/policy field. Exactly four current-projection
-- predicates are expected; any drift fails the migration.
DO $clone_analysis_finalizer$
DECLARE
    definition text;
    patched text;
BEGIN
    IF to_regprocedure(
        'sentinelflow.finalize_analysis_attempt_pre_000017('
        'uuid,uuid,text,timestamptz,timestamptz,text,text,jsonb)'
    ) IS NULL THEN
        ALTER FUNCTION sentinelflow.finalize_analysis_attempt(
            uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
        ) RENAME TO finalize_analysis_attempt_pre_000017;
    END IF;

    SELECT pg_get_functiondef(
        'sentinelflow.finalize_analysis_attempt_pre_000017('
        'uuid,uuid,text,timestamptz,timestamptz,text,text,jsonb)'::regprocedure
    ) INTO definition;
    IF regexp_count(definition, 'version = claim[.]incident_version') <> 4 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'analysis finalizer lifecycle source drift';
    END IF;
    patched := replace(
        definition,
        'finalize_analysis_attempt_pre_000017',
        'finalize_analysis_attempt_lifecycle_000017'
    );
    patched := replace(
        patched,
        'version = claim.incident_version',
        'version = claim.analyzing_incident_version'
    );
    EXECUTE patched;
END
$clone_analysis_finalizer$;

CREATE OR REPLACE FUNCTION sentinelflow.advance_analysis_incident_lifecycle_000017(
    p_incident_id uuid,
    p_expected_version integer,
    p_expected_projection_state text,
    p_target_state text,
    p_failure_reason text,
    p_analysis_id uuid
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    next_version integer;
    incident sentinelflow.incidents%ROWTYPE;
    prior sentinelflow.incident_version_history%ROWTYPE;
    current_signal_count integer;
    mutation_digest_value sentinelflow.sha256_digest;
BEGIN
    IF p_incident_id IS NULL OR p_analysis_id IS NULL OR
       p_expected_version < 1 OR p_expected_version >= 2147483647 OR
       p_expected_projection_state NOT IN (
           'open', 'analyzing', 'review_ready', 'analysis_failed'
       ) OR p_target_state NOT IN (
           'analyzing', 'review_ready', 'analysis_failed'
       ) OR
       (p_target_state = 'analysis_failed' AND p_failure_reason IS NULL) OR
       (p_target_state <> 'analysis_failed' AND p_failure_reason IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid analysis lifecycle transition';
    END IF;

    SELECT * INTO incident
    FROM sentinelflow.incidents current_incident
    WHERE current_incident.incident_id = p_incident_id
      AND current_incident.version = p_expected_version
      AND current_incident.state = p_expected_projection_state
    FOR UPDATE;
    IF NOT FOUND OR incident.evidence_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'analysis lifecycle projection changed';
    END IF;

    SELECT * INTO prior
    FROM sentinelflow.incident_version_history history
    WHERE history.incident_id = p_incident_id
      AND history.incident_version = p_expected_version;
    IF NOT FOUND OR
       NOT (
           (prior.state = 'open' AND p_target_state IN ('analyzing', 'analysis_failed')) OR
           (prior.state = 'analyzing' AND
                p_target_state IN ('review_ready', 'analysis_failed'))
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'analysis lifecycle history transition invalid';
    END IF;

    IF (prior.mutation_kind IN ('created', 'signal_added', 'reopened') AND
            incident.evidence_version <> p_expected_version) OR
       (prior.mutation_kind = 'state_changed' AND
            incident.evidence_version >= p_expected_version) THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'analysis lifecycle evidence version changed';
    END IF;

    SELECT count(*)::integer INTO current_signal_count
    FROM sentinelflow.incident_signals link
    WHERE link.incident_id = p_incident_id;
    IF current_signal_count <> prior.signal_count OR EXISTS (
        SELECT 1
        FROM sentinelflow.incident_signals current_link
        WHERE current_link.incident_id = p_incident_id
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.incident_version_signals historical_link
              WHERE historical_link.incident_id = p_incident_id
                AND historical_link.incident_version = p_expected_version
                AND historical_link.signal_id = current_link.signal_id
          )
    ) OR EXISTS (
        SELECT 1
        FROM sentinelflow.incident_version_signals historical_link
        WHERE historical_link.incident_id = p_incident_id
          AND historical_link.incident_version = p_expected_version
          AND NOT EXISTS (
              SELECT 1
              FROM sentinelflow.incident_signals current_link
              WHERE current_link.incident_id = p_incident_id
                AND current_link.signal_id = historical_link.signal_id
          )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'analysis lifecycle signal membership changed';
    END IF;

    next_version := p_expected_version + 1;
    UPDATE sentinelflow.incidents current_incident
    SET state = p_target_state,
        version = next_version,
        analysis_failure_reason = p_failure_reason,
        updated_at = GREATEST(current_incident.updated_at, server_now)
    WHERE current_incident.incident_id = p_incident_id
      AND current_incident.version = p_expected_version
      AND current_incident.state = p_expected_projection_state
    RETURNING * INTO incident;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'analysis lifecycle projection changed';
    END IF;

    UPDATE sentinelflow.incident_signals
    SET incident_version = next_version
    WHERE incident_id = p_incident_id;
    UPDATE sentinelflow.incident_events
    SET incident_version = next_version
    WHERE incident_id = p_incident_id;

    mutation_digest_value := sentinelflow.analysis_sha256(convert_to(
        'analysis-lifecycle-state-v1' || chr(10) ||
        p_incident_id::text || chr(10) || next_version::text || chr(10) ||
        p_analysis_id::text || chr(10) || p_target_state || chr(10),
        'UTF8'
    ));
    INSERT INTO sentinelflow.incident_version_history (
        incident_id, incident_version, state, kind, source_ip, service_label,
        first_seen, last_seen, closed_at, reopen_until, deterministic_score,
        mutation_kind, mutation_digest, evidence_digest, signal_count, recorded_at
    ) VALUES (
        incident.incident_id, next_version, incident.state, incident.kind,
        incident.source_ip, incident.service_label, incident.first_seen,
        incident.last_seen, incident.closed_at, incident.reopen_until,
        incident.deterministic_score, 'state_changed', mutation_digest_value,
        prior.evidence_digest, prior.signal_count, server_now
    );
    INSERT INTO sentinelflow.incident_version_signals (
        incident_id, incident_version, signal_id, ordinal
    )
    SELECT historical_link.incident_id, next_version,
           historical_link.signal_id, historical_link.ordinal
    FROM sentinelflow.incident_version_signals historical_link
    WHERE historical_link.incident_id = p_incident_id
      AND historical_link.incident_version = p_expected_version
    ORDER BY historical_link.ordinal;
    RETURN next_version;
END
$function$;

-- A deterministic signal that wins the race with an in-flight provider call
-- first terminates that exact D/A attempt. The caller appends the new evidence
-- revision in the same transaction, so a failure cannot consume the signal or
-- leave a started claim detached from the aggregate lifecycle. Lock ordering
-- matches the analysis finalizer: outbox job, claim, then incident.
CREATE OR REPLACE FUNCTION sentinelflow.interrupt_analysis_for_new_evidence_000017(
    p_incident_id uuid,
    p_expected_analyzing_version integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    claim sentinelflow.analysis_attempt_claims%ROWTYPE;
    job sentinelflow.outbox_jobs%ROWTYPE;
    incident sentinelflow.incidents%ROWTYPE;
    terminal_version integer;
    failure_digest sentinelflow.sha256_digest;
BEGIN
    IF p_incident_id IS NULL OR p_expected_analyzing_version < 2 THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid analysis evidence supersession request';
    END IF;

    SELECT * INTO claim
    FROM sentinelflow.analysis_attempt_claims current_claim
    WHERE current_claim.incident_id = p_incident_id
      AND current_claim.analyzing_incident_version = p_expected_analyzing_version
      AND current_claim.state = 'started';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'analysis evidence supersession claim changed';
    END IF;

    SELECT * INTO job
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = claim.job_id
      AND current_job.kind = 'analyze'
      AND current_job.aggregate_type = 'incident'
      AND current_job.aggregate_id = p_incident_id
      AND current_job.aggregate_version = claim.incident_version
      AND current_job.state = 'leased'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'analysis evidence supersession job changed';
    END IF;

    SELECT * INTO claim
    FROM sentinelflow.analysis_attempt_claims current_claim
    WHERE current_claim.analysis_id = claim.analysis_id
      AND current_claim.job_id = job.job_id
      AND current_claim.incident_id = p_incident_id
      AND current_claim.incident_version = job.aggregate_version
      AND current_claim.analyzing_incident_version = p_expected_analyzing_version
      AND current_claim.terminal_incident_version IS NULL
      AND current_claim.state = 'started'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'analysis evidence supersession claim changed';
    END IF;

    SELECT * INTO incident
    FROM sentinelflow.incidents current_incident
    WHERE current_incident.incident_id = p_incident_id
      AND current_incident.version = p_expected_analyzing_version
      AND current_incident.evidence_version = claim.incident_version
      AND current_incident.state = 'analyzing'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'analysis evidence supersession projection changed';
    END IF;

    terminal_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
        p_incident_id, p_expected_analyzing_version, 'analyzing',
        'analysis_failed', 'incomplete', claim.analysis_id
    );
    UPDATE sentinelflow.analysis_attempt_claims
    SET state = 'interrupted', no_call_code = 'analysis_interrupted',
        terminal_at = server_now, terminal_incident_version = terminal_version
    WHERE analysis_id = claim.analysis_id;
    INSERT INTO sentinelflow.analysis_attempt_results (
        analysis_id, result_state, failure_reason, completed_at
    ) VALUES (
        claim.analysis_id, 'interrupted', 'analysis_interrupted', server_now
    );

    failure_digest := sentinelflow.analysis_sha256(
        convert_to('analysis_superseded_by_new_evidence', 'UTF8')
    );
    UPDATE sentinelflow.outbox_jobs
    SET state = 'dead', lease_token = NULL, lease_owner = NULL,
        lease_expires_at = NULL, last_error_code = 'analysis_superseded',
        last_error_digest = failure_digest, updated_at = server_now
    WHERE job_id = job.job_id;
    INSERT INTO sentinelflow.dead_letter_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        attempts, failure_code, failure_digest, dead_at
    ) VALUES (
        job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
        job.aggregate_version, job.attempts, 'analysis_superseded',
        failure_digest, server_now
    ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        incident_id, primary_digest, outcome, occurred_at
    ) VALUES (
        gen_random_uuid(), 'system', 'detection-worker',
        'analysis_superseded_by_new_evidence', 'analysis', claim.analysis_id,
        claim.incident_id, claim.evidence_snapshot_digest,
        'indeterminate', server_now
    );
    RETURN terminal_version;
END
$function$;

-- Upgrade any pre-000017 analysis rows only when their current projection and
-- immutable evidence history still describe exactly the claimed D version.
-- A later deterministic mutation requires an explicit offline reconciliation;
-- silently inventing its historical ordering would weaken evidence binding.
DO $upgrade_existing_analysis_lifecycle$
DECLARE
    claim sentinelflow.analysis_attempt_claims%ROWTYPE;
    incident sentinelflow.incidents%ROWTYPE;
    analyzing_version integer;
    terminal_version integer;
    terminal_state text;
    failure_reason text;
BEGIN
    FOR claim IN
        SELECT * FROM sentinelflow.analysis_attempt_claims current_claim
        WHERE current_claim.analyzing_incident_version IS NULL
          AND current_claim.terminal_incident_version IS NULL
        ORDER BY current_claim.generated_at, current_claim.analysis_id
        FOR UPDATE
    LOOP
        SELECT * INTO incident
        FROM sentinelflow.incidents current_incident
        WHERE current_incident.incident_id = claim.incident_id
        FOR UPDATE;
        IF NOT FOUND OR incident.version <> claim.incident_version OR
           incident.evidence_version IS NULL OR
           incident.evidence_version <> claim.incident_version OR
           NOT EXISTS (
               SELECT 1 FROM sentinelflow.incident_version_history history
               WHERE history.incident_id = claim.incident_id
                 AND history.incident_version = claim.incident_version
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'existing analysis lifecycle requires offline reconciliation';
        END IF;

        IF claim.state = 'no_call' THEN
            IF incident.state <> 'analysis_failed' THEN
                RAISE EXCEPTION USING ERRCODE = '55000',
                    MESSAGE = 'existing no-call lifecycle state mismatch';
            END IF;
            terminal_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
                claim.incident_id, claim.incident_version, incident.state,
                'analysis_failed', incident.analysis_failure_reason, claim.analysis_id
            );
            UPDATE sentinelflow.analysis_attempt_claims
            SET terminal_incident_version = terminal_version
            WHERE analysis_id = claim.analysis_id;
            CONTINUE;
        END IF;

        IF claim.state = 'started' THEN
            terminal_state := NULL;
            failure_reason := NULL;
        ELSIF claim.state = 'succeeded' THEN
            terminal_state := 'review_ready';
            failure_reason := NULL;
        ELSE
            terminal_state := 'analysis_failed';
            failure_reason := incident.analysis_failure_reason;
        END IF;
        IF (claim.state = 'started' AND incident.state <> 'analyzing') OR
           (claim.state = 'succeeded' AND incident.state <> 'review_ready') OR
           (claim.state IN ('failed', 'interrupted') AND
                incident.state <> 'analysis_failed') THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'existing analysis lifecycle state mismatch';
        END IF;

        analyzing_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
            claim.incident_id, claim.incident_version, incident.state,
            'analyzing', NULL, claim.analysis_id
        );
        UPDATE sentinelflow.analysis_attempt_claims
        SET analyzing_incident_version = analyzing_version
        WHERE analysis_id = claim.analysis_id;
        IF terminal_state IS NOT NULL THEN
            terminal_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
                claim.incident_id, analyzing_version, 'analyzing',
                terminal_state, failure_reason, claim.analysis_id
            );
            UPDATE sentinelflow.analysis_attempt_claims
            SET terminal_incident_version = terminal_version
            WHERE analysis_id = claim.analysis_id;
        END IF;
    END LOOP;
END
$upgrade_existing_analysis_lifecycle$;

CREATE OR REPLACE FUNCTION sentinelflow.enforce_analysis_claim_lifecycle_000017()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    current_claim sentinelflow.analysis_attempt_claims%ROWTYPE;
BEGIN
    SELECT * INTO current_claim
    FROM sentinelflow.analysis_attempt_claims claim
    WHERE claim.analysis_id = NEW.analysis_id;
    IF NOT FOUND OR
       (current_claim.state = 'started' AND (
            current_claim.analyzing_incident_version IS NULL OR
            current_claim.terminal_incident_version IS NOT NULL
       )) OR
       (current_claim.state IN ('succeeded', 'failed', 'interrupted') AND (
            current_claim.analyzing_incident_version IS NULL OR
            current_claim.terminal_incident_version IS NULL
       )) OR
       (current_claim.state = 'no_call' AND (
            current_claim.analyzing_incident_version IS NOT NULL OR
            current_claim.terminal_incident_version IS NULL
       )) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'analysis claim lifecycle mapping incomplete';
    END IF;
    RETURN NULL;
END
$function$;

DROP TRIGGER IF EXISTS analysis_attempt_claim_lifecycle_000017
    ON analysis_attempt_claims;
CREATE CONSTRAINT TRIGGER analysis_attempt_claim_lifecycle_000017
AFTER INSERT OR UPDATE OF state, analyzing_incident_version, terminal_incident_version
ON analysis_attempt_claims
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION sentinelflow.enforce_analysis_claim_lifecycle_000017();

CREATE OR REPLACE FUNCTION sentinelflow.prepare_analysis_attempt(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE(status text, snapshot jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    job sentinelflow.outbox_jobs%ROWTYPE;
    claim sentinelflow.analysis_attempt_claims%ROWTYPE;
    base_status text;
    base_snapshot jsonb;
    signal_total integer;
    analysis_id_value uuid;
    lifecycle_version integer;
    failure_digest sentinelflow.sha256_digest;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid analysis prepare request';
    END IF;
    SELECT * INTO job
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
      AND current_job.kind = 'analyze'
      AND current_job.aggregate_type = 'incident'
      AND current_job.state = 'leased'
      AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now
      AND current_job.updated_at <= server_now
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT * INTO claim
    FROM sentinelflow.analysis_attempt_claims current_claim
    WHERE current_claim.job_id = job.job_id
    FOR UPDATE;
    IF FOUND THEN
        IF claim.state = 'started' THEN
            IF claim.analyzing_incident_version IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'started analysis lacks lifecycle fence';
            END IF;
            lifecycle_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
                claim.incident_id, claim.analyzing_incident_version,
                'analyzing', 'analysis_failed', 'incomplete', claim.analysis_id
            );
            UPDATE sentinelflow.analysis_attempt_claims
            SET state = 'interrupted', no_call_code = 'analysis_interrupted',
                terminal_at = server_now,
                terminal_incident_version = lifecycle_version
            WHERE analysis_id = claim.analysis_id;
            INSERT INTO sentinelflow.analysis_attempt_results (
                analysis_id, result_state, failure_reason, completed_at
            ) VALUES (
                claim.analysis_id, 'interrupted', 'analysis_interrupted', server_now
            );
            failure_digest := sentinelflow.analysis_sha256(
                convert_to('analysis_interrupted', 'UTF8')
            );
            UPDATE sentinelflow.outbox_jobs
            SET state = 'dead', lease_token = NULL, lease_owner = NULL,
                lease_expires_at = NULL, last_error_code = 'analysis_interrupted',
                last_error_digest = failure_digest, updated_at = server_now
            WHERE job_id = job.job_id;
            INSERT INTO sentinelflow.dead_letter_jobs (
                job_id, kind, aggregate_type, aggregate_id, aggregate_version,
                attempts, failure_code, failure_digest, dead_at
            ) VALUES (
                job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
                job.aggregate_version, job.attempts, 'analysis_interrupted',
                failure_digest, server_now
            ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
            INSERT INTO sentinelflow.audit_events (
                event_id, actor_type, actor_id, action, object_type, object_id,
                incident_id, primary_digest, outcome, occurred_at
            ) VALUES (
                gen_random_uuid(), 'system', 'analysis-worker',
                'analysis_interrupted', 'analysis', claim.analysis_id,
                claim.incident_id, claim.evidence_snapshot_digest,
                'indeterminate', server_now
            );
            status := 'interrupted';
            snapshot := NULL;
            RETURN NEXT;
            RETURN;
        END IF;

        IF claim.state = 'interrupted' THEN
            failure_digest := sentinelflow.analysis_sha256(
                convert_to('analysis_interrupted', 'UTF8')
            );
            UPDATE sentinelflow.outbox_jobs
            SET state = 'dead', lease_token = NULL, lease_owner = NULL,
                lease_expires_at = NULL, last_error_code = 'analysis_interrupted',
                last_error_digest = failure_digest, updated_at = server_now
            WHERE job_id = job.job_id;
            INSERT INTO sentinelflow.dead_letter_jobs (
                job_id, kind, aggregate_type, aggregate_id, aggregate_version,
                attempts, failure_code, failure_digest, dead_at
            ) VALUES (
                job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
                job.aggregate_version, job.attempts, 'analysis_interrupted',
                failure_digest, server_now
            ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
        ELSE
            UPDATE sentinelflow.outbox_jobs
            SET state = 'completed', lease_token = NULL, lease_owner = NULL,
                lease_expires_at = NULL, last_error_code = NULL,
                last_error_digest = NULL, updated_at = server_now
            WHERE job_id = job.job_id;
        END IF;
        status := 'terminal';
        snapshot := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT history.signal_count INTO signal_total
    FROM sentinelflow.incident_version_history history
    JOIN sentinelflow.incidents incident
      ON incident.incident_id = history.incident_id
     AND incident.version = history.incident_version
     AND incident.evidence_version = history.incident_version
     AND incident.state = 'open'
    WHERE history.incident_id = job.aggregate_id
      AND history.incident_version = job.aggregate_version;
    IF FOUND AND signal_total > 50 THEN
        analysis_id_value := gen_random_uuid();
        INSERT INTO sentinelflow.analysis_attempt_claims (
            analysis_id, job_id, incident_id, incident_version,
            outbox_attempt, state, no_call_code, generated_at, terminal_at
        ) VALUES (
            analysis_id_value, job.job_id, job.aggregate_id,
            job.aggregate_version, job.attempts, 'no_call',
            'input_too_large', server_now, server_now
        );
        INSERT INTO sentinelflow.analysis_attempt_results (
            analysis_id, result_state, failure_reason, completed_at
        ) VALUES (
            analysis_id_value, 'no_call', 'input_too_large', server_now
        );
        lifecycle_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
            job.aggregate_id, job.aggregate_version, 'open',
            'analysis_failed', 'input_too_large', analysis_id_value
        );
        UPDATE sentinelflow.analysis_attempt_claims
        SET terminal_incident_version = lifecycle_version
        WHERE analysis_id = analysis_id_value;
        UPDATE sentinelflow.outbox_jobs
        SET state = 'completed', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = NULL,
            last_error_digest = NULL, updated_at = server_now
        WHERE job_id = job.job_id;
        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            incident_id, primary_digest, outcome, occurred_at
        ) VALUES (
            gen_random_uuid(), 'system', 'analysis-worker', 'analysis_no_call',
            'analysis', analysis_id_value, job.aggregate_id,
            sentinelflow.analysis_sha256(convert_to('input_too_large', 'UTF8')),
            'rejected', server_now
        );
        status := 'no_call';
        snapshot := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT result.status, result.snapshot INTO base_status, base_snapshot
    FROM sentinelflow.prepare_analysis_attempt_pre_000017(
        p_job_id, p_lease_token
    ) result;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF base_status = 'prepared' THEN
        SELECT * INTO claim
        FROM sentinelflow.analysis_attempt_claims current_claim
        WHERE current_claim.job_id = job.job_id
          AND current_claim.state = 'started'
          AND current_claim.incident_version = job.aggregate_version
        FOR UPDATE;
        IF NOT FOUND OR
           (base_snapshot->>'incident_version')::integer <> job.aggregate_version THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'prepared analysis claim mismatch';
        END IF;
        lifecycle_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
            claim.incident_id, claim.incident_version, 'analyzing',
            'analyzing', NULL, claim.analysis_id
        );
        UPDATE sentinelflow.analysis_attempt_claims
        SET analyzing_incident_version = lifecycle_version
        WHERE analysis_id = claim.analysis_id;
    ELSIF base_status = 'no_call' THEN
        SELECT * INTO claim
        FROM sentinelflow.analysis_attempt_claims current_claim
        WHERE current_claim.job_id = job.job_id
          AND current_claim.state = 'no_call'
          AND current_claim.incident_version = job.aggregate_version
        FOR UPDATE;
        IF NOT FOUND AND EXISTS (
            SELECT 1 FROM sentinelflow.outbox_jobs current_job
            WHERE current_job.job_id = job.job_id
              AND current_job.state = 'dead'
              AND current_job.last_error_code = 'analysis_incident_missing'
        ) THEN
            -- A job whose aggregate never existed has no incident lifecycle to
            -- advance. The preserved function already dead-lettered it.
            NULL;
        ELSIF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'no-call analysis claim mismatch';
        ELSE
            lifecycle_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
                claim.incident_id, claim.incident_version, 'analysis_failed',
                'analysis_failed', (
                    SELECT incident.analysis_failure_reason
                    FROM sentinelflow.incidents incident
                    WHERE incident.incident_id = claim.incident_id
                      AND incident.version = claim.incident_version
                ), claim.analysis_id
            );
            UPDATE sentinelflow.analysis_attempt_claims
            SET terminal_incident_version = lifecycle_version
            WHERE analysis_id = claim.analysis_id;
        END IF;
    ELSIF base_status NOT IN ('interrupted', 'terminal') THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'unknown analysis prepare status';
    END IF;

    status := base_status;
    snapshot := base_snapshot;
    RETURN NEXT;
END
$function$;

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
    base_job_id uuid;
    base_state text;
    claim sentinelflow.analysis_attempt_claims%ROWTYPE;
    result sentinelflow.analysis_attempt_results%ROWTYPE;
    target_state text;
    failure_reason text;
    lifecycle_version integer;
BEGIN
    SELECT finished.job_id, finished.state INTO base_job_id, base_state
    FROM sentinelflow.finalize_analysis_attempt_lifecycle_000017(
        p_job_id, p_lease_token, p_finish_state, p_retry_at,
        p_client_now, p_error_code, p_error_digest, p_mutation
    ) finished;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT * INTO claim
    FROM sentinelflow.analysis_attempt_claims current_claim
    WHERE current_claim.job_id = base_job_id
    FOR UPDATE;
    IF FOUND AND claim.state IN ('succeeded', 'failed', 'interrupted') AND
       claim.terminal_incident_version IS NULL THEN
        IF claim.analyzing_incident_version IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'terminal analysis lacks analyzing fence';
        END IF;
        IF claim.state = 'succeeded' THEN
            target_state := 'review_ready';
            failure_reason := NULL;
        ELSE
            target_state := 'analysis_failed';
            SELECT * INTO result
            FROM sentinelflow.analysis_attempt_results current_result
            WHERE current_result.analysis_id = claim.analysis_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'terminal analysis result missing';
            END IF;
            failure_reason := CASE
                WHEN claim.state = 'interrupted' THEN 'incomplete'
                ELSE result.failure_reason
            END;
        END IF;
        lifecycle_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
            claim.incident_id, claim.analyzing_incident_version,
            target_state, target_state, failure_reason, claim.analysis_id
        );
        UPDATE sentinelflow.analysis_attempt_claims
        SET terminal_incident_version = lifecycle_version
        WHERE analysis_id = claim.analysis_id;
    ELSIF FOUND AND claim.state = 'started' AND base_state IN ('completed', 'dead') THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'analysis finalizer left a nonterminal claim';
    END IF;

    job_id := base_job_id;
    state := base_state;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt_pre_000017(
    uuid, uuid
) FROM PUBLIC, sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_analysis_attempt_pre_000017(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) FROM PUBLIC, sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_analysis_attempt_lifecycle_000017(
    uuid, uuid, text, timestamptz, timestamptz, text, text, jsonb
) FROM PUBLIC, sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.advance_analysis_incident_lifecycle_000017(
    uuid, integer, text, text, text, uuid
) FROM PUBLIC, sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.interrupt_analysis_for_new_evidence_000017(
    uuid, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.interrupt_analysis_for_new_evidence_000017(
    uuid, integer
) TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.enforce_analysis_claim_lifecycle_000017()
    FROM PUBLIC, sentinelflow_worker;

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

GRANT UPDATE (evidence_version) ON incidents TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (17, 'analysis_lifecycle_alignment')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
