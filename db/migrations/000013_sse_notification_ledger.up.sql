BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

CREATE SEQUENCE IF NOT EXISTS sentinelflow.sse_notification_cursor_seq
    AS bigint MINVALUE 1 NO MAXVALUE NO CYCLE;

CREATE TABLE IF NOT EXISTS sentinelflow.sse_notification_replay_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    replay_floor bigint NOT NULL DEFAULT 0 CHECK (replay_floor >= 0),
    watermark bigint NOT NULL DEFAULT 0 CHECK (watermark >= replay_floor),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO sentinelflow.sse_notification_replay_state (
    singleton, replay_floor, watermark
) VALUES (true, 0, 0)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS sentinelflow.sse_notification_ledger (
    cursor bigint PRIMARY KEY CHECK (cursor >= 1),
    event_type text NOT NULL CHECK (event_type IN (
        'incident.created', 'incident.updated',
        'analysis.completed', 'analysis.failed',
        'policy.validation_updated', 'approval.recorded',
        'enforcement.updated', 'source.degraded', 'source.recovered'
    )),
    resource_type text NOT NULL CHECK (resource_type IN (
        'incident', 'analysis', 'policy', 'enforcement_action', 'source_health'
    )),
    resource_id uuid NOT NULL,
    resource_version bigint NOT NULL CHECK (resource_version >= 1),
    state text NOT NULL CHECK (state IN (
        'open', 'analyzing', 'review_ready', 'analysis_failed', 'closed',
        'succeeded', 'failed', 'validating', 'valid', 'invalid', 'stale',
        'approved', 'rejected', 'queued', 'active', 'expired', 'revoked',
        'indeterminate', 'degraded', 'lost', 'recovered'
    )),
    summary_code text NOT NULL CHECK (summary_code IN (
        'incident_created', 'incident_updated',
        'analysis_completed', 'analysis_failed',
        'policy_validation_updated', 'approval_recorded',
        'enforcement_updated', 'source_degraded', 'source_recovered'
    )),
    incident_id uuid NULL,
    trace_id uuid NULL,
    occurred_at timestamptz NOT NULL,
    CONSTRAINT sse_notification_event_shape CHECK (
        (event_type = 'incident.created' AND resource_type = 'incident' AND
            state IN ('open', 'analyzing', 'review_ready', 'analysis_failed', 'closed') AND
            summary_code = 'incident_created') OR
        (event_type = 'incident.updated' AND resource_type = 'incident' AND
            state IN ('open', 'analyzing', 'review_ready', 'analysis_failed', 'closed') AND
            summary_code = 'incident_updated') OR
        (event_type = 'analysis.completed' AND resource_type = 'analysis' AND
            state = 'succeeded' AND summary_code = 'analysis_completed') OR
        (event_type = 'analysis.failed' AND resource_type = 'analysis' AND
            state = 'failed' AND summary_code = 'analysis_failed') OR
        (event_type = 'policy.validation_updated' AND resource_type = 'policy' AND
            state IN ('validating', 'valid', 'invalid', 'stale') AND
            summary_code = 'policy_validation_updated') OR
        (event_type = 'approval.recorded' AND
            resource_type IN ('policy', 'enforcement_action') AND
            state IN ('approved', 'rejected', 'revoked') AND
            summary_code = 'approval_recorded') OR
        (event_type = 'enforcement.updated' AND resource_type = 'enforcement_action' AND
            state IN ('approved', 'queued', 'active', 'expired', 'failed', 'revoked', 'indeterminate') AND
            summary_code = 'enforcement_updated') OR
        (event_type = 'source.degraded' AND resource_type = 'source_health' AND
            state IN ('degraded', 'lost') AND summary_code = 'source_degraded') OR
        (event_type = 'source.recovered' AND resource_type = 'source_health' AND
            state = 'recovered' AND summary_code = 'source_recovered')
    ),
    CONSTRAINT sse_notification_incident_shape CHECK (
        (resource_type = 'incident' AND incident_id = resource_id) OR
        (resource_type = 'source_health' AND incident_id IS NULL) OR
        (resource_type IN ('analysis', 'policy', 'enforcement_action') AND
            incident_id IS NOT NULL)
    ),
    UNIQUE (event_type, resource_id, resource_version, state)
);

CREATE INDEX IF NOT EXISTS sse_notification_ledger_occurred_idx
    ON sentinelflow.sse_notification_ledger (occurred_at, cursor);
CREATE INDEX IF NOT EXISTS sse_notification_ledger_resource_idx
    ON sentinelflow.sse_notification_ledger (
        resource_type, resource_id, resource_version, cursor
    );

CREATE OR REPLACE FUNCTION sentinelflow.sse_notification_ledger_append_only()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    -- The marker is transaction-local and is set only by the bounded cleanup
    -- function below. Runtime roles still have no DELETE privilege, so setting
    -- a custom GUC cannot create a direct mutation path.
    IF TG_OP = 'DELETE' AND
       current_setting('sentinelflow.sse_notification_prune', true) = '000013-prune-v1' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'sse notification ledger is append-only';
END
$function$;

DROP TRIGGER IF EXISTS sse_notification_ledger_append_only
    ON sentinelflow.sse_notification_ledger;
CREATE TRIGGER sse_notification_ledger_append_only
BEFORE UPDATE OR DELETE ON sentinelflow.sse_notification_ledger
FOR EACH ROW EXECUTE FUNCTION sentinelflow.sse_notification_ledger_append_only();

-- Owner-only append primitive. The replay-state row serializes cursor
-- allocation, so a committed higher cursor can never become visible before a
-- lower in-flight cursor. Sequence gaps caused by rollback remain valid.
CREATE OR REPLACE FUNCTION sentinelflow.append_sse_notification(
    p_event_type text,
    p_resource_type text,
    p_resource_id uuid,
    p_resource_version bigint,
    p_state text,
    p_summary_code text,
    p_incident_id uuid,
    p_trace_id uuid
)
RETURNS TABLE (cursor bigint, occurred_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    replay_state sentinelflow.sse_notification_replay_state%ROWTYPE;
    next_cursor bigint;
    server_now timestamptz;
BEGIN
    IF p_event_type IS NULL OR p_resource_type IS NULL OR p_resource_id IS NULL OR
       p_resource_version IS NULL OR p_resource_version < 1 OR p_state IS NULL OR
       p_summary_code IS NULL OR
       NOT (
           (p_event_type = 'incident.created' AND p_resource_type = 'incident' AND
               p_state IN ('open', 'analyzing', 'review_ready', 'analysis_failed', 'closed') AND
               p_summary_code = 'incident_created') OR
           (p_event_type = 'incident.updated' AND p_resource_type = 'incident' AND
               p_state IN ('open', 'analyzing', 'review_ready', 'analysis_failed', 'closed') AND
               p_summary_code = 'incident_updated') OR
           (p_event_type = 'analysis.completed' AND p_resource_type = 'analysis' AND
               p_state = 'succeeded' AND p_summary_code = 'analysis_completed') OR
           (p_event_type = 'analysis.failed' AND p_resource_type = 'analysis' AND
               p_state = 'failed' AND p_summary_code = 'analysis_failed') OR
           (p_event_type = 'policy.validation_updated' AND p_resource_type = 'policy' AND
               p_state IN ('validating', 'valid', 'invalid', 'stale') AND
               p_summary_code = 'policy_validation_updated') OR
           (p_event_type = 'approval.recorded' AND
               p_resource_type IN ('policy', 'enforcement_action') AND
               p_state IN ('approved', 'rejected', 'revoked') AND
               p_summary_code = 'approval_recorded') OR
           (p_event_type = 'enforcement.updated' AND p_resource_type = 'enforcement_action' AND
               p_state IN ('approved', 'queued', 'active', 'expired', 'failed', 'revoked', 'indeterminate') AND
               p_summary_code = 'enforcement_updated') OR
           (p_event_type = 'source.degraded' AND p_resource_type = 'source_health' AND
               p_state IN ('degraded', 'lost') AND p_summary_code = 'source_degraded') OR
           (p_event_type = 'source.recovered' AND p_resource_type = 'source_health' AND
               p_state = 'recovered' AND p_summary_code = 'source_recovered')
       ) OR
       NOT (
           (p_resource_type = 'incident' AND p_incident_id = p_resource_id) OR
           (p_resource_type = 'source_health' AND p_incident_id IS NULL) OR
           (p_resource_type IN ('analysis', 'policy', 'enforcement_action') AND
               p_incident_id IS NOT NULL)
       ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF201', MESSAGE = 'invalid_notification';
    END IF;

    SELECT * INTO replay_state
    FROM sentinelflow.sse_notification_replay_state current_state
    WHERE current_state.singleton
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF202', MESSAGE = 'notification_state_missing';
    END IF;

    next_cursor := nextval('sentinelflow.sse_notification_cursor_seq'::regclass);
    server_now := clock_timestamp();
    INSERT INTO sentinelflow.sse_notification_ledger (
        cursor, event_type, resource_type, resource_id, resource_version,
        state, summary_code, incident_id, trace_id, occurred_at
    ) VALUES (
        next_cursor, p_event_type, p_resource_type, p_resource_id,
        p_resource_version, p_state, p_summary_code, p_incident_id,
        p_trace_id, server_now
    );
    UPDATE sentinelflow.sse_notification_replay_state
    SET watermark = next_cursor, updated_at = server_now
    WHERE singleton;
    RETURN QUERY SELECT next_cursor, server_now;
END
$function$;

-- Domain triggers are the only production append callers. They run in the
-- producer's existing transaction, preserving rollback and eliminating an
-- independent notification command channel.
CREATE OR REPLACE FUNCTION sentinelflow.emit_sse_notification_from_domain()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    linked_incident_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'incidents' THEN
        IF TG_OP = 'INSERT' THEN
            PERFORM sentinelflow.append_sse_notification(
                'incident.created', 'incident', NEW.incident_id, NEW.version,
                NEW.state, 'incident_created', NEW.incident_id, NULL
            );
        ELSIF NEW.state IS DISTINCT FROM OLD.state OR NEW.version IS DISTINCT FROM OLD.version THEN
            PERFORM sentinelflow.append_sse_notification(
                'incident.updated', 'incident', NEW.incident_id, NEW.version,
                NEW.state, 'incident_updated', NEW.incident_id, NULL
            );
        END IF;
    ELSIF TG_TABLE_NAME = 'ai_analyses' THEN
        IF NEW.result_state IN ('succeeded', 'failed') AND
           (TG_OP = 'INSERT' OR NEW.result_state IS DISTINCT FROM OLD.result_state) THEN
            PERFORM sentinelflow.append_sse_notification(
                CASE NEW.result_state WHEN 'succeeded' THEN 'analysis.completed' ELSE 'analysis.failed' END,
                'analysis', NEW.analysis_id, NEW.attempt, NEW.result_state,
                CASE NEW.result_state WHEN 'succeeded' THEN 'analysis_completed' ELSE 'analysis_failed' END,
                NEW.incident_id, NULL
            );
        END IF;
    ELSIF TG_TABLE_NAME = 'policy_proposals' THEN
        IF NEW.state IN ('validating', 'valid', 'invalid', 'stale') AND
           (TG_OP = 'INSERT' OR NEW.state IS DISTINCT FROM OLD.state OR
            NEW.state_revision IS DISTINCT FROM OLD.state_revision) THEN
            PERFORM sentinelflow.append_sse_notification(
                'policy.validation_updated', 'policy', NEW.policy_id,
                NEW.state_revision, NEW.state, 'policy_validation_updated',
                NEW.incident_id, NULL
            );
        END IF;
    ELSIF TG_TABLE_NAME = 'approval_decisions' THEN
        SELECT policy.incident_id INTO linked_incident_id
        FROM sentinelflow.policy_proposals policy
        WHERE policy.policy_id = NEW.policy_id AND policy.version = NEW.policy_version;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'SF202', MESSAGE = 'notification_resource_missing';
        END IF;
        PERFORM sentinelflow.append_sse_notification(
            'approval.recorded', NEW.resource_type, NEW.resource_id,
            NEW.resource_version, NEW.decision, 'approval_recorded',
            linked_incident_id, NULL
        );
    ELSIF TG_TABLE_NAME = 'enforcement_actions' THEN
        IF TG_OP = 'INSERT' OR NEW.state IS DISTINCT FROM OLD.state OR
           NEW.version IS DISTINCT FROM OLD.version THEN
            SELECT policy.incident_id INTO linked_incident_id
            FROM sentinelflow.policy_proposals policy
            WHERE policy.policy_id = NEW.policy_id AND policy.version = NEW.policy_version;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = 'SF202', MESSAGE = 'notification_resource_missing';
            END IF;
            PERFORM sentinelflow.append_sse_notification(
                'enforcement.updated', 'enforcement_action', NEW.action_id,
                NEW.version, NEW.state, 'enforcement_updated',
                linked_incident_id, NULL
            );
        END IF;
    ELSIF TG_TABLE_NAME = 'source_health_intervals' THEN
        PERFORM sentinelflow.append_sse_notification(
            CASE NEW.state WHEN 'recovered' THEN 'source.recovered' ELSE 'source.degraded' END,
            'source_health', NEW.event_id, 1, NEW.state,
            CASE NEW.state WHEN 'recovered' THEN 'source_recovered' ELSE 'source_degraded' END,
            NULL, NULL
        );
    ELSE
        RAISE EXCEPTION USING ERRCODE = 'SF201', MESSAGE = 'invalid_notification_source';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS incidents_emit_sse_notification ON sentinelflow.incidents;
CREATE TRIGGER incidents_emit_sse_notification
AFTER INSERT OR UPDATE OF state, version ON sentinelflow.incidents
FOR EACH ROW EXECUTE FUNCTION sentinelflow.emit_sse_notification_from_domain();

DROP TRIGGER IF EXISTS analyses_emit_sse_notification ON sentinelflow.ai_analyses;
CREATE TRIGGER analyses_emit_sse_notification
AFTER INSERT OR UPDATE OF result_state ON sentinelflow.ai_analyses
FOR EACH ROW EXECUTE FUNCTION sentinelflow.emit_sse_notification_from_domain();

DROP TRIGGER IF EXISTS policies_emit_sse_notification ON sentinelflow.policy_proposals;
CREATE TRIGGER policies_emit_sse_notification
AFTER INSERT OR UPDATE OF state, state_revision ON sentinelflow.policy_proposals
FOR EACH ROW EXECUTE FUNCTION sentinelflow.emit_sse_notification_from_domain();

DROP TRIGGER IF EXISTS approvals_emit_sse_notification ON sentinelflow.approval_decisions;
CREATE TRIGGER approvals_emit_sse_notification
AFTER INSERT ON sentinelflow.approval_decisions
FOR EACH ROW EXECUTE FUNCTION sentinelflow.emit_sse_notification_from_domain();

DROP TRIGGER IF EXISTS enforcement_emit_sse_notification ON sentinelflow.enforcement_actions;
CREATE TRIGGER enforcement_emit_sse_notification
AFTER INSERT OR UPDATE OF state, version ON sentinelflow.enforcement_actions
FOR EACH ROW EXECUTE FUNCTION sentinelflow.emit_sse_notification_from_domain();

DROP TRIGGER IF EXISTS source_health_emit_sse_notification ON sentinelflow.source_health_intervals;
CREATE TRIGGER source_health_emit_sse_notification
AFTER INSERT ON sentinelflow.source_health_intervals
FOR EACH ROW EXECUTE FUNCTION sentinelflow.emit_sse_notification_from_domain();

CREATE OR REPLACE FUNCTION sentinelflow.read_sse_notification_window()
RETURNS TABLE (replay_floor bigint, watermark bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    replay_state sentinelflow.sse_notification_replay_state%ROWTYPE;
BEGIN
    SELECT * INTO replay_state
    FROM sentinelflow.sse_notification_replay_state current_state
    WHERE current_state.singleton
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF202', MESSAGE = 'notification_state_missing';
    END IF;
    RETURN QUERY SELECT replay_state.replay_floor, replay_state.watermark;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.read_sse_notification_page(
    p_after bigint,
    p_limit integer
)
RETURNS TABLE (
    replay_floor bigint,
    watermark bigint,
    replay_gap boolean,
    future_cursor boolean,
    cursor bigint,
    event_type text,
    resource_type text,
    resource_id uuid,
    resource_version bigint,
    state text,
    summary_code text,
    incident_id uuid,
    trace_id uuid,
    occurred_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    replay_state sentinelflow.sse_notification_replay_state%ROWTYPE;
BEGIN
    IF p_after IS NULL OR p_after < 0 OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION USING ERRCODE = 'SF201', MESSAGE = 'invalid_notification_page';
    END IF;
    SELECT * INTO replay_state
    FROM sentinelflow.sse_notification_replay_state current_state
    WHERE current_state.singleton
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF202', MESSAGE = 'notification_state_missing';
    END IF;

    RETURN QUERY
    SELECT replay_state.replay_floor, replay_state.watermark,
           p_after < replay_state.replay_floor,
           p_after > replay_state.watermark,
           event.cursor, event.event_type, event.resource_type,
           event.resource_id, event.resource_version, event.state,
           event.summary_code, event.incident_id, event.trace_id,
           event.occurred_at
    FROM (SELECT 1) anchor
    LEFT JOIN LATERAL (
        SELECT ledger.*
        FROM sentinelflow.sse_notification_ledger ledger
        WHERE p_after >= replay_state.replay_floor
          AND p_after <= replay_state.watermark
          AND ledger.cursor > p_after
          AND ledger.cursor <= replay_state.watermark
        ORDER BY ledger.cursor ASC
        LIMIT p_limit
    ) event ON true;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.prune_sse_notification_ledger(
    p_before timestamptz,
    p_max_rows integer
)
RETURNS TABLE (pruned_count integer, replay_floor bigint, watermark bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    replay_state sentinelflow.sse_notification_replay_state%ROWTYPE;
    server_now timestamptz;
    deleted_count integer := 0;
    deleted_through bigint;
BEGIN
    server_now := clock_timestamp();
    IF p_before IS NULL OR NOT isfinite(p_before) OR p_before > server_now OR
       p_max_rows IS NULL OR p_max_rows NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = 'SF201', MESSAGE = 'invalid_notification_prune';
    END IF;
    SELECT * INTO replay_state
    FROM sentinelflow.sse_notification_replay_state current_state
    WHERE current_state.singleton
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'SF202', MESSAGE = 'notification_state_missing';
    END IF;

    PERFORM set_config(
        'sentinelflow.sse_notification_prune',
        '000013-prune-v1',
        true
    );

    WITH ordered AS (
        SELECT ledger.cursor,
               bool_and(ledger.occurred_at < p_before) OVER (
                   ORDER BY ledger.cursor ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
               ) AS expired_prefix
        FROM sentinelflow.sse_notification_ledger ledger
        WHERE ledger.cursor > replay_state.replay_floor
          AND ledger.cursor <= replay_state.watermark
    ), targets AS (
        SELECT ordered.cursor
        FROM ordered
        WHERE ordered.expired_prefix
        ORDER BY ordered.cursor
        LIMIT p_max_rows
    ), deleted AS (
        DELETE FROM sentinelflow.sse_notification_ledger ledger
        USING targets
        WHERE ledger.cursor = targets.cursor
        RETURNING ledger.cursor
    )
    SELECT count(*)::integer, max(cursor)
    INTO deleted_count, deleted_through
    FROM deleted;

    PERFORM set_config('sentinelflow.sse_notification_prune', '', true);

    IF deleted_count > 0 THEN
        UPDATE sentinelflow.sse_notification_replay_state
        SET replay_floor = deleted_through, updated_at = server_now
        WHERE singleton;
        replay_state.replay_floor := deleted_through;
    END IF;
    RETURN QUERY SELECT deleted_count, replay_state.replay_floor, replay_state.watermark;
END
$function$;

REVOKE ALL ON TABLE sentinelflow.sse_notification_ledger,
    sentinelflow.sse_notification_replay_state
FROM PUBLIC, sentinelflow_api, sentinelflow_worker,
     sentinelflow_read, sentinelflow_dispatcher;
REVOKE ALL ON SEQUENCE sentinelflow.sse_notification_cursor_seq
FROM PUBLIC, sentinelflow_api, sentinelflow_worker,
     sentinelflow_read, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.sse_notification_ledger_append_only(),
    sentinelflow.append_sse_notification(text, text, uuid, bigint, text, text, uuid, uuid),
    sentinelflow.emit_sse_notification_from_domain(),
    sentinelflow.read_sse_notification_window(),
    sentinelflow.read_sse_notification_page(bigint, integer),
    sentinelflow.prune_sse_notification_ledger(timestamptz, integer)
FROM PUBLIC, sentinelflow_api, sentinelflow_worker,
     sentinelflow_read, sentinelflow_dispatcher;

GRANT EXECUTE ON FUNCTION sentinelflow.read_sse_notification_window(),
    sentinelflow.read_sse_notification_page(bigint, integer)
TO sentinelflow_api;
GRANT EXECUTE ON FUNCTION sentinelflow.prune_sse_notification_ledger(timestamptz, integer)
TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (13, 'sse_notification_ledger')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
