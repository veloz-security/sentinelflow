BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- A nonzero floor remains durable evidence that retained notifications were
-- pruned. Downgrade must not silently erase either live rows or that history.
DO $sse_notification_downgrade_preflight$
DECLARE
    has_evidence boolean;
BEGIN
    IF to_regclass('sentinelflow.sse_notification_ledger') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM sentinelflow.sse_notification_ledger)'
        INTO has_evidence;
        IF has_evidence THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'cannot discard durable SSE notification evidence';
        END IF;
    END IF;
    IF to_regclass('sentinelflow.sse_notification_replay_state') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (
            SELECT 1 FROM sentinelflow.sse_notification_replay_state
            WHERE replay_floor <> 0 OR watermark <> 0
        )' INTO has_evidence;
        IF has_evidence THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'cannot discard durable SSE notification evidence';
        END IF;
    END IF;
END
$sse_notification_downgrade_preflight$;

DROP TRIGGER IF EXISTS incidents_emit_sse_notification ON sentinelflow.incidents;
DROP TRIGGER IF EXISTS analyses_emit_sse_notification ON sentinelflow.ai_analyses;
DROP TRIGGER IF EXISTS policies_emit_sse_notification ON sentinelflow.policy_proposals;
DROP TRIGGER IF EXISTS approvals_emit_sse_notification ON sentinelflow.approval_decisions;
DROP TRIGGER IF EXISTS enforcement_emit_sse_notification ON sentinelflow.enforcement_actions;
DROP TRIGGER IF EXISTS source_health_emit_sse_notification ON sentinelflow.source_health_intervals;
DROP TRIGGER IF EXISTS sse_notification_ledger_append_only
    ON sentinelflow.sse_notification_ledger;

DROP FUNCTION IF EXISTS sentinelflow.prune_sse_notification_ledger(timestamptz, integer);
DROP FUNCTION IF EXISTS sentinelflow.read_sse_notification_page(bigint, integer);
DROP FUNCTION IF EXISTS sentinelflow.read_sse_notification_window();
DROP FUNCTION IF EXISTS sentinelflow.emit_sse_notification_from_domain();
DROP FUNCTION IF EXISTS sentinelflow.append_sse_notification(
    text, text, uuid, bigint, text, text, uuid, uuid
);
DROP FUNCTION IF EXISTS sentinelflow.sse_notification_ledger_append_only();

DROP TABLE IF EXISTS sentinelflow.sse_notification_ledger;
DROP TABLE IF EXISTS sentinelflow.sse_notification_replay_state;
DROP SEQUENCE IF EXISTS sentinelflow.sse_notification_cursor_seq;

DELETE FROM sentinelflow.schema_migrations
WHERE version = 13 AND name = 'sse_notification_ledger';

COMMIT;
