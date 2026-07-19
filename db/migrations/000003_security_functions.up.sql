BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

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

DO $audit_trigger$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = 'sentinelflow.audit_events'::regclass
          AND tgname = 'audit_events_append_only'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON sentinelflow.audit_events
        FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_audit_mutation();
    END IF;
END
$audit_trigger$;

CREATE OR REPLACE FUNCTION sentinelflow.append_audit_event(
    p_event_id uuid,
    p_actor_type text,
    p_actor_id sentinelflow.ascii_id,
    p_action sentinelflow.ascii_id,
    p_object_type sentinelflow.ascii_id,
    p_object_id uuid,
    p_incident_id uuid,
    p_policy_id uuid,
    p_policy_version integer,
    p_enforcement_action_id uuid,
    p_trace_id uuid,
    p_primary_digest sentinelflow.sha256_digest,
    p_secondary_digest sentinelflow.sha256_digest,
    p_outcome text,
    p_occurred_at timestamptz
)
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        incident_id, policy_id, policy_version, enforcement_action_id,
        trace_id, primary_digest, secondary_digest, outcome, occurred_at
    ) VALUES (
        p_event_id, p_actor_type, p_actor_id, p_action, p_object_type, p_object_id,
        p_incident_id, p_policy_id, p_policy_version, p_enforcement_action_id,
        p_trace_id, p_primary_digest, p_secondary_digest, p_outcome, p_occurred_at
    )
    RETURNING sequence;
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.require_auth_binding_match()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF OLD.binding_state <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'authentication-event binding is terminal';
    END IF;
    IF NEW.binding_state = 'verified' AND NOT EXISTS (
        SELECT 1
        FROM sentinelflow.gateway_events gateway_event
        WHERE gateway_event.event_id = NEW.bound_gateway_event_id
          AND gateway_event.request_id = NEW.gateway_request_id
          AND gateway_event.trace_id = NEW.trace_id
          AND gateway_event.source_ip = NEW.source_ip
          AND gateway_event.service_label = NEW.service_label
          AND gateway_event.route_label = NEW.route_label
          AND NEW.occurred_at <= NEW.binding_deadline
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'verified authentication event does not match gateway evidence';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS auth_events_require_binding_match
    ON sentinelflow.auth_events;
CREATE TRIGGER auth_events_require_binding_match
BEFORE UPDATE OF binding_state, binding_reason, bound_gateway_event_id
ON sentinelflow.auth_events
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_auth_binding_match();

CREATE OR REPLACE FUNCTION sentinelflow.prune_ingest_replay_nonces(
    p_now timestamptz,
    p_limit integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    deleted_count integer;
BEGIN
    IF p_now IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'replay nonce cleanup limit must be between 1 and 1000';
    END IF;

    WITH expired AS MATERIALIZED (
        SELECT replay.ctid
        FROM sentinelflow.ingest_replay_nonces replay
        WHERE replay.expires_at <= p_now
        ORDER BY replay.expires_at, replay.sender_id,
            replay.endpoint_path, replay.nonce_digest
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM sentinelflow.ingest_replay_nonces replay
        USING expired
        WHERE replay.ctid = expired.ctid
        RETURNING 1
    )
    SELECT count(*)::integer
    INTO deleted_count
    FROM deleted;

    RETURN deleted_count;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.require_sender_checkpoint_progress()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.last_acknowledged_sequence <> 0 OR
           NEW.last_acknowledged_body_digest IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'a sender checkpoint must begin before sequence 1';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.sender_id <> OLD.sender_id OR NEW.endpoint_kind <> OLD.endpoint_kind THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'sender checkpoint identity is immutable';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sender checkpoint time cannot move backwards';
    END IF;
    IF NEW.sender_epoch = OLD.sender_epoch THEN
        IF NEW.last_acknowledged_sequence < OLD.last_acknowledged_sequence THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'sender sequence cannot move backwards within an epoch';
        END IF;
        IF NEW.last_acknowledged_sequence = OLD.last_acknowledged_sequence AND
           NEW.last_acknowledged_body_digest IS DISTINCT FROM
               OLD.last_acknowledged_body_digest THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'an acknowledged sequence cannot change its body digest';
        END IF;
    ELSIF NEW.last_acknowledged_sequence < 1 OR
          NEW.last_acknowledged_body_digest IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'a new sender epoch must acknowledge a positive sequence';
    END IF;

    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS sender_checkpoints_require_progress
    ON sentinelflow.sender_checkpoints;
CREATE TRIGGER sender_checkpoints_require_progress
BEFORE INSERT OR UPDATE ON sentinelflow.sender_checkpoints
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_sender_checkpoint_progress();

CREATE OR REPLACE FUNCTION sentinelflow.require_atomic_ingest_checkpoint()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    previous_sequence bigint;
    gap_start bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.sender_checkpoints checkpoint
        WHERE checkpoint.sender_id = NEW.sender_id
          AND checkpoint.endpoint_kind = NEW.endpoint_kind
          AND checkpoint.sender_epoch = NEW.sender_epoch
          AND checkpoint.last_acknowledged_sequence = NEW.sequence
          AND checkpoint.last_acknowledged_body_digest = NEW.raw_body_digest
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'accepted ingest batch requires an exact atomic sender checkpoint';
    END IF;

    SELECT max(batch.sequence)
    INTO previous_sequence
    FROM sentinelflow.ingest_batches batch
    WHERE batch.sender_id = NEW.sender_id
      AND batch.sender_epoch = NEW.sender_epoch
      AND batch.endpoint_kind = NEW.endpoint_kind
      AND batch.sequence < NEW.sequence;

    gap_start := coalesce(previous_sequence, 0) + 1;
    IF NEW.sequence > gap_start AND NOT EXISTS (
        SELECT 1
        FROM sentinelflow.source_health_intervals health
        WHERE health.sender_id = NEW.sender_id
          AND health.sender_epoch = NEW.sender_epoch
          AND health.batch_id = NEW.batch_id
          AND health.source_id = NEW.sender_id
          AND health.cause = 'sequence_gap'
          AND health.state IN ('degraded', 'lost')
          AND health.affected_sender_epoch = NEW.sender_epoch
          AND health.sequence_start = gap_start
          AND health.sequence_end = NEW.sequence - 1
          AND health.dropped_count = NEW.sequence - gap_start
          AND health.detail_code = 'known_range'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sequence gap requires exact source-health coverage in the same batch';
    END IF;

    RETURN NULL;
END
$function$;

DROP TRIGGER IF EXISTS ingest_batches_require_atomic_checkpoint
    ON sentinelflow.ingest_batches;
CREATE CONSTRAINT TRIGGER ingest_batches_require_atomic_checkpoint
AFTER INSERT ON sentinelflow.ingest_batches
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_atomic_ingest_checkpoint();

CREATE OR REPLACE FUNCTION sentinelflow.enforce_policy_state_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    evidence_reference_change_allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'draft' OR NEW.state_revision <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'a policy artifact must begin in draft at state revision 1';
        END IF;
        RETURN NEW;
    END IF;

    evidence_reference_change_allowed :=
        NEW.evidence_snapshot_id IS NOT DISTINCT FROM OLD.evidence_snapshot_id OR
        (
            OLD.evidence_snapshot_id IS NOT NULL AND
            NEW.evidence_snapshot_id IS NULL AND
            NOT EXISTS (
                SELECT 1
                FROM sentinelflow.evidence_snapshots evidence
                WHERE evidence.evidence_snapshot_id = OLD.evidence_snapshot_id
            )
        );

    IF NOT evidence_reference_change_allowed OR
       (to_jsonb(NEW) - 'state' - 'state_revision' - 'updated_at' - 'evidence_snapshot_id') <>
       (to_jsonb(OLD) - 'state' - 'state_revision' - 'updated_at' - 'evidence_snapshot_id') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'policy artifact fields are immutable';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy update time cannot move backwards';
    END IF;

    IF NEW.state = OLD.state THEN
        IF NEW.state_revision <> OLD.state_revision THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'an idempotent policy state write cannot increment its revision';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.state_revision <> OLD.state_revision + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'a policy state transition must increment its revision exactly once';
    END IF;

    IF NOT (
        (OLD.state = 'draft' AND NEW.state IN ('validating', 'stale')) OR
        (OLD.state = 'validating' AND NEW.state IN ('valid', 'invalid', 'stale')) OR
        (OLD.state = 'valid' AND NEW.state IN ('approved', 'rejected', 'stale')) OR
        (OLD.state = 'approved' AND NEW.state IN ('queued', 'stale')) OR
        (OLD.state = 'queued' AND NEW.state IN (
            'active', 'failed', 'indeterminate', 'stale'
        )) OR
        (OLD.state = 'active' AND NEW.state IN (
            'expired', 'failed', 'revoked', 'indeterminate'
        )) OR
        (OLD.state = 'indeterminate' AND NEW.state IN (
            'active', 'expired', 'failed', 'revoked'
        ))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy state transition is not allowed';
    END IF;

    IF NEW.state = 'valid' AND NOT EXISTS (
        SELECT 1
        FROM sentinelflow.validation_snapshots validation
        WHERE validation.policy_id = NEW.policy_id
          AND validation.policy_version = NEW.version
          AND validation.command_candidate_id = NEW.command_candidate_id
          AND validation.evidence_snapshot_digest = NEW.evidence_snapshot_digest
          AND validation.policy_digest = NEW.policy_digest
          AND validation.generated_candidate_digest = NEW.generated_artifact_digest
          AND validation.canonical_artifact_digest = NEW.canonical_artifact_digest
          AND validation.target_ipv4 = NEW.target_ipv4
          AND validation.ttl_seconds = NEW.ttl_seconds
          AND validation.state = 'valid'
          AND validation.valid_until >= NEW.updated_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'valid policy state requires a current exact validation snapshot';
    END IF;

    IF NEW.state IN ('approved', 'rejected') AND NOT EXISTS (
        SELECT 1
        FROM sentinelflow.approval_decisions decision
        JOIN sentinelflow.decision_challenges challenge
          ON challenge.challenge_id = decision.challenge_id
        JOIN sentinelflow.validation_snapshots validation
          ON validation.validation_snapshot_id = decision.validation_snapshot_id
        WHERE decision.policy_id = NEW.policy_id
          AND decision.policy_version = NEW.version
          AND decision.operation = CASE NEW.state
              WHEN 'approved' THEN 'approve'
              WHEN 'rejected' THEN 'reject'
          END
          AND decision.decision = NEW.state
          AND challenge.consumed_decision_id = decision.decision_id
          AND challenge.consumed_at IS NOT NULL
          AND decision.policy_digest = NEW.policy_digest
          AND decision.evidence_snapshot_digest = NEW.evidence_snapshot_digest
          AND decision.generated_artifact_digest = NEW.generated_artifact_digest
          AND decision.canonical_artifact_digest = NEW.canonical_artifact_digest
          AND decision.target_ipv4 = NEW.target_ipv4
          AND decision.decision_valid_until >= NEW.updated_at
          AND validation.state = 'valid'
          AND validation.valid_until >= NEW.updated_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'final policy decision requires an exact consumed HIL decision';
    END IF;

    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS policy_proposals_enforce_state_transition
    ON sentinelflow.policy_proposals;
CREATE TRIGGER policy_proposals_enforce_state_transition
BEFORE INSERT OR UPDATE ON sentinelflow.policy_proposals
FOR EACH ROW EXECUTE FUNCTION sentinelflow.enforce_policy_state_transition();

CREATE OR REPLACE FUNCTION sentinelflow.require_complete_validation_gates()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    gate_count integer;
    passed_count integer;
    ordered_count integer;
    evidence_reference_change_allowed boolean := false;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        evidence_reference_change_allowed :=
            NEW.evidence_snapshot_id IS NOT DISTINCT FROM OLD.evidence_snapshot_id OR
            (
                OLD.evidence_snapshot_id IS NOT NULL AND
                NEW.evidence_snapshot_id IS NULL AND
                NOT EXISTS (
                    SELECT 1
                    FROM sentinelflow.evidence_snapshots evidence
                    WHERE evidence.evidence_snapshot_id = OLD.evidence_snapshot_id
                )
            );
    END IF;
    IF NEW.state <> 'valid' THEN
        IF TG_OP = 'UPDATE' AND OLD.state = 'valid' THEN
            IF NEW.state = 'stale' AND
               evidence_reference_change_allowed AND
               (to_jsonb(NEW) - 'state' - 'evidence_snapshot_id') =
               (to_jsonb(OLD) - 'state' - 'evidence_snapshot_id') THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'valid validation snapshot is immutable except for stale transition';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.state = 'valid' THEN
        IF NOT evidence_reference_change_allowed OR
           (to_jsonb(NEW) - 'evidence_snapshot_id') <>
           (to_jsonb(OLD) - 'evidence_snapshot_id') THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'valid validation snapshot is immutable';
        END IF;
        RETURN NEW;
    END IF;

    SELECT count(*), count(*) FILTER (WHERE passed), count(*) FILTER (
        WHERE (gate_order, gate_name) IN (
            (1, 'structured_output'),
            (2, 'command_grammar'),
            (3, 'policy_evidence_command_consistency'),
            (4, 'protected_network'),
            (5, 'owned_schema_syntax'),
            (6, 'historical_impact')
        )
    )
    INTO gate_count, passed_count, ordered_count
    FROM sentinelflow.validation_gates
    WHERE validation_snapshot_id = NEW.validation_snapshot_id;

    IF gate_count <> 6 OR passed_count <> 6 OR ordered_count <> 6 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'valid validation snapshot requires all ordered gates';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS validation_snapshots_require_gates
    ON sentinelflow.validation_snapshots;
CREATE TRIGGER validation_snapshots_require_gates
BEFORE INSERT OR UPDATE ON sentinelflow.validation_snapshots
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_complete_validation_gates();

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

DROP TRIGGER IF EXISTS validation_gates_protect_valid_snapshot
    ON sentinelflow.validation_gates;
CREATE TRIGGER validation_gates_protect_valid_snapshot
BEFORE INSERT OR UPDATE OR DELETE ON sentinelflow.validation_gates
FOR EACH ROW EXECUTE FUNCTION sentinelflow.protect_valid_validation_gates();

CREATE OR REPLACE FUNCTION sentinelflow.require_hil_decision_match()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.decision_challenges challenge
        JOIN sentinelflow.admin_sessions admin_session
          ON admin_session.session_id = challenge.session_id
        JOIN sentinelflow.hil_reasons reason
          ON reason.reason_id = NEW.reason_id
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = NEW.policy_id
         AND policy.version = NEW.policy_version
        JOIN sentinelflow.validation_snapshots validation
          ON validation.validation_snapshot_id = NEW.validation_snapshot_id
        JOIN sentinelflow.evidence_snapshots evidence
          ON evidence.evidence_snapshot_id = validation.evidence_snapshot_id
        LEFT JOIN sentinelflow.enforcement_actions action
          ON action.action_id = NEW.action_id
        WHERE challenge.challenge_id = NEW.challenge_id
          AND challenge.consumed_at IS NULL
          AND challenge.session_digest = NEW.session_digest
          AND challenge.session_digest = admin_session.token_digest
          AND challenge.actor_id = NEW.actor_id
          AND challenge.authenticated_at = admin_session.authenticated_at
          AND admin_session.actor_id = NEW.actor_id
          AND admin_session.revoked_at IS NULL
          AND admin_session.expires_at >= NEW.decided_at
          AND challenge.operation = NEW.operation
          AND challenge.resource_type = NEW.resource_type
          AND challenge.resource_id = NEW.resource_id
          AND challenge.resource_version = NEW.resource_version
          AND challenge.policy_id = NEW.policy_id
          AND challenge.policy_version = NEW.policy_version
          AND challenge.action_id IS NOT DISTINCT FROM NEW.action_id
          AND challenge.target_ipv4 = NEW.target_ipv4
          AND challenge.policy_digest = NEW.policy_digest
          AND challenge.generated_artifact_digest = NEW.generated_artifact_digest
          AND challenge.canonical_artifact_digest = NEW.canonical_artifact_digest
          AND challenge.original_add_digest IS NOT DISTINCT FROM NEW.original_add_digest
          AND challenge.evidence_snapshot_digest = NEW.evidence_snapshot_digest
          AND challenge.validation_snapshot_digest = NEW.validation_snapshot_digest
          AND challenge.nonce_digest = NEW.challenge_nonce_digest
          AND NEW.decided_at >= challenge.issued_at
          AND NEW.decided_at <= challenge.expires_at
          AND reason.actor_id = NEW.actor_id
          AND reason.operation = NEW.operation
          AND reason.reason_digest = NEW.reason_digest
          AND policy.policy_digest = NEW.policy_digest
          AND policy.target_ipv4 = NEW.target_ipv4
          AND evidence.snapshot_digest = NEW.evidence_snapshot_digest
          AND validation.policy_id = NEW.policy_id
          AND validation.policy_version = NEW.policy_version
          AND validation.snapshot_digest = NEW.validation_snapshot_digest
          AND challenge.validation_valid_until = validation.valid_until
          AND (
              (NEW.operation IN ('approve', 'reject') AND
                  action.action_id IS NULL AND
                  policy.state = 'valid' AND
                  validation.state = 'valid' AND
                  validation.valid_until >= NEW.decision_valid_until AND
                  policy.generated_artifact_digest = NEW.generated_artifact_digest AND
                  policy.canonical_artifact_digest = NEW.canonical_artifact_digest) OR
              (NEW.operation = 'revoke' AND
                  action.action_id = NEW.action_id AND
                  action.version = NEW.resource_version AND
                  action.policy_id = NEW.policy_id AND
                  action.policy_version = NEW.policy_version AND
                  action.target_ipv4 = NEW.target_ipv4 AND
                  action.canonical_artifact_digest = NEW.original_add_digest)
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'HIL decision does not match its exact challenge and artifacts';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS approval_decisions_require_exact_challenge
    ON sentinelflow.approval_decisions;
CREATE TRIGGER approval_decisions_require_exact_challenge
BEFORE INSERT OR UPDATE ON sentinelflow.approval_decisions
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_hil_decision_match();

CREATE OR REPLACE FUNCTION sentinelflow.require_challenge_consumption_match()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF (to_jsonb(NEW) - 'consumed_at' - 'consumed_decision_id') <>
       (to_jsonb(OLD) - 'consumed_at' - 'consumed_decision_id') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'HIL challenge is immutable except for atomic consumption';
    END IF;
    IF OLD.consumed_at IS NOT NULL OR OLD.consumed_decision_id IS NOT NULL OR
       NEW.consumed_at IS NULL OR NEW.consumed_decision_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'HIL challenge consumption is single use';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.approval_decisions decision
        WHERE decision.decision_id = NEW.consumed_decision_id
          AND decision.challenge_id = NEW.challenge_id
          AND decision.decided_at <= NEW.consumed_at
          AND NEW.consumed_at <= NEW.expires_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'HIL challenge consumption does not match a recorded decision';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS decision_challenges_single_use
    ON sentinelflow.decision_challenges;
CREATE TRIGGER decision_challenges_single_use
BEFORE UPDATE ON sentinelflow.decision_challenges
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_challenge_consumption_match();

CREATE OR REPLACE FUNCTION sentinelflow.require_enforcement_authorization_match()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.approval_decisions decision
        JOIN sentinelflow.decision_challenges challenge
          ON challenge.challenge_id = decision.challenge_id
        WHERE decision.decision_id = NEW.approval_decision_id
          AND challenge.consumed_decision_id = decision.decision_id
          AND challenge.consumed_at IS NOT NULL
          AND decision.operation = CASE NEW.authorization_kind
              WHEN 'add' THEN 'approve'
              WHEN 'revoke' THEN 'revoke'
          END
          AND decision.policy_id = NEW.policy_id
          AND decision.policy_version = NEW.policy_version
          AND (NEW.authorization_kind = 'add' OR decision.action_id = NEW.action_id)
          AND decision.target_ipv4 = NEW.target_ipv4
          AND decision.policy_digest = NEW.policy_digest
          AND decision.generated_artifact_digest = NEW.generated_artifact_digest
          AND decision.canonical_artifact_digest = NEW.canonical_artifact_digest
          AND decision.original_add_digest IS NOT DISTINCT FROM NEW.original_add_digest
          AND decision.evidence_snapshot_digest = NEW.evidence_snapshot_digest
          AND decision.validation_snapshot_digest = NEW.validation_snapshot_digest
          AND decision.actor_id = NEW.actor_id
          AND decision.reason_digest = NEW.hil_reason_digest
          AND decision.challenge_nonce_digest = NEW.decision_nonce_digest
          AND decision.idempotency_key_digest = NEW.idempotency_key_digest
          AND decision.decided_at = NEW.decided_at
          AND NEW.valid_until <= decision.decision_valid_until
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'enforcement authorization does not match consumed HIL decision';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS enforcement_authorizations_require_decision
    ON sentinelflow.enforcement_authorizations;
CREATE TRIGGER enforcement_authorizations_require_decision
BEFORE INSERT OR UPDATE ON sentinelflow.enforcement_authorizations
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_enforcement_authorization_match();

CREATE OR REPLACE FUNCTION sentinelflow.require_add_authorization()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.enforcement_authorizations authz
        JOIN sentinelflow.policy_proposals policy
          ON policy.policy_id = NEW.policy_id
         AND policy.version = NEW.policy_version
        JOIN sentinelflow.validation_snapshots validation
          ON validation.validation_snapshot_id = NEW.validation_snapshot_id
        JOIN sentinelflow.evidence_snapshots evidence
          ON evidence.evidence_snapshot_id = NEW.evidence_snapshot_id
        JOIN sentinelflow.command_candidates candidate
          ON candidate.command_candidate_id = NEW.command_candidate_id
        WHERE authz.authorization_id = NEW.add_authorization_id
          AND authz.authorization_kind = 'add'
          AND authz.decision = 'approve'
          AND authz.action_id = NEW.action_id
          AND authz.policy_id = NEW.policy_id
          AND authz.policy_version = NEW.policy_version
          AND authz.target_ipv4 = NEW.target_ipv4
          AND authz.canonical_artifact_digest = NEW.canonical_artifact_digest
          AND authz.original_add_digest IS NULL
          AND authz.valid_until >= NEW.approved_at
          AND NEW.evidence_snapshot_digest = authz.evidence_snapshot_digest
          AND policy.policy_digest = authz.policy_digest
          AND policy.generated_artifact_digest = authz.generated_artifact_digest
          AND policy.canonical_artifact_digest = authz.canonical_artifact_digest
          AND policy.target_ipv4 = NEW.target_ipv4
          AND policy.ttl_seconds = NEW.ttl_seconds
          AND policy.evidence_snapshot_id = NEW.evidence_snapshot_id
          AND policy.evidence_snapshot_digest = NEW.evidence_snapshot_digest
          AND policy.command_candidate_id = NEW.command_candidate_id
          AND policy.state IN (
              'approved', 'queued', 'active', 'expired', 'failed', 'revoked', 'indeterminate'
          )
          AND validation.policy_id = NEW.policy_id
          AND validation.policy_version = NEW.policy_version
          AND validation.evidence_snapshot_id = NEW.evidence_snapshot_id
          AND validation.evidence_snapshot_digest = NEW.evidence_snapshot_digest
          AND validation.command_candidate_id = NEW.command_candidate_id
          AND validation.snapshot_digest = authz.validation_snapshot_digest
          AND validation.evidence_snapshot_digest = authz.evidence_snapshot_digest
          AND validation.canonical_artifact_digest = NEW.canonical_artifact_digest
          AND validation.target_ipv4 = NEW.target_ipv4
          AND validation.ttl_seconds = NEW.ttl_seconds
          AND validation.state = 'valid'
          AND validation.valid_until >= NEW.approved_at
          AND evidence.snapshot_digest = authz.evidence_snapshot_digest
          AND candidate.analysis_id = policy.analysis_id
          AND candidate.evidence_snapshot_id = NEW.evidence_snapshot_id
          AND candidate.evidence_snapshot_digest = NEW.evidence_snapshot_digest
          AND candidate.target_ipv4 = NEW.target_ipv4
          AND candidate.ttl_seconds = NEW.ttl_seconds
          AND candidate.canonical_artifact = NEW.canonical_artifact
          AND candidate.canonical_artifact_digest = NEW.canonical_artifact_digest
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'enforcement action requires matching add authorization';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS enforcement_actions_require_add_authorization
    ON sentinelflow.enforcement_actions;
CREATE TRIGGER enforcement_actions_require_add_authorization
BEFORE INSERT OR UPDATE OF add_authorization_id, policy_id, policy_version,
    validation_snapshot_id, command_candidate_id, evidence_snapshot_digest,
    target_ipv4, canonical_artifact, canonical_artifact_digest, ttl_seconds,
    approved_at
ON sentinelflow.enforcement_actions
FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_add_authorization();

CREATE OR REPLACE FUNCTION sentinelflow.require_dispatch_authority()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    expected_kind text;
BEGIN
    expected_kind := CASE NEW.operation
        WHEN 'add' THEN 'dispatch_add'
        WHEN 'revoke' THEN 'dispatch_revoke'
        WHEN 'inspect' THEN 'dispatch_inspect'
    END;

    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.outbox_jobs job
        JOIN sentinelflow.enforcement_actions action
          ON action.action_id = NEW.action_id
        WHERE job.job_id = NEW.job_id
          AND job.kind = expected_kind
          AND job.operation = NEW.operation
          AND job.aggregate_type = 'enforcement_action'
          AND job.aggregate_id = NEW.action_id
          AND job.aggregate_version = action.version
          AND job.state IN ('pending', 'retry')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'dispatch operation requires matching pending outbox job';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.enforcement_actions action
        WHERE action.action_id = NEW.action_id
          AND action.policy_id = NEW.policy_id
          AND action.policy_version = NEW.policy_version
          AND action.target_ipv4 = NEW.target_ipv4
          AND action.validation_snapshot_id = NEW.validation_snapshot_id
          AND (
              (NEW.operation = 'add' AND
                  action.canonical_artifact_digest = NEW.artifact_digest AND
                  action.state IN ('approved', 'queued')) OR
              (NEW.operation IN ('revoke', 'inspect') AND
                  action.canonical_artifact_digest = NEW.original_add_digest AND
                  action.state IN ('active', 'expired', 'failed', 'indeterminate'))
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'dispatch operation does not match enforcement action';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.validation_snapshots validation
        WHERE validation.validation_snapshot_id = NEW.validation_snapshot_id
          AND validation.snapshot_digest = NEW.validation_snapshot_digest
          AND validation.policy_id = NEW.policy_id
          AND validation.policy_version = NEW.policy_version
          AND (
              (NEW.operation = 'add' AND
                  validation.canonical_artifact_digest = NEW.artifact_digest AND
                  validation.state = 'valid' AND
                  validation.valid_until >= NEW.not_before) OR
              (NEW.operation IN ('revoke', 'inspect') AND
                  validation.canonical_artifact_digest = NEW.original_add_digest)
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'dispatch operation requires matching valid snapshot';
    END IF;

    IF NEW.operation IN ('add', 'revoke') THEN
        IF NOT EXISTS (
            SELECT 1
            FROM sentinelflow.enforcement_authorizations authz
            WHERE authz.authorization_id = NEW.enforcement_authorization_id
              AND authz.authorization_kind = NEW.operation
              AND authz.action_id = NEW.action_id
              AND authz.policy_id = NEW.policy_id
              AND authz.policy_version = NEW.policy_version
              AND authz.authorization_digest = NEW.authorization_digest
              AND authz.target_ipv4 = NEW.target_ipv4
              AND authz.canonical_artifact_digest = NEW.artifact_digest
              AND authz.original_add_digest IS NOT DISTINCT FROM NEW.original_add_digest
              AND authz.evidence_snapshot_digest = NEW.evidence_snapshot_digest
              AND authz.validation_snapshot_digest = NEW.validation_snapshot_digest
              AND authz.actor_id = NEW.actor_id
              AND authz.hil_reason_digest = NEW.reason_digest
              AND authz.valid_until >= NEW.not_before
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'dispatch mutation requires matching HIL authorization';
        END IF;
    ELSE
        IF NOT EXISTS (
            SELECT 1
            FROM sentinelflow.inspection_authorizations authz
            WHERE authz.authorization_id = NEW.inspection_authorization_id
              AND authz.action_id = NEW.action_id
              AND authz.policy_id = NEW.policy_id
              AND authz.policy_version = NEW.policy_version
              AND authz.authorization_digest = NEW.authorization_digest
              AND authz.target_ipv4 = NEW.target_ipv4
              AND authz.artifact_digest = NEW.artifact_digest
              AND authz.original_add_digest = NEW.original_add_digest
              AND authz.evidence_snapshot_digest = NEW.evidence_snapshot_digest
              AND authz.validation_snapshot_digest = NEW.validation_snapshot_digest
              AND authz.owned_schema_digest = NEW.owned_schema_digest
              AND authz.scheduler_id = NEW.actor_id
              AND authz.valid_until >= NEW.not_before
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'dispatch inspection requires matching non-HIL authorization';
        END IF;
    END IF;

    RETURN NEW;
END
$function$;

DO $dispatch_authority_trigger$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = 'sentinelflow.dispatch_operations'::regclass
          AND tgname = 'dispatch_operations_require_authority'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER dispatch_operations_require_authority
        BEFORE INSERT OR UPDATE ON sentinelflow.dispatch_operations
        FOR EACH ROW EXECUTE FUNCTION sentinelflow.require_dispatch_authority();
    END IF;
END
$dispatch_authority_trigger$;

CREATE OR REPLACE VIEW sentinelflow.dispatcher_approved_outbox
WITH (security_barrier = true)
AS
SELECT
    job.job_id,
    job.kind,
    job.state,
    job.available_at,
    job.attempts,
    job.max_attempts,
    operation.operation,
    operation.action_id,
    operation.policy_id,
    operation.policy_version,
    operation.target_ipv4,
    operation.artifact,
    operation.artifact_digest,
    operation.original_add_digest,
    operation.evidence_snapshot_digest,
    operation.validation_snapshot_digest,
    operation.authorization_digest,
    operation.actor_id,
    operation.reason_digest,
    operation.owned_schema_digest,
    operation.not_before,
    operation.valid_until
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.dispatch_operations operation USING (job_id)
JOIN sentinelflow.validation_snapshots validation
  ON validation.validation_snapshot_id = operation.validation_snapshot_id
JOIN sentinelflow.enforcement_actions action
  ON action.action_id = operation.action_id
WHERE job.kind IN ('dispatch_add', 'dispatch_revoke', 'dispatch_inspect')
  AND job.kind = 'dispatch_' || operation.operation
  AND job.operation = operation.operation
  AND job.aggregate_type = 'enforcement_action'
  AND job.aggregate_id = action.action_id
  AND job.aggregate_version = action.version
  AND job.state IN ('pending', 'retry')
  AND job.available_at <= clock_timestamp()
  AND job.attempts < job.max_attempts
  AND operation.not_before <= clock_timestamp()
  AND operation.valid_until >= clock_timestamp()
  AND (
      (operation.operation = 'add' AND
          action.state IN ('approved', 'queued') AND
          validation.state = 'valid' AND
          validation.valid_until >= clock_timestamp()) OR
      (operation.operation IN ('revoke', 'inspect') AND
          action.state IN ('active', 'expired', 'failed', 'indeterminate'))
  )
  AND (
      (operation.operation IN ('add', 'revoke') AND EXISTS (
          SELECT 1
          FROM sentinelflow.enforcement_authorizations authz
          WHERE authz.authorization_id = operation.enforcement_authorization_id
            AND authz.authorization_digest = operation.authorization_digest
            AND authz.valid_until >= clock_timestamp()
      )) OR
      (operation.operation = 'inspect' AND EXISTS (
          SELECT 1
          FROM sentinelflow.inspection_authorizations authz
          WHERE authz.authorization_id = operation.inspection_authorization_id
            AND authz.authorization_digest = operation.authorization_digest
            AND authz.valid_until >= clock_timestamp()
      ))
  );

CREATE OR REPLACE FUNCTION sentinelflow.claim_dispatch_job(
    p_job_id uuid,
    p_lease_token uuid,
    p_lease_owner sentinelflow.ascii_id,
    p_lease_until timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    claimed boolean;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL OR p_lease_owner IS NULL OR
       p_lease_until IS NULL OR p_lease_until <= clock_timestamp() OR
       p_lease_until > clock_timestamp() + interval '60 seconds' THEN
        RETURN false;
    END IF;

    UPDATE sentinelflow.outbox_jobs job
    SET state = 'leased',
        lease_token = p_lease_token,
        lease_owner = p_lease_owner,
        lease_expires_at = p_lease_until,
        attempts = attempts + 1,
        updated_at = clock_timestamp()
    WHERE job.job_id = p_job_id
      AND job.job_id IN (SELECT approved.job_id FROM sentinelflow.dispatcher_approved_outbox approved)
    RETURNING true INTO claimed;

    RETURN coalesce(claimed, false);
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.record_execution_capability(
    p_capability_id uuid,
    p_job_id uuid,
    p_lease_token uuid,
    p_operation text,
    p_action_id uuid,
    p_policy_id uuid,
    p_policy_version integer,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_artifact bytea,
    p_artifact_digest sentinelflow.sha256_digest,
    p_original_add_digest sentinelflow.sha256_digest,
    p_evidence_snapshot_digest sentinelflow.sha256_digest,
    p_validation_snapshot_digest sentinelflow.sha256_digest,
    p_authorization_digest sentinelflow.sha256_digest,
    p_actor_id sentinelflow.ascii_id,
    p_reason_digest sentinelflow.sha256_digest,
    p_owned_schema_digest sentinelflow.sha256_digest,
    p_capability_jcs bytea,
    p_capability_digest sentinelflow.sha256_digest,
    p_capability_signature bytea,
    p_nonce_digest sentinelflow.sha256_digest,
    p_issued_at timestamptz,
    p_not_before timestamptz,
    p_expires_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.outbox_jobs job
        JOIN sentinelflow.dispatch_operations operation USING (job_id)
        WHERE job.job_id = p_job_id
          AND job.state = 'leased'
          AND job.lease_token = p_lease_token
          AND job.lease_expires_at >= clock_timestamp()
          AND operation.operation = p_operation
          AND operation.action_id = p_action_id
          AND operation.policy_id = p_policy_id
          AND operation.policy_version = p_policy_version
          AND operation.target_ipv4 = p_target_ipv4
          AND operation.artifact = p_artifact
          AND operation.artifact_digest = p_artifact_digest
          AND operation.original_add_digest IS NOT DISTINCT FROM p_original_add_digest
          AND operation.evidence_snapshot_digest = p_evidence_snapshot_digest
          AND operation.validation_snapshot_digest = p_validation_snapshot_digest
          AND operation.authorization_digest = p_authorization_digest
          AND operation.actor_id = p_actor_id
          AND operation.reason_digest = p_reason_digest
          AND operation.owned_schema_digest = p_owned_schema_digest
          AND p_not_before >= operation.not_before
          AND p_expires_at <= operation.valid_until
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'capability does not match claimed dispatch job';
    END IF;

    INSERT INTO sentinelflow.execution_capabilities (
        capability_id, schema_version, job_id, operation, action_id, policy_id,
        policy_version, target_ipv4, artifact, artifact_digest, original_add_digest,
        evidence_snapshot_digest, validation_snapshot_digest, authorization_digest,
        actor_id, reason_digest, owned_schema_digest, capability_jcs,
        capability_digest, capability_signature, nonce_digest, issued_at,
        not_before, expires_at
    ) VALUES (
        p_capability_id, 'execution-capability-v1', p_job_id, p_operation, p_action_id, p_policy_id,
        p_policy_version, p_target_ipv4, p_artifact, p_artifact_digest, p_original_add_digest,
        p_evidence_snapshot_digest, p_validation_snapshot_digest, p_authorization_digest,
        p_actor_id, p_reason_digest, p_owned_schema_digest, p_capability_jcs,
        p_capability_digest, p_capability_signature, p_nonce_digest, p_issued_at,
        p_not_before, p_expires_at
    );
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.record_execution_result(
    p_result_id uuid,
    p_job_id uuid,
    p_lease_token uuid,
    p_capability_id uuid,
    p_capability_digest sentinelflow.sha256_digest,
    p_operation text,
    p_action_id uuid,
    p_artifact_digest sentinelflow.sha256_digest,
    p_target_ipv4 sentinelflow.canonical_ipv4,
    p_classification text,
    p_nft_exit_class text,
    p_readback_state text,
    p_element_handle bigint,
    p_remaining_ttl_seconds integer,
    p_owned_schema_digest sentinelflow.sha256_digest,
    p_started_at timestamptz,
    p_completed_at timestamptz,
    p_journal_sequence bigint,
    p_error_code text,
    p_result_jcs bytea,
    p_result_digest sentinelflow.sha256_digest,
    p_result_signature bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.outbox_jobs job
        JOIN sentinelflow.execution_capabilities capability USING (job_id)
        WHERE job.job_id = p_job_id
          AND job.state = 'leased'
          AND job.lease_token = p_lease_token
          AND capability.capability_id = p_capability_id
          AND capability.capability_digest = p_capability_digest
          AND capability.operation = p_operation
          AND capability.action_id = p_action_id
          AND capability.artifact_digest = p_artifact_digest
          AND capability.target_ipv4 = p_target_ipv4
          AND capability.owned_schema_digest = p_owned_schema_digest
          AND capability.consumed_at IS NULL
          AND p_started_at >= capability.not_before
          AND p_started_at <= capability.expires_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'result does not match claimed capability';
    END IF;

    INSERT INTO sentinelflow.execution_results (
        result_id, schema_version, capability_id, capability_digest, operation,
        action_id, artifact_digest, target_ipv4, classification, nft_exit_class,
        readback_state, element_handle, remaining_ttl_seconds, owned_schema_digest,
        started_at, completed_at, journal_sequence, error_code, result_jcs,
        result_digest, result_signature
    ) VALUES (
        p_result_id, 'execution-result-v1', p_capability_id, p_capability_digest, p_operation,
        p_action_id, p_artifact_digest, p_target_ipv4, p_classification, p_nft_exit_class,
        p_readback_state, p_element_handle, p_remaining_ttl_seconds, p_owned_schema_digest,
        p_started_at, p_completed_at, p_journal_sequence, p_error_code, p_result_jcs,
        p_result_digest, p_result_signature
    );

    UPDATE sentinelflow.execution_capabilities
    SET consumed_at = p_completed_at
    WHERE capability_id = p_capability_id;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.finish_dispatch_job(
    p_job_id uuid,
    p_lease_token uuid,
    p_outcome text,
    p_error_code sentinelflow.ascii_id,
    p_error_digest sentinelflow.sha256_digest,
    p_next_available_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    finished boolean;
BEGIN
    IF p_outcome NOT IN ('completed', 'retry', 'dead') THEN
        RETURN false;
    END IF;
    IF p_outcome = 'retry' AND
       (p_next_available_at IS NULL OR p_next_available_at < clock_timestamp()) THEN
        RETURN false;
    END IF;
    IF p_outcome IN ('retry', 'dead') AND
       (p_error_code IS NULL OR p_error_digest IS NULL) THEN
        RETURN false;
    END IF;
    IF p_outcome = 'completed' AND NOT EXISTS (
        SELECT 1
        FROM sentinelflow.execution_results result
        JOIN sentinelflow.execution_capabilities capability USING (capability_id)
        WHERE capability.job_id = p_job_id
    ) THEN
        RETURN false;
    END IF;

    UPDATE sentinelflow.outbox_jobs job
    SET state = p_outcome,
        available_at = CASE WHEN p_outcome = 'retry' THEN p_next_available_at ELSE available_at END,
        lease_token = NULL,
        lease_owner = NULL,
        lease_expires_at = NULL,
        last_error_code = CASE WHEN p_outcome = 'completed' THEN NULL ELSE p_error_code END,
        last_error_digest = CASE WHEN p_outcome = 'completed' THEN NULL ELSE p_error_digest END,
        updated_at = clock_timestamp()
    WHERE job.job_id = p_job_id
      AND job.state = 'leased'
      AND job.lease_token = p_lease_token
      AND (p_outcome <> 'retry' OR job.attempts < job.max_attempts)
    RETURNING true INTO finished;

    IF coalesce(finished, false) AND p_outcome = 'dead' THEN
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest
        )
        SELECT job_id, kind, aggregate_type, aggregate_id, aggregate_version,
               attempts, p_error_code, p_error_digest
        FROM sentinelflow.outbox_jobs
        WHERE job_id = p_job_id
        ON CONFLICT (job_id) DO NOTHING;
    END IF;

    RETURN coalesce(finished, false);
END
$function$;

INSERT INTO schema_migrations (version, name)
VALUES (3, 'security_functions')
ON CONFLICT (version) DO NOTHING;

COMMIT;
