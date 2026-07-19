BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

REVOKE ALL ON ALL TABLES IN SCHEMA sentinelflow FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA sentinelflow FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA sentinelflow FROM PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelflow_migration IN SCHEMA sentinelflow
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinelflow_migration IN SCHEMA sentinelflow
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
-- PostgreSQL's built-in default EXECUTE grant is global. A schema-scoped
-- REVOKE cannot override it, so remove it at the owner/global level before
-- later migrations create any SECURITY DEFINER boundary.
ALTER DEFAULT PRIVILEGES FOR ROLE sentinelflow_migration
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinelflow_migration IN SCHEMA sentinelflow
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

REVOKE ALL ON ALL TABLES IN SCHEMA sentinelflow FROM
    sentinelflow_api,
    sentinelflow_worker,
    sentinelflow_read,
    sentinelflow_dispatcher;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA sentinelflow FROM
    sentinelflow_api,
    sentinelflow_worker,
    sentinelflow_read,
    sentinelflow_dispatcher;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA sentinelflow FROM
    sentinelflow_api,
    sentinelflow_worker,
    sentinelflow_read,
    sentinelflow_dispatcher;

GRANT USAGE ON SCHEMA sentinelflow TO
    sentinelflow_api,
    sentinelflow_worker,
    sentinelflow_read,
    sentinelflow_dispatcher;

GRANT SELECT, INSERT ON TABLE
    ingest_replay_nonces,
    ingest_batches,
    gateway_events,
    auth_events,
    source_health_intervals
TO sentinelflow_api;

GRANT UPDATE (binding_state, binding_reason, bound_gateway_event_id)
    ON auth_events TO sentinelflow_api;

GRANT SELECT, INSERT ON TABLE sender_checkpoints TO sentinelflow_api;
GRANT UPDATE (
    sender_epoch, last_acknowledged_sequence, last_acknowledged_body_digest,
    clean_shutdown, unknown_loss, updated_at
) ON sender_checkpoints TO sentinelflow_api;

GRANT SELECT ON TABLE
    signals,
    signal_evidence,
    incidents,
    incident_signals,
    incident_events,
    evidence_snapshots,
    evidence_snapshot_signals,
    evidence_snapshot_events,
    ai_analyses,
    analysis_false_positive_factors,
    analysis_evidence,
    command_candidates,
    policy_proposals,
    validation_snapshots,
    validation_gates,
    enforcement_actions,
    revocation_operations,
    inspection_authorizations,
    execution_results,
    dead_letter_jobs,
    audit_events
TO sentinelflow_api;

GRANT SELECT, INSERT, UPDATE ON TABLE
    admin_sessions,
    revocation_operations
TO sentinelflow_api;

GRANT INSERT ON TABLE enforcement_actions TO sentinelflow_api;
GRANT UPDATE (
    state, nft_element_handle, queued_at, applied_at, expected_expires_at,
    finished_at, version, updated_at
) ON enforcement_actions TO sentinelflow_api;

GRANT SELECT, INSERT ON TABLE outbox_jobs TO sentinelflow_api;
GRANT UPDATE (
    state, available_at, lease_token, lease_owner, lease_expires_at, attempts,
    last_error_code, last_error_digest, updated_at
) ON outbox_jobs TO sentinelflow_api;

GRANT SELECT, INSERT ON TABLE decision_challenges TO sentinelflow_api;
GRANT UPDATE (consumed_at, consumed_decision_id)
    ON decision_challenges TO sentinelflow_api;

GRANT SELECT, INSERT ON TABLE
    hil_reasons,
    approval_decisions,
    enforcement_authorizations,
    inspection_authorizations,
    dispatch_operations
TO sentinelflow_api;

GRANT SELECT ON TABLE
    ingest_batches,
    gateway_events,
    auth_events,
    source_health_intervals,
    sender_checkpoints,
    approval_decisions,
    enforcement_authorizations,
    enforcement_actions,
    revocation_operations,
    execution_results
TO sentinelflow_worker;

GRANT SELECT, INSERT ON TABLE
    signals,
    signal_evidence,
    incident_signals,
    incident_events,
    evidence_snapshots,
    evidence_snapshot_signals,
    evidence_snapshot_events,
    analysis_false_positive_factors,
    analysis_evidence,
    inspection_authorizations,
    dispatch_operations
TO sentinelflow_worker;

GRANT SELECT, INSERT, UPDATE ON TABLE
    incidents,
    ai_analyses,
    command_candidates,
    validation_snapshots,
    validation_gates,
    dead_letter_jobs,
    ai_budget_ledger
TO sentinelflow_worker;

GRANT SELECT, INSERT ON TABLE policy_proposals TO sentinelflow_worker;
GRANT UPDATE (state, state_revision, updated_at)
    ON policy_proposals TO sentinelflow_worker;

GRANT SELECT, INSERT ON TABLE outbox_jobs TO sentinelflow_worker;
GRANT UPDATE (
    state, available_at, lease_token, lease_owner, lease_expires_at, attempts,
    last_error_code, last_error_digest, updated_at
) ON outbox_jobs TO sentinelflow_worker;

GRANT SELECT ON TABLE
    ingest_batches,
    gateway_events,
    auth_events,
    source_health_intervals,
    sender_checkpoints,
    signals,
    signal_evidence,
    incidents,
    incident_signals,
    incident_events,
    evidence_snapshots,
    evidence_snapshot_signals,
    evidence_snapshot_events,
    ai_analyses,
    analysis_false_positive_factors,
    analysis_evidence,
    command_candidates,
    policy_proposals,
    validation_snapshots,
    validation_gates,
    approval_decisions,
    enforcement_actions,
    revocation_operations,
    inspection_authorizations,
    execution_results,
    dead_letter_jobs,
    audit_events,
    ai_budget_ledger
TO sentinelflow_read;

GRANT SELECT ON sentinelflow.dispatcher_approved_outbox TO sentinelflow_dispatcher;

GRANT EXECUTE ON FUNCTION sentinelflow.append_audit_event(
    uuid, text, sentinelflow.ascii_id, sentinelflow.ascii_id,
    sentinelflow.ascii_id, uuid, uuid, uuid, integer, uuid, uuid,
    sentinelflow.sha256_digest, sentinelflow.sha256_digest, text, timestamptz
) TO sentinelflow_api, sentinelflow_worker;

GRANT EXECUTE ON FUNCTION sentinelflow.prune_ingest_replay_nonces(
    timestamptz, integer
) TO sentinelflow_api;

GRANT EXECUTE ON FUNCTION sentinelflow.claim_dispatch_job(
    uuid, uuid, sentinelflow.ascii_id, timestamptz
) TO sentinelflow_dispatcher;

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

GRANT EXECUTE ON FUNCTION sentinelflow.finish_dispatch_job(
    uuid, uuid, text, sentinelflow.ascii_id,
    sentinelflow.sha256_digest, timestamptz
) TO sentinelflow_dispatcher;

INSERT INTO schema_migrations (version, name)
VALUES (4, 'role_grants')
ON CONFLICT (version) DO NOTHING;

COMMIT;
