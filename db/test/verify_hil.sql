BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

INSERT INTO signals (
    signal_id, schema_version, rule_id, rule_version, kind, source_ip,
    service_label, window_start, window_end, observed_count, threshold_count,
    source_health_status, evidence_digest, configuration_version,
    configuration_digest, signal_digest
) VALUES (
    '019b0000-0000-7000-8000-000000009100', 'signal-v1', 'suspicious-paths', 1,
    'path_scan', '203.0.113.30', 'demo-app', now() - interval '1 minute', now(),
    8, 8, 'complete',
    'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    'detector-v1',
    'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'sha256:7777777777777777777777777777777777777777777777777777777777777777'
);

INSERT INTO incidents (
    incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
    deterministic_score, version, evidence_version
) VALUES (
    '019b0000-0000-7000-8000-000000009101', 'path_scan', 'review_ready',
    '203.0.113.30', 'demo-app', now() - interval '1 minute', now(), 0.95000,
    1, 1
);

INSERT INTO incident_signals (
    incident_id, signal_id, incident_version, relation_reason
) VALUES (
    '019b0000-0000-7000-8000-000000009101',
    '019b0000-0000-7000-8000-000000009100', 1, 'same_source_overlap'
);

INSERT INTO incident_version_history (
    incident_id, incident_version, state, kind, source_ip, service_label,
    first_seen, last_seen, deterministic_score, mutation_kind,
    mutation_digest, evidence_digest, signal_count
) VALUES (
    '019b0000-0000-7000-8000-000000009101', 1, 'review_ready', 'path_scan',
    '203.0.113.30', 'demo-app', now() - interval '1 minute', now(), 0.95000,
    'created',
    'sha256:6666666666666666666666666666666666666666666666666666666666666666',
    'sha256:4011ca5791d4f48e3443ff656497fa342b7a35dbf75c29c5df370c7dbb15ec32',
    1
);

INSERT INTO incident_version_signals (
    incident_id, incident_version, signal_id, ordinal
) VALUES (
    '019b0000-0000-7000-8000-000000009101', 1,
    '019b0000-0000-7000-8000-000000009100', 1
);

INSERT INTO evidence_snapshots (
    evidence_snapshot_id, schema_version, incident_id, incident_version,
    source_ip, service_label, window_start, window_end, source_health_status,
    signal_count, expanded_event_count, snapshot_digest, expires_at
) VALUES (
    '019b0000-0000-7000-8000-000000009102', 'evidence-snapshot-v1',
    '019b0000-0000-7000-8000-000000009101', 1, '203.0.113.30', 'demo-app',
    now() - interval '1 minute', now(), 'complete', 1, 1,
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    now() + interval '30 days'
);

INSERT INTO evidence_snapshot_signals (
    evidence_snapshot_id, ordinal, signal_id, evidence_id, evidence_digest,
    expanded_event_count
) VALUES (
    '019b0000-0000-7000-8000-000000009102', 1,
    '019b0000-0000-7000-8000-000000009100', 'evidence-001',
    'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 1
);

INSERT INTO ai_analyses (
    analysis_id, incident_id, incident_version, evidence_snapshot_id,
    evidence_snapshot_digest, attempt,
    model, reasoning_effort, store_enabled, input_schema_digest, prompt_digest,
    output_schema_digest, input_digest, input_bytes, result_state, output_digest,
    incident_summary, classification, confidence, uncertainty, input_tokens,
    cached_input_tokens, output_tokens, started_at, completed_at
) VALUES (
    '019b0000-0000-7000-8000-000000009103',
    '019b0000-0000-7000-8000-000000009101', 1,
    '019b0000-0000-7000-8000-000000009102',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    1, 'gpt-5.6-sol', 'medium', false,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    2048, 'succeeded',
    'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'Synthetic path-scan incident for database invariant verification.',
    'path_scan', 0.95000, 'Synthetic isolated-demo evidence only.', 400, 0, 180,
    now() - interval '10 seconds', now() - interval '5 seconds'
);

INSERT INTO analysis_evidence (
    analysis_id, ordinal, evidence_snapshot_id, signal_id, evidence_id
) VALUES (
    '019b0000-0000-7000-8000-000000009103', 1,
    '019b0000-0000-7000-8000-000000009102',
    '019b0000-0000-7000-8000-000000009100', 'evidence-001'
);

INSERT INTO command_candidates (
    command_candidate_id, schema_version, analysis_id, evidence_snapshot_id,
    evidence_snapshot_digest,
    target_ipv4, timeout_token, ttl_seconds, generated_command,
    generated_artifact_digest, parse_state, canonical_artifact,
    canonical_artifact_digest
) VALUES (
    '019b0000-0000-7000-8000-000000009104', 'nft-blacklist-v1',
    '019b0000-0000-7000-8000-000000009103',
    '019b0000-0000-7000-8000-000000009102',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    '203.0.113.30', '30m', 1800,
    'add element inet sentinelflow blacklist_ipv4 { 203.0.113.30 timeout 30m }',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    'valid',
    convert_to(E'add element inet sentinelflow blacklist_ipv4 { 203.0.113.30 timeout 30m }\n', 'UTF8'),
    'sha256:3333333333333333333333333333333333333333333333333333333333333333'
);

INSERT INTO policy_proposals (
    policy_id, version, schema_version, incident_id, incident_version,
    analysis_id, command_candidate_id, evidence_snapshot_id,
    evidence_snapshot_digest, policy_digest,
    generated_artifact_digest, canonical_artifact_digest, target_ipv4, action,
    ttl_seconds, rationale, state
) VALUES (
    '019b0000-0000-7000-8000-000000009105', 1, 'response-policy-v1',
    '019b0000-0000-7000-8000-000000009101', 1,
    '019b0000-0000-7000-8000-000000009103',
    '019b0000-0000-7000-8000-000000009104',
    '019b0000-0000-7000-8000-000000009102',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    'sha256:4444444444444444444444444444444444444444444444444444444444444444',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    '203.0.113.30', 'block_ip', 1800, 'Synthetic exact-artifact approval fixture.',
    'draft'
);

DO $policy_state_machine_fails_closed$
BEGIN
    BEGIN
        UPDATE policy_proposals
        SET state = 'approved', state_revision = 2, updated_at = clock_timestamp()
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;
        RAISE EXCEPTION 'draft policy skipped directly to approved';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    BEGIN
        UPDATE policy_proposals
        SET state = 'validating', state_revision = 3, updated_at = clock_timestamp()
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;
        RAISE EXCEPTION 'policy state revision skip was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    BEGIN
        UPDATE policy_proposals
        SET state = 'draft', state_revision = 2, updated_at = clock_timestamp()
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;
        RAISE EXCEPTION 'same-state write incremented the policy revision';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    BEGIN
        UPDATE policy_proposals
        SET state = 'stale', state_revision = 2, updated_at = clock_timestamp()
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;
        UPDATE policy_proposals
        SET state = 'approved', state_revision = 3, updated_at = clock_timestamp()
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;
        RAISE EXCEPTION 'stale policy was approved';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    BEGIN
        UPDATE policy_proposals
        SET state = 'validating', state_revision = 2, updated_at = clock_timestamp()
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;
        UPDATE policy_proposals
        SET state = 'invalid', state_revision = 3, updated_at = clock_timestamp()
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;
        UPDATE policy_proposals
        SET state = 'approved', state_revision = 4, updated_at = clock_timestamp()
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;
        RAISE EXCEPTION 'invalid policy was approved';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    IF NOT EXISTS (
        SELECT 1
        FROM policy_proposals
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105'
          AND version = 1
          AND state = 'draft'
          AND state_revision = 1
    ) THEN
        RAISE EXCEPTION 'failed transition changed the policy state or revision';
    END IF;
END
$policy_state_machine_fails_closed$;

UPDATE policy_proposals
SET state = 'validating', state_revision = 2, updated_at = clock_timestamp()
WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;

INSERT INTO validation_snapshots (
    validation_snapshot_id, schema_version, policy_id, policy_version,
    command_candidate_id, evidence_snapshot_id, snapshot_digest, policy_digest,
    evidence_snapshot_digest, analysis_input_digest, analysis_output_schema_digest,
    prompt_digest, generated_candidate_digest, canonical_artifact_digest,
    grammar_version, parser_version, validator_version,
    base_chain_contract_raw_digest, live_owned_schema_digest,
    protected_ipv4_static_digest, protected_ipv4_effective_config_digest,
    nft_binary_digest, nft_version, historical_impact_digest,
    history_dataset_digest, history_manifest_digest, target_ipv4, ttl_seconds,
    historical_impact_lookback_seconds, state, source_health_status, created_at,
    valid_until
) VALUES (
    '019b0000-0000-7000-8000-000000009106', 'validation-snapshot-v1',
    '019b0000-0000-7000-8000-000000009105', 1,
    '019b0000-0000-7000-8000-000000009104',
    '019b0000-0000-7000-8000-000000009102',
    'sha256:5555555555555555555555555555555555555555555555555555555555555555',
    'sha256:4444444444444444444444444444444444444444444444444444444444444444',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    'nft-blacklist-v1', 'parser-v1', 'validator-v1',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'sha256:d3dfb63a573925e19f29e8595fd5574bc441a9c468d2f9ef6d2f004abb101104',
    'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    '1.1.0',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    '203.0.113.30', 1800, 86400, 'draft', 'complete', now(),
    now() + interval '5 minutes'
);

INSERT INTO validation_gates (
    validation_snapshot_id, gate_order, gate_name, passed, result_code,
    input_digest, result_digest
)
SELECT
    '019b0000-0000-7000-8000-000000009106', gate_order, gate_name, true, 'ok',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
FROM (VALUES
    (1, 'structured_output'),
    (2, 'command_grammar'),
    (3, 'policy_evidence_command_consistency'),
    (4, 'protected_network'),
    (5, 'owned_schema_syntax'),
    (6, 'historical_impact')
) AS ordered_gates(gate_order, gate_name);

UPDATE validation_snapshots
SET state = 'valid'
WHERE validation_snapshot_id = '019b0000-0000-7000-8000-000000009106';

UPDATE policy_proposals
SET state = 'valid', state_revision = 3, updated_at = clock_timestamp()
WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;

DO $valid_snapshot_is_immutable$
BEGIN
    BEGIN
        UPDATE validation_snapshots
        SET policy_digest = 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        WHERE validation_snapshot_id = '019b0000-0000-7000-8000-000000009106';
        RAISE EXCEPTION 'valid validation snapshot mutation was accepted';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
    BEGIN
        UPDATE validation_gates
        SET passed = false
        WHERE validation_snapshot_id = '019b0000-0000-7000-8000-000000009106'
          AND gate_order = 1;
        RAISE EXCEPTION 'valid validation gate mutation was accepted';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
END
$valid_snapshot_is_immutable$;

INSERT INTO admin_sessions (
    session_id, actor_id, token_digest, csrf_digest, authenticated_at,
    created_at, last_seen_at, expires_at
) VALUES (
    '019b0000-0000-7000-8000-000000009107', 'admin-test',
    'sha256:6666666666666666666666666666666666666666666666666666666666666666',
    'sha256:7777777777777777777777777777777777777777777777777777777777777777',
    now() - interval '1 minute', now() - interval '1 minute', now(),
    now() + interval '7 hours'
);

INSERT INTO decision_challenges (
    challenge_id, schema_version, nonce_digest, session_id, session_digest,
    actor_id, operation, resource_type, resource_id, resource_version, policy_id,
    policy_version, target_ipv4, policy_digest, evidence_snapshot_digest,
    generated_artifact_digest, canonical_artifact_digest, original_add_digest,
    validation_snapshot_digest, validation_valid_until, idempotency_key_digest,
    authenticated_at, reauth_required_after_seconds, issued_at, expires_at,
    challenge_jcs, challenge_digest
) VALUES (
    '019b0000-0000-7000-8000-000000009108', 'hil-challenge-v1',
    'sha256:8888888888888888888888888888888888888888888888888888888888888888',
    '019b0000-0000-7000-8000-000000009107',
    'sha256:6666666666666666666666666666666666666666666666666666666666666666',
    'admin-test', 'approve', 'policy',
    '019b0000-0000-7000-8000-000000009105', 1,
    '019b0000-0000-7000-8000-000000009105', 1, '203.0.113.30',
    'sha256:4444444444444444444444444444444444444444444444444444444444444444',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    NULL,
    'sha256:5555555555555555555555555555555555555555555555555555555555555555',
    now() + interval '5 minutes',
    'sha256:9999999999999999999999999999999999999999999999999999999999999999',
    now() - interval '1 minute', 900, now(), now() + interval '5 minutes',
    convert_to('{"challenge":"synthetic-db-invariant"}', 'UTF8'),
    sentinelflow.hil_sha256(convert_to('{"challenge":"synthetic-db-invariant"}', 'UTF8'))
);

INSERT INTO hil_reasons (
    reason_id, schema_version, actor_id, operation, normalized_reason,
    reason_code, reason_jcs, reason_digest
) VALUES (
    '019b0000-0000-7000-8000-000000009109', 'hil-reason-v1', 'admin-test',
    'approve', 'Approve synthetic isolated-demo block for invariant verification.',
    'threat_confirmed',
    convert_to('{"reason":"synthetic-db-invariant"}', 'UTF8'),
    sentinelflow.hil_sha256(convert_to('{"reason":"synthetic-db-invariant"}', 'UTF8'))
);

INSERT INTO approval_decisions (
    decision_id, schema_version, challenge_id, session_digest, operation, decision,
    resource_type, resource_id, resource_version, policy_id, policy_version,
    target_ipv4, validation_snapshot_id, policy_digest, evidence_snapshot_digest,
    generated_artifact_digest, canonical_artifact_digest, original_add_digest,
    validation_snapshot_digest, actor_id, reason_id, reason_digest,
    challenge_nonce_digest, idempotency_key_digest, decided_at,
    decision_valid_until, decision_jcs, decision_digest
) VALUES (
    '019b0000-0000-7000-8000-000000009110', 'hil-decision-v1',
    '019b0000-0000-7000-8000-000000009108',
    'sha256:6666666666666666666666666666666666666666666666666666666666666666',
    'approve', 'approved', 'policy',
    '019b0000-0000-7000-8000-000000009105', 1,
    '019b0000-0000-7000-8000-000000009105', 1, '203.0.113.30',
    '019b0000-0000-7000-8000-000000009106',
    'sha256:4444444444444444444444444444444444444444444444444444444444444444',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    NULL,
    'sha256:5555555555555555555555555555555555555555555555555555555555555555',
    'admin-test', '019b0000-0000-7000-8000-000000009109',
    sentinelflow.hil_sha256(convert_to('{"reason":"synthetic-db-invariant"}', 'UTF8')),
    'sha256:8888888888888888888888888888888888888888888888888888888888888888',
    'sha256:9999999999999999999999999999999999999999999999999999999999999999',
    now() + interval '1 second', now() + interval '4 minutes',
    convert_to('{"decision":"synthetic-db-invariant"}', 'UTF8'),
    sentinelflow.hil_sha256(convert_to('{"decision":"synthetic-db-invariant"}', 'UTF8'))
);

DO $mismatched_decision_fails_closed$
BEGIN
    BEGIN
        INSERT INTO approval_decisions (
            decision_id, schema_version, challenge_id, session_digest, operation,
            decision, resource_type, resource_id, resource_version, policy_id,
            policy_version, target_ipv4, validation_snapshot_id, policy_digest,
            evidence_snapshot_digest, generated_artifact_digest,
            canonical_artifact_digest, original_add_digest,
            validation_snapshot_digest, actor_id, reason_id, reason_digest,
            challenge_nonce_digest, idempotency_key_digest, decided_at,
            decision_valid_until, decision_jcs, decision_digest
        ) VALUES (
            '019b0000-0000-7000-8000-000000009111', 'hil-decision-v1',
            '019b0000-0000-7000-8000-000000009108',
            'sha256:6666666666666666666666666666666666666666666666666666666666666666',
            'approve', 'approved', 'policy',
            '019b0000-0000-7000-8000-000000009105', 1,
            '019b0000-0000-7000-8000-000000009105', 1, '203.0.113.31',
            '019b0000-0000-7000-8000-000000009106',
            'sha256:4444444444444444444444444444444444444444444444444444444444444444',
            'sha256:1111111111111111111111111111111111111111111111111111111111111111',
            'sha256:2222222222222222222222222222222222222222222222222222222222222222',
            'sha256:3333333333333333333333333333333333333333333333333333333333333333',
            NULL,
            'sha256:5555555555555555555555555555555555555555555555555555555555555555',
            'admin-test', '019b0000-0000-7000-8000-000000009109',
            sentinelflow.hil_sha256(convert_to('{"reason":"synthetic-db-invariant"}', 'UTF8')),
            'sha256:8888888888888888888888888888888888888888888888888888888888888888',
            'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            now() + interval '1 second', now() + interval '4 minutes',
            convert_to('{"decision":"synthetic-db-mismatch"}', 'UTF8'),
            sentinelflow.hil_sha256(convert_to('{"decision":"synthetic-db-mismatch"}', 'UTF8'))
        );
        RAISE EXCEPTION 'mismatched HIL decision was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$mismatched_decision_fails_closed$;

UPDATE decision_challenges
SET consumed_at = now() + interval '2 seconds',
    consumed_decision_id = '019b0000-0000-7000-8000-000000009110'
WHERE challenge_id = '019b0000-0000-7000-8000-000000009108';

DO $challenge_replay_fails_closed$
BEGIN
    BEGIN
        UPDATE decision_challenges
        SET consumed_at = now() + interval '3 seconds'
        WHERE challenge_id = '019b0000-0000-7000-8000-000000009108';
        RAISE EXCEPTION 'consumed HIL challenge was reusable';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
END
$challenge_replay_fails_closed$;

UPDATE policy_proposals
SET state = 'approved', state_revision = 4, updated_at = clock_timestamp()
WHERE policy_id = '019b0000-0000-7000-8000-000000009105' AND version = 1;

INSERT INTO enforcement_authorizations (
    authorization_id, schema_version, authorization_kind, action_id, policy_id,
    policy_version, approval_decision_id, decision, target_ipv4, policy_digest,
    generated_artifact_digest, canonical_artifact_digest, original_add_digest,
    evidence_snapshot_digest, validation_snapshot_digest, actor_id,
    hil_reason_digest, decision_nonce_digest, idempotency_key_digest,
    authorization_jcs, authorization_digest, decided_at, valid_until
) VALUES (
    '019b0000-0000-7000-8000-000000009112', 'enforcement-authorization-v1', 'add',
    '019b0000-0000-7000-8000-000000009113',
    '019b0000-0000-7000-8000-000000009105', 1,
    '019b0000-0000-7000-8000-000000009110', 'approve', '203.0.113.30',
    'sha256:4444444444444444444444444444444444444444444444444444444444444444',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    NULL,
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    'sha256:5555555555555555555555555555555555555555555555555555555555555555',
    'admin-test',
    sentinelflow.hil_sha256(convert_to('{"reason":"synthetic-db-invariant"}', 'UTF8')),
    'sha256:8888888888888888888888888888888888888888888888888888888888888888',
    'sha256:9999999999999999999999999999999999999999999999999999999999999999',
    convert_to('{"authorization":"synthetic-db-invariant"}', 'UTF8'),
    sentinelflow.hil_sha256(convert_to('{"authorization":"synthetic-db-invariant"}', 'UTF8')),
    now() + interval '1 second', now() + interval '4 minutes'
);

INSERT INTO enforcement_actions (
    action_id, policy_id, policy_version, validation_snapshot_id,
    evidence_snapshot_id, evidence_snapshot_digest, command_candidate_id,
    add_authorization_id,
    target_ipv4, canonical_artifact, canonical_artifact_digest, ttl_seconds,
    state, approved_at
) VALUES (
    '019b0000-0000-7000-8000-000000009113',
    '019b0000-0000-7000-8000-000000009105', 1,
    '019b0000-0000-7000-8000-000000009106',
    '019b0000-0000-7000-8000-000000009102',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    '019b0000-0000-7000-8000-000000009104',
    '019b0000-0000-7000-8000-000000009112', '203.0.113.30',
    convert_to(E'add element inet sentinelflow blacklist_ipv4 { 203.0.113.30 timeout 30m }\n', 'UTF8'),
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    1800, 'approved', now() + interval '1 second'
);

INSERT INTO outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version, operation,
    idempotency_key, available_at
) VALUES (
    '019b0000-0000-7000-8000-000000009114', 'dispatch_add',
    'enforcement_action', '019b0000-0000-7000-8000-000000009113', 1, 'add',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    now() - interval '1 second'
);

INSERT INTO dispatch_operations (
    job_id, operation, action_id, policy_id, policy_version, target_ipv4,
    artifact, artifact_digest, original_add_digest, evidence_snapshot_digest,
    validation_snapshot_id, validation_snapshot_digest,
    enforcement_authorization_id, inspection_authorization_id,
    authorization_digest, actor_id, reason_digest, owned_schema_digest,
    not_before, valid_until
) VALUES (
    '019b0000-0000-7000-8000-000000009114', 'add',
    '019b0000-0000-7000-8000-000000009113',
    '019b0000-0000-7000-8000-000000009105', 1, '203.0.113.30',
    convert_to(E'add element inet sentinelflow blacklist_ipv4 { 203.0.113.30 timeout 30m }\n', 'UTF8'),
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    NULL,
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    '019b0000-0000-7000-8000-000000009106',
    'sha256:5555555555555555555555555555555555555555555555555555555555555555',
    '019b0000-0000-7000-8000-000000009112', NULL,
    sentinelflow.hil_sha256(convert_to('{"authorization":"synthetic-db-invariant"}', 'UTF8')),
    'admin-test',
    sentinelflow.hil_sha256(convert_to('{"reason":"synthetic-db-invariant"}', 'UTF8')),
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    now() - interval '1 second', now() + interval '3 minutes'
);

DO $approved_dispatch_view$
BEGIN
    IF (SELECT count(*) FROM dispatcher_approved_outbox) <> 1 THEN
        RAISE EXCEPTION 'exact approved dispatch job is not visible';
    END IF;
END
$approved_dispatch_view$;

SET LOCAL ROLE sentinelflow_dispatcher;

SELECT 1 / sentinelflow.claim_dispatch_job(
    '019b0000-0000-7000-8000-000000009114',
    '019b0000-0000-7000-8000-000000009115',
    'dispatcher-test',
    clock_timestamp() + interval '30 seconds'
)::integer;

SELECT 1 / sentinelflow.finish_dispatch_job(
    '019b0000-0000-7000-8000-000000009114',
    '019b0000-0000-7000-8000-000000009115',
    'retry',
    'transport_error',
    'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    clock_timestamp() + interval '10 seconds'
)::integer;

RESET ROLE;

DO $direct_action_tombstone_fails_closed$
BEGIN
    BEGIN
        UPDATE enforcement_actions
        SET evidence_snapshot_id = NULL
        WHERE action_id = '019b0000-0000-7000-8000-000000009113';
        RAISE EXCEPTION 'direct enforcement evidence tombstone was accepted';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
    IF NOT EXISTS (
        SELECT 1 FROM enforcement_actions
        WHERE action_id = '019b0000-0000-7000-8000-000000009113'
          AND evidence_snapshot_id = '019b0000-0000-7000-8000-000000009102'
          AND target_ipv4 = '203.0.113.30'
    ) THEN
        RAISE EXCEPTION 'rejected direct tombstone changed the action';
    END IF;

    PERFORM set_config(
        'sentinelflow.retention_delete', '000023-retention-v1', true
    );
    BEGIN
        UPDATE enforcement_actions
        SET evidence_snapshot_id = NULL
        WHERE action_id = '019b0000-0000-7000-8000-000000009113';
        RAISE EXCEPTION 'forged retention marker enabled a direct tombstone';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
    PERFORM set_config('sentinelflow.retention_delete', '', true);
END
$direct_action_tombstone_fails_closed$;

SET LOCAL ROLE sentinelflow_api;

DO $api_action_tombstone_fails_closed$
BEGIN
    BEGIN
        UPDATE sentinelflow.enforcement_actions
        SET evidence_snapshot_id = NULL
        WHERE action_id = '019b0000-0000-7000-8000-000000009113';
        RAISE EXCEPTION 'API role could tombstone retained action evidence';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$api_action_tombstone_fails_closed$;

RESET ROLE;
SET LOCAL ROLE sentinelflow_worker;

DO $worker_action_tombstone_fails_closed$
BEGIN
    BEGIN
        UPDATE sentinelflow.enforcement_actions
        SET evidence_snapshot_id = NULL
        WHERE action_id = '019b0000-0000-7000-8000-000000009113';
        RAISE EXCEPTION 'worker role could tombstone retained action evidence';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$worker_action_tombstone_fails_closed$;

RESET ROLE;

CREATE FUNCTION pg_temp.attempt_mixed_action_tombstone_000029()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    UPDATE sentinelflow.enforcement_actions
    SET evidence_snapshot_id = NULL,
        created_at = created_at + interval '1 second'
    WHERE action_id = '019b0000-0000-7000-8000-000000009113';
    RETURN OLD;
END
$function$;

-- The quoted name sorts before PostgreSQL's RI_ConstraintTrigger_* trigger.
-- This creates the same nested trigger depth as ON DELETE SET NULL while the
-- parent is already invisible, but changes another action field as well.
CREATE TRIGGER "AAA_retention_mixed_action_000029"
AFTER DELETE ON evidence_snapshots
FOR EACH ROW EXECUTE FUNCTION pg_temp.attempt_mixed_action_tombstone_000029();

DO $mixed_action_tombstone_fails_closed$
BEGIN
    PERFORM set_config(
        'sentinelflow.retention_delete', '000023-retention-v1', true
    );
    PERFORM set_config('sentinelflow.retention_max_rows', '100', true);
    PERFORM set_config('sentinelflow.retention_deleted_rows', '0', true);
    PERFORM set_config('sentinelflow.retention_deleted_event', '0', true);
    PERFORM set_config('sentinelflow.retention_deleted_control', '0', true);
    PERFORM set_config('sentinelflow.retention_deleted_transient', '0', true);
    PERFORM set_config('sentinelflow.retention_deleted_audit', '0', true);
    BEGIN
        DELETE FROM evidence_snapshots
        WHERE evidence_snapshot_id = '019b0000-0000-7000-8000-000000009102';
        RAISE EXCEPTION 'mixed retention action tombstone was accepted';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
    PERFORM set_config('sentinelflow.retention_delete', '', true);

    IF NOT EXISTS (
        SELECT 1 FROM evidence_snapshots
        WHERE evidence_snapshot_id = '019b0000-0000-7000-8000-000000009102'
    ) OR NOT EXISTS (
        SELECT 1 FROM enforcement_actions
        WHERE action_id = '019b0000-0000-7000-8000-000000009113'
          AND evidence_snapshot_id = '019b0000-0000-7000-8000-000000009102'
          AND target_ipv4 = '203.0.113.30'
    ) THEN
        RAISE EXCEPTION 'rejected mixed tombstone changed retained evidence';
    END IF;
END
$mixed_action_tombstone_fails_closed$;

DROP TRIGGER "AAA_retention_mixed_action_000029" ON evidence_snapshots;

SELECT set_config(
    'sentinelflow.retention_delete', '000023-retention-v1', true
);
SELECT set_config('sentinelflow.retention_max_rows', '100', true);
SELECT set_config('sentinelflow.retention_deleted_rows', '0', true);
SELECT set_config('sentinelflow.retention_deleted_event', '0', true);
SELECT set_config('sentinelflow.retention_deleted_control', '0', true);
SELECT set_config('sentinelflow.retention_deleted_transient', '0', true);
SELECT set_config('sentinelflow.retention_deleted_audit', '0', true);

DELETE FROM evidence_snapshots
WHERE evidence_snapshot_id = '019b0000-0000-7000-8000-000000009102';

SELECT set_config('sentinelflow.retention_delete', '', true);

DO $retention_preserves_exact_digests$
BEGIN
    IF EXISTS (
        SELECT 1 FROM ai_analyses
        WHERE analysis_id = '019b0000-0000-7000-8000-000000009103'
          AND (evidence_snapshot_id IS NOT NULL OR
               evidence_snapshot_digest <>
               'sha256:1111111111111111111111111111111111111111111111111111111111111111')
    ) OR EXISTS (
        SELECT 1 FROM command_candidates
        WHERE command_candidate_id = '019b0000-0000-7000-8000-000000009104'
          AND (evidence_snapshot_id IS NOT NULL OR
               evidence_snapshot_digest <>
               'sha256:1111111111111111111111111111111111111111111111111111111111111111')
    ) OR EXISTS (
        SELECT 1 FROM policy_proposals
        WHERE policy_id = '019b0000-0000-7000-8000-000000009105'
          AND (evidence_snapshot_id IS NOT NULL OR
               evidence_snapshot_digest <>
               'sha256:1111111111111111111111111111111111111111111111111111111111111111')
    ) OR EXISTS (
        SELECT 1 FROM validation_snapshots
        WHERE validation_snapshot_id = '019b0000-0000-7000-8000-000000009106'
          AND (evidence_snapshot_id IS NOT NULL OR
               evidence_snapshot_digest <>
               'sha256:1111111111111111111111111111111111111111111111111111111111111111')
    ) OR EXISTS (
        SELECT 1 FROM enforcement_actions
        WHERE action_id = '019b0000-0000-7000-8000-000000009113'
          AND (evidence_snapshot_id IS NOT NULL OR
               evidence_snapshot_digest <>
               'sha256:1111111111111111111111111111111111111111111111111111111111111111')
    ) OR EXISTS (
        SELECT 1 FROM analysis_evidence
        WHERE evidence_snapshot_id = '019b0000-0000-7000-8000-000000009102'
    ) THEN
        RAISE EXCEPTION '7-day evidence deletion broke 30-day digest references';
    END IF;
END
$retention_preserves_exact_digests$;

ROLLBACK;
