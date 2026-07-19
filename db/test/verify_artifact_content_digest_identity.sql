BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $schema_contract$
DECLARE
    generated_attnum smallint;
    canonical_attnum smallint;
    nonunique_content_index_count integer;
BEGIN
    SELECT attribute.attnum::smallint
    INTO generated_attnum
    FROM pg_catalog.pg_attribute attribute
    WHERE attribute.attrelid = 'sentinelflow.command_candidates'::regclass
      AND attribute.attname = 'generated_artifact_digest'
      AND NOT attribute.attisdropped;

    SELECT attribute.attnum::smallint
    INTO canonical_attnum
    FROM pg_catalog.pg_attribute attribute
    WHERE attribute.attrelid = 'sentinelflow.command_candidates'::regclass
      AND attribute.attname = 'canonical_artifact_digest'
      AND NOT attribute.attisdropped;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE constraint_record.conrelid = 'sentinelflow.command_candidates'::regclass
          AND constraint_record.contype = 'u'
          AND constraint_record.conkey IN (
              ARRAY[generated_attnum]::smallint[],
              ARRAY[canonical_attnum]::smallint[]
          )
    ) THEN
        RAISE EXCEPTION 'command candidate content digests remain global identities';
    END IF;

    SELECT count(*)
    INTO nonunique_content_index_count
    FROM (VALUES
        (
            'command_candidates_generated_artifact_digest_idx',
            'sentinelflow.command_candidates'::regclass,
            'generated_artifact_digest'
        ),
        (
            'command_candidates_canonical_artifact_digest_idx',
            'sentinelflow.command_candidates'::regclass,
            'canonical_artifact_digest'
        ),
        (
            'enforcement_actions_canonical_artifact_digest_idx',
            'sentinelflow.enforcement_actions'::regclass,
            'canonical_artifact_digest'
        ),
        (
            'lifecycle_inspection_artifact_digest_000031_idx',
            'sentinelflow.lifecycle_inspection_artifacts_000026'::regclass,
            'inspect_artifact_digest'
        )
    ) expected(index_name, table_oid, column_name)
    JOIN pg_catalog.pg_class index_relation
      ON index_relation.relname = expected.index_name
     AND index_relation.relnamespace =
         'sentinelflow'::regnamespace
    JOIN pg_catalog.pg_index index_record
      ON index_record.indexrelid = index_relation.oid
     AND index_record.indrelid = expected.table_oid
     AND index_record.indnkeyatts = 1
     AND NOT index_record.indisunique
     AND index_record.indisvalid
    JOIN pg_catalog.pg_attribute attribute
      ON attribute.attrelid = expected.table_oid
     AND attribute.attname = expected.column_name
     AND NOT attribute.attisdropped
     AND index_record.indkey[0] = attribute.attnum;
    IF nonunique_content_index_count <> 4 OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE (constraint_record.conrelid =
                   'sentinelflow.enforcement_actions'::regclass
               AND constraint_record.conname =
                   'enforcement_actions_canonical_artifact_digest_key') OR
              (constraint_record.conrelid =
                   'sentinelflow.lifecycle_inspection_artifacts_000026'::regclass
               AND constraint_record.conname =
                   'lifecycle_inspection_artifacts_0000_inspect_artifact_digest_key')
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE constraint_record.conrelid =
              'sentinelflow.enforcement_actions'::regclass
          AND constraint_record.conname = 'enforcement_actions_pkey'
          AND constraint_record.contype = 'p'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE constraint_record.conrelid =
              'sentinelflow.enforcement_actions'::regclass
          AND constraint_record.conname =
              'enforcement_actions_policy_id_policy_version_key'
          AND constraint_record.contype = 'u'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE constraint_record.conrelid =
              'sentinelflow.lifecycle_inspection_artifacts_000026'::regclass
          AND constraint_record.conname =
              'lifecycle_inspection_artifacts_000026_pkey'
          AND constraint_record.contype = 'p'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE constraint_record.conrelid =
              'sentinelflow.lifecycle_inspection_artifacts_000026'::regclass
          AND constraint_record.conname =
              'lifecycle_inspection_artifacts_000026_authorization_id_key'
          AND constraint_record.contype = 'u'
    ) THEN
        RAISE EXCEPTION 'content-address indexes or durable identities differ';
    END IF;
END
$schema_contract$;

INSERT INTO incidents (
    incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
    deterministic_score, version
) VALUES
    (
        '019b0000-0000-7000-8000-00000000c101', 'path_scan', 'review_ready',
        '192.0.2.31', 'content-address-test', clock_timestamp(),
        clock_timestamp(), 0.90000, 1
    ),
    (
        '019b0000-0000-7000-8000-00000000c102', 'path_scan', 'review_ready',
        '192.0.2.31', 'content-address-test', clock_timestamp(),
        clock_timestamp(), 0.90000, 1
    );

INSERT INTO evidence_snapshots (
    evidence_snapshot_id, schema_version, incident_id, incident_version,
    source_ip, service_label, window_start, window_end, source_health_status,
    signal_count, expanded_event_count, snapshot_digest, expires_at
) VALUES
    (
        '019b0000-0000-7000-8000-00000000c111', 'evidence-snapshot-v1',
        '019b0000-0000-7000-8000-00000000c101', 1, '192.0.2.31',
        'content-address-test', clock_timestamp(), clock_timestamp(),
        'complete', 1, 1,
        'sha256:c111111111111111111111111111111111111111111111111111111111111111',
        clock_timestamp() + interval '1 day'
    ),
    (
        '019b0000-0000-7000-8000-00000000c112', 'evidence-snapshot-v1',
        '019b0000-0000-7000-8000-00000000c102', 1, '192.0.2.31',
        'content-address-test', clock_timestamp(), clock_timestamp(),
        'complete', 1, 1,
        'sha256:c222222222222222222222222222222222222222222222222222222222222222',
        clock_timestamp() + interval '1 day'
    );

INSERT INTO ai_analyses (
    analysis_id, incident_id, incident_version, evidence_snapshot_id,
    evidence_snapshot_digest, attempt, model, reasoning_effort, store_enabled,
    input_schema_digest, prompt_digest, output_schema_digest, input_digest,
    input_bytes, result_state, output_digest, incident_summary,
    classification, confidence, uncertainty, input_tokens,
    cached_input_tokens, output_tokens, started_at, completed_at
) VALUES
    (
        '019b0000-0000-7000-8000-00000000c121',
        '019b0000-0000-7000-8000-00000000c101', 1,
        '019b0000-0000-7000-8000-00000000c111',
        'sha256:c111111111111111111111111111111111111111111111111111111111111111',
        1, 'gpt-5.6-sol', 'medium', false,
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        'sha256:c121111111111111111111111111111111111111111111111111111111111111',
        128, 'succeeded',
        'sha256:c131111111111111111111111111111111111111111111111111111111111111',
        'Synthetic content-address regression fixture.', 'path_scan',
        0.90000, 'Synthetic fixture only.', 10, 0, 10,
        clock_timestamp(), clock_timestamp()
    ),
    (
        '019b0000-0000-7000-8000-00000000c122',
        '019b0000-0000-7000-8000-00000000c102', 1,
        '019b0000-0000-7000-8000-00000000c112',
        'sha256:c222222222222222222222222222222222222222222222222222222222222222',
        1, 'gpt-5.6-sol', 'medium', false,
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        'sha256:c122222222222222222222222222222222222222222222222222222222222222',
        128, 'succeeded',
        'sha256:c132222222222222222222222222222222222222222222222222222222222222',
        'Synthetic content-address regression fixture.', 'path_scan',
        0.90000, 'Synthetic fixture only.', 10, 0, 10,
        clock_timestamp(), clock_timestamp()
    );

INSERT INTO command_candidates (
    command_candidate_id, schema_version, analysis_id, evidence_snapshot_id,
    evidence_snapshot_digest, target_ipv4, timeout_token, ttl_seconds,
    generated_command, generated_artifact_digest, parse_state,
    canonical_artifact, canonical_artifact_digest
) VALUES
    (
        '019b0000-0000-7000-8000-00000000c131', 'nft-blacklist-v1',
        '019b0000-0000-7000-8000-00000000c121',
        '019b0000-0000-7000-8000-00000000c111',
        'sha256:c111111111111111111111111111111111111111111111111111111111111111',
        '192.0.2.31', '30m', 1800,
        'add element inet sentinelflow blacklist_ipv4 { 192.0.2.31 timeout 30m }',
        'sha256:c141111111111111111111111111111111111111111111111111111111111111',
        'canonical',
        convert_to(E'add element inet sentinelflow blacklist_ipv4 { 192.0.2.31 timeout 30m }\n', 'UTF8'),
        'sha256:c151111111111111111111111111111111111111111111111111111111111111'
    ),
    (
        '019b0000-0000-7000-8000-00000000c132', 'nft-blacklist-v1',
        '019b0000-0000-7000-8000-00000000c122',
        '019b0000-0000-7000-8000-00000000c112',
        'sha256:c222222222222222222222222222222222222222222222222222222222222222',
        '192.0.2.31', '30m', 1800,
        'add element inet sentinelflow blacklist_ipv4 { 192.0.2.31 timeout 30m }',
        'sha256:c141111111111111111111111111111111111111111111111111111111111111',
        'canonical',
        convert_to(E'add element inet sentinelflow blacklist_ipv4 { 192.0.2.31 timeout 30m }\n', 'UTF8'),
        'sha256:c151111111111111111111111111111111111111111111111111111111111111'
    );

DO $shared_content_distinct_bindings$
DECLARE
    violated_constraint text;
BEGIN
    IF (SELECT count(*) FROM command_candidates
        WHERE generated_artifact_digest =
            'sha256:c141111111111111111111111111111111111111111111111111111111111111'
          AND canonical_artifact_digest =
            'sha256:c151111111111111111111111111111111111111111111111111111111111111'
       ) <> 2 OR
       (SELECT count(DISTINCT command_candidate_id) FROM command_candidates
        WHERE generated_artifact_digest =
            'sha256:c141111111111111111111111111111111111111111111111111111111111111'
       ) <> 2 OR
       (SELECT count(DISTINCT analysis_id) FROM command_candidates
        WHERE generated_artifact_digest =
            'sha256:c141111111111111111111111111111111111111111111111111111111111111'
       ) <> 2 OR
       (SELECT count(DISTINCT evidence_snapshot_id) FROM command_candidates
        WHERE generated_artifact_digest =
            'sha256:c141111111111111111111111111111111111111111111111111111111111111'
       ) <> 2 THEN
        RAISE EXCEPTION 'shared content digests lost distinct candidate bindings';
    END IF;

    BEGIN
        UPDATE command_candidates
        SET command_candidate_id =
            '019b0000-0000-7000-8000-00000000c131'
        WHERE command_candidate_id =
            '019b0000-0000-7000-8000-00000000c132';
        RAISE EXCEPTION 'duplicate command candidate primary identity was accepted';
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS violated_constraint = CONSTRAINT_NAME;
        IF violated_constraint <> 'command_candidates_pkey' THEN
            RAISE EXCEPTION 'unexpected identity constraint rejected duplicate: %',
                violated_constraint;
        END IF;
    END;
END
$shared_content_distinct_bindings$;

-- Build two independently bound approved-action fixtures while bypassing the
-- already-covered HIL creation triggers. The enforcement action inserts below
-- run with normal trigger behavior and therefore still exercise the exact
-- authorization/policy/validation/candidate join guard.
SET LOCAL session_replication_role = replica;

INSERT INTO policy_proposals (
    policy_id, version, schema_version, incident_id, incident_version,
    analysis_id, command_candidate_id, evidence_snapshot_id,
    evidence_snapshot_digest, policy_digest, generated_artifact_digest,
    canonical_artifact_digest, target_ipv4, action, ttl_seconds, rationale,
    state
) VALUES
    (
        '019b0000-0000-7000-8000-00000000c141', 1, 'response-policy-v1',
        '019b0000-0000-7000-8000-00000000c101', 1,
        '019b0000-0000-7000-8000-00000000c121',
        '019b0000-0000-7000-8000-00000000c131',
        '019b0000-0000-7000-8000-00000000c111',
        'sha256:c111111111111111111111111111111111111111111111111111111111111111',
        'sha256:c161111111111111111111111111111111111111111111111111111111111111',
        'sha256:c141111111111111111111111111111111111111111111111111111111111111',
        'sha256:c151111111111111111111111111111111111111111111111111111111111111',
        '192.0.2.31', 'block_ip', 1800,
        'Synthetic approved content-address fixture.', 'approved'
    ),
    (
        '019b0000-0000-7000-8000-00000000c142', 1, 'response-policy-v1',
        '019b0000-0000-7000-8000-00000000c102', 1,
        '019b0000-0000-7000-8000-00000000c122',
        '019b0000-0000-7000-8000-00000000c132',
        '019b0000-0000-7000-8000-00000000c112',
        'sha256:c222222222222222222222222222222222222222222222222222222222222222',
        'sha256:c162222222222222222222222222222222222222222222222222222222222222',
        'sha256:c141111111111111111111111111111111111111111111111111111111111111',
        'sha256:c151111111111111111111111111111111111111111111111111111111111111',
        '192.0.2.31', 'block_ip', 1800,
        'Synthetic approved content-address fixture.', 'approved'
    );

INSERT INTO validation_snapshots (
    validation_snapshot_id, schema_version, policy_id, policy_version,
    command_candidate_id, evidence_snapshot_id, snapshot_digest,
    policy_digest, evidence_snapshot_digest, analysis_input_digest,
    analysis_output_schema_digest, prompt_digest, generated_candidate_digest,
    canonical_artifact_digest, grammar_version, parser_version,
    validator_version, base_chain_contract_raw_digest,
    live_owned_schema_digest, protected_ipv4_static_digest,
    protected_ipv4_effective_config_digest, nft_binary_digest, nft_version,
    historical_impact_digest, target_ipv4, ttl_seconds,
    historical_impact_lookback_seconds, state, source_health_status,
    created_at, valid_until
) VALUES
    (
        '019b0000-0000-7000-8000-00000000c151', 'validation-snapshot-v1',
        '019b0000-0000-7000-8000-00000000c141', 1,
        '019b0000-0000-7000-8000-00000000c131',
        '019b0000-0000-7000-8000-00000000c111',
        'sha256:c171111111111111111111111111111111111111111111111111111111111111',
        'sha256:c161111111111111111111111111111111111111111111111111111111111111',
        'sha256:c111111111111111111111111111111111111111111111111111111111111111',
        'sha256:c121111111111111111111111111111111111111111111111111111111111111',
        'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'sha256:c141111111111111111111111111111111111111111111111111111111111111',
        'sha256:c151111111111111111111111111111111111111111111111111111111111111',
        'nft-blacklist-v1', 'parser-v1', 'validator-v1',
        'sha256:d111111111111111111111111111111111111111111111111111111111111111',
        'sha256:d211111111111111111111111111111111111111111111111111111111111111',
        'sha256:d311111111111111111111111111111111111111111111111111111111111111',
        'sha256:d411111111111111111111111111111111111111111111111111111111111111',
        'sha256:d511111111111111111111111111111111111111111111111111111111111111',
        '1.0.0',
        'sha256:d611111111111111111111111111111111111111111111111111111111111111',
        '192.0.2.31', 1800, 86400, 'valid', 'complete',
        clock_timestamp(), clock_timestamp() + interval '4 minutes'
    ),
    (
        '019b0000-0000-7000-8000-00000000c152', 'validation-snapshot-v1',
        '019b0000-0000-7000-8000-00000000c142', 1,
        '019b0000-0000-7000-8000-00000000c132',
        '019b0000-0000-7000-8000-00000000c112',
        'sha256:c172222222222222222222222222222222222222222222222222222222222222',
        'sha256:c162222222222222222222222222222222222222222222222222222222222222',
        'sha256:c222222222222222222222222222222222222222222222222222222222222222',
        'sha256:c122222222222222222222222222222222222222222222222222222222222222',
        'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'sha256:c141111111111111111111111111111111111111111111111111111111111111',
        'sha256:c151111111111111111111111111111111111111111111111111111111111111',
        'nft-blacklist-v1', 'parser-v1', 'validator-v1',
        'sha256:d122222222222222222222222222222222222222222222222222222222222222',
        'sha256:d222222222222222222222222222222222222222222222222222222222222222',
        'sha256:d322222222222222222222222222222222222222222222222222222222222222',
        'sha256:d422222222222222222222222222222222222222222222222222222222222222',
        'sha256:d522222222222222222222222222222222222222222222222222222222222222',
        '1.0.0',
        'sha256:d622222222222222222222222222222222222222222222222222222222222222',
        '192.0.2.31', 1800, 86400, 'valid', 'complete',
        clock_timestamp(), clock_timestamp() + interval '4 minutes'
    );

INSERT INTO enforcement_authorizations (
    authorization_id, schema_version, authorization_kind, action_id,
    policy_id, policy_version, approval_decision_id, decision, target_ipv4,
    policy_digest, generated_artifact_digest, canonical_artifact_digest,
    original_add_digest, evidence_snapshot_digest, validation_snapshot_digest,
    actor_id, hil_reason_digest, decision_nonce_digest,
    idempotency_key_digest, authorization_jcs, authorization_digest,
    decided_at, valid_until
) VALUES
    (
        '019b0000-0000-7000-8000-00000000c161',
        'enforcement-authorization-v1', 'add',
        '019b0000-0000-7000-8000-00000000c171',
        '019b0000-0000-7000-8000-00000000c141', 1,
        '019b0000-0000-7000-8000-00000000c181', 'approve', '192.0.2.31',
        'sha256:c161111111111111111111111111111111111111111111111111111111111111',
        'sha256:c141111111111111111111111111111111111111111111111111111111111111',
        'sha256:c151111111111111111111111111111111111111111111111111111111111111',
        NULL,
        'sha256:c111111111111111111111111111111111111111111111111111111111111111',
        'sha256:c171111111111111111111111111111111111111111111111111111111111111',
        'db-content-test',
        'sha256:e111111111111111111111111111111111111111111111111111111111111111',
        'sha256:e211111111111111111111111111111111111111111111111111111111111111',
        'sha256:e311111111111111111111111111111111111111111111111111111111111111',
        convert_to('{"authorization":"content-one"}', 'UTF8'),
        sentinelflow.hil_sha256(convert_to('{"authorization":"content-one"}', 'UTF8')),
        clock_timestamp(), clock_timestamp() + interval '4 minutes'
    ),
    (
        '019b0000-0000-7000-8000-00000000c162',
        'enforcement-authorization-v1', 'add',
        '019b0000-0000-7000-8000-00000000c172',
        '019b0000-0000-7000-8000-00000000c142', 1,
        '019b0000-0000-7000-8000-00000000c182', 'approve', '192.0.2.31',
        'sha256:c162222222222222222222222222222222222222222222222222222222222222',
        'sha256:c141111111111111111111111111111111111111111111111111111111111111',
        'sha256:c151111111111111111111111111111111111111111111111111111111111111',
        NULL,
        'sha256:c222222222222222222222222222222222222222222222222222222222222222',
        'sha256:c172222222222222222222222222222222222222222222222222222222222222',
        'db-content-test',
        'sha256:e122222222222222222222222222222222222222222222222222222222222222',
        'sha256:e222222222222222222222222222222222222222222222222222222222222222',
        'sha256:e322222222222222222222222222222222222222222222222222222222222222',
        convert_to('{"authorization":"content-two"}', 'UTF8'),
        sentinelflow.hil_sha256(convert_to('{"authorization":"content-two"}', 'UTF8')),
        clock_timestamp(), clock_timestamp() + interval '4 minutes'
    );

SET LOCAL session_replication_role = origin;

INSERT INTO enforcement_actions (
    action_id, policy_id, policy_version, validation_snapshot_id,
    evidence_snapshot_id, evidence_snapshot_digest, command_candidate_id,
    add_authorization_id, target_ipv4, canonical_artifact,
    canonical_artifact_digest, ttl_seconds, state, approved_at
) VALUES
    (
        '019b0000-0000-7000-8000-00000000c171',
        '019b0000-0000-7000-8000-00000000c141', 1,
        '019b0000-0000-7000-8000-00000000c151',
        '019b0000-0000-7000-8000-00000000c111',
        'sha256:c111111111111111111111111111111111111111111111111111111111111111',
        '019b0000-0000-7000-8000-00000000c131',
        '019b0000-0000-7000-8000-00000000c161', '192.0.2.31',
        convert_to(E'add element inet sentinelflow blacklist_ipv4 { 192.0.2.31 timeout 30m }\n', 'UTF8'),
        'sha256:c151111111111111111111111111111111111111111111111111111111111111',
        1800, 'approved', clock_timestamp()
    ),
    (
        '019b0000-0000-7000-8000-00000000c172',
        '019b0000-0000-7000-8000-00000000c142', 1,
        '019b0000-0000-7000-8000-00000000c152',
        '019b0000-0000-7000-8000-00000000c112',
        'sha256:c222222222222222222222222222222222222222222222222222222222222222',
        '019b0000-0000-7000-8000-00000000c132',
        '019b0000-0000-7000-8000-00000000c162', '192.0.2.31',
        convert_to(E'add element inet sentinelflow blacklist_ipv4 { 192.0.2.31 timeout 30m }\n', 'UTF8'),
        'sha256:c151111111111111111111111111111111111111111111111111111111111111',
        1800, 'approved', clock_timestamp()
    );

DO $enforcement_content_distinct_bindings$
DECLARE
    violated_constraint text;
BEGIN
    IF (SELECT count(*) FROM enforcement_actions
        WHERE canonical_artifact_digest =
            'sha256:c151111111111111111111111111111111111111111111111111111111111111'
       ) <> 2 OR
       (SELECT count(DISTINCT action_id) FROM enforcement_actions
        WHERE canonical_artifact_digest =
            'sha256:c151111111111111111111111111111111111111111111111111111111111111'
       ) <> 2 OR
       (SELECT count(DISTINCT (policy_id, policy_version)) FROM enforcement_actions
        WHERE canonical_artifact_digest =
            'sha256:c151111111111111111111111111111111111111111111111111111111111111'
       ) <> 2 OR
       (SELECT count(DISTINCT add_authorization_id) FROM enforcement_actions
        WHERE canonical_artifact_digest =
            'sha256:c151111111111111111111111111111111111111111111111111111111111111'
       ) <> 2 THEN
        RAISE EXCEPTION 'shared action content digest lost exact bindings';
    END IF;

    PERFORM set_config('session_replication_role', 'replica', true);
    BEGIN
        UPDATE enforcement_actions
        SET action_id = '019b0000-0000-7000-8000-00000000c171'
        WHERE action_id = '019b0000-0000-7000-8000-00000000c172';
        RAISE EXCEPTION 'duplicate enforcement action identity was accepted';
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS violated_constraint = CONSTRAINT_NAME;
        IF violated_constraint <> 'enforcement_actions_pkey' THEN
            RAISE EXCEPTION 'unexpected action identity constraint: %',
                violated_constraint;
        END IF;
    END;
    BEGIN
        UPDATE enforcement_actions
        SET policy_id = '019b0000-0000-7000-8000-00000000c141'
        WHERE action_id = '019b0000-0000-7000-8000-00000000c172';
        RAISE EXCEPTION 'duplicate action policy/version binding was accepted';
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS violated_constraint = CONSTRAINT_NAME;
        IF violated_constraint <>
           'enforcement_actions_policy_id_policy_version_key' THEN
            RAISE EXCEPTION 'unexpected action policy constraint: %',
                violated_constraint;
        END IF;
    END;
    PERFORM set_config('session_replication_role', 'origin', true);
END
$enforcement_content_distinct_bindings$;

SET LOCAL session_replication_role = replica;

INSERT INTO lifecycle_inspection_artifacts_000026 (
    schedule_id, authorization_id, dispatch_job_id, inspect_artifact,
    inspect_artifact_digest, authorization_jcs, authorization_digest
) VALUES
    (
        '019b0000-0000-7000-8000-00000000c191',
        '019b0000-0000-7000-8000-00000000c192',
        '019b0000-0000-7000-8000-00000000c193',
        convert_to('{"operation":"inspect"}', 'UTF8'),
        sentinelflow.validation_sha256(convert_to('{"operation":"inspect"}', 'UTF8')),
        convert_to('{"authorization":"inspect-one"}', 'UTF8'),
        sentinelflow.validation_sha256(convert_to('{"authorization":"inspect-one"}', 'UTF8'))
    ),
    (
        '019b0000-0000-7000-8000-00000000c194',
        '019b0000-0000-7000-8000-00000000c195',
        '019b0000-0000-7000-8000-00000000c196',
        convert_to('{"operation":"inspect"}', 'UTF8'),
        sentinelflow.validation_sha256(convert_to('{"operation":"inspect"}', 'UTF8')),
        convert_to('{"authorization":"inspect-two"}', 'UTF8'),
        sentinelflow.validation_sha256(convert_to('{"authorization":"inspect-two"}', 'UTF8'))
    );

DO $inspection_content_distinct_bindings$
DECLARE
    violated_constraint text;
BEGIN
    IF (SELECT count(*) FROM lifecycle_inspection_artifacts_000026
        WHERE inspect_artifact_digest = sentinelflow.validation_sha256(
            convert_to('{"operation":"inspect"}', 'UTF8'))
       ) <> 2 OR
       (SELECT count(DISTINCT schedule_id)
        FROM lifecycle_inspection_artifacts_000026
        WHERE inspect_artifact_digest = sentinelflow.validation_sha256(
            convert_to('{"operation":"inspect"}', 'UTF8'))
       ) <> 2 OR
       (SELECT count(DISTINCT authorization_id)
        FROM lifecycle_inspection_artifacts_000026
        WHERE inspect_artifact_digest = sentinelflow.validation_sha256(
            convert_to('{"operation":"inspect"}', 'UTF8'))
       ) <> 2 THEN
        RAISE EXCEPTION 'shared inspect content digest lost exact bindings';
    END IF;

    BEGIN
        UPDATE lifecycle_inspection_artifacts_000026
        SET authorization_id = '019b0000-0000-7000-8000-00000000c192'
        WHERE schedule_id = '019b0000-0000-7000-8000-00000000c194';
        RAISE EXCEPTION 'duplicate inspection authorization was accepted';
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS violated_constraint = CONSTRAINT_NAME;
        IF violated_constraint <>
           'lifecycle_inspection_artifacts_000026_authorization_id_key' THEN
            RAISE EXCEPTION 'unexpected inspection authorization constraint: %',
                violated_constraint;
        END IF;
    END;

    BEGIN
        INSERT INTO lifecycle_inspection_artifacts_000026 (
            schedule_id, authorization_id, dispatch_job_id, inspect_artifact,
            inspect_artifact_digest, authorization_jcs, authorization_digest
        ) VALUES (
            '019b0000-0000-7000-8000-00000000c197',
            '019b0000-0000-7000-8000-00000000c198',
            '019b0000-0000-7000-8000-00000000c199',
            convert_to('{"operation":"inspect"}', 'UTF8'),
            'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            convert_to('{"authorization":"inspect-bad"}', 'UTF8'),
            sentinelflow.validation_sha256(
                convert_to('{"authorization":"inspect-bad"}', 'UTF8'))
        );
        RAISE EXCEPTION 'incorrect inspect content digest was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$inspection_content_distinct_bindings$;

SET LOCAL session_replication_role = origin;

ROLLBACK;
