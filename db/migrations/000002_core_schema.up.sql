BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $domains$
BEGIN
    IF to_regtype('sentinelflow.sha256_digest') IS NULL THEN
        CREATE DOMAIN sha256_digest AS text
            CHECK (VALUE ~ '^sha256:[0-9a-f]{64}$');
    END IF;
    IF to_regtype('sentinelflow.hmac_sha256_digest') IS NULL THEN
        CREATE DOMAIN hmac_sha256_digest AS text
            CHECK (VALUE ~ '^hmac-sha256:[0-9a-f]{64}$');
    END IF;
    IF to_regtype('sentinelflow.ascii_id') IS NULL THEN
        CREATE DOMAIN ascii_id AS text
            CHECK (VALUE ~ '^[a-z0-9][a-z0-9._-]{0,127}$');
    END IF;
    IF to_regtype('sentinelflow.event_label') IS NULL THEN
        CREATE DOMAIN event_label AS text
            CHECK (VALUE ~ '^[a-z][a-z0-9_-]{0,63}$');
    END IF;
    IF to_regtype('sentinelflow.sender_epoch') IS NULL THEN
        CREATE DOMAIN sender_epoch AS text
            CHECK (VALUE ~ '^[A-Za-z0-9_-]{22}$');
    END IF;
    IF to_regtype('sentinelflow.canonical_ipv4') IS NULL THEN
        CREATE DOMAIN canonical_ipv4 AS inet
            CHECK (family(VALUE) = 4 AND masklen(VALUE) = 32);
    END IF;
    IF to_regtype('sentinelflow.safe_integer') IS NULL THEN
        CREATE DOMAIN safe_integer AS bigint
            CHECK (VALUE BETWEEN 0 AND 9007199254740991);
    END IF;
END
$domains$;

CREATE TABLE IF NOT EXISTS ingest_replay_nonces (
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    endpoint_path text NOT NULL CHECK (endpoint_path IN (
        '/internal/v1/gateway-events', '/internal/v1/auth-events'
    )),
    nonce_digest sha256_digest NOT NULL,
    authenticated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (sender_id, endpoint_kind, endpoint_path, nonce_digest),
    CONSTRAINT ingest_replay_endpoint_binding CHECK (
        (endpoint_kind = 'gateway' AND endpoint_path = '/internal/v1/gateway-events') OR
        (endpoint_kind = 'auth' AND endpoint_path = '/internal/v1/auth-events')
    ),
    CONSTRAINT ingest_replay_security_window CHECK (
        expires_at = authenticated_at + interval '5 minutes'
    )
);

CREATE INDEX IF NOT EXISTS ingest_replay_nonces_expiry_idx
    ON ingest_replay_nonces (expires_at, sender_id, endpoint_path, nonce_digest);

CREATE TABLE IF NOT EXISTS ingest_batches (
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    sender_epoch sender_epoch NOT NULL,
    batch_id uuid NOT NULL,
    sequence safe_integer NOT NULL CHECK (sequence >= 1),
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    schema_version text NOT NULL CHECK (schema_version = 'event-batch-v1'),
    raw_body_digest sha256_digest NOT NULL,
    raw_body_size integer NOT NULL CHECK (raw_body_size BETWEEN 2 AND 262144),
    record_count smallint NOT NULL CHECK (record_count BETWEEN 1 AND 100),
    sent_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    acknowledgement text NOT NULL DEFAULT 'accepted'
        CHECK (acknowledgement IN ('accepted', 'duplicate')),
    PRIMARY KEY (sender_id, sender_epoch, batch_id),
    UNIQUE (sender_id, batch_id),
    UNIQUE (sender_id, sender_epoch, sequence),
    UNIQUE (sender_id, sender_epoch, batch_id, raw_body_digest)
);

CREATE INDEX IF NOT EXISTS ingest_batches_received_at_idx
    ON ingest_batches (received_at);
CREATE INDEX IF NOT EXISTS ingest_batches_sender_sequence_idx
    ON ingest_batches (sender_id, sender_epoch, sequence);

CREATE TABLE IF NOT EXISTS gateway_events (
    event_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'gateway-http-v1'),
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    sender_epoch sender_epoch NOT NULL,
    batch_id uuid NOT NULL,
    idempotency_key sha256_digest NOT NULL UNIQUE,
    request_id uuid NOT NULL UNIQUE,
    trace_id uuid NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    source_ip canonical_ipv4 NOT NULL,
    method varchar(16) NOT NULL CHECK (method ~ '^[A-Z]{1,16}$'),
    protocol text NOT NULL CHECK (protocol = 'HTTP/1.1'),
    route_label event_label NOT NULL,
    path_catalog_version text NOT NULL CHECK (path_catalog_version = 'path-catalog-v1'),
    suspicious_path_id text NOT NULL CHECK (suspicious_path_id IN (
        'none', 'admin_console', 'env_file', 'git_config', 'wp_admin',
        'phpmyadmin', 'server_status', 'actuator_env', 'backup_archive'
    )),
    host varchar(255) NOT NULL CHECK (
        host ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[1-9][0-9]{0,4})?$'
    ),
    service_label event_label NOT NULL,
    status_code smallint NOT NULL CHECK (status_code BETWEEN 100 AND 599),
    request_bytes bigint NOT NULL CHECK (request_bytes BETWEEN 0 AND 10485760),
    response_bytes safe_integer NOT NULL,
    latency_ms integer NOT NULL CHECK (latency_ms BETWEEN 0 AND 30000),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    trust_state text NOT NULL DEFAULT 'trusted'
        CHECK (trust_state IN ('trusted', 'untrusted')),
    trust_reason text NOT NULL DEFAULT 'none'
        CHECK (trust_reason IN ('none', 'timestamp_skew', 'source_degraded', 'batch_conflict')),
    CONSTRAINT gateway_event_time_order CHECK (completed_at >= started_at),
    CONSTRAINT gateway_event_trust_reason CHECK (
        (trust_state = 'trusted' AND trust_reason = 'none') OR
        (trust_state = 'untrusted' AND trust_reason <> 'none')
    ),
    CONSTRAINT gateway_event_batch_fk FOREIGN KEY (sender_id, sender_epoch, batch_id)
        REFERENCES ingest_batches (sender_id, sender_epoch, batch_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX IF NOT EXISTS gateway_events_source_started_idx
    ON gateway_events (source_ip, started_at);
CREATE INDEX IF NOT EXISTS gateway_events_service_started_idx
    ON gateway_events (service_label, started_at);
CREATE INDEX IF NOT EXISTS gateway_events_route_status_started_idx
    ON gateway_events (route_label, status_code, started_at);
CREATE INDEX IF NOT EXISTS gateway_events_suspicious_started_idx
    ON gateway_events (source_ip, suspicious_path_id, started_at)
    WHERE suspicious_path_id <> 'none';
CREATE INDEX IF NOT EXISTS gateway_events_received_at_idx
    ON gateway_events (received_at);
CREATE INDEX IF NOT EXISTS gateway_events_trace_idx
    ON gateway_events (trace_id);

CREATE TABLE IF NOT EXISTS auth_events (
    event_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'auth-event-v1'),
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    sender_epoch sender_epoch NOT NULL,
    batch_id uuid NOT NULL,
    idempotency_key sha256_digest NOT NULL UNIQUE,
    gateway_request_id uuid NOT NULL,
    trace_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    source_ip canonical_ipv4 NOT NULL,
    service_label event_label NOT NULL,
    route_label event_label NOT NULL,
    account_hash hmac_sha256_digest NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('failed', 'succeeded')),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    trust_state text NOT NULL DEFAULT 'trusted'
        CHECK (trust_state IN ('trusted', 'untrusted')),
    trust_reason text NOT NULL DEFAULT 'none'
        CHECK (trust_reason IN ('none', 'timestamp_skew', 'source_degraded', 'batch_conflict')),
    binding_state text NOT NULL DEFAULT 'pending'
        CHECK (binding_state IN ('pending', 'verified', 'untrusted')),
    binding_deadline timestamptz NOT NULL,
    binding_reason text NOT NULL DEFAULT 'awaiting_gateway_event'
        CHECK (binding_reason IN (
            'awaiting_gateway_event', 'verified', 'request_mismatch', 'trace_mismatch',
            'source_mismatch', 'service_mismatch', 'route_mismatch', 'expired'
        )),
    bound_gateway_event_id uuid NULL REFERENCES gateway_events (event_id) ON DELETE SET NULL,
    CONSTRAINT auth_event_batch_fk FOREIGN KEY (sender_id, sender_epoch, batch_id)
        REFERENCES ingest_batches (sender_id, sender_epoch, batch_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT auth_event_trust_reason CHECK (
        (trust_state = 'trusted' AND trust_reason = 'none') OR
        (trust_state = 'untrusted' AND trust_reason <> 'none')
    ),
    CONSTRAINT auth_event_binding CHECK (
        (binding_state = 'pending' AND binding_reason = 'awaiting_gateway_event' AND bound_gateway_event_id IS NULL) OR
        (binding_state = 'verified' AND binding_reason = 'verified' AND bound_gateway_event_id IS NOT NULL) OR
        (binding_state = 'untrusted' AND
            binding_reason NOT IN ('awaiting_gateway_event', 'verified') AND
            bound_gateway_event_id IS NULL)
    ),
    CONSTRAINT auth_event_binding_deadline CHECK (
        binding_deadline >= received_at AND binding_deadline <= received_at + interval '5 minutes'
    )
);

CREATE INDEX IF NOT EXISTS auth_events_source_outcome_binding_idx
    ON auth_events (source_ip, occurred_at, outcome, binding_state);
CREATE INDEX IF NOT EXISTS auth_events_source_account_idx
    ON auth_events (source_ip, account_hash, occurred_at);
CREATE INDEX IF NOT EXISTS auth_events_gateway_request_idx
    ON auth_events (gateway_request_id, trace_id);
CREATE INDEX IF NOT EXISTS auth_events_binding_deadline_idx
    ON auth_events (binding_state, binding_deadline)
    WHERE binding_state = 'pending';
CREATE INDEX IF NOT EXISTS auth_events_received_at_idx
    ON auth_events (received_at);

CREATE TABLE IF NOT EXISTS source_health_intervals (
    event_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'source-health-v1'),
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    sender_epoch sender_epoch NOT NULL,
    batch_id uuid NOT NULL,
    idempotency_key sha256_digest NOT NULL UNIQUE,
    occurred_at timestamptz NOT NULL,
    source_id ascii_id NOT NULL CHECK (length(source_id) <= 64),
    cause text NOT NULL CHECK (cause IN (
        'queue_overflow', 'delivery_outage', 'rejected_batch', 'sequence_gap',
        'permanent_loss', 'unclean_restart', 'unknown_loss', 'recovered'
    )),
    state text NOT NULL CHECK (state IN ('degraded', 'lost', 'recovered')),
    affected_sender_epoch sender_epoch NOT NULL,
    sequence_start safe_integer NULL CHECK (sequence_start IS NULL OR sequence_start >= 1),
    sequence_end safe_integer NULL CHECK (sequence_end IS NULL OR sequence_end >= 1),
    interval_start timestamptz NULL,
    interval_end timestamptz NULL,
    dropped_count safe_integer NOT NULL,
    detail_code text NOT NULL CHECK (detail_code IN (
        'none', 'known_range', 'unknown_range', 'receiver_rejected',
        'sender_restart', 'delivery_restored'
    )),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    trust_state text NOT NULL DEFAULT 'trusted'
        CHECK (trust_state IN ('trusted', 'untrusted')),
    trust_reason text NOT NULL DEFAULT 'none'
        CHECK (trust_reason IN ('none', 'timestamp_skew', 'batch_conflict')),
    CONSTRAINT source_health_batch_fk FOREIGN KEY (sender_id, sender_epoch, batch_id)
        REFERENCES ingest_batches (sender_id, sender_epoch, batch_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT source_health_sequence_order CHECK (
        sequence_start IS NULL OR sequence_end IS NULL OR sequence_end >= sequence_start
    ),
    CONSTRAINT source_health_interval_order CHECK (
        interval_start IS NULL OR interval_end IS NULL OR interval_end >= interval_start
    ),
    CONSTRAINT source_health_trust_reason CHECK (
        (trust_state = 'trusted' AND trust_reason = 'none') OR
        (trust_state = 'untrusted' AND trust_reason <> 'none')
    )
);

CREATE INDEX IF NOT EXISTS source_health_source_interval_idx
    ON source_health_intervals (source_id, interval_start, interval_end);
CREATE INDEX IF NOT EXISTS source_health_epoch_sequence_idx
    ON source_health_intervals (source_id, affected_sender_epoch, sequence_start, sequence_end);
CREATE INDEX IF NOT EXISTS source_health_received_at_idx
    ON source_health_intervals (received_at);

CREATE TABLE IF NOT EXISTS sender_checkpoints (
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    sender_epoch sender_epoch NOT NULL,
    last_acknowledged_sequence safe_integer NOT NULL DEFAULT 0,
    last_acknowledged_body_digest sha256_digest NULL,
    clean_shutdown boolean NOT NULL DEFAULT false,
    unknown_loss boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (sender_id, endpoint_kind),
    CONSTRAINT sender_checkpoint_ack CHECK (
        (last_acknowledged_sequence = 0 AND last_acknowledged_body_digest IS NULL) OR
        (last_acknowledged_sequence >= 1 AND last_acknowledged_body_digest IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS sender_checkpoints_updated_at_idx
    ON sender_checkpoints (updated_at);

CREATE TABLE IF NOT EXISTS outbox_jobs (
    job_id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN (
        'detect', 'correlate', 'analyze', 'validate',
        'dispatch_add', 'dispatch_revoke', 'dispatch_inspect',
        'reconcile', 'retention', 'audit_recovery'
    )),
    aggregate_type ascii_id NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version integer NOT NULL CHECK (aggregate_version >= 1),
    operation text NULL CHECK (operation IS NULL OR operation IN ('add', 'revoke', 'inspect')),
    idempotency_key sha256_digest NOT NULL UNIQUE,
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'leased', 'retry', 'completed', 'dead')),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_token uuid NULL,
    lease_owner ascii_id NULL,
    lease_expires_at timestamptz NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer NOT NULL DEFAULT 8 CHECK (max_attempts BETWEEN 1 AND 100),
    last_error_code ascii_id NULL,
    last_error_digest sha256_digest NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT outbox_operation_kind CHECK (
        (kind = 'dispatch_add' AND operation = 'add') OR
        (kind = 'dispatch_revoke' AND operation = 'revoke') OR
        (kind = 'dispatch_inspect' AND operation = 'inspect') OR
        (kind NOT IN ('dispatch_add', 'dispatch_revoke', 'dispatch_inspect') AND operation IS NULL)
    ),
    CONSTRAINT outbox_lease_shape CHECK (
        (state = 'leased' AND lease_token IS NOT NULL AND lease_owner IS NOT NULL AND
            lease_expires_at IS NOT NULL AND lease_expires_at > updated_at AND
            lease_expires_at <= updated_at + interval '60 seconds') OR
        (state <> 'leased' AND lease_token IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL)
    ),
    CONSTRAINT outbox_error_shape CHECK (
        (state IN ('retry', 'dead') AND last_error_code IS NOT NULL AND last_error_digest IS NOT NULL) OR
        (state = 'completed' AND last_error_code IS NULL AND last_error_digest IS NULL) OR
        state IN ('pending', 'leased')
    ),
    CONSTRAINT outbox_retry_time CHECK (state <> 'retry' OR available_at >= updated_at),
    CONSTRAINT outbox_attempt_bound CHECK (attempts <= max_attempts),
    CONSTRAINT outbox_time_order CHECK (updated_at >= created_at)
);

CREATE INDEX IF NOT EXISTS outbox_jobs_available_idx
    ON outbox_jobs (state, available_at, created_at)
    WHERE state IN ('pending', 'retry');
CREATE INDEX IF NOT EXISTS outbox_jobs_lease_expiry_idx
    ON outbox_jobs (lease_expires_at)
    WHERE state = 'leased';
CREATE INDEX IF NOT EXISTS outbox_jobs_aggregate_idx
    ON outbox_jobs (aggregate_type, aggregate_id, aggregate_version);

CREATE TABLE IF NOT EXISTS dead_letter_jobs (
    job_id uuid PRIMARY KEY REFERENCES outbox_jobs (job_id) ON DELETE RESTRICT,
    kind text NOT NULL,
    aggregate_type ascii_id NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version integer NOT NULL CHECK (aggregate_version >= 1),
    attempts integer NOT NULL CHECK (attempts >= 1),
    failure_code ascii_id NOT NULL,
    failure_digest sha256_digest NOT NULL,
    dead_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    resolution_state text NOT NULL DEFAULT 'unresolved'
        CHECK (resolution_state IN ('unresolved', 'acknowledged', 'requeued', 'resolved')),
    resolved_at timestamptz NULL,
    resolution_actor ascii_id NULL,
    resolution_digest sha256_digest NULL,
    CONSTRAINT dead_letter_resolution CHECK (
        (resolution_state = 'unresolved' AND resolved_at IS NULL AND resolution_actor IS NULL AND resolution_digest IS NULL) OR
        (resolution_state <> 'unresolved' AND resolved_at IS NOT NULL AND resolution_actor IS NOT NULL AND resolution_digest IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS dead_letter_jobs_state_dead_at_idx
    ON dead_letter_jobs (resolution_state, dead_at);

CREATE TABLE IF NOT EXISTS signals (
    signal_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'signal-v1'),
    rule_id ascii_id NOT NULL,
    rule_version integer NOT NULL CHECK (rule_version >= 1),
    kind text NOT NULL CHECK (kind IN ('path_scan', 'request_burst', 'brute_force', 'credential_stuffing')),
    source_ip canonical_ipv4 NOT NULL,
    service_label event_label NOT NULL,
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    observed_count integer NOT NULL CHECK (observed_count >= 1),
    distinct_count integer NULL CHECK (distinct_count IS NULL OR distinct_count >= 1),
    threshold_count integer NOT NULL CHECK (threshold_count >= 1),
    threshold_distinct integer NULL CHECK (threshold_distinct IS NULL OR threshold_distinct >= 1),
    source_health_status text NOT NULL CHECK (source_health_status IN ('complete', 'incomplete')),
    evidence_digest sha256_digest NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT signal_window_order CHECK (window_end >= window_start),
    UNIQUE (rule_id, rule_version, source_ip, service_label, window_start, window_end, evidence_digest)
);

CREATE INDEX IF NOT EXISTS signals_source_window_idx
    ON signals (source_ip, service_label, window_start, window_end);
CREATE INDEX IF NOT EXISTS signals_created_at_idx
    ON signals (created_at);

CREATE TABLE IF NOT EXISTS signal_evidence (
    evidence_link_id uuid PRIMARY KEY,
    signal_id uuid NOT NULL REFERENCES signals (signal_id) ON DELETE CASCADE,
    event_kind text NOT NULL CHECK (event_kind IN ('gateway', 'auth', 'source_health')),
    gateway_event_id uuid NULL REFERENCES gateway_events (event_id) ON DELETE CASCADE,
    auth_event_id uuid NULL REFERENCES auth_events (event_id) ON DELETE CASCADE,
    source_health_event_id uuid NULL REFERENCES source_health_intervals (event_id) ON DELETE CASCADE,
    event_time timestamptz NOT NULL,
    relation_reason ascii_id NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT signal_evidence_one_event CHECK (
        num_nonnulls(gateway_event_id, auth_event_id, source_health_event_id) = 1
    ),
    CONSTRAINT signal_evidence_kind CHECK (
        (event_kind = 'gateway' AND gateway_event_id IS NOT NULL) OR
        (event_kind = 'auth' AND auth_event_id IS NOT NULL) OR
        (event_kind = 'source_health' AND source_health_event_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS signal_evidence_gateway_unique_idx
    ON signal_evidence (signal_id, gateway_event_id)
    WHERE gateway_event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS signal_evidence_auth_unique_idx
    ON signal_evidence (signal_id, auth_event_id)
    WHERE auth_event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS signal_evidence_health_unique_idx
    ON signal_evidence (signal_id, source_health_event_id)
    WHERE source_health_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS signal_evidence_event_time_idx
    ON signal_evidence (event_time);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN (
        'credential_stuffing', 'brute_force', 'path_scan', 'request_burst', 'mixed', 'unknown'
    )),
    state text NOT NULL CHECK (state IN ('open', 'analyzing', 'review_ready', 'analysis_failed', 'closed')),
    source_ip canonical_ipv4 NOT NULL,
    service_label event_label NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    closed_at timestamptz NULL,
    reopen_until timestamptz NULL,
    deterministic_score numeric(6,5) NOT NULL CHECK (deterministic_score BETWEEN 0 AND 1),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    analysis_failure_reason text NULL CHECK (analysis_failure_reason IS NULL OR analysis_failure_reason IN (
        'budget_exhausted', 'input_too_large', 'network_error', 'http_408', 'http_409',
        'rate_limited', 'server_error', 'timeout', 'refused', 'incomplete', 'schema_invalid',
        'evidence_invalid', 'unsupported_action', 'cancelled', 'configuration_error'
    )),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT incident_time_order CHECK (last_seen >= first_seen),
    CONSTRAINT incident_closed_shape CHECK (
        (state = 'closed' AND closed_at IS NOT NULL AND reopen_until IS NOT NULL AND reopen_until >= closed_at) OR
        (state <> 'closed' AND closed_at IS NULL AND reopen_until IS NULL)
    ),
    CONSTRAINT incident_failure_shape CHECK (
        (state = 'analysis_failed' AND analysis_failure_reason IS NOT NULL) OR
        (state <> 'analysis_failed' AND analysis_failure_reason IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS incidents_state_last_seen_idx
    ON incidents (state, last_seen);
CREATE INDEX IF NOT EXISTS incidents_source_service_last_seen_idx
    ON incidents (source_ip, service_label, last_seen);
CREATE INDEX IF NOT EXISTS incidents_created_at_idx
    ON incidents (created_at);

CREATE TABLE IF NOT EXISTS incident_signals (
    incident_id uuid NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    signal_id uuid NOT NULL REFERENCES signals (signal_id) ON DELETE CASCADE,
    incident_version integer NOT NULL CHECK (incident_version >= 1),
    relation_reason text NOT NULL CHECK (relation_reason IN ('same_source_overlap', 'same_source_reopen')),
    linked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (incident_id, signal_id),
    UNIQUE (signal_id)
);

CREATE INDEX IF NOT EXISTS incident_signals_linked_at_idx
    ON incident_signals (linked_at);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_event_id uuid PRIMARY KEY,
    incident_id uuid NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    incident_version integer NOT NULL CHECK (incident_version >= 1),
    event_kind text NOT NULL CHECK (event_kind IN ('gateway', 'auth', 'source_health')),
    gateway_event_id uuid NULL REFERENCES gateway_events (event_id) ON DELETE CASCADE,
    auth_event_id uuid NULL REFERENCES auth_events (event_id) ON DELETE CASCADE,
    source_health_event_id uuid NULL REFERENCES source_health_intervals (event_id) ON DELETE CASCADE,
    relation_reason ascii_id NOT NULL,
    linked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT incident_event_one_event CHECK (
        num_nonnulls(gateway_event_id, auth_event_id, source_health_event_id) = 1
    ),
    CONSTRAINT incident_event_kind CHECK (
        (event_kind = 'gateway' AND gateway_event_id IS NOT NULL) OR
        (event_kind = 'auth' AND auth_event_id IS NOT NULL) OR
        (event_kind = 'source_health' AND source_health_event_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS incident_events_gateway_unique_idx
    ON incident_events (incident_id, gateway_event_id)
    WHERE gateway_event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS incident_events_auth_unique_idx
    ON incident_events (incident_id, auth_event_id)
    WHERE auth_event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS incident_events_health_unique_idx
    ON incident_events (incident_id, source_health_event_id)
    WHERE source_health_event_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS evidence_snapshots (
    evidence_snapshot_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'evidence-snapshot-v1'),
    incident_id uuid NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    incident_version integer NOT NULL CHECK (incident_version >= 1),
    source_ip canonical_ipv4 NOT NULL,
    service_label event_label NOT NULL,
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    source_health_status text NOT NULL CHECK (source_health_status IN ('complete', 'incomplete')),
    signal_count smallint NOT NULL CHECK (signal_count BETWEEN 1 AND 50),
    expanded_event_count integer NOT NULL CHECK (expanded_event_count >= 1),
    snapshot_digest sha256_digest NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT evidence_snapshot_window CHECK (window_end >= window_start),
    CONSTRAINT evidence_snapshot_expiry CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS evidence_snapshots_incident_version_idx
    ON evidence_snapshots (incident_id, incident_version);
CREATE INDEX IF NOT EXISTS evidence_snapshots_expires_at_idx
    ON evidence_snapshots (expires_at);

CREATE TABLE IF NOT EXISTS evidence_snapshot_signals (
    evidence_snapshot_id uuid NOT NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE CASCADE,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 50),
    signal_id uuid NOT NULL REFERENCES signals (signal_id) ON DELETE CASCADE,
    evidence_id ascii_id NOT NULL,
    evidence_digest sha256_digest NOT NULL,
    expanded_event_count integer NOT NULL CHECK (expanded_event_count >= 1),
    PRIMARY KEY (evidence_snapshot_id, ordinal),
    UNIQUE (evidence_snapshot_id, signal_id),
    UNIQUE (evidence_snapshot_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS evidence_snapshot_events (
    evidence_snapshot_event_id uuid PRIMARY KEY,
    evidence_snapshot_id uuid NOT NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE CASCADE,
    signal_id uuid NOT NULL REFERENCES signals (signal_id) ON DELETE CASCADE,
    event_kind text NOT NULL CHECK (event_kind IN ('gateway', 'auth', 'source_health')),
    gateway_event_id uuid NULL REFERENCES gateway_events (event_id) ON DELETE CASCADE,
    auth_event_id uuid NULL REFERENCES auth_events (event_id) ON DELETE CASCADE,
    source_health_event_id uuid NULL REFERENCES source_health_intervals (event_id) ON DELETE CASCADE,
    event_time timestamptz NOT NULL,
    CONSTRAINT snapshot_event_one_event CHECK (
        num_nonnulls(gateway_event_id, auth_event_id, source_health_event_id) = 1
    ),
    CONSTRAINT snapshot_event_kind CHECK (
        (event_kind = 'gateway' AND gateway_event_id IS NOT NULL) OR
        (event_kind = 'auth' AND auth_event_id IS NOT NULL) OR
        (event_kind = 'source_health' AND source_health_event_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS evidence_snapshot_events_snapshot_signal_idx
    ON evidence_snapshot_events (evidence_snapshot_id, signal_id, event_time);
CREATE INDEX IF NOT EXISTS evidence_snapshot_events_event_time_idx
    ON evidence_snapshot_events (event_time);

CREATE TABLE IF NOT EXISTS ai_analyses (
    analysis_id uuid PRIMARY KEY,
    incident_id uuid NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    incident_version integer NOT NULL CHECK (incident_version >= 1),
    evidence_snapshot_id uuid NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE SET NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 2),
    model ascii_id NOT NULL,
    reasoning_effort text NOT NULL CHECK (reasoning_effort = 'medium'),
    store_enabled boolean NOT NULL CHECK (store_enabled = false),
    input_schema_digest sha256_digest NOT NULL,
    prompt_digest sha256_digest NOT NULL,
    output_schema_digest sha256_digest NOT NULL,
    input_digest sha256_digest NOT NULL,
    input_bytes integer NOT NULL CHECK (input_bytes BETWEEN 2 AND 12288),
    result_state text NOT NULL CHECK (result_state IN ('started', 'succeeded', 'failed')),
    failure_reason text NULL CHECK (failure_reason IS NULL OR failure_reason IN (
        'budget_exhausted', 'input_too_large', 'network_error', 'http_408', 'http_409',
        'rate_limited', 'server_error', 'timeout', 'refused', 'incomplete', 'schema_invalid',
        'evidence_invalid', 'unsupported_action', 'cancelled', 'configuration_error'
    )),
    output_digest sha256_digest NULL,
    incident_summary varchar(1600) NULL,
    classification text NULL CHECK (classification IS NULL OR classification IN (
        'credential_stuffing', 'brute_force', 'path_scan', 'request_burst', 'mixed', 'unknown'
    )),
    confidence numeric(6,5) NULL CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    uncertainty varchar(800) NULL,
    input_tokens integer NULL CHECK (input_tokens IS NULL OR input_tokens >= 0),
    cached_input_tokens integer NULL CHECK (cached_input_tokens IS NULL OR cached_input_tokens >= 0),
    output_tokens integer NULL CHECK (output_tokens IS NULL OR output_tokens BETWEEN 0 AND 2048),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz NULL,
    CONSTRAINT ai_analysis_result_shape CHECK (
        (result_state = 'started' AND failure_reason IS NULL AND output_digest IS NULL AND completed_at IS NULL) OR
        (result_state = 'failed' AND failure_reason IS NOT NULL AND completed_at IS NOT NULL) OR
        (result_state = 'succeeded' AND failure_reason IS NULL AND output_digest IS NOT NULL AND
            incident_summary IS NOT NULL AND classification IS NOT NULL AND confidence IS NOT NULL AND
            uncertainty IS NOT NULL AND completed_at IS NOT NULL)
    ),
    CONSTRAINT ai_analysis_time_order CHECK (completed_at IS NULL OR completed_at >= started_at),
    UNIQUE (incident_id, incident_version, attempt)
);

CREATE INDEX IF NOT EXISTS ai_analyses_incident_version_idx
    ON ai_analyses (incident_id, incident_version, attempt);
CREATE INDEX IF NOT EXISTS ai_analyses_started_at_idx
    ON ai_analyses (started_at);

CREATE TABLE IF NOT EXISTS analysis_false_positive_factors (
    analysis_id uuid NOT NULL REFERENCES ai_analyses (analysis_id) ON DELETE CASCADE,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 5),
    factor varchar(240) NOT NULL CHECK (length(factor) >= 1),
    PRIMARY KEY (analysis_id, ordinal)
);

CREATE TABLE IF NOT EXISTS analysis_evidence (
    analysis_id uuid NOT NULL REFERENCES ai_analyses (analysis_id) ON DELETE CASCADE,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 50),
    evidence_snapshot_id uuid NOT NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE CASCADE,
    signal_id uuid NOT NULL REFERENCES signals (signal_id) ON DELETE CASCADE,
    evidence_id ascii_id NOT NULL,
    PRIMARY KEY (analysis_id, ordinal),
    UNIQUE (analysis_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS command_candidates (
    command_candidate_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'nft-blacklist-v1'),
    analysis_id uuid NOT NULL UNIQUE REFERENCES ai_analyses (analysis_id) ON DELETE RESTRICT,
    evidence_snapshot_id uuid NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE SET NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    target_ipv4 canonical_ipv4 NOT NULL,
    timeout_token varchar(8) NOT NULL CHECK (timeout_token ~ '^[1-9][0-9]{0,4}[smh]$'),
    ttl_seconds integer NOT NULL CHECK (ttl_seconds BETWEEN 60 AND 86400),
    generated_command varchar(256) NOT NULL CHECK (length(generated_command) >= 1),
    generated_artifact_digest sha256_digest NOT NULL,
    parse_state text NOT NULL CHECK (parse_state IN ('generated', 'parsing', 'canonical', 'invalid', 'validating', 'valid', 'stale')),
    parse_error_code ascii_id NULL,
    canonical_artifact bytea NULL,
    canonical_artifact_digest sha256_digest NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT candidate_canonical_shape CHECK (
        (parse_state IN ('canonical', 'validating', 'valid', 'stale') AND
            canonical_artifact IS NOT NULL AND canonical_artifact_digest IS NOT NULL AND parse_error_code IS NULL) OR
        (parse_state = 'invalid' AND parse_error_code IS NOT NULL) OR
        (parse_state IN ('generated', 'parsing') AND canonical_artifact IS NULL AND canonical_artifact_digest IS NULL)
    ),
    CONSTRAINT candidate_time_order CHECK (updated_at >= created_at),
    UNIQUE (generated_artifact_digest),
    UNIQUE (canonical_artifact_digest)
);

CREATE INDEX IF NOT EXISTS command_candidates_created_at_idx
    ON command_candidates (created_at);

CREATE TABLE IF NOT EXISTS policy_proposals (
    policy_id uuid NOT NULL,
    version integer NOT NULL CHECK (version >= 1),
    schema_version text NOT NULL CHECK (schema_version = 'response-policy-v1'),
    incident_id uuid NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    incident_version integer NOT NULL CHECK (incident_version >= 1),
    analysis_id uuid NOT NULL REFERENCES ai_analyses (analysis_id) ON DELETE RESTRICT,
    command_candidate_id uuid NOT NULL REFERENCES command_candidates (command_candidate_id) ON DELETE RESTRICT,
    evidence_snapshot_id uuid NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE SET NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    policy_digest sha256_digest NOT NULL UNIQUE,
    generated_artifact_digest sha256_digest NOT NULL,
    canonical_artifact_digest sha256_digest NOT NULL,
    target_ipv4 canonical_ipv4 NOT NULL,
    action text NOT NULL CHECK (action = 'block_ip'),
    ttl_seconds integer NOT NULL CHECK (ttl_seconds BETWEEN 60 AND 86400),
    rationale varchar(800) NOT NULL CHECK (length(rationale) >= 1),
    state text NOT NULL CHECK (state IN (
        'draft', 'validating', 'valid', 'invalid', 'stale', 'approved', 'rejected',
        'queued', 'active', 'expired', 'failed', 'revoked', 'indeterminate'
    )),
    state_revision bigint NOT NULL DEFAULT 1 CHECK (state_revision >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (policy_id, version),
    UNIQUE (analysis_id, command_candidate_id),
    CONSTRAINT policy_time_order CHECK (updated_at >= created_at)
);

ALTER TABLE policy_proposals
    ADD COLUMN IF NOT EXISTS state_revision bigint NOT NULL DEFAULT 1
        CHECK (state_revision >= 1);

CREATE INDEX IF NOT EXISTS policy_proposals_incident_idx
    ON policy_proposals (incident_id, incident_version);
CREATE INDEX IF NOT EXISTS policy_proposals_state_updated_idx
    ON policy_proposals (state, updated_at);
CREATE INDEX IF NOT EXISTS policy_proposals_created_at_idx
    ON policy_proposals (created_at);

CREATE TABLE IF NOT EXISTS validation_snapshots (
    validation_snapshot_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'validation-snapshot-v1'),
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL,
    command_candidate_id uuid NOT NULL REFERENCES command_candidates (command_candidate_id) ON DELETE RESTRICT,
    evidence_snapshot_id uuid NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE SET NULL,
    snapshot_digest sha256_digest NOT NULL UNIQUE,
    policy_digest sha256_digest NOT NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    analysis_input_digest sha256_digest NOT NULL,
    analysis_output_schema_digest sha256_digest NOT NULL,
    prompt_digest sha256_digest NOT NULL,
    generated_candidate_digest sha256_digest NOT NULL,
    canonical_artifact_digest sha256_digest NOT NULL,
    grammar_version text NOT NULL CHECK (grammar_version = 'nft-blacklist-v1'),
    parser_version event_label NOT NULL,
    validator_version event_label NOT NULL,
    base_chain_contract_raw_digest sha256_digest NOT NULL,
    live_owned_schema_digest sha256_digest NOT NULL,
    protected_ipv4_static_digest sha256_digest NOT NULL,
    protected_ipv4_effective_config_digest sha256_digest NOT NULL,
    nft_binary_digest sha256_digest NOT NULL,
    nft_version text NOT NULL CHECK (
        nft_version ~ '^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9._-]+)?$'
    ),
    historical_impact_digest sha256_digest NOT NULL,
    history_dataset_digest sha256_digest NULL,
    history_manifest_digest sha256_digest NULL,
    target_ipv4 canonical_ipv4 NOT NULL,
    ttl_seconds integer NOT NULL CHECK (ttl_seconds BETWEEN 60 AND 86400),
    historical_impact_lookback_seconds integer NOT NULL CHECK (historical_impact_lookback_seconds = 86400),
    state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'valid', 'invalid', 'stale')),
    failure_code ascii_id NULL,
    source_health_status text NOT NULL CHECK (source_health_status IN ('complete', 'incomplete')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NOT NULL,
    CONSTRAINT validation_policy_fk FOREIGN KEY (policy_id, policy_version)
        REFERENCES policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT validation_validity CHECK (
        valid_until > created_at AND valid_until <= created_at + interval '5 minutes'
    ),
    CONSTRAINT validation_state_shape CHECK (
        (state = 'valid' AND failure_code IS NULL AND source_health_status = 'complete') OR
        (state = 'invalid' AND failure_code IS NOT NULL) OR
        (state IN ('draft', 'stale'))
    )
);

CREATE INDEX IF NOT EXISTS validation_snapshots_policy_idx
    ON validation_snapshots (policy_id, policy_version, created_at DESC);
CREATE INDEX IF NOT EXISTS validation_snapshots_valid_until_idx
    ON validation_snapshots (state, valid_until);
CREATE INDEX IF NOT EXISTS validation_snapshots_created_at_idx
    ON validation_snapshots (created_at);

CREATE TABLE IF NOT EXISTS validation_gates (
    validation_snapshot_id uuid NOT NULL REFERENCES validation_snapshots (validation_snapshot_id) ON DELETE CASCADE,
    gate_order smallint NOT NULL CHECK (gate_order BETWEEN 1 AND 6),
    gate_name text NOT NULL CHECK (gate_name IN (
        'structured_output', 'command_grammar', 'policy_evidence_command_consistency',
        'protected_network', 'owned_schema_syntax', 'historical_impact'
    )),
    passed boolean NOT NULL,
    result_code ascii_id NOT NULL,
    input_digest sha256_digest NOT NULL,
    result_digest sha256_digest NOT NULL,
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (validation_snapshot_id, gate_order),
    UNIQUE (validation_snapshot_id, gate_name)
);

CREATE INDEX IF NOT EXISTS validation_gates_checked_at_idx
    ON validation_gates (checked_at);

CREATE TABLE IF NOT EXISTS admin_sessions (
    session_id uuid PRIMARY KEY,
    actor_id ascii_id NOT NULL,
    token_digest sha256_digest NOT NULL UNIQUE,
    csrf_digest sha256_digest NOT NULL,
    authenticated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    rotation_parent_id uuid NULL REFERENCES admin_sessions (session_id) ON DELETE RESTRICT,
    CONSTRAINT admin_session_time_order CHECK (
        authenticated_at <= created_at AND last_seen_at >= created_at AND
        expires_at > created_at AND expires_at <= created_at + interval '8 hours' AND
        (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

CREATE INDEX IF NOT EXISTS admin_sessions_actor_expiry_idx
    ON admin_sessions (actor_id, expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS admin_sessions_expires_at_idx
    ON admin_sessions (expires_at);

CREATE TABLE IF NOT EXISTS decision_challenges (
    challenge_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'hil-challenge-v1'),
    nonce_digest sha256_digest NOT NULL UNIQUE,
    session_id uuid NOT NULL REFERENCES admin_sessions (session_id) ON DELETE RESTRICT,
    session_digest sha256_digest NOT NULL,
    actor_id ascii_id NOT NULL,
    operation text NOT NULL CHECK (operation IN ('approve', 'reject', 'revoke')),
    resource_type text NOT NULL CHECK (resource_type IN ('policy', 'enforcement_action')),
    resource_id uuid NOT NULL,
    resource_version integer NOT NULL CHECK (resource_version >= 1),
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version >= 1),
    action_id uuid NULL,
    target_ipv4 canonical_ipv4 NOT NULL,
    policy_digest sha256_digest NOT NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    generated_artifact_digest sha256_digest NOT NULL,
    canonical_artifact_digest sha256_digest NOT NULL,
    original_add_digest sha256_digest NULL,
    validation_snapshot_digest sha256_digest NOT NULL,
    validation_valid_until timestamptz NOT NULL,
    idempotency_key_digest sha256_digest NOT NULL UNIQUE,
    authenticated_at timestamptz NOT NULL,
    reauth_required_after_seconds integer NOT NULL DEFAULT 900
        CHECK (reauth_required_after_seconds = 900),
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    consumed_decision_id uuid NULL,
    CONSTRAINT decision_challenge_policy_fk FOREIGN KEY (policy_id, policy_version)
        REFERENCES policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT decision_challenge_validity CHECK (
        issued_at >= authenticated_at AND
        issued_at <= authenticated_at + interval '15 minutes' AND
        expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'
    ),
    CONSTRAINT decision_challenge_consumption CHECK (
        (consumed_at IS NULL AND consumed_decision_id IS NULL) OR
        (consumed_at IS NOT NULL AND consumed_decision_id IS NOT NULL AND consumed_at <= expires_at)
    ),
    CONSTRAINT decision_challenge_operation CHECK (
        (operation IN ('approve', 'reject') AND resource_type = 'policy' AND
            resource_id = policy_id AND resource_version = policy_version AND
            action_id IS NULL AND original_add_digest IS NULL) OR
        (operation = 'revoke' AND resource_type = 'enforcement_action' AND
            action_id IS NOT NULL AND resource_id = action_id AND original_add_digest IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS decision_challenges_session_expiry_idx
    ON decision_challenges (session_id, expires_at)
    WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS decision_challenges_resource_idx
    ON decision_challenges (resource_type, resource_id, resource_version);

CREATE TABLE IF NOT EXISTS hil_reasons (
    reason_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'hil-reason-v1'),
    actor_id ascii_id NOT NULL,
    operation text NOT NULL CHECK (operation IN ('approve', 'reject', 'revoke')),
    normalized_reason varchar(800) NOT NULL CHECK (
        length(normalized_reason) BETWEEN 1 AND 800 AND
        normalized_reason !~ '[[:cntrl:]]'
    ),
    reason_digest sha256_digest NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS hil_reasons_created_at_idx
    ON hil_reasons (created_at);

CREATE TABLE IF NOT EXISTS approval_decisions (
    decision_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'hil-decision-v1'),
    challenge_id uuid NOT NULL UNIQUE REFERENCES decision_challenges (challenge_id) ON DELETE RESTRICT,
    session_digest sha256_digest NOT NULL,
    operation text NOT NULL CHECK (operation IN ('approve', 'reject', 'revoke')),
    decision text NOT NULL CHECK (decision IN ('approved', 'rejected', 'revoked')),
    resource_type text NOT NULL CHECK (resource_type IN ('policy', 'enforcement_action')),
    resource_id uuid NOT NULL,
    resource_version integer NOT NULL CHECK (resource_version >= 1),
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version >= 1),
    action_id uuid NULL,
    target_ipv4 canonical_ipv4 NOT NULL,
    validation_snapshot_id uuid NOT NULL REFERENCES validation_snapshots (validation_snapshot_id) ON DELETE RESTRICT,
    policy_digest sha256_digest NOT NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    generated_artifact_digest sha256_digest NOT NULL,
    canonical_artifact_digest sha256_digest NOT NULL,
    original_add_digest sha256_digest NULL,
    validation_snapshot_digest sha256_digest NOT NULL,
    actor_id ascii_id NOT NULL,
    reason_id uuid NOT NULL REFERENCES hil_reasons (reason_id) ON DELETE RESTRICT,
    reason_digest sha256_digest NOT NULL,
    challenge_nonce_digest sha256_digest NOT NULL,
    idempotency_key_digest sha256_digest NOT NULL UNIQUE,
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    decision_valid_until timestamptz NOT NULL,
    CONSTRAINT approval_decision_policy_fk FOREIGN KEY (policy_id, policy_version)
        REFERENCES policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT approval_decision_validity CHECK (
        decision_valid_until > decided_at AND decision_valid_until <= decided_at + interval '5 minutes'
    ),
    CONSTRAINT approval_decision_operation CHECK (
        (operation = 'approve' AND decision = 'approved' AND resource_type = 'policy' AND
            resource_id = policy_id AND resource_version = policy_version AND
            action_id IS NULL AND original_add_digest IS NULL) OR
        (operation = 'reject' AND decision = 'rejected' AND resource_type = 'policy' AND
            resource_id = policy_id AND resource_version = policy_version AND
            action_id IS NULL AND original_add_digest IS NULL) OR
        (operation = 'revoke' AND decision = 'revoked' AND resource_type = 'enforcement_action' AND
            action_id IS NOT NULL AND resource_id = action_id AND original_add_digest IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS approval_decisions_policy_idx
    ON approval_decisions (policy_id, policy_version, decided_at);
CREATE INDEX IF NOT EXISTS approval_decisions_action_idx
    ON approval_decisions (action_id, decided_at)
    WHERE action_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS approval_decisions_decided_at_idx
    ON approval_decisions (decided_at);
CREATE UNIQUE INDEX IF NOT EXISTS approval_decisions_policy_final_idx
    ON approval_decisions (policy_id, policy_version)
    WHERE operation IN ('approve', 'reject');
CREATE UNIQUE INDEX IF NOT EXISTS approval_decisions_revoke_final_idx
    ON approval_decisions (action_id, resource_version)
    WHERE operation = 'revoke';

DO $challenge_decision_fk$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.decision_challenges'::regclass
          AND conname = 'decision_challenge_consumed_decision_fk'
    ) THEN
        ALTER TABLE decision_challenges
            ADD CONSTRAINT decision_challenge_consumed_decision_fk
            FOREIGN KEY (consumed_decision_id) REFERENCES approval_decisions (decision_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$challenge_decision_fk$;

CREATE TABLE IF NOT EXISTS enforcement_authorizations (
    authorization_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'enforcement-authorization-v1'),
    authorization_kind text NOT NULL CHECK (authorization_kind IN ('add', 'revoke')),
    action_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version >= 1),
    approval_decision_id uuid NOT NULL UNIQUE REFERENCES approval_decisions (decision_id) ON DELETE RESTRICT,
    decision text NOT NULL CHECK (decision IN ('approve', 'revoke')),
    target_ipv4 canonical_ipv4 NOT NULL,
    policy_digest sha256_digest NOT NULL,
    generated_artifact_digest sha256_digest NOT NULL,
    canonical_artifact_digest sha256_digest NOT NULL,
    original_add_digest sha256_digest NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    validation_snapshot_digest sha256_digest NOT NULL,
    actor_id ascii_id NOT NULL,
    hil_reason_digest sha256_digest NOT NULL,
    decision_nonce_digest sha256_digest NOT NULL,
    idempotency_key_digest sha256_digest NOT NULL UNIQUE,
    authorization_digest sha256_digest NOT NULL UNIQUE,
    decided_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    CONSTRAINT enforcement_authorization_policy_fk FOREIGN KEY (policy_id, policy_version)
        REFERENCES policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT enforcement_authorization_validity CHECK (
        valid_until > decided_at AND valid_until <= decided_at + interval '5 minutes'
    ),
    CONSTRAINT enforcement_authorization_kind_shape CHECK (
        (authorization_kind = 'add' AND decision = 'approve' AND original_add_digest IS NULL) OR
        (authorization_kind = 'revoke' AND decision = 'revoke' AND original_add_digest IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS enforcement_authorizations_action_idx
    ON enforcement_authorizations (action_id, authorization_kind, decided_at);
CREATE UNIQUE INDEX IF NOT EXISTS enforcement_authorizations_action_kind_idx
    ON enforcement_authorizations (action_id, authorization_kind);

CREATE TABLE IF NOT EXISTS enforcement_actions (
    action_id uuid PRIMARY KEY,
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version >= 1),
    validation_snapshot_id uuid NOT NULL REFERENCES validation_snapshots (validation_snapshot_id) ON DELETE RESTRICT,
    evidence_snapshot_id uuid NULL REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE SET NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    command_candidate_id uuid NOT NULL REFERENCES command_candidates (command_candidate_id) ON DELETE RESTRICT,
    add_authorization_id uuid NOT NULL UNIQUE REFERENCES enforcement_authorizations (authorization_id) ON DELETE RESTRICT,
    target_ipv4 canonical_ipv4 NOT NULL,
    canonical_artifact bytea NOT NULL CHECK (octet_length(canonical_artifact) BETWEEN 1 AND 257),
    canonical_artifact_digest sha256_digest NOT NULL,
    ttl_seconds integer NOT NULL CHECK (ttl_seconds BETWEEN 60 AND 86400),
    state text NOT NULL CHECK (state IN ('approved', 'queued', 'active', 'expired', 'failed', 'revoked', 'indeterminate')),
    nft_element_handle safe_integer NULL CHECK (nft_element_handle IS NULL OR nft_element_handle >= 1),
    approved_at timestamptz NOT NULL,
    queued_at timestamptz NULL,
    applied_at timestamptz NULL,
    expected_expires_at timestamptz NULL,
    finished_at timestamptz NULL,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT enforcement_action_policy_fk FOREIGN KEY (policy_id, policy_version)
        REFERENCES policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT enforcement_action_time_order CHECK (
        updated_at >= created_at AND (queued_at IS NULL OR queued_at >= approved_at)
    ),
    CONSTRAINT enforcement_action_active_shape CHECK (
        state <> 'active' OR
        (applied_at IS NOT NULL AND expected_expires_at IS NOT NULL AND expected_expires_at > applied_at)
    ),
    UNIQUE (policy_id, policy_version),
    UNIQUE (canonical_artifact_digest)
);

DO $authorization_action_fk$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.enforcement_authorizations'::regclass
          AND conname = 'enforcement_authorization_action_fk'
    ) THEN
        ALTER TABLE enforcement_authorizations
            ADD CONSTRAINT enforcement_authorization_action_fk
            FOREIGN KEY (action_id) REFERENCES enforcement_actions (action_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$authorization_action_fk$;

DO $challenge_action_fk$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.decision_challenges'::regclass
          AND conname = 'decision_challenge_action_fk'
    ) THEN
        ALTER TABLE decision_challenges
            ADD CONSTRAINT decision_challenge_action_fk
            FOREIGN KEY (action_id) REFERENCES enforcement_actions (action_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$challenge_action_fk$;

DO $decision_action_fk$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sentinelflow.approval_decisions'::regclass
          AND conname = 'approval_decision_action_fk'
    ) THEN
        ALTER TABLE approval_decisions
            ADD CONSTRAINT approval_decision_action_fk
            FOREIGN KEY (action_id) REFERENCES enforcement_actions (action_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$decision_action_fk$;

CREATE INDEX IF NOT EXISTS enforcement_actions_state_updated_idx
    ON enforcement_actions (state, updated_at);
CREATE INDEX IF NOT EXISTS enforcement_actions_target_state_idx
    ON enforcement_actions (target_ipv4, state);
CREATE INDEX IF NOT EXISTS enforcement_actions_created_at_idx
    ON enforcement_actions (created_at);

CREATE TABLE IF NOT EXISTS revocation_operations (
    revocation_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'nft-revoke-v1'),
    action_id uuid NOT NULL REFERENCES enforcement_actions (action_id) ON DELETE RESTRICT,
    authorization_id uuid NOT NULL UNIQUE REFERENCES enforcement_authorizations (authorization_id) ON DELETE RESTRICT,
    approval_decision_id uuid NOT NULL UNIQUE REFERENCES approval_decisions (decision_id) ON DELETE RESTRICT,
    actor_id ascii_id NOT NULL,
    reason_id uuid NOT NULL REFERENCES hil_reasons (reason_id) ON DELETE RESTRICT,
    reason_digest sha256_digest NOT NULL,
    target_ipv4 canonical_ipv4 NOT NULL,
    original_add_digest sha256_digest NOT NULL,
    artifact bytea NOT NULL CHECK (octet_length(artifact) BETWEEN 1 AND 257),
    artifact_digest sha256_digest NOT NULL UNIQUE,
    state text NOT NULL CHECK (state IN ('authorized', 'queued', 'revoked', 'failed', 'indeterminate')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz NULL,
    CONSTRAINT revocation_time_order CHECK (completed_at IS NULL OR completed_at >= created_at),
    UNIQUE (action_id)
);

CREATE INDEX IF NOT EXISTS revocation_operations_created_at_idx
    ON revocation_operations (created_at);

CREATE TABLE IF NOT EXISTS inspection_authorizations (
    authorization_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'inspection-authorization-v1'),
    purpose text NOT NULL CHECK (purpose IN ('reconciliation', 'expiry_confirmation', 'operator_status')),
    action_id uuid NOT NULL REFERENCES enforcement_actions (action_id) ON DELETE RESTRICT,
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version >= 1),
    target_ipv4 canonical_ipv4 NOT NULL,
    original_add_digest sha256_digest NOT NULL,
    original_authorization_digest sha256_digest NOT NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    validation_snapshot_digest sha256_digest NOT NULL,
    artifact_digest sha256_digest NOT NULL,
    owned_schema_digest sha256_digest NOT NULL,
    scheduler_id ascii_id NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NOT NULL,
    idempotency_key_digest sha256_digest NOT NULL UNIQUE,
    authorization_digest sha256_digest NOT NULL UNIQUE,
    CONSTRAINT inspection_authorization_policy_fk FOREIGN KEY (policy_id, policy_version)
        REFERENCES policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT inspection_authorization_validity CHECK (
        valid_until > requested_at AND valid_until <= requested_at + interval '5 minutes'
    )
);

CREATE INDEX IF NOT EXISTS inspection_authorizations_action_idx
    ON inspection_authorizations (action_id, purpose, requested_at);

CREATE TABLE IF NOT EXISTS execution_capabilities (
    capability_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'execution-capability-v1'),
    job_id uuid NOT NULL UNIQUE REFERENCES outbox_jobs (job_id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('add', 'revoke', 'inspect')),
    action_id uuid NOT NULL REFERENCES enforcement_actions (action_id) ON DELETE RESTRICT,
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version >= 1),
    target_ipv4 canonical_ipv4 NOT NULL,
    artifact bytea NOT NULL CHECK (octet_length(artifact) BETWEEN 1 AND 16384),
    artifact_digest sha256_digest NOT NULL,
    original_add_digest sha256_digest NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    validation_snapshot_digest sha256_digest NOT NULL,
    authorization_digest sha256_digest NOT NULL,
    actor_id ascii_id NOT NULL,
    reason_digest sha256_digest NOT NULL,
    owned_schema_digest sha256_digest NOT NULL,
    capability_jcs bytea NOT NULL CHECK (octet_length(capability_jcs) BETWEEN 2 AND 16384),
    capability_digest sha256_digest NOT NULL UNIQUE,
    capability_signature bytea NOT NULL CHECK (octet_length(capability_signature) = 64),
    nonce_digest sha256_digest NOT NULL UNIQUE,
    issued_at timestamptz NOT NULL,
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    CONSTRAINT execution_capability_policy_fk FOREIGN KEY (policy_id, policy_version)
        REFERENCES policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT execution_capability_validity CHECK (
        not_before >= issued_at AND expires_at > not_before AND expires_at <= issued_at + interval '60 seconds'
    ),
    CONSTRAINT execution_capability_operation CHECK (
        (operation = 'add' AND original_add_digest IS NULL) OR
        (operation IN ('revoke', 'inspect') AND original_add_digest IS NOT NULL)
    ),
    CONSTRAINT execution_capability_consumed CHECK (consumed_at IS NULL OR consumed_at >= not_before)
);

CREATE INDEX IF NOT EXISTS execution_capabilities_action_idx
    ON execution_capabilities (action_id, operation, issued_at);
CREATE INDEX IF NOT EXISTS execution_capabilities_expires_at_idx
    ON execution_capabilities (expires_at);

CREATE TABLE IF NOT EXISTS execution_results (
    result_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'execution-result-v1'),
    capability_id uuid NOT NULL REFERENCES execution_capabilities (capability_id) ON DELETE RESTRICT,
    capability_digest sha256_digest NOT NULL,
    operation text NOT NULL CHECK (operation IN ('add', 'revoke', 'inspect')),
    action_id uuid NOT NULL REFERENCES enforcement_actions (action_id) ON DELETE RESTRICT,
    artifact_digest sha256_digest NOT NULL,
    target_ipv4 canonical_ipv4 NOT NULL,
    classification text NOT NULL CHECK (classification IN (
        'applied', 'recovered_active', 'revoked', 'inspect_active', 'inspect_absent',
        'inspect_mismatch', 'failed', 'indeterminate'
    )),
    nft_exit_class text NULL CHECK (nft_exit_class IS NULL OR nft_exit_class IN (
        'success', 'not_invoked', 'nonzero', 'timeout', 'signaled'
    )),
    readback_state text NOT NULL CHECK (readback_state IN ('active', 'absent', 'mismatch', 'unavailable')),
    element_handle safe_integer NULL CHECK (element_handle IS NULL OR element_handle >= 1),
    remaining_ttl_seconds integer NULL CHECK (remaining_ttl_seconds BETWEEN 0 AND 86400),
    owned_schema_digest sha256_digest NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    journal_sequence safe_integer NOT NULL CHECK (journal_sequence >= 1),
    error_code text NOT NULL CHECK (error_code IN (
        'none', 'capability_invalid', 'artifact_mismatch', 'schema_mismatch', 'target_exists',
        'target_absent', 'nft_failed', 'readback_failed', 'readback_mismatch', 'journal_failed',
        'deadline_exceeded', 'replay_conflict', 'indeterminate'
    )),
    result_jcs bytea NOT NULL CHECK (octet_length(result_jcs) BETWEEN 2 AND 16384),
    result_digest sha256_digest NOT NULL UNIQUE,
    result_signature bytea NOT NULL CHECK (octet_length(result_signature) = 64),
    persisted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT execution_result_time_order CHECK (completed_at >= started_at),
    CONSTRAINT execution_result_operation_class CHECK (
        (operation = 'add' AND classification IN ('applied', 'recovered_active', 'failed', 'indeterminate')) OR
        (operation = 'revoke' AND classification IN ('revoked', 'failed', 'indeterminate')) OR
        (operation = 'inspect' AND classification IN ('inspect_active', 'inspect_absent', 'inspect_mismatch', 'failed', 'indeterminate'))
    ),
    UNIQUE (capability_id)
);

CREATE INDEX IF NOT EXISTS execution_results_action_idx
    ON execution_results (action_id, persisted_at);
CREATE INDEX IF NOT EXISTS execution_results_persisted_at_idx
    ON execution_results (persisted_at);

CREATE TABLE IF NOT EXISTS dispatch_operations (
    job_id uuid PRIMARY KEY REFERENCES outbox_jobs (job_id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('add', 'revoke', 'inspect')),
    action_id uuid NOT NULL REFERENCES enforcement_actions (action_id) ON DELETE RESTRICT,
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version >= 1),
    target_ipv4 canonical_ipv4 NOT NULL,
    artifact bytea NOT NULL CHECK (octet_length(artifact) BETWEEN 1 AND 16384),
    artifact_digest sha256_digest NOT NULL,
    original_add_digest sha256_digest NULL,
    evidence_snapshot_digest sha256_digest NOT NULL,
    validation_snapshot_id uuid NOT NULL REFERENCES validation_snapshots (validation_snapshot_id) ON DELETE RESTRICT,
    validation_snapshot_digest sha256_digest NOT NULL,
    enforcement_authorization_id uuid NULL REFERENCES enforcement_authorizations (authorization_id) ON DELETE RESTRICT,
    inspection_authorization_id uuid NULL REFERENCES inspection_authorizations (authorization_id) ON DELETE RESTRICT,
    authorization_digest sha256_digest NOT NULL,
    actor_id ascii_id NOT NULL,
    reason_digest sha256_digest NOT NULL,
    owned_schema_digest sha256_digest NOT NULL,
    not_before timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT dispatch_operation_policy_fk FOREIGN KEY (policy_id, policy_version)
        REFERENCES policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT dispatch_operation_authority CHECK (
        (operation IN ('add', 'revoke') AND enforcement_authorization_id IS NOT NULL AND inspection_authorization_id IS NULL) OR
        (operation = 'inspect' AND enforcement_authorization_id IS NULL AND inspection_authorization_id IS NOT NULL)
    ),
    CONSTRAINT dispatch_operation_original_add CHECK (
        (operation = 'add' AND original_add_digest IS NULL) OR
        (operation IN ('revoke', 'inspect') AND original_add_digest IS NOT NULL)
    ),
    CONSTRAINT dispatch_operation_validity CHECK (valid_until > not_before)
);

CREATE INDEX IF NOT EXISTS dispatch_operations_action_idx
    ON dispatch_operations (action_id, operation, created_at);

CREATE TABLE IF NOT EXISTS ai_budget_ledger (
    budget_date date NOT NULL,
    model ascii_id NOT NULL,
    rate_card_version ascii_id NOT NULL,
    limit_micro_usd bigint NOT NULL CHECK (limit_micro_usd > 0),
    reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
    settled_micro_usd bigint NOT NULL DEFAULT 0 CHECK (settled_micro_usd >= 0),
    consumed_micro_usd bigint NOT NULL DEFAULT 0 CHECK (consumed_micro_usd >= 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (budget_date, model, rate_card_version),
    CONSTRAINT ai_budget_limit CHECK (
        reserved_micro_usd + consumed_micro_usd <= limit_micro_usd AND
        settled_micro_usd <= consumed_micro_usd
    )
);

CREATE INDEX IF NOT EXISTS ai_budget_ledger_updated_at_idx
    ON ai_budget_ledger (updated_at);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    actor_type text NOT NULL CHECK (actor_type IN ('administrator', 'system', 'dispatcher', 'executor')),
    actor_id ascii_id NOT NULL,
    action ascii_id NOT NULL,
    object_type ascii_id NOT NULL,
    object_id uuid NULL,
    incident_id uuid NULL,
    policy_id uuid NULL,
    policy_version integer NULL CHECK (policy_version IS NULL OR policy_version >= 1),
    enforcement_action_id uuid NULL,
    trace_id uuid NULL,
    primary_digest sha256_digest NULL,
    secondary_digest sha256_digest NULL,
    outcome text NOT NULL CHECK (outcome IN ('accepted', 'rejected', 'succeeded', 'failed', 'indeterminate')),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_policy_version_shape CHECK (
        (policy_id IS NULL AND policy_version IS NULL) OR
        (policy_id IS NOT NULL AND policy_version IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS audit_events_occurred_at_idx
    ON audit_events (occurred_at);
CREATE INDEX IF NOT EXISTS audit_events_object_idx
    ON audit_events (object_type, object_id, occurred_at);
CREATE INDEX IF NOT EXISTS audit_events_incident_idx
    ON audit_events (incident_id, occurred_at)
    WHERE incident_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS audit_events_policy_idx
    ON audit_events (policy_id, policy_version, occurred_at)
    WHERE policy_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS audit_events_action_idx
    ON audit_events (enforcement_action_id, occurred_at)
    WHERE enforcement_action_id IS NOT NULL;

INSERT INTO schema_migrations (version, name)
VALUES (2, 'core_schema')
ON CONFLICT (version) DO NOTHING;

COMMIT;
