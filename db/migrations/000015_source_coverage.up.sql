BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

ALTER TABLE ingest_batches
    ADD COLUMN IF NOT EXISTS auth_key_id ascii_id NULL
    CHECK (auth_key_id IS NULL OR length(auth_key_id) <= 64);

CREATE TABLE IF NOT EXISTS expected_source_bindings (
    binding_id uuid PRIMARY KEY,
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    endpoint_path text NOT NULL CHECK (endpoint_path IN (
        '/internal/v1/gateway-events', '/internal/v1/auth-events'
    )),
    service_label event_label NOT NULL,
    key_id ascii_id NOT NULL CHECK (length(key_id) <= 64),
    config_digest sha256_digest NOT NULL,
    binding_digest sha256_digest NOT NULL UNIQUE,
    effective_at timestamptz NOT NULL,
    CONSTRAINT expected_source_binding_endpoint CHECK (
        (endpoint_kind = 'gateway' AND endpoint_path = '/internal/v1/gateway-events') OR
        (endpoint_kind = 'auth' AND endpoint_path = '/internal/v1/auth-events')
    ),
    UNIQUE (sender_id, endpoint_kind, binding_id)
);

CREATE INDEX IF NOT EXISTS expected_source_bindings_asof_idx
    ON expected_source_bindings (sender_id, endpoint_kind, effective_at, binding_id);

CREATE TABLE IF NOT EXISTS expected_source_binding_retirements (
    retirement_id uuid PRIMARY KEY,
    binding_id uuid NOT NULL UNIQUE REFERENCES expected_source_bindings (binding_id)
        ON DELETE RESTRICT,
    reason_digest sha256_digest NOT NULL,
    retired_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS source_coverage_attestations (
    coverage_event_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'source-coverage-v1'),
    idempotency_key sha256_digest NOT NULL UNIQUE,
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    sender_epoch sender_epoch NOT NULL,
    segment_id uuid NOT NULL,
    previous_coverage_digest sha256_digest NULL,
    coverage_start timestamptz NOT NULL,
    coverage_end timestamptz NOT NULL,
    covered_through_batch_id uuid NOT NULL,
    covered_through_sequence safe_integer NOT NULL CHECK (covered_through_sequence >= 1),
    coverage_digest sha256_digest NOT NULL UNIQUE,
    binding_id uuid NOT NULL REFERENCES expected_source_bindings (binding_id)
        ON DELETE RESTRICT,
    raw_body_digest sha256_digest NOT NULL,
    received_at timestamptz NOT NULL,
    trust_state text NOT NULL CHECK (trust_state IN ('trusted', 'untrusted')),
    trust_reason text NOT NULL CHECK (trust_reason IN ('none', 'timestamp_skew')),
    CONSTRAINT source_coverage_batch_fk FOREIGN KEY (
        sender_id, sender_epoch, covered_through_batch_id, raw_body_digest
    ) REFERENCES ingest_batches (sender_id, sender_epoch, batch_id, raw_body_digest)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT source_coverage_interval CHECK (
        coverage_end >= coverage_start AND
        date_trunc('milliseconds', coverage_start) = coverage_start AND
        date_trunc('milliseconds', coverage_end) = coverage_end
    ),
    CONSTRAINT source_coverage_trust CHECK (
        (trust_state = 'trusted' AND trust_reason = 'none') OR
        (trust_state = 'untrusted' AND trust_reason = 'timestamp_skew')
    ),
    UNIQUE (sender_id, endpoint_kind, sender_epoch, covered_through_sequence),
    UNIQUE (sender_id, endpoint_kind, sender_epoch, segment_id, coverage_end)
);

CREATE INDEX IF NOT EXISTS source_coverage_window_idx
    ON source_coverage_attestations (
        sender_id, endpoint_kind, sender_epoch, coverage_start, coverage_end
    );

CREATE TABLE IF NOT EXISTS ingest_gap_lifecycle (
    lifecycle_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    lifecycle_state text NOT NULL CHECK (lifecycle_state IN ('opened', 'late_closed', 'lost')),
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    sender_epoch sender_epoch NOT NULL,
    sequence_start safe_integer NOT NULL CHECK (sequence_start >= 1),
    sequence_end safe_integer NOT NULL CHECK (sequence_end >= sequence_start),
    detected_by_batch_id uuid NOT NULL,
    detected_at timestamptz NOT NULL,
    resolved_by_batch_id uuid NULL,
    source_health_event_id uuid NULL REFERENCES source_health_intervals (event_id)
        ON DELETE RESTRICT,
    resolved_at timestamptz NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ingest_gap_lifecycle_detecting_batch_fk FOREIGN KEY (
        sender_id, sender_epoch, detected_by_batch_id
    ) REFERENCES ingest_batches (sender_id, sender_epoch, batch_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ingest_gap_lifecycle_resolving_batch_fk FOREIGN KEY (
        sender_id, sender_epoch, resolved_by_batch_id
    ) REFERENCES ingest_batches (sender_id, sender_epoch, batch_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ingest_gap_lifecycle_shape CHECK (
        (lifecycle_state = 'opened' AND resolved_by_batch_id IS NULL AND
            source_health_event_id IS NULL AND resolved_at IS NULL) OR
        (lifecycle_state = 'late_closed' AND resolved_by_batch_id IS NOT NULL AND
            source_health_event_id IS NULL AND resolved_at IS NOT NULL) OR
        (lifecycle_state = 'lost' AND resolved_by_batch_id IS NULL AND
            source_health_event_id IS NOT NULL AND resolved_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ingest_gap_lifecycle_asof_idx
    ON ingest_gap_lifecycle (
        sender_id, endpoint_kind, sender_epoch, detected_at, resolved_at,
        sequence_start, sequence_end
    );

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

DO $append_only_triggers$
DECLARE
    table_name text;
    trigger_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'expected_source_bindings', 'expected_source_binding_retirements',
        'source_coverage_attestations', 'ingest_gap_lifecycle'
    ]
    LOOP
        trigger_name := table_name || '_append_only';
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgrelid = ('sentinelflow.' || table_name)::regclass
              AND tgname = trigger_name AND NOT tgisinternal
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON sentinelflow.%I '
                'FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_source_coverage_mutation()',
                trigger_name, table_name
            );
        END IF;
    END LOOP;
END
$append_only_triggers$;

CREATE OR REPLACE FUNCTION sentinelflow.source_coverage_canonical(
    p_event_id uuid,
    p_idempotency_key text,
    p_source_id text,
    p_sender_epoch text,
    p_segment_id uuid,
    p_previous_digest text,
    p_coverage_start timestamptz,
    p_coverage_end timestamptz,
    p_batch_id uuid,
    p_sequence bigint
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT convert_to(
        '{"affected_sender_epoch":' || to_json(p_sender_epoch)::text ||
        ',"coverage_end":' || to_json(to_char(p_coverage_end AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
        ',"coverage_start":' || to_json(to_char(p_coverage_start AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
        ',"covered_through_batch_id":' || to_json(p_batch_id::text)::text ||
        ',"covered_through_sequence":' || p_sequence::text ||
        ',"event_id":' || to_json(p_event_id::text)::text ||
        ',"idempotency_key":' || to_json(p_idempotency_key)::text ||
        ',"previous_coverage_digest":' ||
            CASE WHEN p_previous_digest = '' THEN 'null' ELSE to_json(p_previous_digest)::text END ||
        ',"schema_version":"source-coverage-v1"' ||
        ',"segment_id":' || to_json(p_segment_id::text)::text ||
        ',"source_id":' || to_json(p_source_id)::text ||
        ',"state":"complete"}',
        'UTF8'
    );
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.source_coverage_sha256(p_bytes bytea)
RETURNS sentinelflow.sha256_digest
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT ('sha256:' || encode(sha256(p_bytes), 'hex'))::sentinelflow.sha256_digest;
$function$;

-- API lost direct outbox mutation authority when final HIL commitment was
-- hardened. Ingest needs only this one exact append path: an immutable,
-- authenticated batch and its deterministic detect job identity.
CREATE OR REPLACE FUNCTION sentinelflow.append_ingest_detect_outbox(
    p_sender_id text,
    p_batch_id uuid,
    p_raw_body_digest text,
    p_job_id uuid,
    p_idempotency_key text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    batch sentinelflow.ingest_batches%ROWTYPE;
    existing sentinelflow.outbox_jobs%ROWTYPE;
    canonical bytea;
    digest_bytes bytea;
    uuid_bytes bytea;
    expected_job_id uuid;
    expected_idempotency sentinelflow.sha256_digest;
BEGIN
    IF p_sender_id !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       p_batch_id IS NULL OR p_job_id IS NULL OR
       p_raw_body_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_idempotency_key !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid ingest detect outbox request';
    END IF;

    SELECT * INTO batch
    FROM sentinelflow.ingest_batches candidate
    WHERE candidate.sender_id = p_sender_id
      AND candidate.batch_id = p_batch_id
      AND candidate.raw_body_digest = p_raw_body_digest
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = 'ingest detect outbox requires the exact authenticated batch';
    END IF;

    canonical := convert_to(
        'sentinelflow ingest detect outbox v1' || chr(10) ||
        batch.sender_id || chr(10) || batch.sender_epoch || chr(10) ||
        batch.batch_id::text || chr(10), 'UTF8');
    digest_bytes := sha256(canonical);
    expected_idempotency := ('sha256:' || encode(digest_bytes, 'hex'))::sentinelflow.sha256_digest;
    uuid_bytes := substring(digest_bytes FROM 1 FOR 16);
    uuid_bytes := set_byte(uuid_bytes, 6, (get_byte(uuid_bytes, 6) & 15) | 128);
    uuid_bytes := set_byte(uuid_bytes, 8, (get_byte(uuid_bytes, 8) & 63) | 128);
    expected_job_id := (
        substring(encode(uuid_bytes, 'hex') FROM 1 FOR 8) || '-' ||
        substring(encode(uuid_bytes, 'hex') FROM 9 FOR 4) || '-' ||
        substring(encode(uuid_bytes, 'hex') FROM 13 FOR 4) || '-' ||
        substring(encode(uuid_bytes, 'hex') FROM 17 FOR 4) || '-' ||
        substring(encode(uuid_bytes, 'hex') FROM 21 FOR 12)
    )::uuid;
    IF p_job_id <> expected_job_id OR p_idempotency_key <> expected_idempotency THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'ingest detect outbox identity mismatch';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'ingest-detect-outbox:' || p_job_id::text, 0));
    SELECT * INTO existing
    FROM sentinelflow.outbox_jobs job
    WHERE job.job_id = p_job_id OR job.idempotency_key = p_idempotency_key
    FOR UPDATE;
    IF FOUND THEN
        IF existing.job_id <> p_job_id OR existing.kind <> 'detect' OR
           existing.aggregate_type <> 'ingest_batch' OR
           existing.aggregate_id <> p_batch_id OR existing.aggregate_version <> 1 OR
           existing.operation IS NOT NULL OR
           existing.idempotency_key <> expected_idempotency THEN
            RAISE EXCEPTION USING ERRCODE = '23505',
                MESSAGE = 'ingest detect outbox identity conflict';
        END IF;
        RETURN existing.job_id;
    END IF;

    INSERT INTO sentinelflow.outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        operation, idempotency_key, state, available_at, max_attempts
    ) VALUES (
        p_job_id, 'detect', 'ingest_batch', p_batch_id, 1,
        NULL, expected_idempotency, 'pending', batch.received_at, 8
    );
    RETURN p_job_id;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.register_expected_source_binding(
    p_binding_id uuid,
    p_sender_id text,
    p_endpoint_kind text,
    p_service_label text,
    p_key_id text,
    p_config_digest text
)
RETURNS SETOF sentinelflow.expected_source_bindings
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    existing sentinelflow.expected_source_bindings%ROWTYPE;
    created sentinelflow.expected_source_bindings%ROWTYPE;
    endpoint_path_value text;
    server_now timestamptz := clock_timestamp();
    binding_digest_value sentinelflow.sha256_digest;
BEGIN
    IF p_binding_id IS NULL OR
       p_sender_id !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       p_endpoint_kind NOT IN ('gateway', 'auth') OR
       p_service_label !~ '^[a-z][a-z0-9_-]{0,63}$' OR
       p_key_id !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       p_config_digest !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid expected source binding';
    END IF;
    endpoint_path_value := CASE p_endpoint_kind
        WHEN 'gateway' THEN '/internal/v1/gateway-events'
        ELSE '/internal/v1/auth-events'
    END;
    binding_digest_value := sentinelflow.source_coverage_sha256(convert_to(
        'expected-source-binding-v1' || chr(10) || p_binding_id::text || chr(10) ||
        p_sender_id || chr(10) || p_endpoint_kind || chr(10) || endpoint_path_value || chr(10) ||
        p_service_label || chr(10) || p_key_id || chr(10) || p_config_digest || chr(10), 'UTF8'));

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'expected-source-binding:' || p_sender_id || ':' || p_endpoint_kind, 0));
    SELECT * INTO existing FROM sentinelflow.expected_source_bindings
    WHERE binding_id = p_binding_id;
    IF FOUND THEN
        IF existing.sender_id <> p_sender_id OR existing.endpoint_kind <> p_endpoint_kind OR
           existing.endpoint_path <> endpoint_path_value OR existing.service_label <> p_service_label OR
           existing.key_id <> p_key_id OR existing.config_digest <> p_config_digest OR
           existing.binding_digest <> binding_digest_value THEN
            RAISE EXCEPTION USING ERRCODE = '23505',
                MESSAGE = 'expected source binding identity conflict';
        END IF;
        RETURN NEXT existing;
        RETURN;
    END IF;
    IF EXISTS (
        SELECT 1 FROM sentinelflow.expected_source_bindings binding
        WHERE binding.sender_id = p_sender_id AND binding.endpoint_kind = p_endpoint_kind
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.expected_source_binding_retirements retirement
              WHERE retirement.binding_id = binding.binding_id
          )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23505',
            MESSAGE = 'expected source already has an active binding';
    END IF;
    INSERT INTO sentinelflow.expected_source_bindings (
        binding_id, sender_id, endpoint_kind, endpoint_path, service_label,
        key_id, config_digest, binding_digest, effective_at
    ) VALUES (
        p_binding_id, p_sender_id, p_endpoint_kind, endpoint_path_value,
        p_service_label, p_key_id, p_config_digest, binding_digest_value, server_now
    ) RETURNING * INTO created;
    RETURN NEXT created;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.retire_expected_source_binding(
    p_retirement_id uuid,
    p_binding_id uuid,
    p_reason_digest text
)
RETURNS SETOF sentinelflow.expected_source_binding_retirements
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    existing sentinelflow.expected_source_binding_retirements%ROWTYPE;
    created sentinelflow.expected_source_binding_retirements%ROWTYPE;
BEGIN
    IF p_retirement_id IS NULL OR p_binding_id IS NULL OR
       p_reason_digest !~ '^sha256:[0-9a-f]{64}$' OR
       NOT EXISTS (SELECT 1 FROM sentinelflow.expected_source_bindings WHERE binding_id = p_binding_id) THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid expected source retirement';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'expected-source-retirement:' || p_binding_id::text, 0));
    SELECT * INTO existing FROM sentinelflow.expected_source_binding_retirements
    WHERE binding_id = p_binding_id OR retirement_id = p_retirement_id
    FOR UPDATE;
    IF FOUND THEN
        IF existing.retirement_id <> p_retirement_id OR existing.binding_id <> p_binding_id OR
           existing.reason_digest <> p_reason_digest THEN
            RAISE EXCEPTION USING ERRCODE = '23505',
                MESSAGE = 'expected source retirement conflict';
        END IF;
        RETURN NEXT existing;
        RETURN;
    END IF;
    INSERT INTO sentinelflow.expected_source_binding_retirements (
        retirement_id, binding_id, reason_digest, retired_at
    ) VALUES (p_retirement_id, p_binding_id, p_reason_digest, clock_timestamp())
    RETURNING * INTO created;
    RETURN NEXT created;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.append_source_coverage_attestation(
    p_event_id uuid,
    p_idempotency_key text,
    p_sender_id text,
    p_endpoint_kind text,
    p_sender_epoch text,
    p_segment_id uuid,
    p_previous_digest text,
    p_coverage_start timestamptz,
    p_coverage_end timestamptz,
    p_batch_id uuid,
    p_sequence bigint,
    p_record_ordinal integer,
    p_trust_state text,
    p_trust_reason text
)
RETURNS SETOF sentinelflow.source_coverage_attestations
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    batch sentinelflow.ingest_batches%ROWTYPE;
    binding sentinelflow.expected_source_bindings%ROWTYPE;
    prior sentinelflow.source_coverage_attestations%ROWTYPE;
    existing sentinelflow.source_coverage_attestations%ROWTYPE;
    created sentinelflow.source_coverage_attestations%ROWTYPE;
    digest_value sentinelflow.sha256_digest;
BEGIN
    IF p_event_id IS NULL OR p_segment_id IS NULL OR p_previous_digest IS NULL OR
       p_idempotency_key !~ '^sha256:[0-9a-f]{64}$' OR
       p_sender_id !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       p_endpoint_kind NOT IN ('gateway', 'auth') OR
       p_sender_epoch !~ '^[A-Za-z0-9_-]{22}$' OR
       (p_previous_digest <> '' AND p_previous_digest !~ '^sha256:[0-9a-f]{64}$') OR
       p_coverage_start IS NULL OR p_coverage_end IS NULL OR
       NOT isfinite(p_coverage_start) OR NOT isfinite(p_coverage_end) OR
       p_coverage_end < p_coverage_start OR
       date_trunc('milliseconds', p_coverage_start) <> p_coverage_start OR
       date_trunc('milliseconds', p_coverage_end) <> p_coverage_end OR
       p_batch_id IS NULL OR p_sequence < 1 OR p_record_ordinal < 1 OR
       p_trust_state NOT IN ('trusted', 'untrusted') OR
       (p_trust_state = 'trusted' AND p_trust_reason <> 'none') OR
       (p_trust_state = 'untrusted' AND p_trust_reason <> 'timestamp_skew') THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid source coverage attestation';
    END IF;

    SELECT * INTO batch FROM sentinelflow.ingest_batches current_batch
    WHERE current_batch.sender_id = p_sender_id
      AND current_batch.endpoint_kind = p_endpoint_kind
      AND current_batch.sender_epoch = p_sender_epoch
      AND current_batch.batch_id = p_batch_id
      AND current_batch.sequence = p_sequence
      AND current_batch.record_count = p_record_ordinal
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'source coverage must be the final record of its exact batch';
    END IF;

    SELECT candidate.* INTO binding
    FROM sentinelflow.expected_source_bindings candidate
    WHERE candidate.sender_id = p_sender_id
      AND candidate.endpoint_kind = p_endpoint_kind
      AND candidate.effective_at <= batch.received_at
      AND NOT EXISTS (
          SELECT 1 FROM sentinelflow.expected_source_binding_retirements retirement
          WHERE retirement.binding_id = candidate.binding_id
            AND retirement.retired_at <= batch.received_at
      )
    ORDER BY candidate.effective_at DESC, candidate.binding_id
    LIMIT 1;
    IF NOT FOUND OR batch.auth_key_id IS NULL OR batch.auth_key_id <> binding.key_id OR EXISTS (
        SELECT 1 FROM sentinelflow.gateway_events event
        WHERE event.sender_id = p_sender_id AND event.sender_epoch = p_sender_epoch
          AND event.batch_id = p_batch_id AND event.service_label <> binding.service_label
        UNION ALL
        SELECT 1 FROM sentinelflow.auth_events event
        WHERE event.sender_id = p_sender_id AND event.sender_epoch = p_sender_epoch
          AND event.batch_id = p_batch_id AND event.service_label <> binding.service_label
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'source coverage has no exact active source binding';
    END IF;

    digest_value := sentinelflow.source_coverage_sha256(
        sentinelflow.source_coverage_canonical(
            p_event_id, p_idempotency_key, p_sender_id, p_sender_epoch,
            p_segment_id, p_previous_digest, p_coverage_start, p_coverage_end,
            p_batch_id, p_sequence
        )
    );
    SELECT * INTO existing FROM sentinelflow.source_coverage_attestations
    WHERE coverage_event_id = p_event_id OR idempotency_key = p_idempotency_key;
    IF FOUND THEN
        IF existing.coverage_event_id <> p_event_id OR existing.idempotency_key <> p_idempotency_key OR
           existing.sender_id <> p_sender_id OR existing.endpoint_kind <> p_endpoint_kind OR
           existing.sender_epoch <> p_sender_epoch OR existing.segment_id <> p_segment_id OR
           existing.previous_coverage_digest IS DISTINCT FROM NULLIF(p_previous_digest, '') OR
           existing.coverage_start <> p_coverage_start OR existing.coverage_end <> p_coverage_end OR
           existing.covered_through_batch_id <> p_batch_id OR
           existing.covered_through_sequence <> p_sequence OR
           existing.coverage_digest <> digest_value OR existing.binding_id <> binding.binding_id OR
           existing.raw_body_digest <> batch.raw_body_digest OR
           existing.received_at <> batch.received_at OR existing.trust_state <> p_trust_state OR
           existing.trust_reason <> p_trust_reason THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'source coverage identity conflict';
        END IF;
        RETURN NEXT existing;
        RETURN;
    END IF;

    SELECT * INTO prior FROM sentinelflow.source_coverage_attestations candidate
    WHERE candidate.sender_id = p_sender_id AND candidate.endpoint_kind = p_endpoint_kind
      AND candidate.sender_epoch = p_sender_epoch
    ORDER BY candidate.covered_through_sequence DESC, candidate.coverage_event_id DESC
    LIMIT 1 FOR UPDATE;
    IF p_previous_digest = '' THEN
        IF FOUND AND NOT EXISTS (
            SELECT 1 FROM sentinelflow.source_health_intervals health
            JOIN sentinelflow.ingest_batches health_batch
              ON health_batch.sender_id = health.sender_id
             AND health_batch.sender_epoch = health.sender_epoch
             AND health_batch.batch_id = health.batch_id
            WHERE health.source_id = p_sender_id
              AND health.affected_sender_epoch = p_sender_epoch
              AND health_batch.endpoint_kind = p_endpoint_kind
              AND health_batch.sender_epoch = p_sender_epoch
              AND health_batch.sequence > prior.covered_through_sequence
              AND health_batch.sequence <= p_sequence
              AND health.state IN ('degraded', 'lost', 'recovered')
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'source coverage reset requires authenticated health evidence';
        END IF;
    ELSE
        IF NOT FOUND OR prior.coverage_digest <> p_previous_digest OR
           prior.segment_id <> p_segment_id OR prior.coverage_end <> p_coverage_start OR
           prior.covered_through_sequence >= p_sequence OR p_coverage_end <= p_coverage_start THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'source coverage chain is not exactly adjacent';
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1 FROM sentinelflow.ingest_sequence_gaps gap
        WHERE gap.sender_id = p_sender_id AND gap.endpoint_kind = p_endpoint_kind
          AND gap.sender_epoch = p_sender_epoch
          AND gap.sequence_start <= p_sequence
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.source_health_intervals health
        WHERE health.source_id = p_sender_id
          AND health.affected_sender_epoch = p_sender_epoch
          AND health.received_at <= batch.received_at
          AND ((health.interval_start IS NOT NULL AND health.interval_end IS NOT NULL AND
                  tstzrange(health.interval_start, health.interval_end, '[)') &&
                  tstzrange(p_coverage_start, p_coverage_end, '[)')) OR
               ((health.interval_start IS NULL OR health.interval_end IS NULL) AND
                  health.received_at >= p_coverage_start AND health.received_at < p_coverage_end))
          AND (health.trust_state <> 'trusted' OR health.state IN ('degraded', 'lost', 'recovered') OR
              health.dropped_count > 0)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'source coverage overlaps incomplete source state';
    END IF;

    INSERT INTO sentinelflow.source_coverage_attestations (
        coverage_event_id, schema_version, idempotency_key, sender_id, endpoint_kind,
        sender_epoch, segment_id, previous_coverage_digest, coverage_start, coverage_end,
        covered_through_batch_id, covered_through_sequence, coverage_digest, binding_id,
        raw_body_digest, received_at, trust_state, trust_reason
    ) VALUES (
        p_event_id, 'source-coverage-v1', p_idempotency_key, p_sender_id, p_endpoint_kind,
        p_sender_epoch, p_segment_id, NULLIF(p_previous_digest, ''), p_coverage_start,
        p_coverage_end, p_batch_id, p_sequence, digest_value, binding.binding_id,
        batch.raw_body_digest, batch.received_at, p_trust_state, p_trust_reason
    ) RETURNING * INTO created;
    RETURN NEXT created;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.record_ingest_gap_opened()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    INSERT INTO sentinelflow.ingest_gap_lifecycle (
        lifecycle_state, sender_id, endpoint_kind, sender_epoch,
        sequence_start, sequence_end, detected_by_batch_id, detected_at
    ) VALUES (
        'opened', NEW.sender_id, NEW.endpoint_kind, NEW.sender_epoch,
        NEW.sequence_start, NEW.sequence_end, NEW.detected_by_batch_id, NEW.detected_at
    );
    RETURN NULL;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.record_ingest_gap_resolution()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    opened sentinelflow.ingest_gap_lifecycle%ROWTYPE;
    resolving_batch_id uuid;
BEGIN
    SELECT candidate.* INTO opened
    FROM sentinelflow.ingest_gap_lifecycle candidate
    WHERE candidate.lifecycle_state = 'opened'
      AND candidate.sender_id = NEW.sender_id
      AND candidate.endpoint_kind = NEW.endpoint_kind
      AND candidate.sender_epoch = NEW.sender_epoch
      AND candidate.sequence_start <= NEW.sequence_start
      AND candidate.sequence_end >= NEW.sequence_end
      AND candidate.detected_at <= NEW.resolved_at
    ORDER BY candidate.detected_at, candidate.lifecycle_id
    LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'gap resolution has no append-only opened evidence';
    END IF;
    resolving_batch_id := CASE WHEN NEW.resolution = 'late_arrival'
        THEN NEW.resolution_batch_id ELSE NULL END;
    INSERT INTO sentinelflow.ingest_gap_lifecycle (
        lifecycle_state, sender_id, endpoint_kind, sender_epoch,
        sequence_start, sequence_end, detected_by_batch_id, detected_at,
        resolved_by_batch_id, source_health_event_id, resolved_at
    ) VALUES (
        CASE NEW.resolution WHEN 'late_arrival' THEN 'late_closed' ELSE 'lost' END,
        NEW.sender_id, NEW.endpoint_kind, NEW.sender_epoch,
        NEW.sequence_start, NEW.sequence_end, opened.detected_by_batch_id,
        opened.detected_at, resolving_batch_id, NEW.source_health_event_id, NEW.resolved_at
    );
    RETURN NULL;
END
$function$;

DROP TRIGGER IF EXISTS ingest_sequence_gap_opened_lifecycle ON sentinelflow.ingest_sequence_gaps;
CREATE TRIGGER ingest_sequence_gap_opened_lifecycle
AFTER INSERT ON sentinelflow.ingest_sequence_gaps
FOR EACH ROW EXECUTE FUNCTION sentinelflow.record_ingest_gap_opened();

DROP TRIGGER IF EXISTS ingest_sequence_gap_resolution_lifecycle ON sentinelflow.ingest_sequence_gap_resolutions;
CREATE TRIGGER ingest_sequence_gap_resolution_lifecycle
AFTER INSERT ON sentinelflow.ingest_sequence_gap_resolutions
FOR EACH ROW EXECUTE FUNCTION sentinelflow.record_ingest_gap_resolution();

INSERT INTO sentinelflow.ingest_gap_lifecycle (
    lifecycle_state, sender_id, endpoint_kind, sender_epoch,
    sequence_start, sequence_end, detected_by_batch_id, detected_at
)
SELECT 'opened', gap.sender_id, gap.endpoint_kind, gap.sender_epoch,
       gap.sequence_start, gap.sequence_end, gap.detected_by_batch_id, gap.detected_at
FROM sentinelflow.ingest_sequence_gaps gap
WHERE NOT EXISTS (
    SELECT 1 FROM sentinelflow.ingest_gap_lifecycle lifecycle
    WHERE lifecycle.lifecycle_state = 'opened'
      AND lifecycle.sender_id = gap.sender_id
      AND lifecycle.endpoint_kind = gap.endpoint_kind
      AND lifecycle.sender_epoch = gap.sender_epoch
      AND lifecycle.sequence_start = gap.sequence_start
      AND lifecycle.sequence_end = gap.sequence_end
      AND lifecycle.detected_by_batch_id = gap.detected_by_batch_id
      AND lifecycle.detected_at = gap.detected_at
);

REVOKE ALL ON expected_source_bindings, expected_source_binding_retirements,
    source_coverage_attestations, ingest_gap_lifecycle FROM PUBLIC;
REVOKE ALL ON expected_source_bindings, expected_source_binding_retirements,
    source_coverage_attestations, ingest_gap_lifecycle FROM
    sentinelflow_api, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
GRANT SELECT ON expected_source_bindings, expected_source_binding_retirements,
    source_coverage_attestations, ingest_gap_lifecycle TO
    sentinelflow_api, sentinelflow_worker, sentinelflow_read;

REVOKE ALL ON FUNCTION sentinelflow.source_coverage_canonical(
    uuid, text, text, text, uuid, text, timestamptz, timestamptz, uuid, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.source_coverage_sha256(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.append_ingest_detect_outbox(
    text, uuid, text, uuid, text
) FROM PUBLIC, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.append_ingest_detect_outbox(
    text, uuid, text, uuid, text
) TO sentinelflow_api;
REVOKE ALL ON FUNCTION sentinelflow.register_expected_source_binding(
    uuid, text, text, text, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.register_expected_source_binding(
    uuid, text, text, text, text, text
) TO sentinelflow_api;
REVOKE ALL ON FUNCTION sentinelflow.retire_expected_source_binding(
    uuid, uuid, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.retire_expected_source_binding(
    uuid, uuid, text
) TO sentinelflow_api;
REVOKE ALL ON FUNCTION sentinelflow.append_source_coverage_attestation(
    uuid, text, text, text, text, uuid, text, timestamptz, timestamptz,
    uuid, bigint, integer, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.append_source_coverage_attestation(
    uuid, text, text, text, text, uuid, text, timestamptz, timestamptz,
    uuid, bigint, integer, text, text
) TO sentinelflow_api;
REVOKE ALL ON FUNCTION sentinelflow.record_ingest_gap_opened() FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.record_ingest_gap_resolution() FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.reject_source_coverage_mutation()
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
    sentinelflow_dispatcher;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (15, 'source_coverage')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
