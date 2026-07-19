BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- A receiver-observed sequence gap is transport state, not a producer-signed
-- source-health event. Keep the current unresolved ranges separately so a
-- late byte-identical batch can close one sequence without rewinding the
-- sender high-water checkpoint or fabricating authenticated evidence.
CREATE TABLE IF NOT EXISTS ingest_sequence_gaps (
    gap_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    sender_epoch sender_epoch NOT NULL,
    sequence_start safe_integer NOT NULL CHECK (sequence_start >= 1),
    sequence_end safe_integer NOT NULL CHECK (sequence_end >= sequence_start),
    detected_by_batch_id uuid NOT NULL,
    detected_at timestamptz NOT NULL,
    CONSTRAINT ingest_sequence_gap_batch_fk FOREIGN KEY (
        sender_id, sender_epoch, detected_by_batch_id
    ) REFERENCES ingest_batches (sender_id, sender_epoch, batch_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (sender_id, endpoint_kind, sender_epoch, sequence_start, sequence_end)
);

CREATE INDEX IF NOT EXISTS ingest_sequence_gaps_lookup_idx
    ON ingest_sequence_gaps (
        sender_id, endpoint_kind, sender_epoch, sequence_start, sequence_end
    );

CREATE TABLE IF NOT EXISTS ingest_sequence_gap_resolutions (
    resolution_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id ascii_id NOT NULL CHECK (length(sender_id) <= 64),
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    sender_epoch sender_epoch NOT NULL,
    sequence_start safe_integer NOT NULL CHECK (sequence_start >= 1),
    sequence_end safe_integer NOT NULL CHECK (sequence_end >= sequence_start),
    resolution text NOT NULL CHECK (resolution IN ('late_arrival', 'permanent_loss')),
    resolution_batch_id uuid NULL,
    source_health_event_id uuid NULL REFERENCES source_health_intervals (event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    resolved_at timestamptz NOT NULL,
    CONSTRAINT ingest_gap_resolution_batch_fk FOREIGN KEY (
        sender_id, sender_epoch, resolution_batch_id
    ) REFERENCES ingest_batches (sender_id, sender_epoch, batch_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ingest_gap_resolution_authority CHECK (
        (resolution = 'late_arrival' AND sequence_start = sequence_end AND
            resolution_batch_id IS NOT NULL AND source_health_event_id IS NULL) OR
        (resolution = 'permanent_loss' AND resolution_batch_id IS NULL AND
            source_health_event_id IS NOT NULL)
    ),
    UNIQUE (
        sender_id, endpoint_kind, sender_epoch, sequence_start,
        sequence_end, resolution
    )
);

CREATE INDEX IF NOT EXISTS ingest_sequence_gap_resolutions_lookup_idx
    ON ingest_sequence_gap_resolutions (
        sender_id, endpoint_kind, sender_epoch, sequence_start, sequence_end
    );

CREATE OR REPLACE FUNCTION sentinelflow.register_ingest_sequence(
    p_sender_id text,
    p_endpoint_kind text,
    p_sender_epoch text,
    p_sequence bigint,
    p_batch_id uuid,
    p_body_digest text,
    p_received_at timestamptz
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    checkpoint sentinelflow.sender_checkpoints%ROWTYPE;
    gap sentinelflow.ingest_sequence_gaps%ROWTYPE;
    disposition text;
BEGIN
    IF p_endpoint_kind NOT IN ('gateway', 'auth') OR
       p_sequence < 1 OR
       p_received_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid ingest sequence registration';
    END IF;

    SELECT *
    INTO checkpoint
    FROM sentinelflow.sender_checkpoints
    WHERE sender_id = p_sender_id
      AND endpoint_kind = p_endpoint_kind
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'sender checkpoint must be initialized before registration';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.ingest_batches batch
        WHERE batch.sender_id = p_sender_id
          AND batch.endpoint_kind = p_endpoint_kind
          AND batch.sender_epoch = p_sender_epoch
          AND batch.sequence = p_sequence
          AND batch.batch_id = p_batch_id
          AND batch.raw_body_digest = p_body_digest
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sequence registration requires the exact accepted batch';
    END IF;

    IF checkpoint.sender_epoch <> p_sender_epoch THEN
        SELECT *
        INTO gap
        FROM sentinelflow.ingest_sequence_gaps current_gap
        WHERE current_gap.sender_id = p_sender_id
          AND current_gap.endpoint_kind = p_endpoint_kind
          AND current_gap.sender_epoch = p_sender_epoch
          AND p_sequence BETWEEN current_gap.sequence_start AND current_gap.sequence_end
        FOR UPDATE;

        IF FOUND THEN
            DELETE FROM sentinelflow.ingest_sequence_gaps
            WHERE gap_id = gap.gap_id;

            IF gap.sequence_start < p_sequence THEN
                INSERT INTO sentinelflow.ingest_sequence_gaps (
                    sender_id, endpoint_kind, sender_epoch, sequence_start,
                    sequence_end, detected_by_batch_id, detected_at
                ) VALUES (
                    gap.sender_id, gap.endpoint_kind, gap.sender_epoch,
                    gap.sequence_start, p_sequence - 1,
                    gap.detected_by_batch_id, gap.detected_at
                );
            END IF;
            IF p_sequence < gap.sequence_end THEN
                INSERT INTO sentinelflow.ingest_sequence_gaps (
                    sender_id, endpoint_kind, sender_epoch, sequence_start,
                    sequence_end, detected_by_batch_id, detected_at
                ) VALUES (
                    gap.sender_id, gap.endpoint_kind, gap.sender_epoch,
                    p_sequence + 1, gap.sequence_end,
                    gap.detected_by_batch_id, gap.detected_at
                );
            END IF;
            INSERT INTO sentinelflow.ingest_sequence_gap_resolutions (
                sender_id, endpoint_kind, sender_epoch, sequence_start,
                sequence_end, resolution, resolution_batch_id, resolved_at
            ) VALUES (
                p_sender_id, p_endpoint_kind, p_sender_epoch, p_sequence,
                p_sequence, 'late_arrival', p_batch_id, p_received_at
            );
            RETURN 'late_gap_closed';
        END IF;

        IF EXISTS (
            SELECT 1
            FROM sentinelflow.ingest_batches prior
            WHERE prior.sender_id = p_sender_id
              AND prior.endpoint_kind = p_endpoint_kind
              AND prior.sender_epoch = p_sender_epoch
              AND prior.batch_id <> p_batch_id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'a prior sender epoch cannot replace the current high-water';
        END IF;

        IF p_sequence > 1 THEN
            INSERT INTO sentinelflow.ingest_sequence_gaps (
                sender_id, endpoint_kind, sender_epoch, sequence_start,
                sequence_end, detected_by_batch_id, detected_at
            ) VALUES (
                p_sender_id, p_endpoint_kind, p_sender_epoch, 1,
                p_sequence - 1, p_batch_id, p_received_at
            );
            disposition := 'new_epoch_gap';
        ELSE
            disposition := 'new_epoch';
        END IF;

        UPDATE sentinelflow.sender_checkpoints
        SET sender_epoch = p_sender_epoch,
            last_acknowledged_sequence = p_sequence,
            last_acknowledged_body_digest = p_body_digest,
            clean_shutdown = false,
            unknown_loss = unknown_loss OR NOT checkpoint.clean_shutdown,
            updated_at = p_received_at
        WHERE sender_id = p_sender_id
          AND endpoint_kind = p_endpoint_kind;
        RETURN disposition;
    END IF;

    IF p_sequence > checkpoint.last_acknowledged_sequence THEN
        IF p_sequence > checkpoint.last_acknowledged_sequence + 1 THEN
            INSERT INTO sentinelflow.ingest_sequence_gaps (
                sender_id, endpoint_kind, sender_epoch, sequence_start,
                sequence_end, detected_by_batch_id, detected_at
            ) VALUES (
                p_sender_id, p_endpoint_kind, p_sender_epoch,
                checkpoint.last_acknowledged_sequence + 1, p_sequence - 1,
                p_batch_id, p_received_at
            );
            disposition := 'gap';
        ELSE
            disposition := 'next';
        END IF;

        UPDATE sentinelflow.sender_checkpoints
        SET last_acknowledged_sequence = p_sequence,
            last_acknowledged_body_digest = p_body_digest,
            clean_shutdown = false,
            updated_at = p_received_at
        WHERE sender_id = p_sender_id
          AND endpoint_kind = p_endpoint_kind
          AND sender_epoch = p_sender_epoch
          AND last_acknowledged_sequence = checkpoint.last_acknowledged_sequence;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                MESSAGE = 'sender checkpoint changed during sequence registration';
        END IF;
        RETURN disposition;
    END IF;

    SELECT *
    INTO gap
    FROM sentinelflow.ingest_sequence_gaps current_gap
    WHERE current_gap.sender_id = p_sender_id
      AND current_gap.endpoint_kind = p_endpoint_kind
      AND current_gap.sender_epoch = p_sender_epoch
      AND p_sequence BETWEEN current_gap.sequence_start AND current_gap.sequence_end
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'sequence is neither above high-water nor unresolved';
    END IF;

    DELETE FROM sentinelflow.ingest_sequence_gaps
    WHERE gap_id = gap.gap_id;

    IF gap.sequence_start < p_sequence THEN
        INSERT INTO sentinelflow.ingest_sequence_gaps (
            sender_id, endpoint_kind, sender_epoch, sequence_start,
            sequence_end, detected_by_batch_id, detected_at
        ) VALUES (
            gap.sender_id, gap.endpoint_kind, gap.sender_epoch,
            gap.sequence_start, p_sequence - 1,
            gap.detected_by_batch_id, gap.detected_at
        );
    END IF;
    IF p_sequence < gap.sequence_end THEN
        INSERT INTO sentinelflow.ingest_sequence_gaps (
            sender_id, endpoint_kind, sender_epoch, sequence_start,
            sequence_end, detected_by_batch_id, detected_at
        ) VALUES (
            gap.sender_id, gap.endpoint_kind, gap.sender_epoch,
            p_sequence + 1, gap.sequence_end,
            gap.detected_by_batch_id, gap.detected_at
        );
    END IF;
    INSERT INTO sentinelflow.ingest_sequence_gap_resolutions (
        sender_id, endpoint_kind, sender_epoch, sequence_start, sequence_end,
        resolution, resolution_batch_id, resolved_at
    ) VALUES (
        p_sender_id, p_endpoint_kind, p_sender_epoch, p_sequence, p_sequence,
        'late_arrival', p_batch_id, p_received_at
    );
    RETURN 'late_gap_closed';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.resolve_ingest_gap_as_lost(
    p_source_health_event_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    health sentinelflow.source_health_intervals%ROWTYPE;
    gap_id_value uuid;
    health_endpoint text;
BEGIN
    SELECT *
    INTO health
    FROM sentinelflow.source_health_intervals
    WHERE event_id = p_source_health_event_id
      AND trust_state = 'trusted'
      AND cause = 'permanent_loss'
      AND state = 'lost'
      AND detail_code = 'known_range'
      AND sequence_start IS NOT NULL
      AND sequence_end IS NOT NULL
      AND dropped_count = sequence_end - sequence_start + 1
      AND source_id = sender_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'gap loss resolution requires one exact trusted health event';
    END IF;

    SELECT batch.endpoint_kind
    INTO health_endpoint
    FROM sentinelflow.ingest_batches batch
    WHERE batch.sender_id = health.sender_id
      AND batch.sender_epoch = health.sender_epoch
      AND batch.batch_id = health.batch_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'gap loss resolution requires the authenticated source batch';
    END IF;

    SELECT gap.gap_id
    INTO gap_id_value
    FROM sentinelflow.ingest_sequence_gaps gap
    WHERE gap.sender_id = health.source_id
      AND gap.endpoint_kind = health_endpoint
      AND gap.sender_epoch = health.affected_sender_epoch
      AND gap.sequence_start = health.sequence_start
      AND gap.sequence_end = health.sequence_end
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'health loss range does not exactly match one unresolved gap';
    END IF;

    DELETE FROM sentinelflow.ingest_sequence_gaps
    WHERE gap_id = gap_id_value;

    INSERT INTO sentinelflow.ingest_sequence_gap_resolutions (
        sender_id, endpoint_kind, sender_epoch, sequence_start, sequence_end,
        resolution, source_health_event_id, resolved_at
    ) VALUES (
        health.sender_id, health_endpoint, health.affected_sender_epoch,
        health.sequence_start, health.sequence_end, 'permanent_loss',
        health.event_id, health.received_at
    );
END
$function$;

-- The checkpoint is a monotonic high-water mark. A late missing batch binds to
-- a lower sequence and closes its unresolved range without changing it.
CREATE OR REPLACE FUNCTION sentinelflow.require_atomic_ingest_checkpoint()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    previous_sequence bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sentinelflow.sender_checkpoints checkpoint
        WHERE checkpoint.sender_id = NEW.sender_id
          AND checkpoint.endpoint_kind = NEW.endpoint_kind
          AND checkpoint.sender_epoch = NEW.sender_epoch
          AND checkpoint.last_acknowledged_sequence >= NEW.sequence
          AND (
              checkpoint.last_acknowledged_sequence <> NEW.sequence OR
              checkpoint.last_acknowledged_body_digest = NEW.raw_body_digest
          )
        UNION ALL
        SELECT 1
        FROM sentinelflow.ingest_sequence_gap_resolutions resolution
        WHERE resolution.sender_id = NEW.sender_id
          AND resolution.endpoint_kind = NEW.endpoint_kind
          AND resolution.sender_epoch = NEW.sender_epoch
          AND resolution.sequence_start = NEW.sequence
          AND resolution.sequence_end = NEW.sequence
          AND resolution.resolution = 'late_arrival'
          AND resolution.resolution_batch_id = NEW.batch_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'accepted ingest batch requires an atomic high-water checkpoint';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM sentinelflow.ingest_sequence_gaps gap
        WHERE gap.sender_id = NEW.sender_id
          AND gap.endpoint_kind = NEW.endpoint_kind
          AND gap.sender_epoch = NEW.sender_epoch
          AND NEW.sequence BETWEEN gap.sequence_start AND gap.sequence_end
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'an accepted batch cannot remain in an unresolved gap';
    END IF;

    SELECT max(batch.sequence)
    INTO previous_sequence
    FROM sentinelflow.ingest_batches batch
    WHERE batch.sender_id = NEW.sender_id
      AND batch.sender_epoch = NEW.sender_epoch
      AND batch.endpoint_kind = NEW.endpoint_kind
      AND batch.sequence < NEW.sequence;

    IF EXISTS (
        SELECT 1
        FROM sentinelflow.sender_checkpoints checkpoint
        WHERE checkpoint.sender_id = NEW.sender_id
          AND checkpoint.endpoint_kind = NEW.endpoint_kind
          AND checkpoint.sender_epoch = NEW.sender_epoch
          AND checkpoint.last_acknowledged_sequence = NEW.sequence
    ) AND NEW.sequence > coalesce(previous_sequence, 0) + 1 AND NOT EXISTS (
        SELECT 1
        FROM sentinelflow.ingest_sequence_gaps gap
        WHERE gap.sender_id = NEW.sender_id
          AND gap.endpoint_kind = NEW.endpoint_kind
          AND gap.sender_epoch = NEW.sender_epoch
          AND gap.sequence_start = coalesce(previous_sequence, 0) + 1
          AND gap.sequence_end = NEW.sequence - 1
          AND gap.detected_by_batch_id = NEW.batch_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'a high-water jump requires the exact unresolved range';
    END IF;

    RETURN NULL;
END
$function$;

REVOKE UPDATE (
    sender_epoch, last_acknowledged_sequence, last_acknowledged_body_digest,
    clean_shutdown, unknown_loss, updated_at
) ON sentinelflow.sender_checkpoints FROM sentinelflow_api;

REVOKE ALL ON sentinelflow.ingest_sequence_gaps FROM PUBLIC;
REVOKE ALL ON sentinelflow.ingest_sequence_gap_resolutions FROM PUBLIC;
GRANT SELECT ON
    sentinelflow.ingest_sequence_gaps,
    sentinelflow.ingest_sequence_gap_resolutions
TO
    sentinelflow_api, sentinelflow_worker, sentinelflow_read;

REVOKE ALL ON FUNCTION sentinelflow.register_ingest_sequence(
    text, text, text, bigint, uuid, text, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.register_ingest_sequence(
    text, text, text, bigint, uuid, text, timestamptz
) TO sentinelflow_api;

REVOKE ALL ON FUNCTION sentinelflow.resolve_ingest_gap_as_lost(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.resolve_ingest_gap_as_lost(uuid)
    TO sentinelflow_api;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (5, 'ingest_gap_ranges')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
