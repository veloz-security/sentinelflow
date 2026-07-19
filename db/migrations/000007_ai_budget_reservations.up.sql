BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

CREATE TABLE IF NOT EXISTS ai_budget_reservations (
    reservation_id uuid PRIMARY KEY,
    budget_date date NOT NULL,
    model ascii_id NOT NULL,
    rate_card_version ascii_id NOT NULL,
    reserved_micro_usd bigint NOT NULL CHECK (reserved_micro_usd > 0),
    charged_micro_usd bigint NULL CHECK (
        charged_micro_usd IS NULL OR charged_micro_usd > 0
    ),
    state text NOT NULL CHECK (state IN ('active', 'settled', 'expired')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    settled_at timestamptz NULL,
    CONSTRAINT ai_budget_reservation_ledger_fk FOREIGN KEY (
        budget_date, model, rate_card_version
    ) REFERENCES ai_budget_ledger (
        budget_date, model, rate_card_version
    ) ON DELETE RESTRICT,
    CONSTRAINT ai_budget_reservation_time CHECK (
        expires_at > created_at AND
        expires_at <= created_at + interval '2 minutes' AND
        (settled_at IS NULL OR settled_at >= created_at)
    ),
    CONSTRAINT ai_budget_reservation_state CHECK (
        (state = 'active' AND charged_micro_usd IS NULL AND settled_at IS NULL) OR
        (state IN ('settled', 'expired') AND charged_micro_usd IS NOT NULL AND settled_at IS NOT NULL)
    ),
    CONSTRAINT ai_budget_reservation_charge CHECK (
        charged_micro_usd IS NULL OR charged_micro_usd <= reserved_micro_usd
    )
);

CREATE INDEX IF NOT EXISTS ai_budget_reservations_ledger_state_idx
    ON ai_budget_reservations (
        budget_date, model, rate_card_version, state, expires_at
    );

CREATE OR REPLACE FUNCTION sentinelflow.reserve_ai_budget(
    p_reservation_id uuid,
    p_model text,
    p_rate_card_version text,
    p_limit_micro_usd bigint,
    p_reserved_micro_usd bigint
)
RETURNS SETOF sentinelflow.ai_budget_reservations
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    server_budget_date date;
    ledger sentinelflow.ai_budget_ledger%ROWTYPE;
    reservation sentinelflow.ai_budget_reservations%ROWTYPE;
    expired_charge bigint := 0;
BEGIN
    IF p_reservation_id IS NULL OR p_model IS NULL OR p_rate_card_version IS NULL OR
       p_model !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       p_rate_card_version !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       p_limit_micro_usd IS NULL OR p_limit_micro_usd <= 0 OR
       p_limit_micro_usd > 1000000000000 OR
       p_reserved_micro_usd IS NULL OR p_reserved_micro_usd <= 0 OR
       p_reserved_micro_usd > p_limit_micro_usd THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid AI budget reservation';
    END IF;

    server_budget_date := (server_now AT TIME ZONE 'UTC')::date;

    INSERT INTO sentinelflow.ai_budget_ledger (
        budget_date, model, rate_card_version, limit_micro_usd,
        reserved_micro_usd, settled_micro_usd, consumed_micro_usd, updated_at
    ) VALUES (
        server_budget_date, p_model, p_rate_card_version, p_limit_micro_usd,
        0, 0, 0, server_now
    )
    ON CONFLICT (budget_date, model, rate_card_version) DO NOTHING;

    SELECT * INTO STRICT ledger
    FROM sentinelflow.ai_budget_ledger
    WHERE budget_date = server_budget_date
      AND model = p_model
      AND rate_card_version = p_rate_card_version
    FOR UPDATE;

    IF ledger.limit_micro_usd <> p_limit_micro_usd THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'AI budget limit mismatch';
    END IF;

    -- A process crash cannot release an unknown request as free. Once the
    -- bounded request/settlement window expires, charge the full reservation.
    WITH expired AS (
        SELECT candidate.reservation_id
        FROM sentinelflow.ai_budget_reservations candidate
        WHERE candidate.budget_date = server_budget_date
          AND candidate.model = p_model
          AND candidate.rate_card_version = p_rate_card_version
          AND candidate.state = 'active'
          AND candidate.expires_at <= server_now
        ORDER BY candidate.expires_at, candidate.reservation_id
        FOR UPDATE
    ), charged AS (
        UPDATE sentinelflow.ai_budget_reservations current
        SET state = 'expired',
            charged_micro_usd = current.reserved_micro_usd,
            settled_at = server_now
        FROM expired
        WHERE current.reservation_id = expired.reservation_id
        RETURNING current.reserved_micro_usd
    )
    SELECT COALESCE(sum(charged.reserved_micro_usd), 0)::bigint
    INTO expired_charge
    FROM charged;

    IF expired_charge > 0 THEN
        UPDATE sentinelflow.ai_budget_ledger current
        SET reserved_micro_usd = current.reserved_micro_usd - expired_charge,
            settled_micro_usd = current.settled_micro_usd + expired_charge,
            consumed_micro_usd = current.consumed_micro_usd + expired_charge,
            updated_at = server_now
        WHERE current.budget_date = server_budget_date
          AND current.model = p_model
          AND current.rate_card_version = p_rate_card_version
        RETURNING current.* INTO ledger;
    END IF;

    IF ledger.reserved_micro_usd::numeric +
       ledger.consumed_micro_usd::numeric +
       p_reserved_micro_usd::numeric > ledger.limit_micro_usd::numeric THEN
        RETURN;
    END IF;

    INSERT INTO sentinelflow.ai_budget_reservations (
        reservation_id, budget_date, model, rate_card_version,
        reserved_micro_usd, state, created_at, expires_at
    ) VALUES (
        p_reservation_id, server_budget_date, p_model, p_rate_card_version,
        p_reserved_micro_usd, 'active', server_now,
        server_now + interval '2 minutes'
    )
    RETURNING * INTO reservation;

    UPDATE sentinelflow.ai_budget_ledger current
    SET reserved_micro_usd = current.reserved_micro_usd + p_reserved_micro_usd,
        updated_at = server_now
    WHERE current.budget_date = server_budget_date
      AND current.model = p_model
      AND current.rate_card_version = p_rate_card_version;

    RETURN NEXT reservation;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.settle_ai_budget(
    p_reservation_id uuid,
    p_charged_micro_usd bigint
)
RETURNS SETOF sentinelflow.ai_budget_reservations
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    reservation_key sentinelflow.ai_budget_reservations%ROWTYPE;
    reservation sentinelflow.ai_budget_reservations%ROWTYPE;
BEGIN
    IF p_reservation_id IS NULL OR p_charged_micro_usd IS NULL OR
       p_charged_micro_usd <= 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid AI budget settlement';
    END IF;

    -- Read the immutable ledger key, then acquire locks in the same
    -- ledger-before-reservation order used by reserve_ai_budget.
    SELECT * INTO reservation_key
    FROM sentinelflow.ai_budget_reservations
    WHERE reservation_id = p_reservation_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    PERFORM 1
    FROM sentinelflow.ai_budget_ledger
    WHERE budget_date = reservation_key.budget_date
      AND model = reservation_key.model
      AND rate_card_version = reservation_key.rate_card_version
    FOR UPDATE;

    SELECT * INTO STRICT reservation
    FROM sentinelflow.ai_budget_reservations
    WHERE reservation_id = p_reservation_id
    FOR UPDATE;

    IF reservation.state = 'settled' THEN
        IF reservation.charged_micro_usd <> p_charged_micro_usd THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'AI budget settlement mismatch';
        END IF;
        RETURN NEXT reservation;
        RETURN;
    END IF;

    IF reservation.state <> 'active' OR reservation.expires_at <= server_now OR
       p_charged_micro_usd > reservation.reserved_micro_usd THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'AI budget reservation is not settleable';
    END IF;

    UPDATE sentinelflow.ai_budget_reservations current
    SET state = 'settled',
        charged_micro_usd = p_charged_micro_usd,
        settled_at = server_now
    WHERE current.reservation_id = p_reservation_id
    RETURNING current.* INTO reservation;

    UPDATE sentinelflow.ai_budget_ledger current
    SET reserved_micro_usd = current.reserved_micro_usd - reservation.reserved_micro_usd,
        settled_micro_usd = current.settled_micro_usd + p_charged_micro_usd,
        consumed_micro_usd = current.consumed_micro_usd + p_charged_micro_usd,
        updated_at = server_now
    WHERE current.budget_date = reservation.budget_date
      AND current.model = reservation.model
      AND current.rate_card_version = reservation.rate_card_version;

    RETURN NEXT reservation;
END
$function$;

REVOKE INSERT, UPDATE, DELETE ON sentinelflow.ai_budget_ledger
    FROM sentinelflow_worker;
REVOKE ALL ON sentinelflow.ai_budget_reservations FROM PUBLIC;
GRANT SELECT ON sentinelflow.ai_budget_reservations TO sentinelflow_read;

REVOKE ALL ON FUNCTION sentinelflow.reserve_ai_budget(
    uuid, text, text, bigint, bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.reserve_ai_budget(
    uuid, text, text, bigint, bigint
) TO sentinelflow_worker;

REVOKE ALL ON FUNCTION sentinelflow.settle_ai_budget(
    uuid, bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.settle_ai_budget(
    uuid, bigint
) TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (7, 'ai_budget_reservations')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
