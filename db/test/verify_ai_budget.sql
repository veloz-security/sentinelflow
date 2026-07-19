BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $reservation_settlement_and_limit$
DECLARE
    reserved ai_budget_reservations%ROWTYPE;
    none ai_budget_reservations%ROWTYPE;
    settled ai_budget_reservations%ROWTYPE;
    ledger ai_budget_ledger%ROWTYPE;
BEGIN
    SELECT * INTO reserved FROM reserve_ai_budget(
        '019b0000-0000-4000-8000-000000008001',
        'gpt-5.6-sol', 'operator-v1', 10000000, 6000000
    );
    IF reserved.reservation_id IS NULL OR reserved.state <> 'active' OR
       reserved.reserved_micro_usd <> 6000000 OR
       reserved.budget_date <> (clock_timestamp() AT TIME ZONE 'UTC')::date OR
       reserved.expires_at - reserved.created_at <> interval '2 minutes' THEN
        RAISE EXCEPTION 'atomic AI budget reservation was not created';
    END IF;

    SELECT * INTO none FROM reserve_ai_budget(
        '019b0000-0000-4000-8000-000000008002',
        'gpt-5.6-sol', 'operator-v1', 10000000, 5000000
    );
    IF none.reservation_id IS NOT NULL THEN
        RAISE EXCEPTION 'over-budget concurrent reservation was accepted';
    END IF;

    SELECT * INTO settled FROM settle_ai_budget(
        reserved.reservation_id, 2000000
    );
    IF settled.state <> 'settled' OR settled.charged_micro_usd <> 2000000 THEN
        RAISE EXCEPTION 'trusted-usage settlement was not recorded';
    END IF;

    SELECT * INTO settled FROM settle_ai_budget(
        reserved.reservation_id, 2000000
    );
    IF settled.state <> 'settled' THEN
        RAISE EXCEPTION 'exact settlement replay was not idempotent';
    END IF;

    BEGIN
        PERFORM * FROM settle_ai_budget(reserved.reservation_id, 2000001);
        RAISE EXCEPTION 'conflicting settlement replay was accepted';
    EXCEPTION WHEN invalid_parameter_value THEN
        NULL;
    END;

    SELECT * INTO ledger
    FROM ai_budget_ledger
    WHERE budget_date = reserved.budget_date
      AND model = reserved.model
      AND rate_card_version = reserved.rate_card_version;
    IF ledger.reserved_micro_usd <> 0 OR ledger.consumed_micro_usd <> 2000000 OR
       ledger.settled_micro_usd <> 2000000 THEN
        RAISE EXCEPTION 'settlement did not atomically update the ledger';
    END IF;
END
$reservation_settlement_and_limit$;

DO $expired_reservation_is_fully_charged$
DECLARE
    reserved ai_budget_reservations%ROWTYPE;
    none ai_budget_reservations%ROWTYPE;
    ledger ai_budget_ledger%ROWTYPE;
BEGIN
    SELECT * INTO reserved FROM reserve_ai_budget(
        '019b0000-0000-4000-8000-000000008003',
        'gpt-5.6-sol', 'operator-v1', 10000000, 8000000
    );
    IF reserved.reservation_id IS NULL THEN
        RAISE EXCEPTION 'remaining daily budget was not reservable';
    END IF;

    UPDATE ai_budget_reservations
    SET created_at = reference_time.value - interval '2 minutes',
        expires_at = reference_time.value - interval '1 microsecond'
    FROM (SELECT clock_timestamp() AS value) AS reference_time
    WHERE reservation_id = reserved.reservation_id;

    SELECT * INTO none FROM reserve_ai_budget(
        '019b0000-0000-4000-8000-000000008004',
        'gpt-5.6-sol', 'operator-v1', 10000000, 1
    );
    IF none.reservation_id IS NOT NULL THEN
        RAISE EXCEPTION 'expired conservative charge allowed overspend';
    END IF;

    SELECT * INTO reserved
    FROM ai_budget_reservations
    WHERE reservation_id = reserved.reservation_id;
    SELECT * INTO ledger
    FROM ai_budget_ledger
    WHERE budget_date = reserved.budget_date
      AND model = reserved.model
      AND rate_card_version = reserved.rate_card_version;
    IF reserved.state <> 'expired' OR reserved.charged_micro_usd <> 8000000 OR
       ledger.reserved_micro_usd <> 0 OR ledger.consumed_micro_usd <> 10000000 OR
       ledger.settled_micro_usd <> 10000000 THEN
        RAISE EXCEPTION 'crashed request was not conservatively charged';
    END IF;

    BEGIN
        PERFORM * FROM reserve_ai_budget(
            '019b0000-0000-4000-8000-000000008005',
            'gpt-5.6-sol', 'operator-v1', 10000001, 1
        );
        RAISE EXCEPTION 'daily limit mutation was accepted';
    EXCEPTION WHEN invalid_parameter_value THEN
        NULL;
    END;
END
$expired_reservation_is_fully_charged$;

ROLLBACK;
