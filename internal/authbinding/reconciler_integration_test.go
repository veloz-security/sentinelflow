//go:build integration

package authbinding

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestPostgreSQLReconcilerIntegration is opt-in because it requires an empty or
// disposable PostgreSQL 17 database with all SentinelFlow migrations applied.
// The environment value is never logged.
func TestPostgreSQLReconcilerIntegration(t *testing.T) {
	databaseURL := os.Getenv("SENTINELFLOW_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SENTINELFLOW_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal("connect to disposable PostgreSQL")
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) })

	cleanup := func(cleanupCtx context.Context) {
		_, _ = connection.Exec(cleanupCtx, `RESET ROLE`)
		_, _ = connection.Exec(cleanupCtx, `
DELETE FROM sentinelflow.auth_events
WHERE event_id IN (
    '019b0000-0000-7000-8000-000000000401',
    '019b0000-0000-7000-8000-000000000402',
    '019b0000-0000-7000-8000-000000000403'
);
DELETE FROM sentinelflow.gateway_events
WHERE event_id = '019b0000-0000-7000-8000-000000000101';
DELETE FROM sentinelflow.ingest_batches
WHERE sender_id IN ('gateway.authbinding.integration', 'auth.authbinding.integration');
DELETE FROM sentinelflow.sender_checkpoints
WHERE sender_id IN ('gateway.authbinding.integration', 'auth.authbinding.integration');`)
	}
	cleanup(ctx)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		cleanup(cleanupCtx)
	})

	if _, err = connection.Exec(ctx, integrationSeedSQL); err != nil {
		t.Fatalf("seed synthetic reconciliation rows: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set least-privilege API role")
	}

	reconciler, err := NewPostgreSQLReconciler(connection, 10)
	if err != nil {
		t.Fatalf("NewPostgreSQLReconciler() error = %v", err)
	}
	result, err := reconciler.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result != (Result{Examined: 3, Verified: 1, Untrusted: 2, Expired: 1}) {
		t.Fatalf("Reconcile() = %+v", result)
	}

	rows, err := connection.Query(ctx, `
SELECT event_id::text, binding_state, binding_reason,
       COALESCE(bound_gateway_event_id::text, '')
FROM sentinelflow.auth_events
WHERE event_id IN (
    '019b0000-0000-7000-8000-000000000401',
    '019b0000-0000-7000-8000-000000000402',
    '019b0000-0000-7000-8000-000000000403'
)
ORDER BY event_id`)
	if err != nil {
		t.Fatal("query reconciliation states")
	}
	defer rows.Close()
	want := [][4]string{
		{"019b0000-0000-7000-8000-000000000401", "verified", "verified", "019b0000-0000-7000-8000-000000000101"},
		{"019b0000-0000-7000-8000-000000000402", "untrusted", "source_mismatch", ""},
		{"019b0000-0000-7000-8000-000000000403", "untrusted", "expired", ""},
	}
	index := 0
	for rows.Next() {
		var got [4]string
		if err = rows.Scan(&got[0], &got[1], &got[2], &got[3]); err != nil {
			t.Fatal("scan reconciliation state")
		}
		if index >= len(want) || got != want[index] {
			t.Fatalf("row %d = %#v", index, got)
		}
		index++
	}
	if err = rows.Err(); err != nil || index != len(want) {
		t.Fatalf("state rows=%d err=%v", index, err)
	}
}

const integrationSeedSQL = `
INSERT INTO sentinelflow.sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, updated_at
) VALUES
(
    'gateway.authbinding.integration', 'gateway',
    'AAAAAAAAAAAAAAAAAAAAAA', 0, NULL, clock_timestamp()
),
(
    'auth.authbinding.integration', 'auth',
    'AQEBAQEBAQEBAQEBAQEBAQ', 0, NULL, clock_timestamp()
);

INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind,
    schema_version, raw_body_digest, raw_body_size, record_count,
    sent_at, received_at
) VALUES
(
    'gateway.authbinding.integration', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-000000000001', 1, 'gateway',
    'event-batch-v1',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    100, 1, clock_timestamp(), clock_timestamp()
),
(
    'auth.authbinding.integration', 'AQEBAQEBAQEBAQEBAQEBAQ',
    '019b0000-0000-7000-8000-000000000002', 1, 'auth',
    'event-batch-v1',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    300, 3, clock_timestamp(), clock_timestamp()
);

UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest = CASE endpoint_kind
        WHEN 'gateway' THEN
            'sha256:1111111111111111111111111111111111111111111111111111111111111111'
        ELSE
            'sha256:2222222222222222222222222222222222222222222222222222222222222222'
    END,
    updated_at = clock_timestamp()
WHERE sender_id IN ('gateway.authbinding.integration', 'auth.authbinding.integration');

INSERT INTO sentinelflow.gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id,
    idempotency_key, request_id, trace_id, started_at, completed_at,
    source_ip, method, protocol, route_label, path_catalog_version,
    suspicious_path_id, host, service_label, status_code, request_bytes,
    response_bytes, latency_ms, received_at
) VALUES (
    '019b0000-0000-7000-8000-000000000101', 'gateway-http-v1',
    'gateway.authbinding.integration', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-000000000001',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    '019b0000-0000-7000-8000-000000000201',
    '019b0000-0000-7000-8000-000000000301',
    clock_timestamp() - interval '2 seconds',
    clock_timestamp() - interval '1 second',
    '203.0.113.10', 'POST', 'HTTP/1.1', 'login', 'path-catalog-v1',
    'none', 'demo.local', 'demo-app', 401, 100, 200, 1, clock_timestamp()
);

WITH timing AS MATERIALIZED (
    SELECT clock_timestamp() AS now
)
INSERT INTO sentinelflow.auth_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id,
    idempotency_key, gateway_request_id, trace_id, occurred_at, source_ip,
    service_label, route_label, account_hash, outcome, received_at,
    binding_deadline
)
SELECT
    '019b0000-0000-7000-8000-000000000401'::uuid, 'auth-event-v1',
    'auth.authbinding.integration', 'AQEBAQEBAQEBAQEBAQEBAQ',
    '019b0000-0000-7000-8000-000000000002'::uuid,
    'sha256:4444444444444444444444444444444444444444444444444444444444444444',
    '019b0000-0000-7000-8000-000000000201'::uuid,
    '019b0000-0000-7000-8000-000000000301'::uuid,
    timing.now - interval '1 second', '203.0.113.10'::inet,
    'demo-app', 'login',
    'hmac-sha256:5555555555555555555555555555555555555555555555555555555555555555',
    'failed', timing.now, timing.now + interval '5 minutes'
FROM timing
UNION ALL
SELECT
    '019b0000-0000-7000-8000-000000000402'::uuid, 'auth-event-v1',
    'auth.authbinding.integration', 'AQEBAQEBAQEBAQEBAQEBAQ',
    '019b0000-0000-7000-8000-000000000002'::uuid,
    'sha256:6666666666666666666666666666666666666666666666666666666666666666',
    '019b0000-0000-7000-8000-000000000201'::uuid,
    '019b0000-0000-7000-8000-000000000301'::uuid,
    timing.now - interval '1 second', '203.0.113.11'::inet,
    'demo-app', 'login',
    'hmac-sha256:7777777777777777777777777777777777777777777777777777777777777777',
    'failed', timing.now, timing.now + interval '5 minutes'
FROM timing
UNION ALL
SELECT
    '019b0000-0000-7000-8000-000000000403'::uuid, 'auth-event-v1',
    'auth.authbinding.integration', 'AQEBAQEBAQEBAQEBAQEBAQ',
    '019b0000-0000-7000-8000-000000000002'::uuid,
    'sha256:8888888888888888888888888888888888888888888888888888888888888888',
    '019b0000-0000-7000-8000-000000000202'::uuid,
    '019b0000-0000-7000-8000-000000000302'::uuid,
    timing.now - interval '7 minutes', '203.0.113.12'::inet,
    'demo-app', 'login',
    'hmac-sha256:9999999999999999999999999999999999999999999999999999999999999999',
    'failed', timing.now - interval '6 minutes',
    timing.now - interval '1 minute'
FROM timing;`
