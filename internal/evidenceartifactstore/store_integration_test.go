//go:build integration

package evidenceartifactstore

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/jackc/pgx/v5"
)

const postgres17Image = "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"

func TestAtomicEvidenceProducerAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-evidence-artifact-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only", "--publish", "127.0.0.1::5432",
		postgres17Image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitPostgres(t, ctx, container)
	port := publishedPort(t, ctx, container)
	connection := connectPostgres(t, ctx, fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	))
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	applyAllMigrations(t, ctx, connection)
	insertProducerSources(t, ctx, connection)

	if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	store, err := NewPostgreSQLStore(connection)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest(t)
	inserted, err := store.Insert(ctx, request)
	if err != nil || !inserted {
		t.Fatalf("inserted=%v err=%v", inserted, err)
	}
	inserted, err = store.Insert(ctx, request)
	if err != nil || inserted {
		t.Fatalf("replay inserted=%v err=%v", inserted, err)
	}
	conflict := request
	conflict.ExpiresAt = conflict.ExpiresAt.Add(time.Hour)
	if _, err := store.Insert(ctx, conflict); err != ErrPersistence {
		t.Fatalf("conflicting replay err=%v", err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO sentinelflow.evidence_snapshots DEFAULT VALUES`); err == nil {
		t.Fatal("worker retained raw evidence insert authority")
	}
	if _, err := connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}

	missingSnapshotID := "019b0000-0000-7000-8000-00000000a101"
	missingEventID := "019b0000-0000-7000-8000-00000000a102"
	missingEventRowID := "019b0000-0000-7000-8000-00000000a103"
	checked, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:    missingSnapshotID, IncidentID: testIncidentID, IncidentVersion: 1,
		SourceIPv4: "8.8.8.8", ServiceLabel: "gateway",
		WindowStart: testNow.Add(-time.Minute), WindowEnd: testNow,
		SourceHealthDigest: testDigest, EventIDs: []string{missingEventID},
		SignalIDs: []string{testSignalID}, CreatedAt: testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	rollbackRequest := InsertRequest{
		Evidence: checked, SourceHealthStatus: validation.SourceHealthComplete,
		ExpiresAt: testNow.Add(24 * time.Hour),
		Signals:   []SignalRow{{testSignalID, testDigest, 1}},
		Events:    []EventRow{{missingEventRowID, testSignalID, EventGateway, missingEventID, testNow}},
	}
	if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Insert(ctx, rollbackRequest); err != ErrPersistence {
		t.Fatalf("missing source err=%v", err)
	}
	if _, err := connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	var rolledBack int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.evidence_snapshots
WHERE evidence_snapshot_id = $1`, missingSnapshotID).Scan(&rolledBack); err != nil || rolledBack != 0 {
		t.Fatalf("rollback count=%d err=%v", rolledBack, err)
	}
	if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_api"); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT * FROM sentinelflow.evidence_snapshot_artifacts`); err == nil {
		t.Fatal("API obtained direct canonical evidence read authority")
	}
	if _, err := connection.Exec(ctx, `SELECT * FROM sentinelflow.read_hil_exact_artifact(
'019b0000-0000-7000-8000-00000000ffff', 1)`); err != nil {
		t.Fatalf("bounded read coordinator unavailable: %v", err)
	}
}

func insertProducerSources(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES ('exact-producer', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 0,
    NULL, false, false, $1::timestamptz);
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES ('exact-producer', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-00000000a010', 1, 'gateway', 'event-batch-v1',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    100, 1, $1::timestamptz, $1::timestamptz);
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest =
        'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    clean_shutdown = true, updated_at = $1::timestamptz
WHERE sender_id = 'exact-producer' AND endpoint_kind = 'gateway';
INSERT INTO sentinelflow.gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
    route_label, path_catalog_version, suspicious_path_id, host, service_label,
    status_code, request_bytes, response_bytes, latency_ms, trust_state, trust_reason
) VALUES ($2, 'gateway-http-v1', 'exact-producer', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-00000000a010',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    '019b0000-0000-7000-8000-00000000a011',
    '019b0000-0000-7000-8000-00000000a012', $1::timestamptz, $1::timestamptz, '8.8.8.8', 'GET',
    'HTTP/1.1', 'public', 'path-catalog-v1', 'admin_console', 'example.test',
    'gateway', 404, 0, 0, 1, 'trusted', 'none');
INSERT INTO sentinelflow.signals (
    signal_id, schema_version, rule_id, rule_version, kind, source_ip,
    service_label, window_start, window_end, observed_count, distinct_count,
    threshold_count, threshold_distinct, source_health_status, evidence_digest
) VALUES ($3, 'signal-v1', 'path_scan.v1', 1, 'path_scan', '8.8.8.8',
    'gateway', $1::timestamptz - interval '1 minute', $1::timestamptz, 1, 1, 1, 1, 'complete', $4);
INSERT INTO sentinelflow.signal_evidence (
    evidence_link_id, signal_id, event_kind, gateway_event_id,
    event_time, relation_reason, created_at
) VALUES ('019b0000-0000-7000-8000-00000000a013', $3, 'gateway', $2,
    $1::timestamptz, 'threshold_member', $1::timestamptz);
INSERT INTO sentinelflow.incidents (
    incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
    deterministic_score, version, created_at, updated_at
) VALUES ($5, 'path_scan', 'open', '8.8.8.8', 'gateway',
    $1::timestamptz - interval '1 minute', $1::timestamptz, 0.9, 1,
    $1::timestamptz, $1::timestamptz);`,
		pgx.QueryExecModeSimpleProtocol,
		testNow, testEventID, testSignalID, testDigest, testIncidentID)
	if err != nil {
		t.Fatalf("insert producer sources: %v", err)
	}
}

func applyAllMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate integration test")
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, execErr := connection.Exec(ctx, string(contents)); execErr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(path), execErr)
		}
	}
}

func connectPostgres(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	for range 40 {
		connection, err := pgx.Connect(ctx, connectionString)
		if err == nil {
			return connection
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("connect PostgreSQL 17")
	return nil
}

func waitPostgres(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	for range 80 {
		if exec.CommandContext(ctx, "docker", "exec", container,
			"pg_isready", "-U", "postgres", "-d", "postgres").Run() == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("PostgreSQL 17 did not become ready")
}

func publishedPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := runDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 {
		t.Fatalf("unexpected port output %q", output)
	}
	return parts[len(parts)-1]
}

func runDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}
