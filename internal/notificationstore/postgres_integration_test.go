//go:build integration

package notificationstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/investigationapi"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestNotificationLedgerAgainstPostgreSQL17 exercises the production role and
// function boundary while append, replay, and bounded cleanup contend on the
// durable watermark. A rolled-back append proves that cursor gaps are valid.
func TestNotificationLedgerAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-notification-%d", time.Now().UnixNano())
	runNotificationDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForNotificationPostgreSQL(t, ctx, container)
	port := notificationDockerPort(t, ctx, container)
	dsn := fmt.Sprintf("postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port)

	owner := connectNotification(t, ctx, dsn)
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	applyNotificationMigrations(t, ctx, owner)
	var versionText string
	if err := owner.QueryRow(ctx, `SHOW server_version_num`).Scan(&versionText); err != nil {
		t.Fatal("query PostgreSQL version")
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version/10000 != 17 {
		t.Fatalf("expected PostgreSQL 17, got %q", versionText)
	}

	appendIncidentsConcurrently(t, ctx, dsn, 1, 12)
	time.Sleep(10 * time.Millisecond)
	var cutoff time.Time
	if err = owner.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&cutoff); err != nil {
		t.Fatalf("read database cleanup cutoff: %v", err)
	}

	api := connectNotification(t, ctx, dsn)
	t.Cleanup(func() { _ = api.Close(context.Background()) })
	if _, err = api.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatalf("set API role: %v", err)
	}
	store, err := NewPostgreSQLStore(api)
	if err != nil {
		t.Fatal(err)
	}
	leaseID := "019b0000-0000-4000-8000-00000000f020"
	processInstance := "019b0000-0000-4000-8000-00000000f021"
	if err = store.RegisterLease(ctx, leaseID, processInstance); err != nil {
		t.Fatalf("register SSE lease: %v", err)
	}
	var connectedAt, touchedAt, expiresAt time.Time
	if err = owner.QueryRow(ctx, `SELECT connected_at, touched_at, expires_at
FROM sentinelflow.sse_client_leases WHERE lease_id = $1`, leaseID).Scan(
		&connectedAt, &touchedAt, &expiresAt,
	); err != nil || !connectedAt.Equal(touchedAt) || !expiresAt.Equal(touchedAt.Add(45*time.Second)) {
		t.Fatalf("registered SSE lease connected=%s touched=%s expiry=%s err=%v",
			connectedAt, touchedAt, expiresAt, err)
	}
	if err = store.TouchLease(ctx, leaseID, processInstance); err != nil {
		t.Fatalf("touch SSE lease: %v", err)
	}
	if err = store.UnregisterLease(ctx, leaseID, processInstance); err != nil {
		t.Fatalf("unregister SSE lease: %v", err)
	}
	var leaseCount int
	if err = owner.QueryRow(ctx,
		`SELECT count(*) FROM sentinelflow.sse_client_leases WHERE lease_id = $1`, leaseID,
	).Scan(&leaseCount); err != nil || leaseCount != 0 {
		t.Fatalf("unregistered SSE lease count=%d err=%v", leaseCount, err)
	}

	worker := connectNotification(t, ctx, dsn)
	t.Cleanup(func() { _ = worker.Close(context.Background()) })
	if _, err = worker.Exec(ctx, `SET ROLE sentinelflow_worker`); err != nil {
		t.Fatalf("set worker role: %v", err)
	}

	operationErrors := make(chan error, 10)
	var operations sync.WaitGroup
	operations.Add(3)
	go func() {
		defer operations.Done()
		if appendErr := appendIncidentRange(ctx, dsn, 100, 8); appendErr != nil {
			operationErrors <- appendErr
		}
	}()
	go func() {
		defer operations.Done()
		_, pollErr := store.Poll(ctx, integrationPrincipal(), "s1.0000000000000000", 64)
		if pollErr != nil && !errors.Is(pollErr, investigationapi.ErrReplayGap) {
			operationErrors <- fmt.Errorf("concurrent replay: %w", pollErr)
		}
	}()
	go func() {
		defer operations.Done()
		var pruned int
		var floor, watermark int64
		pruneErr := worker.QueryRow(ctx,
			`SELECT pruned_count, replay_floor, watermark
			 FROM sentinelflow.prune_sse_notification_ledger($1, 5)`, cutoff,
		).Scan(&pruned, &floor, &watermark)
		if pruneErr != nil {
			operationErrors <- fmt.Errorf("concurrent prune: %w", pruneErr)
			return
		}
		if pruned != 5 || floor <= 0 || watermark < floor {
			operationErrors <- fmt.Errorf("invalid prune result count=%d floor=%d watermark=%d", pruned, floor, watermark)
		}
	}()
	operations.Wait()
	close(operationErrors)
	for operationErr := range operationErrors {
		t.Error(operationErr)
	}
	if t.Failed() {
		return
	}

	var beforeRollback int64
	if err = owner.QueryRow(ctx,
		`SELECT watermark FROM sentinelflow.sse_notification_replay_state WHERE singleton`,
	).Scan(&beforeRollback); err != nil {
		t.Fatalf("read pre-rollback watermark: %v", err)
	}
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = insertIntegrationIncident(ctx, tx, 900); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("insert rolled-back incident: %v", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback notification allocation: %v", err)
	}
	if err = insertIntegrationIncident(ctx, owner, 901); err != nil {
		t.Fatalf("insert post-rollback incident: %v", err)
	}

	var floor, watermark, minimumRetained, maximumRetained int64
	var retained int
	if err = owner.QueryRow(ctx, `
SELECT state.replay_floor, state.watermark,
       min(ledger.cursor), max(ledger.cursor), count(*)
FROM sentinelflow.sse_notification_replay_state state
JOIN sentinelflow.sse_notification_ledger ledger
  ON ledger.cursor > state.replay_floor AND ledger.cursor <= state.watermark
WHERE state.singleton
GROUP BY state.replay_floor, state.watermark`).Scan(
		&floor, &watermark, &minimumRetained, &maximumRetained, &retained,
	); err != nil {
		t.Fatalf("read final replay state: %v", err)
	}
	if floor <= 0 || retained != 16 || minimumRetained <= floor || maximumRetained != watermark ||
		watermark <= beforeRollback+1 {
		t.Fatalf("final floor=%d watermark=%d min=%d max=%d retained=%d before_rollback=%d",
			floor, watermark, minimumRetained, maximumRetained, retained, beforeRollback)
	}

	window, err := store.Tail(ctx, integrationPrincipal())
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	expectedFloor, _ := investigationapi.FormatSequenceCursor(floor)
	expectedWatermark, _ := investigationapi.FormatSequenceCursor(watermark)
	if window.Floor != expectedFloor || window.Watermark != expectedWatermark {
		t.Fatalf("window=%+v expected=%s..%s", window, expectedFloor, expectedWatermark)
	}
	page, err := store.Poll(ctx, integrationPrincipal(), expectedFloor, 64)
	if err != nil || page.Gap || len(page.Events) != retained || page.Next != expectedWatermark {
		t.Fatalf("retained page count=%d page=%+v err=%v", retained, page, err)
	}
	for index, event := range page.Events {
		if event.Type != investigationapi.EventIncidentCreated || event.IncidentID == nil ||
			*event.IncidentID != event.ResourceID {
			t.Fatalf("event[%d]=%+v", index, event)
		}
		if index > 0 {
			comparison, compareErr := store.CompareCursor(page.Events[index-1].ID, event.ID)
			if compareErr != nil || comparison >= 0 {
				t.Fatalf("event order at %d comparison=%d err=%v", index, comparison, compareErr)
			}
		}
	}
	gapPage, err := store.Poll(ctx, integrationPrincipal(), "s1.0000000000000000", 64)
	if !errors.Is(err, investigationapi.ErrReplayGap) || !gapPage.Gap || len(gapPage.Events) != 0 {
		t.Fatalf("old cursor page=%+v err=%v", gapPage, err)
	}

	if _, err = api.Exec(ctx, `SELECT cursor FROM sentinelflow.sse_notification_ledger LIMIT 1`); err == nil {
		t.Fatal("API role unexpectedly read the notification ledger directly")
	}
	if _, err = api.Exec(ctx, `SELECT lease_id FROM sentinelflow.sse_client_leases LIMIT 1`); err == nil {
		t.Fatal("API role unexpectedly read SSE client leases directly")
	}
	if _, err = worker.Exec(ctx, `DELETE FROM sentinelflow.sse_notification_ledger WHERE false`); err == nil {
		t.Fatal("worker role unexpectedly deleted from the notification ledger directly")
	}
}

type integrationExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertIntegrationIncident(ctx context.Context, connection integrationExecer, sequence int) error {
	id := fmt.Sprintf("019b0000-0000-7000-8000-%012x", sequence)
	_, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.incidents (
    incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
    deterministic_score, version, created_at, updated_at
) VALUES ($1, 'request_burst', 'open', '203.0.113.20', 'demo',
          clock_timestamp(), clock_timestamp(), 0.9, 1,
          clock_timestamp(), clock_timestamp())`, id)
	return err
}

func appendIncidentsConcurrently(t *testing.T, ctx context.Context, dsn string, start, count int) {
	t.Helper()
	if err := appendIncidentRange(ctx, dsn, start, count); err != nil {
		t.Fatal(err)
	}
}

func appendIncidentRange(ctx context.Context, dsn string, start, count int) error {
	errorsChannel := make(chan error, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		sequence := start + index
		wait.Add(1)
		go func() {
			defer wait.Done()
			connection, err := pgx.Connect(ctx, dsn)
			if err != nil {
				errorsChannel <- err
				return
			}
			defer connection.Close(context.Background())
			if err = insertIntegrationIncident(ctx, connection, sequence); err != nil {
				errorsChannel <- err
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			return err
		}
	}
	return nil
}

func integrationPrincipal() investigationapi.Principal {
	now := time.Now().UTC()
	return investigationapi.Principal{
		ActorID: "admin", SessionID: testSessionID,
		ValidatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
}

func connectNotification(t *testing.T, ctx context.Context, dsn string) *pgx.Conn {
	t.Helper()
	var lastErr error
	for range 60 {
		connection, err := pgx.Connect(ctx, dsn)
		if err == nil {
			return connection
		}
		lastErr = err
		select {
		case <-ctx.Done():
			t.Fatalf("connect PostgreSQL: %v", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatalf("connect PostgreSQL: %v", lastErr)
	return nil
}

func applyNotificationMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test")
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", filepath.Base(path), readErr)
		}
		if _, applyErr := connection.Exec(ctx, string(contents)); applyErr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(path), applyErr)
		}
	}
}

func waitForNotificationPostgreSQL(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	for range 80 {
		if exec.CommandContext(ctx, "docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "postgres").Run() == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PostgreSQL readiness: %v", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("PostgreSQL 17 did not become ready")
}

func notificationDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := runNotificationDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func runNotificationDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}
