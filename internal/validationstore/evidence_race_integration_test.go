//go:build integration

package validationstore

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/validationworker"
)

func TestValidationEvidenceRaceBothLockOrdersAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-validation-race-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432",
		"postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForPostgreSQL(t, ctx, container)
	port := dockerPort(t, ctx, container)

	t.Run("validation_prepare_commits_before_later_evidence", func(t *testing.T) {
		url := provisionValidationRaceDatabase(t, ctx, container, port, "validation_race_first")
		admin := connectWithRetry(t, ctx, url)
		defer admin.Close(context.Background())
		observer := connectWithRetry(t, ctx, url)
		defer observer.Close(context.Background())
		insertValidationFixture(t, ctx, admin)
		pool := demoValidationWorkerPool(t, ctx, url)
		defer pool.Close()
		store, _ := NewPostgreSQLStore(pool)
		lease := leaseRequest()
		lease.Now = time.Now().UTC()
		lease.LeaseExpiresAt = lease.Now.Add(30 * time.Second)
		job, found, err := store.Lease(ctx, lease)
		if err != nil || !found {
			t.Fatalf("lease found=%v err=%v", found, err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		txStore, _ := NewPostgreSQLStore(tx)
		snapshot, prepared, err := txStore.Prepare(ctx, validationworker.PrepareRequest{
			Job: job.Job, LeaseToken: job.LeaseToken,
		})
		if err != nil || !prepared {
			_ = tx.Rollback(ctx)
			t.Fatalf("prepare prepared=%v err=%v", prepared, err)
		}

		updater := connectWithRetry(t, ctx, url)
		defer updater.Close(context.Background())
		updateDone := make(chan error, 1)
		go func() {
			_, updateErr := updater.Exec(ctx, `/* validation-first-evidence */
UPDATE sentinelflow.incidents SET evidence_version = 2
WHERE incident_id = $1::uuid`, testIncidentID)
			updateDone <- updateErr
		}()
		waitForValidationRaceBlock(t, ctx, observer, "validation-first-evidence")
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-updateDone; err != nil {
			t.Fatal(err)
		}

		request := exactValidFinalize(t, snapshot)
		request.Finish.Now = time.Now().UTC()
		request.Finish.LeaseToken = job.LeaseToken
		request.Mutation.ValidationAttemptID = snapshot.ValidationAttemptID
		if finished, finalizeErr := store.Finalize(ctx, request); finished ||
			!errors.Is(finalizeErr, ErrEvidenceStale) {
			t.Fatalf("stale finalize finished=%v err=%v", finished, finalizeErr)
		}
		assertStaleValidationTerminal(t, ctx, admin, true)
	})

	t.Run("evidence_commits_before_waiting_validation_prepare", func(t *testing.T) {
		url := provisionValidationRaceDatabase(t, ctx, container, port, "validation_evidence_first")
		admin := connectWithRetry(t, ctx, url)
		defer admin.Close(context.Background())
		observer := connectWithRetry(t, ctx, url)
		defer observer.Close(context.Background())
		insertValidationFixture(t, ctx, admin)
		pool := demoValidationWorkerPool(t, ctx, url)
		defer pool.Close()
		store, _ := NewPostgreSQLStore(pool)
		lease := leaseRequest()
		lease.Now = time.Now().UTC()
		lease.LeaseExpiresAt = lease.Now.Add(30 * time.Second)
		job, found, err := store.Lease(ctx, lease)
		if err != nil || !found {
			t.Fatalf("lease found=%v err=%v", found, err)
		}

		evidenceTx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceTx.Exec(ctx, `UPDATE sentinelflow.incidents
SET evidence_version = 2 WHERE incident_id = $1::uuid`, testIncidentID); err != nil {
			_ = evidenceTx.Rollback(ctx)
			t.Fatal(err)
		}
		type prepareResult struct {
			prepared bool
			err      error
		}
		prepareDone := make(chan prepareResult, 1)
		go func() {
			_, prepared, prepareErr := store.Prepare(ctx, validationworker.PrepareRequest{
				Job: job.Job, LeaseToken: job.LeaseToken,
			})
			prepareDone <- prepareResult{prepared: prepared, err: prepareErr}
		}()
		waitForValidationRaceBlock(t, ctx, observer, "prepare_validation_attempt_exact")
		if err := evidenceTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		result := <-prepareDone
		if result.err != nil || result.prepared {
			t.Fatalf("stale prepare prepared=%v err=%v", result.prepared, result.err)
		}
		assertStaleValidationTerminal(t, ctx, admin, false)
	})
}

func provisionValidationRaceDatabase(
	t *testing.T,
	ctx context.Context,
	container string,
	port string,
	database string,
) string {
	t.Helper()
	var createOutput []byte
	var createErr error
	for range 20 {
		createOutput, createErr = exec.CommandContext(ctx, "docker", "exec", container,
			"createdb", "--username", "postgres", database).CombinedOutput()
		if createErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if createErr != nil {
		t.Fatalf("create validation race database: %v: %s", createErr, createOutput)
	}
	url := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/%s?sslmode=disable",
		port, database,
	)
	connection := connectWithRetry(t, ctx, url)
	applyMigrations(t, ctx, connection)
	_ = connection.Close(context.Background())
	return url
}

func waitForValidationRaceBlock(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	queryMarker string,
) {
	t.Helper()
	for range 100 {
		var blocked bool
		err := connection.QueryRow(ctx, `SELECT EXISTS (
    SELECT 1 FROM pg_catalog.pg_stat_activity
    WHERE datname = current_database()
      AND pid <> pg_backend_pid()
      AND position($1 in query) > 0
      AND wait_event_type = 'Lock'
)`, queryMarker).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("query containing %q did not reach a lock wait", strings.TrimSpace(queryMarker))
}
