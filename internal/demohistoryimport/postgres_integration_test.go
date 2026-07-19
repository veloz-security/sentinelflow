//go:build integration

package demohistoryimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/analysisstore"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const postgres17Image = "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"

func TestPostgreSQL17AtomicImportRuntime(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-demo-history-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", postgres17Image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForPostgres(t, ctx, container)
	port := dockerPort(t, ctx, container)

	t.Run("expired importer lease rejects an already authenticated session", func(t *testing.T) {
		const database = "demo_history_importer_lease_expiry"
		runDocker(t, ctx, "exec", container, "createdb", "--username", "postgres", database)
		adminURL := fmt.Sprintf("postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/%s?sslmode=disable", port, database)
		admin := connectPostgres(t, ctx, adminURL)
		defer admin.Close(context.Background())
		hardenDemoBootstrapRoles(t, ctx, admin)
		applyMigrations(t, ctx, admin)
		deadline := prepareDemoImporterLeaseFor(t, ctx, admin, database, 900*time.Millisecond)
		pool := importerPool(t, ctx, adminURL)
		defer pool.Close()
		if wait := time.Until(deadline) + 150*time.Millisecond; wait > 0 {
			time.Sleep(wait)
		}
		_, err := pool.Exec(ctx,
			`SELECT sentinelflow.complete_demo_history_import_leased_000030($1::uuid)`,
			fixtureImportID,
		)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "SF006" {
			t.Fatalf("expired importer lease error=%v", err)
		}
		var ledgers int
		if err := admin.QueryRow(ctx,
			`SELECT count(*) FROM sentinelflow.demo_history_imports`,
		).Scan(&ledgers); err != nil || ledgers != 0 {
			t.Fatalf("expired importer lease ledgers=%d err=%v", ledgers, err)
		}
	})

	t.Run("session finalizer cannot run before committed role fence", func(t *testing.T) {
		adminURL := provisionDatabase(t, ctx, container, port, "demo_history_fence_phase_order")
		pool := importerPool(t, ctx, adminURL)
		defer pool.Close()
		first, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Release()
		second, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Release()
		var ready bool
		if err := first.QueryRow(ctx,
			`SELECT sentinelflow.finalize_demo_history_importer_role_fence_000030()`,
		).Scan(&ready); err != nil || ready {
			t.Fatalf("pre-fence finalizer ready=%v err=%v", ready, err)
		}
		var one int
		if err := second.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
			t.Fatalf("pre-fence finalizer terminated peer: one=%d err=%v", one, err)
		}
		if err := first.QueryRow(ctx,
			`SELECT sentinelflow.fence_demo_history_importer_role_000030()`,
		).Scan(&ready); err != nil || !ready {
			t.Fatalf("phase-one importer fence ready=%v err=%v", ready, err)
		}
		if err := first.QueryRow(ctx,
			`SELECT sentinelflow.finalize_demo_history_importer_role_fence_000030()`,
		).Scan(&ready); err != nil || !ready {
			t.Fatalf("phase-two importer fence ready=%v err=%v", ready, err)
		}
		if err := second.QueryRow(ctx, `SELECT 1`).Scan(&one); err == nil {
			t.Fatal("committed importer fence left peer session usable")
		}
	})

	t.Run("activation pair is exact one shot and closes bootstrap authority", func(t *testing.T) {
		adminURL := provisionDatabase(t, ctx, container, port, "demo_history_activation_one_shot")
		admin := connectPostgres(t, ctx, adminURL)
		defer admin.Close(context.Background())
		pool := importerPool(t, ctx, adminURL)
		verifier, envelope, _ := freshRunManifest(t)
		reader, err := NewFixedDatasetFile(integrationRepositoryRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		importer, err := New(pool, reader, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if result, importErr := importer.ImportOrAttachExisting(ctx, envelope); importErr != nil ||
			result.Disposition() != DispositionApplied {
			t.Fatalf("fresh import disposition=%v err=%v", result.Disposition(), importErr)
		}
		pool.Close()

		analysisSecret := []byte(strings.Repeat("a", 32))
		validationSecret := []byte(strings.Repeat("v", 32))
		input := validation.DemoHistoryVerificationInput{
			SignedManifestEnvelope: envelope,
			ImportedRowsDigest:     validation.PinnedDemoHistoryImportedRowsDigest,
			ImportedRecordCount:    validation.PinnedDemoHistoryDatasetRecordCount,
		}
		activator := enableAndConnectDemoActivator(t, ctx, admin, adminURL)
		pair, err := validation.CreateDemoHistoryRuntimeActivationPair(
			ctx, activator, analysisSecret, validationSecret, verifier, input,
		)
		if err != nil {
			activator.Close(context.Background())
			t.Fatal(err)
		}
		if _, ok := pair.Analysis(); !ok {
			t.Fatal("analysis activation unavailable")
		}
		if _, ok := pair.Validation(); !ok {
			t.Fatal("validation activation unavailable")
		}
		if _, secondErr := validation.CreateDemoHistoryRuntimeActivationPair(
			ctx, activator, analysisSecret, validationSecret, verifier, input,
		); !errors.Is(secondErr, validation.ErrDemoHistoryActivationRejected) {
			activator.Close(context.Background())
			t.Fatalf("same-session activation replay error=%v", secondErr)
		}
		if err := demohistoryactivation.FenceBootstrap(ctx, activator); err != nil {
			activator.Close(context.Background())
			t.Fatalf("finalize bootstrap authority: %v", err)
		}
		activator.Close(context.Background())

		var activations, consumers, activationTimes, expectations, activeSessions, inertRoles int
		if err := admin.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM sentinelflow.demo_history_runtime_activations),
  (SELECT count(DISTINCT consumer) FROM sentinelflow.demo_history_runtime_activations),
  (SELECT count(DISTINCT activated_at) FROM sentinelflow.demo_history_runtime_activations),
  (SELECT count(*) FROM sentinelflow.demo_history_runtime_capability_expectation),
  (SELECT count(*) FROM pg_catalog.pg_stat_activity
   WHERE usename IN ('sentinelflow_demo_importer','sentinelflow_demo_activator')),
  (SELECT count(*) FROM pg_catalog.pg_authid
   WHERE rolname IN ('sentinelflow_demo_importer','sentinelflow_demo_activator')
     AND NOT rolcanlogin AND rolpassword IS NULL AND NOT rolinherit
     AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
     AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit = 2
     AND rolvaliduntil = '1970-01-01 00:00:00+00'::timestamptz)`).Scan(
			&activations, &consumers, &activationTimes, &expectations,
			&activeSessions, &inertRoles,
		); err != nil || activations != 2 || consumers != 2 || activationTimes != 1 ||
			expectations != 1 || activeSessions != 0 || inertRoles != 2 {
			t.Fatalf("pair=%d consumers=%d times=%d expectation=%d sessions=%d inert=%d err=%v",
				activations, consumers, activationTimes, expectations, activeSessions, inertRoles, err)
		}
	})

	t.Run("rejected activation still fences both bootstrap roles", func(t *testing.T) {
		adminURL := provisionDatabase(t, ctx, container, port, "demo_history_activation_rejected")
		admin := connectPostgres(t, ctx, adminURL)
		defer admin.Close(context.Background())
		pool := importerPool(t, ctx, adminURL)
		verifier, envelope, _ := freshRunManifest(t)
		reader, err := NewFixedDatasetFile(integrationRepositoryRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		importer, err := New(pool, reader, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := importer.ImportOrAttachExisting(ctx, envelope); err != nil {
			t.Fatal(err)
		}
		pool.Close()
		activator := enableAndConnectDemoActivator(t, ctx, admin, adminURL)
		_, createErr := validation.CreateDemoHistoryRuntimeActivationPair(
			ctx, activator, []byte(strings.Repeat("x", 32)),
			[]byte(strings.Repeat("y", 32)), verifier,
			validation.DemoHistoryVerificationInput{
				SignedManifestEnvelope: envelope,
				ImportedRowsDigest:     validation.PinnedDemoHistoryImportedRowsDigest,
				ImportedRecordCount:    validation.PinnedDemoHistoryDatasetRecordCount,
			},
		)
		if !errors.Is(createErr, validation.ErrDemoHistoryActivationRejected) {
			activator.Close(context.Background())
			t.Fatalf("rejected activation error=%v", createErr)
		}
		if err := demohistoryactivation.FenceBootstrap(ctx, activator); err != nil {
			activator.Close(context.Background())
			t.Fatalf("finalize rejected activation fence: %v", err)
		}
		activator.Close(context.Background())
		var activations, activeSessions, inertRoles int
		if err := admin.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM sentinelflow.demo_history_runtime_activations),
  (SELECT count(*) FROM pg_catalog.pg_stat_activity
   WHERE usename IN ('sentinelflow_demo_importer','sentinelflow_demo_activator')),
  (SELECT count(*) FROM pg_catalog.pg_authid
   WHERE rolname IN ('sentinelflow_demo_importer','sentinelflow_demo_activator')
     AND NOT rolcanlogin AND rolpassword IS NULL
     AND rolvaliduntil = '1970-01-01 00:00:00+00'::timestamptz)`).Scan(
			&activations, &activeSessions, &inertRoles,
		); err != nil || activations != 0 || activeSessions != 0 || inertRoles != 2 {
			t.Fatalf("rejected activation rows=%d sessions=%d inert=%d err=%v",
				activations, activeSessions, inertRoles, err)
		}
	})

	t.Run("concurrent exactly once and fail closed replay", func(t *testing.T) {
		adminURL := provisionDatabase(t, ctx, container, port, "demo_history_exactly_once")
		admin := connectPostgres(t, ctx, adminURL)
		defer admin.Close(context.Background())
		pool := importerPool(t, ctx, adminURL)
		defer pool.Close()
		assertLeastPrivilege(t, ctx, admin)

		reader, err := NewFixedDatasetFile(integrationRepositoryRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		importer, err := New(pool, reader, fixtureVerifier(t))
		if err != nil {
			t.Fatal(err)
		}
		envelope := readFixture(t, "contracts/fixtures/demo_history_manifest_v1.json")
		results := make(chan Result, 2)
		errorsFound := make(chan error, 2)
		var group sync.WaitGroup
		for range 2 {
			group.Add(1)
			go func() {
				defer group.Done()
				result, importErr := importer.Import(ctx, envelope)
				if importErr != nil {
					errorsFound <- importErr
					return
				}
				results <- result
			}()
		}
		group.Wait()
		close(results)
		close(errorsFound)
		for importErr := range errorsFound {
			t.Fatalf("concurrent import: %v", importErr)
		}
		dispositions := map[Disposition]int{}
		for result := range results {
			dispositions[result.Disposition()]++
			assertCompletedResult(t, result)
		}
		if dispositions[DispositionApplied] != 1 || dispositions[DispositionHistorical] != 1 {
			t.Fatalf("dispositions=%v", dispositions)
		}
		assertDatabaseCounts(t, ctx, admin, 1, 4, 3, 1, 2)

		historical, err := importer.Import(ctx, envelope)
		if err != nil || historical.Disposition() != DispositionHistorical {
			t.Fatalf("historical replay=%v err=%v", historical.Disposition(), err)
		}
		assertCompletedResult(t, historical)
		assertDatabaseCounts(t, ctx, admin, 1, 4, 3, 1, 2)

		var compact bytes.Buffer
		if err := json.Compact(&compact, readFixture(t, validation.DemoHistoryDatasetLocator)); err != nil {
			t.Fatal(err)
		}
		alternate, err := New(pool, staticReader{raw: compact.Bytes()}, fixtureVerifier(t))
		if err != nil {
			t.Fatal(err)
		}
		_, err = alternate.Import(ctx, envelope)
		assertCode(t, err, ErrorConflict)
		assertDatabaseCounts(t, ctx, admin, 1, 4, 3, 1, 2)

		if _, err := admin.Exec(ctx, `UPDATE sentinelflow.gateway_events
SET status_code = 500 WHERE event_id = '019b0000-0000-7000-8000-000000000101'`); err != nil {
			t.Fatal(err)
		}
		if _, err := importer.Import(ctx, envelope); err == nil {
			t.Fatal("tampered mapped row was accepted as historical authority")
		}
		var status string
		if err := admin.QueryRow(ctx, `SELECT status FROM sentinelflow.demo_history_imports`).Scan(&status); err != nil || status != "completed" {
			t.Fatalf("completed ledger mutated after drift: status=%q err=%v", status, err)
		}

		down := readMigration(t, "000020_demo_history_atomic_import.down.sql")
		if _, err := admin.Exec(ctx, down); err == nil {
			t.Fatal("populated down migration discarded durable history")
		}
		if _, err := admin.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatalf("rollback expected fail-stop transaction: %v", err)
		}
		var versionCount, ledgerCount int
		if err := admin.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 20),
  (SELECT count(*) FROM sentinelflow.demo_history_imports)`).Scan(&versionCount, &ledgerCount); err != nil || versionCount != 1 || ledgerCount != 1 {
			t.Fatalf("failed down changed state: version=%d ledger=%d err=%v", versionCount, ledgerCount, err)
		}
	})

	t.Run("restart recovery is exact and never revives stale mutation authority", func(t *testing.T) {
		reader, err := NewFixedDatasetFile(integrationRepositoryRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		envelope := readFixture(t, "contracts/fixtures/demo_history_manifest_v1.json")
		staleVerifier := fixtureVerifierAt(t, mustTime(t, fixtureClock).Add(10*time.Minute))

		t.Run("stale completed attaches content only", func(t *testing.T) {
			adminURL := provisionDatabase(t, ctx, container, port, "demo_history_stale_completed")
			admin := connectPostgres(t, ctx, adminURL)
			defer admin.Close(context.Background())
			pool := importerPool(t, ctx, adminURL)
			defer pool.Close()
			fresh, _ := New(pool, reader, fixtureVerifier(t))
			if first, importErr := fresh.ImportOrAttachExisting(ctx, envelope); importErr != nil ||
				first.Disposition() != DispositionApplied || first.VerifiedBinding().HistoryCutoff().At().IsZero() {
				t.Fatalf("first import disposition=%v err=%v", first.Disposition(), importErr)
			}
			stale, _ := New(pool, reader, staleVerifier)
			recovered, recoverErr := stale.ImportOrAttachExisting(ctx, envelope)
			if recoverErr != nil || recovered.Disposition() != DispositionHistorical ||
				!recovered.VerifiedBinding().HistoryCutoff().At().IsZero() {
				t.Fatalf("stale recovery disposition=%v err=%v", recovered.Disposition(), recoverErr)
			}
		})

		t.Run("stale absent and stale failed cannot import", func(t *testing.T) {
			adminURL := provisionDatabase(t, ctx, container, port, "demo_history_stale_absent")
			admin := connectPostgres(t, ctx, adminURL)
			defer admin.Close(context.Background())
			pool := importerPool(t, ctx, adminURL)
			defer pool.Close()
			stale, _ := New(pool, reader, staleVerifier)
			_, recoverErr := stale.ImportOrAttachExisting(ctx, envelope)
			assertCode(t, recoverErr, ErrorManifest)
			var ledgers int
			if scanErr := admin.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.demo_history_imports`).Scan(&ledgers); scanErr != nil || ledgers != 0 {
				t.Fatalf("stale absence wrote failure evidence: ledgers=%d err=%v", ledgers, scanErr)
			}

			fresh, _ := New(pool, reader, fixtureVerifier(t))
			fresh.fault = func(stage string, ordinal int) error {
				if stage == "after_begin" {
					return errors.New("synthetic fault")
				}
				return nil
			}
			_, importErr := fresh.Import(ctx, envelope)
			assertCode(t, importErr, ErrorFaultInjected)
			_, recoverErr = stale.ImportOrAttachExisting(ctx, envelope)
			assertCode(t, recoverErr, ErrorManifest)
			var status, failure string
			var attempt int
			if scanErr := admin.QueryRow(ctx, `SELECT status, failure_code, attempt_count
FROM sentinelflow.demo_history_imports`).Scan(&status, &failure, &attempt); scanErr != nil ||
				status != "failed" || failure != string(ErrorFaultInjected) || attempt != 1 {
				t.Fatalf("stale failed retry mutated ledger: status=%s failure=%s attempt=%d err=%v",
					status, failure, attempt, scanErr)
			}
			fresh.fault = nil
			result, retryErr := fresh.ImportOrAttachExisting(ctx, envelope)
			if retryErr != nil || result.Disposition() != DispositionApplied || result.AttemptCount() != 2 {
				t.Fatalf("fresh failed-row retry disposition=%v attempt=%d err=%v",
					result.Disposition(), result.AttemptCount(), retryErr)
			}
		})

		t.Run("concurrent absent recovery and ambiguous completion converge", func(t *testing.T) {
			adminURL := provisionDatabase(t, ctx, container, port, "demo_history_recovery_race")
			pool := importerPool(t, ctx, adminURL)
			defer pool.Close()
			fresh, _ := New(pool, reader, fixtureVerifier(t))
			results := make(chan Result, 2)
			errs := make(chan error, 2)
			var group sync.WaitGroup
			for range 2 {
				group.Add(1)
				go func() {
					defer group.Done()
					result, importErr := fresh.ImportOrAttachExisting(ctx, envelope)
					if importErr != nil {
						errs <- importErr
						return
					}
					results <- result
				}()
			}
			group.Wait()
			close(results)
			close(errs)
			for importErr := range errs {
				t.Fatal(importErr)
			}
			dispositions := map[Disposition]int{}
			for result := range results {
				dispositions[result.Disposition()]++
				if result.Disposition() == DispositionApplied && result.VerifiedBinding().HistoryCutoff().At().IsZero() {
					t.Fatal("applied race result lost fresh binding")
				}
				if result.Disposition() == DispositionHistorical && !result.VerifiedBinding().HistoryCutoff().At().IsZero() {
					t.Fatal("historical race result retained runtime binding")
				}
			}
			if dispositions[DispositionApplied] != 1 || dispositions[DispositionHistorical] != 1 {
				t.Fatalf("race dispositions=%v", dispositions)
			}
			// Treat the first successful commit as an ambiguous client outcome and
			// prove a later stale process can only exact-read the completed ledger.
			stale, _ := New(pool, reader, staleVerifier)
			if recovered, recoverErr := stale.ImportOrAttachExisting(ctx, envelope); recoverErr != nil ||
				recovered.Disposition() != DispositionHistorical ||
				!recovered.VerifiedBinding().HistoryCutoff().At().IsZero() {
				t.Fatalf("ambiguous completion recovery=%v err=%v", recovered.Disposition(), recoverErr)
			}
		})

		t.Run("drift partial and importing states fail closed", func(t *testing.T) {
			adminURL := provisionDatabase(t, ctx, container, port, "demo_history_recovery_drift")
			admin := connectPostgres(t, ctx, adminURL)
			defer admin.Close(context.Background())
			pool := importerPool(t, ctx, adminURL)
			defer pool.Close()
			fresh, _ := New(pool, reader, fixtureVerifier(t))
			if _, importErr := fresh.Import(ctx, envelope); importErr != nil {
				t.Fatal(importErr)
			}
			if _, updateErr := admin.Exec(ctx, `ALTER TABLE sentinelflow.demo_history_import_batches DISABLE TRIGGER demo_history_import_batches_append_only;
DELETE FROM sentinelflow.demo_history_import_batches
WHERE batch_id = '019b0000-0000-7000-8000-000000000203'::uuid;
ALTER TABLE sentinelflow.demo_history_import_batches ENABLE TRIGGER demo_history_import_batches_append_only;`); updateErr != nil {
				t.Fatal(updateErr)
			}
			stale, _ := New(pool, reader, staleVerifier)
			_, recoverErr := stale.ImportOrAttachExisting(ctx, envelope)
			assertCode(t, recoverErr, ErrorBinding)
			var status string
			var attempt int
			if scanErr := admin.QueryRow(ctx, `SELECT status, attempt_count FROM sentinelflow.demo_history_imports`).Scan(&status, &attempt); scanErr != nil || status != "completed" || attempt != 1 {
				t.Fatalf("drift recovery mutated ledger: status=%s attempt=%d err=%v", status, attempt, scanErr)
			}
			if _, updateErr := admin.Exec(ctx, `ALTER TABLE sentinelflow.demo_history_imports DISABLE TRIGGER demo_history_import_update_guard;
UPDATE sentinelflow.demo_history_imports
SET status = 'importing', failure_code = NULL, gateway_record_count = 0,
    auth_record_count = 0, source_coverage_count = 0, completed_at = NULL;
ALTER TABLE sentinelflow.demo_history_imports ENABLE TRIGGER demo_history_import_update_guard;`); updateErr != nil {
				t.Fatal(updateErr)
			}
			_, recoverErr = stale.ImportOrAttachExisting(ctx, envelope)
			assertCode(t, recoverErr, ErrorBinding)
			if scanErr := admin.QueryRow(ctx, `SELECT status, attempt_count FROM sentinelflow.demo_history_imports`).Scan(&status, &attempt); scanErr != nil || status != "importing" || attempt != 1 {
				t.Fatalf("ambiguous recovery mutated ledger: status=%s attempt=%d err=%v", status, attempt, scanErr)
			}
		})
	})

	t.Run("activation-authorized no-call writes exact use evidence", func(t *testing.T) {
		adminURL := provisionDatabase(t, ctx, container, port, "demo_history_no_call_use")
		admin := connectPostgres(t, ctx, adminURL)
		defer admin.Close(context.Background())
		importPool := importerPool(t, ctx, adminURL)
		defer importPool.Close()
		verifier, envelope, _ := freshRunManifest(t)
		reader, err := NewFixedDatasetFile(integrationRepositoryRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		importer, _ := New(importPool, reader, verifier)
		if result, importErr := importer.ImportOrAttachExisting(ctx, envelope); importErr != nil ||
			result.Disposition() != DispositionApplied {
			t.Fatalf("fresh import disposition=%v err=%v", result.Disposition(), importErr)
		}
		importPool.Close()
		analysisSecret := []byte(strings.Repeat("a", 32))
		validationSecret := []byte(strings.Repeat("v", 32))
		pair := createDemoActivationPair(
			t, ctx, admin, adminURL, analysisSecret, validationSecret, verifier,
			validation.DemoHistoryVerificationInput{
				SignedManifestEnvelope: envelope,
				ImportedRowsDigest:     validation.PinnedDemoHistoryImportedRowsDigest,
				ImportedRecordCount:    validation.PinnedDemoHistoryDatasetRecordCount,
			},
		)
		analysisActivation, ok := pair.Analysis()
		if !ok {
			t.Fatal("analysis activation unavailable")
		}
		jobID := "019b0000-0000-4000-8000-000000000901"
		aggregateID := "019b0000-0000-7000-8000-000000000902"
		if _, err = admin.Exec(ctx, `INSERT INTO sentinelflow.outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    operation, idempotency_key, state, available_at, max_attempts
) VALUES ($1::uuid, 'analyze', 'incident', $2::uuid, 1, NULL,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'pending', clock_timestamp(), 2)`, jobID, aggregateID); err != nil {
			t.Fatal(err)
		}
		workerPool := analysisWorkerPool(t, ctx, adminURL)
		defer workerPool.Close()
		store, err := analysisstore.NewPostgreSQLActivatedDemoStore(workerPool, analysisActivation)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		leased, found, err := store.Lease(ctx, worker.LeaseRequest{
			Now: now, LeaseToken: "00000000-0000-4000-8000-000000000903",
			LeaseOwner: "demo-no-call-test", LeaseExpiresAt: now.Add(30 * time.Second),
		})
		if err != nil || !found || leased.JobID != jobID {
			t.Fatalf("lease=%+v found=%v err=%v", leased, found, err)
		}
		if _, prepared, prepareErr := store.Prepare(ctx, analysisworker.PrepareRequest{
			Job: leased.Job, LeaseToken: leased.LeaseToken,
		}); prepareErr != nil || prepared {
			t.Fatalf("missing-incident no-call prepared=%v err=%v", prepared, prepareErr)
		}
		var uses, deadLetters int
		var state string
		if err = admin.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM sentinelflow.demo_history_runtime_uses
   WHERE consumer = 'analysis' AND job_id = $1::uuid
     AND aggregate_id = $2::uuid AND aggregate_version = 1),
  (SELECT count(*) FROM sentinelflow.dead_letter_jobs WHERE job_id = $1::uuid),
  (SELECT state FROM sentinelflow.outbox_jobs WHERE job_id = $1::uuid)`,
			jobID, aggregateID).Scan(&uses, &deadLetters, &state); err != nil ||
			uses != 1 || deadLetters != 1 || state != "dead" {
			t.Fatalf("no-call use=%d dead=%d state=%s err=%v", uses, deadLetters, state, err)
		}
	})

	t.Run("down refuses expired unused activation evidence", func(t *testing.T) {
		adminURL := provisionDatabase(t, ctx, container, port, "demo_history_expired_activation_down")
		admin := connectPostgres(t, ctx, adminURL)
		defer admin.Close(context.Background())
		pool := importerPool(t, ctx, adminURL)
		defer pool.Close()
		verifier, envelope, _ := freshRunManifest(t)
		reader, err := NewFixedDatasetFile(integrationRepositoryRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		importer, _ := New(pool, reader, verifier)
		if _, err = importer.ImportOrAttachExisting(ctx, envelope); err != nil {
			t.Fatal(err)
		}
		pool.Close()
		analysisSecret := []byte(strings.Repeat("a", 32))
		validationSecret := []byte(strings.Repeat("v", 32))
		_ = createDemoActivationPair(
			t, ctx, admin, adminURL, analysisSecret, validationSecret,
			verifier, validation.DemoHistoryVerificationInput{
				SignedManifestEnvelope: envelope,
				ImportedRowsDigest:     validation.PinnedDemoHistoryImportedRowsDigest,
				ImportedRecordCount:    validation.PinnedDemoHistoryDatasetRecordCount,
			},
		)
		if _, err = admin.Exec(ctx, `ALTER TABLE sentinelflow.demo_history_runtime_activations
DISABLE TRIGGER demo_history_runtime_activation_append_only;
WITH boundary AS (SELECT clock_timestamp() AS at)
UPDATE sentinelflow.demo_history_runtime_activations
SET activated_at = boundary.at - interval '1 hour' + interval '500 milliseconds',
    expires_at = boundary.at + interval '500 milliseconds'
FROM boundary;
ALTER TABLE sentinelflow.demo_history_runtime_activations
ENABLE TRIGGER demo_history_runtime_activation_append_only;`); err != nil {
			t.Fatal(err)
		}
		lockConnection := connectPostgres(t, ctx, adminURL)
		defer lockConnection.Close(context.Background())
		lockTx, err := lockConnection.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = lockTx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('sentinelflow:demo-history-activation-pair-v1', 0))`); err != nil {
			t.Fatal(err)
		}
		reattachConnection := enableAndConnectDemoActivator(t, ctx, admin, adminURL)
		defer reattachConnection.Close(context.Background())
		result := make(chan error, 1)
		go func() {
			_, createErr := validation.CreateDemoHistoryRuntimeActivationPair(
				ctx, reattachConnection, analysisSecret, validationSecret, verifier,
				validation.DemoHistoryVerificationInput{
					SignedManifestEnvelope: envelope,
					ImportedRowsDigest:     validation.PinnedDemoHistoryImportedRowsDigest,
					ImportedRecordCount:    validation.PinnedDemoHistoryDatasetRecordCount,
				},
			)
			fenceErr := demohistoryactivation.FenceBootstrap(ctx, reattachConnection)
			if createErr == nil {
				createErr = fenceErr
			}
			result <- createErr
		}()
		select {
		case early := <-result:
			t.Fatalf("activation reattach escaped advisory lock: %v", early)
		case <-time.After(150 * time.Millisecond):
		}
		time.Sleep(600 * time.Millisecond)
		if err = lockTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if reattachErr := <-result; !errors.Is(reattachErr, validation.ErrDemoHistoryActivationRejected) {
			t.Fatalf("expired lock-delayed reattach err=%v", reattachErr)
		}
		if _, err = admin.Exec(ctx, readMigration(t, "000030_demo_history_runtime_activation.down.sql")); err == nil {
			t.Fatal("down migration erased expired activation evidence")
		}
		if _, rollbackErr := admin.Exec(ctx, `ROLLBACK`); rollbackErr != nil {
			t.Fatalf("rollback failed down migration: %v", rollbackErr)
		}
		var version, activations int
		if err = admin.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 30),
  (SELECT count(*) FROM sentinelflow.demo_history_runtime_activations)`).Scan(
			&version, &activations); err != nil || version != 1 || activations != 2 {
			t.Fatalf("failed down changed evidence: version=%d activations=%d err=%v",
				version, activations, err)
		}
	})

	t.Run("fault rollback durable failure and retry", func(t *testing.T) {
		adminURL := provisionDatabase(t, ctx, container, port, "demo_history_fault_retry")
		admin := connectPostgres(t, ctx, adminURL)
		defer admin.Close(context.Background())
		pool := importerPool(t, ctx, adminURL)
		defer pool.Close()
		reader, err := NewFixedDatasetFile(integrationRepositoryRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		importer, err := New(pool, reader, fixtureVerifier(t))
		if err != nil {
			t.Fatal(err)
		}
		importer.fault = func(stage string, ordinal int) error {
			if stage == "after_record" && ordinal == 1 {
				return errors.New("synthetic fault")
			}
			return nil
		}
		envelope := readFixture(t, "contracts/fixtures/demo_history_manifest_v1.json")
		_, err = importer.Import(ctx, envelope)
		assertCode(t, err, ErrorFaultInjected)
		var status, failure string
		var attempt, mappings, gateway, auth, coverage, outbox int
		err = admin.QueryRow(ctx, `SELECT ledger.status, ledger.failure_code, ledger.attempt_count,
  (SELECT count(*) FROM sentinelflow.demo_history_import_batches),
  (SELECT count(*) FROM sentinelflow.gateway_events WHERE sender_id = 'gateway-demo'),
  (SELECT count(*) FROM sentinelflow.auth_events WHERE sender_id = 'auth-demo'),
  (SELECT count(*) FROM sentinelflow.demo_history_source_coverage),
  (SELECT count(*) FROM sentinelflow.outbox_jobs WHERE aggregate_type = 'auth_binding')
FROM sentinelflow.demo_history_imports ledger`).Scan(
			&status, &failure, &attempt, &mappings, &gateway, &auth, &coverage, &outbox)
		if err != nil || status != "failed" || failure != string(ErrorFaultInjected) || attempt != 1 ||
			mappings != 0 || gateway != 0 || auth != 0 || coverage != 0 || outbox != 0 {
			t.Fatalf("rollback status=%s failure=%s attempt=%d mapping=%d gateway=%d auth=%d coverage=%d outbox=%d err=%v",
				status, failure, attempt, mappings, gateway, auth, coverage, outbox, err)
		}

		importer.fault = nil
		result, err := importer.Import(ctx, envelope)
		if err != nil || result.Disposition() != DispositionApplied || result.AttemptCount() != 2 {
			t.Fatalf("retry disposition=%v attempt=%d err=%v", result.Disposition(), result.AttemptCount(), err)
		}
		assertCompletedResult(t, result)
		assertDatabaseCounts(t, ctx, admin, 1, 4, 3, 1, 2)
	})

	t.Run("application clock is not signature freshness", func(t *testing.T) {
		adminURL := provisionDatabase(t, ctx, container, port, "demo_history_clock_domains")
		admin := connectPostgres(t, ctx, adminURL)
		defer admin.Close(context.Background())
		pool := importerPool(t, ctx, adminURL)
		defer pool.Close()
		verifier, envelope, issuedAt := freshRunManifest(t)
		reader, err := NewFixedDatasetFile(integrationRepositoryRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		importer, err := New(pool, reader, verifier)
		if err != nil {
			t.Fatal(err)
		}
		result, err := importer.Import(ctx, envelope)
		if err != nil {
			t.Fatal(err)
		}
		if !result.ClockAt().Equal(mustTime(t, fixtureClock)) || !result.IssuedAt().Equal(issuedAt) ||
			result.IssuedAt().Equal(result.ClockAt()) {
			t.Fatalf("clock_at=%s issued_at=%s", result.ClockAt(), result.IssuedAt())
		}
		var secretColumns int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
WHERE table_schema = 'sentinelflow' AND table_name = 'demo_history_imports'
  AND column_name IN ('private_key', 'public_key', 'signature', 'signed_envelope', 'raw_dataset')`).Scan(&secretColumns); err != nil || secretColumns != 0 {
			t.Fatalf("secret-bearing ledger columns=%d err=%v", secretColumns, err)
		}
	})

	t.Run("empty down up and reapply", func(t *testing.T) {
		adminURL := provisionDatabase(t, ctx, container, port, "demo_history_migration_lifecycle")
		admin := connectPostgres(t, ctx, adminURL)
		defer admin.Close(context.Background())
		if _, err := admin.Exec(ctx, readMigration(t, "000030_demo_history_runtime_activation.down.sql")); err != nil {
			t.Fatal(err)
		}
		var importerExists, activatorExists, importerCanBegin bool
		var databaseRoleSettings int
		if err := admin.QueryRow(ctx, `SELECT
  to_regrole('sentinelflow_demo_importer') IS NOT NULL,
  to_regrole('sentinelflow_demo_activator') IS NOT NULL,
  has_function_privilege('sentinelflow_demo_importer',
    'sentinelflow.begin_demo_history_import(uuid,uuid,text,text,text,bigint,text,text,text,text,text,timestamptz,timestamptz,timestamptz,timestamptz)',
    'EXECUTE'),
  (SELECT count(*) FROM pg_db_role_setting setting
   WHERE setting.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
     AND setting.setrole IN (to_regrole('sentinelflow_demo_importer'),
                             to_regrole('sentinelflow_demo_activator')))`).Scan(
			&importerExists, &activatorExists, &importerCanBegin, &databaseRoleSettings); err != nil ||
			!importerExists || !activatorExists || importerCanBegin || databaseRoleSettings != 0 {
			t.Fatalf("down role cleanup importer=%v activator=%v begin=%v settings=%d err=%v",
				importerExists, activatorExists, importerCanBegin, databaseRoleSettings, err)
		}
		if _, err := admin.Exec(ctx, readMigration(t, "000020_demo_history_atomic_import.down.sql")); err != nil {
			t.Fatal(err)
		}
		var tableName *string
		var versionCount int
		if err := admin.QueryRow(ctx, `SELECT to_regclass('sentinelflow.demo_history_imports')::text,
  (SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 20)`).Scan(&tableName, &versionCount); err != nil || tableName != nil || versionCount != 0 {
			t.Fatalf("down table=%v version=%d err=%v", tableName, versionCount, err)
		}
		up := readMigration(t, "000020_demo_history_atomic_import.up.sql")
		if _, err := admin.Exec(ctx, up); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, up); err != nil {
			t.Fatalf("reapply: %v", err)
		}
		if _, err := admin.Exec(ctx, readMigration(t, "000030_demo_history_runtime_activation.up.sql")); err != nil {
			t.Fatalf("reapply activation boundary: %v", err)
		}
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 20`).Scan(&versionCount); err != nil || versionCount != 1 {
			t.Fatalf("up/re-up version=%d err=%v", versionCount, err)
		}
	})
}

func assertCompletedResult(t testing.TB, result Result) {
	t.Helper()
	if result.ImportID() != fixtureImportID || result.DatasetID() != validation.PinnedDemoHistoryDatasetID ||
		result.ImportedRowsJCSDigest() != validation.PinnedDemoHistoryImportedRowsDigest ||
		result.SourceHealthJCSDigest() != validation.PinnedDemoHistorySourceHealthDigest ||
		result.ImportedRecordCount() != 4 || result.Status() != "completed" || result.FailureCode() != "" ||
		result.GatewayRecordCount() != 3 || result.AuthRecordCount() != 1 || result.SourceCoverageCount() != 2 ||
		result.RunScopeDigest() == "" || result.PublicKeyDigest() == "" || result.SignatureVerificationDigest() == "" ||
		result.CompletedAt().IsZero() || result.VerifiedBinding().HistoryCutoff().At().IsZero() {
		t.Fatalf("invalid completed result: %+v", result)
	}
}

func assertDatabaseCounts(t testing.TB, ctx context.Context, admin *pgx.Conn, ledgers, mappings, gateway, auth, coverage int) {
	t.Helper()
	var got [5]int
	err := admin.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM sentinelflow.demo_history_imports),
  (SELECT count(*) FROM sentinelflow.demo_history_import_batches),
  (SELECT count(*) FROM sentinelflow.gateway_events WHERE sender_id = 'gateway-demo'),
  (SELECT count(*) FROM sentinelflow.auth_events WHERE sender_id = 'auth-demo'),
  (SELECT count(*) FROM sentinelflow.demo_history_source_coverage)`).Scan(
		&got[0], &got[1], &got[2], &got[3], &got[4])
	want := [5]int{ledgers, mappings, gateway, auth, coverage}
	if err != nil || got != want {
		t.Fatalf("database counts=%v want=%v err=%v", got, want, err)
	}
}

func assertLeastPrivilege(t testing.TB, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	functions := []string{
		"begin_demo_history_import", "append_demo_history_gateway", "append_demo_history_auth",
		"append_demo_history_source_coverage", "complete_demo_history_import",
		"record_demo_history_import_failure", "read_demo_history_import",
		"read_demo_history_import_recovery_000030",
	}
	for _, name := range functions {
		var importer, activator, worker, api, reader, dispatcher bool
		err := admin.QueryRow(ctx, `SELECT
  has_function_privilege('sentinelflow_demo_importer', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_demo_activator', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_worker', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_api', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_read', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_dispatcher', procedure.oid, 'EXECUTE')
FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'sentinelflow' AND procedure.proname = $1`, name).Scan(
			&importer, &activator, &worker, &api, &reader, &dispatcher)
		if err != nil || importer || activator || worker || api || reader || dispatcher {
			t.Fatalf("function=%s importer=%v activator=%v worker=%v api=%v read=%v dispatcher=%v err=%v",
				name, importer, activator, worker, api, reader, dispatcher, err)
		}
	}
	for _, name := range []string{
		"begin_demo_history_import_leased_000030",
		"append_demo_history_gateway_leased_000030",
		"append_demo_history_auth_leased_000030",
		"append_demo_history_source_coverage_leased_000030",
		"complete_demo_history_import_leased_000030",
		"record_demo_history_import_failure_leased_000030",
		"read_demo_history_import_leased_000030",
		"read_demo_history_import_recovery_leased_000030",
	} {
		var importer, activator, worker, api, reader, dispatcher bool
		err := admin.QueryRow(ctx, `SELECT
  has_function_privilege('sentinelflow_demo_importer', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_demo_activator', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_worker', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_api', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_read', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_dispatcher', procedure.oid, 'EXECUTE')
FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'sentinelflow' AND procedure.proname = $1`, name).Scan(
			&importer, &activator, &worker, &api, &reader, &dispatcher)
		if err != nil || !importer || activator || worker || api || reader || dispatcher {
			t.Fatalf("leased function=%s importer=%v activator=%v worker=%v api=%v read=%v dispatcher=%v err=%v",
				name, importer, activator, worker, api, reader, dispatcher, err)
		}
	}
	var directTable bool
	if err := admin.QueryRow(ctx, `SELECT has_table_privilege(
  'sentinelflow_demo_importer', 'sentinelflow.demo_history_imports', 'SELECT,INSERT,UPDATE,DELETE')`).Scan(&directTable); err != nil || directTable {
		t.Fatalf("importer direct ledger authority=%v err=%v", directTable, err)
	}
	for _, function := range []struct {
		name              string
		worker, activator bool
		importer          bool
	}{
		{name: "create_demo_history_runtime_activation_pair_000030"},
		{name: "create_demo_history_runtime_activation_pair_and_fence_000030", activator: true},
		{name: "pin_demo_history_runtime_capability_expectation_000030"},
		{name: "fence_demo_history_importer_role_000030", importer: true},
		{name: "finalize_demo_history_importer_role_fence_000030", importer: true},
		{name: "fence_demo_history_bootstrap_roles_000030", activator: true},
		{name: "finalize_demo_history_bootstrap_role_fence_000030", activator: true},
		{name: "attach_demo_history_runtime_activation_000030", worker: true},
		{name: "prepare_analysis_attempt_verified_demo_000030", worker: true},
		{name: "prepare_validation_attempt_verified_demo_000030", worker: true},
		{name: "verify_demo_history_immutable_binding_000030"},
		{name: "verify_demo_history_runtime_activation_000030"},
		{name: "record_demo_history_runtime_use_000030"},
	} {
		var worker, activator, importer bool
		err := admin.QueryRow(ctx, `SELECT
  has_function_privilege('sentinelflow_worker', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_demo_activator', procedure.oid, 'EXECUTE'),
  has_function_privilege('sentinelflow_demo_importer', procedure.oid, 'EXECUTE')
FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'sentinelflow' AND procedure.proname = $1`, function.name).Scan(
			&worker, &activator, &importer)
		if err != nil || worker != function.worker || activator != function.activator || importer != function.importer {
			t.Fatalf("function=%s worker=%v activator=%v importer=%v err=%v",
				function.name, worker, activator, importer, err)
		}
	}
	for _, name := range []string{
		"pin_demo_history_runtime_capability_expectation_000030",
		"create_demo_history_runtime_activation_pair_and_fence_000030",
		"fence_demo_history_importer_role_000030",
		"finalize_demo_history_importer_role_fence_000030",
		"fence_demo_history_bootstrap_roles_000030",
		"finalize_demo_history_bootstrap_role_fence_000030",
	} {
		var owner string
		var securityDefiner bool
		if err := admin.QueryRow(ctx, `SELECT owner.rolname, procedure.prosecdef
FROM pg_proc procedure
JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
JOIN pg_roles owner ON owner.oid = procedure.proowner
WHERE namespace.nspname = 'sentinelflow' AND procedure.proname = $1`, name).Scan(
			&owner, &securityDefiner); err != nil || owner != "postgres" || !securityDefiner {
			t.Fatalf("function=%s owner=%s security_definer=%v err=%v",
				name, owner, securityDefiner, err)
		}
	}
	for _, role := range []string{"sentinelflow_worker", "sentinelflow_demo_activator", "sentinelflow_demo_importer"} {
		var activationTable, useTable, expectationTable bool
		err := admin.QueryRow(ctx, `SELECT
  has_table_privilege($1, 'sentinelflow.demo_history_runtime_activations', 'SELECT,INSERT,UPDATE,DELETE'),
  has_table_privilege($1, 'sentinelflow.demo_history_runtime_uses', 'SELECT,INSERT,UPDATE,DELETE'),
  has_table_privilege($1, 'sentinelflow.demo_history_runtime_capability_expectation', 'SELECT,INSERT,UPDATE,DELETE')`, role).Scan(
			&activationTable, &useTable, &expectationTable)
		if err != nil || activationTable || useTable || expectationTable {
			t.Fatalf("role=%s direct activation tables=%v/%v/%v err=%v",
				role, activationTable, useTable, expectationTable, err)
		}
	}
}

func freshRunManifest(t testing.TB) (*validation.StrictDemoHistoryManifestVerifier, []byte, time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Now().UTC().Truncate(time.Millisecond)
	clockAt := mustTime(t, fixtureClock)
	runScope := "sentinelflow-demo-run:019b0000-0000-7000-8000-000000000602"
	importID := "019b0000-0000-7000-8000-000000000601"
	manifest := map[string]any{
		"clock_at":               clockAt.Format("2006-01-02T15:04:05.000Z"),
		"coverage_end":           clockAt.Format("2006-01-02T15:04:05.000Z"),
		"coverage_start":         clockAt.Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000Z"),
		"dataset_digest":         validation.PinnedDemoHistoryDatasetDigest,
		"dataset_id":             validation.PinnedDemoHistoryDatasetID,
		"dataset_record_count":   validation.PinnedDemoHistoryDatasetRecordCount,
		"dataset_schema_version": validation.DemoHistoryDatasetSchemaVersion,
		"import_id":              importID,
		"issued_at":              issuedAt.Format("2006-01-02T15:04:05.000Z"),
		"manifest_id":            "019b0000-0000-7000-8000-000000000600",
		"path_catalog_version":   "path-catalog-v1",
		"profile":                validation.DemoHistoryProfile,
		"schema_version":         validation.DemoHistoryManifestSchemaVersion,
		"source_health_digest":   validation.PinnedDemoHistorySourceHealthDigest,
	}
	manifestJCS, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest(manifestJCS)
	digestBytes, err := hex.DecodeString(strings.TrimPrefix(manifestDigest, "sha256:"))
	if err != nil {
		t.Fatal(err)
	}
	signingInput := append([]byte(validation.DemoHistorySignatureDomain+"\n"), digestBytes...)
	signature := ed25519.Sign(privateKey, signingInput)
	envelope := map[string]any{
		"fixture_only":        false,
		"key_scope":           runScope,
		"manifest":            manifest,
		"manifest_digest":     manifestDigest,
		"manifest_jcs_b64url": base64.RawURLEncoding.EncodeToString(manifestJCS),
		"public_key_b64url":   base64.RawURLEncoding.EncodeToString(publicKey),
		"schema_version":      validation.DemoHistorySignedManifestSchemaVersion,
		"signature_b64url":    base64.RawURLEncoding.EncodeToString(signature),
	}
	rawEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := validation.NewStrictDemoHistoryManifestVerifier(validation.DemoHistoryManifestVerifierConfig{
		Environment:                      validation.EnvironmentDemo,
		ExpectedPublicKey:                append([]byte(nil), publicKey...),
		ExpectedRunScope:                 runScope,
		ExpectedImportID:                 importID,
		ExpectedClockAt:                  clockAt,
		ExpectedImpactSourceHealthDigest: validation.PinnedDemoHistoryImpactSourceHealthDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier, rawEnvelope, issuedAt
}

func provisionDatabase(t testing.TB, ctx context.Context, container, port, database string) string {
	t.Helper()
	runDocker(t, ctx, "exec", container, "createdb", "--username", "postgres", database)
	url := fmt.Sprintf("postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/%s?sslmode=disable", port, database)
	connection := connectPostgres(t, ctx, url)
	hardenDemoBootstrapRoles(t, ctx, connection)
	applyMigrations(t, ctx, connection)
	prepareDemoImporterLease(t, ctx, connection, database)
	connection.Close(context.Background())
	return url
}

func hardenDemoBootstrapRoles(t testing.TB, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	if _, err := connection.Exec(ctx, `DO $block$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['sentinelflow_demo_importer','sentinelflow_demo_activator']
  LOOP
    IF pg_catalog.to_regrole(role_name) IS NOT NULL THEN
      EXECUTE pg_catalog.format(
        'ALTER ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL VALID UNTIL ''1970-01-01 00:00:00+00''',
        role_name
      );
    END IF;
  END LOOP;
  PERFORM pg_catalog.pg_terminate_backend(activity.pid, 5000)
  FROM pg_catalog.pg_stat_activity AS activity
  WHERE activity.usename IN ('sentinelflow_demo_importer','sentinelflow_demo_activator')
    AND activity.pid <> pg_catalog.pg_backend_pid();
END
$block$;`); err != nil {
		t.Fatalf("harden prior demo bootstrap roles: %v", err)
	}
}

func prepareDemoImporterLease(
	t testing.TB,
	ctx context.Context,
	connection *pgx.Conn,
	database string,
) {
	prepareDemoImporterLeaseFor(t, ctx, connection, database, 4*time.Minute)
}

func prepareDemoImporterLeaseFor(
	t testing.TB,
	ctx context.Context,
	connection *pgx.Conn,
	database string,
	lifetime time.Duration,
) time.Time {
	t.Helper()
	if lifetime < 250*time.Millisecond || lifetime > 5*time.Minute {
		t.Fatalf("invalid demo importer lease lifetime %s", lifetime)
	}
	quotedDatabase := pgx.Identifier{database}.Sanitize()
	statements := []string{
		"ALTER ROLE sentinelflow_demo_importer IN DATABASE " + quotedDatabase + " SET statement_timeout = '30s'",
		"ALTER ROLE sentinelflow_demo_importer IN DATABASE " + quotedDatabase + " SET transaction_timeout = '2min'",
		"ALTER ROLE sentinelflow_demo_importer IN DATABASE " + quotedDatabase + " SET idle_in_transaction_session_timeout = '5s'",
		"ALTER ROLE sentinelflow_demo_importer IN DATABASE " + quotedDatabase + " SET idle_session_timeout = '30s'",
		"ALTER ROLE sentinelflow_demo_activator IN DATABASE " + quotedDatabase + " SET statement_timeout = '15s'",
		"ALTER ROLE sentinelflow_demo_activator IN DATABASE " + quotedDatabase + " SET transaction_timeout = '30s'",
		"ALTER ROLE sentinelflow_demo_activator IN DATABASE " + quotedDatabase + " SET idle_in_transaction_session_timeout = '5s'",
		"ALTER ROLE sentinelflow_demo_activator IN DATABASE " + quotedDatabase + " SET idle_session_timeout = '30s'",
	}
	for _, statement := range statements {
		if _, err := connection.Exec(ctx, statement); err != nil {
			t.Fatalf("configure demo bootstrap timeout: %v", err)
		}
	}
	deadline := time.Now().UTC().Add(lifetime).Truncate(time.Millisecond)
	if _, err := connection.Exec(ctx, fmt.Sprintf(
		"ALTER ROLE sentinelflow_demo_importer LOGIN PASSWORD 'demo-importer-test-only' VALID UNTIL '%s'",
		deadline.Format(time.RFC3339Nano),
	)); err != nil {
		t.Fatalf("enable demo importer lease: %v", err)
	}
	analysis := sha256.Sum256([]byte(strings.Repeat("a", 32)))
	validationSecret := sha256.Sum256([]byte(strings.Repeat("v", 32)))
	analysisDigest := "sha256:" + hex.EncodeToString(analysis[:])
	validationDigest := "sha256:" + hex.EncodeToString(validationSecret[:])
	var pinned bool
	if err := connection.QueryRow(ctx, `SELECT sentinelflow.pin_demo_history_runtime_capability_expectation_000030($1,$2,$3)`,
		analysisDigest, validationDigest, deadline).Scan(&pinned); err != nil || !pinned {
		t.Fatalf("pin demo runtime capability expectation: pinned=%v err=%v", pinned, err)
	}
	return deadline
}

func createDemoActivationPair(
	t testing.TB,
	ctx context.Context,
	admin *pgx.Conn,
	adminURL string,
	analysisSecret []byte,
	validationSecret []byte,
	verifier *validation.StrictDemoHistoryManifestVerifier,
	input validation.DemoHistoryVerificationInput,
) validation.CreatedDemoHistoryActivationPair {
	t.Helper()
	connection := enableAndConnectDemoActivator(t, ctx, admin, adminURL)
	defer connection.Close(context.Background())
	pair, err := validation.CreateDemoHistoryRuntimeActivationPair(
		ctx, connection, analysisSecret, validationSecret, verifier, input,
	)
	if err != nil {
		t.Fatalf("create demo activation pair: %v", err)
	}
	if err := demohistoryactivation.FenceBootstrap(ctx, connection); err != nil {
		t.Fatalf("finalize demo bootstrap authority: %v", err)
	}
	return pair
}

func enableAndConnectDemoActivator(
	t testing.TB,
	ctx context.Context,
	admin *pgx.Conn,
	adminURL string,
) *pgx.Conn {
	t.Helper()
	deadline := time.Now().UTC().Add(4 * time.Minute).Truncate(time.Millisecond)
	if _, err := admin.Exec(ctx, fmt.Sprintf(
		"ALTER ROLE sentinelflow_demo_activator LOGIN PASSWORD 'demo-activator-test-only' VALID UNTIL '%s'",
		deadline.Format(time.RFC3339Nano),
	)); err != nil {
		t.Fatalf("enable demo activator lease: %v", err)
	}
	config, err := pgx.ParseConfig(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "sentinelflow_demo_activator"
	config.Password = "demo-activator-test-only"
	config.RuntimeParams["application_name"] = "sentinelflow-demo-activator-test"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect demo activator: %v", err)
	}
	var role string
	if err := connection.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil ||
		role != "sentinelflow_demo_activator" {
		connection.Close(context.Background())
		t.Fatalf("demo activator role=%q err=%v", role, err)
	}
	return connection
}

func applyMigrations(t testing.TB, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(integrationRepositoryRoot(t), "db", "migrations", "*.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(path), err)
		}
	}
}

func readMigration(t testing.TB, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(integrationRepositoryRoot(t), "db", "migrations", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func importerPool(t testing.TB, ctx context.Context, url string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 4
	config.ConnConfig.User = "sentinelflow_demo_importer"
	config.ConnConfig.Password = "demo-importer-test-only"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}

func analysisWorkerPool(t testing.TB, ctx context.Context, url string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 2
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, `SET ROLE sentinelflow_worker`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}

func connectPostgres(t testing.TB, ctx context.Context, url string) *pgx.Conn {
	t.Helper()
	var connection *pgx.Conn
	var err error
	for range 300 {
		connection, err = pgx.Connect(ctx, url)
		if err == nil {
			return connection
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("connect to disposable PostgreSQL 17: %v", err)
	return nil
}

func waitForPostgres(t testing.TB, ctx context.Context, container string) {
	t.Helper()
	consecutive := 0
	for range 300 {
		command := exec.CommandContext(ctx, "docker", "exec", container,
			"pg_isready", "--host", "127.0.0.1", "--username", "postgres", "--dbname", "postgres")
		if command.Run() == nil {
			consecutive++
			if consecutive == 2 {
				return
			}
		} else {
			consecutive = 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("disposable PostgreSQL 17 did not become ready")
}

func dockerPort(t testing.TB, ctx context.Context, container string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", "port", container, "5432/tcp")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	value := strings.TrimSpace(string(output))
	index := strings.LastIndexByte(value, ':')
	if index < 0 || index == len(value)-1 {
		t.Fatalf("invalid docker port output %q", value)
	}
	return value[index+1:]
}

func runDocker(t testing.TB, ctx context.Context, arguments ...string) {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("docker command failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

func integrationRepositoryRoot(t testing.TB) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
