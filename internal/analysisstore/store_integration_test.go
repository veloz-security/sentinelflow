//go:build integration

package analysisstore

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

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/worker"
)

// This protocol-level test complements db/test/verify_analysis_worker.sql. The
// SQL harness exercises every state path; this test proves pgx encodes the
// adapter's JSON bytes for the jsonb SECURITY DEFINER function signature and
// scans its no-row fencing result without a direct table query.
func TestPostgreSQLStoreProtocolAgainstPostgreSQL17(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-analysisstore-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", container).Run()
	})
	waitForPostgreSQL(t, ctx, container)
	port := dockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	connection, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		t.Fatalf("connect PostgreSQL 17: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	applyIntegrationMigrations(t, ctx, connection)
	cycleAnalysisLifecycleMigration(t, ctx, connection)
	if _, err = connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatalf("set worker role: %v", err)
	}
	store, err := NewPostgreSQLStore(connection)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Lease(ctx, leaseRequest()); err != nil || found {
		t.Fatalf("empty Lease() found=%v err=%v", found, err)
	}
	if _, prepared, err := store.Prepare(ctx, prepareRequest()); err != nil || prepared {
		t.Fatalf("empty Prepare() prepared=%v err=%v", prepared, err)
	}
	if finished, err := store.Finalize(ctx, failureFinalize()); err != nil || finished {
		t.Fatalf("empty Finalize() finished=%v err=%v", finished, err)
	}

	secondConnection, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		t.Fatalf("connect second PostgreSQL session: %v", err)
	}
	t.Cleanup(func() { _ = secondConnection.Close(context.Background()) })
	if _, err = secondConnection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatalf("set second worker role: %v", err)
	}
	secondStore, err := NewPostgreSQLStore(secondConnection)
	if err != nil {
		t.Fatal(err)
	}
	insertOperationalAnalysisJob(t, ctx, connection, testJob, testIncident, testDigest)

	requestOne := leaseRequest()
	requestOne.Now = time.Now().UTC()
	requestOne.LeaseExpiresAt = requestOne.Now.Add(30 * time.Second)
	requestTwo := requestOne
	requestTwo.LeaseToken = "019b0000-0000-4000-8000-000000008502"
	requestTwo.LeaseOwner = "analysis-worker-two"
	type leaseResult struct {
		job   worker.LeasedJob
		found bool
		err   error
		store *PostgreSQLStore
	}
	leaseResults := make(chan leaseResult, 2)
	start := make(chan struct{})
	for index, target := range []*PostgreSQLStore{store, secondStore} {
		request := []worker.LeaseRequest{requestOne, requestTwo}[index]
		go func() {
			<-start
			job, found, leaseErr := target.Lease(ctx, request)
			leaseResults <- leaseResult{job: job, found: found, err: leaseErr, store: target}
		}()
	}
	close(start)
	var winner leaseResult
	foundCount := 0
	for range 2 {
		result := <-leaseResults
		if result.err != nil {
			t.Fatalf("concurrent Lease(): %v", result.err)
		}
		if result.found {
			foundCount++
			winner = result
		}
	}
	if foundCount != 1 || winner.job.JobID != testJob {
		t.Fatalf("concurrent leases found=%d winner=%+v", foundCount, winner.job)
	}

	// Both sessions race the same token. The first atomically dead-letters the
	// missing incident without a provider call; the second observes no live
	// lease. Neither may return a prepared snapshot.
	prepareResults := make(chan error, 2)
	prepareStart := make(chan struct{})
	prepare := analysisworker.PrepareRequest{Job: winner.job.Job, LeaseToken: winner.job.LeaseToken}
	for _, target := range []*PostgreSQLStore{store, secondStore} {
		go func() {
			<-prepareStart
			_, prepared, prepareErr := target.Prepare(ctx, prepare)
			if prepareErr == nil && prepared {
				prepareErr = fmt.Errorf("concurrent prepare crossed provider boundary")
			}
			prepareResults <- prepareErr
		}()
	}
	close(prepareStart)
	for range 2 {
		if err := <-prepareResults; err != nil {
			t.Fatal(err)
		}
	}
	var state string
	if err := connection.QueryRow(ctx,
		"SELECT state FROM sentinelflow.outbox_jobs WHERE job_id = $1", testJob,
	).Scan(&state); err != nil || state != "dead" {
		t.Fatalf("concurrent Prepare() state=%q err=%v", state, err)
	}

	insertOperationalAnalysisJob(t, ctx, connection, testJobTwo,
		"019b0000-0000-7000-8000-000000008102",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	finalLease := requestOne
	finalLease.LeaseToken = "019b0000-0000-4000-8000-000000008503"
	finalLease.LeaseOwner = "analysis-finalize"
	finalJob, found, err := store.Lease(ctx, finalLease)
	if err != nil || !found || finalJob.JobID != testJobTwo {
		t.Fatalf("finalize fixture lease=%+v found=%v err=%v", finalJob, found, err)
	}
	finish := worker.FinishRequest{
		State: worker.FinishDead, Now: time.Now().UTC(), JobID: finalJob.JobID,
		LeaseToken: finalJob.LeaseToken, ErrorCode: "snapshot_unavailable",
		ErrorDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	finishResults := make(chan struct {
		finished bool
		err      error
	}, 2)
	finishStart := make(chan struct{})
	for _, target := range []*PostgreSQLStore{store, secondStore} {
		go func() {
			<-finishStart
			finished, finishErr := target.Finalize(ctx, analysisworker.FinalizeRequest{Finish: finish})
			finishResults <- struct {
				finished bool
				err      error
			}{finished: finished, err: finishErr}
		}()
	}
	close(finishStart)
	finishedCount := 0
	for range 2 {
		result := <-finishResults
		if result.err != nil {
			t.Fatalf("concurrent Finalize(): %v", result.err)
		}
		if result.finished {
			finishedCount++
		}
	}
	if finishedCount != 1 {
		t.Fatalf("concurrent finalize committed %d times", finishedCount)
	}
}

func cycleAnalysisLifecycleMigration(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
) {
	t.Helper()
	down, up := analysisLifecycleMigrationFiles(t)
	var err error
	if _, err = connection.Exec(ctx, string(down)); err != nil {
		t.Fatalf("000017 down migration: %v", err)
	}
	var versionPresent, columnPresent, restoredLimit bool
	err = connection.QueryRow(ctx, `
SELECT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations WHERE version = 17
       ), EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'sentinelflow' AND table_name = 'incidents'
             AND column_name = 'evidence_version'
       ), position(
           'evidence.signal_count > 16' IN pg_get_functiondef(
               'sentinelflow.prepare_analysis_attempt_legacy(uuid,uuid)'::regprocedure
           )
       ) > 0`).Scan(&versionPresent, &columnPresent, &restoredLimit)
	if err != nil || versionPresent || columnPresent || !restoredLimit {
		t.Fatalf("000017 down state version=%v column=%v old_limit=%v err=%v",
			versionPresent, columnPresent, restoredLimit, err)
	}
	if _, err = connection.Exec(ctx, string(up)); err != nil {
		t.Fatalf("000017 re-up migration: %v", err)
	}
	if _, err = connection.Exec(ctx, string(up)); err != nil {
		t.Fatalf("000017 idempotent re-up migration: %v", err)
	}
	var raisedLimit, workerPublic, workerPrivate, apiPublic, workerHelper bool
	var workerEvidenceInterrupt, apiEvidenceInterrupt bool
	var workerEvidenceUpdate, apiEvidenceUpdate bool
	err = connection.QueryRow(ctx, `
SELECT position(
           'evidence.signal_count > 50' IN pg_get_functiondef(
               'sentinelflow.prepare_analysis_attempt_legacy(uuid,uuid)'::regprocedure
           )
       ) > 0,
       has_function_privilege(
           'sentinelflow_worker',
           'sentinelflow.prepare_analysis_attempt(uuid,uuid)'::regprocedure,
           'EXECUTE'
       ),
       has_function_privilege(
           'sentinelflow_worker',
           'sentinelflow.prepare_analysis_attempt_pre_000017(uuid,uuid)'::regprocedure,
           'EXECUTE'
       ),
       has_function_privilege(
           'sentinelflow_api',
           'sentinelflow.prepare_analysis_attempt(uuid,uuid)'::regprocedure,
           'EXECUTE'
       ),
       has_function_privilege(
           'sentinelflow_worker',
           'sentinelflow.advance_analysis_incident_lifecycle_000017('
               'uuid,integer,text,text,text,uuid)'::regprocedure,
           'EXECUTE'
       ),
       has_column_privilege(
           'sentinelflow_worker', 'sentinelflow.incidents',
           'evidence_version', 'UPDATE'
       ),
       has_column_privilege(
           'sentinelflow_api', 'sentinelflow.incidents',
           'evidence_version', 'UPDATE'
       ),
       has_function_privilege(
           'sentinelflow_worker',
           'sentinelflow.interrupt_analysis_for_new_evidence_000017('
               'uuid,integer)'::regprocedure,
           'EXECUTE'
       ),
       has_function_privilege(
           'sentinelflow_api',
           'sentinelflow.interrupt_analysis_for_new_evidence_000017('
               'uuid,integer)'::regprocedure,
           'EXECUTE'
       )`).Scan(&raisedLimit, &workerPublic, &workerPrivate, &apiPublic,
		&workerHelper, &workerEvidenceUpdate, &apiEvidenceUpdate,
		&workerEvidenceInterrupt, &apiEvidenceInterrupt)
	if err != nil || !raisedLimit || !workerPublic || workerPrivate || apiPublic ||
		workerHelper || !workerEvidenceUpdate || apiEvidenceUpdate ||
		!workerEvidenceInterrupt || apiEvidenceInterrupt {
		t.Fatalf("000017 role/limit state raised=%v worker_public=%v worker_private=%v api_public=%v worker_helper=%v worker_evidence_update=%v api_evidence_update=%v worker_evidence_interrupt=%v api_evidence_interrupt=%v err=%v",
			raisedLimit, workerPublic, workerPrivate, apiPublic, workerHelper,
			workerEvidenceUpdate, apiEvidenceUpdate,
			workerEvidenceInterrupt, apiEvidenceInterrupt, err)
	}
}

func analysisLifecycleMigrationFiles(t *testing.T) (down, up []byte) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate integration test")
	}
	migrationRoot := filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations")
	downPath := filepath.Join(migrationRoot, "000017_analysis_lifecycle_alignment.down.sql")
	upPath := filepath.Join(migrationRoot, "000017_analysis_lifecycle_alignment.up.sql")
	down, err := os.ReadFile(downPath)
	if err != nil {
		t.Fatal(err)
	}
	up, err = os.ReadFile(upPath)
	if err != nil {
		t.Fatal(err)
	}
	return down, up
}

func insertOperationalAnalysisJob(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	jobID, aggregateID, digest string,
) {
	t.Helper()
	_, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    operation, idempotency_key, state, available_at, max_attempts
) VALUES ($1, 'analyze', 'incident', $2, 1, NULL, $3, 'pending', clock_timestamp(), 2)`,
		jobID, aggregateID, digest)
	if err != nil {
		t.Fatalf("insert operational analysis job: %v", err)
	}
}

func applyIntegrationMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate integration test")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(matches)
	for _, migration := range matches {
		// These analysis-store tests intentionally cycle 000017 down and back up.
		// Apply only its dependency prefix so newer migrations that legitimately
		// reference evidence_version do not make an out-of-order rollback appear
		// supported.
		name := filepath.Base(migration)
		if len(name) < 6 || name[:6] > "000017" {
			continue
		}
		contents, readErr := os.ReadFile(migration)
		if readErr != nil {
			t.Fatalf("read %s: %v", filepath.Base(migration), readErr)
		}
		if _, execErr := connection.Exec(ctx, string(contents)); execErr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(migration), execErr)
		}
	}
}

func waitForPostgreSQL(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	consecutiveReady := 0
	for range 80 {
		command := exec.CommandContext(ctx, "docker", "exec", container,
			"pg_isready", "-U", "postgres", "-d", "postgres")
		if command.Run() == nil {
			consecutiveReady++
			if consecutiveReady >= 3 {
				return
			}
		} else {
			// The image initialization server briefly reports ready before its
			// intentional shutdown/restart. Require a stable sequence so callers
			// never connect to that transient bootstrap postmaster.
			consecutiveReady = 0
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PostgreSQL 17 readiness: %v", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("PostgreSQL 17 did not become ready")
}

func dockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := runDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func runDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}
