//go:build integration

package dispatchstore

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestDispatcherStoreAgainstPostgreSQL17 proves deterministic concurrent
// claiming, exact signed capability/result persistence, fenced completion, and
// the dispatcher role's inability to read any underlying control-plane table.
func TestDispatcherStoreAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-dispatchstore-%d", time.Now().UnixNano())
	dispatchDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForDispatchPostgreSQL(t, ctx, container)
	port := dispatchDockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	owner := connectDispatchPostgreSQL(t, ctx, connectionString)
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	applyDispatchMigrations(t, ctx, owner)
	seedApprovedDispatchFixture(t, ctx, owner)
	// The reviewed HIL fixture deliberately timestamps approval one second in
	// the future. Capability persistence is the approved -> queued lifecycle
	// transition, whose queued_at must not precede approved_at. Poll the
	// database clock because the disposable container and host clocks can skew.
	waitForApprovedDispatchAction(t, ctx, owner, "019b0000-0000-7000-8000-000000009113")

	var versionText string
	if err := owner.QueryRow(ctx, `SHOW server_version_num`).Scan(&versionText); err != nil {
		t.Fatal("query PostgreSQL version")
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version/10000 != 17 {
		t.Fatalf("expected PostgreSQL 17, got %q", versionText)
	}

	first := dispatchRoleConnection(t, ctx, connectionString)
	second := dispatchRoleConnection(t, ctx, connectionString)
	var emptyRecoveryRows int
	if err := first.QueryRow(ctx, `
SELECT count(*)::integer
FROM sentinelflow.dispatcher_recovery_outbox_000025`).Scan(&emptyRecoveryRows); err != nil || emptyRecoveryRows != 0 {
		t.Fatalf("dispatcher cannot inspect empty recovery view: rows=%d err=%v", emptyRecoveryRows, err)
	}
	capVerifier, resultVerifier, issuer := fixtureVerifiers()
	firstStore, err := NewPostgreSQLStore(first, capVerifier, resultVerifier, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, err := NewPostgreSQLStore(second, capVerifier, resultVerifier, nil)
	if err != nil {
		t.Fatal(err)
	}

	type claimResult struct {
		claim ClaimedJob
		found bool
		err   error
		store *PostgreSQLStore
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	requests := []struct {
		store *PostgreSQLStore
		token string
	}{
		{firstStore, "019b0000-0000-4000-8000-000000009151"},
		{secondStore, "019b0000-0000-4000-8000-000000009152"},
	}
	for _, request := range requests {
		go func() {
			<-start
			claim, found, claimErr := request.store.ClaimNext(ctx, ClaimRequest{
				LeaseOwner: "dispatcher-test", LeaseDuration: 900 * time.Millisecond,
				CandidateLimit: 4, LeaseToken: request.token,
			})
			results <- claimResult{claim: claim, found: found, err: claimErr, store: request.store}
		}()
	}
	close(start)
	var winner claimResult
	successes, misses := 0, 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent claim: %v", result.err)
		}
		if result.found {
			successes++
			winner = result
		} else {
			misses++
		}
	}
	if successes != 1 || misses != 1 ||
		winner.claim.Job().JobID() != "019b0000-0000-7000-8000-000000009114" {
		t.Fatalf("concurrent claims: success=%d miss=%d", successes, misses)
	}
	emptyRecovery, err := winner.store.Recover(ctx, winner.claim)
	if err != nil || emptyRecovery.State() != RecoveryNone {
		t.Fatalf("ordinary claimed job did not recover as none: state=%s err=%v",
			emptyRecovery.State(), err)
	}

	signedCapability, _ := fixtureSignedCapability(t, winner.claim, issuer, 300*time.Millisecond)
	// Both paths lock the same outbox row. The ordinary claim can neither pass
	// an in-flight capability insert nor create a second mutation authority.
	ownerTx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ownerTx.Exec(ctx, `
SELECT job_id FROM sentinelflow.outbox_jobs WHERE job_id = $1::uuid FOR UPDATE`,
		winner.claim.Job().JobID()); err != nil {
		t.Fatal(err)
	}
	type persistOutcome struct {
		value PersistedCapability
		err   error
	}
	persisted := make(chan persistOutcome, 1)
	claimed := make(chan struct {
		value bool
		err   error
	}, 1)
	go func() {
		value, persistErr := winner.store.PersistCapability(ctx, winner.claim, signedCapability)
		persisted <- persistOutcome{value: value, err: persistErr}
	}()
	competitor := first
	if winner.store == firstStore {
		competitor = second
	}
	go func() {
		var value bool
		claimErr := competitor.QueryRow(ctx, `
SELECT sentinelflow.claim_dispatch_job($1::uuid, $2::uuid, $3, $4)`,
			winner.claim.Job().JobID(), "019b0000-0000-4000-8000-000000009159",
			"dispatcher-race", winner.claim.LeaseUntil()).Scan(&value)
		claimed <- struct {
			value bool
			err   error
		}{value: value, err: claimErr}
	}()
	time.Sleep(50 * time.Millisecond)
	if err = ownerTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	persistResult := <-persisted
	claimRaceResult := <-claimed
	if persistResult.err != nil || claimRaceResult.err != nil || claimRaceResult.value {
		t.Fatalf("capability/ordinary-claim fence failed: persist=%v claim=%t/%v",
			persistResult.err, claimRaceResult.value, claimRaceResult.err)
	}
	persistedCapability := persistResult.value
	replayedCapability, err := winner.store.PersistCapability(ctx, winner.claim, signedCapability)
	if err != nil || replayedCapability.verified.Digest() != persistedCapability.verified.Digest() {
		t.Fatalf("exact capability replay was not idempotent: digest=%q err=%v",
			replayedCapability.verified.Digest(), err)
	}
	changedCapability, _ := fixtureSignedCapability(t, winner.claim, issuer, 200*time.Millisecond)
	if _, err := winner.store.PersistCapability(ctx, winner.claim, changedCapability); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed capability replay was not a typed conflict: %v", err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.outbox_jobs SET attempts = max_attempts WHERE job_id = $1::uuid`,
		winner.claim.Job().JobID()); err != nil {
		t.Fatalf("set exhausted-attempt recovery fixture: %v", err)
	}
	if _, err := owner.Exec(ctx, `
DELETE FROM sentinelflow.execution_capabilities WHERE job_id = $1::uuid`,
		winner.claim.Job().JobID()); dispatchPGCode(err) != "55000" {
		t.Fatalf("retention removed unresolved capability: %v", err)
	}
	worker := roleDispatchConnection(t, ctx, connectionString, "sentinelflow_worker")
	if _, err := worker.Exec(ctx, `
UPDATE sentinelflow.dead_letter_jobs
SET resolution_state = resolution_state WHERE false`); dispatchPGCode(err) != "42501" {
		t.Fatalf("worker retained direct dead-letter UPDATE: %v", err)
	}
	waitForDispatchInstant(t, ctx, owner, winner.claim.LeaseUntil().Add(30*time.Millisecond))
	if ordinary, ordinaryFound, ordinaryErr := firstStore.ClaimNext(ctx, ClaimRequest{
		LeaseOwner: "dispatcher-ordinary", LeaseDuration: 900 * time.Millisecond,
		CandidateLimit: 4, LeaseToken: "019b0000-0000-4000-8000-000000009158",
	}); ordinaryErr != nil || ordinaryFound || ordinary.Job().JobID() != "" {
		t.Fatalf("ordinary path reclaimed capability-owned job: found=%t err=%v", ordinaryFound, ordinaryErr)
	}
	reclaimedClaim, found, err := firstStore.ClaimRecoveryNext(ctx, ClaimRequest{
		LeaseOwner: "dispatcher-recovery", LeaseDuration: 5 * time.Second,
		CandidateLimit: 4, LeaseToken: "019b0000-0000-4000-8000-000000009153",
	})
	if err != nil || !found || !reclaimedClaim.Job().RecoveryOnly() ||
		reclaimedClaim.Job().Attempts() != reclaimedClaim.Job().MaxAttempts() {
		t.Fatalf("reclaim uncertain capability: found=%t err=%v", found, err)
	}

	// Recovery is read-only and may run concurrently. Both readers must return
	// the same exact capability and no result under the new lease.
	type recoveryResult struct {
		value RecoveredExecution
		err   error
	}
	recoveryResults := make(chan recoveryResult, 2)
	recoveryStart := make(chan struct{})
	for _, recoveryStore := range []*PostgreSQLStore{firstStore, secondStore} {
		go func(current *PostgreSQLStore) {
			<-recoveryStart
			value, recoverErr := current.Recover(ctx, reclaimedClaim)
			recoveryResults <- recoveryResult{value: value, err: recoverErr}
		}(recoveryStore)
	}
	close(recoveryStart)
	firstRecovery := <-recoveryResults
	secondRecovery := <-recoveryResults
	if firstRecovery.err != nil || secondRecovery.err != nil ||
		firstRecovery.value.State() != RecoveryCapability ||
		secondRecovery.value.State() != RecoveryCapability {
		t.Fatalf("concurrent capability recovery: first=%v second=%v",
			firstRecovery.err, secondRecovery.err)
	}
	recoveredCapability, exactCapability, ok := firstRecovery.value.Capability()
	if !ok || !bytes.Equal(exactCapability.CanonicalBytes(), signedCapability.CanonicalBytes()) ||
		!bytes.Equal(exactCapability.Signature(), signedCapability.Signature()) ||
		!bytes.Equal(exactCapability.ArtifactBytes(), signedCapability.ArtifactBytes()) ||
		recoveredCapability.verified.Value().CapabilityID != persistedCapability.verified.Value().CapabilityID {
		t.Fatal("recovery changed exact persisted capability bytes or identity")
	}
	if _, _, hasResult := firstRecovery.value.Result(); hasResult {
		t.Fatal("capability-only recovery fabricated a result")
	}

	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.execution_capabilities
SET capability_signature = decode(repeat('00', 64), 'hex')
WHERE job_id = $1::uuid`, reclaimedClaim.Job().JobID()); err != nil {
		t.Fatalf("inject capability signature corruption: %v", err)
	}
	if _, err := firstStore.Recover(ctx, reclaimedClaim); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("tampered capability signature err=%v", err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.execution_capabilities
SET capability_signature = $2
WHERE job_id = $1::uuid`, reclaimedClaim.Job().JobID(), signedCapability.Signature()); err != nil {
		t.Fatalf("restore capability signature: %v", err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.execution_capabilities
SET capability_jcs = set_byte(capability_jcs, 0, get_byte(capability_jcs, 0) # 1)
WHERE job_id = $1::uuid`, reclaimedClaim.Job().JobID()); err != nil {
		t.Fatalf("inject capability JCS corruption: %v", err)
	}
	if _, err := firstStore.Recover(ctx, reclaimedClaim); !errors.Is(err, ErrInvalidRow) {
		t.Fatalf("tampered capability JCS err=%v", err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.execution_capabilities
SET capability_jcs = $2, capability_digest = $3
WHERE job_id = $1::uuid`, reclaimedClaim.Job().JobID(),
		signedCapability.CanonicalBytes(), persistedCapability.verified.Digest()); err != nil {
		t.Fatalf("restore capability JCS/digest: %v", err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.execution_capabilities
SET capability_digest = ('sha256:' || repeat('f', 64))::sentinelflow.sha256_digest
WHERE job_id = $1::uuid`, reclaimedClaim.Job().JobID()); err != nil {
		t.Fatalf("inject capability digest corruption: %v", err)
	}
	if _, err := firstStore.Recover(ctx, reclaimedClaim); !errors.Is(err, ErrInvalidRow) {
		t.Fatalf("tampered capability digest err=%v", err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.execution_capabilities
SET capability_digest = $2
WHERE job_id = $1::uuid`, reclaimedClaim.Job().JobID(), persistedCapability.verified.Digest()); err != nil {
		t.Fatalf("restore capability digest: %v", err)
	}

	wrongLease := cloneClaim(reclaimedClaim)
	wrongLease.leaseToken = "019b0000-0000-4000-8000-000000009154"
	wrongLease.claimDigest = digestClaim(wrongLease)
	if _, err := firstStore.Recover(ctx, wrongLease); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong recovery lease err=%v", err)
	}
	otherJob := cloneClaim(reclaimedClaim)
	otherJob.job.jobID = "019b0000-0000-4000-8000-000000009199"
	otherJob.claimDigest = digestClaim(otherJob)
	if _, err := firstStore.Recover(ctx, otherJob); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("other-job recovery err=%v", err)
	}

	// Bind the recovered attestation to the capability's canonical clock rather
	// than the host clock. The disposable PostgreSQL container may be slightly
	// ahead of the host, and recovery results are intentionally allowed after
	// capability expiry without recreating mutation authority.
	recoveryStarted := recoveredCapability.verified.Value().ExpiresAt.Add(time.Millisecond)
	recoveryCompleted := recoveryStarted.Add(10 * time.Millisecond)
	signedResult := fixtureRecoveredResult(t, recoveredCapability, recoveryStarted, recoveryCompleted)
	persistedResult, err := firstStore.PersistResult(ctx, recoveredCapability, signedResult)
	if err != nil {
		t.Fatalf("persist result through recovered capability: %v", err)
	}
	replayedResult, err := firstStore.PersistResult(ctx, recoveredCapability, signedResult)
	if err != nil || replayedResult.resultID != persistedResult.resultID || replayedResult.digest != persistedResult.digest {
		t.Fatalf("exact signed result replay was not idempotent: %v", err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.execution_results
SET result_signature = decode(repeat('00', 64), 'hex')
WHERE result_id = $1::uuid`, persistedResult.resultID); err != nil {
		t.Fatalf("inject result signature corruption: %v", err)
	}
	if _, err := firstStore.Recover(ctx, reclaimedClaim); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("tampered result signature err=%v", err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.execution_results
SET result_signature = $2
WHERE result_id = $1::uuid`, persistedResult.resultID, signedResult.Signature()); err != nil {
		t.Fatalf("restore result signature: %v", err)
	}

	// The ordinary finisher must not bypass restore-authorized provenance,
	// even though its private predecessor would otherwise accept this live
	// lease and exact persisted result. Exercise every outcome under the
	// dispatcher role, then roll back the synthetic marker-backed dead letter.
	bypassTx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatalf("begin ordinary finish bypass probe: %v", err)
	}
	if _, err := bypassTx.Exec(ctx, `
UPDATE sentinelflow.outbox_jobs SET attempts = 1 WHERE job_id = $1::uuid`,
		reclaimedClaim.Job().JobID()); err != nil {
		_ = bypassTx.Rollback(ctx)
		t.Fatalf("prepare ordinary finish bypass attempts: %v", err)
	}
	if _, err := bypassTx.Exec(ctx, `
INSERT INTO sentinelflow.dead_letter_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    attempts, failure_code, failure_digest
)
SELECT job_id, kind, aggregate_type, aggregate_id, aggregate_version,
       attempts, 'wrapper_probe', $2::sentinelflow.sha256_digest
FROM sentinelflow.outbox_jobs WHERE job_id = $1::uuid`,
		reclaimedClaim.Job().JobID(), digestBytes([]byte("wrapper_probe"))); err != nil {
		_ = bypassTx.Rollback(ctx)
		t.Fatalf("prepare ordinary finish bypass dead letter: %v", err)
	}
	if _, err := bypassTx.Exec(ctx, `
UPDATE sentinelflow.dead_letter_jobs dead
SET resolution_state = 'requeued', resolved_at = clock_timestamp(),
    resolution_actor = 'sentinelflow_recovery',
    resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
        dead.job_id, capability.capability_digest,
        dead.failure_code, dead.failure_digest
    )
FROM sentinelflow.execution_capabilities capability
WHERE dead.job_id = $1::uuid AND capability.job_id = dead.job_id`,
		reclaimedClaim.Job().JobID()); err != nil {
		_ = bypassTx.Rollback(ctx)
		t.Fatalf("prepare ordinary finish bypass marker: %v", err)
	}
	if _, err := bypassTx.Exec(ctx, `
UPDATE sentinelflow.outbox_jobs job
SET last_error_code = 'recovery_started', last_error_digest = dead.resolution_digest
FROM sentinelflow.dead_letter_jobs dead
WHERE job.job_id = $1::uuid AND dead.job_id = job.job_id`, reclaimedClaim.Job().JobID()); err != nil {
		_ = bypassTx.Rollback(ctx)
		t.Fatalf("prepare ordinary finish bypass job marker: %v", err)
	}
	if _, err := bypassTx.Exec(ctx, `SET LOCAL ROLE sentinelflow_dispatcher`); err != nil {
		_ = bypassTx.Rollback(ctx)
		t.Fatalf("set dispatcher for ordinary finish bypass probe: %v", err)
	}
	var predecessorAllowed, wrapperAllowed bool
	if err := bypassTx.QueryRow(ctx, `
SELECT
  has_function_privilege(
    current_user,
    'sentinelflow.finish_dispatch_job_pre_000025(uuid,uuid,text,sentinelflow.ascii_id,sentinelflow.sha256_digest,timestamptz)',
    'EXECUTE'
  ),
  has_function_privilege(
    current_user,
    'sentinelflow.finish_dispatch_job(uuid,uuid,text,sentinelflow.ascii_id,sentinelflow.sha256_digest,timestamptz)',
    'EXECUTE'
  )`).Scan(&predecessorAllowed, &wrapperAllowed); err != nil || predecessorAllowed || !wrapperAllowed {
		_ = bypassTx.Rollback(ctx)
		t.Fatalf("finish ACL boundary predecessor=%t wrapper=%t err=%v",
			predecessorAllowed, wrapperAllowed, err)
	}
	finishCalls := []struct {
		name      string
		query     string
		useDigest bool
	}{
		{
			name: "completed",
			query: `SELECT sentinelflow.finish_dispatch_job(
                $1::uuid, $2::uuid, 'completed', NULL, NULL, NULL)`,
		},
		{
			name: "retry", useDigest: true,
			query: `SELECT sentinelflow.finish_dispatch_job(
                $1::uuid, $2::uuid, 'retry', 'wrapper_probe',
                $3::sentinelflow.sha256_digest, clock_timestamp() + interval '1 second')`,
		},
		{
			name: "dead", useDigest: true,
			query: `SELECT sentinelflow.finish_dispatch_job(
                $1::uuid, $2::uuid, 'dead', 'wrapper_probe',
                $3::sentinelflow.sha256_digest, NULL)`,
		},
	}
	for _, call := range finishCalls {
		var bypassed bool
		arguments := []any{reclaimedClaim.Job().JobID(), reclaimedClaim.leaseToken}
		if call.useDigest {
			arguments = append(arguments, digestBytes([]byte("wrapper_probe")))
		}
		if err := bypassTx.QueryRow(ctx, call.query, arguments...).Scan(&bypassed); err != nil || bypassed {
			_ = bypassTx.Rollback(ctx)
			t.Fatalf("ordinary %s finish bypassed recovery boundary: finished=%t err=%v",
				call.name, bypassed, err)
		}
	}
	if _, err := bypassTx.Exec(ctx, `RESET ROLE`); err != nil {
		_ = bypassTx.Rollback(ctx)
		t.Fatalf("reset bypass probe role: %v", err)
	}
	var bypassState, bypassToken, bypassDeadState string
	var bypassAttempts int
	if err := bypassTx.QueryRow(ctx, `
SELECT job.state, job.lease_token::text, job.attempts, dead.resolution_state
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.dead_letter_jobs dead USING (job_id)
WHERE job.job_id = $1::uuid`, reclaimedClaim.Job().JobID()).Scan(
		&bypassState, &bypassToken, &bypassAttempts, &bypassDeadState,
	); err != nil || bypassState != "leased" || bypassToken != reclaimedClaim.leaseToken ||
		bypassAttempts != 1 || bypassDeadState != "requeued" {
		_ = bypassTx.Rollback(ctx)
		t.Fatalf("ordinary finish bypass mutated recovery state=%s token=%s attempts=%d dead=%s err=%v",
			bypassState, bypassToken, bypassAttempts, bypassDeadState, err)
	}
	if err := bypassTx.Rollback(ctx); err != nil {
		t.Fatalf("rollback ordinary finish bypass probe: %v", err)
	}

	// Every mutable relational field used by recovery Finish is checked before
	// the private finisher runs. A rejected transaction must leave the live
	// lease, attempt counter, and aggregate version unchanged.
	type finishState struct {
		state    string
		token    string
		attempts int
		version  int
	}
	readFinishState := func() finishState {
		var current finishState
		if err := owner.QueryRow(ctx, `
SELECT state, lease_token::text, attempts, aggregate_version
FROM sentinelflow.outbox_jobs WHERE job_id = $1::uuid`,
			reclaimedClaim.Job().JobID()).Scan(
			&current.state, &current.token, &current.attempts, &current.version,
		); err != nil {
			t.Fatalf("read recovery finish state: %v", err)
		}
		return current
	}
	mutationTests := []struct {
		name      string
		query     string
		argument  any
		jobTarget bool
	}{
		{
			name: "application result digest",
			query: `UPDATE sentinelflow.lifecycle_result_applications_000026
                SET result_digest = $2::sentinelflow.sha256_digest
                WHERE result_id = $1::uuid`,
			argument: digestBytes([]byte("forged-application-result")),
		},
		{
			name: "application resulting state",
			query: `UPDATE sentinelflow.lifecycle_result_applications_000026
                SET resulting_state = $2
                WHERE result_id = $1::uuid`,
			argument: "failed",
		},
		{
			name: "application processed at",
			query: `UPDATE sentinelflow.lifecycle_result_applications_000026 application
                SET processed_at = result.completed_at - interval '1 second'
                FROM sentinelflow.execution_results result
                WHERE application.result_id = $1::uuid
                  AND result.result_id = application.result_id`,
		},
		{
			name: "result capability digest",
			query: `UPDATE sentinelflow.execution_results
                SET capability_digest = $2::sentinelflow.sha256_digest
                WHERE result_id = $1::uuid`,
			argument: digestBytes([]byte("forged-result-capability")),
		},
		{
			name: "job aggregate version",
			query: `UPDATE sentinelflow.outbox_jobs
                SET aggregate_version = aggregate_version + 1
                WHERE job_id = $1::uuid`,
			jobTarget: true,
		},
	}
	for _, test := range mutationTests {
		t.Run("recovery finish rejects "+test.name, func(t *testing.T) {
			before := readFinishState()
			mutationTx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatalf("begin mutation probe: %v", err)
			}
			targetID := persistedResult.resultID
			if test.jobTarget {
				targetID = reclaimedClaim.Job().JobID()
			}
			arguments := []any{targetID}
			if test.argument != nil {
				arguments = append(arguments, test.argument)
			}
			if _, err := mutationTx.Exec(ctx, test.query, arguments...); err != nil {
				_ = mutationTx.Rollback(ctx)
				t.Fatalf("apply mutation probe: %v", err)
			}
			var ignored bool
			finishErr := mutationTx.QueryRow(ctx, `
SELECT sentinelflow.finish_dispatch_recovery_job_000025($1::uuid, $2::uuid)`,
				reclaimedClaim.Job().JobID(), reclaimedClaim.leaseToken).Scan(&ignored)
			var databaseError *pgconn.PgError
			if !errors.As(finishErr, &databaseError) || databaseError.Code != "55000" {
				_ = mutationTx.Rollback(ctx)
				t.Fatalf("mutated recovery finish error=%v", finishErr)
			}
			if err := mutationTx.Rollback(ctx); err != nil {
				t.Fatalf("rollback mutation probe: %v", err)
			}
			after := readFinishState()
			if after != before {
				t.Fatalf("rejected recovery finish mutated state: before=%+v after=%+v", before, after)
			}
		})
	}
	_, err = owner.Exec(ctx, dispatchMigrationContents(t, "000025_dispatch_started_recovery.down.sql"))
	var downgradeError *pgconn.PgError
	if !errors.As(err, &downgradeError) || downgradeError.Code != "55000" {
		t.Fatalf("nonterminal recovery downgrade should fail-stop: %v", err)
	}
	if _, rollbackErr := owner.Exec(ctx, `ROLLBACK`); rollbackErr != nil {
		t.Fatalf("rollback rejected downgrade: %v", rollbackErr)
	}

	// The runtime finishes a newly recovered result under the same recovery
	// lease. Prove that lifecycle result application cannot invalidate the
	// dead-letter recovery fence before that exact finish; roll the probe back
	// so the uncertain-Finish reclaim scenario below remains intact.
	immediateFinishTx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatalf("begin immediate recovery finish probe: %v", err)
	}
	var immediateFinished bool
	immediateFinishErr := immediateFinishTx.QueryRow(ctx, `
SELECT sentinelflow.finish_dispatch_recovery_job_000025($1::uuid, $2::uuid)`,
		reclaimedClaim.Job().JobID(), reclaimedClaim.leaseToken).Scan(&immediateFinished)
	if rollbackErr := immediateFinishTx.Rollback(ctx); rollbackErr != nil {
		t.Fatalf("rollback immediate recovery finish probe: %v", rollbackErr)
	}
	if immediateFinishErr != nil || !immediateFinished {
		t.Fatalf("same-lease recovery finish rejected after result persistence: finished=%t err=%v",
			immediateFinished, immediateFinishErr)
	}

	// Simulate an uncertain Finish commit. After the second lease expires, the
	// next owner recovers the exact result and completes without another UDS call.
	waitForDispatchInstant(t, ctx, owner, reclaimedClaim.LeaseUntil().Add(30*time.Millisecond))
	if _, err := firstStore.Recover(ctx, reclaimedClaim); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired recovery lease err=%v", err)
	}
	completionClaim, found, err := secondStore.ClaimRecoveryNext(ctx, ClaimRequest{
		LeaseOwner: "dispatcher-completion", LeaseDuration: 2 * time.Second,
		CandidateLimit: 4, LeaseToken: "019b0000-0000-4000-8000-000000009155",
	})
	if err != nil || !found {
		t.Fatalf("reclaim uncertain finish: found=%t err=%v", found, err)
	}
	completedRecovery, err := secondStore.Recover(ctx, completionClaim)
	if err != nil || completedRecovery.State() != RecoveryResult {
		t.Fatalf("recover durable result: state=%s err=%v", completedRecovery.State(), err)
	}
	completionResult, exactResult, ok := completedRecovery.Result()
	if !ok || !bytes.Equal(exactResult.CanonicalBytes(), signedResult.CanonicalBytes()) ||
		!bytes.Equal(exactResult.Signature(), signedResult.Signature()) {
		t.Fatal("recovery changed exact executor result")
	}
	if err := secondStore.Finish(ctx, completionClaim, FinishRequest{
		Outcome: FinishCompleted, Result: &completionResult,
	}); err != nil {
		t.Fatalf("finish from recovered result without UDS: %v", err)
	}

	for _, connection := range []*pgx.Conn{first, second} {
		for _, table := range []string{
			"outbox_jobs", "incidents", "admin_sessions", "execution_capabilities", "execution_results",
		} {
			var ignored int
			err := connection.QueryRow(ctx, `SELECT 1 FROM sentinelflow.`+table+` LIMIT 1`).Scan(&ignored)
			var databaseError *pgconn.PgError
			if !errors.As(err, &databaseError) || databaseError.Code != "42501" {
				t.Fatalf("dispatcher unexpectedly read %s: %v", table, err)
			}
		}
	}

	if _, err := owner.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset owner role")
	}
	var state string
	var capabilityCount, resultCount int
	if err := owner.QueryRow(ctx, `
SELECT job.state,
       (SELECT count(*) FROM sentinelflow.execution_capabilities WHERE job_id = job.job_id),
       (SELECT count(*) FROM sentinelflow.execution_results result
        JOIN sentinelflow.execution_capabilities capability USING (capability_id)
        WHERE capability.job_id = job.job_id)
FROM sentinelflow.outbox_jobs job
WHERE job.job_id = '019b0000-0000-7000-8000-000000009114'`).Scan(
		&state, &capabilityCount, &resultCount,
	); err != nil || state != "completed" || capabilityCount != 1 || resultCount != 1 {
		t.Fatalf("durable state=%q capability=%d result=%d err=%v", state, capabilityCount, resultCount, err)
	}

	if _, err := owner.Exec(ctx, dispatchMigrationContents(t, "000025_dispatch_started_recovery.down.sql")); err != nil {
		t.Fatalf("safe completed-job recovery downgrade: %v", err)
	}
	upMigration := dispatchMigrationContents(t, "000025_dispatch_started_recovery.up.sql")
	if _, err := owner.Exec(ctx, upMigration); err != nil {
		t.Fatalf("reapply recovery migration: %v", err)
	}
}

func dispatchRoleConnection(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	return roleDispatchConnection(t, ctx, connectionString, "sentinelflow_dispatcher")
}

func roleDispatchConnection(
	t *testing.T,
	ctx context.Context,
	connectionString string,
	role string,
) *pgx.Conn {
	t.Helper()
	connection := connectDispatchPostgreSQL(t, ctx, connectionString)
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	if _, err := connection.Exec(ctx, `SET ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatalf("set least-privilege role %s", role)
	}
	return connection
}

func dispatchPGCode(err error) string {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		return databaseError.Code
	}
	return ""
}

func waitForApprovedDispatchAction(t *testing.T, ctx context.Context, connection *pgx.Conn, actionID string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var reached bool
		if err := connection.QueryRow(ctx, `
SELECT clock_timestamp() >= approved_at + interval '1 millisecond'
FROM sentinelflow.enforcement_actions
WHERE action_id = $1::uuid`, actionID).Scan(&reached); err != nil {
			t.Fatalf("read PostgreSQL approval clock: %v", err)
		}
		if reached {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for PostgreSQL approval clock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForDispatchInstant(t *testing.T, ctx context.Context, connection *pgx.Conn, instant time.Time) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var reached bool
		if err := connection.QueryRow(ctx, `SELECT clock_timestamp() >= $1::timestamptz`, instant).Scan(&reached); err != nil {
			t.Fatalf("read PostgreSQL dispatch clock: %v", err)
		}
		if reached {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for PostgreSQL dispatch clock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func connectDispatchPostgreSQL(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	for range 40 {
		connection, err := pgx.Connect(ctx, connectionString)
		if err == nil {
			return connection
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PostgreSQL connection: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("connect to disposable PostgreSQL 17")
	return nil
}

func seedApprovedDispatchFixture(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "db", "test", "verify_hil.sql")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read reviewed HIL database fixture")
	}
	marker := "DO $approved_dispatch_view$"
	index := strings.Index(string(contents), marker)
	if index < 0 {
		t.Fatal("reviewed HIL fixture marker is missing")
	}
	prefix := string(contents[:index])
	artifact := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.30 timeout 30m }\n")
	prefix = strings.ReplaceAll(prefix,
		"sha256:3333333333333333333333333333333333333333333333333333333333333333",
		digestBytes(artifact),
	)
	if _, err := connection.Exec(ctx, prefix+"\nCOMMIT;"); err != nil {
		t.Fatalf("seed approved exact-artifact fixture: %v", err)
	}
}

func applyDispatchMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test")
	}
	migrations, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(migrations) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(migrations)
	for _, migration := range migrations {
		contents, readErr := os.ReadFile(migration)
		if readErr != nil {
			t.Fatalf("read %s", filepath.Base(migration))
		}
		if _, applyErr := connection.Exec(ctx, string(contents)); applyErr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(migration), applyErr)
		}
	}
}

func dispatchMigrationContents(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate dispatch migration")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}

func waitForDispatchPostgreSQL(t *testing.T, ctx context.Context, container string) {
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

func dispatchDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := dispatchDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func dispatchDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}
