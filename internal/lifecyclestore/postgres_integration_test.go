//go:build integration

package lifecyclestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleruntime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	lifecyclePolicyID     = "019b0000-0000-7000-8000-000000009105"
	lifecycleValidationID = "019b0000-0000-7000-8000-000000009106"
	lifecycleAddAuthID    = "019b0000-0000-7000-8000-000000009112"
	lifecycleActionID     = "019b0000-0000-7000-8000-000000009113"
	lifecycleAddJobID     = "019b0000-0000-7000-8000-000000009114"
	lifecycleTarget       = "203.0.113.30"
	lifecycleOwnedDigest  = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	lifecyclePassword     = "sentinelflow-lifecycle-test-only"
	lifecyclePostgres17   = "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"
)

var lifecycleAddArtifact = []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.30 timeout 30m }\n")

type dispatchFixture struct {
	operation                string
	actionID                 string
	policyID                 string
	policyVersion            int32
	targetIPv4               string
	artifact                 []byte
	artifactDigest           string
	originalAddDigest        *string
	evidenceSnapshotDigest   string
	validationSnapshotDigest string
	authorizationDigest      string
	actorID                  string
	reasonDigest             string
	ownedSchemaDigest        string
	notBefore                time.Time
	validUntil               time.Time
}

type capabilityRecord struct {
	id, jobID, leaseToken string
	digest                string
	issuedAt              time.Time
	notBefore             time.Time
	expiresAt             time.Time
	jcs                   []byte
	signature             []byte
	operation             dispatchFixture
}

type resultRecord struct {
	id, digest        string
	started, complete time.Time
	jcs, signature    []byte
	classification    string
	nftExitClass      string
	readbackState     string
	remainingTTL      *int32
	errorCode         string
}

func TestLifecycleStoreAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 lifecycle coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-lifecyclestore-%d", time.Now().UnixNano())
	lifecycleDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", lifecyclePostgres17)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForLifecyclePostgreSQL(t, ctx, container)
	port := lifecycleDockerPort(t, ctx, container)
	ownerURL := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	owner := connectLifecyclePostgreSQL(t, ctx, ownerURL)
	t.Cleanup(func() { _ = owner.Close(context.Background()) })

	// Empty down/up cycles prove that the migration is reversible only before
	// lifecycle evidence exists.  The final application is the tested schema.
	applyLifecycleMigrationsThrough(t, ctx, owner, 26)
	applyLifecycleMigration(t, ctx, owner, "000026_enforcement_lifecycle.down.sql")
	applyLifecycleMigration(t, ctx, owner, "000026_enforcement_lifecycle.up.sql")
	applyLifecycleMigration(t, ctx, owner, "000026_enforcement_lifecycle.down.sql")
	applyLifecycleMigration(t, ctx, owner, "000026_enforcement_lifecycle.up.sql")
	assertPostgreSQL17AndRole(t, ctx, owner)

	seedLifecycleFixture(t, ctx, owner)
	waitForDatabasePredicate(t, ctx, owner, `
SELECT clock_timestamp() >= approved_at
FROM sentinelflow.enforcement_actions
WHERE action_id = $1::uuid`, lifecycleActionID)

	addLease := "019f0000-0000-4000-8000-000000000101"
	if !claimDispatchJob(t, ctx, owner, lifecycleAddJobID, addLease) {
		t.Fatal("approved add job was not claimed")
	}
	addOperation := loadDispatchFixture(t, ctx, owner, lifecycleAddJobID)
	addCapability := recordCapability(t, ctx, owner,
		"019f0000-0000-7000-8000-000000000102", lifecycleAddJobID, addLease, addOperation)
	assertActionState(t, ctx, owner, "queued", 2)
	var policyState string
	var capabilityApplications, queuedAudits int
	if err := owner.QueryRow(ctx, `
SELECT policy.state,
       (SELECT count(*)::integer FROM sentinelflow.lifecycle_capability_applications_000026),
       (SELECT count(*)::integer FROM sentinelflow.audit_events
        WHERE event_id = $1::uuid AND action = 'enforcement_queued')
FROM sentinelflow.policy_proposals policy
WHERE policy.policy_id = $2::uuid AND policy.version = 1`,
		addCapability.id, lifecyclePolicyID).Scan(&policyState, &capabilityApplications, &queuedAudits); err != nil {
		t.Fatal(err)
	}
	if policyState != "queued" || capabilityApplications != 1 || queuedAudits != 1 {
		t.Fatalf("capability lifecycle not atomic: policy=%s applications=%d audit=%d",
			policyState, capabilityApplications, queuedAudits)
	}
	// Exact replay is a no-op; any valid changed byte is a hard conflict.
	replayCapability(t, ctx, owner, addCapability)
	changedCapability := addCapability
	changedCapability.jcs = []byte(`{"changed":true}`)
	changedCapability.digest = lifecycleDigest(changedCapability.jcs)
	if err := callRecordCapability(ctx, owner, changedCapability); lifecyclePGCode(err) != "23505" {
		t.Fatalf("changed capability replay was accepted: %v", err)
	}

	remaining := int32(60)
	addResult := resultRecord{
		id:             "019f0000-0000-7000-8000-000000000103",
		classification: "applied", nftExitClass: "success", readbackState: "active",
		remainingTTL: &remaining, errorCode: "none",
	}
	recordResult(t, ctx, owner, addCapability, &addResult)
	assertActionState(t, ctx, owner, "active", 3)
	var expectedExpiry time.Time
	var scheduleAuthorization string
	if err := owner.QueryRow(ctx, `
SELECT action.expected_expires_at, schedule.authorization_id::text
FROM sentinelflow.enforcement_actions action
JOIN sentinelflow.lifecycle_inspection_schedules_000026 schedule
  ON schedule.schedule_id = $1::uuid
WHERE action.action_id = $2::uuid`, addResult.id, lifecycleActionID).
		Scan(&expectedExpiry, &scheduleAuthorization); err != nil {
		t.Fatal(err)
	}
	if expectedExpiry.After(addResult.complete.Add(60*time.Second)) ||
		expectedExpiry.After(addResult.started.Add(1800*time.Second)) {
		t.Fatalf("expected expiry extended signed/approved TTL: %s", expectedExpiry)
	}
	replayResult(t, ctx, owner, addCapability, addResult)
	changedResult := addResult
	changedResult.jcs = []byte(`{"changed":true}`)
	changedResult.digest = lifecycleDigest(changedResult.jcs)
	if err := callRecordResult(ctx, owner, addCapability, changedResult); lifecyclePGCode(err) != "23505" {
		t.Fatalf("changed result replay was accepted: %v", err)
	}

	// Transition and immutable-field guards reject direct resurrection and
	// target mutation even for the migration owner.
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.enforcement_actions
SET state = 'approved', version = version + 1, updated_at = clock_timestamp()
WHERE action_id = $1::uuid`, lifecycleActionID); lifecyclePGCode(err) != "23514" {
		t.Fatalf("illegal lifecycle resurrection was accepted: %v", err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.enforcement_actions
SET target_ipv4 = '203.0.113.31', updated_at = clock_timestamp()
WHERE action_id = $1::uuid`, lifecycleActionID); lifecyclePGCode(err) != "55000" && lifecyclePGCode(err) != "23514" {
		t.Fatalf("immutable action target was changed: %v", err)
	}

	// Expedite only the test schedule; production due selection remains solely
	// DB-clocked.  Two independent LOGIN-role stores must yield one lease.
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.lifecycle_inspection_schedules_000026
SET due_at = clock_timestamp(), updated_at = clock_timestamp()
WHERE schedule_id = $1::uuid`, addResult.id); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `ALTER ROLE sentinelflow_lifecycle PASSWORD '`+lifecyclePassword+`'`); err != nil {
		t.Fatal(err)
	}
	roleURL := fmt.Sprintf(
		"postgresql://sentinelflow_lifecycle:%s@127.0.0.1:%s/postgres?sslmode=disable",
		lifecyclePassword, port,
	)
	first := connectLifecyclePostgreSQL(t, ctx, roleURL)
	second := connectLifecyclePostgreSQL(t, ctx, roleURL)
	t.Cleanup(func() { _ = first.Close(context.Background()) })
	t.Cleanup(func() { _ = second.Close(context.Background()) })
	firstStore := mustLifecycleStore(t, first, "worker-a")
	secondStore := mustLifecycleStore(t, second, "worker-b")
	type claimResult struct {
		claim lifecycleruntime.Claim
		found bool
		err   error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	for _, store := range []*PostgreSQLStore{firstStore, secondStore} {
		go func(current *PostgreSQLStore) {
			<-start
			claim, found, err := current.ClaimDue(ctx)
			results <- claimResult{claim: claim, found: found, err: err}
		}(store)
	}
	close(start)
	wins, misses := 0, 0
	var won lifecycleruntime.Claim
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent lifecycle claim: %v", result.err)
		}
		if result.found {
			wins++
			won = result.claim
		} else {
			misses++
		}
	}
	if wins != 1 || misses != 1 {
		t.Fatalf("lease fencing yielded wins=%d misses=%d", wins, misses)
	}
	scheduleID, leaseID := won.StoreIdentity()
	failureDigest := lifecycleDigest([]byte("sentinelflow lifecycle-runtime-failure-v1\ncontext_cancelled\n"))
	var failureDisposition string
	if err := first.QueryRow(ctx, `
SELECT sentinelflow.finish_lifecycle_inspection_failure_000026(
  $1::uuid, $2::uuid, $3, 'context_cancelled', $4, 1
)`, scheduleID, leaseID, int32(won.ActionVersion()), failureDigest).Scan(&failureDisposition); err != nil {
		t.Fatal(err)
	}
	if failureDisposition != "retry" {
		t.Fatalf("context cancellation disposition=%s", failureDisposition)
	}
	// Exact failure replay is stable. A caller-supplied digest can never select
	// a different semantic failure code.
	var replayDisposition string
	if err := second.QueryRow(ctx, `
SELECT sentinelflow.finish_lifecycle_inspection_failure_000026(
  $1::uuid, $2::uuid, $3, 'context_cancelled', $4, 1
)`, scheduleID, leaseID, int32(won.ActionVersion()), failureDigest).Scan(&replayDisposition); err != nil || replayDisposition != "retry" {
		t.Fatalf("failure replay=%s err=%v", replayDisposition, err)
	}
	if err := second.QueryRow(ctx, `
SELECT sentinelflow.finish_lifecycle_inspection_failure_000026(
  $1::uuid, $2::uuid, $3, 'context_cancelled', $4, 1
)`, scheduleID, leaseID, int32(won.ActionVersion()), lifecycleDigest([]byte("wrong"))).Scan(&replayDisposition); lifecyclePGCode(err) != "23514" {
		t.Fatalf("wrong failure digest was accepted: %v", err)
	}
	waitForDatabasePredicate(t, ctx, owner, `
SELECT clock_timestamp() >= due_at
FROM sentinelflow.lifecycle_inspection_schedules_000026
WHERE schedule_id = $1::uuid`, scheduleID)
	runtimeWorker, err := lifecycleruntime.New(firstStore,
		lifecycleruntime.DefaultConfig("lifecycle-v1"), lifecycleruntime.Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := runtimeWorker.ProcessNext(ctx)
	if err != nil || processed.Outcome() != lifecycleruntime.OutcomeCommitted {
		t.Fatalf("runtime inspection commit=%s err=%v", processed.Outcome(), err)
	}
	var persistedAuthorization, scheduleState string
	if err := owner.QueryRow(ctx, `
SELECT artifact.authorization_id::text, schedule.state
FROM sentinelflow.lifecycle_inspection_artifacts_000026 artifact
JOIN sentinelflow.lifecycle_inspection_schedules_000026 schedule USING (schedule_id)
WHERE schedule.schedule_id = $1::uuid`, scheduleID).
		Scan(&persistedAuthorization, &scheduleState); err != nil {
		t.Fatal(err)
	}
	if persistedAuthorization != scheduleAuthorization || scheduleState != "dispatched" {
		t.Fatalf("stable authorization/commit mismatch: got=%s want=%s state=%s",
			persistedAuthorization, scheduleAuthorization, scheduleState)
	}
	var inspectJobID string
	if err := owner.QueryRow(ctx, `
SELECT dispatch_job_id::text
FROM sentinelflow.lifecycle_inspection_artifacts_000026
WHERE schedule_id=$1::uuid`, scheduleID).Scan(&inspectJobID); err != nil {
		t.Fatal(err)
	}
	inspectLease := "019f0000-0000-4000-8000-000000000105"
	if !claimDispatchJob(t, ctx, owner, inspectJobID, inspectLease) {
		t.Fatal("read-only inspection job was not claimed")
	}
	inspectCapability := recordCapability(t, ctx, owner,
		"019f0000-0000-7000-8000-000000000106", inspectJobID, inspectLease,
		loadDispatchFixture(t, ctx, owner, inspectJobID))
	inspectRemaining := int32(60)
	inspectResult := resultRecord{
		id:             "019f0000-0000-7000-8000-000000000107",
		classification: "inspect_active", nftExitClass: "success", readbackState: "active",
		remainingTTL: &inspectRemaining, errorCode: "none",
	}
	recordResult(t, ctx, owner, inspectCapability, &inspectResult)
	var expiryAfterInspect time.Time
	if err := owner.QueryRow(ctx, `
SELECT expected_expires_at
FROM sentinelflow.enforcement_actions WHERE action_id=$1::uuid`, lifecycleActionID).
		Scan(&expiryAfterInspect); err != nil {
		t.Fatal(err)
	}
	if !expiryAfterInspect.Equal(expectedExpiry) {
		t.Fatalf("read-only inspection extended expiry: before=%s after=%s",
			expectedExpiry, expiryAfterInspect)
	}
	assertActionState(t, ctx, owner, "active", 3)
	replayResult(t, ctx, owner, inspectCapability, inspectResult)
	processed, err = runtimeWorker.ProcessNext(ctx)
	if err != nil || processed.Outcome() != lifecycleruntime.OutcomeNoWork {
		t.Fatalf("committed schedule was reclaimed: outcome=%s err=%v", processed.Outcome(), err)
	}
	assertLifecycleRoleIsFunctionsOnly(t, ctx, owner, first)

	// Simulate an in-flight inspection changing active -> indeterminate before
	// a separately authorized revoke result arrives. Shortening (never
	// extending) expected expiry creates both sides of the expiry race quickly.
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.policy_proposals
SET state = 'indeterminate', state_revision = state_revision + 1,
    updated_at = clock_timestamp()
WHERE policy_id = $1::uuid AND version = 1 AND state = 'active'`, lifecyclePolicyID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.enforcement_actions
SET state = 'indeterminate', expected_expires_at = clock_timestamp() + interval '1 second',
    version = version + 1, updated_at = clock_timestamp()
WHERE action_id = $1::uuid AND state = 'active'`, lifecycleActionID); err != nil {
		t.Fatal(err)
	}
	revokeJobID := "019f0000-0000-7000-8000-000000000110"
	insertRevokeDispatch(t, ctx, owner, revokeJobID)
	revokeLease := "019f0000-0000-4000-8000-000000000111"
	if !claimDispatchJob(t, ctx, owner, revokeJobID, revokeLease) {
		t.Fatal("indeterminate revoke job was not claimed")
	}
	revokeOperation := loadDispatchFixture(t, ctx, owner, revokeJobID)
	revokeCapability := recordCapability(t, ctx, owner,
		"019f0000-0000-7000-8000-000000000112", revokeJobID, revokeLease, revokeOperation)
	for _, test := range []struct {
		id             string
		classification string
		nftExitClass   string
		errorCode      string
		wantState      string
	}{
		{"019f0000-0000-7000-8000-000000000115", "failed", "not_invoked", "nft_failed", "failed"},
		{"019f0000-0000-7000-8000-000000000116", "indeterminate", "not_invoked", "indeterminate", "indeterminate"},
	} {
		t.Run("revoke result from indeterminate "+test.classification, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			value := resultRecord{
				id: test.id, classification: test.classification,
				nftExitClass: test.nftExitClass, readbackState: "unavailable",
				errorCode: test.errorCode,
			}
			prepareResultTimes(t, ctx, tx, &value)
			if err := callRecordResult(ctx, tx, revokeCapability, value); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatalf("persist exact result: %v", err)
			}
			var state string
			if err := tx.QueryRow(ctx, `
SELECT state FROM sentinelflow.enforcement_actions WHERE action_id=$1::uuid`,
				lifecycleActionID).Scan(&state); err != nil || state != test.wantState {
				_ = tx.Rollback(ctx)
				t.Fatalf("state=%s want=%s err=%v", state, test.wantState, err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}

	// Prove the pre-expiry indeterminate -> revoked branch inside a rolled-back
	// transaction so the same exact persisted capability can cover the race.
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := resultRecord{
		id:             "019f0000-0000-7000-8000-000000000113",
		classification: "revoked", nftExitClass: "success", readbackState: "absent",
		errorCode: "none",
	}
	prepareResultTimes(t, ctx, tx, &before)
	if err := callRecordResult(ctx, tx, revokeCapability, before); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("pre-expiry revoke from indeterminate: %v", err)
	}
	var stateInTransaction string
	if err := tx.QueryRow(ctx, `SELECT state FROM sentinelflow.enforcement_actions WHERE action_id=$1::uuid`,
		lifecycleActionID).Scan(&stateInTransaction); err != nil || stateInTransaction != "revoked" {
		_ = tx.Rollback(ctx)
		t.Fatalf("pre-expiry revoke state=%s err=%v", stateInTransaction, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	waitForDatabasePredicate(t, ctx, owner, `
SELECT clock_timestamp() >= expected_expires_at
FROM sentinelflow.enforcement_actions WHERE action_id=$1::uuid`, lifecycleActionID)
	after := resultRecord{
		id:             "019f0000-0000-7000-8000-000000000114",
		classification: "revoked", nftExitClass: "success", readbackState: "absent",
		errorCode: "none",
	}
	recordResult(t, ctx, owner, revokeCapability, &after)
	assertActionState(t, ctx, owner, "expired", 5)
	replayResult(t, ctx, owner, revokeCapability, after)

	// One synthetic terminal-source schedule exercises both failure branches.
	// Exhaustion is checked first in a rolled-back transaction; the same row is
	// then normalized to pending and must die as a stale binding with a distinct
	// authorization-keyed audit record.
	deadScheduleID := "019f0000-0000-7000-8000-000000000120"
	deadAuthorizationID := "019f0000-0000-7000-8000-000000000121"
	insertExhaustedSchedule(t, ctx, owner, deadScheduleID, deadAuthorizationID, after)
	tx, err = owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE sentinelflow_lifecycle`); err != nil {
		t.Fatal(err)
	}
	var ignored string
	err = tx.QueryRow(ctx, `
SELECT schedule_identity
FROM sentinelflow.claim_lifecycle_inspection_schedule_000026('lifecycle-v1','worker-x',30)`).Scan(&ignored)
	if !errors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		t.Fatalf("exhausted schedule was returned: %v", err)
	}
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	var deadState, deadCode string
	var deadAudits int
	if err := tx.QueryRow(ctx, `
SELECT schedule.state, schedule.last_error_code,
       (SELECT count(*)::integer FROM sentinelflow.audit_events
        WHERE event_id=$2::uuid AND action='inspection_schedule_dead')
FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
WHERE schedule.schedule_id=$1::uuid`, deadScheduleID, deadAuthorizationID).
		Scan(&deadState, &deadCode, &deadAudits); err != nil || deadState != "dead" ||
		deadCode != "lease_attempts_exhausted" || deadAudits != 1 {
		_ = tx.Rollback(ctx)
		t.Fatalf("exhaustion state=%s code=%s audits=%d err=%v", deadState, deadCode, deadAudits, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.lifecycle_inspection_schedules_000026
SET state='pending', attempts=0, scheduler_id=NULL, lease_owner=NULL,
    lease_token=NULL, leased_at=NULL, lease_expires_at=NULL,
    authorization_requested_at=NULL, authorization_valid_until=NULL,
    last_error_code=NULL, last_error_digest=NULL, updated_at=clock_timestamp()
WHERE schedule_id=$1::uuid`, deadScheduleID); err != nil {
		t.Fatal(err)
	}
	err = owner.QueryRow(ctx, `
SELECT schedule_identity
FROM sentinelflow.claim_lifecycle_inspection_schedule_000026('lifecycle-v1','worker-x',30)`).Scan(&ignored)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale terminal schedule was returned: %v", err)
	}
	if err := owner.QueryRow(ctx, `
SELECT schedule.state, schedule.last_error_code,
       (SELECT count(*)::integer FROM sentinelflow.audit_events
        WHERE event_id=$2::uuid AND action='inspection_schedule_stale')
FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
WHERE schedule.schedule_id=$1::uuid`, deadScheduleID, deadAuthorizationID).
		Scan(&deadState, &deadCode, &deadAudits); err != nil || deadState != "dead" ||
		deadCode != "binding_stale" || deadAudits != 1 {
		t.Fatalf("stale state=%s code=%s audits=%d err=%v", deadState, deadCode, deadAudits, err)
	}

	// Evidence-bearing rollback is deliberately blocked.
	down := lifecycleMigrationContents(t, "000026_enforcement_lifecycle.down.sql")
	if _, err := owner.Exec(ctx, down); lifecyclePGCode(err) != "55000" {
		t.Fatalf("unsafe down migration succeeded: %v", err)
	}
	_, _ = owner.Exec(ctx, `ROLLBACK`)
	var versionExists bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sentinelflow.schema_migrations WHERE version=26)`).
		Scan(&versionExists); err != nil || !versionExists {
		t.Fatalf("unsafe down changed schema version: exists=%t err=%v", versionExists, err)
	}

	t.Run("pre-000026 execution artifacts block upgrade", func(t *testing.T) {
		testPreLifecycleArtifactUpgradeGuard(t, ctx, owner, ownerURL)
	})
}

func mustLifecycleStore(t *testing.T, connection *pgx.Conn, owner string) *PostgreSQLStore {
	t.Helper()
	store, err := NewPostgreSQLStore(connection, Config{
		SchedulerID: "lifecycle-v1", LeaseOwner: owner,
		LeaseDuration: 30 * time.Second, RetryBackoff: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func seedLifecycleFixture(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	contents := lifecycleTestContents(t, "db", "test", "verify_hil.sql")
	marker := "DO $approved_dispatch_view$"
	index := strings.Index(contents, marker)
	if index < 0 {
		t.Fatal("reviewed HIL fixture marker is missing")
	}
	prefix := strings.ReplaceAll(contents[:index],
		"sha256:3333333333333333333333333333333333333333333333333333333333333333",
		lifecycleDigest(lifecycleAddArtifact),
	)
	if _, err := connection.Exec(ctx, prefix+"\nCOMMIT;"); err != nil {
		t.Fatalf("seed lifecycle fixture: %v", err)
	}
}

func claimDispatchJob(t *testing.T, ctx context.Context, connection *pgx.Conn, jobID, lease string) bool {
	t.Helper()
	var claimed bool
	if err := connection.QueryRow(ctx, `
SELECT sentinelflow.claim_dispatch_job($1::uuid,$2::uuid,'lifecycle-test',clock_timestamp()+interval '30 seconds')`,
		jobID, lease).Scan(&claimed); err != nil {
		t.Fatal(err)
	}
	return claimed
}

func loadDispatchFixture(t *testing.T, ctx context.Context, connection *pgx.Conn, jobID string) dispatchFixture {
	t.Helper()
	var value dispatchFixture
	if err := connection.QueryRow(ctx, `
SELECT operation, action_id::text, policy_id::text, policy_version, host(target_ipv4),
       artifact, artifact_digest::text, original_add_digest::text,
       evidence_snapshot_digest::text, validation_snapshot_digest::text,
       authorization_digest::text, actor_id::text, reason_digest::text,
       owned_schema_digest::text, not_before, valid_until
FROM sentinelflow.dispatch_operations WHERE job_id=$1::uuid`, jobID).Scan(
		&value.operation, &value.actionID, &value.policyID, &value.policyVersion,
		&value.targetIPv4, &value.artifact, &value.artifactDigest, &value.originalAddDigest,
		&value.evidenceSnapshotDigest, &value.validationSnapshotDigest,
		&value.authorizationDigest, &value.actorID, &value.reasonDigest,
		&value.ownedSchemaDigest, &value.notBefore, &value.validUntil,
	); err != nil {
		t.Fatal(err)
	}
	return value
}

func recordCapability(
	t *testing.T, ctx context.Context, connection *pgx.Conn,
	capabilityID, jobID, lease string, operation dispatchFixture,
) capabilityRecord {
	t.Helper()
	var now time.Time
	if err := connection.QueryRow(ctx, `SELECT date_trunc('milliseconds',clock_timestamp())`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	jcs := []byte(fmt.Sprintf(`{"capability_id":%q}`, capabilityID))
	value := capabilityRecord{
		id: capabilityID, jobID: jobID, leaseToken: lease,
		digest: lifecycleDigest(jcs), issuedAt: now, notBefore: now,
		expiresAt: now.Add(30 * time.Second), jcs: jcs,
		signature: bytes.Repeat([]byte{0x41}, 64), operation: operation,
	}
	if err := callRecordCapability(ctx, connection, value); err != nil {
		t.Fatalf("record capability: %v", err)
	}
	return value
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func callRecordCapability(ctx context.Context, connection queryRower, value capabilityRecord) error {
	var ignored string
	return connection.QueryRow(ctx, `
SELECT sentinelflow.record_execution_capability(
 $1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6::uuid,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
 $18,$19,$20,$21,$22,$23,$24
)::text`, value.id, value.jobID, value.leaseToken, value.operation.operation,
		value.operation.actionID, value.operation.policyID, value.operation.policyVersion,
		value.operation.targetIPv4, value.operation.artifact, value.operation.artifactDigest,
		value.operation.originalAddDigest, value.operation.evidenceSnapshotDigest,
		value.operation.validationSnapshotDigest, value.operation.authorizationDigest,
		value.operation.actorID, value.operation.reasonDigest, value.operation.ownedSchemaDigest,
		value.jcs, value.digest, value.signature,
		lifecycleDigest([]byte("nonce:"+value.id)), value.issuedAt, value.notBefore, value.expiresAt,
	).Scan(&ignored)
}

func replayCapability(t *testing.T, ctx context.Context, connection queryRower, value capabilityRecord) {
	t.Helper()
	if err := callRecordCapability(ctx, connection, value); err != nil {
		t.Fatalf("exact capability replay: %v", err)
	}
}

func prepareResultTimes(t *testing.T, ctx context.Context, connection queryRower, value *resultRecord) {
	t.Helper()
	if err := connection.QueryRow(ctx, `SELECT date_trunc('milliseconds',clock_timestamp())`).Scan(&value.started); err != nil {
		t.Fatal(err)
	}
	value.complete = value.started
	value.jcs = []byte(fmt.Sprintf(`{"result_id":%q}`, value.id))
	value.digest = lifecycleDigest(value.jcs)
	value.signature = bytes.Repeat([]byte{0x52}, 64)
}

func recordResult(
	t *testing.T, ctx context.Context, connection queryRower,
	capability capabilityRecord, value *resultRecord,
) {
	t.Helper()
	prepareResultTimes(t, ctx, connection, value)
	if err := callRecordResult(ctx, connection, capability, *value); err != nil {
		t.Fatalf("record %s result: %v", value.classification, err)
	}
}

func callRecordResult(
	ctx context.Context, connection queryRower, capability capabilityRecord, value resultRecord,
) error {
	var ignored string
	return connection.QueryRow(ctx, `
SELECT sentinelflow.record_execution_result(
 $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7::uuid,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22
)::text`, value.id, capability.jobID, capability.leaseToken, capability.id,
		capability.digest, capability.operation.operation, capability.operation.actionID,
		capability.operation.artifactDigest, capability.operation.targetIPv4,
		value.classification, value.nftExitClass, value.readbackState, nil,
		value.remainingTTL, capability.operation.ownedSchemaDigest,
		value.started, value.complete, int64(1), value.errorCode,
		value.jcs, value.digest, value.signature,
	).Scan(&ignored)
}

func replayResult(
	t *testing.T, ctx context.Context, connection queryRower,
	capability capabilityRecord, value resultRecord,
) {
	t.Helper()
	if err := callRecordResult(ctx, connection, capability, value); err != nil {
		t.Fatalf("exact result replay: %v", err)
	}
}

func insertRevokeDispatch(t *testing.T, ctx context.Context, connection *pgx.Conn, jobID string) {
	t.Helper()
	revokeArtifact := []byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.30 }\n")
	revokeDigest := lifecycleDigest(revokeArtifact)
	if _, err := connection.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.enforcement_authorizations (
 authorization_id,schema_version,authorization_kind,action_id,policy_id,policy_version,
 approval_decision_id,decision,target_ipv4,policy_digest,generated_artifact_digest,
 canonical_artifact_digest,original_add_digest,evidence_snapshot_digest,
 validation_snapshot_digest,actor_id,hil_reason_digest,decision_nonce_digest,
 idempotency_key_digest,authorization_jcs,authorization_digest,decided_at,valid_until
)
SELECT '019f0000-0000-7000-8000-000000000108','enforcement-authorization-v1','revoke',
       action.action_id,action.policy_id,action.policy_version,
       '019f0000-0000-7000-8000-000000000107','revoke',action.target_ipv4,
       policy.policy_digest,$1,$1,action.canonical_artifact_digest,
       action.evidence_snapshot_digest,validation.snapshot_digest,'admin-test',
       $2,$3,$4,convert_to('{"revoke":"synthetic-lifecycle-race"}','UTF8'),$5,
       clock_timestamp(),clock_timestamp()+interval '5 minutes'
FROM sentinelflow.enforcement_actions action
JOIN sentinelflow.policy_proposals policy
  ON policy.policy_id=action.policy_id AND policy.version=action.policy_version
JOIN sentinelflow.validation_snapshots validation
  ON validation.validation_snapshot_id=action.validation_snapshot_id
WHERE action.action_id=$6::uuid`, revokeDigest,
		lifecycleDigest([]byte("revoke reason")), lifecycleDigest([]byte("revoke nonce")),
		lifecycleDigest([]byte("revoke idempotency")),
		lifecycleDigest([]byte(`{"revoke":"synthetic-lifecycle-race"}`)), lifecycleActionID); err != nil {
		_, _ = connection.Exec(ctx, `SET session_replication_role = origin`)
		t.Fatalf("insert revoke authorization: %v", err)
	}
	if _, err := connection.Exec(ctx, `SET session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.outbox_jobs (
 job_id,kind,aggregate_type,aggregate_id,aggregate_version,operation,idempotency_key,
 state,available_at,max_attempts,created_at,updated_at
)
SELECT $1::uuid,'dispatch_revoke','enforcement_action',action_id,version,'revoke',$2,
       'pending',clock_timestamp(),8,clock_timestamp(),clock_timestamp()
FROM sentinelflow.enforcement_actions WHERE action_id=$3::uuid`,
		jobID, lifecycleDigest([]byte("revoke job")), lifecycleActionID); err != nil {
		t.Fatalf("insert revoke job: %v", err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.dispatch_operations (
 job_id,operation,action_id,policy_id,policy_version,target_ipv4,artifact,artifact_digest,
 original_add_digest,evidence_snapshot_digest,validation_snapshot_id,
 validation_snapshot_digest,enforcement_authorization_id,inspection_authorization_id,
 authorization_digest,actor_id,reason_digest,owned_schema_digest,not_before,valid_until,created_at
)
SELECT $1::uuid,'revoke',action.action_id,action.policy_id,action.policy_version,
       action.target_ipv4,$3,$4,action.canonical_artifact_digest,
       action.evidence_snapshot_digest,action.validation_snapshot_id,validation.snapshot_digest,
       auth.authorization_id,NULL,auth.authorization_digest,auth.actor_id,auth.hil_reason_digest,
       $5,clock_timestamp()-interval '1 second',clock_timestamp()+interval '3 minutes',clock_timestamp()
FROM sentinelflow.enforcement_actions action
JOIN sentinelflow.validation_snapshots validation
  ON validation.validation_snapshot_id=action.validation_snapshot_id
JOIN sentinelflow.enforcement_authorizations auth
  ON auth.action_id=action.action_id AND auth.authorization_kind='revoke'
WHERE action.action_id=$2::uuid`, jobID, lifecycleActionID,
		revokeArtifact, revokeDigest, lifecycleOwnedDigest); err != nil {
		t.Fatalf("insert revoke dispatch: %v", err)
	}
}

func insertExhaustedSchedule(
	t *testing.T, ctx context.Context, connection *pgx.Conn,
	scheduleID, authorizationID string, source resultRecord,
) {
	t.Helper()
	if _, err := connection.Exec(ctx, `
WITH instant AS MATERIALIZED (
 SELECT clock_timestamp() AS server_now
)
INSERT INTO sentinelflow.lifecycle_inspection_schedules_000026 (
 schedule_id,authorization_id,dispatch_job_id,source_result_id,source_result_digest,
 action_id,action_version,policy_id,policy_version,target_ipv4,original_add_digest,
 original_authorization_digest,evidence_snapshot_digest,validation_snapshot_id,
 validation_snapshot_digest,owned_schema_digest,purpose,due_at,state,attempts,max_attempts,
 scheduler_id,lease_owner,lease_token,leased_at,lease_expires_at,
 authorization_requested_at,authorization_valid_until,created_at,updated_at
)
SELECT $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,action.action_id,action.version,
       action.policy_id,action.policy_version,action.target_ipv4,action.canonical_artifact_digest,
       operation.authorization_digest,action.evidence_snapshot_digest,action.validation_snapshot_id,
       operation.validation_snapshot_digest,operation.owned_schema_digest,'reconciliation',
       instant.server_now-interval '2 minutes','leased',8,8,'lifecycle-v1','worker-dead',
       $6::uuid,instant.server_now-interval '2 minutes',instant.server_now-interval '1 minute',
       instant.server_now-interval '2 minutes',instant.server_now+interval '3 minutes',
       instant.server_now-interval '2 minutes',instant.server_now-interval '1 minute'
FROM sentinelflow.enforcement_actions action
JOIN sentinelflow.dispatch_operations operation ON operation.job_id=$7::uuid
CROSS JOIN instant
WHERE action.action_id=$8::uuid`, scheduleID, authorizationID,
		"019f0000-0000-7000-8000-000000000122", source.id, source.digest,
		"019f0000-0000-4000-8000-000000000123", lifecycleAddJobID, lifecycleActionID); err != nil {
		t.Fatalf("insert exhausted lifecycle schedule: %v", err)
	}
}

func assertLifecycleRoleIsFunctionsOnly(
	t *testing.T, ctx context.Context, owner, role *pgx.Conn,
) {
	t.Helper()
	if err := role.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.lifecycle_inspection_schedules_000026`).Scan(new(int)); lifecyclePGCode(err) != "42501" {
		t.Fatalf("lifecycle role can read table: %v", err)
	}
	if _, err := role.Exec(ctx, `DELETE FROM sentinelflow.lifecycle_inspection_schedules_000026 WHERE false`); lifecyclePGCode(err) != "42501" {
		t.Fatalf("lifecycle role can mutate table: %v", err)
	}
	var exactFunctions int
	var forbiddenDispatcher bool
	if err := owner.QueryRow(ctx, `
SELECT count(*)::integer,
       has_function_privilege('sentinelflow_lifecycle',
         'sentinelflow.record_execution_result(uuid,uuid,uuid,uuid,sentinelflow.sha256_digest,text,uuid,sentinelflow.sha256_digest,sentinelflow.canonical_ipv4,text,text,text,bigint,integer,sentinelflow.sha256_digest,timestamptz,timestamptz,bigint,text,bytea,sentinelflow.sha256_digest,bytea)',
         'EXECUTE')
FROM information_schema.routine_privileges
WHERE grantee='sentinelflow_lifecycle' AND routine_schema='sentinelflow'
  AND routine_name IN ('claim_lifecycle_inspection_schedule_000026',
    'commit_lifecycle_inspection_000026','finish_lifecycle_inspection_failure_000026')`).
		Scan(&exactFunctions, &forbiddenDispatcher); err != nil {
		t.Fatal(err)
	}
	if exactFunctions != 3 || forbiddenDispatcher {
		t.Fatalf("role grants: exact=%d dispatcher=%t", exactFunctions, forbiddenDispatcher)
	}
}

func assertActionState(t *testing.T, ctx context.Context, connection *pgx.Conn, want string, version int32) {
	t.Helper()
	var state string
	var gotVersion int32
	if err := connection.QueryRow(ctx, `
SELECT state,version FROM sentinelflow.enforcement_actions WHERE action_id=$1::uuid`, lifecycleActionID).
		Scan(&state, &gotVersion); err != nil {
		t.Fatal(err)
	}
	if state != want || gotVersion != version {
		t.Fatalf("action state/version=%s/%d want=%s/%d", state, gotVersion, want, version)
	}
}

func assertPostgreSQL17AndRole(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	var version int
	var login, inherit, superuser, bypass bool
	var limit int
	if err := connection.QueryRow(ctx, `
SELECT current_setting('server_version_num')::integer/10000,rolcanlogin,rolinherit,rolsuper,
       rolbypassrls,rolconnlimit
FROM pg_roles WHERE rolname='sentinelflow_lifecycle'`).
		Scan(&version, &login, &inherit, &superuser, &bypass, &limit); err != nil {
		t.Fatal(err)
	}
	if version != 17 || !login || inherit || superuser || bypass || limit != 4 {
		t.Fatalf("PostgreSQL/role invariant: v=%d login=%t inherit=%t super=%t bypass=%t limit=%d",
			version, login, inherit, superuser, bypass, limit)
	}
}

func testPreLifecycleArtifactUpgradeGuard(
	t *testing.T, ctx context.Context, owner *pgx.Conn, ownerURL string,
) {
	t.Helper()
	if _, err := owner.Exec(ctx, `CREATE DATABASE lifecycle_upgrade_guard`); err != nil {
		t.Fatal(err)
	}
	guardURL := strings.Replace(ownerURL, "/postgres?", "/lifecycle_upgrade_guard?", 1)
	guard := connectLifecyclePostgreSQL(t, ctx, guardURL)
	defer guard.Close(context.Background())
	applyLifecycleMigrationsThrough(t, ctx, guard, 25)
	seedLifecycleFixture(t, ctx, guard)
	waitForDatabasePredicate(t, ctx, guard, `
SELECT clock_timestamp() >= approved_at
FROM sentinelflow.enforcement_actions WHERE action_id=$1::uuid`, lifecycleActionID)
	lease := "019f0000-0000-4000-8000-000000000131"
	if !claimDispatchJob(t, ctx, guard, lifecycleAddJobID, lease) {
		t.Fatal("pre-lifecycle artifact job not claimed")
	}
	recordCapability(t, ctx, guard,
		"019f0000-0000-7000-8000-000000000132", lifecycleAddJobID, lease,
		loadDispatchFixture(t, ctx, guard, lifecycleAddJobID))
	contents := lifecycleMigrationContents(t, "000026_enforcement_lifecycle.up.sql")
	if _, err := guard.Exec(ctx, contents); lifecyclePGCode(err) != "55000" {
		t.Fatalf("pre-000026 artifact upgrade was accepted: %v", err)
	}
	_, _ = guard.Exec(ctx, `ROLLBACK`)
	var exists bool
	if err := guard.QueryRow(ctx, `SELECT to_regclass('sentinelflow.lifecycle_inspection_schedules_000026') IS NOT NULL`).
		Scan(&exists); err != nil || exists {
		t.Fatalf("failed upgrade left lifecycle schema: exists=%t err=%v", exists, err)
	}
}

func waitForDatabasePredicate(
	t *testing.T, ctx context.Context, connection *pgx.Conn, query string, arguments ...any,
) {
	t.Helper()
	for range 200 {
		var ready bool
		if err := connection.QueryRow(ctx, query, arguments...).Scan(&ready); err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("database-clock wait: %v", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	t.Fatal("database-clock predicate did not become true")
}

func lifecycleDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func lifecyclePGCode(err error) string {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		return databaseError.Code
	}
	return ""
}

func applyLifecycleMigrationsThrough(
	t *testing.T, ctx context.Context, connection *pgx.Conn, maximum int,
) {
	t.Helper()
	root := lifecycleRepositoryRoot(t)
	migrations, err := filepath.Glob(filepath.Join(root, "db", "migrations", "*.up.sql"))
	if err != nil || len(migrations) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(migrations)
	for _, path := range migrations {
		var version int
		if _, err := fmt.Sscanf(filepath.Base(path), "%06d_", &version); err != nil || version > maximum {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, string(contents)); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(path), err)
		}
	}
}

func applyLifecycleMigration(
	t *testing.T, ctx context.Context, connection *pgx.Conn, name string,
) {
	t.Helper()
	if _, err := connection.Exec(ctx, lifecycleMigrationContents(t, name)); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
}

func lifecycleMigrationContents(t *testing.T, name string) string {
	t.Helper()
	return lifecycleTestContents(t, "db", "migrations", name)
}

func lifecycleTestContents(t *testing.T, elements ...string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(append([]string{lifecycleRepositoryRoot(t)}, elements...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func lifecycleRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate lifecycle integration test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func waitForLifecyclePostgreSQL(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	for range 80 {
		if exec.CommandContext(ctx, "docker", "exec", container,
			"pg_isready", "-U", "postgres", "-d", "postgres").Run() == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("PostgreSQL 17 did not become ready")
}

func lifecycleDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := lifecycleDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func lifecycleDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}

func connectLifecyclePostgreSQL(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	for range 40 {
		connection, err := pgx.Connect(ctx, connectionString)
		if err == nil {
			return connection
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("connect to disposable PostgreSQL 17")
	return nil
}
