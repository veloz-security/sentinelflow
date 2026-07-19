//go:build integration

package lifecyclestore

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleruntime"
	"github.com/jackc/pgx/v5"
)

type persistedInspect struct {
	scheduleID, authorizationID, dispatchJobID string
	purpose                                    string
	artifact, authorizationJCS                 []byte
	artifactDigest, authorizationDigest        string
}

func TestLifecycleStoreAllowsRepeatedReadOnlyInspectArtifact(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 lifecycle coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-lifecycle-repeat-%d", time.Now().UnixNano())
	lifecycleDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", lifecyclePostgres17)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForLifecyclePostgreSQL(t, ctx, container)
	port := lifecycleDockerPort(t, ctx, container)
	owner := connectLifecyclePostgreSQL(t, ctx, fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	))
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	applyLifecycleMigrationsThrough(t, ctx, owner, 31)
	seedLifecycleFixture(t, ctx, owner)
	waitForDatabasePredicate(t, ctx, owner, `
SELECT clock_timestamp() >= approved_at
FROM sentinelflow.enforcement_actions
WHERE action_id = $1::uuid`, lifecycleActionID)

	addLease := "019f0000-0000-4000-8000-000000000201"
	if !claimDispatchJob(t, ctx, owner, lifecycleAddJobID, addLease) {
		t.Fatal("approved add job was not claimed")
	}
	addCapability := recordCapability(t, ctx, owner,
		"019f0000-0000-7000-8000-000000000202", lifecycleAddJobID, addLease,
		loadDispatchFixture(t, ctx, owner, lifecycleAddJobID))
	remaining := int32(300)
	addResult := resultRecord{
		id:             "019f0000-0000-7000-8000-000000000203",
		classification: "applied", nftExitClass: "success", readbackState: "active",
		remainingTTL: &remaining, errorCode: "none",
	}
	recordResult(t, ctx, owner, addCapability, &addResult)

	runtimeStore := mustLifecycleStore(t, owner, "repeat-inspect-worker")
	runtimeWorker, err := lifecycleruntime.New(runtimeStore,
		lifecycleruntime.DefaultConfig("lifecycle-v1"), lifecycleruntime.Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	first := authorizeDueInspect(t, ctx, owner, runtimeWorker, addResult.id)
	firstLease := "019f0000-0000-4000-8000-000000000204"
	if !claimDispatchJob(t, ctx, owner, first.dispatchJobID, firstLease) {
		t.Fatal("first read-only inspection job was not claimed")
	}
	firstCapability := recordCapability(t, ctx, owner,
		"019f0000-0000-7000-8000-000000000205", first.dispatchJobID, firstLease,
		loadDispatchFixture(t, ctx, owner, first.dispatchJobID))
	inspectRemaining := int32(240)
	firstResult := resultRecord{
		id:             "019f0000-0000-7000-8000-000000000206",
		classification: "inspect_active", nftExitClass: "success", readbackState: "active",
		remainingTTL: &inspectRemaining, errorCode: "none",
	}
	recordResult(t, ctx, owner, firstCapability, &firstResult)

	var stateBefore string
	var versionBefore int32
	var expiryBefore time.Time
	if err := owner.QueryRow(ctx, `
SELECT state, version, expected_expires_at
FROM sentinelflow.enforcement_actions WHERE action_id=$1::uuid`, lifecycleActionID).
		Scan(&stateBefore, &versionBefore, &expiryBefore); err != nil {
		t.Fatal(err)
	}
	second := authorizeDueInspect(t, ctx, owner, runtimeWorker, firstResult.id)
	if !bytes.Equal(first.artifact, second.artifact) ||
		first.artifactDigest != second.artifactDigest || first.purpose != second.purpose {
		t.Fatalf("same-action inspect content drifted: first=%+v second=%+v", first, second)
	}
	if first.scheduleID == second.scheduleID || first.authorizationID == second.authorizationID ||
		first.dispatchJobID == second.dispatchJobID ||
		bytes.Equal(first.authorizationJCS, second.authorizationJCS) ||
		first.authorizationDigest == second.authorizationDigest {
		t.Fatalf("inspection identities were reused: first=%+v second=%+v", first, second)
	}

	var stateAfter string
	var versionAfter int32
	var expiryAfter time.Time
	if err := owner.QueryRow(ctx, `
SELECT state, version, expected_expires_at
FROM sentinelflow.enforcement_actions WHERE action_id=$1::uuid`, lifecycleActionID).
		Scan(&stateAfter, &versionAfter, &expiryAfter); err != nil {
		t.Fatal(err)
	}
	if stateAfter != stateBefore || versionAfter != versionBefore || !expiryAfter.Equal(expiryBefore) {
		t.Fatalf("read-only authorization mutated action: before=%s/%d/%s after=%s/%d/%s",
			stateBefore, versionBefore, expiryBefore, stateAfter, versionAfter, expiryAfter)
	}

	secondLease := "019f0000-0000-4000-8000-000000000207"
	if !claimDispatchJob(t, ctx, owner, second.dispatchJobID, secondLease) {
		t.Fatal("second read-only inspection job was not claimed")
	}
	secondOperation := loadDispatchFixture(t, ctx, owner, second.dispatchJobID)
	forgedMutation := secondOperation
	forgedMutation.operation = "add"
	forgedCapability := capabilityRecord{
		id:         "019f0000-0000-7000-8000-000000000208",
		jobID:      second.dispatchJobID,
		leaseToken: secondLease,
		operation:  forgedMutation,
	}
	var now time.Time
	if err := owner.QueryRow(ctx, `SELECT date_trunc('milliseconds',clock_timestamp())`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	forgedCapability.jcs = []byte(`{"capability_id":"019f0000-0000-7000-8000-000000000208"}`)
	forgedCapability.digest = lifecycleDigest(forgedCapability.jcs)
	forgedCapability.signature = bytes.Repeat([]byte{0x41}, 64)
	forgedCapability.issuedAt = now
	forgedCapability.notBefore = now
	forgedCapability.expiresAt = now.Add(30 * time.Second)
	if err := callRecordCapability(ctx, owner, forgedCapability); lifecyclePGCode(err) != "42501" {
		t.Fatalf("inspect authority was usable as mutation authority: %v", err)
	}
	recordCapability(t, ctx, owner,
		"019f0000-0000-7000-8000-000000000209", second.dispatchJobID, secondLease,
		secondOperation)

	var inspectRows, distinctSchedules, distinctAuthorizations, distinctJobs int
	var mutationAuthorizations int
	if err := owner.QueryRow(ctx, `
SELECT count(*)::integer,
       count(DISTINCT artifact.schedule_id)::integer,
       count(DISTINCT artifact.authorization_id)::integer,
       count(DISTINCT artifact.dispatch_job_id)::integer,
       count(*) FILTER (WHERE operation.enforcement_authorization_id IS NOT NULL)::integer
FROM sentinelflow.lifecycle_inspection_artifacts_000026 artifact
JOIN sentinelflow.dispatch_operations operation
  ON operation.job_id = artifact.dispatch_job_id
WHERE artifact.schedule_id = ANY($1::uuid[])`,
		[]string{first.scheduleID, second.scheduleID}).Scan(
		&inspectRows, &distinctSchedules, &distinctAuthorizations, &distinctJobs,
		&mutationAuthorizations,
	); err != nil || inspectRows != 2 || distinctSchedules != 2 ||
		distinctAuthorizations != 2 || distinctJobs != 2 || mutationAuthorizations != 0 {
		t.Fatalf("read-only identity rows=%d schedules=%d authorizations=%d jobs=%d mutation_auth=%d err=%v",
			inspectRows, distinctSchedules, distinctAuthorizations, distinctJobs,
			mutationAuthorizations, err)
	}
}

func authorizeDueInspect(
	t *testing.T,
	ctx context.Context,
	owner *pgx.Conn,
	runtimeWorker *lifecycleruntime.Runtime,
	scheduleID string,
) persistedInspect {
	t.Helper()
	if _, err := owner.Exec(ctx, `
UPDATE sentinelflow.lifecycle_inspection_schedules_000026
SET due_at=clock_timestamp(), updated_at=clock_timestamp()
WHERE schedule_id=$1::uuid`, scheduleID); err != nil {
		t.Fatal(err)
	}
	processed, err := runtimeWorker.ProcessNext(ctx)
	if err != nil || processed.Outcome() != lifecycleruntime.OutcomeCommitted {
		t.Fatalf("authorize schedule=%s outcome=%s err=%v", scheduleID, processed.Outcome(), err)
	}
	var value persistedInspect
	if err := owner.QueryRow(ctx, `
SELECT schedule.schedule_id::text, artifact.authorization_id::text,
       artifact.dispatch_job_id::text, schedule.purpose, artifact.inspect_artifact,
       artifact.inspect_artifact_digest::text, artifact.authorization_jcs,
       artifact.authorization_digest::text
FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
JOIN sentinelflow.lifecycle_inspection_artifacts_000026 artifact USING (schedule_id)
WHERE schedule.schedule_id=$1::uuid`, scheduleID).Scan(
		&value.scheduleID, &value.authorizationID, &value.dispatchJobID, &value.purpose,
		&value.artifact, &value.artifactDigest, &value.authorizationJCS,
		&value.authorizationDigest,
	); err != nil {
		t.Fatal(err)
	}
	return value
}
