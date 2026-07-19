package hilstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgreSQL17RevocationHILStatelessRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("PostgreSQL 17 integration test disabled by -short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-revocation-hil-%d", time.Now().UnixNano())
	runIntegrationDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"-e", "POSTGRES_PASSWORD=sentinelflow-test-only", "-p", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", container).Run()
	})
	waitForIntegrationPostgreSQL(t, ctx, container)
	port := integrationDockerPort(t, ctx, container)
	connectionString := "postgresql://postgres:sentinelflow-test-only@127.0.0.1:" + port + "/postgres?sslmode=disable"
	connection := connectIntegrationPostgreSQL(t, ctx, connectionString)
	defer connection.Close(context.Background())
	applyIntegrationMigrations(t, ctx, connection)

	now := time.Now().UTC().Truncate(time.Microsecond)
	addRequest := fixtureIssueRequest(t, now, hil.OperationApprove)
	seedChallengeFixture(t, ctx, connection, addRequest, now)
	if _, err := connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal(err)
	}
	addStore, err := NewPostgreSQLStore(connection, deterministicEntropy(4096))
	if err != nil {
		t.Fatal(err)
	}
	addIssued, err := addStore.Issue(ctx, addRequest)
	if err != nil {
		t.Fatalf("issue add: %v", err)
	}
	addNonceText, err := addIssued.TakeNonce()
	if err != nil {
		t.Fatal(err)
	}
	addNonce, err := CheckDecisionNonce(addNonceText)
	if err != nil {
		t.Fatal(err)
	}
	addReason, err := hil.CheckReason(hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion,
		ReasonCode:    hil.ReasonThreatConfirmed,
		ReasonText:    "Confirmed synthetic attack pattern",
	})
	if err != nil {
		t.Fatal(err)
	}
	addLookup := DecisionLookup{
		Browser: addRequest.Browser, Challenge: addIssued.Challenge(), Nonce: addNonce,
		Artifact: addRequest.Artifact, Reason: addReason,
	}
	addCommit := fixturePrivilegedCommit(t, addLookup, addIssued.Challenge().Value().IssuedAt)
	addStored, err := addStore.Commit(ctx, addCommit)
	if err != nil {
		t.Fatalf("commit add: %v", err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}

	// Move only the lifecycle state needed by this leaf. The immutable add
	// provenance remains the coordinator-created action and validation row.
	activationStatements := []struct {
		query string
		args  []any
	}{
		{`UPDATE sentinelflow.policy_proposals
         SET state = 'queued', state_revision = state_revision + 1, updated_at = clock_timestamp()
         WHERE policy_id = $1::uuid AND version = $2 AND state = 'approved'`,
			[]any{addRequest.Artifact.PolicyID(), addRequest.Artifact.PolicyVersion()}},
		{`UPDATE sentinelflow.enforcement_actions
         SET state = 'queued', queued_at = clock_timestamp(), version = version + 1,
             updated_at = clock_timestamp()
         WHERE action_id = $1::uuid AND state = 'approved'`, []any{addStored.ActionID()}},
		{`UPDATE sentinelflow.policy_proposals
         SET state = 'active', state_revision = state_revision + 1, updated_at = clock_timestamp()
         WHERE policy_id = $1::uuid AND version = $2 AND state = 'queued'`,
			[]any{addRequest.Artifact.PolicyID(), addRequest.Artifact.PolicyVersion()}},
		{`UPDATE sentinelflow.enforcement_actions
         SET state = 'active', applied_at = clock_timestamp(),
             expected_expires_at = clock_timestamp() + interval '20 minutes',
             version = version + 1, updated_at = clock_timestamp()
         WHERE action_id = $1::uuid AND state = 'queued'`, []any{addStored.ActionID()}},
	}
	for index, statement := range activationStatements {
		if _, err = connection.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("activate action step %d: %v", index+1, err)
		}
	}
	testRevocationInspectionResultVersionFence(
		t, ctx, connection, addStored.ActionID(), addRequest.Artifact.PolicyID(),
		addRequest.Artifact.PolicyVersion(), addRequest.Artifact.TargetIPv4(),
		addRequest.Artifact.CanonicalArtifactDigest(),
	)

	revokeKey, err := CheckIdempotencyKey([]byte("revocation-stateless-roundtrip-key-0001"))
	if err != nil {
		t.Fatal(err)
	}
	revokeBrowser, err := BindValidatedBrowserRequest(addCommit.replacement, revokeKey)
	if err != nil {
		t.Fatal(err)
	}
	revokeRequest := RevocationIssueRequest{
		Browser: revokeBrowser, ActionID: addStored.ActionID(), ActionVersion: 3,
		TargetIPv4:        addRequest.Artifact.TargetIPv4(),
		OriginalAddDigest: addRequest.Artifact.CanonicalArtifactDigest(),
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal(err)
	}
	issueStore, err := NewPostgreSQLStore(connection, deterministicEntropy(4096))
	if err != nil {
		t.Fatal(err)
	}
	badTarget := revokeRequest
	badTarget.TargetIPv4 = "203.0.113.21"
	if _, err = issueStore.IssueRevocation(ctx, badTarget); !errors.Is(err, ErrConflict) {
		t.Fatalf("target mismatch: %v", err)
	}
	badDigest := revokeRequest
	badDigest.OriginalAddDigest = testDigest('7')
	if _, err = issueStore.IssueRevocation(ctx, badDigest); !errors.Is(err, ErrConflict) {
		t.Fatalf("original add mismatch: %v", err)
	}
	var leakedChallenges int
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if err = connection.QueryRow(ctx, `
SELECT count(*)::integer FROM sentinelflow.decision_challenges WHERE operation = 'revoke'`).Scan(&leakedChallenges); err != nil || leakedChallenges != 0 {
		t.Fatalf("mismatch leaked challenge count=%d err=%v", leakedChallenges, err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal(err)
	}
	revokeIssued, err := issueStore.IssueRevocation(ctx, revokeRequest)
	if err != nil {
		t.Fatalf("issue revoke: %v", err)
	}
	revokeNonceText, err := revokeIssued.TakeNonce()
	if err != nil {
		t.Fatal(err)
	}
	revokeNonce, err := CheckDecisionNonce(revokeNonceText)
	if err != nil {
		t.Fatal(err)
	}
	revokeReason, err := hil.CheckReason(hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion,
		ReasonCode:    hil.ReasonEmergencyRevoke,
		ReasonText:    "Emergency removal of the synthetic blacklist entry",
	})
	if err != nil {
		t.Fatal(err)
	}
	decisionInput := RevocationDecisionInput{
		Browser:                 revokeBrowser,
		CanonicalChallenge:      revokeIssued.Challenge().CanonicalBytes(),
		CanonicalRevokeArtifact: revokeIssued.Challenge().RevokeArtifactBytes(),
		Nonce:                   revokeNonce, Reason: revokeReason,
		PolicyID: revokeIssued.PolicyID(), PolicyVersion: revokeIssued.PolicyVersion(),
	}
	revokeLookup, err := BindRevocationLookup(decisionInput)
	if err != nil {
		t.Fatalf("stateless bind: %v", err)
	}
	mutated := decisionInput
	mutated.CanonicalRevokeArtifact = append(bytes.Clone(mutated.CanonicalRevokeArtifact), '\n')
	if _, err = BindRevocationLookup(mutated); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mutated artifact bind: %v", err)
	}

	// A fresh store instance has no issuance object or server cache.
	commitStore, err := NewPostgreSQLStore(connection, deterministicEntropy(8192))
	if err != nil {
		t.Fatal(err)
	}
	revokeCommit := fixturePrivilegedRevocationCommit(
		t, revokeLookup, revokeIssued.Challenge().Value().IssuedAt,
	)
	revoked, err := commitRevocationAgainstInspectionRace(
		t, ctx, connection, connectionString, commitStore, revokeCommit,
	)
	if err != nil {
		t.Fatalf("commit revoke from fresh store: %v", err)
	}
	if revoked.RevocationID() == "" || revoked.AuthorizationID() == "" ||
		revoked.AuthorizationDigest() == "" || revoked.OutboxJobID() == "" ||
		revoked.AuditEventID() == "" ||
		!revoked.SessionRotated() ||
		!revoked.Decision().RevokesAt(revoked.Decision().Value().DecidedAt) {
		t.Fatalf("incomplete revoke result: %v", revoked)
	}
	replayed, err := commitStore.CommitRevocation(ctx, revokeCommit)
	if err != nil || replayed.SessionRotated() ||
		replayed.Decision().Value().DecisionID != revoked.Decision().Value().DecisionID ||
		replayed.RevocationID() != revoked.RevocationID() ||
		replayed.AuthorizationID() != revoked.AuthorizationID() ||
		replayed.AuthorizationDigest() != revoked.AuthorizationDigest() ||
		replayed.OutboxJobID() != revoked.OutboxJobID() ||
		replayed.AuditEventID() != revoked.AuditEventID() {
		t.Fatalf("response-loss exact replay=%v err=%v", replayed, err)
	}
	mutationReason, err := hil.CheckReason(hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion,
		ReasonCode:    hil.ReasonOperatorRequest,
		ReasonText:    "Changed replay authority must never reuse the committed decision",
	})
	if err != nil {
		t.Fatal(err)
	}
	replayMutations := []struct {
		name   string
		mutate func(*PrivilegedRevocationCommit)
	}{
		{"reason-id", func(value *PrivilegedRevocationCommit) {
			value.material.identities[0] = "019b0000-0000-4000-8000-000000000501"
		}},
		{"decision-id", func(value *PrivilegedRevocationCommit) {
			value.material.identities[1] = "019b0000-0000-4000-8000-000000000502"
		}},
		{"authorization-id", func(value *PrivilegedRevocationCommit) {
			value.material.identities[2] = "019b0000-0000-4000-8000-000000000503"
		}},
		{"revocation-id", func(value *PrivilegedRevocationCommit) {
			value.material.identities[3] = "019b0000-0000-4000-8000-000000000504"
		}},
		{"outbox-id", func(value *PrivilegedRevocationCommit) {
			value.material.identities[4] = "019b0000-0000-4000-8000-000000000505"
		}},
		{"audit-id", func(value *PrivilegedRevocationCommit) {
			value.material.identities[5] = "019b0000-0000-4000-8000-000000000506"
		}},
		{"decided-at", func(value *PrivilegedRevocationCommit) {
			value.material.decidedAt = value.material.decidedAt.Add(time.Microsecond)
		}},
		{"valid-until", func(value *PrivilegedRevocationCommit) {
			value.material.validUntil = value.material.validUntil.Add(-time.Microsecond)
		}},
		{"authorization-jcs", func(value *PrivilegedRevocationCommit) {
			value.material.authorizationJCS = append(value.material.authorizationJCS, ' ')
		}},
		{"authorization-digest", func(value *PrivilegedRevocationCommit) { value.material.authorizationDigest = testDigest('7') }},
		{"policy-id", func(value *PrivilegedRevocationCommit) {
			value.lookup.policyID = "019b0000-0000-4000-8000-000000000507"
		}},
		{"policy-version", func(value *PrivilegedRevocationCommit) { value.lookup.policyVersion++ }},
		{"reason", func(value *PrivilegedRevocationCommit) { value.lookup.Reason = mutationReason }},
		{"replacement-token", func(value *PrivilegedRevocationCommit) { value.replacement.TokenDigest[0] ^= 1 }},
	}
	for _, mutation := range replayMutations {
		t.Run("replay-conflict-"+mutation.name, func(t *testing.T) {
			candidate := cloneRevocationCommit(revokeCommit)
			mutation.mutate(&candidate)
			if _, replayErr := commitStore.CommitRevocation(ctx, candidate); !errors.Is(replayErr, ErrConflict) {
				t.Fatalf("changed replay error=%v", replayErr)
			}
		})
	}

	// Concurrent copies of the same checked commit share the exact first DB
	// clock/UUID material. Every retry must return the same durable IDs, must
	// not rotate the session again, and must not duplicate audit evidence.
	const replayWorkers = 20
	stores := make([]*PostgreSQLStore, 0, replayWorkers)
	connections := make([]interface{ Close(context.Context) error }, 0, replayWorkers)
	for index := range replayWorkers {
		workerConnection := connectIntegrationPostgreSQL(t, ctx, connectionString)
		connections = append(connections, workerConnection)
		if _, err = workerConnection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
			t.Fatal(err)
		}
		workerStore, storeErr := NewPostgreSQLStore(workerConnection, deterministicEntropy(256+index))
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		stores = append(stores, workerStore)
	}
	defer func() {
		for _, workerConnection := range connections {
			_ = workerConnection.Close(context.Background())
		}
	}()
	type replayResult struct {
		stored StoredRevocation
		err    error
	}
	start := make(chan struct{})
	results := make(chan replayResult, replayWorkers)
	var workers sync.WaitGroup
	workers.Add(replayWorkers)
	for _, workerStore := range stores {
		go func(store *PostgreSQLStore) {
			defer workers.Done()
			<-start
			stored, commitErr := store.CommitRevocation(ctx, revokeCommit)
			results <- replayResult{stored: stored, err: commitErr}
		}(workerStore)
	}
	close(start)
	workers.Wait()
	close(results)
	for result := range results {
		if result.err != nil || result.stored.SessionRotated() ||
			result.stored.Decision().Value().DecisionID != revoked.Decision().Value().DecisionID ||
			result.stored.RevocationID() != revoked.RevocationID() ||
			result.stored.AuthorizationID() != revoked.AuthorizationID() ||
			result.stored.AuthorizationDigest() != revoked.AuthorizationDigest() ||
			result.stored.OutboxJobID() != revoked.OutboxJobID() ||
			result.stored.AuditEventID() != revoked.AuditEventID() {
			t.Fatalf("concurrent exact replay=%v err=%v", result.stored, result.err)
		}
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	var durableCounts [5]int
	if err = connection.QueryRow(ctx, `
SELECT
    (SELECT count(*)::integer FROM sentinelflow.approval_decisions WHERE operation = 'revoke'),
    (SELECT count(*)::integer FROM sentinelflow.enforcement_authorizations WHERE authorization_kind = 'revoke'),
    (SELECT count(*)::integer FROM sentinelflow.revocation_operations),
    (SELECT count(*)::integer FROM sentinelflow.outbox_jobs WHERE operation = 'revoke'),
    (SELECT count(*)::integer FROM sentinelflow.audit_events WHERE action = 'enforcement_revoke_authorized')`).Scan(
		&durableCounts[0], &durableCounts[1], &durableCounts[2], &durableCounts[3], &durableCounts[4],
	); err != nil || durableCounts != [5]int{1, 1, 1, 1, 1} {
		t.Fatalf("concurrent replay duplicated durable chain counts=%v err=%v", durableCounts, err)
	}

	// Once an exact action-version revoke exists, neither its authorized nor
	// queued state may issue a second challenge under a fresh idempotency key.
	for index, state := range []string{"authorized", "queued"} {
		if state == "queued" {
			if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.revocation_operations SET state = 'queued'
WHERE revocation_id = $1::uuid`, revoked.RevocationID()); err != nil {
				t.Fatal(err)
			}
		}
		key, keyErr := CheckIdempotencyKey([]byte(fmt.Sprintf(
			"post-authorization-revocation-issue-key-%02d", index,
		)))
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		browser, browserErr := BindValidatedBrowserRequest(revokeCommit.replacement, key)
		if browserErr != nil {
			t.Fatal(browserErr)
		}
		duplicateRequest := revokeRequest
		duplicateRequest.Browser = browser
		if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
			t.Fatal(err)
		}
		_, issueErr := issueStore.IssueRevocation(ctx, duplicateRequest)
		if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(issueErr, ErrConflict) {
			t.Fatalf("post-%s issue=%v", state, issueErr)
		}
	}
	var revokeChallengeCount int
	if err = connection.QueryRow(ctx, `
SELECT count(*)::integer FROM sentinelflow.decision_challenges WHERE operation = 'revoke'`).Scan(&revokeChallengeCount); err != nil || revokeChallengeCount != 1 {
		t.Fatalf("duplicate revoke challenge count=%d err=%v", revokeChallengeCount, err)
	}

	// Reconstruct a historical read with only persisted browser-roundtrippable
	// bytes and the Boundary-validated revoked parent projection.
	historicalRecord := cloneSession(revokeCommit.expected)
	if err = connection.QueryRow(ctx, `
SELECT revoked_at FROM sentinelflow.admin_sessions WHERE session_id = $1::uuid`,
		historicalRecord.ID.String()).Scan(&historicalRecord.RevokedAt); err != nil {
		t.Fatal(err)
	}
	historicalBrowser, err := BindHistoricalReplayBrowserRequest(historicalRecord, revokeKey)
	if err != nil {
		t.Fatal(err)
	}
	historicalInput := decisionInput
	historicalInput.Browser = historicalBrowser
	historicalLookup, err := BindRevocationLookup(historicalInput)
	if err != nil {
		t.Fatalf("historical stateless bind: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal(err)
	}
	historicalStore, err := NewPostgreSQLStore(connection, deterministicEntropy(64))
	if err != nil {
		t.Fatal(err)
	}
	historical, err := historicalStore.LookupHistoricalRevocation(ctx, historicalLookup)
	if err != nil || historical.SessionRotated() ||
		historical.Decision().Value().DecisionID != revoked.Decision().Value().DecisionID {
		t.Fatalf("historical lookup=%v err=%v", historical, err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	assertRevocationOwnerInsertFence(
		t, ctx, connection, revoked.RevocationID(), addStored.ActionID(),
	)
}

func assertRevocationOwnerInsertFence(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	revocationID, actionID string,
) {
	t.Helper()
	mutations := []struct {
		name       string
		actionSQL  string
		restoreSQL string
	}{
		{
			name:       "version-mismatch",
			actionSQL:  `UPDATE sentinelflow.enforcement_actions SET version = version + 1 WHERE action_id = $1::uuid`,
			restoreSQL: `UPDATE sentinelflow.enforcement_actions SET version = version - 1 WHERE action_id = $1::uuid`,
		},
		{
			name:       "state-mismatch",
			actionSQL:  `UPDATE sentinelflow.enforcement_actions SET state = 'revoked' WHERE action_id = $1::uuid`,
			restoreSQL: `UPDATE sentinelflow.enforcement_actions SET state = 'active' WHERE action_id = $1::uuid`,
		},
	}
	for index, mutation := range mutations {
		t.Run("owner-insert-"+mutation.name, func(t *testing.T) {
			if _, err := connection.Exec(ctx, `SET session_replication_role = replica`); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Exec(ctx, mutation.actionSQL, actionID); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Exec(ctx, `RESET session_replication_role`); err != nil {
				t.Fatal(err)
			}
			_, insertErr := connection.Exec(ctx, `
INSERT INTO sentinelflow.revocation_operations (
    revocation_id, schema_version, action_id, action_version,
    authorization_id, approval_decision_id, actor_id, reason_id,
    reason_digest, target_ipv4, original_add_digest, artifact,
    artifact_digest, state, created_at
)
SELECT
    $1::uuid, source.schema_version, source.action_id, source.action_version,
    source.authorization_id, source.approval_decision_id, source.actor_id,
    source.reason_id, source.reason_digest, source.target_ipv4,
    source.original_add_digest, source.artifact, source.artifact_digest,
    'authorized', clock_timestamp()
FROM sentinelflow.revocation_operations source
WHERE source.revocation_id = $2::uuid`,
				fmt.Sprintf("019b0000-0000-4000-8000-00000000052%d", index), revocationID,
			)
			if revocationPGCode(insertErr) != "23514" {
				t.Fatalf("owner stale insert code=%s err=%v", revocationPGCode(insertErr), insertErr)
			}
			if _, err := connection.Exec(ctx, `SET session_replication_role = replica`); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Exec(ctx, mutation.restoreSQL, actionID); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Exec(ctx, `RESET session_replication_role`); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testRevocationInspectionResultVersionFence(
	t *testing.T,
	ctx context.Context,
	connection interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	actionID, policyID string,
	policyVersion uint32,
	targetIPv4, originalAddDigest string,
) {
	t.Helper()
	const (
		scheduleID    = "019b0000-0000-4000-8000-000000000401"
		authorization = "019b0000-0000-4000-8000-000000000402"
		jobID         = "019b0000-0000-4000-8000-000000000403"
		capabilityID  = "019b0000-0000-4000-8000-000000000404"
		resultID      = "019b0000-0000-4000-8000-000000000405"
	)
	insertSyntheticInspectionSchedule(
		t, ctx, connection, scheduleID, authorization, jobID,
		"019b0000-0000-4000-8000-000000000406", actionID, 3,
	)
	if _, err := connection.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
UPDATE sentinelflow.enforcement_actions SET version = 4
WHERE action_id = $1::uuid`, actionID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `RESET session_replication_role`); err != nil {
		t.Fatal(err)
	}

	if _, err := connection.Exec(ctx, `SET ROLE sentinelflow_dispatcher`); err != nil {
		t.Fatal(err)
	}
	classifications := []struct {
		name, nftExit, readback string
		remaining               *int32
	}{
		{name: "inspect_active", nftExit: "success", readback: "active", remaining: int32Pointer(60)},
		{name: "inspect_absent", nftExit: "success", readback: "absent"},
		{name: "inspect_mismatch", nftExit: "success", readback: "mismatch"},
	}
	for index, classification := range classifications {
		resultJCS := []byte(fmt.Sprintf(`{"stale_result":%d}`, index))
		err := callSyntheticInspectionResult(
			ctx, connection,
			fmt.Sprintf("019b0000-0000-4000-8000-00000000041%d", index),
			jobID, "019b0000-0000-4000-8000-000000000420", capabilityID,
			testDigest('1'), actionID, testDigest('2'), targetIPv4,
			classification.name, classification.nftExit, classification.readback,
			classification.remaining, testDigest('3'),
			time.Date(2026, 7, 19, 2, 0, index, 0, time.UTC),
			resultJCS, digestBytes(resultJCS),
		)
		if revocationPGCode(err) != "55000" {
			t.Fatalf("fresh stale %s code=%s err=%v", classification.name, revocationPGCode(err), err)
		}
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}

	// Persist one exact v3 result/application as historical evidence, then
	// prove its exact replay is still idempotent after the action reached v4.
	startedAt := time.Date(2026, 7, 19, 2, 1, 0, 0, time.UTC)
	resultJCS := []byte(`{"result_id":"019b0000-0000-4000-8000-000000000405"}`)
	resultDigest := digestBytes(resultJCS)
	capabilityJCS := []byte(`{"capability":"historical-inspect"}`)
	capabilityDigest := digestBytes(capabilityJCS)
	if _, err := connection.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.execution_capabilities (
    capability_id, schema_version, job_id, operation, action_id, policy_id,
    policy_version, target_ipv4, artifact, artifact_digest, original_add_digest,
    evidence_snapshot_digest, validation_snapshot_digest, authorization_digest,
    actor_id, reason_digest, owned_schema_digest, capability_jcs,
    capability_digest, capability_signature, nonce_digest, issued_at,
    not_before, expires_at, consumed_at
) VALUES (
    $1::uuid, 'execution-capability-v1', $2::uuid, 'inspect', $3::uuid,
    $4::uuid, $5, $6, convert_to('{}', 'UTF8'), $7, $8, $9, $10, $11,
    'lifecycle-v1', $12, $13, $14, $15, decode(repeat('43', 64), 'hex'),
    $16, $17::timestamptz, $17::timestamptz, $17::timestamptz + interval '30 seconds',
    $17::timestamptz
)`, capabilityID, jobID, actionID, policyID, policyVersion, targetIPv4,
		testDigest('2'), originalAddDigest, testDigest('4'), testDigest('5'),
		testDigest('6'), testDigest('7'), testDigest('3'), capabilityJCS,
		capabilityDigest, testDigest('8'), startedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.execution_results (
    result_id, schema_version, capability_id, capability_digest, operation,
    action_id, artifact_digest, target_ipv4, classification, nft_exit_class,
    readback_state, element_handle, remaining_ttl_seconds, owned_schema_digest,
    started_at, completed_at, journal_sequence, error_code, result_jcs,
    result_digest, result_signature
) VALUES (
    $1::uuid, 'execution-result-v1', $2::uuid, $3, 'inspect', $4::uuid,
    $5, $6, 'inspect_absent', 'success', 'absent', NULL, NULL, $7,
    $8::timestamptz, $8::timestamptz, 1, 'none', $9, $10,
    decode(repeat('52', 64), 'hex')
)`, resultID, capabilityID, capabilityDigest, actionID, testDigest('2'),
		targetIPv4, testDigest('3'), startedAt, resultJCS, resultDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.lifecycle_result_applications_000026 (
    result_id, result_digest, action_id, operation, classification,
    resulting_state, resulting_action_version, schedule_id, processed_at
) VALUES (
    $1::uuid, $2, $3::uuid, 'inspect', 'inspect_absent',
    'failed', 3, NULL, $4::timestamptz
)`, resultID, resultDigest, actionID, startedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `RESET session_replication_role`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SET ROLE sentinelflow_dispatcher`); err != nil {
		t.Fatal(err)
	}
	if err := callSyntheticInspectionResult(
		ctx, connection, resultID, jobID,
		"019b0000-0000-4000-8000-000000000420", capabilityID,
		capabilityDigest, actionID, testDigest('2'), targetIPv4,
		"inspect_absent", "success", "absent", nil, testDigest('3'),
		startedAt, resultJCS, resultDigest,
	); err != nil {
		t.Fatalf("exact historical inspect replay: %v", err)
	}
	changedJCS := []byte(`{"result_id":"changed"}`)
	if err := callSyntheticInspectionResult(
		ctx, connection, resultID, jobID,
		"019b0000-0000-4000-8000-000000000420", capabilityID,
		capabilityDigest, actionID, testDigest('2'), targetIPv4,
		"inspect_absent", "success", "absent", nil, testDigest('3'),
		startedAt, changedJCS, digestBytes(changedJCS),
	); revocationPGCode(err) != "23505" {
		t.Fatalf("changed historical inspect replay code=%s err=%v", revocationPGCode(err), err)
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	var actionState string
	var actionVersion int
	var freshResults int
	if err := connection.QueryRow(ctx, `
SELECT action.state, action.version,
       (SELECT count(*)::integer FROM sentinelflow.execution_results
        WHERE result_id <> $2::uuid AND action_id = $1::uuid)
FROM sentinelflow.enforcement_actions action WHERE action.action_id = $1::uuid`,
		actionID, resultID).Scan(&actionState, &actionVersion, &freshResults); err != nil ||
		actionState != "active" || actionVersion != 4 || freshResults != 0 {
		t.Fatalf("stale fence mutated action=%s/%d fresh_results=%d err=%v",
			actionState, actionVersion, freshResults, err)
	}

	if _, err := connection.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	cleanupStatements := []struct {
		query string
		args  []any
	}{
		{`DELETE FROM sentinelflow.lifecycle_result_applications_000026 WHERE result_id = $1::uuid`, []any{resultID}},
		{`DELETE FROM sentinelflow.execution_results WHERE result_id = $1::uuid`, []any{resultID}},
		{`DELETE FROM sentinelflow.execution_capabilities WHERE capability_id = $1::uuid`, []any{capabilityID}},
		{`DELETE FROM sentinelflow.lifecycle_inspection_schedules_000026 WHERE schedule_id = $1::uuid`, []any{scheduleID}},
		{`UPDATE sentinelflow.enforcement_actions SET version = 3 WHERE action_id = $1::uuid`, []any{actionID}},
	}
	for _, statement := range cleanupStatements {
		if _, err := connection.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `RESET session_replication_role`); err != nil {
		t.Fatal(err)
	}
}

func commitRevocationAgainstInspectionRace(
	t *testing.T,
	ctx context.Context,
	owner *pgx.Conn,
	connectionString string,
	store *PostgreSQLStore,
	commit PrivilegedRevocationCommit,
) (StoredRevocation, error) {
	t.Helper()
	const (
		scheduleID    = "019b0000-0000-4000-8000-000000000451"
		authorization = "019b0000-0000-4000-8000-000000000452"
		jobID         = "019b0000-0000-4000-8000-000000000453"
		resultID      = "019b0000-0000-4000-8000-000000000454"
	)
	if _, err := owner.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	insertSyntheticInspectionSchedule(
		t, ctx, owner, scheduleID, authorization, jobID,
		"019b0000-0000-4000-8000-000000000455",
		commit.lookup.Challenge.Value().ResourceID,
		int(commit.lookup.Challenge.Value().ResourceVersion),
	)
	if _, err := owner.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal(err)
	}
	inspector := connectIntegrationPostgreSQL(t, ctx, connectionString)
	defer inspector.Close(context.Background())
	if _, err := inspector.Exec(ctx, `SET ROLE sentinelflow_dispatcher`); err != nil {
		t.Fatal(err)
	}
	raceCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	commitResult := make(chan replayResultForRace, 1)
	inspectResult := make(chan error, 1)
	go func() {
		<-start
		stored, err := store.CommitRevocation(raceCtx, commit)
		commitResult <- replayResultForRace{stored: stored, err: err}
	}()
	go func() {
		<-start
		resultJCS := []byte(`{"race":"inspect"}`)
		inspectResult <- callSyntheticInspectionResult(
			raceCtx, inspector, resultID, jobID,
			"019b0000-0000-4000-8000-000000000456",
			"019b0000-0000-4000-8000-000000000457", testDigest('1'),
			commit.lookup.Challenge.Value().ResourceID, testDigest('2'),
			commit.lookup.Challenge.Value().TargetIPv4,
			"inspect_absent", "success", "absent", nil, testDigest('3'),
			time.Date(2026, 7, 19, 3, 0, 0, 0, time.UTC), resultJCS, digestBytes(resultJCS),
		)
	}()
	close(start)
	committed := <-commitResult
	inspectErr := <-inspectResult
	if committed.err != nil {
		return StoredRevocation{}, committed.err
	}
	if code := revocationPGCode(inspectErr); code != "42501" && code != "55000" {
		t.Fatalf("inspect/revoke race result code=%s err=%v", code, inspectErr)
	}
	if _, err := owner.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	var scheduleState, actionState string
	var actionVersion, resultCount int
	if err := owner.QueryRow(ctx, `
SELECT schedule.state, action.state, action.version,
       (SELECT count(*)::integer FROM sentinelflow.execution_results
        WHERE result_id = $3::uuid)
FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
JOIN sentinelflow.enforcement_actions action ON action.action_id = schedule.action_id
WHERE schedule.schedule_id = $1::uuid AND action.action_id = $2::uuid`,
		scheduleID, commit.lookup.Challenge.Value().ResourceID, resultID).Scan(
		&scheduleState, &actionState, &actionVersion, &resultCount,
	); err != nil || scheduleState != "dead" || actionState != "active" ||
		actionVersion != int(commit.lookup.Challenge.Value().ResourceVersion) || resultCount != 0 {
		t.Fatalf("inspect/revoke race state schedule=%s action=%s/%d results=%d err=%v",
			scheduleState, actionState, actionVersion, resultCount, err)
	}
	if _, err := owner.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal(err)
	}
	return committed.stored, nil
}

type replayResultForRace struct {
	stored StoredRevocation
	err    error
}

func cloneRevocationCommit(value PrivilegedRevocationCommit) PrivilegedRevocationCommit {
	clone := value
	material := value.material
	clone.material = &revocationCommitMaterial{
		initialized:         material.initialized,
		decidedAt:           material.decidedAt,
		validUntil:          material.validUntil,
		identities:          append([]string(nil), material.identities...),
		decision:            material.decision,
		authorizationJCS:    bytes.Clone(material.authorizationJCS),
		authorizationDigest: material.authorizationDigest,
	}
	clone.expected = cloneSession(value.expected)
	clone.replacement = cloneSession(value.replacement)
	return clone
}

func insertSyntheticInspectionSchedule(
	t *testing.T,
	ctx context.Context,
	connection interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	},
	scheduleID, authorizationID, jobID, sourceResultID, actionID string,
	actionVersion int,
) {
	t.Helper()
	if _, err := connection.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
WITH instant AS (SELECT clock_timestamp() AS now)
INSERT INTO sentinelflow.lifecycle_inspection_schedules_000026 (
    schedule_id, authorization_id, dispatch_job_id, source_result_id,
    source_result_digest, action_id, action_version, policy_id, policy_version,
    target_ipv4, original_add_digest, original_authorization_digest,
    evidence_snapshot_digest, validation_snapshot_id,
    validation_snapshot_digest, owned_schema_digest, purpose, due_at, state,
    attempts, max_attempts, scheduler_id, lease_owner, lease_token, leased_at,
    lease_expires_at, authorization_requested_at, authorization_valid_until,
    dispatch_authorization_digest, created_at, updated_at
)
SELECT
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, action.action_id, $6,
    action.policy_id, action.policy_version, action.target_ipv4,
    action.canonical_artifact_digest, add_auth.authorization_digest,
    action.evidence_snapshot_digest, action.validation_snapshot_id,
    validation.snapshot_digest, validation.live_owned_schema_digest,
    'reconciliation', instant.now, 'dispatched', 1, 8,
    'lifecycle-v1', 'worker-test',
    '019b0000-0000-4000-8000-000000000499'::uuid,
    instant.now - interval '1 second', instant.now + interval '29 seconds',
    instant.now - interval '1 second', instant.now + interval '4 minutes',
    $7, instant.now - interval '1 second', instant.now
FROM sentinelflow.enforcement_actions action
JOIN sentinelflow.enforcement_authorizations add_auth
  ON add_auth.authorization_id = action.add_authorization_id
JOIN sentinelflow.validation_snapshots validation
  ON validation.validation_snapshot_id = action.validation_snapshot_id
CROSS JOIN instant
WHERE action.action_id = $8::uuid`,
		scheduleID, authorizationID, jobID, sourceResultID, testDigest('9'),
		actionVersion, testDigest('8'), actionID); err != nil {
		_, _ = connection.Exec(ctx, `RESET session_replication_role`)
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `RESET session_replication_role`); err != nil {
		t.Fatal(err)
	}
}

func callSyntheticInspectionResult(
	ctx context.Context,
	connection interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	},
	resultID, jobID, leaseToken, capabilityID, capabilityDigest, actionID,
	artifactDigest, targetIPv4, classification, nftExit, readback string,
	remaining *int32,
	ownedSchemaDigest string,
	startedAt time.Time,
	resultJCS []byte,
	resultDigest string,
) error {
	_, err := connection.Exec(ctx, `
SELECT sentinelflow.record_execution_result(
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'inspect', $6::uuid,
    $7, $8, $9, $10, $11, NULL::bigint, $12::integer, $13,
    $14::timestamptz, $14::timestamptz, 1::bigint, 'none', $15, $16,
    decode(repeat('52', 64), 'hex')
)`, resultID, jobID, leaseToken, capabilityID, capabilityDigest, actionID,
		artifactDigest, targetIPv4, classification, nftExit, readback, remaining,
		ownedSchemaDigest, startedAt, resultJCS, resultDigest)
	return err
}

func int32Pointer(value int32) *int32 { return &value }

func fixturePrivilegedRevocationCommit(
	t *testing.T,
	lookup RevocationLookup,
	rotationAt time.Time,
) PrivilegedRevocationCommit {
	t.Helper()
	expected := cloneSession(lookup.Browser.session)
	rotationAt = rotationAt.UTC().Truncate(time.Microsecond)
	revoked := cloneSession(expected)
	revoked.LastSeenAt = rotationAt
	revokedAt := rotationAt
	revoked.RevokedAt = &revokedAt
	replacement := cloneSession(expected)
	replacement.ID[15] ^= 0x36
	replacement.TokenDigest[0] ^= 0x36
	replacement.CSRFDigest[0] ^= 0x63
	replacement.CreatedAt = rotationAt
	replacement.LastSeenAt = rotationAt
	replacement.ExpiresAt = rotationAt.Add(adminauth.SessionAbsoluteLifetime)
	replacement.RevokedAt = nil
	parent := expected.ID
	replacement.RotationParentID = &parent
	commit, err := BindPrivilegedRevocationCommit(
		lookup, expected,
		adminauth.SessionRotation{
			Revoked: revoked,
			Issued:  adminauth.IssuedSession{Record: replacement},
		},
	)
	if err != nil {
		t.Fatalf("bind privileged revoke commit: %v", err)
	}
	return commit
}
