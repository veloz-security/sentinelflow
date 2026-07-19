package hilstore

import (
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

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/adminstore"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgreSQL17ChallengeIssuanceAndRoleBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("PostgreSQL 17 integration test disabled by -short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-hilstore-%d", time.Now().UnixNano())
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
	request := fixtureIssueRequest(t, now, hil.OperationApprove)
	seedChallengeFixture(t, ctx, connection, request, now)

	if _, err := connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set API role")
	}
	store, err := NewPostgreSQLStore(connection, deterministicEntropy(4096))
	if err != nil {
		t.Fatal(err)
	}
	// Evidence arriving before challenge issuance is a typed SF005 fence. The
	// failed SECURITY DEFINER statement cannot leave a challenge behind, and an
	// administrator operation cannot override it.
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role for pre-issue stale fixture")
	}
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.incidents SET evidence_version = 2
WHERE incident_id = '019b0000-0000-4000-8000-000000000101'::uuid`); err != nil {
		t.Fatalf("advance evidence before challenge: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("restore API role for stale issue")
	}
	if _, err = store.Issue(ctx, request); !errors.Is(err, ErrValidationStale) {
		t.Fatalf("stale pre-issue evidence err=%v", err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role after stale issue")
	}
	var staleChallengeCount int
	if err = connection.QueryRow(ctx,
		`SELECT count(*)::integer FROM sentinelflow.decision_challenges`).Scan(&staleChallengeCount); err != nil || staleChallengeCount != 0 {
		t.Fatalf("stale issue leaked challenge count=%d err=%v", staleChallengeCount, err)
	}
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.incidents SET evidence_version = 1
WHERE incident_id = '019b0000-0000-4000-8000-000000000101'::uuid`); err != nil {
		t.Fatalf("restore current fixture evidence: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("restore API role after stale fixture")
	}
	issued, err := store.Issue(ctx, request)
	if err != nil {
		t.Fatalf("API-role challenge issuance: %v", err)
	}
	nonce, err := issued.TakeNonce()
	if err != nil {
		t.Fatal(err)
	}
	checkedNonce, err := CheckDecisionNonce(nonce)
	if err != nil || checkedNonce.digest != issued.Challenge().Value().NonceDigest {
		t.Fatalf("persisted nonce binding: %v", err)
	}
	if _, err = store.Issue(ctx, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate challenge idempotency err=%v", err)
	}

	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role")
	}
	var (
		storedNonceDigest string
		storedIDDigest    string
		challengeCount    int
	)
	if err = connection.QueryRow(ctx, `
SELECT nonce_digest::text, idempotency_key_digest::text
FROM sentinelflow.decision_challenges
WHERE challenge_id = $1::uuid`, issued.Challenge().Value().ChallengeID).Scan(
		&storedNonceDigest, &storedIDDigest,
	); err != nil {
		t.Fatal("load persisted challenge projection")
	}
	if storedNonceDigest != checkedNonce.digest || storedIDDigest != request.Browser.idempotency.digest {
		t.Fatal("database did not persist the exact digest-only bindings")
	}

	// A stale authenticated_at receives the typed step-up result without
	// inserting a challenge.
	staleSession := fixtureSession(now)
	staleSession.ID[15] ^= 0x40
	staleSession.TokenDigest[0] ^= 0x40
	staleSession.CSRFDigest[0] ^= 0x40
	staleSession.AuthenticatedAt = now.Add(-16 * time.Minute)
	staleSession.CreatedAt = staleSession.AuthenticatedAt
	staleSession.LastSeenAt = now
	staleSession.ExpiresAt = staleSession.CreatedAt.Add(adminauth.SessionAbsoluteLifetime)
	if _, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.admin_sessions (
    session_id, actor_id, token_digest, csrf_digest, authenticated_at,
    created_at, last_seen_at, expires_at
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)`,
		staleSession.ID.String(), staleSession.ActorID, staleSession.TokenDigest.String(),
		staleSession.CSRFDigest.String(), staleSession.AuthenticatedAt, staleSession.CreatedAt,
		staleSession.LastSeenAt, staleSession.ExpiresAt,
	); err != nil {
		t.Fatalf("seed stale-auth session: %v", err)
	}
	staleKey, _ := CheckIdempotencyKey([]byte("fedcba9876543210-stale-step-up-key"))
	staleBrowser, err := BindValidatedBrowserRequest(staleSession, staleKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("restore API role")
	}
	_, err = store.Issue(ctx, IssueRequest{Operation: hil.OperationApprove, Browser: staleBrowser, Artifact: request.Artifact})
	if !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("stale authenticated_at err=%v", err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role after stale check")
	}

	// Non-API units cannot insert HIL challenges.
	workerKey, _ := CheckIdempotencyKey([]byte("abcdef0123456789-worker-negative-key"))
	workerBrowser, _ := BindValidatedBrowserRequest(request.Browser.session, workerKey)
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_worker`); err != nil {
		t.Fatal("set worker role")
	}
	_, err = store.Issue(ctx, IssueRequest{Operation: hil.OperationApprove, Browser: workerBrowser, Artifact: request.Artifact})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("worker challenge write err=%v", err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset worker role")
	}
	if err = connection.QueryRow(ctx, `SELECT count(*)::integer FROM sentinelflow.decision_challenges`).Scan(&challengeCount); err != nil {
		t.Fatal("count challenges")
	}
	if challengeCount != 1 {
		t.Fatalf("unexpected challenge count %d", challengeCount)
	}

	// The final decision is committed only through the narrow coordinator. It
	// atomically creates the exact approval, authorization, action, one outbox
	// operation, and audit record. A logical retry returns those original IDs.
	reason, err := hil.CheckReason(hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion,
		ReasonCode:    hil.ReasonThreatConfirmed,
		ReasonText:    "Confirmed synthetic attack pattern",
	})
	if err != nil {
		t.Fatal(err)
	}
	lookup := DecisionLookup{
		Browser: request.Browser, Challenge: issued.Challenge(), Nonce: checkedNonce,
		Artifact: request.Artifact, Reason: reason,
	}
	commitInput := fixturePrivilegedCommit(t, lookup, issued.Challenge().Value().IssuedAt)
	secondConnection := connectIntegrationPostgreSQL(t, ctx, connectionString)
	defer secondConnection.Close(context.Background())
	secondEntropy := deterministicEntropy(4096)
	_, _ = secondEntropy.ReadByte()
	secondStore, err := NewPostgreSQLStore(secondConnection, secondEntropy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set API role for coordinator")
	}
	if _, err = secondConnection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set second API role for coordinator")
	}
	type commitResult struct {
		stored StoredDecision
		err    error
	}
	commitResults := make(chan commitResult, 2)
	startCommit := make(chan struct{})
	for _, concurrentStore := range []*PostgreSQLStore{store, secondStore} {
		go func(current *PostgreSQLStore) {
			<-startCommit
			stored, commitErr := current.Commit(ctx, commitInput)
			commitResults <- commitResult{stored: stored, err: commitErr}
		}(concurrentStore)
	}
	close(startCommit)
	first := <-commitResults
	second := <-commitResults
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent coordinated approvals: first=%v second=%v", first.err, second.err)
	}
	stored := first.stored
	replayed := second.stored
	if stored.Decision().Value().Decision != hil.DecisionApproved || stored.ActionID() == "" ||
		stored.AuthorizationDigest() == "" || stored.OutboxJobID() == "" {
		t.Fatal("coordinator returned an incomplete approval projection")
	}
	if replayed.Decision().Value().DecisionID != stored.Decision().Value().DecisionID ||
		replayed.ActionID() != stored.ActionID() || replayed.OutboxJobID() != stored.OutboxJobID() {
		t.Fatalf("concurrent exact-idempotent replay diverged: first=%v second=%v", stored, replayed)
	}
	if stored.SessionRotated() == replayed.SessionRotated() {
		t.Fatalf("concurrent commit must rotate exactly once: first=%t second=%t",
			stored.SessionRotated(), replayed.SessionRotated())
	}

	conflictingSessionLookup := lookup
	conflictingSessionLookup.Browser.session.CSRFDigest[0] ^= 0x40
	conflictingSessionCommit := fixturePrivilegedCommit(
		t, conflictingSessionLookup, issued.Challenge().Value().IssuedAt,
	)
	if _, commitErr := store.Commit(ctx, conflictingSessionCommit); !errors.Is(commitErr, ErrConflict) {
		t.Fatalf("conflicting CSRF-bound logical retry err=%v", commitErr)
	}

	// Reusing the idempotency binding with changed authority-bearing input must
	// fail without leaving a partial reason, decision, action, job, or audit row.
	conflictingReason, reasonErr := hil.CheckReason(hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion,
		ReasonCode:    hil.ReasonThreatConfirmed,
		ReasonText:    "Conflicting synthetic operator reason",
	})
	if reasonErr != nil {
		t.Fatal(reasonErr)
	}
	conflictingLookup := lookup
	conflictingLookup.Reason = conflictingReason
	conflictingCommit := fixturePrivilegedCommit(t, conflictingLookup, issued.Challenge().Value().IssuedAt)
	if _, commitErr := store.Commit(ctx, conflictingCommit); !errors.Is(commitErr, ErrConflict) {
		t.Fatalf("conflicting logical retry err=%v", commitErr)
	}
	unrelatedLookup := lookup
	unrelatedLookup.Browser.session.ID[15] ^= 0x33
	unrelatedCommit := fixturePrivilegedCommit(t, unrelatedLookup, issued.Challenge().Value().IssuedAt)
	if _, commitErr := store.Commit(ctx, unrelatedCommit); commitErr == nil {
		t.Fatalf("unrelated old-session retry err=%v", commitErr)
	}
	conflictingReplacement := commitInput
	conflictingReplacement.replacement.ID[15] ^= 0x22
	conflictingReplacement.replacement.TokenDigest[1] ^= 0x22
	conflictingReplacement.replacement.CSRFDigest[1] ^= 0x44
	if !validPrivilegedDecisionCommit(conflictingReplacement) {
		t.Fatal("conflicting replacement fixture is not a valid checked commit")
	}
	if _, commitErr := store.Commit(ctx, conflictingReplacement); commitErr == nil {
		t.Fatalf("conflicting replacement replay err=%v", commitErr)
	}
	if _, err = secondConnection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset second role after coordinator")
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role after coordinator")
	}
	var reasonCount, decisionCount, actionCount, outboxCount, auditCount int
	if err = connection.QueryRow(ctx, `
SELECT
	(SELECT count(*)::integer FROM sentinelflow.hil_reasons),
	(SELECT count(*)::integer FROM sentinelflow.approval_decisions),
    (SELECT count(*)::integer FROM sentinelflow.enforcement_actions
      WHERE policy_id = $1::uuid AND policy_version = $2),
    (SELECT count(*)::integer FROM sentinelflow.outbox_jobs
      WHERE aggregate_id = $3::uuid AND kind = 'dispatch_add'),
    (SELECT count(*)::integer FROM sentinelflow.audit_events
      WHERE object_id = $1::uuid AND action = 'policy_approved')`,
		request.Artifact.PolicyID(), request.Artifact.PolicyVersion(), stored.ActionID(),
	).Scan(&reasonCount, &decisionCount, &actionCount, &outboxCount, &auditCount); err != nil {
		t.Fatal("load atomic coordinator evidence")
	}
	if reasonCount != 1 || decisionCount != 1 || actionCount != 1 || outboxCount != 1 || auditCount != 1 {
		t.Fatalf("atomic evidence reason=%d decision=%d action=%d outbox=%d audit=%d",
			reasonCount, decisionCount, actionCount, outboxCount, auditCount)
	}
	var oldRevokedAt, oldLastSeenAt, replacementCreatedAt, replacementLastSeenAt time.Time
	var replacementActor, replacementToken, replacementCSRF, replacementParent string
	var childCount int
	if err = connection.QueryRow(ctx, `
SELECT old.revoked_at, old.last_seen_at,
       replacement.actor_id::text, replacement.token_digest::text,
       replacement.csrf_digest::text, replacement.created_at,
       replacement.last_seen_at, replacement.rotation_parent_id::text,
       (SELECT count(*)::integer FROM sentinelflow.admin_sessions child
         WHERE child.rotation_parent_id = old.session_id)
FROM sentinelflow.admin_sessions old
JOIN sentinelflow.admin_sessions replacement
  ON replacement.session_id = $2::uuid
WHERE old.session_id = $1::uuid`,
		commitInput.expected.ID.String(), commitInput.replacement.ID.String(),
	).Scan(&oldRevokedAt, &oldLastSeenAt, &replacementActor, &replacementToken,
		&replacementCSRF, &replacementCreatedAt, &replacementLastSeenAt,
		&replacementParent, &childCount); err != nil {
		t.Fatalf("load exact session rotation: %v", err)
	}
	if oldRevokedAt.Before(commitInput.rotationAt) ||
		!oldLastSeenAt.Equal(commitInput.expected.LastSeenAt) ||
		replacementActor != commitInput.replacement.ActorID ||
		replacementToken != commitInput.replacement.TokenDigest.String() ||
		replacementCSRF != commitInput.replacement.CSRFDigest.String() ||
		!replacementCreatedAt.Equal(commitInput.rotationAt) ||
		!replacementLastSeenAt.Equal(commitInput.rotationAt) ||
		replacementParent != commitInput.expected.ID.String() || childCount != 1 {
		t.Fatalf("session rotation drift: revoked=%s created=%s children=%d",
			oldRevokedAt, replacementCreatedAt, childCount)
	}

	// The API retains no direct policy-state/action mutation authority; only the
	// coordinator above can perform the exact transition.
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set API role for policy privilege negative")
	}
	historical, historicalErr := store.LookupHistoricalDecision(ctx, lookup)
	if historicalErr != nil || historical.SessionRotated() ||
		historical.Decision().Value().DecisionID != stored.Decision().Value().DecisionID {
		t.Fatalf("post-revocation historical lookup: stored=%v err=%v", historical, historicalErr)
	}
	_, err = connection.Exec(ctx, `
UPDATE sentinelflow.policy_proposals
SET state = 'approved', state_revision = state_revision + 1,
    updated_at = clock_timestamp()
WHERE policy_id = $1::uuid AND version = $2`, request.Artifact.PolicyID(), request.Artifact.PolicyVersion())
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "42501" {
		t.Fatalf("API policy UPDATE should be privilege-denied, err=%v", err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("final reset role")
	}

	// HIL may win before a later evidence mutation. The approval remains
	// immutable history, but an add claimed before that mutation cannot mint a
	// capability afterward, and the stale job is no longer eligible to reclaim.
	const dispatchLeaseToken = "019b0000-0000-4000-8000-000000000190"
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_dispatcher`); err != nil {
		t.Fatal("set dispatcher role for current claim")
	}
	var claimed bool
	if err = connection.QueryRow(ctx, `SELECT sentinelflow.claim_dispatch_job(
        $1::uuid, $2::uuid, 'hil-stale-test', clock_timestamp() + interval '30 seconds')`,
		stored.OutboxJobID(), dispatchLeaseToken,
	).Scan(&claimed); err != nil || !claimed {
		t.Fatalf("claim current approved add claimed=%t err=%v", claimed, err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset dispatcher before evidence advance")
	}
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.incidents SET evidence_version = 2
WHERE incident_id = '019b0000-0000-4000-8000-000000000101'::uuid`); err != nil {
		t.Fatalf("advance evidence after HIL: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_dispatcher`); err != nil {
		t.Fatal("set dispatcher role for stale capability")
	}
	_, err = connection.Exec(ctx, `
SELECT sentinelflow.record_execution_capability(
    '019b0000-0000-4000-8000-000000000191'::uuid, $1::uuid, $2::uuid,
    'add', $3::uuid, $4::uuid, $5, $6, $7::bytea, $8,
    NULL::sentinelflow.sha256_digest, $9, $10, $11, $12, $13, $14,
	    convert_to('{}', 'UTF8'),
	    'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    decode(repeat('00', 64), 'hex'),
    'sha256:2929292929292929292929292929292929292929292929292929292929292929',
    clock_timestamp(), clock_timestamp(), clock_timestamp() + interval '30 seconds'
)`, stored.OutboxJobID(), dispatchLeaseToken, stored.ActionID(),
		request.Artifact.PolicyID(), request.Artifact.PolicyVersion(),
		request.Artifact.TargetIPv4(), request.Artifact.CanonicalBytes(),
		request.Artifact.CanonicalArtifactDigest(), request.Artifact.EvidenceSnapshotDigest(),
		request.Artifact.ValidationSnapshotDigest(), stored.AuthorizationDigest(),
		request.Browser.session.ActorID, reason.Digest(), nftvalidate.PinnedLiveSchemaDigest)
	var staleCapabilityError *pgconn.PgError
	if !errors.As(err, &staleCapabilityError) || staleCapabilityError.Code != "42501" {
		t.Fatalf("stale capability persistence err=%v", err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset dispatcher after stale capability")
	}
	var capabilityCount, eligibleCount int
	if err = connection.QueryRow(ctx, `
SELECT (SELECT count(*)::integer FROM sentinelflow.execution_capabilities
         WHERE job_id = $1::uuid),
       (SELECT count(*)::integer FROM sentinelflow.dispatcher_approved_outbox
         WHERE job_id = $1::uuid)`, stored.OutboxJobID()).Scan(
		&capabilityCount, &eligibleCount,
	); err != nil || capabilityCount != 0 || eligibleCount != 0 {
		t.Fatalf("stale dispatch authority capability=%d eligible=%d err=%v",
			capabilityCount, eligibleCount, err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set API role for stale historical replay")
	}
	historicalReplay, replayErr := store.Commit(ctx, commitInput)
	if replayErr != nil || historicalReplay.SessionRotated() ||
		historicalReplay.Decision().Value().DecisionID != stored.Decision().Value().DecisionID {
		t.Fatalf("stale historical replay=%v err=%v", historicalReplay, replayErr)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset API after historical replay")
	}
}

func TestPostgreSQL17RejectCoordinatorAtomicShape(t *testing.T) {
	if testing.Short() {
		t.Skip("PostgreSQL 17 integration test disabled by -short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-hilstore-reject-%d", time.Now().UnixNano())
	runIntegrationDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"-e", "POSTGRES_PASSWORD=sentinelflow-test-only", "-p", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", container).Run()
	})
	waitForIntegrationPostgreSQL(t, ctx, container)
	port := integrationDockerPort(t, ctx, container)
	connection := connectIntegrationPostgreSQL(t, ctx,
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:"+port+"/postgres?sslmode=disable")
	defer connection.Close(context.Background())
	applyIntegrationMigrations(t, ctx, connection)

	now := time.Now().UTC().Truncate(time.Microsecond)
	request := fixtureIssueRequest(t, now, hil.OperationReject)
	seedChallengeFixture(t, ctx, connection, request, now)
	if _, err := connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set API role")
	}
	store, err := NewPostgreSQLStore(connection, deterministicEntropy(4096))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Issue(ctx, request)
	if err != nil {
		t.Fatalf("issue reject challenge: %v", err)
	}
	nonce, err := issued.TakeNonce()
	if err != nil {
		t.Fatal(err)
	}
	checkedNonce, err := CheckDecisionNonce(nonce)
	if err != nil {
		t.Fatal(err)
	}
	reason, err := hil.CheckReason(hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion,
		ReasonCode:    hil.ReasonFalsePositive,
		ReasonText:    "Synthetic evidence does not justify enforcement",
	})
	if err != nil {
		t.Fatal(err)
	}
	lookup := DecisionLookup{
		Browser: request.Browser, Challenge: issued.Challenge(), Nonce: checkedNonce,
		Artifact: request.Artifact, Reason: reason,
	}
	commitInput := fixturePrivilegedCommit(t, lookup, issued.Challenge().Value().IssuedAt)
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role before post-issue stale fixture")
	}
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.incidents SET evidence_version = 2
WHERE incident_id = '019b0000-0000-4000-8000-000000000101'::uuid`); err != nil {
		t.Fatalf("advance evidence after challenge: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set API role for stale decision")
	}
	if _, err = store.Commit(ctx, commitInput); !errors.Is(err, ErrValidationStale) {
		t.Fatalf("post-issue stale commit err=%v", err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role after stale decision")
	}
	var staleDecisionCount int
	var staleChallengeConsumed bool
	var staleSessionRevoked *time.Time
	if err = connection.QueryRow(ctx, `
SELECT (SELECT count(*)::integer FROM sentinelflow.approval_decisions),
       challenge.consumed_at IS NOT NULL, session.revoked_at
FROM sentinelflow.decision_challenges challenge
JOIN sentinelflow.admin_sessions session USING (session_id)
WHERE challenge.challenge_id = $1::uuid`,
		issued.Challenge().Value().ChallengeID,
	).Scan(&staleDecisionCount, &staleChallengeConsumed, &staleSessionRevoked); err != nil {
		t.Fatalf("load stale decision rollback: %v", err)
	}
	if staleDecisionCount != 0 || staleChallengeConsumed || staleSessionRevoked != nil {
		t.Fatalf("stale decision leaked state decisions=%d consumed=%t revoked=%v",
			staleDecisionCount, staleChallengeConsumed, staleSessionRevoked)
	}
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.incidents SET evidence_version = 1
WHERE incident_id = '019b0000-0000-4000-8000-000000000101'::uuid`); err != nil {
		t.Fatalf("restore evidence after stale decision: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("restore API role after stale decision")
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role before stale-session fixture")
	}
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.admin_sessions
SET last_seen_at = last_seen_at + interval '1 microsecond'
WHERE session_id = $1::uuid`, commitInput.expected.ID.String()); err != nil {
		t.Fatalf("seed stale expected session: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set API role for stale expected session")
	}
	if _, err = store.Commit(ctx, commitInput); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale expected session err=%v", err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role after stale expected session")
	}
	var staleSessionDecisionCount int
	var staleOldRevoked *time.Time
	if err = connection.QueryRow(ctx, `
SELECT (SELECT count(*)::integer FROM sentinelflow.approval_decisions), revoked_at
FROM sentinelflow.admin_sessions WHERE session_id = $1::uuid`,
		commitInput.expected.ID.String(),
	).Scan(&staleSessionDecisionCount, &staleOldRevoked); err != nil {
		t.Fatalf("load stale-session rollback: %v", err)
	}
	if staleSessionDecisionCount != 0 || staleOldRevoked != nil {
		t.Fatalf("stale session leaked decision/revoke: decisions=%d revoked=%v",
			staleSessionDecisionCount, staleOldRevoked)
	}
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.admin_sessions SET last_seen_at = $2
WHERE session_id = $1::uuid`, commitInput.expected.ID.String(),
		commitInput.expected.LastSeenAt); err != nil {
		t.Fatalf("restore exact expected session: %v", err)
	}
	if _, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.admin_sessions (
    session_id, actor_id, token_digest, csrf_digest, authenticated_at,
    created_at, last_seen_at, expires_at, rotation_parent_id
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9::uuid)`,
		commitInput.replacement.ID.String(), commitInput.replacement.ActorID,
		commitInput.replacement.TokenDigest.String(), commitInput.replacement.CSRFDigest.String(),
		commitInput.replacement.AuthenticatedAt, commitInput.replacement.CreatedAt,
		commitInput.replacement.LastSeenAt, commitInput.replacement.ExpiresAt,
		commitInput.expected.ID.String(),
	); err != nil {
		t.Fatalf("seed replacement conflict: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set API role for replacement conflict")
	}
	if _, err = store.Commit(ctx, commitInput); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement conflict err=%v", err)
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role after replacement conflict")
	}
	var rollbackReasonCount, rollbackDecisionCount, rollbackAuthorizationCount int
	var rollbackActionCount, rollbackOutboxCount, rollbackAuditCount int
	var rollbackOldRevoked *time.Time
	if err = connection.QueryRow(ctx, `
SELECT (SELECT count(*)::integer FROM sentinelflow.hil_reasons),
       (SELECT count(*)::integer FROM sentinelflow.approval_decisions),
       (SELECT count(*)::integer FROM sentinelflow.enforcement_authorizations),
       (SELECT count(*)::integer FROM sentinelflow.enforcement_actions),
       (SELECT count(*)::integer FROM sentinelflow.outbox_jobs),
       (SELECT count(*)::integer FROM sentinelflow.audit_events
         WHERE action IN ('policy_approved', 'policy_rejected')),
       revoked_at
FROM sentinelflow.admin_sessions WHERE session_id = $1::uuid`,
		commitInput.expected.ID.String(),
	).Scan(&rollbackReasonCount, &rollbackDecisionCount, &rollbackAuthorizationCount,
		&rollbackActionCount, &rollbackOutboxCount, &rollbackAuditCount,
		&rollbackOldRevoked); err != nil {
		t.Fatalf("load replacement-conflict rollback: %v", err)
	}
	if rollbackReasonCount != 0 || rollbackDecisionCount != 0 || rollbackAuthorizationCount != 0 ||
		rollbackActionCount != 0 || rollbackOutboxCount != 0 || rollbackAuditCount != 0 ||
		rollbackOldRevoked != nil {
		t.Fatalf("replacement conflict leaked atomic state: reason=%d decision=%d authz=%d action=%d outbox=%d audit=%d revoked=%v",
			rollbackReasonCount, rollbackDecisionCount, rollbackAuthorizationCount,
			rollbackActionCount, rollbackOutboxCount, rollbackAuditCount, rollbackOldRevoked)
	}
	if _, err = connection.Exec(ctx, `DELETE FROM sentinelflow.admin_sessions WHERE session_id = $1::uuid`,
		commitInput.replacement.ID.String()); err != nil {
		t.Fatalf("remove replacement conflict fixture: %v", err)
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("restore API role after replacement conflict")
	}
	stored, err := store.Commit(ctx, commitInput)
	if err != nil {
		t.Fatalf("coordinated rejection: %v", err)
	}
	if stored.Decision().Value().Decision != hil.DecisionRejected || stored.ActionID() != "" ||
		stored.AuthorizationDigest() != "" || stored.OutboxJobID() != "" || !stored.SessionRotated() {
		t.Fatalf("rejection returned mutation authority: %v", stored)
	}
	replayed, err := store.Commit(ctx, commitInput)
	if err != nil || replayed.Decision().Value().DecisionID != stored.Decision().Value().DecisionID ||
		replayed.SessionRotated() {
		t.Fatalf("exact rejection replay: replay=%v err=%v", replayed, err)
	}
	var secondRotationAt time.Time
	if err = connection.QueryRow(ctx, databaseClockSQL).Scan(&secondRotationAt); err != nil {
		t.Fatal("query second-rotation database clock")
	}
	grandchild := cloneSession(commitInput.replacement)
	grandchild.ID[15] ^= 0x33
	grandchild.ID[6] = grandchild.ID[6]&0x0f | 0x40
	grandchild.ID[8] = grandchild.ID[8]&0x3f | 0x80
	grandchild.TokenDigest[0] ^= 0x33
	grandchild.CSRFDigest[0] ^= 0x66
	grandchild.CreatedAt = secondRotationAt.UTC().Truncate(time.Microsecond)
	grandchild.LastSeenAt = grandchild.CreatedAt
	grandchild.ExpiresAt = grandchild.CreatedAt.Add(adminauth.SessionAbsoluteLifetime)
	childID := commitInput.replacement.ID
	grandchild.RotationParentID = &childID
	sessionStore, storeErr := adminstore.NewPostgreSQLStore(connection)
	if storeErr != nil {
		t.Fatal(storeErr)
	}
	if _, storeErr = sessionStore.Rotate(ctx, commitInput.replacement, grandchild); storeErr != nil {
		t.Fatalf("rotate retained child a second time: %v", storeErr)
	}
	if _, err = store.Commit(ctx, commitInput); err == nil {
		t.Fatal("second rotation left retained credentials replayable")
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset role")
	}

	var reasonCount, decisionCount, authorizationCount, actionCount, outboxCount, auditCount int
	var policyState string
	var challengeConsumed bool
	if err = connection.QueryRow(ctx, `
SELECT
    (SELECT count(*)::integer FROM sentinelflow.hil_reasons),
    (SELECT count(*)::integer FROM sentinelflow.approval_decisions),
    (SELECT count(*)::integer FROM sentinelflow.enforcement_authorizations),
    (SELECT count(*)::integer FROM sentinelflow.enforcement_actions),
    (SELECT count(*)::integer FROM sentinelflow.outbox_jobs),
    (SELECT count(*)::integer FROM sentinelflow.audit_events
      WHERE object_id = $1::uuid AND action = 'policy_rejected'),
    (SELECT state FROM sentinelflow.policy_proposals
      WHERE policy_id = $1::uuid AND version = $2),
    (SELECT consumed_at IS NOT NULL AND consumed_decision_id = $3::uuid
      FROM sentinelflow.decision_challenges WHERE challenge_id = $4::uuid)`,
		request.Artifact.PolicyID(), request.Artifact.PolicyVersion(),
		stored.Decision().Value().DecisionID, issued.Challenge().Value().ChallengeID,
	).Scan(&reasonCount, &decisionCount, &authorizationCount, &actionCount,
		&outboxCount, &auditCount, &policyState, &challengeConsumed); err != nil {
		t.Fatal("load rejection evidence")
	}
	if reasonCount != 1 || decisionCount != 1 || authorizationCount != 0 ||
		actionCount != 0 || outboxCount != 0 || auditCount != 1 ||
		policyState != "rejected" || !challengeConsumed {
		t.Fatalf("rejection shape reason=%d decision=%d authorization=%d action=%d outbox=%d audit=%d policy=%s consumed=%t",
			reasonCount, decisionCount, authorizationCount, actionCount, outboxCount,
			auditCount, policyState, challengeConsumed)
	}
}

type integrationChallengeFixtureIDs struct {
	incidentID                string
	signalID                  string
	analysisID                string
	candidateID               string
	evidenceID                string
	validationID              string
	signalDigestByte          byte
	signalEvidenceDigestByte  byte
	historyMutationDigestByte byte
}

var defaultIntegrationChallengeFixtureIDs = integrationChallengeFixtureIDs{
	incidentID:                "019b0000-0000-4000-8000-000000000101",
	signalID:                  "019b0000-0000-4000-8000-000000000102",
	analysisID:                "019b0000-0000-4000-8000-000000000103",
	candidateID:               "019b0000-0000-4000-8000-000000000105",
	evidenceID:                "019b0000-0000-4000-8000-000000000108",
	validationID:              "019b0000-0000-4000-8000-000000000104",
	signalDigestByte:          '1',
	signalEvidenceDigestByte:  '2',
	historyMutationDigestByte: '3',
}

func seedChallengeFixture(t *testing.T, ctx context.Context, connection *pgx.Conn, request IssueRequest, now time.Time) {
	t.Helper()
	seedChallengeFixtureWithIDs(t, ctx, connection, request, now, defaultIntegrationChallengeFixtureIDs)
}

func seedChallengeFixtureWithIDs(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	request IssueRequest,
	now time.Time,
	ids integrationChallengeFixtureIDs,
) {
	t.Helper()
	artifact := request.Artifact
	session := request.Browser.session
	incidentID := ids.incidentID
	signalID := ids.signalID
	analysisID := ids.analysisID
	candidateID := ids.candidateID
	evidenceID := ids.evidenceID
	validationID := ids.validationID
	signalDigest := testDigest(ids.signalDigestByte)
	signalEvidenceDigest := testDigest(ids.signalEvidenceDigestByte)
	historyEvidenceDigest := integrationIncidentEvidenceDigest(
		incidentID, 1, signalID, signalDigest,
	)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO sentinelflow.incidents (
            incident_id, kind, state, source_ip, service_label, first_seen,
			last_seen, deterministic_score, version, evidence_version
		) VALUES ($1::uuid, 'path_scan', 'review_ready', $2, 'demo-app', $3, $4, 0.95, 3, 1)`,
			[]any{incidentID, artifact.TargetIPv4(), now.Add(-10 * time.Minute), now.Add(-2 * time.Minute)}},
		{`INSERT INTO sentinelflow.signals (
			signal_id, schema_version, rule_id, rule_version, kind, source_ip,
			service_label, window_start, window_end, observed_count,
			distinct_count, threshold_count, threshold_distinct,
			source_health_status, evidence_digest, configuration_version,
			configuration_digest, signal_digest
		) VALUES ($1::uuid, 'signal-v1', 'path_scan.v1', 1, 'path_scan', $2,
			'demo-app', $3, $4, 8, 8, 8, 8, 'complete', $5,
			'detector-v1', $6, $7)`,
			[]any{signalID, artifact.TargetIPv4(), now.Add(-10 * time.Minute),
				now.Add(-2 * time.Minute), signalEvidenceDigest, testDigest('f'), signalDigest}},
		{`INSERT INTO sentinelflow.incident_signals (
			incident_id, signal_id, incident_version, relation_reason, linked_at
		) VALUES ($1::uuid, $2::uuid, 3, 'same_source_overlap', $3)`,
			[]any{incidentID, signalID, now.Add(-2 * time.Minute)}},
		{`INSERT INTO sentinelflow.incident_version_history (
			incident_id, incident_version, state, kind, source_ip, service_label,
			first_seen, last_seen, deterministic_score, mutation_kind,
			mutation_digest, evidence_digest, signal_count, recorded_at
		) VALUES ($1::uuid, 1, 'open', 'path_scan', $2, 'demo-app', $3, $4,
			0.95, 'created', $5, $6, 1, $7)`,
			[]any{incidentID, artifact.TargetIPv4(), now.Add(-10 * time.Minute),
				now.Add(-2 * time.Minute), testDigest(ids.historyMutationDigestByte), historyEvidenceDigest,
				now.Add(-2 * time.Minute)}},
		{`INSERT INTO sentinelflow.incident_version_signals (
			incident_id, incident_version, signal_id, ordinal
		) VALUES ($1::uuid, 1, $2::uuid, 1)`, []any{incidentID, signalID}},
		{`INSERT INTO sentinelflow.evidence_snapshots (
            evidence_snapshot_id, schema_version, incident_id, incident_version,
            source_ip, service_label, window_start, window_end,
            source_health_status, signal_count, expanded_event_count,
            snapshot_digest, created_at, expires_at
        ) VALUES ($1::uuid, 'evidence-snapshot-v1', $2::uuid, 1, $3,
            'demo-app', $4, $5, 'complete', 1, 1, $6, $7, $8)`,
			[]any{evidenceID, incidentID, artifact.TargetIPv4(), now.Add(-10 * time.Minute),
				now.Add(-2 * time.Minute), artifact.EvidenceSnapshotDigest(), now.Add(-2 * time.Minute), now.Add(30 * 24 * time.Hour)}},
		{`INSERT INTO sentinelflow.evidence_snapshot_signals (
			evidence_snapshot_id, ordinal, signal_id, evidence_id,
			evidence_digest, expanded_event_count
		) VALUES ($1::uuid, 1, $2::uuid, $2::text, $3, 1)`,
			[]any{evidenceID, signalID, signalEvidenceDigest}},
		{`INSERT INTO sentinelflow.ai_analyses (
            analysis_id, incident_id, incident_version, evidence_snapshot_id,
            evidence_snapshot_digest, attempt, model, reasoning_effort,
            store_enabled, input_schema_digest, prompt_digest,
            output_schema_digest, input_digest, input_bytes, result_state,
            output_digest, incident_summary, classification, confidence,
            uncertainty, input_tokens, cached_input_tokens, output_tokens,
            started_at, completed_at
        ) VALUES ($1::uuid, $2::uuid, 1, $3::uuid, $4, 1, 'gpt-5.6-sol',
            'medium', false, $5, $6, $7, $8, 2048, 'succeeded', $9,
            'Synthetic exact-artifact HIL integration fixture.', 'path_scan',
            0.95, 'Synthetic isolated integration evidence only.', 400, 0, 180,
            $10, $11)`,
			[]any{analysisID, incidentID, evidenceID, artifact.EvidenceSnapshotDigest(),
				testDigest('4'), testDigest('6'), testDigest('5'), testDigest('7'),
				testDigest('a'), now.Add(-90 * time.Second), now.Add(-80 * time.Second)}},
		{`INSERT INTO sentinelflow.command_candidates (
            command_candidate_id, schema_version, analysis_id,
            evidence_snapshot_id, evidence_snapshot_digest, target_ipv4,
            timeout_token, ttl_seconds, generated_command,
            generated_artifact_digest, parse_state, canonical_artifact,
            canonical_artifact_digest
        ) VALUES ($1::uuid, 'nft-blacklist-v1', $2::uuid, $3::uuid, $4,
            $5, '1800s', $6, $7, $8, 'valid', $9, $10)`,
			[]any{candidateID, analysisID, evidenceID, artifact.EvidenceSnapshotDigest(),
				artifact.TargetIPv4(), artifact.TTLSeconds(), string(artifact.GeneratedBytes()),
				artifact.GeneratedArtifactDigest(), artifact.CanonicalBytes(), artifact.CanonicalArtifactDigest()}},
		{`INSERT INTO sentinelflow.policy_proposals (
            policy_id, version, schema_version, incident_id, incident_version,
            analysis_id, command_candidate_id, evidence_snapshot_id,
            evidence_snapshot_digest, policy_digest,
            generated_artifact_digest, canonical_artifact_digest, target_ipv4,
            action, ttl_seconds, rationale, state
        ) VALUES ($1::uuid, $2, 'response-policy-v1', $3::uuid, 1, $4::uuid,
            $5::uuid, $6::uuid, $7, $8, $9, $10, $11, 'block_ip', $12,
            'Synthetic exact-artifact HIL integration fixture.', 'draft')`,
			[]any{artifact.PolicyID(), artifact.PolicyVersion(), incidentID, analysisID,
				candidateID, evidenceID, artifact.EvidenceSnapshotDigest(), artifact.PolicyDigest(),
				artifact.GeneratedArtifactDigest(), artifact.CanonicalArtifactDigest(),
				artifact.TargetIPv4(), artifact.TTLSeconds()}},
		{`INSERT INTO sentinelflow.validation_snapshots (
            validation_snapshot_id, schema_version, policy_id, policy_version,
            command_candidate_id, evidence_snapshot_id, snapshot_digest,
            policy_digest, evidence_snapshot_digest, analysis_input_digest,
            analysis_output_schema_digest, prompt_digest,
            generated_candidate_digest, canonical_artifact_digest,
            grammar_version, parser_version, validator_version,
            base_chain_contract_raw_digest, live_owned_schema_digest,
            protected_ipv4_static_digest,
            protected_ipv4_effective_config_digest, nft_binary_digest,
            nft_version, historical_impact_digest, target_ipv4, ttl_seconds,
            historical_impact_lookback_seconds, state, source_health_status,
            created_at, valid_until
        ) VALUES ($1::uuid, 'validation-snapshot-v1', $2::uuid, $3, $4::uuid,
            $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13,
            'nft-blacklist-v1', $14, $15, $16, $17, $18, $19, $20,
            '1.1.0', $21, $22, $23, 86400, 'draft', 'complete', $24, $25)`,
			[]any{validationID, artifact.PolicyID(), artifact.PolicyVersion(), candidateID,
				evidenceID, artifact.ValidationSnapshotDigest(), artifact.PolicyDigest(),
				artifact.EvidenceSnapshotDigest(), testDigest('4'), testDigest('5'), testDigest('6'),
				artifact.GeneratedArtifactDigest(), artifact.CanonicalArtifactDigest(),
				nftvalidate.ParserVersion, nftvalidate.ValidatorVersion, nftvalidate.PinnedBaseChainRawDigest,
				nftvalidate.PinnedLiveSchemaDigest, validation.PinnedProtectedIPv4Digest,
				testDigest('8'), testDigest('9'), testDigest('0'), artifact.TargetIPv4(),
				artifact.TTLSeconds(), artifact.ValidationCreatedAt(), artifact.ValidationValidUntil()}},
		{`INSERT INTO sentinelflow.admin_sessions (
            session_id, actor_id, token_digest, csrf_digest, authenticated_at,
            created_at, last_seen_at, expires_at
        ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)`,
			[]any{session.ID.String(), session.ActorID, session.TokenDigest.String(),
				session.CSRFDigest.String(), session.AuthenticatedAt, session.CreatedAt,
				session.LastSeenAt, session.ExpiresAt}},
	}
	for index, statement := range statements {
		if _, err := connection.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed statement %d: %v", index+1, err)
		}
	}
	gateNames := []string{
		"structured_output", "command_grammar", "policy_evidence_command_consistency",
		"protected_network", "owned_schema_syntax", "historical_impact",
	}
	for index, name := range gateNames {
		if _, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.validation_gates (
    validation_snapshot_id, gate_order, gate_name, passed, result_code,
    input_digest, result_digest, checked_at
) VALUES ($1::uuid, $2, $3, true, 'ok', $4, $5, $6)`,
			validationID, index+1, name, testDigest('d'), testDigest('e'), now,
		); err != nil {
			t.Fatalf("seed validation gate %d: %v", index+1, err)
		}
	}
	if _, err := connection.Exec(ctx, `
UPDATE sentinelflow.validation_snapshots
SET state = 'valid'
WHERE validation_snapshot_id = $1::uuid`, validationID); err != nil {
		t.Fatalf("finalize validation fixture: %v", err)
	}
	if _, err := connection.Exec(ctx, `
UPDATE sentinelflow.policy_proposals
SET state = 'validating', state_revision = 2, updated_at = clock_timestamp()
WHERE policy_id = $1::uuid AND version = $2`, artifact.PolicyID(), artifact.PolicyVersion()); err != nil {
		t.Fatalf("start policy validation fixture: %v", err)
	}
	if _, err := connection.Exec(ctx, `
UPDATE sentinelflow.policy_proposals
SET state = 'valid', state_revision = 3, updated_at = clock_timestamp()
WHERE policy_id = $1::uuid AND version = $2`, artifact.PolicyID(), artifact.PolicyVersion()); err != nil {
		t.Fatalf("finalize policy validation fixture: %v", err)
	}
}

func integrationIncidentEvidenceDigest(
	incidentID string,
	version int,
	signalID string,
	signalDigest string,
) string {
	values := []string{
		"incident-evidence-v1", incidentID, fmt.Sprintf("%d", version),
		signalID, signalDigest,
	}
	hash := sha256.New()
	for _, value := range values {
		_, _ = fmt.Fprintf(hash, "%d:%s\n", len(value), value)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func applyIntegrationMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
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

func waitForIntegrationPostgreSQL(t *testing.T, ctx context.Context, container string) {
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

func connectIntegrationPostgreSQL(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	var lastErr error
	for range 40 {
		connection, err := pgx.Connect(ctx, connectionString)
		if err == nil {
			return connection
		}
		lastErr = err
		select {
		case <-ctx.Done():
			t.Fatalf("connect PostgreSQL 17: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("connect PostgreSQL 17: %v", lastErr)
	return nil
}

func integrationDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := runIntegrationDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func runIntegrationDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}
