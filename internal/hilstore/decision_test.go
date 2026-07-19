package hilstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/jackc/pgx/v5"
)

func TestLookupHistoricalDecisionReturnsExactCommittedApprovalWithoutExecutionAuthority(t *testing.T) {
	now := fixtureTime()
	lookup := fixtureDecisionLookup(t, now, hil.OperationApprove)
	tx := &scriptedTx{
		query: func(query string, arguments []any) pgx.Row {
			if query != lookupDecisionSQL || len(arguments) != 1 ||
				arguments[0] != lookup.Browser.idempotency.digest {
				t.Fatalf("unexpected lookup query or arguments")
			}
			return valuesRow(storedDecisionValues(lookup, now, true)...)
		},
	}
	store := storeWithTransaction(tx, deterministicEntropy(64))
	stored, err := store.LookupHistoricalDecision(context.Background(), lookup)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if tx.options.IsoLevel != pgx.ReadCommitted || tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("transaction commits=%d rollbacks=%d options=%+v", tx.commits, tx.rollbacks, tx.options)
	}
	if stored.ActionID() == "" || stored.AuthorizationDigest() == "" || stored.OutboxJobID() == "" {
		t.Fatal("approved durable linkage missing")
	}
	if stored.Decision().Value().Decision != hil.DecisionApproved || stored.Decision().AuthorizesAt(now.Add(time.Minute)) {
		t.Fatal("historical lookup became execution authority")
	}
	if !strings.Contains(stored.String(), "REDACTED") || !strings.Contains(lookup.String(), "REDACTED") {
		t.Fatal("decision formatting exposed content")
	}
}

func TestLookupHistoricalDecisionReturnsRejectionOnlyWithoutDispatch(t *testing.T) {
	now := fixtureTime()
	lookup := fixtureDecisionLookup(t, now, hil.OperationReject)
	tx := &scriptedTx{query: func(string, []any) pgx.Row {
		return valuesRow(storedDecisionValues(lookup, now, false)...)
	}}
	stored, err := storeWithTransaction(tx, deterministicEntropy(64)).LookupHistoricalDecision(context.Background(), lookup)
	if err != nil {
		t.Fatalf("lookup rejection: %v", err)
	}
	if stored.Decision().Value().Decision != hil.DecisionRejected || stored.ActionID() != "" ||
		stored.AuthorizationDigest() != "" || stored.OutboxJobID() != "" {
		t.Fatal("rejection acquired an enforcement path")
	}
}

func TestHistoricalReplayBrowserCanOnlyReadExactCommittedDecision(t *testing.T) {
	now := fixtureTime()
	lookup := fixtureDecisionLookup(t, now, hil.OperationApprove)
	active := cloneSession(lookup.Browser.session)
	revoked := cloneSession(active)
	revokedAt := now
	revoked.RevokedAt = &revokedAt
	historicalBrowser, err := BindHistoricalReplayBrowserRequest(revoked, lookup.Browser.idempotency)
	if err != nil || !historicalBrowser.historicalOnly {
		t.Fatalf("historical binding failed: browser=%v err=%v", historicalBrowser, err)
	}
	lookup.Browser = historicalBrowser
	tx := &scriptedTx{query: func(string, []any) pgx.Row {
		return valuesRow(storedDecisionValues(lookup, now, true)...)
	}}
	stored, err := storeWithTransaction(tx, deterministicEntropy(64)).LookupHistoricalDecision(context.Background(), lookup)
	if err != nil || stored.Decision().Value().Decision != hil.DecisionApproved || stored.SessionRotated() {
		t.Fatalf("historical exact read failed: stored=%v err=%v", stored, err)
	}

	issueStore := storeWithTransaction(&scriptedTx{}, deterministicEntropy(64))
	if _, err := issueStore.Issue(context.Background(), IssueRequest{
		Operation: hil.OperationApprove, Browser: historicalBrowser, Artifact: lookup.Artifact,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("historical browser issued challenge: %v", err)
	}
	rotationAt := now.Add(time.Second).Truncate(time.Microsecond)
	rotationRevoked := cloneSession(active)
	rotationRevoked.LastSeenAt = rotationAt
	rotationRevoked.RevokedAt = &rotationAt
	replacement := cloneSession(active)
	replacement.ID[15] ^= 1
	replacement.ID[6] = replacement.ID[6]&0x0f | 0x40
	replacement.ID[8] = replacement.ID[8]&0x3f | 0x80
	replacement.TokenDigest[0] ^= 1
	replacement.CSRFDigest[0] ^= 1
	replacement.CreatedAt = rotationAt
	replacement.LastSeenAt = rotationAt
	replacement.ExpiresAt = rotationAt.Add(adminauth.SessionAbsoluteLifetime)
	parent := active.ID
	replacement.RotationParentID = &parent
	if _, err := BindPrivilegedDecisionCommit(lookup, active, adminauth.SessionRotation{
		Revoked: rotationRevoked, Issued: adminauth.IssuedSession{Record: replacement},
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("historical browser entered mutating commit: %v", err)
	}
	forgedCommit := fixturePrivilegedCommit(t, fixtureDecisionLookup(t, now, hil.OperationApprove), rotationAt)
	forgedCommit.lookup = lookup
	queries := 0
	tx = &scriptedTx{query: func(string, []any) pgx.Row {
		queries++
		return errorRow(errors.New("historical-only query must not execute"))
	}}
	if _, err := storeWithTransaction(tx, deterministicEntropy(256)).Commit(context.Background(), forgedCommit); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("direct historical-only commit reached mutation: %v", err)
	}
	if queries != 0 || tx.commits != 0 || tx.rollbacks != 0 {
		t.Fatalf("direct historical-only commit opened persistence: queries=%d commits=%d rollbacks=%d",
			queries, tx.commits, tx.rollbacks)
	}

	if _, err := BindHistoricalReplayBrowserRequest(active, lookup.Browser.idempotency); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("live session accepted as historical replay: %v", err)
	}
}

func TestLookupHistoricalDecisionFailsClosedOnMissingConflictAndIncompleteAtomicShape(t *testing.T) {
	now := fixtureTime()
	lookup := fixtureDecisionLookup(t, now, hil.OperationApprove)
	tests := []struct {
		name string
		row  pgx.Row
		want error
	}{
		{"missing", errorRow(pgx.ErrNoRows), ErrNotFound},
		{"driver", errorRow(errors.New("driver detail")), ErrUnavailable},
		{"conflicting-reason", func() pgx.Row {
			values := storedDecisionValues(lookup, now, true)
			values[31] = "different normalized reason"
			return valuesRow(values...)
		}(), ErrConflict},
		{"missing-authorization", func() pgx.Row {
			values := storedDecisionValues(lookup, now, true)
			values[37] = (*string)(nil)
			return valuesRow(values...)
		}(), ErrUnavailable},
		{"duplicate-outbox", func() pgx.Row {
			values := storedDecisionValues(lookup, now, true)
			values[40] = 2
			return valuesRow(values...)
		}(), ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := &scriptedTx{query: func(string, []any) pgx.Row { return test.row }}
			stored, err := storeWithTransaction(tx, deterministicEntropy(64)).LookupHistoricalDecision(context.Background(), lookup)
			if !errors.Is(err, test.want) || stored.Decision().Digest() != "" || tx.commits != 0 || tx.rollbacks != 1 {
				t.Fatalf("stored=%v err=%v commits=%d rollbacks=%d", stored, err, tx.commits, tx.rollbacks)
			}
		})
	}
}

func TestLookupHistoricalDecisionRejectsInvalidInputAndCommitUncertainty(t *testing.T) {
	var missingContext context.Context
	store := storeWithTransaction(&scriptedTx{}, deterministicEntropy(64))
	if _, err := store.LookupHistoricalDecision(missingContext, DecisionLookup{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context: %v", err)
	}
	if _, err := (*PostgreSQLStore)(nil).LookupHistoricalDecision(context.Background(), DecisionLookup{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil store: %v", err)
	}
	if _, err := store.LookupHistoricalDecision(context.Background(), DecisionLookup{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero lookup: %v", err)
	}

	now := fixtureTime()
	lookup := fixtureDecisionLookup(t, now, hil.OperationApprove)
	tx := &scriptedTx{
		query:     func(string, []any) pgx.Row { return valuesRow(storedDecisionValues(lookup, now, true)...) },
		commitErr: errors.New("commit uncertainty"),
	}
	if _, err := storeWithTransaction(tx, deterministicEntropy(64)).LookupHistoricalDecision(context.Background(), lookup); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("commit uncertainty: %v", err)
	}
}

func fixtureDecisionLookup(t *testing.T, now time.Time, operation hil.Operation) DecisionLookup {
	t.Helper()
	request := fixtureIssueRequest(t, now, operation)
	nonceBytes := make([]byte, decisionNonceBytes)
	for index := range nonceBytes {
		nonceBytes[index] = byte(index + 31)
	}
	nonce, err := CheckDecisionNonce(rawURL(nonceBytes))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := hil.CheckChallenge(hil.Challenge{
		SchemaVersion:              hil.ChallengeSchemaVersion,
		ChallengeID:                "019b0000-0000-4000-8000-000000000120",
		SessionDigest:              request.Browser.session.TokenDigest.String(),
		Operation:                  operation,
		ResourceType:               hil.ResourcePolicy,
		ResourceID:                 request.Artifact.PolicyID(),
		ResourceVersion:            request.Artifact.PolicyVersion(),
		TargetIPv4:                 request.Artifact.TargetIPv4(),
		PolicyDigest:               request.Artifact.PolicyDigest(),
		GeneratedArtifactDigest:    request.Artifact.GeneratedArtifactDigest(),
		CanonicalArtifactDigest:    request.Artifact.CanonicalArtifactDigest(),
		EvidenceSnapshotDigest:     request.Artifact.EvidenceSnapshotDigest(),
		ValidationSnapshotDigest:   request.Artifact.ValidationSnapshotDigest(),
		ValidationValidUntil:       request.Artifact.ValidationValidUntil(),
		NonceDigest:                nonce.digest,
		AuthenticatedAt:            request.Browser.session.AuthenticatedAt,
		ReauthRequiredAfterSeconds: uint32(hil.ReauthAfter / time.Second),
		IssuedAt:                   now,
		ExpiresAt:                  request.Artifact.ValidationValidUntil(),
	})
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	reasonCode := hil.ReasonThreatConfirmed
	reasonText := "Confirmed synthetic attack pattern"
	if operation == hil.OperationReject {
		reasonCode = hil.ReasonFalsePositive
		reasonText = "Confirmed synthetic false positive"
	}
	reason, err := hil.CheckReason(hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion, ReasonCode: reasonCode, ReasonText: reasonText,
	})
	if err != nil {
		t.Fatalf("reason: %v", err)
	}
	return DecisionLookup{
		Browser: request.Browser, Challenge: challenge, Nonce: nonce,
		Artifact: request.Artifact, Reason: reason,
	}
}

func storedDecisionValues(lookup DecisionLookup, now time.Time, approved bool) []any {
	challenge := lookup.Challenge.Value()
	artifact := lookup.Artifact
	reason := lookup.Reason.Value()
	operation := hil.OperationReject
	decisionValue := hil.DecisionRejected
	policyState := "rejected"
	var authorizationDigest, authorizationActionID, actionID, outboxJobID *string
	var authorizationID *string
	var authorizationJCS []byte
	var authorizationDecidedAt, authorizationValidUntil *time.Time
	outboxCount := 0
	if approved {
		operation = hil.OperationApprove
		decisionValue = hil.DecisionApproved
		policyState = "approved"
		authorization := testDigest('a')
		authorizationIdentity := "019b0000-0000-4000-8000-000000000124"
		action := "019b0000-0000-4000-8000-000000000121"
		job := "019b0000-0000-4000-8000-000000000122"
		authorizationDigest = &authorization
		authorizationID = &authorizationIdentity
		authorizationActionID = &action
		actionID = &action
		outboxJobID = &job
		outboxCount = 1
	}
	decisionID := "019b0000-0000-4000-8000-000000000123"
	decidedAt := now.Add(5 * time.Second)
	decisionValidUntil := now.Add(3 * time.Minute)
	checkedDecision, _ := hil.CheckDecision(hil.Decision{
		SchemaVersion: hil.DecisionSchemaVersion, DecisionID: decisionID,
		ChallengeID: challenge.ChallengeID, SessionDigest: lookup.Browser.session.TokenDigest.String(),
		Operation: operation, Decision: decisionValue, ResourceType: hil.ResourcePolicy,
		ResourceID: artifact.PolicyID(), ResourceVersion: artifact.PolicyVersion(),
		TargetIPv4: artifact.TargetIPv4(), PolicyDigest: artifact.PolicyDigest(),
		GeneratedArtifactDigest:  artifact.GeneratedArtifactDigest(),
		CanonicalArtifactDigest:  artifact.CanonicalArtifactDigest(),
		EvidenceSnapshotDigest:   artifact.EvidenceSnapshotDigest(),
		ValidationSnapshotDigest: artifact.ValidationSnapshotDigest(), ActorID: lookup.Browser.session.ActorID,
		ReasonDigest: lookup.Reason.Digest(), NonceDigest: lookup.Nonce.digest,
		IdempotencyKeyDigest: lookup.Browser.idempotency.digest,
		DecidedAt:            decidedAt, DecisionValidUntil: decisionValidUntil,
	})
	if approved {
		authorizationJCS = marshalAddAuthorization(*actionID, lookup.Browser.session.ActorID,
			*authorizationID, artifact, lookup, decidedAt, decisionValidUntil)
		digest := digestBytes(authorizationJCS)
		authorizationDigest = &digest
		authorizationDecidedAt = &decidedAt
		authorizationValidUntil = &decisionValidUntil
	}
	consumedAt := now.Add(10 * time.Second)
	consumedDecisionID := decisionID
	return []any{
		hil.DecisionSchemaVersion, decisionID, challenge.ChallengeID,
		lookup.Browser.session.TokenDigest.String(), string(operation), string(decisionValue),
		hil.ResourcePolicy, artifact.PolicyID(), int64(artifact.PolicyVersion()),
		artifact.TargetIPv4(), artifact.PolicyDigest(), artifact.GeneratedArtifactDigest(),
		artifact.CanonicalArtifactDigest(), (*string)(nil), artifact.EvidenceSnapshotDigest(),
		artifact.ValidationSnapshotDigest(), lookup.Browser.session.ActorID,
		lookup.Reason.Digest(), lookup.Nonce.digest, lookup.Browser.idempotency.digest,
		decidedAt, decisionValidUntil,
		lookup.Browser.session.ID.String(), challenge.AuthenticatedAt,
		challenge.ValidationValidUntil, challenge.IssuedAt, challenge.ExpiresAt,
		&consumedAt, &consumedDecisionID, lookup.Browser.session.ActorID,
		string(operation), reason.ReasonText, policyState, string(artifact.GeneratedBytes()),
		artifact.CanonicalBytes(), artifact.ValidationCreatedAt(), artifact.ValidationValidUntil(),
		authorizationDigest, authorizationActionID, actionID, outboxCount, outboxJobID,
		lookup.Challenge.CanonicalBytes(), lookup.Challenge.Digest(), string(reason.ReasonCode),
		lookup.Reason.CanonicalBytes(), checkedDecision.CanonicalBytes(), checkedDecision.Digest(),
		authorizationJCS, authorizationID, authorizationDecidedAt, authorizationValidUntil,
	}
}
