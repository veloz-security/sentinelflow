package hilstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
	"github.com/jackc/pgx/v5"
)

func TestIssuedRevocationChallengeTakeNonceIsExactlyOnceUnderConcurrency(t *testing.T) {
	raw := bytes.Repeat([]byte{0x6a}, decisionNonceBytes)
	issued := &IssuedRevocationChallenge{nonce: bytes.Clone(raw)}
	const workers = 64
	var wait sync.WaitGroup
	wait.Add(workers)
	results := make(chan string, workers)
	errorsSeen := make(chan error, workers)
	for range workers {
		go func() {
			defer wait.Done()
			value, err := issued.TakeNonce()
			if err != nil {
				errorsSeen <- err
				return
			}
			results <- value
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	if len(results) != 1 || len(errorsSeen) != workers-1 {
		t.Fatalf("successes=%d failures=%d", len(results), len(errorsSeen))
	}
	for result := range results {
		checked, err := CheckDecisionNonce(result)
		if err != nil || checked.digest != digestBytes(raw) {
			t.Fatalf("winning nonce err=%v", err)
		}
	}
	for err := range errorsSeen {
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("losing nonce error=%v", err)
		}
	}
	if _, err := issued.TakeNonce(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-concurrency nonce replay=%v", err)
	}
}

func TestBindRevocationLookupRejectsMutationsAndOwnsCanonicalBytes(t *testing.T) {
	input, baseline := fixtureRevocationDecisionInput(t, fixtureTime())
	tests := []struct {
		name   string
		mutate func(*RevocationDecisionInput)
	}{
		{"challenge", func(value *RevocationDecisionInput) {
			value.CanonicalChallenge = bytes.Clone(value.CanonicalChallenge)
			value.CanonicalChallenge[len(value.CanonicalChallenge)/2] ^= 1
		}},
		{"artifact", func(value *RevocationDecisionInput) {
			value.CanonicalRevokeArtifact = append(bytes.Clone(value.CanonicalRevokeArtifact), '\n')
		}},
		{"nonce", func(value *RevocationDecisionInput) { value.Nonce = DecisionNonce{} }},
		{"session", func(value *RevocationDecisionInput) { value.Browser.session.TokenDigest[0] ^= 1 }},
		{"idempotency", func(value *RevocationDecisionInput) { value.Browser.idempotency = IdempotencyKey{} }},
		{"policy-id", func(value *RevocationDecisionInput) { value.PolicyID = "not-a-uuid" }},
		{"policy-version", func(value *RevocationDecisionInput) { value.PolicyVersion = 0 }},
		{"reason", func(value *RevocationDecisionInput) { value.Reason = hil.CheckedReason{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := input
			candidate.CanonicalChallenge = bytes.Clone(input.CanonicalChallenge)
			candidate.CanonicalRevokeArtifact = bytes.Clone(input.CanonicalRevokeArtifact)
			test.mutate(&candidate)
			if _, err := BindRevocationLookup(candidate); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}

	wantChallenge := bytes.Clone(baseline.Challenge.CanonicalBytes())
	wantArtifact := bytes.Clone(baseline.Challenge.RevokeArtifactBytes())
	clear(input.CanonicalChallenge)
	clear(input.CanonicalRevokeArtifact)
	if !bytes.Equal(baseline.Challenge.CanonicalBytes(), wantChallenge) ||
		!bytes.Equal(baseline.Challenge.RevokeArtifactBytes(), wantArtifact) {
		t.Fatal("lookup retained aliases to browser-owned bytes")
	}
	exposedChallenge := baseline.Challenge.CanonicalBytes()
	exposedArtifact := baseline.Challenge.RevokeArtifactBytes()
	clear(exposedChallenge)
	clear(exposedArtifact)
	if !bytes.Equal(baseline.Challenge.CanonicalBytes(), wantChallenge) ||
		!bytes.Equal(baseline.Challenge.RevokeArtifactBytes(), wantArtifact) {
		t.Fatal("lookup getters exposed mutable canonical storage")
	}
}

func TestBindPrivilegedRevocationCommitRejectsEveryRotationMutation(t *testing.T) {
	_, lookup := fixtureRevocationDecisionInput(t, fixtureTime())
	valid := fixturePrivilegedRevocationCommit(t, lookup, fixtureTime().Add(time.Second))
	rotation := func() (adminauth.SessionRecord, adminauth.SessionRotation) {
		expected := cloneSession(valid.expected)
		revoked := cloneSession(expected)
		revoked.LastSeenAt = valid.rotationAt
		revokedAt := valid.rotationAt
		revoked.RevokedAt = &revokedAt
		return expected, adminauth.SessionRotation{
			Revoked: revoked,
			Issued:  adminauth.IssuedSession{Record: cloneSession(valid.replacement)},
		}
	}
	tests := []struct {
		name   string
		mutate func(*adminauth.SessionRecord, *adminauth.SessionRotation)
	}{
		{"expected-token", func(expected *adminauth.SessionRecord, _ *adminauth.SessionRotation) {
			expected.TokenDigest[0] ^= 1
		}},
		{"revoked-token", func(_ *adminauth.SessionRecord, value *adminauth.SessionRotation) {
			value.Revoked.TokenDigest[0] ^= 1
		}},
		{"revoked-at", func(_ *adminauth.SessionRecord, value *adminauth.SessionRotation) {
			value.Revoked.RevokedAt = nil
		}},
		{"replacement-actor", func(_ *adminauth.SessionRecord, value *adminauth.SessionRotation) {
			value.Issued.Record.ActorID = "different-admin"
		}},
		{"replacement-parent", func(_ *adminauth.SessionRecord, value *adminauth.SessionRotation) {
			value.Issued.Record.RotationParentID = nil
		}},
		{"replacement-authenticated-at", func(_ *adminauth.SessionRecord, value *adminauth.SessionRotation) {
			value.Issued.Record.AuthenticatedAt = value.Issued.Record.AuthenticatedAt.Add(time.Second)
		}},
		{"replacement-expiry", func(_ *adminauth.SessionRecord, value *adminauth.SessionRotation) {
			value.Issued.Record.ExpiresAt = value.Issued.Record.CreatedAt
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected, candidate := rotation()
			test.mutate(&expected, &candidate)
			if _, err := BindPrivilegedRevocationCommit(lookup, expected, candidate); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("rotation mutation accepted: %v", err)
			}
		})
	}
}

func TestRevocationBoundaryFormattingRedactsAllSensitiveMaterial(t *testing.T) {
	input, lookup := fixtureRevocationDecisionInput(t, fixtureTime())
	commit := fixturePrivilegedRevocationCommit(t, lookup, fixtureTime().Add(time.Second))
	rawValues := []string{
		lookup.Nonce.digest,
		lookup.Reason.Value().ReasonText,
		string(lookup.Challenge.RevokeArtifactBytes()),
		string(lookup.Challenge.CanonicalBytes()),
		lookup.Browser.session.TokenDigest.String(),
	}
	values := []any{
		RevocationIssueRequest{}, &IssuedRevocationChallenge{}, input, lookup,
		commit, StoredRevocation{},
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%v %#v", value, value)
		if !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("missing redaction marker for %T: %q", value, formatted)
		}
		for _, raw := range rawValues {
			if raw != "" && strings.Contains(formatted, raw) {
				t.Fatalf("%T formatting exposed sensitive material", value)
			}
		}
	}
}

func TestStoredRevocationScanFailsClosedOnEveryDurableLinkCorruption(t *testing.T) {
	now := fixtureTime()
	_, active := fixtureRevocationDecisionInput(t, now)
	revokedSession := cloneSession(active.Browser.session)
	revokedAt := now.Add(10 * time.Second)
	revokedSession.RevokedAt = &revokedAt
	historicalBrowser, err := BindHistoricalReplayBrowserRequest(revokedSession, active.Browser.idempotency)
	if err != nil {
		t.Fatal(err)
	}
	historicalInput := RevocationDecisionInput{
		Browser: historicalBrowser, CanonicalChallenge: active.Challenge.CanonicalBytes(),
		CanonicalRevokeArtifact: active.Challenge.RevokeArtifactBytes(),
		Nonce:                   active.Nonce, Reason: active.Reason,
		PolicyID: active.policyID, PolicyVersion: active.policyVersion,
	}
	lookup, err := BindRevocationLookup(historicalInput)
	if err != nil {
		t.Fatal(err)
	}
	baseline := storedRevocationValues(t, lookup, now)
	if stored, err := scanStoredRevocation(valuesRow(baseline...), lookup); err != nil ||
		stored.AuditEventID() == "" || stored.OutboxJobID() == "" {
		t.Fatalf("baseline scan=%v err=%v", stored, err)
	}
	tests := []struct {
		name  string
		index int
		value any
	}{
		{"decision-jcs", 24, append(bytes.Clone(baseline[24].([]byte)), ' ')},
		{"challenge-jcs", 26, append(bytes.Clone(baseline[26].([]byte)), ' ')},
		{"reason-jcs", 35, append(bytes.Clone(baseline[35].([]byte)), ' ')},
		{"authorization-jcs", 38, append(bytes.Clone(baseline[38].([]byte)), ' ')},
		{"revocation-artifact", 44, append(bytes.Clone(baseline[44].([]byte)), ' ')},
		{"outbox-idempotency", 52, testDigest('9')},
		{"dispatch-policy", 59, "019b0000-0000-4000-8000-000000000299"},
		{"dispatch-validation", 63, "019b0000-0000-4000-8000-000000000298"},
		{"dispatch-owned-schema", 67, testDigest('8')},
		{"dispatch-valid-until", 69, now.Add(3 * time.Minute)},
		{"audit-id", 70, "not-a-uuid"},
		{"audit-count", 71, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			corrupt := append([]any(nil), baseline...)
			corrupt[test.index] = test.value
			tx := &scriptedTx{query: func(string, []any) pgx.Row { return valuesRow(corrupt...) }}
			stored, err := storeWithTransaction(tx, deterministicEntropy(64)).LookupHistoricalRevocation(
				context.Background(), lookup,
			)
			if err == nil || stored.Decision().Digest() != "" || tx.commits != 0 || tx.rollbacks != 1 {
				t.Fatalf("corruption escaped stored=%v err=%v commits=%d rollbacks=%d",
					stored, err, tx.commits, tx.rollbacks)
			}
		})
	}
}

func FuzzBindRevocationLookupUntrustedCanonicalBytes(f *testing.F) {
	input, _ := fixtureRevocationDecisionInput(f, fixtureTime())
	f.Add(input.CanonicalChallenge, input.CanonicalRevokeArtifact)
	f.Add([]byte(`{}`), []byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n"))
	f.Fuzz(func(t *testing.T, challengeBytes, artifactBytes []byte) {
		candidate := input
		candidate.CanonicalChallenge = bytes.Clone(challengeBytes)
		candidate.CanonicalRevokeArtifact = bytes.Clone(artifactBytes)
		lookup, err := BindRevocationLookup(candidate)
		if err != nil {
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("untrusted bytes exposed non-public error: %v", err)
			}
			return
		}
		canonicalChallenge := lookup.Challenge.CanonicalBytes()
		canonicalArtifact := lookup.Challenge.RevokeArtifactBytes()
		clear(candidate.CanonicalChallenge)
		clear(candidate.CanonicalRevokeArtifact)
		if !bytes.Equal(lookup.Challenge.CanonicalBytes(), canonicalChallenge) ||
			!bytes.Equal(lookup.Challenge.RevokeArtifactBytes(), canonicalArtifact) {
			t.Fatal("successful fuzz bind retained input aliases")
		}
		if rebound, bindErr := BindRevocationLookup(RevocationDecisionInput{
			Browser: input.Browser, CanonicalChallenge: canonicalChallenge,
			CanonicalRevokeArtifact: canonicalArtifact, Nonce: input.Nonce,
			Reason: input.Reason, PolicyID: input.PolicyID, PolicyVersion: input.PolicyVersion,
		}); bindErr != nil || rebound.Challenge.Digest() != lookup.Challenge.Digest() {
			t.Fatalf("successful fuzz bind was not stable: %v", bindErr)
		}
	})
}

func fixtureRevocationDecisionInput(
	t testing.TB,
	now time.Time,
) (RevocationDecisionInput, RevocationLookup) {
	t.Helper()
	key, err := CheckIdempotencyKey([]byte("revocation-unit-stateless-idempotency-key"))
	if err != nil {
		t.Fatal(err)
	}
	browser, err := BindValidatedBrowserRequest(fixtureSession(now), key)
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes := bytes.Repeat([]byte{0x4a}, decisionNonceBytes)
	nonce, err := CheckDecisionNonce(rawURL(nonceBytes))
	if err != nil {
		t.Fatal(err)
	}
	revoke, err := lifecycleartifact.CheckRevokeArtifact("203.0.113.20")
	if err != nil {
		t.Fatal(err)
	}
	eligibleUntil := now.Add(4 * time.Minute)
	actionID := "019b0000-0000-4000-8000-000000000201"
	originalAddDigest := testDigest('a')
	binding, err := hil.CheckRevocationBinding(hil.RevocationBindingInput{
		ActionID: actionID, ActionVersion: 3, TargetIPv4: "203.0.113.20",
		OriginalAddDigest:        originalAddDigest,
		PolicyDigest:             testDigest('b'),
		EvidenceSnapshotDigest:   testDigest('c'),
		ValidationSnapshotDigest: testDigest('d'),
		EligibilityValidUntil:    eligibleUntil,
		Session: hil.SessionBinding{
			SessionID: browser.session.ID.String(), SessionDigest: browser.session.TokenDigest.String(),
			ActorID: browser.session.ActorID, AuthenticatedAt: browser.session.AuthenticatedAt,
			ExpiresAt: browser.session.ExpiresAt,
		},
		IdempotencyKeyDigest: browser.idempotency.digest,
		Artifact:             revoke,
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := hil.CheckChallenge(hil.Challenge{
		SchemaVersion: hil.ChallengeSchemaVersion,
		ChallengeID:   "019b0000-0000-4000-8000-000000000202",
		SessionDigest: browser.session.TokenDigest.String(), Operation: hil.OperationRevoke,
		ResourceType: hil.ResourceEnforcementAction, ResourceID: actionID, ResourceVersion: 3,
		TargetIPv4: "203.0.113.20", PolicyDigest: testDigest('b'),
		GeneratedArtifactDigest: revoke.Digest(), CanonicalArtifactDigest: revoke.Digest(),
		OriginalAddDigest: &originalAddDigest, EvidenceSnapshotDigest: testDigest('c'),
		ValidationSnapshotDigest: testDigest('d'), ValidationValidUntil: eligibleUntil,
		NonceDigest: nonce.digest, AuthenticatedAt: browser.session.AuthenticatedAt,
		ReauthRequiredAfterSeconds: uint32(hil.ReauthAfter / time.Second),
		IssuedAt:                   now, ExpiresAt: eligibleUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := hil.BindRevocationChallenge(binding, challenge)
	if err != nil {
		t.Fatal(err)
	}
	reason, err := hil.CheckReason(hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion, ReasonCode: hil.ReasonEmergencyRevoke,
		ReasonText: "Emergency removal of synthetic unit-test entry",
	})
	if err != nil {
		t.Fatal(err)
	}
	input := RevocationDecisionInput{
		Browser: browser, CanonicalChallenge: bound.CanonicalBytes(),
		CanonicalRevokeArtifact: bound.RevokeArtifactBytes(), Nonce: nonce, Reason: reason,
		PolicyID: "019b0000-0000-4000-8000-000000000203", PolicyVersion: 7,
	}
	lookup, err := BindRevocationLookup(input)
	if err != nil {
		t.Fatal(err)
	}
	return input, lookup
}

func storedRevocationValues(t *testing.T, lookup RevocationLookup, now time.Time) []any {
	t.Helper()
	challenge := lookup.Challenge.Value()
	originalAddDigest := *challenge.OriginalAddDigest
	decisionID := "019b0000-0000-4000-8000-000000000210"
	validationID := "019b0000-0000-4000-8000-000000000211"
	ownedSchemaDigest := testDigest('f')
	decidedAt := now.Add(time.Second)
	validUntil := now.Add(2 * time.Minute)
	decision, err := hil.CheckDecision(hil.Decision{
		SchemaVersion: hil.DecisionSchemaVersion, DecisionID: decisionID,
		ChallengeID: challenge.ChallengeID, SessionDigest: lookup.Browser.session.TokenDigest.String(),
		Operation: hil.OperationRevoke, Decision: hil.DecisionRevoked,
		ResourceType: hil.ResourceEnforcementAction, ResourceID: challenge.ResourceID,
		ResourceVersion: challenge.ResourceVersion, TargetIPv4: challenge.TargetIPv4,
		PolicyDigest: challenge.PolicyDigest, GeneratedArtifactDigest: challenge.GeneratedArtifactDigest,
		CanonicalArtifactDigest: challenge.CanonicalArtifactDigest,
		OriginalAddDigest:       &originalAddDigest, EvidenceSnapshotDigest: challenge.EvidenceSnapshotDigest,
		ValidationSnapshotDigest: challenge.ValidationSnapshotDigest,
		ActorID:                  lookup.Browser.session.ActorID, ReasonDigest: lookup.Reason.Digest(),
		NonceDigest: lookup.Nonce.digest, IdempotencyKeyDigest: lookup.Browser.idempotency.digest,
		DecidedAt: decidedAt, DecisionValidUntil: validUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	reason := lookup.Reason.Value()
	reasonID := stableRevocationReasonID(decision.Value().ActorID, lookup.Reason.Digest())
	authorizationID := "019b0000-0000-4000-8000-000000000212"
	authorizationJCS := marshalRevokeAuthorization(
		challenge.ResourceID, decision.Value().ActorID, authorizationID,
		lookup.policyID, lookup.policyVersion, lookup, decidedAt, validUntil,
	)
	authorizationDigest := digestBytes(authorizationJCS)
	revocationID := "019b0000-0000-4000-8000-000000000213"
	outboxID := "019b0000-0000-4000-8000-000000000214"
	auditID := "019b0000-0000-4000-8000-000000000215"
	consumedAt := now.Add(2 * time.Second)
	consumedDecisionID := decisionID
	return []any{
		hil.DecisionSchemaVersion, decisionID, challenge.ChallengeID,
		lookup.Browser.session.TokenDigest.String(), string(hil.OperationRevoke),
		string(hil.DecisionRevoked), hil.ResourceEnforcementAction, challenge.ResourceID,
		int64(challenge.ResourceVersion), challenge.TargetIPv4, challenge.PolicyDigest,
		challenge.GeneratedArtifactDigest, challenge.CanonicalArtifactDigest,
		&originalAddDigest, challenge.EvidenceSnapshotDigest, challenge.ValidationSnapshotDigest,
		validationID, ownedSchemaDigest, decision.Value().ActorID, lookup.Reason.Digest(),
		lookup.Nonce.digest, lookup.Browser.idempotency.digest, decidedAt, validUntil,
		decision.CanonicalBytes(), decision.Digest(), lookup.Challenge.CanonicalBytes(),
		lookup.Challenge.Digest(), &consumedAt, &consumedDecisionID,
		reasonID, decision.Value().ActorID, "revoke", string(reason.ReasonCode), reason.ReasonText,
		lookup.Reason.CanonicalBytes(), lookup.Reason.Digest(), authorizationID,
		authorizationJCS, authorizationDigest, decidedAt, validUntil,
		revocationID, int64(challenge.ResourceVersion), lookup.Challenge.RevokeArtifactBytes(),
		lookup.Challenge.RevokeArtifactDigest(), originalAddDigest, "authorized",
		outboxID, int64(challenge.ResourceVersion), "dispatch_revoke", "revoke", authorizationDigest,
		lookup.Challenge.RevokeArtifactBytes(), lookup.Challenge.RevokeArtifactDigest(),
		originalAddDigest, authorizationDigest, authorizationID, (*string)(nil),
		lookup.policyID, int64(lookup.policyVersion), challenge.TargetIPv4,
		challenge.EvidenceSnapshotDigest, validationID, challenge.ValidationSnapshotDigest,
		decision.Value().ActorID, lookup.Reason.Digest(), ownedSchemaDigest, decidedAt, validUntil,
		auditID, 1,
	}
}
