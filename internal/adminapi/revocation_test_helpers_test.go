package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/hilstore"
	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

const (
	revocationTestActionID        = "019b0000-0000-4000-8000-000000000201"
	revocationTestDecisionID      = "019b0000-0000-4000-8000-000000000202"
	revocationTestRevocationID    = "019b0000-0000-4000-8000-000000000203"
	revocationTestAuthorizationID = "019b0000-0000-4000-8000-000000000204"
	revocationTestOutboxID        = "019b0000-0000-4000-8000-000000000205"
	revocationTestAuditID         = "019b0000-0000-4000-8000-000000000206"
	revocationTestChallengeID     = "019b0000-0000-4000-8000-000000000207"
	revocationTestTarget          = "203.0.113.20"
	revocationTestIdempotency     = "0123456789abcdef-revocation-http"
)

type fakeRevocationIssued struct {
	mu            sync.Mutex
	challenge     hil.CheckedRevocationChallenge
	policyID      string
	policyVersion uint32
	nonce         string
	err           error
	takes         int
}

func (issued *fakeRevocationIssued) Challenge() hil.CheckedRevocationChallenge {
	if issued == nil {
		return hil.CheckedRevocationChallenge{}
	}
	return issued.challenge
}

func (issued *fakeRevocationIssued) PolicyID() string {
	if issued == nil {
		return ""
	}
	return issued.policyID
}

func (issued *fakeRevocationIssued) PolicyVersion() uint32 {
	if issued == nil {
		return 0
	}
	return issued.policyVersion
}

func (issued *fakeRevocationIssued) TakeNonce() (string, error) {
	issued.mu.Lock()
	defer issued.mu.Unlock()
	issued.takes++
	if issued.err != nil {
		return "", issued.err
	}
	if issued.takes != 1 || issued.nonce == "" {
		return "", hilstore.ErrNotFound
	}
	return issued.nonce, nil
}

func (*fakeRevocationIssued) String() string {
	return "adminapi.fakeRevocationIssued{nonce:[REDACTED],artifact:[REDACTED]}"
}

type fakeStoredRevocation struct {
	decision            hil.CheckedRevocationDecision
	revocationID        string
	authorizationID     string
	authorizationDigest string
	outboxID            string
	auditID             string
	sessionRotated      bool
}

func (stored fakeStoredRevocation) Decision() hil.CheckedRevocationDecision { return stored.decision }
func (stored fakeStoredRevocation) RevocationID() string                    { return stored.revocationID }
func (stored fakeStoredRevocation) AuthorizationID() string                 { return stored.authorizationID }
func (stored fakeStoredRevocation) AuthorizationDigest() string             { return stored.authorizationDigest }
func (stored fakeStoredRevocation) OutboxJobID() string                     { return stored.outboxID }
func (stored fakeStoredRevocation) AuditEventID() string                    { return stored.auditID }
func (stored fakeStoredRevocation) SessionRotated() bool                    { return stored.sessionRotated }
func (fakeStoredRevocation) String() string {
	return "adminapi.fakeStoredRevocation{decision:[REDACTED],artifact:[REDACTED]}"
}

type fakeRevocationResult struct {
	stored RevocationStoredResult
	err    error
}

type fakeRevocationPersistence struct {
	mu sync.Mutex

	issued RevocationIssuedChallenge
	stored RevocationStoredResult

	issueErr error
	commits  []fakeRevocationResult
	lookups  []fakeRevocationResult

	issueCalls  int
	commitCalls int
	lookupCalls int
	request     hilstore.RevocationIssueRequest
	commitHook  func(int)
	lookupHook  func(int)
	commitSeen  []hilstore.PrivilegedRevocationCommit
}

func (store *fakeRevocationPersistence) IssueRevocation(
	_ context.Context,
	request hilstore.RevocationIssueRequest,
) (RevocationIssuedChallenge, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.issueCalls++
	store.request = request
	return store.issued, store.issueErr
}

func (store *fakeRevocationPersistence) LookupHistoricalRevocation(
	_ context.Context,
	_ hilstore.RevocationLookup,
) (RevocationStoredResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.lookupCalls++
	if store.lookupHook != nil {
		store.lookupHook(store.lookupCalls)
	}
	if len(store.lookups) == 0 {
		return nil, hilstore.ErrNotFound
	}
	result := store.lookups[0]
	store.lookups = store.lookups[1:]
	return result.stored, result.err
}

func (store *fakeRevocationPersistence) CommitRevocation(
	_ context.Context,
	commit hilstore.PrivilegedRevocationCommit,
) (RevocationStoredResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.commitCalls++
	store.commitSeen = append(store.commitSeen, commit)
	if store.commitHook != nil {
		store.commitHook(store.commitCalls)
	}
	if len(store.commits) == 0 {
		return store.stored, nil
	}
	result := store.commits[0]
	store.commits = store.commits[1:]
	return result.stored, result.err
}

type revocationHTTPFixture struct {
	handler         *Handler
	boundary        *hilTestBoundary
	sessions        *fakeStore
	store           *fakeRevocationPersistence
	policy          adminauth.CookiePolicy
	issuedSession   adminauth.IssuedSession
	issuedChallenge *fakeRevocationIssued
	challenge       hil.CheckedRevocationChallenge
	artifact        lifecycleartifact.CheckedRevokeArtifact
	nonce           string
	originalDigest  string
	policyID        string
	policyVersion   uint32
	actionID        string
	actionVersion   uint32
	now             time.Time
}

func newRevocationHTTPFixture(t *testing.T) *revocationHTTPFixture {
	t.Helper()
	base := newHILHTTPFixture(t, hil.OperationApprove)
	actionVersion := uint32(3)
	originalDigest := hilTestDigest('7')
	nonce := base64RawURL(bytes.Repeat([]byte{0x6a}, hil.NonceBytes))
	artifact, challenge := revocationHTTPChallenge(
		t, base.sessions.record, revocationTestActionID, actionVersion,
		revocationTestTarget, originalDigest, revocationTestIdempotency, nonce, base.now,
	)
	issued := &fakeRevocationIssued{
		challenge: challenge, policyID: hilTestPolicyID,
		policyVersion: base.artifact.PolicyVersion(), nonce: nonce,
	}
	store := &fakeRevocationPersistence{issued: issued}
	handler, err := NewHandler(Config{
		Boundary: base.boundary, Sessions: base.sessions, Cookies: base.policy,
		ExactArtifacts: base.reader, HIL: base.hil, Revocations: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &revocationHTTPFixture{
		handler: handler, boundary: base.boundary, sessions: base.sessions,
		store: store, policy: base.policy, issuedSession: base.issued,
		issuedChallenge: issued, challenge: challenge, artifact: artifact,
		nonce: nonce, originalDigest: originalDigest, policyID: hilTestPolicyID,
		policyVersion: base.artifact.PolicyVersion(), actionID: revocationTestActionID,
		actionVersion: actionVersion, now: base.now,
	}
}

func revocationHTTPChallenge(
	t testing.TB,
	record adminauth.SessionRecord,
	actionID string,
	actionVersion uint32,
	targetIPv4 string,
	originalDigest string,
	idempotency string,
	nonce string,
	issuedAt time.Time,
) (lifecycleartifact.CheckedRevokeArtifact, hil.CheckedRevocationChallenge) {
	t.Helper()
	artifact, err := lifecycleartifact.CheckRevokeArtifact(targetIPv4)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := issuedAt.Add(4 * time.Minute)
	binding, err := hil.CheckRevocationBinding(hil.RevocationBindingInput{
		ActionID: actionID, ActionVersion: actionVersion, TargetIPv4: targetIPv4,
		OriginalAddDigest: originalDigest, PolicyDigest: hilTestDigest('c'),
		EvidenceSnapshotDigest: hilTestDigest('b'), ValidationSnapshotDigest: hilTestDigest('d'),
		EligibilityValidUntil: eligibility,
		Session: hil.SessionBinding{
			SessionID: record.ID.String(), SessionDigest: record.TokenDigest.String(),
			ActorID: record.ActorID, AuthenticatedAt: record.AuthenticatedAt, ExpiresAt: record.ExpiresAt,
		},
		IdempotencyKeyDigest: digestBytes([]byte(idempotency)), Artifact: artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	original := originalDigest
	checked, err := hil.CheckChallenge(hil.Challenge{
		SchemaVersion: hil.ChallengeSchemaVersion, ChallengeID: revocationTestChallengeID,
		SessionDigest: record.TokenDigest.String(), Operation: hil.OperationRevoke,
		ResourceType: hil.ResourceEnforcementAction, ResourceID: actionID,
		ResourceVersion: actionVersion, TargetIPv4: targetIPv4,
		PolicyDigest: hilTestDigest('c'), GeneratedArtifactDigest: artifact.Digest(),
		CanonicalArtifactDigest: artifact.Digest(), OriginalAddDigest: &original,
		EvidenceSnapshotDigest: hilTestDigest('b'), ValidationSnapshotDigest: hilTestDigest('d'),
		ValidationValidUntil: eligibility, NonceDigest: digestBytes(mustDecodeBase64RawURL(nonce)),
		AuthenticatedAt:            record.AuthenticatedAt,
		ReauthRequiredAfterSeconds: uint32(hil.ReauthAfter / time.Second),
		IssuedAt:                   issuedAt, ExpiresAt: eligibility,
	})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := hil.BindRevocationChallenge(binding, checked)
	if err != nil {
		t.Fatal(err)
	}
	return artifact, bound
}

func revocationHTTPStored(
	t testing.TB,
	fixture *revocationHTTPFixture,
	record adminauth.SessionRecord,
	reason hil.Reason,
	rotated bool,
) fakeStoredRevocation {
	t.Helper()
	checkedReason, err := hil.CheckReason(reason)
	if err != nil {
		t.Fatal(err)
	}
	challengeValue := fixture.challenge.Value()
	original := fixture.originalDigest
	decision, err := hil.CheckDecision(hil.Decision{
		SchemaVersion: hil.DecisionSchemaVersion, DecisionID: revocationTestDecisionID,
		ChallengeID: challengeValue.ChallengeID, SessionDigest: record.TokenDigest.String(),
		Operation: hil.OperationRevoke, Decision: hil.DecisionRevoked,
		ResourceType: hil.ResourceEnforcementAction, ResourceID: fixture.actionID,
		ResourceVersion: fixture.actionVersion, TargetIPv4: revocationTestTarget,
		PolicyDigest:            challengeValue.PolicyDigest,
		GeneratedArtifactDigest: fixture.artifact.Digest(), CanonicalArtifactDigest: fixture.artifact.Digest(),
		OriginalAddDigest: &original, EvidenceSnapshotDigest: challengeValue.EvidenceSnapshotDigest,
		ValidationSnapshotDigest: challengeValue.ValidationSnapshotDigest,
		ActorID:                  record.ActorID, ReasonDigest: checkedReason.Digest(),
		NonceDigest:          challengeValue.NonceDigest,
		IdempotencyKeyDigest: digestBytes([]byte(revocationTestIdempotency)),
		DecidedAt:            challengeValue.IssuedAt.Add(time.Second),
		DecisionValidUntil:   challengeValue.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := hil.BindRevocationDecision(fixture.challenge, decision, checkedReason)
	if err != nil {
		t.Fatal(err)
	}
	authorizationDigest, ok := revocationAuthorizationDigest(
		bound.Value(), revocationTestAuthorizationID, fixture.policyID, fixture.policyVersion,
	)
	if !ok {
		t.Fatal("construct revocation authorization digest")
	}
	return fakeStoredRevocation{
		decision: bound, revocationID: revocationTestRevocationID,
		authorizationID:     revocationTestAuthorizationID,
		authorizationDigest: authorizationDigest, outboxID: revocationTestOutboxID,
		auditID: revocationTestAuditID, sessionRotated: rotated,
	}
}

func revocationReason() hil.Reason {
	return hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion,
		ReasonCode:    hil.ReasonOperatorRequest,
		ReasonText:    "Remove the synthetic block",
	}
}

func revocationChallengeBody(fixture *revocationHTTPFixture) string {
	return fmt.Sprintf(`{"action_version":%d,"target_ipv4":%s,"original_add_digest":%s}`,
		fixture.actionVersion, strconv.Quote(revocationTestTarget), strconv.Quote(fixture.originalDigest))
}

func revocationDecisionBody(fixture *revocationHTTPFixture, reason hil.Reason) string {
	document := map[string]any{
		"action_version": fixture.actionVersion, "target_ipv4": revocationTestTarget,
		"original_add_digest":       fixture.originalDigest,
		"challenge":                 json.RawMessage(fixture.challenge.CanonicalBytes()),
		"challenge_nonce":           fixture.nonce,
		"canonical_revoke_artifact": string(fixture.artifact.CanonicalBytes()),
		"policy_id":                 fixture.policyID, "policy_version": fixture.policyVersion,
		"reason": map[string]any{
			"schema_version": reason.SchemaVersion,
			"reason_code":    reason.ReasonCode,
			"reason_text":    reason.ReasonText,
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func revocationChallengePath(fixture *revocationHTTPFixture) string {
	return revocationPathPrefix + fixture.actionID + "/revocation-challenges"
}

func revocationDecisionPath(fixture *revocationHTTPFixture) string {
	return revocationPathPrefix + fixture.actionID + "/revocations"
}

func addRevocationBrowserCredential(t *testing.T, request *http.Request, fixture *revocationHTTPFixture) {
	t.Helper()
	addCredential(t, request, fixture.policy, fixture.issuedSession)
	request.Header.Set("X-CSRF-Token", fixture.issuedSession.CSRFToken())
}

var _ RevocationPersistence = (*fakeRevocationPersistence)(nil)
