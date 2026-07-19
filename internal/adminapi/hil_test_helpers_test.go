package adminapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/hilstore"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const (
	hilTestPolicyID     = "019b0000-0000-4000-8000-000000000101"
	hilTestIncidentID   = "019b0000-0000-4000-8000-000000000102"
	hilTestAnalysisID   = "019b0000-0000-4000-8000-000000000103"
	hilTestEvidenceID   = "019b0000-0000-4000-8000-000000000104"
	hilTestEventID      = "019b0000-0000-4000-8000-000000000105"
	hilTestValidationID = "019b0000-0000-4000-8000-000000000106"
	hilTestChallengeID  = "019b0000-0000-4000-8000-000000000107"
	hilTestDecisionID   = "019b0000-0000-4000-8000-000000000108"
	hilTestActionID     = "019b0000-0000-4000-8000-000000000109"
	hilTestOutboxID     = "019b0000-0000-4000-8000-000000000110"
	hilTestIdempotency  = "0123456789abcdef-hil-http"
)

func hilTestDigest(label byte) string {
	return "sha256:" + string(bytes.Repeat([]byte{label}, 64))
}

type fakeExactArtifactReader struct {
	mu       sync.Mutex
	artifact hil.ExactArtifact
	err      error
	calls    int
	policyID string
	version  uint32
}

func (reader *fakeExactArtifactReader) LoadExactArtifact(_ context.Context, policyID string, version uint32) (hil.ExactArtifact, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.calls++
	reader.policyID = policyID
	reader.version = version
	return reader.artifact, reader.err
}

func (reader *fakeExactArtifactReader) LoadHistoricalExactArtifact(_ context.Context, policyID string, version uint32) (hil.ExactArtifact, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.calls++
	reader.policyID = policyID
	reader.version = version
	return reader.artifact, reader.err
}

type fakeHILIssuedChallenge struct {
	mu        sync.Mutex
	challenge hil.CheckedChallenge
	nonce     string
	err       error
	takes     int
}

func (issued *fakeHILIssuedChallenge) Challenge() hil.CheckedChallenge {
	if issued == nil {
		return hil.CheckedChallenge{}
	}
	return issued.challenge
}

func (issued *fakeHILIssuedChallenge) TakeNonce() (string, error) {
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

func (*fakeHILIssuedChallenge) String() string {
	return "adminapi.fakeHILIssuedChallenge{nonce:[REDACTED]}"
}

type fakeHILStoredDecision struct {
	decision       hil.CheckedDecision
	actionID       string
	authorization  string
	outboxID       string
	sessionRotated bool
}

func (stored fakeHILStoredDecision) Decision() hil.CheckedDecision { return stored.decision }
func (stored fakeHILStoredDecision) ActionID() string              { return stored.actionID }
func (stored fakeHILStoredDecision) AuthorizationDigest() string   { return stored.authorization }
func (stored fakeHILStoredDecision) OutboxJobID() string           { return stored.outboxID }
func (stored fakeHILStoredDecision) SessionRotated() bool          { return stored.sessionRotated }
func (fakeHILStoredDecision) String() string {
	return "adminapi.fakeHILStoredDecision{decision:[REDACTED]}"
}

type fakeHILPersistence struct {
	mu sync.Mutex

	issued HILIssuedChallenge
	stored HILStoredDecision

	issueErr   error
	commitErr  error
	lookups    []fakeHILLookupResult
	commits    []fakeHILLookupResult
	lookupHook func(int)
	commitHook func(int)

	issueCalls  int
	lookupCalls int
	commitCalls int
	operation   hil.Operation
	artifact    hil.ExactArtifact
}

type fakeHILLookupResult struct {
	stored HILStoredDecision
	err    error
}

func (store *fakeHILPersistence) Issue(_ context.Context, request hilstore.IssueRequest) (HILIssuedChallenge, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.issueCalls++
	store.operation = request.Operation
	store.artifact = request.Artifact
	return store.issued, store.issueErr
}

func (store *fakeHILPersistence) LookupHistoricalDecision(_ context.Context, _ hilstore.DecisionLookup) (HILStoredDecision, error) {
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

func (store *fakeHILPersistence) Commit(_ context.Context, _ hilstore.PrivilegedDecisionCommit) (HILStoredDecision, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.commitCalls++
	if store.commitHook != nil {
		store.commitHook(store.commitCalls)
	}
	if len(store.commits) > 0 {
		result := store.commits[0]
		store.commits = store.commits[1:]
		return result.stored, result.err
	}
	return store.stored, store.commitErr
}

type hilTestBoundary struct {
	*fakeBoundary
	manager      *adminauth.SessionManager
	forceStepUp  bool
	stepUpErr    error
	rotationErr  error
	rotationCall int
	lastRotation adminauth.SessionRotation
}

func (boundary *hilTestBoundary) RequiresStepUp(record adminauth.SessionRecord) (bool, error) {
	if boundary.stepUpErr != nil {
		return false, boundary.stepUpErr
	}
	if boundary.forceStepUp {
		return true, nil
	}
	return boundary.manager.RequiresStepUp(record)
}

func (boundary *hilTestBoundary) RotateAfterPrivilege(record adminauth.SessionRecord, token string) (adminauth.SessionRotation, error) {
	boundary.rotationCall++
	if boundary.rotationErr != nil {
		return adminauth.SessionRotation{}, boundary.rotationErr
	}
	rotation, err := boundary.manager.RotateAfterPrivilege(record, token)
	if err == nil {
		boundary.lastRotation = rotation
	}
	return rotation, err
}

type hilHTTPFixture struct {
	handler     *Handler
	boundary    *hilTestBoundary
	sessions    *fakeStore
	reader      *fakeExactArtifactReader
	hil         *fakeHILPersistence
	policy      adminauth.CookiePolicy
	issued      adminauth.IssuedSession
	artifact    hil.ExactArtifact
	challenge   hil.CheckedChallenge
	nonce       string
	idempotency string
	now         time.Time
}

func newHILHTTPFixture(t *testing.T, operation hil.Operation) *hilHTTPFixture {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)}
	entropy := make([]byte, 512)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	manager, err := adminauth.NewSessionManager(bytes.Repeat([]byte{0x45}, 32), bytes.NewReader(entropy), clock)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	artifact := hilHTTPExactArtifact(t, clock.Now())
	policyValue, err := adminauth.NewCookiePolicy("__Host-sentinelflow", adminauth.CookieTransportTLS)
	if err != nil {
		t.Fatal(err)
	}
	base := &fakeBoundary{
		issued: issued, wantOrigin: testOrigin, wantToken: issued.SessionToken(), wantCSRF: issued.CSRFToken(),
	}
	boundary := &hilTestBoundary{fakeBoundary: base, manager: manager}
	sessions := &fakeStore{record: issued.Record}
	nonceRaw := bytes.Repeat([]byte{0x5a}, hil.NonceBytes)
	nonce := base64RawURL(nonceRaw)
	challenge := hilHTTPChallenge(t, operation, sessions.record, artifact, nonce, clock.Now())
	issuedChallenge := &fakeHILIssuedChallenge{challenge: challenge, nonce: nonce}
	reader := &fakeExactArtifactReader{artifact: artifact}
	hilPersistence := &fakeHILPersistence{issued: issuedChallenge}
	handler, err := NewHandler(Config{
		Boundary: boundary, Sessions: sessions, Cookies: policyValue,
		ExactArtifacts: reader, HIL: hilPersistence,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &hilHTTPFixture{
		handler: handler, boundary: boundary, sessions: sessions, reader: reader, hil: hilPersistence,
		policy: policyValue, issued: issued, artifact: artifact, challenge: challenge, nonce: nonce,
		idempotency: hilTestIdempotency, now: clock.Now(),
	}
}

func addHILBrowserCredential(t *testing.T, request *http.Request, fixture *hilHTTPFixture) {
	t.Helper()
	addCredential(t, request, fixture.policy, fixture.issued)
	request.Header.Set("X-CSRF-Token", fixture.issued.CSRFToken())
}

func hilChallengePath() string { return policyHILPathPrefix + hilTestPolicyID + "/decision-challenges" }
func hilDecisionPath() string  { return policyHILPathPrefix + hilTestPolicyID + "/decisions" }

func artifactRequestBody(artifact hil.ExactArtifact, operation hil.Operation) string {
	return fmt.Sprintf(`{"operation":%s,"policy_version":%d,"target_ipv4":%s,"ttl_seconds":%d,"policy_digest":%s,"generated_artifact_digest":%s,"canonical_artifact_digest":%s,"evidence_snapshot_digest":%s,"validation_snapshot_digest":%s}`,
		strconv.Quote(string(operation)), artifact.PolicyVersion(), strconv.Quote(artifact.TargetIPv4()), artifact.TTLSeconds(),
		strconv.Quote(artifact.PolicyDigest()), strconv.Quote(artifact.GeneratedArtifactDigest()),
		strconv.Quote(artifact.CanonicalArtifactDigest()), strconv.Quote(artifact.EvidenceSnapshotDigest()),
		strconv.Quote(artifact.ValidationSnapshotDigest()))
}

func decisionRequestBody(artifact hil.ExactArtifact, operation hil.Operation, challenge hil.CheckedChallenge, nonce string, reason hil.Reason) string {
	base := artifactRequestBody(artifact, operation)
	return strings.TrimSuffix(base, "}") + fmt.Sprintf(`,"challenge":%s,"challenge_nonce":%s,"reason":{"schema_version":%s,"reason_code":%s,"reason_text":%s}}`,
		challenge.CanonicalBytes(), strconv.Quote(nonce), strconv.Quote(reason.SchemaVersion),
		strconv.Quote(string(reason.ReasonCode)), strconv.Quote(reason.ReasonText))
}

func hilHTTPReason(operation hil.Operation) hil.Reason {
	if operation == hil.OperationReject {
		return hil.Reason{SchemaVersion: hil.ReasonSchemaVersion, ReasonCode: hil.ReasonFalsePositive, ReasonText: "Synthetic traffic is benign"}
	}
	return hil.Reason{SchemaVersion: hil.ReasonSchemaVersion, ReasonCode: hil.ReasonThreatConfirmed, ReasonText: "Confirmed synthetic attack"}
}

func hilHTTPStoredDecision(t *testing.T, operation hil.Operation, record adminauth.SessionRecord,
	artifact hil.ExactArtifact, challenge hil.CheckedChallenge, idempotency string, rotated bool,
) fakeHILStoredDecision {
	t.Helper()
	reason, err := hil.CheckReason(hilHTTPReason(operation))
	if err != nil {
		t.Fatal(err)
	}
	value := hil.DecisionRejected
	if operation == hil.OperationApprove {
		value = hil.DecisionApproved
	}
	checked, err := hil.CheckDecision(hil.Decision{
		SchemaVersion: hil.DecisionSchemaVersion, DecisionID: hilTestDecisionID,
		ChallengeID: challenge.Value().ChallengeID, SessionDigest: record.TokenDigest.String(),
		Operation: operation, Decision: value, ResourceType: hil.ResourcePolicy,
		ResourceID: artifact.PolicyID(), ResourceVersion: artifact.PolicyVersion(), TargetIPv4: artifact.TargetIPv4(),
		PolicyDigest: artifact.PolicyDigest(), GeneratedArtifactDigest: artifact.GeneratedArtifactDigest(),
		CanonicalArtifactDigest: artifact.CanonicalArtifactDigest(), EvidenceSnapshotDigest: artifact.EvidenceSnapshotDigest(),
		ValidationSnapshotDigest: artifact.ValidationSnapshotDigest(), ActorID: record.ActorID,
		ReasonDigest: reason.Digest(), NonceDigest: challenge.Value().NonceDigest,
		IdempotencyKeyDigest: digestBytes([]byte(idempotency)), DecidedAt: challenge.Value().IssuedAt.Add(time.Second),
		DecisionValidUntil: challenge.Value().ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := fakeHILStoredDecision{decision: checked, sessionRotated: rotated}
	if operation == hil.OperationApprove {
		stored.actionID = hilTestActionID
		stored.authorization = hilTestDigest('a')
		stored.outboxID = hilTestOutboxID
	}
	return stored
}

func hilHTTPChallenge(t *testing.T, operation hil.Operation, record adminauth.SessionRecord,
	artifact hil.ExactArtifact, nonce string, issuedAt time.Time,
) hil.CheckedChallenge {
	t.Helper()
	expiresAt := issuedAt.Add(hil.ChallengeLifetime)
	if artifact.ValidationValidUntil().Before(expiresAt) {
		expiresAt = artifact.ValidationValidUntil()
	}
	checked, err := hil.CheckChallenge(hil.Challenge{
		SchemaVersion: hil.ChallengeSchemaVersion, ChallengeID: hilTestChallengeID,
		SessionDigest: record.TokenDigest.String(), Operation: operation, ResourceType: hil.ResourcePolicy,
		ResourceID: artifact.PolicyID(), ResourceVersion: artifact.PolicyVersion(), TargetIPv4: artifact.TargetIPv4(),
		PolicyDigest: artifact.PolicyDigest(), GeneratedArtifactDigest: artifact.GeneratedArtifactDigest(),
		CanonicalArtifactDigest: artifact.CanonicalArtifactDigest(), EvidenceSnapshotDigest: artifact.EvidenceSnapshotDigest(),
		ValidationSnapshotDigest: artifact.ValidationSnapshotDigest(), ValidationValidUntil: artifact.ValidationValidUntil(),
		NonceDigest: digestBytes(mustDecodeBase64RawURL(nonce)), AuthenticatedAt: record.AuthenticatedAt,
		ReauthRequiredAfterSeconds: uint32(hil.ReauthAfter / time.Second), IssuedAt: issuedAt, ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return checked
}

func hilHTTPExactArtifact(t *testing.T, now time.Time) hil.ExactArtifact {
	t.Helper()
	evidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion, SnapshotID: "019b0000-0000-4000-8000-000000000111",
		IncidentID: hilTestIncidentID, IncidentVersion: 1, SourceIPv4: "203.0.113.20", ServiceLabel: "demo-app",
		WindowStart: now.Add(-10 * time.Minute), WindowEnd: now.Add(-2 * time.Minute),
		SourceHealthDigest: hilTestDigest('b'), EventIDs: []string{hilTestEventID}, SignalIDs: []string{hilTestEvidenceID},
		CreatedAt: now.Add(-2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	checkedPolicy, err := policy.CheckResponsePolicy(policy.ResponsePolicy{
		SchemaVersion: policy.PolicySchemaVersion, PolicyID: hilTestPolicyID, PolicyVersion: 3,
		IncidentID: hilTestIncidentID, AnalysisID: hilTestAnalysisID, Action: policy.ActionBlockIP,
		TargetIPv4: "203.0.113.20", TTLSeconds: 1800, EvidenceSnapshotDigest: evidence.Digest(),
		EvidenceIDs: []string{hilTestEvidenceID}, RationaleDigest: hilTestDigest('c'), CreatedAt: now.Add(-90 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	command, err := nftvalidate.Canonicalize([]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1800s }\n"), 1800)
	if err != nil {
		t.Fatal(err)
	}
	checks := []validation.ValidationCheck{
		{CheckID: validation.CheckStructuredOutput, Result: "pass", ReasonCode: "ok", InputDigest: hilTestDigest('d')},
		{CheckID: validation.CheckCommandGrammar, Result: "pass", ReasonCode: "ok", InputDigest: hilTestDigest('e')},
		{CheckID: validation.CheckPolicyEvidenceCommandConsistency, Result: "pass", ReasonCode: "ok", InputDigest: hilTestDigest('f')},
		{CheckID: validation.CheckProtectedNetwork, Result: "pass", ReasonCode: "ok", InputDigest: hilTestDigest('1')},
		{CheckID: validation.CheckOwnedSchemaSyntax, Result: "pass", ReasonCode: "ok", InputDigest: hilTestDigest('2')},
		{CheckID: validation.CheckHistoricalImpact, Result: "pass", ReasonCode: "ok", InputDigest: hilTestDigest('3')},
	}
	checkedValidation, err := validation.CheckValidationSnapshot(validation.ValidationSnapshot{
		SchemaVersion: validation.ValidationSnapshotSchemaVersion, ValidationID: hilTestValidationID,
		PolicyDigest: checkedPolicy.Digest(), EvidenceSnapshotDigest: evidence.Digest(),
		AnalysisInputDigest: hilTestDigest('4'), AnalysisOutputSchemaDigest: hilTestDigest('5'), PromptDigest: hilTestDigest('6'),
		GeneratedCandidateDigest: command.GeneratedDigest(), CanonicalArtifactDigest: command.CanonicalDigest(),
		GrammarVersion: nftvalidate.GrammarVersion, ParserVersion: nftvalidate.ParserVersion, ValidatorVersion: nftvalidate.ValidatorVersion,
		BaseChainContractRawDigest: nftvalidate.PinnedBaseChainRawDigest, LiveOwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest,
		ProtectedIPv4StaticDigest:          validation.PinnedProtectedIPv4Digest,
		ProtectedIPv4EffectiveConfigDigest: hilTestDigest('8'), NFTBinaryDigest: hilTestDigest('9'), NFTVersion: "1.1.0",
		HistoricalImpactDigest: hilTestDigest('0'), Checks: checks, CreatedAt: now.Add(-time.Minute), ValidUntil: now.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	exact, err := hil.CheckExactArtifact(hil.ExactArtifactInput{
		Policy: checkedPolicy, Command: command, Evidence: evidence, Validation: checkedValidation,
	})
	if err != nil {
		t.Fatal(err)
	}
	return exact
}

func base64RawURL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func mustDecodeBase64RawURL(value string) []byte {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

var _ HILPersistence = (*fakeHILPersistence)(nil)
