package hil

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const (
	testPolicyID     = "019b0000-0000-4000-8000-000000000101"
	testIncidentID   = "019b0000-0000-4000-8000-000000000102"
	testAnalysisID   = "019b0000-0000-4000-8000-000000000103"
	testEvidenceID   = "019b0000-0000-4000-8000-000000000104"
	testEventID      = "019b0000-0000-4000-8000-000000000105"
	testValidationID = "019b0000-0000-4000-8000-000000000106"
	testSessionID    = "019b0000-0000-4000-8000-000000000107"
)

var testNow = time.Date(2026, 7, 18, 3, 0, 0, 123_000_000, time.UTC)

func testDigest(label byte) string {
	return "sha256:" + string(bytes.Repeat([]byte{label}, 64))
}

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) Set(value time.Time) {
	c.mu.Lock()
	c.now = value
	c.mu.Unlock()
}

func fixtureSession(now time.Time) SessionBinding {
	return SessionBinding{
		SessionID:       testSessionID,
		SessionDigest:   testDigest('a'),
		ActorID:         "admin-demo",
		AuthenticatedAt: now.Add(-5 * time.Minute),
		ExpiresAt:       now.Add(time.Hour),
	}
}

func fixtureReason(operation Operation) Reason {
	if operation == OperationReject {
		return Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonFalsePositive, ReasonText: "Benign retry pattern"}
	}
	return Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonThreatConfirmed, ReasonText: "Confirmed attack pattern"}
}

func fixtureExactInput(t *testing.T, now time.Time) ExactArtifactInput {
	t.Helper()
	evidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion:      validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:         "019b0000-0000-4000-8000-000000000108",
		IncidentID:         testIncidentID,
		IncidentVersion:    1,
		SourceIPv4:         "203.0.113.20",
		ServiceLabel:       "demo-app",
		WindowStart:        now.Add(-10 * time.Minute),
		WindowEnd:          now.Add(-2 * time.Minute),
		SourceHealthDigest: testDigest('b'),
		EventIDs:           []string{testEventID},
		SignalIDs:          []string{testEvidenceID},
		CreatedAt:          now.Add(-2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("check evidence: %v", err)
	}
	checkedPolicy, err := policy.CheckResponsePolicy(policy.ResponsePolicy{
		SchemaVersion:          policy.PolicySchemaVersion,
		PolicyID:               testPolicyID,
		PolicyVersion:          3,
		IncidentID:             testIncidentID,
		AnalysisID:             testAnalysisID,
		Action:                 policy.ActionBlockIP,
		TargetIPv4:             "203.0.113.20",
		TTLSeconds:             1800,
		EvidenceSnapshotDigest: evidence.Digest(),
		EvidenceIDs:            []string{testEvidenceID},
		RationaleDigest:        testDigest('c'),
		CreatedAt:              now.Add(-90 * time.Second),
	})
	if err != nil {
		t.Fatalf("check policy: %v", err)
	}
	command, err := nftvalidate.Canonicalize([]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1800s }\n"), 1800)
	if err != nil {
		t.Fatalf("canonicalize command: %v", err)
	}
	checks := []validation.ValidationCheck{
		{CheckID: validation.CheckStructuredOutput, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('d')},
		{CheckID: validation.CheckCommandGrammar, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('e')},
		{CheckID: validation.CheckPolicyEvidenceCommandConsistency, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('f')},
		{CheckID: validation.CheckProtectedNetwork, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('1')},
		{CheckID: validation.CheckOwnedSchemaSyntax, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('2')},
		{CheckID: validation.CheckHistoricalImpact, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('3')},
	}
	checkedValidation, err := validation.CheckValidationSnapshot(validation.ValidationSnapshot{
		SchemaVersion:                      validation.ValidationSnapshotSchemaVersion,
		ValidationID:                       testValidationID,
		PolicyDigest:                       checkedPolicy.Digest(),
		EvidenceSnapshotDigest:             evidence.Digest(),
		AnalysisInputDigest:                testDigest('4'),
		AnalysisOutputSchemaDigest:         testDigest('5'),
		PromptDigest:                       testDigest('6'),
		GeneratedCandidateDigest:           command.GeneratedDigest(),
		CanonicalArtifactDigest:            command.CanonicalDigest(),
		GrammarVersion:                     nftvalidate.GrammarVersion,
		ParserVersion:                      nftvalidate.ParserVersion,
		ValidatorVersion:                   nftvalidate.ValidatorVersion,
		BaseChainContractRawDigest:         nftvalidate.PinnedBaseChainRawDigest,
		LiveOwnedSchemaDigest:              nftvalidate.PinnedLiveSchemaDigest,
		ProtectedIPv4StaticDigest:          validation.PinnedProtectedIPv4Digest,
		ProtectedIPv4EffectiveConfigDigest: testDigest('8'),
		NFTBinaryDigest:                    testDigest('9'),
		NFTVersion:                         "1.1.0",
		HistoricalImpactDigest:             testDigest('0'),
		Checks:                             checks,
		CreatedAt:                          now.Add(-time.Minute),
		ValidUntil:                         now.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatalf("check validation: %v", err)
	}
	return ExactArtifactInput{
		Policy:     checkedPolicy,
		Command:    command,
		Evidence:   evidence,
		Validation: checkedValidation,
	}
}

func fixtureExact(t *testing.T, now time.Time) ExactArtifact {
	t.Helper()
	checked, err := CheckExactArtifact(fixtureExactInput(t, now))
	if err != nil {
		t.Fatalf("check exact artifact: %v", err)
	}
	return checked
}

func deterministicEntropy(length int) *bytes.Reader {
	data := make([]byte, length)
	for index := range data {
		data[index] = byte(index + 1)
	}
	return bytes.NewReader(data)
}

func issueFixture(t *testing.T, operation Operation, clock *mutableClock) (*Service, *IssuedChallenge, string, SessionBinding, ExactArtifact, []byte) {
	t.Helper()
	service, err := NewService(clock, deterministicEntropy(16+NonceBytes+16+64))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	session := fixtureSession(clock.Now())
	exact := fixtureExact(t, clock.Now())
	idempotency := []byte("0123456789abcdef-fixture")
	issued, err := service.Issue(IssueRequest{
		Operation: operation, Session: session, Artifact: exact, IdempotencyKey: idempotency,
	})
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	nonce, err := issued.TakeNonce()
	if err != nil {
		t.Fatalf("take nonce: %v", err)
	}
	return service, issued, nonce, session, exact, idempotency
}
