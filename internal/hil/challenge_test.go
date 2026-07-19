package hil

import (
	"bytes"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIssueCreatesExactBoundChallengeAndOneTimeNonce(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, err := NewService(clock, deterministicEntropy(16+NonceBytes))
	if err != nil {
		t.Fatal(err)
	}
	exact := fixtureExact(t, testNow)
	session := fixtureSession(testNow)
	idempotency := []byte("0123456789abcdef-challenge")
	issued, err := service.Issue(IssueRequest{
		Operation: OperationApprove, Session: session, Artifact: exact, IdempotencyKey: idempotency,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	challenge := issued.Challenge()
	value := challenge.Value()
	if value.SchemaVersion != ChallengeSchemaVersion || value.Operation != OperationApprove ||
		value.ResourceID != exact.PolicyID() || value.ResourceVersion != exact.PolicyVersion() ||
		value.PolicyDigest != exact.PolicyDigest() || value.GeneratedArtifactDigest != exact.GeneratedArtifactDigest() ||
		value.CanonicalArtifactDigest != exact.CanonicalArtifactDigest() ||
		value.EvidenceSnapshotDigest != exact.EvidenceSnapshotDigest() ||
		value.ValidationSnapshotDigest != exact.ValidationSnapshotDigest() || value.OriginalAddDigest != nil {
		t.Fatalf("challenge binding = %+v", value)
	}
	if !value.ExpiresAt.Equal(exact.ValidationValidUntil()) || value.ExpiresAt.Sub(value.IssuedAt) != 4*time.Minute {
		t.Fatalf("challenge expiry = %s validation=%s", value.ExpiresAt, exact.ValidationValidUntil())
	}
	if len(value.ChallengeID) != 36 || value.ChallengeID[14] != '4' || !strings.ContainsRune("89ab", rune(value.ChallengeID[19])) {
		t.Fatalf("challenge ID is not UUIDv4: %q", value.ChallengeID)
	}
	parsed, err := ParseCanonicalChallenge(challenge.CanonicalBytes())
	if err != nil || parsed.Digest() != challenge.Digest() {
		t.Fatalf("parse challenge: digest=%q err=%v", parsed.Digest(), err)
	}
	if challenge.Digest() != digestBytes(challenge.CanonicalBytes()) {
		t.Fatal("challenge digest does not bind exact JCS")
	}

	nonce, err := issued.TakeNonce()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != NonceBytes || digestBytes(raw) != value.NonceDigest {
		t.Fatalf("nonce binding length=%d digest=%q err=%v", len(raw), digestBytes(raw), err)
	}
	if _, err := issued.TakeNonce(); !IsCode(err, ErrorNonceUnavailable) {
		t.Fatalf("second nonce error = %v", err)
	}
	if strings.Contains(issued.String(), nonce) || strings.Contains(issued.GoString(), nonce) {
		t.Fatal("issued challenge formatting exposed nonce")
	}

	record := issued.Guard().Record()
	if record.ActorID != session.ActorID || record.SessionID != session.SessionID ||
		record.IdempotencyKeyDigest != digestBytes(idempotency) ||
		!bytes.Equal(record.CanonicalCommandBytes, exact.CanonicalBytes()) {
		t.Fatalf("record binding = %+v", record)
	}
	record.CanonicalCommandBytes[0] ^= 1
	if bytes.Equal(record.CanonicalCommandBytes, issued.Guard().Record().CanonicalCommandBytes) {
		t.Fatal("record leaked mutable canonical command bytes")
	}
}

func TestIssueRejectsStaleAuthValidationAndBadInputs(t *testing.T) {
	exact := fixtureExact(t, testNow)
	validSession := fixtureSession(testNow)
	validID := []byte("0123456789abcdef")
	tests := []struct {
		name    string
		clock   time.Time
		request IssueRequest
		code    ErrorCode
	}{
		{"operation", testNow, IssueRequest{Operation: "revoke", Session: validSession, Artifact: exact, IdempotencyKey: validID}, ErrorField},
		{"idempotency short", testNow, IssueRequest{Operation: OperationApprove, Session: validSession, Artifact: exact, IdempotencyKey: []byte("short")}, ErrorIdempotency},
		{"artifact zero", testNow, IssueRequest{Operation: OperationApprove, Session: validSession, IdempotencyKey: validID}, ErrorArtifact},
		{"session invalid", testNow, IssueRequest{Operation: OperationApprove, Session: SessionBinding{}, Artifact: exact, IdempotencyKey: validID}, ErrorAuthentication},
		{"step up", testNow, IssueRequest{Operation: OperationApprove, Session: func() SessionBinding {
			s := validSession
			s.AuthenticatedAt = testNow.Add(-ReauthAfter - time.Nanosecond)
			return s
		}(), Artifact: exact, IdempotencyKey: validID}, ErrorStepUpRequired},
		{"validation future", exact.ValidationCreatedAt().Add(-time.Nanosecond), IssueRequest{Operation: OperationApprove, Session: func() SessionBinding {
			s := validSession
			s.AuthenticatedAt = exact.ValidationCreatedAt().Add(-time.Minute)
			return s
		}(), Artifact: exact, IdempotencyKey: validID}, ErrorValidationStale},
		{"validation expired", exact.ValidationValidUntil(), IssueRequest{Operation: OperationApprove, Session: validSession, Artifact: exact, IdempotencyKey: validID}, ErrorValidationStale},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &mutableClock{now: test.clock}
			service, err := NewService(clock, deterministicEntropy(128))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Issue(test.request); !IsCode(err, test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}

	if _, err := NewService(nil, bytes.NewReader(nil)); !IsCode(err, ErrorConfiguration) {
		t.Fatalf("nil clock error = %v", err)
	}
	if _, err := NewService(&mutableClock{now: testNow}, nil); !IsCode(err, ErrorConfiguration) {
		t.Fatalf("nil entropy error = %v", err)
	}
	service, _ := NewService(&mutableClock{now: testNow}, deterministicEntropy(16))
	if _, err := service.Issue(IssueRequest{Operation: OperationApprove, Session: validSession, Artifact: exact, IdempotencyKey: validID}); !IsCode(err, ErrorEntropy) {
		t.Fatalf("entropy error = %v", err)
	}
}

func TestChallengeStrictParserAndValidation(t *testing.T) {
	clock := &mutableClock{now: testNow}
	_, issued, _, _, _, _ := issueFixture(t, OperationApprove, clock)
	canonical := issued.Challenge().CanonicalBytes()
	mutations := [][]byte{
		append([]byte{' '}, canonical...),
		append(bytes.Clone(canonical), '\n'),
		bytes.Replace(canonical, []byte(`"challenge_id":`), []byte(`"challenge_id":"019b0000-0000-4000-8000-000000000999","challenge_id":`), 1),
		bytes.Replace(canonical, []byte(`"schema_version":`), []byte(`"unknown":1,"schema_version":`), 1),
		bytes.Repeat([]byte{'x'}, MaxChallengeBytes+1),
	}
	for index, mutation := range mutations {
		if _, err := ParseCanonicalChallenge(mutation); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}

	base := issued.Challenge().Value()
	tests := []struct {
		name string
		edit func(*Challenge)
		code ErrorCode
	}{
		{"schema", func(v *Challenge) { v.SchemaVersion = "v2" }, ErrorSchema},
		{"resource", func(v *Challenge) { v.ResourceID = "bad" }, ErrorField},
		{"digest", func(v *Challenge) { v.PolicyDigest = "bad" }, ErrorDigest},
		{"reauth", func(v *Challenge) { v.ReauthRequiredAfterSeconds = 1 }, ErrorField},
		{"expiry", func(v *Challenge) { v.ExpiresAt = v.IssuedAt }, ErrorTime},
		{"overlong", func(v *Challenge) { v.ExpiresAt = v.IssuedAt.Add(ChallengeLifetime + time.Nanosecond) }, ErrorTime},
		{"beyond validation", func(v *Challenge) { v.ExpiresAt = v.ValidationValidUntil.Add(time.Nanosecond) }, ErrorTime},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.edit(&value)
			if _, err := CheckChallenge(value); !IsCode(err, test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}
}

func TestTakeNonceConcurrentExactlyOnce(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, err := NewService(clock, deterministicEntropy(16+NonceBytes))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Issue(IssueRequest{
		Operation: OperationApprove,
		Session:   fixtureSession(testNow), Artifact: fixtureExact(t, testNow),
		IdempotencyKey: []byte("0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := issued.TakeNonce()
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !IsCode(err, ErrorNonceUnavailable) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("nonce successes = %d, want 1", successes)
	}
}
