package hil

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestConsumeApprovalBindsExactArtifactsAndIsIdempotent(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, issued, nonce, session, exact, idempotency := issueFixture(t, OperationApprove, clock)
	reason := Reason{SchemaVersion: ReasonSchemaVersion, ReasonCode: ReasonThreatConfirmed, ReasonText: "Cafe\u0301 attack confirmed"}
	request := DecisionRequest{
		Operation: OperationApprove, Session: session, Artifact: exact, Nonce: nonce,
		IdempotencyKey: idempotency, Reason: reason,
	}
	decision, err := service.Consume(issued.Guard(), request)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	value := decision.Value()
	if value.Decision != DecisionApproved || value.Operation != OperationApprove ||
		value.ActorID != session.ActorID || value.ChallengeID != issued.Challenge().Value().ChallengeID ||
		value.ResourceID != exact.PolicyID() || value.ResourceVersion != exact.PolicyVersion() ||
		value.PolicyDigest != exact.PolicyDigest() || value.GeneratedArtifactDigest != exact.GeneratedArtifactDigest() ||
		value.CanonicalArtifactDigest != exact.CanonicalArtifactDigest() ||
		value.EvidenceSnapshotDigest != exact.EvidenceSnapshotDigest() ||
		value.ValidationSnapshotDigest != exact.ValidationSnapshotDigest() || value.OriginalAddDigest != nil {
		t.Fatalf("decision binding = %+v", value)
	}
	if !value.DecisionValidUntil.Equal(issued.Challenge().Value().ExpiresAt) {
		t.Fatalf("decision validity = %s challenge=%s", value.DecisionValidUntil, issued.Challenge().Value().ExpiresAt)
	}
	if !decision.AuthorizesAt(testNow) || decision.AuthorizesAt(value.DecisionValidUntil) || decision.AuthorizesAt(time.Time{}) {
		t.Fatal("approval freshness/authorization boundary is wrong")
	}
	checkedReason, err := CheckReason(reason)
	if err != nil || value.ReasonDigest != checkedReason.Digest() ||
		!bytes.Equal(decision.ReasonCanonicalBytes(), checkedReason.CanonicalBytes()) ||
		!bytes.Equal(decision.CanonicalCommandBytes(), exact.CanonicalBytes()) {
		t.Fatalf("reason/command binding mismatch err=%v", err)
	}
	if decision.Digest() != digestBytes(decision.CanonicalBytes()) {
		t.Fatal("decision digest does not bind JCS bytes")
	}
	parsed, err := ParseCanonicalDecision(decision.CanonicalBytes())
	if err != nil || parsed.Digest() != decision.Digest() || parsed.AuthorizesAt(testNow) {
		t.Fatalf("parsed decision digest=%q authorizes=%v err=%v", parsed.Digest(), parsed.AuthorizesAt(testNow), err)
	}

	retry, err := service.Consume(issued.Guard(), request)
	if err != nil || retry.Digest() != decision.Digest() || retry.Value().DecisionID != value.DecisionID {
		t.Fatalf("idempotent retry digest=%q value=%+v err=%v", retry.Digest(), retry.Value(), err)
	}
	conflict := request
	conflict.Reason.ReasonText = "different decision"
	if _, err := service.Consume(issued.Guard(), conflict); !IsCode(err, ErrorConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
	if !issued.Guard().Consumed() {
		t.Fatal("guard did not record consumption")
	}
	stored, ok := issued.Guard().ConsumedDecision()
	if !ok || stored.Digest() != decision.Digest() {
		t.Fatalf("stored decision ok=%v digest=%q", ok, stored.Digest())
	}
	copyCommand := stored.CanonicalCommandBytes()
	copyCommand[0] ^= 1
	storedAgain, _ := issued.Guard().ConsumedDecision()
	if bytes.Equal(copyCommand, storedAgain.CanonicalCommandBytes()) {
		t.Fatal("stored decision leaked mutable bytes")
	}
}

func TestRejectDecisionNeverAuthorizes(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, issued, nonce, session, exact, idempotency := issueFixture(t, OperationReject, clock)
	decision, err := service.Consume(issued.Guard(), DecisionRequest{
		Operation: OperationReject, Session: session, Artifact: exact, Nonce: nonce,
		IdempotencyKey: idempotency, Reason: fixtureReason(OperationReject),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Value().Decision != DecisionRejected || decision.AuthorizesAt(testNow) {
		t.Fatal("rejection became enforcement authority")
	}
}

func TestConsumeFailsClosedWithoutConsuming(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DecisionRequest, *mutableClock, ExactArtifact)
		code   ErrorCode
	}{
		{"operation", func(r *DecisionRequest, _ *mutableClock, _ ExactArtifact) { r.Operation = OperationReject }, ErrorChallengeMismatch},
		{"idempotency", func(r *DecisionRequest, _ *mutableClock, _ ExactArtifact) {
			r.IdempotencyKey = []byte("fedcba9876543210")
		}, ErrorIdempotency},
		{"artifact bytes", func(r *DecisionRequest, _ *mutableClock, _ ExactArtifact) { r.Artifact.canonicalBytes[0] ^= 1 }, ErrorArtifactMismatch},
		{"session actor", func(r *DecisionRequest, _ *mutableClock, _ ExactArtifact) { r.Session.ActorID = "other-admin" }, ErrorAuthentication},
		{"nonce", func(r *DecisionRequest, _ *mutableClock, _ ExactArtifact) {
			r.Nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}, ErrorNonce},
		{"padded nonce", func(r *DecisionRequest, _ *mutableClock, _ ExactArtifact) { r.Nonce += "=" }, ErrorNonce},
		{"reason", func(r *DecisionRequest, _ *mutableClock, _ ExactArtifact) { r.Reason.ReasonText = "\x00" }, ErrorReason},
		{"challenge expired", func(_ *DecisionRequest, c *mutableClock, exact ExactArtifact) { c.Set(exact.ValidationValidUntil()) }, ErrorChallengeExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &mutableClock{now: testNow}
			service, issued, nonce, session, exact, idempotency := issueFixture(t, OperationApprove, clock)
			request := DecisionRequest{Operation: OperationApprove, Session: session, Artifact: exact, Nonce: nonce, IdempotencyKey: idempotency, Reason: fixtureReason(OperationApprove)}
			test.mutate(&request, clock, exact)
			if _, err := service.Consume(issued.Guard(), request); !IsCode(err, test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
			if issued.Guard().Consumed() {
				t.Fatal("invalid request consumed challenge")
			}
		})
	}

	if _, err := (*Service)(nil).Consume(nil, DecisionRequest{}); !IsCode(err, ErrorConfiguration) {
		t.Fatalf("nil consume error = %v", err)
	}
}

func TestConsumeRequiresStepUpAtDecisionTime(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, err := NewService(clock, deterministicEntropy(128))
	if err != nil {
		t.Fatal(err)
	}
	session := fixtureSession(testNow)
	session.AuthenticatedAt = testNow.Add(-ReauthAfter)
	exact := fixtureExact(t, testNow)
	idempotency := []byte("0123456789abcdef")
	issued, err := service.Issue(IssueRequest{Operation: OperationApprove, Session: session, Artifact: exact, IdempotencyKey: idempotency})
	if err != nil {
		t.Fatalf("issue at exact step-up boundary: %v", err)
	}
	nonce, _ := issued.TakeNonce()
	clock.Set(testNow.Add(time.Nanosecond))
	if _, err := service.Consume(issued.Guard(), DecisionRequest{
		Operation: OperationApprove, Session: session, Artifact: exact, Nonce: nonce,
		IdempotencyKey: idempotency, Reason: fixtureReason(OperationApprove),
	}); !IsCode(err, ErrorStepUpRequired) {
		t.Fatalf("decision step-up error = %v", err)
	}
	if issued.Guard().Consumed() {
		t.Fatal("stale authentication consumed challenge")
	}
}

func TestDecisionStrictParserAndValidation(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, issued, nonce, session, exact, idempotency := issueFixture(t, OperationApprove, clock)
	checked, err := service.Consume(issued.Guard(), DecisionRequest{
		Operation: OperationApprove, Session: session, Artifact: exact, Nonce: nonce,
		IdempotencyKey: idempotency, Reason: fixtureReason(OperationApprove),
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical := checked.CanonicalBytes()
	mutations := [][]byte{
		append([]byte{' '}, canonical...),
		append(bytes.Clone(canonical), '\n'),
		bytes.Replace(canonical, []byte(`"decision_id":`), []byte(`"decision_id":"019b0000-0000-4000-8000-000000000999","decision_id":`), 1),
		bytes.Replace(canonical, []byte(`"schema_version":`), []byte(`"unknown":1,"schema_version":`), 1),
		bytes.Repeat([]byte{'x'}, MaxDecisionBytes+1),
	}
	for index, mutation := range mutations {
		if _, err := ParseCanonicalDecision(mutation); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}

	base := checked.Value()
	tests := []struct {
		name string
		edit func(*Decision)
		code ErrorCode
	}{
		{"schema", func(v *Decision) { v.SchemaVersion = "v2" }, ErrorSchema},
		{"decision pair", func(v *Decision) { v.Decision = DecisionRejected }, ErrorSchema},
		{"resource", func(v *Decision) { v.DecisionID = "bad" }, ErrorField},
		{"actor", func(v *Decision) { v.ActorID = "UPPER" }, ErrorField},
		{"digest", func(v *Decision) { v.ReasonDigest = "bad" }, ErrorDigest},
		{"validity empty", func(v *Decision) { v.DecisionValidUntil = v.DecidedAt }, ErrorTime},
		{"validity overlong", func(v *Decision) { v.DecisionValidUntil = v.DecidedAt.Add(DecisionLifetime + time.Nanosecond) }, ErrorTime},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.edit(&value)
			if _, err := CheckDecision(value); !IsCode(err, test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}
}

func TestConcurrentConsumptionStoresOneDecision(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, issued, nonce, session, exact, idempotency := issueFixture(t, OperationApprove, clock)
	base := DecisionRequest{Operation: OperationApprove, Session: session, Artifact: exact, Nonce: nonce, IdempotencyKey: idempotency, Reason: fixtureReason(OperationApprove)}

	const workers = 64
	var wg sync.WaitGroup
	type result struct {
		digest string
		err    error
	}
	results := make(chan result, workers)
	for index := range workers {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			request := base
			if index%2 == 1 {
				request.Reason.ReasonText = "conflicting reason"
			}
			decision, err := service.Consume(issued.Guard(), request)
			results <- result{digest: decision.Digest(), err: err}
		}(index)
	}
	wg.Wait()
	close(results)
	successDigest := ""
	successes := 0
	conflicts := 0
	for result := range results {
		switch {
		case result.err == nil:
			successes++
			if successDigest == "" {
				successDigest = result.digest
			} else if successDigest != result.digest {
				t.Fatalf("multiple stored decision digests: %q and %q", successDigest, result.digest)
			}
		case IsCode(result.err, ErrorConflict):
			conflicts++
		default:
			t.Fatalf("unexpected race error: %v", result.err)
		}
	}
	if successes == 0 || conflicts == 0 || successes+conflicts != workers {
		t.Fatalf("success=%d conflict=%d", successes, conflicts)
	}
	stored, ok := issued.Guard().ConsumedDecision()
	if !ok || stored.Digest() != successDigest {
		t.Fatalf("stored ok=%v digest=%q want=%q", ok, stored.Digest(), successDigest)
	}
}

func TestConsumeEntropyFailureDoesNotConsume(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, err := NewService(clock, deterministicEntropy(16+NonceBytes))
	if err != nil {
		t.Fatal(err)
	}
	session := fixtureSession(testNow)
	exact := fixtureExact(t, testNow)
	idempotency := []byte("0123456789abcdef")
	issued, err := service.Issue(IssueRequest{Operation: OperationApprove, Session: session, Artifact: exact, IdempotencyKey: idempotency})
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := issued.TakeNonce()
	if _, err := service.Consume(issued.Guard(), DecisionRequest{
		Operation: OperationApprove, Session: session, Artifact: exact, Nonce: nonce,
		IdempotencyKey: idempotency, Reason: fixtureReason(OperationApprove),
	}); !IsCode(err, ErrorEntropy) {
		t.Fatalf("entropy error = %v", err)
	}
	if issued.Guard().Consumed() {
		t.Fatal("entropy failure consumed challenge")
	}
}
