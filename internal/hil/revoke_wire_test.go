package hil

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

const (
	testActionID    = "019b0000-0000-4000-8000-000000000201"
	testChallengeID = "019b0000-0000-4000-8000-000000000202"
	testDecisionID  = "019b0000-0000-4000-8000-000000000203"
	testRevokeBytes = "delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n"
)

func revokeChallengeFixture() Challenge {
	originalAddDigest := testDigest('e')
	revokeDigest := digestBytes([]byte(testRevokeBytes))
	return Challenge{
		SchemaVersion:              ChallengeSchemaVersion,
		ChallengeID:                testChallengeID,
		SessionDigest:              testDigest('a'),
		Operation:                  OperationRevoke,
		ResourceType:               ResourceEnforcementAction,
		ResourceID:                 testActionID,
		ResourceVersion:            2,
		TargetIPv4:                 "203.0.113.20",
		PolicyDigest:               testDigest('b'),
		GeneratedArtifactDigest:    revokeDigest,
		CanonicalArtifactDigest:    revokeDigest,
		OriginalAddDigest:          &originalAddDigest,
		EvidenceSnapshotDigest:     testDigest('f'),
		ValidationSnapshotDigest:   testDigest('7'),
		ValidationValidUntil:       testNow.Add(5 * ChallengeLifetime),
		NonceDigest:                testDigest('8'),
		AuthenticatedAt:            testNow.Add(-ChallengeLifetime),
		ReauthRequiredAfterSeconds: uint32(ReauthAfter.Seconds()),
		IssuedAt:                   testNow,
		ExpiresAt:                  testNow.Add(ChallengeLifetime),
	}
}

func revokeDecisionFixture() (Decision, []byte, []byte) {
	originalAddDigest := testDigest('e')
	command := []byte(testRevokeBytes)
	reason := []byte(`{"reason_code":"emergency_revoke","reason_text":"Operator requested removal","schema_version":"hil-reason-v1"}`)
	return Decision{
		SchemaVersion:            DecisionSchemaVersion,
		DecisionID:               testDecisionID,
		ChallengeID:              testChallengeID,
		SessionDigest:            testDigest('a'),
		Operation:                OperationRevoke,
		Decision:                 DecisionRevoked,
		ResourceType:             ResourceEnforcementAction,
		ResourceID:               testActionID,
		ResourceVersion:          2,
		TargetIPv4:               "203.0.113.20",
		PolicyDigest:             testDigest('b'),
		GeneratedArtifactDigest:  digestBytes(command),
		CanonicalArtifactDigest:  digestBytes(command),
		OriginalAddDigest:        &originalAddDigest,
		EvidenceSnapshotDigest:   testDigest('f'),
		ValidationSnapshotDigest: testDigest('7'),
		ActorID:                  "admin-demo",
		ReasonDigest:             digestBytes(reason),
		NonceDigest:              testDigest('8'),
		IdempotencyKeyDigest:     testDigest('9'),
		DecidedAt:                testNow,
		DecisionValidUntil:       testNow.Add(DecisionLifetime),
	}, command, reason
}

func expectedRevokeChallengeJCS(value Challenge) []byte {
	return []byte(fmt.Sprintf(
		`{"authenticated_at":"2026-07-18T02:55:00.123Z","canonical_artifact_digest":"%s","challenge_id":"%s","evidence_snapshot_digest":"%s","expires_at":"2026-07-18T03:05:00.123Z","generated_artifact_digest":"%s","issued_at":"2026-07-18T03:00:00.123Z","nonce_digest":"%s","operation":"revoke","original_add_digest":"%s","policy_digest":"%s","reauth_required_after_seconds":900,"resource_id":"%s","resource_type":"enforcement_action","resource_version":2,"schema_version":"hil-challenge-v1","session_digest":"%s","target_ipv4":"203.0.113.20","validation_snapshot_digest":"%s","validation_valid_until":"2026-07-18T03:25:00.123Z"}`,
		value.CanonicalArtifactDigest,
		value.ChallengeID,
		value.EvidenceSnapshotDigest,
		value.GeneratedArtifactDigest,
		value.NonceDigest,
		*value.OriginalAddDigest,
		value.PolicyDigest,
		value.ResourceID,
		value.SessionDigest,
		value.ValidationSnapshotDigest,
	))
}

func expectedRevokeDecisionJCS(value Decision) []byte {
	return []byte(fmt.Sprintf(
		`{"actor_id":"admin-demo","canonical_artifact_digest":"%s","challenge_id":"%s","decided_at":"2026-07-18T03:00:00.123Z","decision":"revoked","decision_id":"%s","decision_valid_until":"2026-07-18T03:05:00.123Z","evidence_snapshot_digest":"%s","generated_artifact_digest":"%s","idempotency_key_digest":"%s","nonce_digest":"%s","operation":"revoke","original_add_digest":"%s","policy_digest":"%s","reason_digest":"%s","resource_id":"%s","resource_type":"enforcement_action","resource_version":2,"schema_version":"hil-decision-v1","session_digest":"%s","target_ipv4":"203.0.113.20","validation_snapshot_digest":"%s"}`,
		value.CanonicalArtifactDigest,
		value.ChallengeID,
		value.DecisionID,
		value.EvidenceSnapshotDigest,
		value.GeneratedArtifactDigest,
		value.IdempotencyKeyDigest,
		value.NonceDigest,
		*value.OriginalAddDigest,
		value.PolicyDigest,
		value.ReasonDigest,
		value.ResourceID,
		value.SessionDigest,
		value.ValidationSnapshotDigest,
	))
}

func TestRevokeWireRequiresIdenticalArtifactDigests(t *testing.T) {
	t.Run("challenge", func(t *testing.T) {
		value := revokeChallengeFixture()
		value.GeneratedArtifactDigest = testDigest('c')
		if _, err := CheckChallenge(value); !IsCode(err, ErrorArtifactMismatch) {
			t.Fatalf("mismatched revoke challenge digests error=%v", err)
		}
		checked, err := CheckChallenge(revokeChallengeFixture())
		if err != nil {
			t.Fatal(err)
		}
		valid := checked.CanonicalBytes()
		mismatch := bytes.Replace(valid, []byte(revokeChallengeFixture().GeneratedArtifactDigest), []byte(testDigest('c')), 1)
		if _, err := ParseCanonicalChallenge(mismatch); !IsCode(err, ErrorArtifactMismatch) {
			t.Fatalf("parsed mismatched revoke challenge digests error=%v", err)
		}
	})

	t.Run("decision", func(t *testing.T) {
		value, _, _ := revokeDecisionFixture()
		value.GeneratedArtifactDigest = testDigest('c')
		if _, err := CheckDecision(value); !IsCode(err, ErrorArtifactMismatch) {
			t.Fatalf("mismatched revoke decision digests error=%v", err)
		}
		validValue, _, _ := revokeDecisionFixture()
		checked, err := CheckDecision(validValue)
		if err != nil {
			t.Fatal(err)
		}
		valid := checked.CanonicalBytes()
		mismatch := bytes.Replace(valid, []byte(validValue.GeneratedArtifactDigest), []byte(testDigest('c')), 1)
		if _, err := ParseCanonicalDecision(mismatch); !IsCode(err, ErrorArtifactMismatch) {
			t.Fatalf("parsed mismatched revoke decision digests error=%v", err)
		}
	})
}

func TestRevokeDigestInvariantPreservesPolicyWireBranches(t *testing.T) {
	for _, operation := range []Operation{OperationApprove, OperationReject} {
		t.Run(string(operation), func(t *testing.T) {
			clock := &mutableClock{now: testNow}
			service, issued, nonce, session, exact, idempotency := issueFixture(t, operation, clock)
			challenge := issued.Challenge()
			challengeValue := challenge.Value()
			if challengeValue.GeneratedArtifactDigest == challengeValue.CanonicalArtifactDigest {
				t.Fatal("fixture no longer proves generated/canonical policy digest compatibility")
			}
			parsedChallenge, err := ParseCanonicalChallenge(challenge.CanonicalBytes())
			if err != nil || parsedChallenge.Digest() != challenge.Digest() {
				t.Fatalf("policy challenge roundtrip digest=%q err=%v", parsedChallenge.Digest(), err)
			}
			decision, err := service.Consume(issued.Guard(), DecisionRequest{
				Operation: operation, Session: session, Artifact: exact, Nonce: nonce,
				IdempotencyKey: idempotency, Reason: fixtureReason(operation),
			})
			if err != nil {
				t.Fatalf("consume policy decision: %v", err)
			}
			decisionValue := decision.Value()
			if decisionValue.GeneratedArtifactDigest == decisionValue.CanonicalArtifactDigest {
				t.Fatal("policy decision lost generated/canonical digest distinction")
			}
			parsedDecision, err := ParseCanonicalDecision(decision.CanonicalBytes())
			if err != nil || parsedDecision.Digest() != decision.Digest() {
				t.Fatalf("policy decision roundtrip digest=%q err=%v", parsedDecision.Digest(), err)
			}
		})
	}
}

func TestRevokeChallengeCanonicalRoundTripAndDefensiveCopies(t *testing.T) {
	value := revokeChallengeFixture()
	originalPointer := value.OriginalAddDigest
	checked, err := CheckChallenge(value)
	if err != nil {
		t.Fatalf("check revoke challenge: %v", err)
	}
	want := expectedRevokeChallengeJCS(value)
	if !bytes.Equal(checked.CanonicalBytes(), want) {
		t.Fatalf("canonical revoke challenge = %s\nwant = %s", checked.CanonicalBytes(), want)
	}
	parsed, err := ParseCanonicalChallenge(want)
	if err != nil || parsed.Digest() != checked.Digest() {
		t.Fatalf("parse revoke challenge digest=%q err=%v", parsed.Digest(), err)
	}

	*originalPointer = testDigest('1')
	got := checked.Value()
	if got.OriginalAddDigest == nil || *got.OriginalAddDigest != testDigest('e') {
		t.Fatalf("caller mutation changed checked digest: %v", got.OriginalAddDigest)
	}
	*got.OriginalAddDigest = testDigest('2')
	canonicalCopy := checked.CanonicalBytes()
	canonicalCopy[0] ^= 1
	got = checked.Value()
	if *got.OriginalAddDigest != testDigest('e') || !bytes.Equal(checked.CanonicalBytes(), want) {
		t.Fatal("challenge accessor leaked mutable state")
	}
}

func TestRevokeDecisionCanonicalRoundTripNeverAuthorizesAdd(t *testing.T) {
	value, command, reason := revokeDecisionFixture()
	originalPointer := value.OriginalAddDigest
	checked, err := CheckDecision(value)
	if err != nil {
		t.Fatalf("check revoke decision: %v", err)
	}
	want := expectedRevokeDecisionJCS(value)
	if !bytes.Equal(checked.CanonicalBytes(), want) {
		t.Fatalf("canonical revoke decision = %s\nwant = %s", checked.CanonicalBytes(), want)
	}
	parsed, err := ParseCanonicalDecision(want)
	if err != nil || parsed.Digest() != checked.Digest() {
		t.Fatalf("parse revoke decision digest=%q err=%v", parsed.Digest(), err)
	}
	if checked.AuthorizesAt(testNow) || parsed.AuthorizesAt(testNow) {
		t.Fatal("checked or parsed revoke decision authorized an add")
	}
	bound := cloneDecision(checked)
	bound.reasonCanonical = bytes.Clone(reason)
	bound.canonicalCommandBytes = bytes.Clone(command)
	if bound.AuthorizesAt(testNow) {
		t.Fatal("revoke decision with digest-matching private bytes authorized an add")
	}

	*originalPointer = testDigest('1')
	got := checked.Value()
	if got.OriginalAddDigest == nil || *got.OriginalAddDigest != testDigest('e') {
		t.Fatalf("caller mutation changed checked digest: %v", got.OriginalAddDigest)
	}
	*got.OriginalAddDigest = testDigest('2')
	canonicalCopy := checked.CanonicalBytes()
	canonicalCopy[0] ^= 1
	got = checked.Value()
	if *got.OriginalAddDigest != testDigest('e') || !bytes.Equal(checked.CanonicalBytes(), want) {
		t.Fatal("decision accessor leaked mutable state")
	}
}

func TestChallengeOperationResourceAndOriginalDigestBranches(t *testing.T) {
	revoke := revokeChallengeFixture()
	policy := revoke
	policy.Operation = OperationApprove
	policy.ResourceType = ResourcePolicy
	policy.OriginalAddDigest = nil
	if _, err := CheckChallenge(policy); err != nil {
		t.Fatalf("valid approve branch: %v", err)
	}
	policy.Operation = OperationReject
	if _, err := CheckChallenge(policy); err != nil {
		t.Fatalf("valid reject branch: %v", err)
	}

	tests := []struct {
		name string
		edit func(*Challenge)
		code ErrorCode
	}{
		{"approve action resource", func(v *Challenge) { v.Operation = OperationApprove }, ErrorSchema},
		{"reject action resource", func(v *Challenge) { v.Operation = OperationReject }, ErrorSchema},
		{"approve non-null original", func(v *Challenge) {
			v.Operation = OperationApprove
			v.ResourceType = ResourcePolicy
		}, ErrorSchema},
		{"reject non-null original", func(v *Challenge) {
			v.Operation = OperationReject
			v.ResourceType = ResourcePolicy
		}, ErrorSchema},
		{"revoke policy resource", func(v *Challenge) { v.ResourceType = ResourcePolicy }, ErrorSchema},
		{"revoke null original", func(v *Challenge) { v.OriginalAddDigest = nil }, ErrorSchema},
		{"revoke empty original", func(v *Challenge) { empty := ""; v.OriginalAddDigest = &empty }, ErrorDigest},
		{"revoke malformed original", func(v *Challenge) { malformed := "sha256:ABC"; v.OriginalAddDigest = &malformed }, ErrorDigest},
		{"unknown operation", func(v *Challenge) { v.Operation = "remove" }, ErrorSchema},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := revokeChallengeFixture()
			test.edit(&value)
			if _, err := CheckChallenge(value); !IsCode(err, test.code) {
				t.Fatalf("error=%v want=%s", err, test.code)
			}
		})
	}
}

func TestDecisionOperationValueResourceAndOriginalDigestBranches(t *testing.T) {
	operations := []Operation{OperationApprove, OperationReject, OperationRevoke}
	decisions := []DecisionValue{DecisionApproved, DecisionRejected, DecisionRevoked}
	for _, operation := range operations {
		for _, decision := range decisions {
			name := string(operation) + "_" + string(decision)
			t.Run(name, func(t *testing.T) {
				value, _, _ := revokeDecisionFixture()
				value.Operation = operation
				value.Decision = decision
				if operation != OperationRevoke {
					value.ResourceType = ResourcePolicy
					value.OriginalAddDigest = nil
				}
				_, err := CheckDecision(value)
				validPair := operation == OperationApprove && decision == DecisionApproved ||
					operation == OperationReject && decision == DecisionRejected ||
					operation == OperationRevoke && decision == DecisionRevoked
				if validPair && err != nil {
					t.Fatalf("valid pair rejected: %v", err)
				}
				if !validPair && !IsCode(err, ErrorSchema) {
					t.Fatalf("mismatched pair error=%v", err)
				}
			})
		}
	}

	tests := []struct {
		name string
		edit func(*Decision)
		code ErrorCode
	}{
		{"approve action resource", func(v *Decision) {
			v.Operation = OperationApprove
			v.Decision = DecisionApproved
			v.OriginalAddDigest = nil
		}, ErrorSchema},
		{"reject action resource", func(v *Decision) {
			v.Operation = OperationReject
			v.Decision = DecisionRejected
			v.OriginalAddDigest = nil
		}, ErrorSchema},
		{"approve non-null original", func(v *Decision) {
			v.Operation = OperationApprove
			v.Decision = DecisionApproved
			v.ResourceType = ResourcePolicy
		}, ErrorSchema},
		{"reject non-null original", func(v *Decision) {
			v.Operation = OperationReject
			v.Decision = DecisionRejected
			v.ResourceType = ResourcePolicy
		}, ErrorSchema},
		{"revoke policy resource", func(v *Decision) { v.ResourceType = ResourcePolicy }, ErrorSchema},
		{"revoke null original", func(v *Decision) { v.OriginalAddDigest = nil }, ErrorSchema},
		{"revoke empty original", func(v *Decision) { empty := ""; v.OriginalAddDigest = &empty }, ErrorDigest},
		{"revoke malformed original", func(v *Decision) { malformed := "sha256:ABC"; v.OriginalAddDigest = &malformed }, ErrorDigest},
		{"unknown operation", func(v *Decision) { v.Operation = "remove" }, ErrorSchema},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, _, _ := revokeDecisionFixture()
			test.edit(&value)
			if _, err := CheckDecision(value); !IsCode(err, test.code) {
				t.Fatalf("error=%v want=%s", err, test.code)
			}
		})
	}
}

func TestRevokeCanonicalParsersRejectBranchAndEncodingMutations(t *testing.T) {
	challengeValue := revokeChallengeFixture()
	challenge, err := CheckChallenge(challengeValue)
	if err != nil {
		t.Fatal(err)
	}
	decisionValue, _, _ := revokeDecisionFixture()
	decision, err := CheckDecision(decisionValue)
	if err != nil {
		t.Fatal(err)
	}
	original := *challengeValue.OriginalAddDigest

	challengeMutations := []struct {
		name string
		data []byte
		code ErrorCode
	}{
		{"null original", bytes.Replace(challenge.CanonicalBytes(), []byte(`"original_add_digest":"`+original+`"`), []byte(`"original_add_digest":null`), 1), ErrorSchema},
		{"policy resource", bytes.Replace(challenge.CanonicalBytes(), []byte(`"resource_type":"enforcement_action"`), []byte(`"resource_type":"policy"`), 1), ErrorSchema},
		{"approve with digest", bytes.Replace(challenge.CanonicalBytes(), []byte(`"operation":"revoke"`), []byte(`"operation":"approve"`), 1), ErrorSchema},
		{"malformed digest", bytes.Replace(challenge.CanonicalBytes(), []byte(original), []byte("sha256:"+string(bytes.Repeat([]byte{'A'}, 64))), 1), ErrorDigest},
		{"noncanonical order", bytes.Replace(challenge.CanonicalBytes(), []byte(`"operation":"revoke","original_add_digest":"`+original+`"`), []byte(`"original_add_digest":"`+original+`","operation":"revoke"`), 1), ErrorCanonical},
		{"duplicate original", bytes.Replace(challenge.CanonicalBytes(), []byte(`"original_add_digest":`), []byte(`"original_add_digest":null,"original_add_digest":`), 1), ErrorEncoding},
	}
	for _, test := range challengeMutations {
		t.Run("challenge_"+test.name, func(t *testing.T) {
			if _, err := ParseCanonicalChallenge(test.data); !IsCode(err, test.code) {
				t.Fatalf("error=%v want=%s data=%s", err, test.code, test.data)
			}
		})
	}

	decisionMutations := []struct {
		name string
		data []byte
		code ErrorCode
	}{
		{"null original", bytes.Replace(decision.CanonicalBytes(), []byte(`"original_add_digest":"`+original+`"`), []byte(`"original_add_digest":null`), 1), ErrorSchema},
		{"policy resource", bytes.Replace(decision.CanonicalBytes(), []byte(`"resource_type":"enforcement_action"`), []byte(`"resource_type":"policy"`), 1), ErrorSchema},
		{"approved pair", bytes.Replace(decision.CanonicalBytes(), []byte(`"decision":"revoked"`), []byte(`"decision":"approved"`), 1), ErrorSchema},
		{"reject pair", bytes.Replace(decision.CanonicalBytes(), []byte(`"operation":"revoke"`), []byte(`"operation":"reject"`), 1), ErrorSchema},
		{"malformed digest", bytes.Replace(decision.CanonicalBytes(), []byte(original), []byte("sha256:"+string(bytes.Repeat([]byte{'A'}, 64))), 1), ErrorDigest},
		{"noncanonical order", bytes.Replace(decision.CanonicalBytes(), []byte(`"operation":"revoke","original_add_digest":"`+original+`"`), []byte(`"original_add_digest":"`+original+`","operation":"revoke"`), 1), ErrorCanonical},
		{"duplicate original", bytes.Replace(decision.CanonicalBytes(), []byte(`"original_add_digest":`), []byte(`"original_add_digest":null,"original_add_digest":`), 1), ErrorEncoding},
	}
	for _, test := range decisionMutations {
		t.Run("decision_"+test.name, func(t *testing.T) {
			if _, err := ParseCanonicalDecision(test.data); !IsCode(err, test.code) {
				t.Fatalf("error=%v want=%s data=%s", err, test.code, test.data)
			}
		})
	}
}

func TestRevokeCheckedArtifactsAreConcurrencySafeCopies(t *testing.T) {
	challenge, err := CheckChallenge(revokeChallengeFixture())
	if err != nil {
		t.Fatal(err)
	}
	decisionValue, _, _ := revokeDecisionFixture()
	decision, err := CheckDecision(decisionValue)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 64
	var wg sync.WaitGroup
	errors := make(chan string, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			challengeValue := challenge.Value()
			decisionValue := decision.Value()
			if challengeValue.OriginalAddDigest == nil || decisionValue.OriginalAddDigest == nil {
				errors <- "missing copied original digest"
				return
			}
			*challengeValue.OriginalAddDigest = testDigest('1')
			*decisionValue.OriginalAddDigest = testDigest('2')
			challengeBytes := challenge.CanonicalBytes()
			decisionBytes := decision.CanonicalBytes()
			challengeBytes[0] ^= 1
			decisionBytes[0] ^= 1
			if challenge.Digest() != digestBytes(challenge.DigestInput()) ||
				decision.Digest() != digestBytes(decision.DigestInput()) {
				errors <- "digest or canonical bytes changed"
			}
		}()
	}
	wg.Wait()
	close(errors)
	for message := range errors {
		t.Error(message)
	}
	if *challenge.Value().OriginalAddDigest != testDigest('e') ||
		*decision.Value().OriginalAddDigest != testDigest('e') {
		t.Fatal("concurrent access mutated checked artifact")
	}
}

func TestPolicyServiceDoesNotIssueOrConsumeRevoke(t *testing.T) {
	clock := &mutableClock{now: testNow}
	service, err := NewService(clock, deterministicEntropy(256))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Issue(IssueRequest{
		Operation: OperationRevoke, Session: fixtureSession(testNow),
		Artifact: fixtureExact(t, testNow), IdempotencyKey: []byte("0123456789abcdef"),
	}); !IsCode(err, ErrorField) {
		t.Fatalf("policy service revoke issue error=%v", err)
	}

	service, issued, nonce, session, exact, idempotency := issueFixture(t, OperationApprove, clock)
	if _, err := service.Consume(issued.Guard(), DecisionRequest{
		Operation: OperationRevoke, Session: session, Artifact: exact, Nonce: nonce,
		IdempotencyKey: idempotency, Reason: fixtureReason(OperationApprove),
	}); !IsCode(err, ErrorChallengeMismatch) {
		t.Fatalf("policy service revoke consume error=%v", err)
	}
	if issued.Guard().Consumed() {
		t.Fatal("revoke request consumed policy challenge")
	}
}
