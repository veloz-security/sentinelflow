package hil

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

func validRevocationBindingInput(t testing.TB) RevocationBindingInput {
	t.Helper()
	artifact, err := lifecycleartifact.CheckRevokeArtifact("203.0.113.20")
	if err != nil {
		t.Fatalf("check revoke artifact: %v", err)
	}
	challenge := boundedRevokeChallengeFixture()
	return RevocationBindingInput{
		ActionID:                 challenge.ResourceID,
		ActionVersion:            challenge.ResourceVersion,
		TargetIPv4:               challenge.TargetIPv4,
		OriginalAddDigest:        *challenge.OriginalAddDigest,
		PolicyDigest:             challenge.PolicyDigest,
		EvidenceSnapshotDigest:   challenge.EvidenceSnapshotDigest,
		ValidationSnapshotDigest: challenge.ValidationSnapshotDigest,
		EligibilityValidUntil:    challenge.ValidationValidUntil,
		Session:                  fixtureSession(testNow),
		IdempotencyKeyDigest:     testDigest('9'),
		Artifact:                 artifact,
	}
}

func boundedRevokeChallengeFixture() Challenge {
	challenge := revokeChallengeFixture()
	challenge.ValidationValidUntil = challenge.IssuedAt.Add(ChallengeLifetime)
	return challenge
}

func checkedRevocationBinding(t testing.TB) CheckedRevocationBinding {
	t.Helper()
	checked, err := CheckRevocationBinding(validRevocationBindingInput(t))
	if err != nil {
		t.Fatalf("check revocation binding: %v", err)
	}
	return checked
}

func checkedRevocationChallenge(t testing.TB, binding CheckedRevocationBinding, value Challenge) CheckedRevocationChallenge {
	t.Helper()
	challenge, err := CheckChallenge(value)
	if err != nil {
		t.Fatalf("check revoke challenge: %v", err)
	}
	checked, err := BindRevocationChallenge(binding, challenge)
	if err != nil {
		t.Fatalf("bind revoke challenge: %v", err)
	}
	return checked
}

func checkedRevocationReason(t testing.TB) CheckedReason {
	t.Helper()
	_, _, canonical := revokeDecisionFixture()
	checked, err := ParseCanonicalReason(canonical)
	if err != nil {
		t.Fatalf("parse revoke reason: %v", err)
	}
	return checked
}

func checkedRevocationDecision(t testing.TB, challenge CheckedRevocationChallenge, value Decision, reason CheckedReason) CheckedRevocationDecision {
	t.Helper()
	decision, err := CheckDecision(value)
	if err != nil {
		t.Fatalf("check revoke decision: %v", err)
	}
	checked, err := BindRevocationDecision(challenge, decision, reason)
	if err != nil {
		t.Fatalf("bind revoke decision: %v", err)
	}
	return checked
}

func TestRevocationBindingProducesRevokeOnlyDefensiveResult(t *testing.T) {
	binding := checkedRevocationBinding(t)
	challenge := checkedRevocationChallenge(t, binding, boundedRevokeChallengeFixture())
	reason := checkedRevocationReason(t)
	decisionValue, _, _ := revokeDecisionFixture()
	decision := checkedRevocationDecision(t, challenge, decisionValue, reason)

	if binding.ActionID() != testActionID || binding.ActionVersion() != 2 ||
		binding.TargetIPv4() != "203.0.113.20" ||
		binding.RevokeArtifactDigest() != digestBytes([]byte(testRevokeBytes)) {
		t.Fatalf("binding fields do not match lifecycle state: %+v", binding)
	}
	if challenge.Digest() != digestBytes(challenge.CanonicalBytes()) ||
		challenge.RevokeArtifactDigest() != binding.RevokeArtifactDigest() {
		t.Fatal("challenge lost exact revoke binding")
	}
	if decision.Digest() != digestBytes(decision.CanonicalBytes()) ||
		decision.ChallengeDigest() != challenge.Digest() ||
		decision.RevokeArtifactDigest() != binding.RevokeArtifactDigest() ||
		!bytes.Equal(decision.ReasonCanonicalBytes(), reason.CanonicalBytes()) {
		t.Fatal("decision lost challenge, reason, or artifact binding")
	}
	if !decision.RevokesAt(decisionValue.DecidedAt) ||
		decision.RevokesAt(decisionValue.DecisionValidUntil) || decision.RevokesAt(time.Time{}) {
		t.Fatal("revoke authority time boundary is wrong")
	}
	if (CheckedRevocationDecision{}).RevokesAt(testNow) {
		t.Fatal("zero revocation decision granted authority")
	}

	for _, copyBytes := range [][]byte{
		binding.RevokeArtifactBytes(), challenge.CanonicalBytes(), challenge.RevokeArtifactBytes(),
		decision.CanonicalBytes(), decision.ReasonCanonicalBytes(), decision.RevokeArtifactBytes(),
	} {
		copyBytes[0] ^= 1
	}
	value := decision.Value()
	*value.OriginalAddDigest = testDigest('1')
	if !decision.RevokesAt(decisionValue.DecidedAt) ||
		!bytes.Equal(decision.RevokeArtifactBytes(), []byte(testRevokeBytes)) ||
		!bytes.Equal(decision.ReasonCanonicalBytes(), reason.CanonicalBytes()) ||
		*decision.Value().OriginalAddDigest != testDigest('e') {
		t.Fatal("revocation result leaked mutable state")
	}

	resultType := reflect.TypeOf(CheckedRevocationDecision{})
	for _, forbidden := range []string{"AuthorizesAt", "CanonicalCommandBytes", "CheckedDecision"} {
		if _, ok := resultType.MethodByName(forbidden); ok {
			t.Fatalf("revocation result exposes add-authority method %q", forbidden)
		}
	}
	formatted := []any{validRevocationBindingInput(t), binding, challenge, decision}
	for _, value := range formatted {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			got := fmt.Sprintf(format, value)
			for _, secret := range []string{
				testActionID, "203.0.113.20", testDigest('e'), testDigest('9'),
				testRevokeBytes, string(reason.CanonicalBytes()),
			} {
				if bytes.Contains([]byte(got), []byte(secret)) {
					t.Fatalf("format %q exposed %q in %q", format, secret, got)
				}
			}
		}
	}
}

func TestCheckRevocationBindingRejectsZeroForgedAndMismatchedArtifacts(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RevocationBindingInput)
		code ErrorCode
	}{
		{"zero artifact", func(v *RevocationBindingInput) { v.Artifact = lifecycleartifact.CheckedRevokeArtifact{} }, ErrorArtifact},
		{"action id", func(v *RevocationBindingInput) { v.ActionID = "bad" }, ErrorField},
		{"action version", func(v *RevocationBindingInput) { v.ActionVersion = 0 }, ErrorField},
		{"target", func(v *RevocationBindingInput) { v.TargetIPv4 = "203.0.113.21" }, ErrorArtifactMismatch},
		{"original digest", func(v *RevocationBindingInput) { v.OriginalAddDigest = "bad" }, ErrorDigest},
		{"policy digest", func(v *RevocationBindingInput) { v.PolicyDigest = "bad" }, ErrorDigest},
		{"evidence digest", func(v *RevocationBindingInput) { v.EvidenceSnapshotDigest = "bad" }, ErrorDigest},
		{"validation digest", func(v *RevocationBindingInput) { v.ValidationSnapshotDigest = "bad" }, ErrorDigest},
		{"eligibility", func(v *RevocationBindingInput) { v.EligibilityValidUntil = time.Time{} }, ErrorTime},
		{"session", func(v *RevocationBindingInput) { v.Session.SessionDigest = "bad" }, ErrorAuthentication},
		{"idempotency", func(v *RevocationBindingInput) { v.IdempotencyKeyDigest = "bad" }, ErrorDigest},
		{"other artifact", func(v *RevocationBindingInput) {
			artifact, err := lifecycleartifact.CheckRevokeArtifact("203.0.113.21")
			if err != nil {
				t.Fatal(err)
			}
			v.Artifact = artifact
		}, ErrorArtifactMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validRevocationBindingInput(t)
			test.edit(&input)
			if _, err := CheckRevocationBinding(input); !IsCode(err, test.code) {
				t.Fatalf("error=%v want=%s", err, test.code)
			}
		})
	}

	input := validRevocationBindingInput(t)
	input.Artifact = forgeCheckedRevokeValue(input.Artifact, "203.0.113.21", input.Artifact.Digest())
	if _, err := CheckRevocationBinding(input); !IsCode(err, ErrorArtifact) {
		t.Fatalf("forged checked value error=%v", err)
	}
	input = validRevocationBindingInput(t)
	input.Artifact = forgeCheckedRevokeValue(input.Artifact, input.TargetIPv4, testDigest('1'))
	if _, err := CheckRevocationBinding(input); !IsCode(err, ErrorArtifact) {
		t.Fatalf("forged checked digest error=%v", err)
	}
}

// checkedRevokeLayout mirrors the private lifecycleartifact layout only to
// prove this package reparses instead of trusting a forged checked wrapper.
type checkedRevokeLayout struct {
	value     lifecycleartifact.RevokeValue
	canonical string
	digest    string
}

func forgeCheckedRevokeValue(
	value lifecycleartifact.CheckedRevokeArtifact,
	target string,
	digest string,
) lifecycleartifact.CheckedRevokeArtifact {
	forged := value
	layout := (*checkedRevokeLayout)(unsafe.Pointer(&forged))
	layout.value.TargetIPv4 = target
	layout.digest = digest
	return forged
}

func TestBindRevocationChallengeRejectsEveryLifecycleMutation(t *testing.T) {
	binding := checkedRevocationBinding(t)
	tests := []struct {
		name string
		edit func(*Challenge)
		code ErrorCode
	}{
		{"cross operation", func(v *Challenge) {
			v.Operation = OperationApprove
			v.ResourceType = ResourcePolicy
			v.OriginalAddDigest = nil
		}, ErrorChallengeMismatch},
		{"action id", func(v *Challenge) { v.ResourceID = testPolicyID }, ErrorArtifactMismatch},
		{"action version", func(v *Challenge) { v.ResourceVersion++ }, ErrorArtifactMismatch},
		{"target", func(v *Challenge) { v.TargetIPv4 = "203.0.113.21" }, ErrorArtifactMismatch},
		{"policy", func(v *Challenge) { v.PolicyDigest = testDigest('1') }, ErrorArtifactMismatch},
		{"artifact", func(v *Challenge) {
			v.GeneratedArtifactDigest = testDigest('1')
			v.CanonicalArtifactDigest = testDigest('1')
		}, ErrorArtifactMismatch},
		{"original add", func(v *Challenge) { changed := testDigest('1'); v.OriginalAddDigest = &changed }, ErrorArtifactMismatch},
		{"evidence", func(v *Challenge) { v.EvidenceSnapshotDigest = testDigest('1') }, ErrorArtifactMismatch},
		{"validation", func(v *Challenge) { v.ValidationSnapshotDigest = testDigest('1') }, ErrorArtifactMismatch},
		{"eligibility", func(v *Challenge) { v.ValidationValidUntil = v.ValidationValidUntil.Add(time.Second) }, ErrorArtifactMismatch},
		{"session", func(v *Challenge) { v.SessionDigest = testDigest('1') }, ErrorAuthentication},
		{"authentication time", func(v *Challenge) { v.AuthenticatedAt = v.AuthenticatedAt.Add(time.Nanosecond) }, ErrorAuthentication},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := boundedRevokeChallengeFixture()
			test.edit(&value)
			challenge, err := CheckChallenge(value)
			if err != nil {
				t.Fatalf("mutation must remain a valid generic wire: %v", err)
			}
			if _, err := BindRevocationChallenge(binding, challenge); !IsCode(err, test.code) {
				t.Fatalf("error=%v want=%s", err, test.code)
			}
		})
	}
	if _, err := BindRevocationChallenge(CheckedRevocationBinding{}, mustCheckedChallenge(t, boundedRevokeChallengeFixture())); err == nil {
		t.Fatal("zero checked binding accepted")
	}
	if _, err := BindRevocationChallenge(binding, CheckedChallenge{}); !IsCode(err, ErrorArtifact) {
		t.Fatalf("zero checked challenge error=%v", err)
	}
	forgedChallenge := mustCheckedChallenge(t, boundedRevokeChallengeFixture())
	forgedChallenge.value.ResourceID = testPolicyID
	if _, err := BindRevocationChallenge(binding, forgedChallenge); !IsCode(err, ErrorArtifact) {
		t.Fatalf("forged checked challenge error=%v", err)
	}

	shortSession := validRevocationBindingInput(t)
	shortSession.Session.ExpiresAt = testNow.Add(time.Minute)
	checkedShort, err := CheckRevocationBinding(shortSession)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindRevocationChallenge(checkedShort, mustCheckedChallenge(t, boundedRevokeChallengeFixture())); !IsCode(err, ErrorAuthentication) {
		t.Fatalf("challenge beyond session error=%v", err)
	}
}

func TestBindRevocationChallengeRejectsOverlongEligibilityHorizon(t *testing.T) {
	input := validRevocationBindingInput(t)
	input.EligibilityValidUntil = revokeChallengeFixture().ValidationValidUntil
	binding, err := CheckRevocationBinding(input)
	if err != nil {
		t.Fatal(err)
	}
	challenge := mustCheckedChallenge(t, revokeChallengeFixture())
	if _, err := BindRevocationChallenge(binding, challenge); !IsCode(err, ErrorTime) {
		t.Fatalf("overlong revoke eligibility error=%v", err)
	}
}

func TestBindRevocationChallengeEligibilityHorizonBoundaries(t *testing.T) {
	tests := []struct {
		name              string
		eligibilityOffset time.Duration
		wireOffset        time.Duration
		expiryOffset      time.Duration
		sessionOffset     time.Duration
		wantCode          ErrorCode
	}{
		{"just after issue", time.Nanosecond, time.Nanosecond, time.Nanosecond, time.Nanosecond, ""},
		{"at five minutes", ChallengeLifetime, ChallengeLifetime, ChallengeLifetime, ChallengeLifetime, ""},
		{"equal to issue", 0, time.Nanosecond, time.Nanosecond, time.Hour, ErrorTime},
		{"over five minutes", ChallengeLifetime + time.Nanosecond, ChallengeLifetime + time.Nanosecond, ChallengeLifetime, time.Hour, ErrorTime},
		{"after session expiry", 3 * time.Minute, 3 * time.Minute, time.Minute, 2 * time.Minute, ErrorTime},
		{"at session expiry", 3 * time.Minute, 3 * time.Minute, time.Minute, 3 * time.Minute, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			challengeValue := boundedRevokeChallengeFixture()
			challengeValue.ValidationValidUntil = challengeValue.IssuedAt.Add(test.wireOffset)
			challengeValue.ExpiresAt = challengeValue.IssuedAt.Add(test.expiryOffset)
			challenge := mustCheckedChallenge(t, challengeValue)

			input := validRevocationBindingInput(t)
			input.EligibilityValidUntil = challengeValue.IssuedAt.Add(test.eligibilityOffset)
			input.Session.ExpiresAt = challengeValue.IssuedAt.Add(test.sessionOffset)
			binding, err := CheckRevocationBinding(input)
			if err != nil {
				t.Fatalf("check binding: %v", err)
			}
			bound, err := BindRevocationChallenge(binding, challenge)
			if test.wantCode != "" {
				if !IsCode(err, test.wantCode) {
					t.Fatalf("error=%v want=%s", err, test.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid boundary rejected: %v", err)
			}
			if !bound.EligibilityValidUntil().Equal(input.EligibilityValidUntil) {
				t.Fatal("bound eligibility changed")
			}
		})
	}
}

func mustCheckedChallenge(t testing.TB, value Challenge) CheckedChallenge {
	t.Helper()
	checked, err := CheckChallenge(value)
	if err != nil {
		t.Fatalf("check challenge: %v", err)
	}
	return checked
}

func mustCheckedDecision(t testing.TB, value Decision) CheckedDecision {
	t.Helper()
	checked, err := CheckDecision(value)
	if err != nil {
		t.Fatalf("check decision: %v", err)
	}
	return checked
}

func TestBindRevocationDecisionRejectsReplayCrossOperationAndMutations(t *testing.T) {
	binding := checkedRevocationBinding(t)
	challenge := checkedRevocationChallenge(t, binding, boundedRevokeChallengeFixture())
	reason := checkedRevocationReason(t)
	tests := []struct {
		name string
		edit func(*Decision)
		code ErrorCode
	}{
		{"challenge replay", func(v *Decision) { v.ChallengeID = testPolicyID }, ErrorChallengeMismatch},
		{"cross operation", func(v *Decision) {
			v.Operation = OperationApprove
			v.Decision = DecisionApproved
			v.ResourceType = ResourcePolicy
			v.OriginalAddDigest = nil
		}, ErrorChallengeMismatch},
		{"session", func(v *Decision) { v.SessionDigest = testDigest('1') }, ErrorAuthentication},
		{"actor", func(v *Decision) { v.ActorID = "other-admin" }, ErrorAuthentication},
		{"nonce", func(v *Decision) { v.NonceDigest = testDigest('1') }, ErrorNonce},
		{"action id", func(v *Decision) { v.ResourceID = testPolicyID }, ErrorArtifactMismatch},
		{"action version", func(v *Decision) { v.ResourceVersion++ }, ErrorArtifactMismatch},
		{"target", func(v *Decision) { v.TargetIPv4 = "203.0.113.21" }, ErrorArtifactMismatch},
		{"policy", func(v *Decision) { v.PolicyDigest = testDigest('1') }, ErrorArtifactMismatch},
		{"artifact", func(v *Decision) {
			v.GeneratedArtifactDigest = testDigest('1')
			v.CanonicalArtifactDigest = testDigest('1')
		}, ErrorArtifactMismatch},
		{"original add", func(v *Decision) { changed := testDigest('1'); v.OriginalAddDigest = &changed }, ErrorArtifactMismatch},
		{"evidence", func(v *Decision) { v.EvidenceSnapshotDigest = testDigest('1') }, ErrorArtifactMismatch},
		{"validation", func(v *Decision) { v.ValidationSnapshotDigest = testDigest('1') }, ErrorArtifactMismatch},
		{"reason", func(v *Decision) { v.ReasonDigest = testDigest('1') }, ErrorReason},
		{"idempotency", func(v *Decision) { v.IdempotencyKeyDigest = testDigest('1') }, ErrorIdempotency},
		{"before issue", func(v *Decision) {
			v.DecidedAt = challenge.Value().IssuedAt.Add(-time.Nanosecond)
			v.DecisionValidUntil = v.DecidedAt.Add(time.Minute)
		}, ErrorTime},
		{"at challenge expiry", func(v *Decision) {
			v.DecidedAt = challenge.Value().ExpiresAt
			v.DecisionValidUntil = v.DecidedAt.Add(time.Nanosecond)
		}, ErrorChallengeExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, _, _ := revokeDecisionFixture()
			test.edit(&value)
			decision := mustCheckedDecision(t, value)
			if _, err := BindRevocationDecision(challenge, decision, reason); !IsCode(err, test.code) {
				t.Fatalf("error=%v want=%s", err, test.code)
			}
		})
	}
	if _, err := BindRevocationDecision(CheckedRevocationChallenge{}, mustCheckedDecision(t, mustRevokeDecisionValue()), reason); err == nil {
		t.Fatal("zero bound challenge accepted")
	}
	if _, err := BindRevocationDecision(challenge, CheckedDecision{}, reason); !IsCode(err, ErrorArtifact) {
		t.Fatalf("zero checked decision error=%v", err)
	}
	forgedDecision := mustCheckedDecision(t, mustRevokeDecisionValue())
	forgedDecision.value.ResourceID = testPolicyID
	if _, err := BindRevocationDecision(challenge, forgedDecision, reason); !IsCode(err, ErrorArtifact) {
		t.Fatalf("forged checked decision error=%v", err)
	}
	if _, err := BindRevocationDecision(challenge, mustCheckedDecision(t, mustRevokeDecisionValue()), CheckedReason{}); !IsCode(err, ErrorReason) {
		t.Fatalf("zero checked reason error=%v", err)
	}

	forgedReason := reason
	forgedReason.value.ReasonText = "forged reason"
	if _, err := BindRevocationDecision(challenge, mustCheckedDecision(t, mustRevokeDecisionValue()), forgedReason); !IsCode(err, ErrorReason) {
		t.Fatalf("forged checked reason error=%v", err)
	}

	replayChallengeValue := boundedRevokeChallengeFixture()
	replayChallengeValue.ChallengeID = "019b0000-0000-4000-8000-000000000204"
	replayChallengeValue.NonceDigest = testDigest('2')
	replayChallenge := checkedRevocationChallenge(t, binding, replayChallengeValue)
	decision := mustCheckedDecision(t, mustRevokeDecisionValue())
	if _, err := BindRevocationDecision(replayChallenge, decision, reason); !IsCode(err, ErrorChallengeMismatch) {
		t.Fatalf("cross-challenge replay error=%v", err)
	}
	first, err := BindRevocationDecision(challenge, decision, reason)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BindRevocationDecision(challenge, decision, reason)
	if err != nil || second.Digest() != first.Digest() {
		t.Fatalf("exact consumed-decision recheck digest=%q err=%v", second.Digest(), err)
	}
}

func mustRevokeDecisionValue() Decision {
	value, _, _ := revokeDecisionFixture()
	return value
}

func TestRevocationDecisionTimeBoundaries(t *testing.T) {
	binding := checkedRevocationBinding(t)
	challengeValue := boundedRevokeChallengeFixture()
	challengeValue.ExpiresAt = testNow.Add(4 * time.Minute)
	challenge := checkedRevocationChallenge(t, binding, challengeValue)
	reason := checkedRevocationReason(t)

	value := mustRevokeDecisionValue()
	value.DecisionValidUntil = challengeValue.ExpiresAt
	checked := checkedRevocationDecision(t, challenge, value, reason)
	if !checked.RevokesAt(value.DecidedAt) || checked.RevokesAt(value.DecisionValidUntil) {
		t.Fatal("equal challenge boundary must bind and remain exclusive at use")
	}

	value = mustRevokeDecisionValue()
	if _, err := BindRevocationDecision(challenge, mustCheckedDecision(t, value), reason); !IsCode(err, ErrorTime) {
		t.Fatalf("validity after challenge error=%v", err)
	}

	input := validRevocationBindingInput(t)
	input.EligibilityValidUntil = challengeValue.ExpiresAt
	challengeValue.ValidationValidUntil = challengeValue.ExpiresAt
	equalBinding, err := CheckRevocationBinding(input)
	if err != nil {
		t.Fatal(err)
	}
	equalChallenge := checkedRevocationChallenge(t, equalBinding, challengeValue)
	value = mustRevokeDecisionValue()
	value.DecisionValidUntil = challengeValue.ExpiresAt
	checked = checkedRevocationDecision(t, equalChallenge, value, reason)
	if !checked.EligibilityValidUntil().Equal(value.DecisionValidUntil) ||
		checked.RevokesAt(checked.EligibilityValidUntil()) {
		t.Fatal("eligibility horizon equality is not exclusive")
	}
}

func TestRevocationBindingConcurrentChecksAndCopies(t *testing.T) {
	binding := checkedRevocationBinding(t)
	challenge := checkedRevocationChallenge(t, binding, boundedRevokeChallengeFixture())
	reason := checkedRevocationReason(t)
	decision := mustCheckedDecision(t, mustRevokeDecisionValue())

	const workers = 64
	var wait sync.WaitGroup
	errors := make(chan string, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			checked, err := BindRevocationDecision(challenge, decision, reason)
			if err != nil {
				errors <- err.Error()
				return
			}
			artifact := checked.RevokeArtifactBytes()
			reasonBytes := checked.ReasonCanonicalBytes()
			canonical := checked.CanonicalBytes()
			artifact[0] ^= 1
			reasonBytes[0] ^= 1
			canonical[0] ^= 1
			if !checked.RevokesAt(testNow) || checked.Digest() != digestBytes(checked.CanonicalBytes()) {
				errors <- "checked decision mutated"
			}
		}()
	}
	wait.Wait()
	close(errors)
	for message := range errors {
		t.Error(message)
	}
}
