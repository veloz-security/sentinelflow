package hil

import (
	"bytes"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

func FuzzRevocationBinding(f *testing.F) {
	artifact, err := lifecycleartifact.CheckRevokeArtifact("203.0.113.20")
	if err != nil {
		f.Fatal(err)
	}
	binding, err := CheckRevocationBinding(RevocationBindingInput{
		ActionID:                 testActionID,
		ActionVersion:            2,
		TargetIPv4:               "203.0.113.20",
		OriginalAddDigest:        testDigest('e'),
		PolicyDigest:             testDigest('b'),
		EvidenceSnapshotDigest:   testDigest('f'),
		ValidationSnapshotDigest: testDigest('7'),
		EligibilityValidUntil:    boundedRevokeChallengeFixture().ValidationValidUntil,
		Session:                  fixtureSession(testNow),
		IdempotencyKeyDigest:     testDigest('9'),
		Artifact:                 artifact,
	})
	if err != nil {
		f.Fatal(err)
	}
	challenge, err := CheckChallenge(boundedRevokeChallengeFixture())
	if err != nil {
		f.Fatal(err)
	}
	boundChallenge, err := BindRevocationChallenge(binding, challenge)
	if err != nil {
		f.Fatal(err)
	}
	reason := checkedRevocationReason(f)
	decision, err := CheckDecision(mustRevokeDecisionValue())
	if err != nil {
		f.Fatal(err)
	}
	boundDecision, err := BindRevocationDecision(boundChallenge, decision, reason)
	if err != nil {
		f.Fatal(err)
	}
	if !boundDecision.RevokesAt(testNow) {
		f.Fatal("seed decision lost revoke authority")
	}
	f.Add(
		artifact.CanonicalBytes(), challenge.CanonicalBytes(),
		decision.CanonicalBytes(), reason.CanonicalBytes(),
	)

	f.Fuzz(func(t *testing.T, artifactBytes, challengeBytes, decisionBytes, reasonBytes []byte) {
		artifact, err := lifecycleartifact.ParseCanonicalRevokeArtifact(artifactBytes)
		if err != nil {
			return
		}
		binding, err := CheckRevocationBinding(RevocationBindingInput{
			ActionID:                 testActionID,
			ActionVersion:            2,
			TargetIPv4:               "203.0.113.20",
			OriginalAddDigest:        testDigest('e'),
			PolicyDigest:             testDigest('b'),
			EvidenceSnapshotDigest:   testDigest('f'),
			ValidationSnapshotDigest: testDigest('7'),
			EligibilityValidUntil:    boundedRevokeChallengeFixture().ValidationValidUntil,
			Session:                  fixtureSession(testNow),
			IdempotencyKeyDigest:     testDigest('9'),
			Artifact:                 artifact,
		})
		if err != nil {
			return
		}
		challenge, err := ParseCanonicalChallenge(challengeBytes)
		if err != nil {
			return
		}
		boundChallenge, err := BindRevocationChallenge(binding, challenge)
		if err != nil {
			return
		}
		decision, err := ParseCanonicalDecision(decisionBytes)
		if err != nil {
			return
		}
		reason, err := ParseCanonicalReason(reasonBytes)
		if err != nil {
			return
		}
		bound, err := BindRevocationDecision(boundChallenge, decision, reason)
		if err != nil {
			return
		}
		value := bound.Value()
		if value.Operation != OperationRevoke || value.Decision != DecisionRevoked ||
			!bound.RevokesAt(value.DecidedAt) ||
			bound.Digest() != digestBytes(bound.CanonicalBytes()) ||
			bound.RevokeArtifactDigest() != digestBytes(bound.RevokeArtifactBytes()) ||
			!bytes.Equal(bound.RevokeArtifactBytes(), artifactBytes) {
			t.Fatal("successful fuzz bind violated revoke invariants")
		}
		copyBytes := bound.RevokeArtifactBytes()
		copyBytes[0] ^= 1
		if bytes.Equal(copyBytes, bound.RevokeArtifactBytes()) {
			t.Fatal("fuzz bind leaked mutable artifact bytes")
		}
	})
}

func FuzzRevocationEligibilityHorizon(f *testing.F) {
	for _, seed := range [][2]int64{
		{1, 1},
		{int64(ChallengeLifetime), int64(ChallengeLifetime)},
		{int64(ChallengeLifetime + time.Nanosecond), int64(time.Hour)},
		{int64(3 * time.Minute), int64(2 * time.Minute)},
		{0, int64(time.Hour)},
	} {
		f.Add(seed[0], seed[1])
	}
	artifact, err := lifecycleartifact.CheckRevokeArtifact("203.0.113.20")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, eligibilityNanos, sessionExpiryNanos int64) {
		eligibilityOffset := time.Duration(eligibilityNanos)
		sessionExpiryOffset := time.Duration(sessionExpiryNanos)
		challengeValue := boundedRevokeChallengeFixture()
		wireOffset := eligibilityOffset
		if wireOffset < time.Nanosecond {
			wireOffset = time.Nanosecond
		}
		challengeValue.ValidationValidUntil = challengeValue.IssuedAt.Add(wireOffset)
		challengeValue.ExpiresAt = challengeValue.IssuedAt.Add(time.Nanosecond)
		challenge, err := CheckChallenge(challengeValue)
		if err != nil {
			t.Fatalf("constructed generic challenge: %v", err)
		}

		session := fixtureSession(testNow)
		session.ExpiresAt = challengeValue.IssuedAt.Add(sessionExpiryOffset)
		binding, bindingErr := CheckRevocationBinding(RevocationBindingInput{
			ActionID:                 testActionID,
			ActionVersion:            2,
			TargetIPv4:               "203.0.113.20",
			OriginalAddDigest:        testDigest('e'),
			PolicyDigest:             testDigest('b'),
			EvidenceSnapshotDigest:   testDigest('f'),
			ValidationSnapshotDigest: testDigest('7'),
			EligibilityValidUntil:    challengeValue.IssuedAt.Add(eligibilityOffset),
			Session:                  session,
			IdempotencyKeyDigest:     testDigest('9'),
			Artifact:                 artifact,
		})
		wantValid := eligibilityOffset > 0 && eligibilityOffset <= ChallengeLifetime &&
			sessionExpiryOffset >= eligibilityOffset
		if bindingErr != nil {
			if wantValid {
				t.Fatalf("valid binding rejected: %v", bindingErr)
			}
			return
		}
		bound, err := BindRevocationChallenge(binding, challenge)
		if !wantValid {
			if err == nil {
				t.Fatalf("invalid eligibility bound until %s", bound.EligibilityValidUntil())
			}
			return
		}
		if err != nil {
			t.Fatalf("valid eligibility rejected: %v", err)
		}
		if !bound.EligibilityValidUntil().Equal(challengeValue.ValidationValidUntil) {
			t.Fatal("successful bind changed eligibility horizon")
		}
	})
}
