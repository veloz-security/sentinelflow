package hil

import (
	"bytes"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
)

func TestCheckExactArtifactBindsAllPrecedingArtifacts(t *testing.T) {
	input := fixtureExactInput(t, testNow)
	exact, err := CheckExactArtifact(input)
	if err != nil {
		t.Fatalf("check exact: %v", err)
	}
	if exact.PolicyID() != testPolicyID || exact.PolicyVersion() != 3 ||
		exact.TargetIPv4() != "203.0.113.20" || exact.TTLSeconds() != 1800 {
		t.Fatalf("identity = %s/%d %s/%d", exact.PolicyID(), exact.PolicyVersion(), exact.TargetIPv4(), exact.TTLSeconds())
	}
	if exact.PolicyDigest() != input.Policy.Digest() ||
		exact.EvidenceSnapshotDigest() != input.Evidence.Digest() ||
		exact.ValidationSnapshotDigest() != input.Validation.Digest() ||
		exact.GeneratedArtifactDigest() != input.Command.GeneratedDigest() ||
		exact.CanonicalArtifactDigest() != input.Command.CanonicalDigest() {
		t.Fatal("exact artifact digest binding differs from checked inputs")
	}
	if bytes.Equal(exact.GeneratedBytes(), exact.CanonicalBytes()) {
		t.Fatal("fixture must preserve generated/canonical distinction")
	}
	if !exact.FreshAt(testNow) || exact.FreshAt(exact.ValidationValidUntil()) || exact.FreshAt(time.Time{}) {
		t.Fatal("validation freshness boundaries are not strict")
	}
	generated := exact.GeneratedBytes()
	canonical := exact.CanonicalBytes()
	generated[0] ^= 1
	canonical[0] ^= 1
	if digestBytes(exact.GeneratedBytes()) != exact.GeneratedArtifactDigest() ||
		digestBytes(exact.CanonicalBytes()) != exact.CanonicalArtifactDigest() {
		t.Fatal("exact artifact accessors leaked mutable command bytes")
	}
}

func TestCheckExactArtifactFailsClosedOnMismatchOrFailedGate(t *testing.T) {
	input := fixtureExactInput(t, testNow)

	t.Run("zero checked inputs", func(t *testing.T) {
		if _, err := CheckExactArtifact(ExactArtifactInput{}); !IsCode(err, ErrorArtifact) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("policy evidence mismatch", func(t *testing.T) {
		policyValue := input.Policy.Value()
		policyValue.EvidenceIDs = []string{"019b0000-0000-4000-8000-000000000999"}
		changed, err := policy.CheckResponsePolicy(policyValue)
		if err != nil {
			t.Fatal(err)
		}
		changedInput := input
		changedInput.Policy = changed
		if _, err := CheckExactArtifact(changedInput); !IsCode(err, ErrorArtifactMismatch) && !IsCode(err, ErrorValidationFailed) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("command TTL mismatch", func(t *testing.T) {
		changedInput := input
		command, err := nftvalidate.Canonicalize([]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1h }\n"), 3600)
		if err != nil {
			t.Fatal(err)
		}
		changedInput.Command = command
		if _, err := CheckExactArtifact(changedInput); !IsCode(err, ErrorArtifact) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("failed validation cannot become checked", func(t *testing.T) {
		value := input.Validation.Value()
		value.Checks[5].Result = "fail"
		if _, err := validation.CheckValidationSnapshot(value); err == nil {
			t.Fatal("failed validation unexpectedly became immutable pass snapshot")
		}
		changedInput := input
		changedInput.Validation = validation.CheckedValidationSnapshot{}
		if _, err := CheckExactArtifact(changedInput); !IsCode(err, ErrorValidationFailed) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("owned schema version mismatch", func(t *testing.T) {
		value := input.Validation.Value()
		value.ParserVersion = "other-parser-v1"
		changed, err := validation.CheckValidationSnapshot(value)
		if err != nil {
			t.Fatal(err)
		}
		changedInput := input
		changedInput.Validation = changed
		if _, err := CheckExactArtifact(changedInput); !IsCode(err, ErrorValidationFailed) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("protected contract digest mismatch", func(t *testing.T) {
		value := input.Validation.Value()
		value.ProtectedIPv4StaticDigest = testDigest('7')
		changed, err := validation.CheckValidationSnapshot(value)
		if err != nil {
			t.Fatal(err)
		}
		changedInput := input
		changedInput.Validation = changed
		if _, err := CheckExactArtifact(changedInput); !IsCode(err, ErrorValidationFailed) {
			t.Fatalf("error = %v", err)
		}
	})
}
