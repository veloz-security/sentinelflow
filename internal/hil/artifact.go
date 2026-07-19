package hil

import (
	"bytes"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
)

// ExactArtifactInput composes checked values from the preceding policy,
// command, evidence, and ordered validation stages. CheckExactArtifact binds
// their byte identities; it does not run or replace any of those stages.
type ExactArtifactInput struct {
	Policy     policy.CheckedResponsePolicy
	Command    nftvalidate.Artifact
	Evidence   validation.CheckedEvidenceSnapshot
	Validation validation.CheckedValidationSnapshot
}

// ExactArtifact is an immutable handoff into HIL. It retains both generated
// and canonical command bytes so a digest-only substitution cannot pass.
type ExactArtifact struct {
	policyID                 string
	policyVersion            uint32
	targetIPv4               string
	ttlSeconds               uint32
	policyDigest             string
	generatedDigest          string
	canonicalDigest          string
	evidenceSnapshotDigest   string
	validationSnapshotDigest string
	validationCreatedAt      timeValue
	validationValidUntil     timeValue
	generatedBytes           []byte
	canonicalBytes           []byte
}

func (ExactArtifact) String() string     { return "hil.ExactArtifact{command:[REDACTED]}" }
func (a ExactArtifact) GoString() string { return a.String() }

// timeValue prevents callers from constructing ExactArtifact with arbitrary
// timestamps while keeping clone/equality code compact.
type timeValue struct {
	value int64
	nanos int32
}

func freezeTime(value time.Time) timeValue {
	value = value.Round(0).UTC()
	return timeValue{value: value.Unix(), nanos: int32(value.Nanosecond())}
}

func (v timeValue) Time() time.Time { return time.Unix(v.value, int64(v.nanos)).UTC() }

func (a ExactArtifact) PolicyID() string                 { return a.policyID }
func (a ExactArtifact) PolicyVersion() uint32            { return a.policyVersion }
func (a ExactArtifact) TargetIPv4() string               { return a.targetIPv4 }
func (a ExactArtifact) TTLSeconds() uint32               { return a.ttlSeconds }
func (a ExactArtifact) PolicyDigest() string             { return a.policyDigest }
func (a ExactArtifact) GeneratedArtifactDigest() string  { return a.generatedDigest }
func (a ExactArtifact) CanonicalArtifactDigest() string  { return a.canonicalDigest }
func (a ExactArtifact) EvidenceSnapshotDigest() string   { return a.evidenceSnapshotDigest }
func (a ExactArtifact) ValidationSnapshotDigest() string { return a.validationSnapshotDigest }
func (a ExactArtifact) ValidationCreatedAt() time.Time   { return a.validationCreatedAt.Time() }
func (a ExactArtifact) ValidationValidUntil() time.Time  { return a.validationValidUntil.Time() }
func (a ExactArtifact) GeneratedBytes() []byte           { return bytes.Clone(a.generatedBytes) }
func (a ExactArtifact) CanonicalBytes() []byte           { return bytes.Clone(a.canonicalBytes) }

func (a ExactArtifact) FreshAt(now time.Time) bool {
	now, ok := normalizedTime(now)
	return ok && !now.Before(a.ValidationCreatedAt()) && now.Before(a.ValidationValidUntil())
}

func cloneExactArtifact(value ExactArtifact) ExactArtifact {
	value.generatedBytes = bytes.Clone(value.generatedBytes)
	value.canonicalBytes = bytes.Clone(value.canonicalBytes)
	return value
}

func sameExactArtifact(left, right ExactArtifact) bool {
	return left.policyID == right.policyID && left.policyVersion == right.policyVersion &&
		left.targetIPv4 == right.targetIPv4 && left.ttlSeconds == right.ttlSeconds &&
		constantStringEqual(left.policyDigest, right.policyDigest) &&
		constantStringEqual(left.generatedDigest, right.generatedDigest) &&
		constantStringEqual(left.canonicalDigest, right.canonicalDigest) &&
		constantStringEqual(left.evidenceSnapshotDigest, right.evidenceSnapshotDigest) &&
		constantStringEqual(left.validationSnapshotDigest, right.validationSnapshotDigest) &&
		left.validationCreatedAt == right.validationCreatedAt &&
		left.validationValidUntil == right.validationValidUntil &&
		bytes.Equal(left.generatedBytes, right.generatedBytes) && bytes.Equal(left.canonicalBytes, right.canonicalBytes)
}

func CheckExactArtifact(input ExactArtifactInput) (ExactArtifact, error) {
	policyBytes := input.Policy.CanonicalBytes()
	checkedPolicy, err := policy.ParseCanonicalResponsePolicy(policyBytes)
	if err != nil || checkedPolicy.Digest() != input.Policy.Digest() {
		return ExactArtifact{}, reject(ErrorArtifact)
	}
	evidenceBytes := input.Evidence.CanonicalBytes()
	checkedEvidence, err := validation.ParseCanonicalEvidenceSnapshot(evidenceBytes)
	if err != nil || checkedEvidence.Digest() != input.Evidence.Digest() {
		return ExactArtifact{}, reject(ErrorArtifact)
	}
	validationBytes := input.Validation.CanonicalBytes()
	checkedValidation, err := validation.ParseCanonicalValidationSnapshot(validationBytes)
	if err != nil || checkedValidation.Digest() != input.Validation.Digest() {
		return ExactArtifact{}, reject(ErrorValidationFailed)
	}

	policyValue := checkedPolicy.Value()
	evidenceValue := checkedEvidence.Value()
	validationValue := checkedValidation.Value()
	generated := input.Command.GeneratedBytes()
	canonical := input.Command.CanonicalBytes()
	recheckedCommand, err := nftvalidate.Canonicalize(generated, policyValue.TTLSeconds)
	if err != nil || len(canonical) == 0 ||
		!bytes.Equal(recheckedCommand.CanonicalBytes(), canonical) ||
		recheckedCommand.GeneratedDigest() != input.Command.GeneratedDigest() ||
		recheckedCommand.CanonicalDigest() != input.Command.CanonicalDigest() ||
		digestBytes(generated) != input.Command.GeneratedDigest() ||
		digestBytes(canonical) != input.Command.CanonicalDigest() {
		return ExactArtifact{}, reject(ErrorArtifact)
	}

	if policyValue.IncidentID != evidenceValue.IncidentID ||
		policyValue.TargetIPv4 != evidenceValue.SourceIPv4 ||
		policyValue.TargetIPv4 != input.Command.TargetIPv4() ||
		policyValue.TTLSeconds != input.Command.TTLSeconds() ||
		policyValue.EvidenceSnapshotDigest != checkedEvidence.Digest() ||
		!sameStrings(policyValue.EvidenceIDs, evidenceValue.SignalIDs) {
		return ExactArtifact{}, reject(ErrorArtifactMismatch)
	}
	if validationValue.PolicyDigest != checkedPolicy.Digest() ||
		validationValue.EvidenceSnapshotDigest != checkedEvidence.Digest() ||
		validationValue.GeneratedCandidateDigest != input.Command.GeneratedDigest() ||
		validationValue.CanonicalArtifactDigest != input.Command.CanonicalDigest() ||
		validationValue.GrammarVersion != nftvalidate.GrammarVersion ||
		validationValue.ParserVersion != nftvalidate.ParserVersion ||
		validationValue.ValidatorVersion != nftvalidate.ValidatorVersion ||
		validationValue.BaseChainContractRawDigest != nftvalidate.PinnedBaseChainRawDigest ||
		validationValue.LiveOwnedSchemaDigest != nftvalidate.PinnedLiveSchemaDigest ||
		validationValue.ProtectedIPv4StaticDigest != validation.PinnedProtectedIPv4Digest {
		return ExactArtifact{}, reject(ErrorValidationFailed)
	}

	return ExactArtifact{
		policyID:                 policyValue.PolicyID,
		policyVersion:            policyValue.PolicyVersion,
		targetIPv4:               policyValue.TargetIPv4,
		ttlSeconds:               policyValue.TTLSeconds,
		policyDigest:             checkedPolicy.Digest(),
		generatedDigest:          input.Command.GeneratedDigest(),
		canonicalDigest:          input.Command.CanonicalDigest(),
		evidenceSnapshotDigest:   checkedEvidence.Digest(),
		validationSnapshotDigest: checkedValidation.Digest(),
		validationCreatedAt:      freezeTime(validationValue.CreatedAt),
		validationValidUntil:     freezeTime(validationValue.ValidUntil),
		generatedBytes:           bytes.Clone(generated),
		canonicalBytes:           bytes.Clone(canonical),
	}, nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
