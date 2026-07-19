package capability

import (
	"context"
	"crypto/subtle"
)

// ReplayIdentity is the immutable row identity expected by a durable CAS
// adapter. CapabilityID is the lookup key; every digest and operation is
// compared to distinguish an exact retry from a conflicting replay.
type ReplayIdentity struct {
	CapabilityID     string
	CapabilityDigest string
	Operation        Operation
	ArtifactDigest   string
	ActionID         string
}

func (v VerifiedCapability) ReplayIdentity() (ReplayIdentity, error) {
	if len(v.canonical) == 0 || !digestPattern.MatchString(v.digest) {
		return ReplayIdentity{}, reject(ErrorUnchecked)
	}
	return ReplayIdentity{
		CapabilityID: v.value.CapabilityID, CapabilityDigest: v.digest, Operation: v.value.Operation,
		ArtifactDigest: v.value.ArtifactDigest, ActionID: v.value.ActionID,
	}, nil
}

// Same reports byte-exact idempotency without early-exit digest comparison.
func (r ReplayIdentity) Same(other ReplayIdentity) bool {
	return r.CapabilityID == other.CapabilityID && r.Operation == other.Operation && r.ActionID == other.ActionID &&
		constantString(r.CapabilityDigest, other.CapabilityDigest) && constantString(r.ArtifactDigest, other.ArtifactDigest)
}

func (r ReplayIdentity) valid() bool {
	return uuidPattern.MatchString(r.CapabilityID) && uuidPattern.MatchString(r.ActionID) &&
		digestPattern.MatchString(r.CapabilityDigest) && digestPattern.MatchString(r.ArtifactDigest) &&
		(r.Operation == OperationAdd || r.Operation == OperationRevoke || r.Operation == OperationInspect)
}

func constantString(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

type ClaimState string

const (
	ClaimedUnseen   ClaimState = "claimed_unseen"
	ClaimExactRetry ClaimState = "exact_retry"
	ClaimConflict   ClaimState = "conflict"
)

// ClaimResult contains no executable bytes. Exact retries must be resolved
// from the durable journal/result, never passed back through AddAt.
type ClaimResult struct {
	State    ClaimState
	Existing ReplayIdentity
}

// SingleUseCAS is intentionally persistence-agnostic. A PostgreSQL adapter can
// implement it with INSERT ... ON CONFLICT plus a byte-exact digest comparison.
// The claim must commit before the caller invokes a mutation.
type SingleUseCAS interface {
	ClaimUnseen(context.Context, ReplayIdentity) (ClaimResult, error)
}

// ValidateClaim defensively validates adapter output. It rejects a claimed row
// that does not describe the supplied verified capability.
func ValidateClaim(incoming ReplayIdentity, result ClaimResult) error {
	if !incoming.valid() {
		return reject(ErrorUnchecked)
	}
	switch result.State {
	case ClaimedUnseen:
		if !incoming.Same(result.Existing) {
			return reject(ErrorReplayConflict)
		}
		return nil
	case ClaimExactRetry:
		if !incoming.Same(result.Existing) {
			return reject(ErrorReplayConflict)
		}
		return nil
	case ClaimConflict:
		return reject(ErrorReplayConflict)
	default:
		return reject(ErrorReplayConflict)
	}
}
