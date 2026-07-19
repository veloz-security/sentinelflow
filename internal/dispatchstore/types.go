package dispatchstore

import (
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
)

const (
	MaxListLimit       = 100
	MaxClaimCandidates = 32
	MaxLeaseDuration   = 60 * time.Second
	MinRetryBackoff    = 100 * time.Millisecond
	MaxRetryBackoff    = 5 * time.Minute
)

type jobSnapshot struct {
	jobID                    string
	kind                     string
	state                    string
	availableAt              time.Time
	attempts                 int32
	maxAttempts              int32
	operation                capability.Operation
	actionID                 string
	policyID                 string
	policyVersion            uint32
	targetIPv4               string
	artifact                 []byte
	artifactDigest           string
	originalAddDigest        *string
	evidenceSnapshotDigest   string
	validationSnapshotDigest string
	authorizationDigest      string
	actorID                  string
	reasonDigest             string
	ownedSchemaDigest        string
	notBefore                time.Time
	validUntil               time.Time
	recoveryOnly             bool
}

func cloneJob(value jobSnapshot) jobSnapshot {
	value.artifact = append([]byte(nil), value.artifact...)
	value.availableAt = value.availableAt.Round(0).UTC()
	value.notBefore = value.notBefore.Round(0).UTC()
	value.validUntil = value.validUntil.Round(0).UTC()
	if value.originalAddDigest != nil {
		copyValue := *value.originalAddDigest
		value.originalAddDigest = &copyValue
	}
	return value
}

// EligibleJob is an immutable projection from dispatcher_approved_outbox.
// Explicit accessors are required so ordinary formatting cannot print an IP
// address or exact nftables artifact by accident.
type EligibleJob struct{ value jobSnapshot }

func (EligibleJob) String() string     { return "dispatchstore.EligibleJob{exact_artifact:[REDACTED]}" }
func (j EligibleJob) GoString() string { return j.String() }

func (j EligibleJob) JobID() string                    { return j.value.jobID }
func (j EligibleJob) Kind() string                     { return j.value.kind }
func (j EligibleJob) Operation() capability.Operation  { return j.value.operation }
func (j EligibleJob) ActionID() string                 { return j.value.actionID }
func (j EligibleJob) PolicyID() string                 { return j.value.policyID }
func (j EligibleJob) PolicyVersion() uint32            { return j.value.policyVersion }
func (j EligibleJob) TargetIPv4() string               { return j.value.targetIPv4 }
func (j EligibleJob) ArtifactBytes() []byte            { return append([]byte(nil), j.value.artifact...) }
func (j EligibleJob) ArtifactDigest() string           { return j.value.artifactDigest }
func (j EligibleJob) EvidenceSnapshotDigest() string   { return j.value.evidenceSnapshotDigest }
func (j EligibleJob) ValidationSnapshotDigest() string { return j.value.validationSnapshotDigest }
func (j EligibleJob) AuthorizationDigest() string      { return j.value.authorizationDigest }
func (j EligibleJob) ActorID() string                  { return j.value.actorID }
func (j EligibleJob) ReasonDigest() string             { return j.value.reasonDigest }
func (j EligibleJob) OwnedSchemaDigest() string        { return j.value.ownedSchemaDigest }
func (j EligibleJob) AvailableAt() time.Time           { return j.value.availableAt }
func (j EligibleJob) Attempts() int32                  { return j.value.attempts }
func (j EligibleJob) MaxAttempts() int32               { return j.value.maxAttempts }
func (j EligibleJob) RecoveryOnly() bool               { return j.value.recoveryOnly }
func (j EligibleJob) NotBefore() time.Time             { return j.value.notBefore }
func (j EligibleJob) ValidUntil() time.Time            { return j.value.validUntil }

func (j EligibleJob) OriginalAddDigest() (string, bool) {
	if j.value.originalAddDigest == nil {
		return "", false
	}
	return *j.value.originalAddDigest, true
}

// ClaimRequest uses PostgreSQL's clock for lease timing. LeaseToken may be an
// already generated canonical UUIDv4 for controlled recovery/testing; when it
// is empty the store generates one from its configured cryptographic reader.
type ClaimRequest struct {
	LeaseOwner     string
	LeaseDuration  time.Duration
	CandidateLimit int
	LeaseToken     string
}

func (ClaimRequest) String() string     { return "dispatchstore.ClaimRequest{lease:[REDACTED]}" }
func (r ClaimRequest) GoString() string { return r.String() }

// ClaimedJob binds an immutable approved projection to one fenced lease.
type ClaimedJob struct {
	job         jobSnapshot
	leaseToken  string
	leaseOwner  string
	claimedAt   time.Time
	leaseUntil  time.Time
	claimDigest [32]byte
}

func (ClaimedJob) String() string {
	return "dispatchstore.ClaimedJob{lease:[REDACTED],exact_artifact:[REDACTED]}"
}
func (c ClaimedJob) GoString() string { return c.String() }

func (c ClaimedJob) Job() EligibleJob { return EligibleJob{value: cloneJob(c.job)} }
func (c ClaimedJob) ClaimedAt() time.Time {
	return c.claimedAt
}
func (c ClaimedJob) LeaseUntil() time.Time { return c.leaseUntil }
func (c ClaimedJob) Attempt() int32        { return c.job.attempts + 1 }

// CapabilityWindow derives canonical millisecond timestamps from the later
// post-claim database clock. The deadline is fenced by both the approved job
// authority and the lease, and never exceeds the capability contract maximum.
func (c ClaimedJob) CapabilityWindow(validity time.Duration) (time.Time, time.Time, time.Time, error) {
	if !validClaimedJob(c) || c.job.recoveryOnly || validity <= 0 || validity > capability.MaxValidity {
		return time.Time{}, time.Time{}, time.Time{}, ErrInvalidInput
	}
	issuedAt := ceilMillisecond(c.claimedAt)
	notBefore := issuedAt
	if jobNotBefore := ceilMillisecond(c.job.notBefore); jobNotBefore.After(notBefore) {
		notBefore = jobNotBefore
	}
	deadline := floorMillisecond(c.job.validUntil)
	if leaseDeadline := floorMillisecond(c.leaseUntil); leaseDeadline.Before(deadline) {
		deadline = leaseDeadline
	}
	expiresAt := issuedAt.Add(validity)
	if expiresAt.After(deadline) {
		expiresAt = deadline
	}
	if !expiresAt.After(notBefore) || expiresAt.Sub(issuedAt) > capability.MaxValidity {
		return time.Time{}, time.Time{}, time.Time{}, ErrLeaseLost
	}
	return issuedAt, notBefore, expiresAt, nil
}

type PersistedCapability struct {
	claim     ClaimedJob
	verified  capability.VerifiedCapability
	recovered bool
}

func (PersistedCapability) String() string {
	return "dispatchstore.PersistedCapability{capability:[REDACTED]}"
}
func (p PersistedCapability) GoString() string { return p.String() }

type PersistedResult struct {
	capability PersistedCapability
	resultID   string
	digest     string
}

func (PersistedResult) String() string     { return "dispatchstore.PersistedResult{result:[REDACTED]}" }
func (p PersistedResult) GoString() string { return p.String() }

// RecoveryState is the complete state machine returned for one newly claimed
// job. RecoveryNone is the only state in which a new capability may be minted.
type RecoveryState string

const (
	RecoveryNone       RecoveryState = "none"
	RecoveryCapability RecoveryState = "capability"
	RecoveryResult     RecoveryState = "result"
)

// RecoveredExecution contains verified copies of exact signed bytes already
// stored for one job. Its fields remain opaque so callers cannot manufacture a
// persisted token or silently substitute a different claim.
type RecoveredExecution struct {
	state            RecoveryState
	claim            ClaimedJob
	capability       PersistedCapability
	signedCapability capability.SignedCapability
	result           PersistedResult
	signedResult     capability.SignedResult
}

func (RecoveredExecution) String() string {
	return "dispatchstore.RecoveredExecution{signed_artifacts:[REDACTED]}"
}
func (r RecoveredExecution) GoString() string     { return r.String() }
func (r RecoveredExecution) State() RecoveryState { return r.state }

// Capability returns the verified persisted token and the byte-exact signed
// transport. The transport accessors clone all byte slices.
func (r RecoveredExecution) Capability() (PersistedCapability, capability.SignedCapability, bool) {
	if r.state != RecoveryCapability && r.state != RecoveryResult {
		return PersistedCapability{}, capability.SignedCapability{}, false
	}
	return clonePersistedCapability(r.capability), capability.NewUntrustedSignedCapability(
		r.signedCapability.KeyID(), r.signedCapability.CanonicalBytes(),
		r.signedCapability.Signature(), r.signedCapability.ArtifactBytes(),
	), true
}

// Result returns the completion token and the byte-exact executor attestation
// only when a durable verified result exists. It can be passed directly to a
// fenced FinishCompleted under the current recovered claim.
func (r RecoveredExecution) Result() (PersistedResult, capability.SignedResult, bool) {
	if r.state != RecoveryResult {
		return PersistedResult{}, capability.SignedResult{}, false
	}
	return clonePersistedResult(r.result), capability.NewUntrustedSignedResult(
		r.signedResult.KeyID(), r.signedResult.ExecutorID(),
		r.signedResult.CanonicalBytes(), r.signedResult.Signature(),
	), true
}

type FinishOutcome string

const (
	FinishCompleted FinishOutcome = "completed"
	FinishRetry     FinishOutcome = "retry"
	FinishDead      FinishOutcome = "dead"
)

// FinishRequest computes retry availability from a fresh database timestamp.
// Completed requires the opaque result returned by PersistResult.
type FinishRequest struct {
	Outcome      FinishOutcome
	RetryBackoff time.Duration
	ErrorCode    string
	ErrorDigest  string
	Result       *PersistedResult
}

func (FinishRequest) String() string     { return "dispatchstore.FinishRequest{evidence:[REDACTED]}" }
func (r FinishRequest) GoString() string { return r.String() }
