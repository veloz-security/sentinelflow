package dispatchruntime

import (
	"context"
	"time"

	"github.com/devwooops/sentinelflow/internal/dispatchstore"
	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
)

// Job is the minimum immutable restricted-view projection needed to construct
// a capability. Formatting intentionally cannot reveal its target or artifact.
type Job struct {
	jobID                    string
	kind                     string
	operation                capability.Operation
	actionID                 string
	policyID                 string
	policyVersion            uint32
	targetIPv4               string
	artifact                 []byte
	artifactDigest           string
	originalAddDigest        string
	hasOriginalAddDigest     bool
	evidenceSnapshotDigest   string
	validationSnapshotDigest string
	authorizationDigest      string
	actorID                  string
	reasonDigest             string
	ownedSchemaDigest        string
	availableAt              time.Time
	attempts                 int32
	maxAttempts              int32
	notBefore                time.Time
	validUntil               time.Time
	recoveryOnly             bool
}

func (Job) String() string     { return "dispatchruntime.Job{restricted:[REDACTED]}" }
func (j Job) GoString() string { return j.String() }

func (j Job) JobID() string                   { return j.jobID }
func (j Job) Operation() capability.Operation { return j.operation }
func (j Job) Attempts() int32                 { return j.attempts }
func (j Job) MaxAttempts() int32              { return j.maxAttempts }

func cloneJob(j Job) Job {
	j.artifact = append([]byte(nil), j.artifact...)
	return j
}

// Claim keeps the dispatchstore fencing token opaque while exposing only
// database-clock times needed for bounded work.
type Claim struct {
	job        Job
	claimedAt  time.Time
	leaseUntil time.Time
	attempt    int32
	raw        *dispatchstore.ClaimedJob
}

func (Claim) String() string     { return "dispatchruntime.Claim{lease:[REDACTED]}" }
func (c Claim) GoString() string { return c.String() }
func (c Claim) Job() Job         { return cloneJob(c.job) }
func (c Claim) ClaimedAt() time.Time {
	return c.claimedAt
}
func (c Claim) LeaseUntil() time.Time { return c.leaseUntil }
func (c Claim) Attempt() int32        { return c.attempt }
func (c Claim) RecoveryOnly() bool    { return c.job.recoveryOnly }

func (c Claim) capabilityWindow(validity time.Duration) (time.Time, time.Time, time.Time, error) {
	if c.job.recoveryOnly {
		return time.Time{}, time.Time{}, time.Time{}, ErrContractRejected
	}
	if c.raw != nil {
		return c.raw.CapabilityWindow(validity)
	}
	if validity <= 0 || validity > capability.MaxValidity || c.claimedAt.IsZero() ||
		!c.leaseUntil.After(c.claimedAt) || !c.job.validUntil.After(c.job.notBefore) {
		return time.Time{}, time.Time{}, time.Time{}, ErrContractRejected
	}
	issuedAt := ceilMillisecond(c.claimedAt)
	notBefore := issuedAt
	if candidate := ceilMillisecond(c.job.notBefore); candidate.After(notBefore) {
		notBefore = candidate
	}
	deadline := floorMillisecond(c.job.validUntil)
	if lease := floorMillisecond(c.leaseUntil); lease.Before(deadline) {
		deadline = lease
	}
	expiresAt := issuedAt.Add(validity)
	if expiresAt.After(deadline) {
		expiresAt = deadline
	}
	if !expiresAt.After(notBefore) {
		return time.Time{}, time.Time{}, time.Time{}, ErrLeaseLost
	}
	return issuedAt, notBefore, expiresAt, nil
}

func ceilMillisecond(value time.Time) time.Time {
	value = value.Round(0).UTC()
	truncated := value.Truncate(time.Millisecond)
	if truncated.Equal(value) {
		return value
	}
	return truncated.Add(time.Millisecond)
}

func floorMillisecond(value time.Time) time.Time {
	return value.Round(0).UTC().Truncate(time.Millisecond)
}

type StoredCapability struct {
	claim    Claim
	signed   capability.SignedCapability
	verified capability.VerifiedCapability
	raw      *dispatchstore.PersistedCapability
}

func (StoredCapability) String() string {
	return "dispatchruntime.StoredCapability{capability:[REDACTED]}"
}
func (s StoredCapability) GoString() string { return s.String() }

type StoredResult struct {
	capability StoredCapability
	verified   capability.VerifiedResult
	raw        *dispatchstore.PersistedResult
}

func (StoredResult) String() string     { return "dispatchruntime.StoredResult{result:[REDACTED]}" }
func (s StoredResult) GoString() string { return s.String() }

type RecoveryState string

const (
	RecoveryNone       RecoveryState = "none"
	RecoveryCapability RecoveryState = "capability"
	RecoveryResult     RecoveryState = "result"
)

type RecoveredExecution struct {
	state            RecoveryState
	capability       StoredCapability
	signedCapability capability.SignedCapability
	result           StoredResult
	signedResult     capability.SignedResult
}

func (RecoveredExecution) String() string {
	return "dispatchruntime.RecoveredExecution{signed_artifacts:[REDACTED]}"
}
func (r RecoveredExecution) GoString() string     { return r.String() }
func (r RecoveredExecution) State() RecoveryState { return r.state }

type ClaimRequest struct {
	LeaseOwner     string
	LeaseDuration  time.Duration
	CandidateLimit int
}

type FinishOutcome string

const (
	FinishCompleted FinishOutcome = "completed"
	FinishRetry     FinishOutcome = "retry"
	FinishDead      FinishOutcome = "dead"
)

type FinishRequest struct {
	Outcome      FinishOutcome
	RetryBackoff time.Duration
	ErrorCode    string
	ErrorDigest  string
	Result       *StoredResult
}

type Store interface {
	ClaimRecoveryNext(context.Context, ClaimRequest) (Claim, bool, error)
	ClaimNext(context.Context, ClaimRequest) (Claim, bool, error)
	Recover(context.Context, Claim) (RecoveredExecution, error)
	PersistCapability(context.Context, Claim, capability.SignedCapability, capability.VerifiedCapability) (StoredCapability, error)
	PersistResult(context.Context, StoredCapability, capability.SignedResult, capability.VerifiedResult) (StoredResult, error)
	Finish(context.Context, Claim, FinishRequest) error
}

func (s *PostgreSQLStore) ClaimRecoveryNext(ctx context.Context, request ClaimRequest) (Claim, bool, error) {
	if s == nil || s.inner == nil {
		return Claim{}, false, ErrInvalidConfiguration
	}
	raw, found, err := s.inner.ClaimRecoveryNext(ctx, dispatchstore.ClaimRequest{
		LeaseOwner: request.LeaseOwner, LeaseDuration: request.LeaseDuration,
		CandidateLimit: request.CandidateLimit,
	})
	if err != nil || !found {
		return Claim{}, found, err
	}
	job := snapshotJob(raw.Job())
	if !job.recoveryOnly {
		return Claim{}, false, ErrContractRejected
	}
	return Claim{
		job: job, claimedAt: raw.ClaimedAt(), leaseUntil: raw.LeaseUntil(),
		attempt: raw.Attempt(), raw: &raw,
	}, true, nil
}

func (s *PostgreSQLStore) Recover(ctx context.Context, claim Claim) (RecoveredExecution, error) {
	if s == nil || s.inner == nil || claim.raw == nil {
		return RecoveredExecution{}, ErrInvalidConfiguration
	}
	recovered, err := s.inner.Recover(ctx, *claim.raw)
	if err != nil {
		return RecoveredExecution{}, err
	}
	result := RecoveredExecution{state: RecoveryState(recovered.State())}
	if rawCapability, signed, ok := recovered.Capability(); ok {
		result.capability = StoredCapability{claim: claim, signed: signed, raw: &rawCapability}
		result.signedCapability = signed
	}
	if rawResult, signed, ok := recovered.Result(); ok {
		result.result = StoredResult{capability: result.capability, raw: &rawResult}
		result.signedResult = signed
	}
	return result, nil
}

// PostgreSQLStore adapts the already hardened restricted dispatchstore without
// broadening its database authority.
type PostgreSQLStore struct {
	inner *dispatchstore.PostgreSQLStore
}

func NewPostgreSQLStore(inner *dispatchstore.PostgreSQLStore) (*PostgreSQLStore, error) {
	if inner == nil {
		return nil, ErrInvalidConfiguration
	}
	return &PostgreSQLStore{inner: inner}, nil
}

func (s *PostgreSQLStore) ClaimNext(ctx context.Context, request ClaimRequest) (Claim, bool, error) {
	if s == nil || s.inner == nil {
		return Claim{}, false, ErrInvalidConfiguration
	}
	raw, found, err := s.inner.ClaimNext(ctx, dispatchstore.ClaimRequest{
		LeaseOwner: request.LeaseOwner, LeaseDuration: request.LeaseDuration,
		CandidateLimit: request.CandidateLimit,
	})
	if err != nil || !found {
		return Claim{}, found, err
	}
	job := snapshotJob(raw.Job())
	return Claim{
		job: job, claimedAt: raw.ClaimedAt(), leaseUntil: raw.LeaseUntil(),
		attempt: raw.Attempt(), raw: &raw,
	}, true, nil
}

func (s *PostgreSQLStore) PersistCapability(
	ctx context.Context,
	claim Claim,
	signed capability.SignedCapability,
	verified capability.VerifiedCapability,
) (StoredCapability, error) {
	if s == nil || s.inner == nil || claim.raw == nil {
		return StoredCapability{}, ErrInvalidConfiguration
	}
	raw, err := s.inner.PersistCapability(ctx, *claim.raw, signed)
	if err != nil {
		return StoredCapability{}, err
	}
	return StoredCapability{claim: claim, signed: signed, verified: verified, raw: &raw}, nil
}

func (s *PostgreSQLStore) PersistResult(
	ctx context.Context,
	stored StoredCapability,
	signed capability.SignedResult,
	verified capability.VerifiedResult,
) (StoredResult, error) {
	if s == nil || s.inner == nil || stored.raw == nil {
		return StoredResult{}, ErrInvalidConfiguration
	}
	raw, err := s.inner.PersistResult(ctx, *stored.raw, signed)
	if err != nil {
		return StoredResult{}, err
	}
	return StoredResult{capability: stored, verified: verified, raw: &raw}, nil
}

func (s *PostgreSQLStore) Finish(ctx context.Context, claim Claim, request FinishRequest) error {
	if s == nil || s.inner == nil || claim.raw == nil {
		return ErrInvalidConfiguration
	}
	mapped := dispatchstore.FinishRequest{
		Outcome: dispatchstore.FinishOutcome(request.Outcome), RetryBackoff: request.RetryBackoff,
		ErrorCode: request.ErrorCode, ErrorDigest: request.ErrorDigest,
	}
	if request.Result != nil {
		if request.Result.raw == nil {
			return ErrInvalidConfiguration
		}
		mapped.Result = request.Result.raw
	}
	return s.inner.Finish(ctx, *claim.raw, mapped)
}

func snapshotJob(raw dispatchstore.EligibleJob) Job {
	original, hasOriginal := raw.OriginalAddDigest()
	return Job{
		jobID: raw.JobID(), kind: raw.Kind(), operation: raw.Operation(),
		actionID: raw.ActionID(), policyID: raw.PolicyID(), policyVersion: raw.PolicyVersion(),
		targetIPv4: raw.TargetIPv4(), artifact: raw.ArtifactBytes(), artifactDigest: raw.ArtifactDigest(),
		originalAddDigest: original, hasOriginalAddDigest: hasOriginal,
		evidenceSnapshotDigest:   raw.EvidenceSnapshotDigest(),
		validationSnapshotDigest: raw.ValidationSnapshotDigest(), authorizationDigest: raw.AuthorizationDigest(),
		actorID: raw.ActorID(), reasonDigest: raw.ReasonDigest(), ownedSchemaDigest: raw.OwnedSchemaDigest(),
		availableAt: raw.AvailableAt(), attempts: raw.Attempts(), maxAttempts: raw.MaxAttempts(),
		notBefore: raw.NotBefore(), validUntil: raw.ValidUntil(),
		recoveryOnly: raw.RecoveryOnly(),
	}
}
