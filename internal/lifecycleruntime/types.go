package lifecycleruntime

import (
	"context"
	"errors"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

const (
	DefaultPollInterval   = 250 * time.Millisecond
	DefaultCleanupTimeout = time.Second
	MaxPollInterval       = time.Minute
	MaxCleanupTimeout     = 5 * time.Second
)

var (
	ErrInvalidConfiguration = errors.New("lifecycle runtime: invalid configuration")
	ErrCancelled            = errors.New("lifecycle runtime: cancelled")
	ErrStoreUnavailable     = errors.New("lifecycle runtime: store unavailable")
	ErrProjectionInvalid    = errors.New("lifecycle runtime: schedule projection invalid")
	ErrContractRejected     = errors.New("lifecycle runtime: artifact contract rejected")
)

type Config struct {
	SchedulerID    string
	PollInterval   time.Duration
	CleanupTimeout time.Duration
}

func DefaultConfig(schedulerID string) Config {
	return Config{
		SchedulerID: schedulerID, PollInterval: DefaultPollInterval,
		CleanupTimeout: DefaultCleanupTimeout,
	}
}

// Clock is used only for cancellable polling. Security validity comes from the
// claimed DB-clock projection and is never extended from this clock.
type Clock interface {
	Sleep(context.Context, time.Duration) error
}

type Dependencies struct {
	Clock Clock
}

// ClaimInput is the untrusted adapter boundary used to snapshot one DB row.
// AuthorizationID is preassigned when the immutable schedule is created and
// remains stable across lease reclaim, including after a commit response is
// lost. The projection contains no mutation bytes, TTL, administrator nonce,
// or reason.
type ClaimInput struct {
	ScheduleIdentity            string
	LeaseIdentity               string
	AuthorizationID             string
	ActionID                    string
	ActionVersion               uint32
	PolicyID                    string
	PolicyVersion               uint32
	TargetIPv4                  string
	OriginalAddDigest           string
	OriginalAuthorizationDigest string
	EvidenceSnapshotDigest      string
	ValidationSnapshotDigest    string
	OwnedSchemaDigest           string
	Purpose                     lifecycleartifact.Purpose
	RequestedAt                 time.Time
	ValidUntil                  time.Time
}

// Claim is an immutable, redacted snapshot of a DB-clocked due schedule and
// its opaque fenced lease. The identities are never interpreted as authority.
type Claim struct {
	scheduleIdentity            string
	leaseIdentity               string
	authorizationID             string
	actionID                    string
	actionVersion               uint32
	policyID                    string
	policyVersion               uint32
	targetIPv4                  string
	originalAddDigest           string
	originalAuthorizationDigest string
	evidenceSnapshotDigest      string
	validationSnapshotDigest    string
	ownedSchemaDigest           string
	purpose                     lifecycleartifact.Purpose
	requestedAt                 time.Time
	validUntil                  time.Time
}

// NewClaim snapshots an untrusted store projection. ProcessNext independently
// validates every field before using it or asking Store to commit it.
func NewClaim(input ClaimInput) Claim {
	return Claim{
		scheduleIdentity: input.ScheduleIdentity, leaseIdentity: input.LeaseIdentity,
		authorizationID: input.AuthorizationID,
		actionID:        input.ActionID, actionVersion: input.ActionVersion,
		policyID: input.PolicyID, policyVersion: input.PolicyVersion,
		targetIPv4: input.TargetIPv4, originalAddDigest: input.OriginalAddDigest,
		originalAuthorizationDigest: input.OriginalAuthorizationDigest,
		evidenceSnapshotDigest:      input.EvidenceSnapshotDigest,
		validationSnapshotDigest:    input.ValidationSnapshotDigest,
		ownedSchemaDigest:           input.OwnedSchemaDigest, purpose: input.Purpose,
		requestedAt: input.RequestedAt, validUntil: input.ValidUntil,
	}
}

func (Claim) String() string     { return "lifecycleruntime.Claim{schedule:[REDACTED],lease:[REDACTED]}" }
func (c Claim) GoString() string { return c.String() }

// StoreIdentity returns opaque values only so a Store adapter can bind its
// exact schedule row and lease. Callers must not parse or log these values.
func (c Claim) StoreIdentity() (schedule, lease string) {
	return c.scheduleIdentity, c.leaseIdentity
}

func (c Claim) ActionVersion() uint32 { return c.actionVersion }

// PreparedInspection contains no executable or mutation bytes. Both members
// are independently checked immutable lifecycle artifacts.
type PreparedInspection struct {
	inspect       lifecycleartifact.CheckedInspectArtifact
	authorization lifecycleartifact.CheckedInspectionAuthorization
}

func (PreparedInspection) String() string {
	return "lifecycleruntime.PreparedInspection{artifacts:[REDACTED]}"
}
func (p PreparedInspection) GoString() string { return p.String() }

func (p PreparedInspection) Inspect() lifecycleartifact.CheckedInspectArtifact { return p.inspect }
func (p PreparedInspection) Authorization() lifecycleartifact.CheckedInspectionAuthorization {
	return p.authorization
}

type CommitDisposition string

const (
	CommitCreated  CommitDisposition = "created"
	CommitReplayed CommitDisposition = "replayed"
)

type FailureCode string

const (
	FailureProjectionInvalid FailureCode = "projection_invalid"
	FailureContractRejected  FailureCode = "contract_rejected"
	FailureContextCancelled  FailureCode = "context_cancelled"
)

// Failure is a typed, content-free, pre-mutation terminal record.
type Failure struct {
	code   FailureCode
	digest string
}

func (Failure) String() string      { return "lifecycleruntime.Failure{detail:[REDACTED]}" }
func (f Failure) GoString() string  { return f.String() }
func (f Failure) Code() FailureCode { return f.code }
func (f Failure) Digest() string    { return f.digest }

// Store is the narrow persistence boundary. ClaimDue uses the database clock
// and returns at most one due row; runtime never supplies a due/lease time.
// CommitInspection and FinishFailure must fence on both opaque identities.
type Store interface {
	ClaimDue(context.Context) (Claim, bool, error)
	CommitInspection(context.Context, Claim, PreparedInspection) (CommitDisposition, error)
	FinishFailure(context.Context, Claim, Failure) error
}

type Outcome string

const (
	OutcomeNoWork        Outcome = "no_work"
	OutcomeCommitted     Outcome = "committed"
	OutcomeReplayed      Outcome = "replayed"
	OutcomeFailed        Outcome = "failed"
	OutcomeCommitUnknown Outcome = "commit_unknown"
)

// Result intentionally contains no schedule, lease, target, or artifact data.
type Result struct {
	outcome     Outcome
	failureCode FailureCode
}

func (Result) String() string             { return "lifecycleruntime.Result{detail:[REDACTED]}" }
func (r Result) GoString() string         { return r.String() }
func (r Result) Outcome() Outcome         { return r.outcome }
func (r Result) FailureCode() FailureCode { return r.failureCode }
