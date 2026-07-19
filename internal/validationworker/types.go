// Package validationworker orchestrates the fail-closed validation of staged
// AI policy and nftables command candidates.
//
// The package has no HIL or executor authority. PostgreSQL owns leasing,
// immutable attempt snapshots, fencing, and terminal publication; this
// package owns only the ordered deterministic gates.
package validationworker

import (
	"context"
	"errors"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	MaxConcurrency             = 8
	MaxPreparedSnapshotBytes   = 64 * 1024 * 1024
	MaxHistoricalGatewayRows   = 100_000
	MaxHistoricalAuthRows      = 100_000
	ValidationAggregateType    = "analysis_staging"
	ValidationFailureNone      = "none"
	ValidationAuditSucceeded   = "validation_succeeded"
	ValidationAuditRejected    = "validation_rejected"
	ValidationParserVersion    = "nft-blacklist-parser-v1"
	ValidationValidatorVersion = "owned-schema-validator-v1"
)

var (
	ErrInvalidConfig        = errors.New("validation worker: invalid configuration")
	ErrInvalidLease         = errors.New("validation worker: invalid lease")
	ErrUnexpectedJobKind    = errors.New("validation worker: unexpected job kind")
	ErrLeaseLost            = errors.New("validation worker: lease lost")
	ErrPersistence          = errors.New("validation worker: persistence unavailable")
	ErrRetryablePersistence = errors.New("validation worker: retryable persistence conflict")
	ErrInvalidSnapshot      = errors.New("validation worker: invalid prepared snapshot")
	ErrAtomicStoreMissing   = errors.New("validation worker: atomic persistence adapter is unavailable")
)

type Config struct {
	LeaseOwner                 string
	LeaseDuration              time.Duration
	PollInterval               time.Duration
	MaxConcurrency             int
	Environment                validation.Environment
	NFTBinaryDigest            string
	ExpectedNFTVersion         string
	ExpectedOutputSchemaDigest string
	ExpectedPromptDigest       string
	Backoff                    worker.BackoffPolicy
}

func DefaultConfig(
	owner, nftBinaryDigest, expectedNFTVersion, expectedOutputSchemaDigest, expectedPromptDigest string,
) Config {
	base := worker.DefaultConfig(owner)
	return Config{
		LeaseOwner: owner, LeaseDuration: worker.MaxLeaseDuration,
		PollInterval: base.PollInterval, MaxConcurrency: 1,
		Environment:     validation.EnvironmentProduction,
		NFTBinaryDigest: nftBinaryDigest, ExpectedNFTVersion: expectedNFTVersion,
		ExpectedOutputSchemaDigest: expectedOutputSchemaDigest,
		ExpectedPromptDigest:       expectedPromptDigest,
		Backoff:                    base.Backoff,
	}
}

// Snapshot is the immutable allowlisted projection captured with one
// PostgreSQL clock_timestamp(). It contains no request body, exact path,
// headers, credentials, raw account identifiers, or arbitrary log text.
type Snapshot struct {
	ValidationAttemptID string
	PolicyID            string
	ValidationID        string
	CommandCandidateID  string
	AnalysisID          string
	IncidentID          string
	IncidentVersion     uint32
	GeneratedAt         time.Time

	EvidenceSnapshotID     string
	EvidenceSnapshotDigest string
	EvidenceCanonicalBytes []byte
	AnalysisInputDigest    string
	OutputSchemaDigest     string
	PromptDigest           string
	AnalysisOutputDigest   string
	GeneratedCommandDigest string

	StructuredOutput       []byte
	PolicyOutput           []byte
	CommandCandidateOutput []byte
	Evidence               EvidenceBinding
	History                HistorySnapshot
}

type EvidenceBinding struct {
	SourceIPv4         string
	ServiceLabel       string
	SourceHealthDigest string
	SourceHealthStatus string
	SignalIDs          []string
	EventIDs           []string
	Signals            []SignalBinding
}

type SignalBinding struct {
	SignalID            string
	SignalDigest        string
	SourceIPv4          string
	EventIDs            []string
	ThresholdReproduced bool
	SourceHealthStatus  string
}

// HistorySnapshot is a bounded PostgreSQL projection. Retained mode uses the
// same database timestamp as GeneratedAt. Verified demo mode uses the signed,
// DB-reverified sealed history clock while GeneratedAt remains real DB time.
type HistorySnapshot struct {
	Cutoff           time.Time
	WindowStart      time.Time
	CoverageComplete bool
	GatewayRecords   []validation.HistoricalGatewayRecord
	AuthRecords      []validation.HistoricalAuthRecord
}

type PrepareRequest struct {
	Job        worker.Job
	LeaseToken string
}

type FinalizeRequest struct {
	Finish   worker.FinishRequest
	Mutation *Mutation
}

type Store interface {
	Lease(context.Context, worker.LeaseRequest) (worker.LeasedJob, bool, error)
	Prepare(context.Context, PrepareRequest) (Snapshot, bool, error)
	Finalize(context.Context, FinalizeRequest) (bool, error)
}

// VerifiedDemoHistoryStore is implemented only by a persistence adapter that
// has reverified the signed binding against a completed import ledger and its
// canonical mapped rows. Runtime construction never accepts caller-supplied
// demo claims through Config.
type VerifiedDemoHistoryStore interface {
	Store
	VerifiedDemoHistoryBinding() (validation.VerifiedDemoHistoryBinding, bool)
}

type SyntaxChecker interface {
	Check(context.Context, nftcheck.Input) (nftcheck.Evidence, error)
}

var _ SyntaxChecker = (*nftcheck.Checker)(nil)

type Dependencies struct {
	Clock         Clock
	Tokens        worker.TokenSource
	Jitter        worker.JitterSource
	ProtectedGate *validation.ProtectedGate
	SyntaxChecker SyntaxChecker
	BaseContract  []byte
	LiveSchema    []byte
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type ValidationState string

const (
	StateValid   ValidationState = "valid"
	StateInvalid ValidationState = "invalid"
)

type GateRecord struct {
	Order        uint8
	Name         validation.ValidationCheckID
	Passed       bool
	ResultCode   string
	InputDigest  string
	ResultDigest string
}

type CandidateRecord struct {
	SchemaVersion   string
	TargetIPv4      string
	TimeoutToken    string
	TTLSeconds      uint32
	GeneratedBytes  []byte
	GeneratedDigest string
	CanonicalBytes  []byte
	CanonicalDigest string
}

type PolicyRecord struct {
	SchemaVersion  string
	PolicyID       string
	PolicyVersion  uint32
	CanonicalBytes []byte
	PolicyDigest   string
	TargetIPv4     string
	TTLSeconds     uint32
	Rationale      string
}

type ValidationRecord struct {
	CanonicalBytes                     []byte
	SnapshotDigest                     string
	PolicyDigest                       string
	EvidenceSnapshotDigest             string
	AnalysisInputDigest                string
	AnalysisOutputSchemaDigest         string
	PromptDigest                       string
	GeneratedCandidateDigest           string
	CanonicalArtifactDigest            string
	GrammarVersion                     string
	ParserVersion                      string
	ValidatorVersion                   string
	BaseChainContractRawDigest         string
	LiveOwnedSchemaDigest              string
	ProtectedIPv4StaticDigest          string
	ProtectedIPv4EffectiveConfigDigest string
	NFTBinaryDigest                    string
	NFTVersion                         string
	HistoricalImpactDigest             string
	TargetIPv4                         string
	TTLSeconds                         uint32
	SourceHealthStatus                 string
	CreatedAt                          time.Time
	ValidUntil                         time.Time
}

type Mutation struct {
	ValidationAttemptID    string
	AnalysisID             string
	IncidentID             string
	IncidentVersion        uint32
	State                  ValidationState
	FailureCode            string
	AuditAction            string
	EvidenceCanonicalBytes []byte
	Gates                  []GateRecord
	Candidate              *CandidateRecord
	Policy                 *PolicyRecord
	Validation             *ValidationRecord
}

type Result struct {
	Outcome     worker.Outcome
	JobID       string
	AnalysisID  string
	Attempt     int32
	State       ValidationState
	FailureCode string
	FailedGate  validation.ValidationCheckID
	RetryAt     *time.Time
}
