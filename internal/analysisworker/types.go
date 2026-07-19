// Package analysisworker orchestrates leased, asynchronous incident analysis.
//
// It deliberately owns no PostgreSQL statements. The persistence adapter must
// atomically fence the exact lease token, write the analysis state and audit
// evidence, enqueue validation for a successful candidate, and finish the
// outbox job. Splitting those effects would allow stale workers to publish an
// analysis after losing their lease.
package analysisworker

import (
	"context"
	"errors"
	"time"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	AnalysisInputSchemaVersion = "sentinelflow_analysis_input_v1"
	PromptVersion              = "sentinelflow_system_prompt_v1"
	OutputSchemaVersion        = "sentinelflow_analysis_v1"
	EvidenceSnapshotVersion    = "evidence-snapshot-v1"
	DefaultMinimumTTLSeconds   = 60
	DefaultTTLSeconds          = 1800
	DefaultMaximumTTLSeconds   = 86400
	MaxSignals                 = 50
	maxResponseIDBytes         = 128
)

var (
	ErrInvalidConfig      = errors.New("analysis worker: invalid configuration")
	ErrInvalidLease       = errors.New("analysis worker: invalid lease")
	ErrLeaseLost          = errors.New("analysis worker: lease lost")
	ErrUnexpectedJobKind  = errors.New("analysis worker: unexpected job kind")
	ErrPersistence        = errors.New("analysis worker: persistence unavailable")
	ErrInvalidAnalyzer    = errors.New("analysis worker: analyzer returned invalid result")
	ErrAtomicStoreMissing = errors.New("analysis worker: atomic persistence adapter is unavailable")
)

type Config struct {
	LeaseOwner      string
	LeaseDuration   time.Duration
	PollInterval    time.Duration
	MaxConcurrency  int
	RateCardVersion string
	Backoff         worker.BackoffPolicy
}

func DefaultConfig(owner, rateCardVersion string) Config {
	base := worker.DefaultConfig(owner)
	return Config{
		LeaseOwner: owner, LeaseDuration: worker.MaxLeaseDuration,
		PollInterval: base.PollInterval, MaxConcurrency: ai.MaxConcurrency,
		RateCardVersion: rateCardVersion, Backoff: base.Backoff,
	}
}

// Snapshot is the complete allowlisted input projection. It has no fields for
// exact paths, queries, request/response bodies, headers, cookies, credentials,
// account identifiers, or arbitrary log text.
type Snapshot struct {
	IncidentID             string
	IncidentVersion        int32
	AnalysisID             string
	GeneratedAt            time.Time
	EvidenceSnapshotID     string
	EvidenceSnapshotDigest string
	SourceIP               string
	ServiceLabel           string
	WindowStart            time.Time
	WindowEnd              time.Time
	DetectorConfigVersion  string
	Signals                []Signal
	HistoricalImpact       HistoricalImpact
}

type Signal struct {
	SignalID                    string
	RuleID                      string
	Classification              string
	WindowStart                 time.Time
	WindowEnd                   time.Time
	EventCount                  int64
	DistinctAccountCount        int64
	DistinctSuspiciousPathCount int64
	EvidenceDigest              string
}

type HistoricalImpact struct {
	LookbackStart time.Time
	LookbackEnd   time.Time
	ImpactDigest  string
}

// Analyzer is intentionally satisfied by *ai.Client. That client owns the
// mandatory pre-call atomic worst-case reservation, strict Responses request,
// trusted-usage settlement, and conservative full charging on failure or
// malformed usage. An implementation that bypasses those properties is not a
// production adapter.
type Analyzer interface {
	Identity() ai.ProviderIdentity
	Analyze(context.Context, []byte) (ai.Result, error)
}

var _ Analyzer = (*ai.Client)(nil)

// Store is a deliberately stronger boundary than worker.Store. Prepare must
// atomically verify the live lease token, lock the incident/version, enforce
// that the immutable analysis attempt has not already started, persist its
// started marker, and return the compact allowlisted projection with a
// database-fixed GeneratedAt. PostgreSQL's clock is authoritative for lease
// validity and timestamps; caller times are never an authorization input. A
// false result means no provider call is allowed.
// This conservative marker prevents a crash after an OpenAI call from causing
// an unbounded new call on lease recovery.
//
// Finalize must execute as one database transaction and in this order:
//
//  1. lock and verify the still-live outbox lease by job ID and token;
//  2. apply Mutation, including its audit row and optional validation outbox;
//  3. apply the requested retry/dead/completed transition; and
//  4. commit all effects together.
//
// If the lease is stale, Finalize returns (false, nil) and commits no mutation.
// A successful mutation must never be committed separately from completion.
type Store interface {
	Lease(context.Context, worker.LeaseRequest) (worker.LeasedJob, bool, error)
	Prepare(context.Context, PrepareRequest) (Snapshot, bool, error)
	Finalize(context.Context, FinalizeRequest) (bool, error)
}

type PrepareRequest struct {
	Job        worker.Job
	LeaseToken string
}

type FinalizeRequest struct {
	Finish   worker.FinishRequest
	Mutation *Mutation
}

type AnalysisState string

const (
	StateReviewReady    AnalysisState = "review_ready"
	StateAnalysisFailed AnalysisState = "analysis_failed"
)

// Mutation is the atomic domain effect associated with a completed analyze
// job. Exactly one of Success and Failure is populated.
type Mutation struct {
	IncidentID             string
	IncidentVersion        int32
	AnalysisID             string
	EvidenceSnapshotID     string
	EvidenceSnapshotDigest string
	State                  AnalysisState
	Success                *Success
	Failure                *Failure
	AuditAction            string
	ValidationRequested    bool
}

type Success struct {
	ProviderKind           string
	AdapterID              string
	Model                  string
	ReasoningEffort        string
	RateCardVersion        string
	ResponseID             string
	Attempts               int
	InputBytes             int
	InputDigest            string
	InputSchemaDigest      string
	PromptDigest           string
	OutputSchemaDigest     string
	OutputDigest           string
	AnalysisJSON           []byte
	PolicyJSON             []byte
	CommandCandidateJSON   []byte
	GeneratedCommandDigest string
	EvidenceIDs            []string
	Usage                  ai.Usage
}

type Failure struct {
	Reason        ai.FailureReason
	Attempts      int
	RetryEligible bool
	InputBytes    int
	InputDigest   string
}

type Result struct {
	Outcome       worker.Outcome
	JobID         string
	IncidentID    string
	Attempt       int32
	State         AnalysisState
	FailureReason ai.FailureReason
	FailureCode   string
	RetryAt       *time.Time
}

type Dependencies struct {
	Clock  Clock
	Tokens worker.TokenSource
	Jitter worker.JitterSource
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}
