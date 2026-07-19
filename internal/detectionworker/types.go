// Package detectionworker owns the durable, outbox-fenced boundary between
// normalized observations, deterministic detection, and incident correlation.
// It has no AI, policy, HIL, dispatcher, or executor authority.
package detectionworker

import (
	"context"
	"errors"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	DefaultPollInterval = 250 * time.Millisecond
	DefaultCloseLimit   = 100
)

var (
	ErrInvalidConfig        = errors.New("detection worker: invalid configuration")
	ErrInvalidRequest       = errors.New("detection worker: invalid request")
	ErrInvalidSnapshot      = errors.New("detection worker: invalid snapshot")
	ErrPersistence          = errors.New("detection worker: persistence unavailable")
	ErrRetryablePersistence = errors.New("detection worker: retryable persistence conflict")
	ErrLeaseLost            = errors.New("detection worker: lease lost")
)

type Config struct {
	LeaseOwner    string
	LeaseDuration time.Duration
	PollInterval  time.Duration
	CloseLimit    int
	Backoff       worker.BackoffPolicy
}

func DefaultConfig(owner string) Config {
	base := worker.DefaultConfig(owner)
	return Config{
		LeaseOwner: owner, LeaseDuration: worker.MaxLeaseDuration,
		PollInterval: DefaultPollInterval, CloseLimit: DefaultCloseLimit,
		Backoff: base.Backoff,
	}
}

type Snapshot struct {
	JobID              string
	AggregateType      string
	AggregateID        string
	AggregateVersion   int32
	BatchID            string
	EndpointKind       string
	ServiceLabel       string
	EvaluatedAt        time.Time
	CandidateSourceIPs []string
	Input              detection.EvaluationInput
}

type SignalDisposition string

const (
	SignalCreated   SignalDisposition = "created"
	SignalDuplicate SignalDisposition = "duplicate"
)

type SignalEffect struct {
	SignalID        string
	Disposition     SignalDisposition
	IncidentID      string
	IncidentVersion int32
}

type RunOutcome string

const (
	RunComplete     RunOutcome = "complete"
	RunIncomplete   RunOutcome = "incomplete"
	RunNoCandidates RunOutcome = "no_candidates"
)

type Mutation struct {
	ConfigurationVersion string
	ConfigurationDigest  string
	EvaluatedAt          time.Time
	InputDigest          string
	Outcome              RunOutcome
	Signals              []detection.Signal
}

type FinalizeRequest struct {
	Job        worker.LeasedJob
	Snapshot   Snapshot
	Mutation   Mutation
	FinishedAt time.Time
}

type FinalizeResult struct {
	Effects           []SignalEffect
	IncidentMutations int
}

type Store interface {
	Lease(context.Context, worker.LeaseRequest) (worker.LeasedJob, bool, error)
	Prepare(context.Context, worker.LeasedJob) (Snapshot, bool, error)
	Finalize(context.Context, FinalizeRequest) (FinalizeResult, bool, error)
	FinishFailure(context.Context, worker.FinishRequest) (bool, error)
	CloseIdle(context.Context, int) (int, error)
}

type Result struct {
	Outcome           worker.Outcome
	JobID             string
	Attempt           int32
	RunOutcome        RunOutcome
	SignalCount       int
	IncidentMutations int
	FailureCode       string
	RetryAt           *time.Time
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type Dependencies struct {
	Clock  Clock
	Tokens worker.TokenSource
	Jitter worker.JitterSource
}
