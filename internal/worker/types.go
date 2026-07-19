package worker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const MaxLeaseDuration = 60 * time.Second

var (
	asciiIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

	ErrLeaseLost       = errors.New("worker: lease lost")
	ErrInvalidLease    = errors.New("worker: invalid leased job")
	ErrForbiddenJob    = errors.New("worker: dispatcher job is forbidden")
	ErrInvalidStoreRow = errors.New("worker: invalid store result")
)

// JobKind is a database outbox discriminator. Dispatch jobs intentionally do
// not belong to the generic worker; only the separately privileged dispatcher
// may consume them.
type JobKind string

const (
	JobDetect        JobKind = "detect"
	JobCorrelate     JobKind = "correlate"
	JobAnalyze       JobKind = "analyze"
	JobValidate      JobKind = "validate"
	JobReconcile     JobKind = "reconcile"
	JobRetention     JobKind = "retention"
	JobAuditRecovery JobKind = "audit_recovery"

	JobDispatchAdd     JobKind = "dispatch_add"
	JobDispatchRevoke  JobKind = "dispatch_revoke"
	JobDispatchInspect JobKind = "dispatch_inspect"
)

func (k JobKind) isDispatch() bool {
	switch k {
	case JobDispatchAdd, JobDispatchRevoke, JobDispatchInspect:
		return true
	default:
		return false
	}
}

func (k JobKind) isGeneric() bool {
	switch k {
	case JobDetect, JobCorrelate, JobAnalyze, JobValidate, JobReconcile, JobRetention, JobAuditRecovery:
		return true
	default:
		return false
	}
}

// Job is the typed, payload-free envelope passed to a domain handler. A
// handler resolves required state by aggregate ID and version. Lease tokens,
// owners, and expiry timestamps are intentionally not exposed to handlers.
type Job struct {
	JobID            string
	Kind             JobKind
	AggregateType    string
	AggregateID      string
	AggregateVersion int32
	Attempt          int32
	MaxAttempts      int32
}

// LeasedJob is the Store-to-Runner lease record. Its fencing authority stays
// inside the persistence/runtime boundary and is removed before handler
// invocation.
type LeasedJob struct {
	Job
	State          string
	AvailableAt    time.Time
	LeaseToken     string
	LeaseOwner     string
	LeaseGrantedAt time.Time
	LeaseExpiresAt time.Time
}

type LeaseRequest struct {
	Now            time.Time
	LeaseToken     string
	LeaseOwner     string
	LeaseExpiresAt time.Time
}

type FinishState string

const (
	FinishCompleted FinishState = "completed"
	FinishRetry     FinishState = "retry"
	FinishDead      FinishState = "dead"
)

type FinishRequest struct {
	State       FinishState
	RetryAt     *time.Time
	ErrorCode   string
	ErrorDigest string
	Now         time.Time
	JobID       string
	LeaseToken  string
}

// Store is the complete persistence authority required by Runner. Production
// implementations must delegate to the SECURITY DEFINER lease and finish
// functions rather than updating outbox rows directly.
type Store interface {
	Lease(context.Context, LeaseRequest) (LeasedJob, bool, error)
	Finish(context.Context, FinishRequest) (bool, error)
}

type Handler interface {
	Handle(context.Context, Job) error
}

type HandlerFunc func(context.Context, Job) error

func (f HandlerFunc) Handle(ctx context.Context, job Job) error {
	return f(ctx, job)
}

// HandlerFailure forces a handler to classify its outcome. Error deliberately
// omits Cause so accidental logging cannot disclose payloads or secrets.
type HandlerFailure struct {
	Code      string
	Retryable bool
	cause     error
}

func RetryableFailure(code string, cause error) *HandlerFailure {
	return &HandlerFailure{Code: code, Retryable: true, cause: cause}
}

func PermanentFailure(code string, cause error) *HandlerFailure {
	return &HandlerFailure{Code: code, Retryable: false, cause: cause}
}

func (e *HandlerFailure) Error() string {
	if e == nil {
		return "worker handler failure"
	}
	return fmt.Sprintf("worker handler failure: %s", e.Code)
}

func (e *HandlerFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type Registry struct {
	handlers map[JobKind]Handler
}

func NewRegistry(handlers map[JobKind]Handler) (*Registry, error) {
	registry := &Registry{handlers: make(map[JobKind]Handler, len(handlers))}
	for kind, handler := range handlers {
		if !kind.isGeneric() {
			return nil, fmt.Errorf("worker: handler kind is not available to the generic worker")
		}
		if handler == nil {
			return nil, fmt.Errorf("worker: nil handler")
		}
		registry.handlers[kind] = handler
	}
	return registry, nil
}

func (r *Registry) lookup(kind JobKind) (Handler, bool) {
	if r == nil {
		return nil, false
	}
	handler, ok := r.handlers[kind]
	return handler, ok
}

type Outcome string

const (
	OutcomeNoJob          Outcome = "no_job"
	OutcomeCompleted      Outcome = "completed"
	OutcomeRetryScheduled Outcome = "retry_scheduled"
	OutcomeDeadLettered   Outcome = "dead_lettered"
	OutcomeLeaseLost      Outcome = "lease_lost"
)

// Result contains only bounded operational metadata. It never includes a
// handler error, panic value, aggregate payload, or credential.
type Result struct {
	Outcome     Outcome
	JobID       string
	Kind        JobKind
	Attempt     int32
	FailureCode string
	RetryAt     *time.Time
}
