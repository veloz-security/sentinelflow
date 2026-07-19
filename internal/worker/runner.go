package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const failureDigestDomain = "sentinelflow worker-failure-v1\n"

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

type Config struct {
	LeaseOwner    string
	LeaseDuration time.Duration
	PollInterval  time.Duration
	Backoff       BackoffPolicy
}

func DefaultConfig(owner string) Config {
	return Config{
		LeaseOwner:    owner,
		LeaseDuration: 30 * time.Second,
		PollInterval:  250 * time.Millisecond,
		Backoff: BackoffPolicy{
			BaseDelay: time.Second,
			MaxDelay:  time.Minute,
		},
	}
}

func (c Config) validate() error {
	if !asciiIDPattern.MatchString(c.LeaseOwner) || c.LeaseDuration <= 0 ||
		c.LeaseDuration > MaxLeaseDuration || c.PollInterval <= 0 {
		return errors.New("worker: invalid runner config")
	}
	return c.Backoff.validate()
}

type Dependencies struct {
	Clock  Clock
	Tokens TokenSource
	Jitter JitterSource
}

type Runner struct {
	store    Store
	registry *Registry
	config   Config
	clock    Clock
	tokens   TokenSource
	jitter   JitterSource

	processGate chan struct{}
}

func NewRunner(store Store, registry *Registry, config Config, dependencies Dependencies) (*Runner, error) {
	if store == nil {
		return nil, errors.New("worker: store is required")
	}
	if registry == nil {
		return nil, errors.New("worker: registry is required")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if dependencies.Clock == nil {
		dependencies.Clock = SystemClock{}
	}
	if dependencies.Tokens == nil {
		dependencies.Tokens = CryptoTokenSource{}
	}
	if dependencies.Jitter == nil {
		dependencies.Jitter = CryptoJitterSource{}
	}
	return &Runner{
		store: store, registry: registry, config: config,
		clock: dependencies.Clock, tokens: dependencies.Tokens,
		jitter: dependencies.Jitter, processGate: make(chan struct{}, 1),
	}, nil
}

// Run processes jobs serially until cancellation. Cancellation is a graceful
// stop and therefore returns nil. Other store or invariant failures return to
// the process supervisor without attempting an unfenced completion.
func (r *Runner) Run(ctx context.Context) error {
	for {
		result, err := r.RunOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrLeaseLost) {
				continue
			}
			return err
		}
		if result.Outcome != OutcomeNoJob {
			continue
		}

		timer := time.NewTimer(r.config.PollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-timer.C:
		}
	}
}

// RunOnce leases and completes at most one job. Calls on the same Runner are
// serialized so one process-local runner cannot invoke handlers concurrently.
func (r *Runner) RunOnce(ctx context.Context) (Result, error) {
	select {
	case r.processGate <- struct{}{}:
		defer func() { <-r.processGate }()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	// PostgreSQL timestamptz has microsecond precision. Normalize before
	// creating the lease so the row returned by PostgreSQL remains byte-for-
	// byte comparable to the exact request instead of losing nanoseconds.
	now := postgresTime(r.clock.Now())
	token, err := r.tokens.NewLeaseToken()
	if err != nil {
		return Result{}, err
	}
	if !validUUIDV4(token) {
		return Result{}, fmt.Errorf("worker: token source returned invalid UUIDv4")
	}
	leaseRequest := LeaseRequest{
		Now:            now,
		LeaseToken:     token,
		LeaseOwner:     r.config.LeaseOwner,
		LeaseExpiresAt: now.Add(r.config.LeaseDuration),
	}
	job, found, err := r.store.Lease(ctx, leaseRequest)
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{Outcome: OutcomeNoJob}, nil
	}
	result := Result{JobID: job.JobID, Kind: job.Kind, Attempt: job.Attempt}
	if err := validateLeasedJob(job, leaseRequest); err != nil {
		return result, err
	}
	if job.Kind.isDispatch() {
		return result, ErrForbiddenJob
	}

	handlerCtx, cancel := context.WithDeadline(ctx, job.LeaseExpiresAt)
	handlerErr := r.invoke(handlerCtx, job)
	handlerContextErr := handlerCtx.Err()
	cancel()

	if err := ctx.Err(); err != nil {
		return result, err
	}
	completionNow := postgresTime(r.clock.Now())
	if handlerContextErr != nil || !completionNow.Before(job.LeaseExpiresAt) {
		result.Outcome = OutcomeLeaseLost
		return result, ErrLeaseLost
	}

	finish := FinishRequest{
		State:      FinishCompleted,
		Now:        completionNow,
		JobID:      job.JobID,
		LeaseToken: job.LeaseToken,
	}
	if handlerErr != nil {
		code, retryable := classifyHandlerFailure(handlerErr)
		finish.ErrorCode = code
		finish.ErrorDigest = failureDigest(code)
		result.FailureCode = code
		if retryable && job.Attempt < job.MaxAttempts {
			jitter, jitterErr := r.jitter.Uint64()
			if jitterErr != nil {
				return result, fmt.Errorf("worker: retry jitter unavailable: %w", jitterErr)
			}
			delay, delayErr := r.config.Backoff.Delay(job.Attempt, jitter)
			if delayErr != nil {
				return result, delayErr
			}
			retryAt := postgresTime(completionNow.Add(delay))
			finish.State = FinishRetry
			finish.RetryAt = &retryAt
			result.Outcome = OutcomeRetryScheduled
			result.RetryAt = &retryAt
		} else {
			finish.State = FinishDead
			result.Outcome = OutcomeDeadLettered
		}
	} else {
		result.Outcome = OutcomeCompleted
	}

	finished, err := r.store.Finish(ctx, finish)
	if err != nil {
		return result, err
	}
	if !finished {
		result.Outcome = OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	return result, nil
}

func (r *Runner) invoke(ctx context.Context, job LeasedJob) (err error) {
	defer func() {
		if recover() != nil {
			err = RetryableFailure("handler_panic", nil)
		}
	}()
	handler, ok := r.registry.lookup(job.Kind)
	if !ok {
		return PermanentFailure("unknown_job_kind", nil)
	}
	return handler.Handle(ctx, job.Job)
}

func validateLeasedJob(job LeasedJob, request LeaseRequest) error {
	requestedDuration := request.LeaseExpiresAt.Sub(request.Now)
	if !uuidPattern.MatchString(job.JobID) || job.AggregateType == "" ||
		!asciiIDPattern.MatchString(job.AggregateType) ||
		!uuidPattern.MatchString(job.AggregateID) || job.AggregateVersion < 1 ||
		job.State != "leased" || job.LeaseToken != request.LeaseToken ||
		job.LeaseOwner != request.LeaseOwner ||
		job.LeaseGrantedAt.IsZero() ||
		!job.LeaseExpiresAt.After(job.LeaseGrantedAt) ||
		job.LeaseExpiresAt.Sub(job.LeaseGrantedAt) != requestedDuration ||
		requestedDuration <= 0 || requestedDuration > MaxLeaseDuration ||
		job.Attempt < 1 || job.MaxAttempts < 1 || job.Attempt > job.MaxAttempts {
		return ErrInvalidLease
	}
	return nil
}

func classifyHandlerFailure(err error) (string, bool) {
	var failure *HandlerFailure
	if !errors.As(err, &failure) {
		return "unclassified_handler_error", false
	}
	if failure == nil || !asciiIDPattern.MatchString(failure.Code) {
		return "invalid_failure_code", false
	}
	return failure.Code, failure.Retryable
}

func failureDigest(code string) string {
	sum := sha256.Sum256([]byte(failureDigestDomain + code + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func postgresTime(value time.Time) time.Time {
	return time.UnixMicro(value.UTC().UnixMicro()).UTC()
}
