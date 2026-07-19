package worker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTokenOne  = "00000000-0000-4000-8000-000000000001"
	testTokenTwo  = "00000000-0000-4000-8000-000000000002"
	testJobOne    = "019b0000-0000-7000-8000-000000000001"
	testJobTwo    = "019b0000-0000-7000-8000-000000000002"
	testAggregate = "019b0000-0000-7000-8000-000000000101"
)

func TestRunnerCompletesSuccessfulJob(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobDetect, 1, 3)}, finishOK: true}
	var handled Job
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{
		JobDetect: HandlerFunc(func(_ context.Context, job Job) error {
			handled = job
			return nil
		}),
	}, &tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Outcome != OutcomeCompleted || result.JobID != testJobOne || handled.JobID != testJobOne {
		t.Fatalf("unexpected result or envelope: result=%+v handled=%+v", result, handled)
	}
	finish := store.onlyFinish(t)
	if finish.State != FinishCompleted || finish.RetryAt != nil ||
		finish.ErrorCode != "" || finish.ErrorDigest != "" {
		t.Fatalf("unexpected successful finish: %+v", finish)
	}
	lease := store.onlyLease(t)
	if lease.LeaseExpiresAt.Sub(lease.Now) != 30*time.Second || lease.LeaseToken != testTokenOne {
		t.Fatalf("unexpected lease request: %+v", lease)
	}
}

func TestRunnerNormalizesLeaseTimesToPostgreSQLPrecision(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime().Add(987 * time.Nanosecond))
	store := &fakeStore{finishOK: true}
	runner := newTestRunner(t, store, clock, nil,
		&tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	result, err := runner.RunOnce(context.Background())
	if err != nil || result.Outcome != OutcomeNoJob {
		t.Fatalf("RunOnce result=%+v err=%v", result, err)
	}
	lease := store.onlyLease(t)
	if lease.Now.Nanosecond()%int(time.Microsecond) != 0 ||
		lease.LeaseExpiresAt.Nanosecond()%int(time.Microsecond) != 0 {
		t.Fatalf("lease times exceed PostgreSQL precision: %+v", lease)
	}
}

func TestRunnerSchedulesTypedRetryWithoutLeakingCause(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobAnalyze, 2, 4)}, finishOK: true}
	secretCause := errors.New("provider response contained secret-value")
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{
		JobAnalyze: HandlerFunc(func(context.Context, Job) error {
			return RetryableFailure("provider_unavailable", secretCause)
		}),
	}, &tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Outcome != OutcomeRetryScheduled || result.FailureCode != "provider_unavailable" {
		t.Fatalf("unexpected retry result: %+v", result)
	}
	finish := store.onlyFinish(t)
	if finish.State != FinishRetry || finish.RetryAt == nil {
		t.Fatalf("unexpected retry finish: %+v", finish)
	}
	// Attempt two has a 20 second exponential ceiling and equal jitter starts at
	// half, so a zero jitter source deterministically schedules ten seconds.
	wantRetryAt := clock.Now().Add(10 * time.Second)
	if !finish.RetryAt.Equal(wantRetryAt) || !result.RetryAt.Equal(wantRetryAt) {
		t.Fatalf("retry time = %v, want %v", finish.RetryAt, wantRetryAt)
	}
	if finish.ErrorDigest != failureDigest("provider_unavailable") ||
		strings.Contains(finish.ErrorDigest, "secret-value") ||
		strings.Contains(RetryableFailure("provider_unavailable", secretCause).Error(), "secret-value") {
		t.Fatal("failure evidence exposed the handler cause")
	}
}

func TestRunnerPermanentlyDeadLettersTypedFailure(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobValidate, 1, 8)}, finishOK: true}
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{
		JobValidate: HandlerFunc(func(context.Context, Job) error {
			return PermanentFailure("invalid_contract", errors.New("untrusted payload"))
		}),
	}, &tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Outcome != OutcomeDeadLettered || result.FailureCode != "invalid_contract" {
		t.Fatalf("unexpected dead-letter result: %+v", result)
	}
	finish := store.onlyFinish(t)
	if finish.State != FinishDead || finish.RetryAt != nil ||
		finish.ErrorDigest != failureDigest("invalid_contract") {
		t.Fatalf("unexpected dead finish: %+v", finish)
	}
}

func TestRunnerUnknownKindFailsClosed(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobKind("future_job"), 1, 8)}, finishOK: true}
	runner := newTestRunner(t, store, clock, nil,
		&tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Outcome != OutcomeDeadLettered || result.FailureCode != "unknown_job_kind" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if finish := store.onlyFinish(t); finish.State != FinishDead || finish.ErrorCode != "unknown_job_kind" {
		t.Fatalf("unexpected finish: %+v", finish)
	}
}

func TestRunnerRefusesDispatchJobWithoutHandlingOrFinishing(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobDispatchAdd, 1, 8)}, finishOK: true}
	runner := newTestRunner(t, store, clock, nil,
		&tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	_, err := runner.RunOnce(context.Background())
	if !errors.Is(err, ErrForbiddenJob) {
		t.Fatalf("error = %v, want ErrForbiddenJob", err)
	}
	if got := store.finishCount(); got != 0 {
		t.Fatalf("dispatch job reached finish path %d times", got)
	}
}

func TestRunnerDoesNotFinishAtExactLeaseExpiry(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobDetect, 1, 3)}, finishOK: true}
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{
		JobDetect: HandlerFunc(func(_ context.Context, _ Job) error {
			clock.Set(clock.Now().Add(30 * time.Second))
			return nil
		}),
	}, &tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	result, err := runner.RunOnce(context.Background())
	if !errors.Is(err, ErrLeaseLost) || result.Outcome != OutcomeLeaseLost {
		t.Fatalf("result=%+v error=%v, want exact-expiry lease loss", result, err)
	}
	if got := store.finishCount(); got != 0 {
		t.Fatalf("finish called %d times at strict expiry", got)
	}
}

func TestRunnerReportsLeaseTokenFenceLoss(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobDetect, 1, 3)}, finishOK: false}
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{
		JobDetect: HandlerFunc(func(context.Context, Job) error { return nil }),
	}, &tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	result, err := runner.RunOnce(context.Background())
	if !errors.Is(err, ErrLeaseLost) || result.Outcome != OutcomeLeaseLost {
		t.Fatalf("result=%+v error=%v, want fenced lease loss", result, err)
	}
	if got := store.finishCount(); got != 1 {
		t.Fatalf("finish count = %d, want 1", got)
	}
}

func TestRunnerDeadLettersRetryableFailureAtMaxAttempt(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobCorrelate, 3, 3)}, finishOK: true}
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{
		JobCorrelate: HandlerFunc(func(context.Context, Job) error {
			return RetryableFailure("dependency_timeout", context.DeadlineExceeded)
		}),
	}, &tokenSequence{values: []string{testTokenOne}}, panicJitter{})

	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Outcome != OutcomeDeadLettered {
		t.Fatalf("unexpected result: %+v", result)
	}
	if finish := store.onlyFinish(t); finish.State != FinishDead || finish.RetryAt != nil {
		t.Fatalf("unexpected max-attempt finish: %+v", finish)
	}
}

func TestRunnerCancellationLeavesLeaseForDatabaseRecovery(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobAnalyze, 1, 3)}, finishOK: true}
	started := make(chan struct{})
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{
		JobAnalyze: HandlerFunc(func(ctx context.Context, _ Job) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}),
	}, &tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runner.RunOnce(ctx)
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce error = %v, want context cancellation", err)
	}
	if got := store.finishCount(); got != 0 {
		t.Fatalf("canceled handler was finished %d times", got)
	}
}

func TestRunnerContainsPanicAndRetriesSafely(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{jobs: []LeasedJob{testJob(JobDetect, 1, 3)}, finishOK: true}
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{
		JobDetect: HandlerFunc(func(context.Context, Job) error {
			panic("secret panic payload")
		}),
	}, &tokenSequence{values: []string{testTokenOne}}, fixedJitter(0))

	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Outcome != OutcomeRetryScheduled || result.FailureCode != "handler_panic" {
		t.Fatalf("panic was not contained as retryable evidence: %+v", result)
	}
	finish := store.onlyFinish(t)
	if finish.ErrorCode != "handler_panic" || strings.Contains(finish.ErrorDigest, "panic payload") {
		t.Fatalf("panic detail escaped bounded evidence: %+v", finish)
	}
}

func TestRunnerSerializesConcurrentRunOnceCalls(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	first := testJob(JobDetect, 1, 3)
	second := first
	second.JobID = testJobTwo
	store := &fakeStore{jobs: []LeasedJob{first, second}, finishOK: true}
	firstStarted := make(chan struct{})
	release := make(chan struct{})
	var calls, active, maximum atomic.Int32
	handler := HandlerFunc(func(context.Context, Job) error {
		current := active.Add(1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-release
		}
		active.Add(-1)
		return nil
	})
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{JobDetect: handler},
		&tokenSequence{values: []string{testTokenOne, testTokenTwo}}, fixedJitter(0))

	errorsCh := make(chan error, 2)
	go func() { _, err := runner.RunOnce(context.Background()); errorsCh <- err }()
	<-firstStarted
	go func() { _, err := runner.RunOnce(context.Background()); errorsCh <- err }()

	deadline := time.After(100 * time.Millisecond)
	for store.leaseCount() != 1 {
		select {
		case <-deadline:
			t.Fatalf("first lease was not observed")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if got := store.leaseCount(); got != 1 {
		t.Fatalf("second lease started concurrently; count=%d", got)
	}
	close(release)
	for range 2 {
		if err := <-errorsCh; err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
	}
	if maximum.Load() != 1 || store.leaseCount() != 2 || store.finishCount() != 2 {
		t.Fatalf("max active=%d leases=%d finishes=%d", maximum.Load(), store.leaseCount(), store.finishCount())
	}
}

func TestRunnerCancellationInterruptsWaitForProcessSlot(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	first := testJob(JobDetect, 1, 3)
	second := first
	second.JobID = testJobTwo
	store := &fakeStore{jobs: []LeasedJob{first, second}, finishOK: true}
	started := make(chan struct{})
	release := make(chan struct{})
	runner := newTestRunner(t, store, clock, map[JobKind]Handler{
		JobDetect: HandlerFunc(func(context.Context, Job) error {
			select {
			case <-started:
			default:
				close(started)
				<-release
			}
			return nil
		}),
	}, &tokenSequence{values: []string{testTokenOne, testTokenTwo}}, fixedJitter(0))

	firstDone := make(chan error, 1)
	go func() { _, err := runner.RunOnce(context.Background()); firstDone <- err }()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runner.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting RunOnce error = %v, want context cancellation", err)
	}
	if got := store.leaseCount(); got != 1 {
		t.Fatalf("canceled waiter leased work; count=%d", got)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
}

func TestRunStopsGracefullyWhileIdle(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime())
	store := &fakeStore{leased: make(chan struct{}, 1), finishOK: true}
	runner := newTestRunner(t, store, clock, nil, repeatingToken(testTokenOne), fixedJitter(0))
	runner.config.PollInterval = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	<-store.leased
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned on graceful cancellation: %v", err)
	}
}

func TestInvalidUntypedAndInvalidCodeErrorsArePermanent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		code string
	}{
		{name: "untyped", err: errors.New("raw payload detail"), code: "unclassified_handler_error"},
		{name: "invalid code", err: RetryableFailure("INVALID CODE", nil), code: "invalid_failure_code"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newFakeClock(testTime())
			store := &fakeStore{jobs: []LeasedJob{testJob(JobDetect, 1, 3)}, finishOK: true}
			runner := newTestRunner(t, store, clock, map[JobKind]Handler{
				JobDetect: HandlerFunc(func(context.Context, Job) error { return test.err }),
			}, &tokenSequence{values: []string{testTokenOne}}, panicJitter{})

			result, err := runner.RunOnce(context.Background())
			if err != nil {
				t.Fatalf("RunOnce: %v", err)
			}
			if result.Outcome != OutcomeDeadLettered || result.FailureCode != test.code {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func newTestRunner(
	t *testing.T,
	store Store,
	clock Clock,
	handlers map[JobKind]Handler,
	tokens TokenSource,
	jitter JitterSource,
) *Runner {
	t.Helper()
	registry, err := NewRegistry(handlers)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	config := DefaultConfig("worker-test")
	config.Backoff = BackoffPolicy{BaseDelay: 10 * time.Second, MaxDelay: time.Minute}
	runner, err := NewRunner(store, registry, config, Dependencies{
		Clock: clock, Tokens: tokens, Jitter: jitter,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return runner
}

func testJob(kind JobKind, attempt, maximum int32) LeasedJob {
	return LeasedJob{
		Job: Job{
			JobID:            testJobOne,
			Kind:             kind,
			AggregateType:    "incident",
			AggregateID:      testAggregate,
			AggregateVersion: 1,
			Attempt:          attempt,
			MaxAttempts:      maximum,
		},
	}
}

func testTime() time.Time {
	return time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond)
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

type tokenSequence struct {
	mu     sync.Mutex
	values []string
}

func (s *tokenSequence) NewLeaseToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.values) == 0 {
		return "", errors.New("no test token")
	}
	value := s.values[0]
	s.values = s.values[1:]
	return value, nil
}

type repeatingToken string

func (s repeatingToken) NewLeaseToken() (string, error) { return string(s), nil }

type fixedJitter uint64

func (j fixedJitter) Uint64() (uint64, error) { return uint64(j), nil }

type panicJitter struct{}

func (panicJitter) Uint64() (uint64, error) { panic("jitter must not be requested") }

type fakeStore struct {
	mu       sync.Mutex
	jobs     []LeasedJob
	leases   []LeaseRequest
	finishes []FinishRequest
	finishOK bool
	leased   chan struct{}
}

func (s *fakeStore) Lease(_ context.Context, request LeaseRequest) (LeasedJob, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases = append(s.leases, request)
	if s.leased != nil {
		select {
		case s.leased <- struct{}{}:
		default:
		}
	}
	if len(s.jobs) == 0 {
		return LeasedJob{}, false, nil
	}
	job := s.jobs[0]
	s.jobs = s.jobs[1:]
	job.State = "leased"
	job.LeaseToken = request.LeaseToken
	job.LeaseOwner = request.LeaseOwner
	job.LeaseGrantedAt = request.Now
	job.LeaseExpiresAt = request.LeaseExpiresAt
	return job, true, nil
}

func (s *fakeStore) Finish(_ context.Context, request FinishRequest) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishes = append(s.finishes, request)
	return s.finishOK, nil
}

func (s *fakeStore) onlyLease(t *testing.T) LeaseRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.leases) != 1 {
		t.Fatalf("lease requests = %d, want 1", len(s.leases))
	}
	return s.leases[0]
}

func (s *fakeStore) onlyFinish(t *testing.T) FinishRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.finishes) != 1 {
		t.Fatalf("finish requests = %d, want 1", len(s.finishes))
	}
	return s.finishes[0]
}

func (s *fakeStore) leaseCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.leases)
}

func (s *fakeStore) finishCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.finishes)
}
