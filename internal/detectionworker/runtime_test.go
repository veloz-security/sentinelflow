package detectionworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/worker"
)

var runtimeTestNow = time.Date(2026, 7, 18, 5, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(context.Context, time.Duration) error { return nil }

type fixedTokens struct{ value string }

func (s fixedTokens) NewLeaseToken() (string, error) { return s.value, nil }

type fixedJitter struct{}

func (fixedJitter) Uint64() (uint64, error) { return 0, nil }

type cancellableClock struct{ now time.Time }

func (c cancellableClock) Now() time.Time { return c.now }

func (cancellableClock) Sleep(ctx context.Context, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

type fakeStore struct {
	mu              sync.Mutex
	job             worker.LeasedJob
	snapshot        Snapshot
	leaseFound      bool
	prepareFound    bool
	prepareErr      error
	finalizeFound   bool
	finalizeResult  FinalizeResult
	finalizeErr     error
	mutation        Mutation
	failure         worker.FinishRequest
	failureFinished bool
	failureErr      error
}

func (s *fakeStore) Lease(_ context.Context, request worker.LeaseRequest) (worker.LeasedJob, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.leaseFound {
		return worker.LeasedJob{}, false, nil
	}
	job := s.job
	job.LeaseToken = request.LeaseToken
	job.LeaseOwner = request.LeaseOwner
	job.LeaseGrantedAt = request.Now
	job.LeaseExpiresAt = request.LeaseExpiresAt
	return job, true, nil
}

func (s *fakeStore) Prepare(context.Context, worker.LeasedJob) (Snapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot, s.prepareFound, s.prepareErr
}

func (s *fakeStore) Finalize(_ context.Context, request FinalizeRequest) (FinalizeResult, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutation = request.Mutation
	result := s.finalizeResult
	if result.Effects == nil {
		for _, signal := range request.Mutation.Signals {
			result.Effects = append(result.Effects, SignalEffect{
				SignalID: signal.SignalID, Disposition: SignalCreated,
				IncidentID: "019f0000-0000-8000-8000-000000000099", IncidentVersion: 1,
			})
			result.IncidentMutations++
		}
	}
	return result, s.finalizeFound, s.finalizeErr
}

func (s *fakeStore) FinishFailure(_ context.Context, request worker.FinishRequest) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = request
	return s.failureFinished, s.failureErr
}

func (*fakeStore) CloseIdle(context.Context, int) (int, error) { return 0, nil }

type cancelAfterRetryStore struct {
	*fakeStore
	cancel     context.CancelFunc
	leaseCalls int
}

func (s *cancelAfterRetryStore) Lease(ctx context.Context, request worker.LeaseRequest) (worker.LeasedJob, bool, error) {
	s.leaseCalls++
	if s.leaseCalls == 2 {
		s.cancel()
		return worker.LeasedJob{}, false, nil
	}
	return s.fakeStore.Lease(ctx, request)
}

func TestRuntimeCompletesDeterministicBurstAndPersistsExactMutation(t *testing.T) {
	t.Parallel()
	input := completeInput(runtimeTestNow)
	for index := 0; index < detection.RequestBurstThreshold; index++ {
		input.GatewayEvents = append(input.GatewayEvents, gatewayObservation(index, runtimeTestNow))
	}
	store := validFakeStore(input)
	runtime := newTestRuntime(t, store)
	result, err := runtime.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != worker.OutcomeCompleted || result.RunOutcome != RunComplete ||
		result.SignalCount != 1 || result.IncidentMutations != 1 {
		t.Fatalf("result = %+v", result)
	}
	if store.mutation.Outcome != RunComplete || len(store.mutation.Signals) != 1 ||
		store.mutation.Signals[0].RuleID != detection.RuleRequestBurst ||
		!digestPattern.MatchString(store.mutation.InputDigest) {
		t.Fatalf("mutation = %+v", store.mutation)
	}
}

func TestRuntimeRetriesIncompleteCoverageWithoutPrematureMutation(t *testing.T) {
	t.Parallel()
	input := completeInput(runtimeTestNow)
	input.GatewayHealth.Complete = false
	input.GatewayEvents = append(input.GatewayEvents, gatewayObservation(1, runtimeTestNow))
	store := validFakeStore(input)
	store.failureFinished = true
	result, err := newTestRuntime(t, store).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != worker.OutcomeRetryScheduled || result.RunOutcome != RunIncomplete ||
		result.FailureCode != "detection_source_coverage_incomplete" || result.RetryAt == nil ||
		store.failure.State != worker.FinishRetry || store.mutation.ConfigurationVersion != "" {
		t.Fatalf("result=%+v failure=%+v mutation=%+v", result, store.failure, store.mutation)
	}
}

func TestRuntimePersistsTerminalIncompleteOnlyAtMaxAttempt(t *testing.T) {
	t.Parallel()
	input := completeInput(runtimeTestNow)
	input.GatewayHealth.Complete = false
	input.GatewayEvents = append(input.GatewayEvents, gatewayObservation(1, runtimeTestNow))
	store := validFakeStore(input)
	store.job.Attempt = store.job.MaxAttempts
	result, err := newTestRuntime(t, store).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != worker.OutcomeCompleted || result.RunOutcome != RunIncomplete ||
		result.SignalCount != 0 || store.mutation.Outcome != RunIncomplete ||
		len(store.mutation.Signals) != 0 || store.failure.State != "" {
		t.Fatalf("result=%+v failure=%+v mutation=%+v", result, store.failure, store.mutation)
	}
}

func TestRuntimePersistsIndependentSignalDespiteOtherIncompleteSource(t *testing.T) {
	t.Parallel()
	input := completeInput(runtimeTestNow)
	input.AuthHealth.Complete = false
	for index := 0; index < detection.RequestBurstThreshold; index++ {
		input.GatewayEvents = append(input.GatewayEvents, gatewayObservation(index, runtimeTestNow))
	}
	store := validFakeStore(input)
	result, err := newTestRuntime(t, store).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != worker.OutcomeCompleted || result.RunOutcome != RunComplete ||
		result.SignalCount != 1 || len(store.mutation.Signals) != 1 ||
		store.mutation.Signals[0].RuleID != detection.RuleRequestBurst ||
		store.failure.State != "" {
		t.Fatalf("result=%+v failure=%+v mutation=%+v", result, store.failure, store.mutation)
	}
}

func TestRuntimeRecordsNoCandidatesWithoutManufacturingSignals(t *testing.T) {
	t.Parallel()
	store := validFakeStore(completeInput(runtimeTestNow))
	store.snapshot.CandidateSourceIPs = nil
	result, err := newTestRuntime(t, store).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.RunOutcome != RunNoCandidates || store.mutation.Outcome != RunNoCandidates ||
		len(store.mutation.Signals) != 0 {
		t.Fatalf("result=%+v mutation=%+v", result, store.mutation)
	}
}

func TestRuntimeRetriesNoCandidateSnapshotWhenARequiredSourceIsIncomplete(t *testing.T) {
	t.Parallel()
	input := completeInput(runtimeTestNow)
	input.AuthHealth.Complete = false
	store := validFakeStore(input)
	store.snapshot.CandidateSourceIPs = nil
	store.failureFinished = true
	result, err := newTestRuntime(t, store).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != worker.OutcomeRetryScheduled || result.RunOutcome != RunIncomplete ||
		result.FailureCode != "detection_source_coverage_incomplete" ||
		store.mutation.ConfigurationVersion != "" {
		t.Fatalf("result=%+v mutation=%+v", result, store.mutation)
	}
}

func TestRuntimeRejectsUnsortedCandidateIdentityAndFencesFailure(t *testing.T) {
	t.Parallel()
	store := validFakeStore(completeInput(runtimeTestNow))
	store.snapshot.CandidateSourceIPs = []string{"203.0.113.9", "198.51.100.4"}
	store.failureFinished = true
	result, err := newTestRuntime(t, store).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != worker.OutcomeRetryScheduled ||
		result.FailureCode != "detection_snapshot_invalid" ||
		store.failure.ErrorCode != "detection_snapshot_invalid" ||
		!digestPattern.MatchString(store.failure.ErrorDigest) {
		t.Fatalf("result=%+v failure=%+v", result, store.failure)
	}
}

func TestRuntimePreservesDuplicateSignalAsNoIncidentMutation(t *testing.T) {
	t.Parallel()
	input := completeInput(runtimeTestNow)
	for index := 0; index < detection.RequestBurstThreshold; index++ {
		input.GatewayEvents = append(input.GatewayEvents, gatewayObservation(index, runtimeTestNow))
	}
	store := validFakeStore(input)
	detector := detection.NewDefault()
	output, err := detector.Evaluate(input)
	if err != nil || len(output.RequestBurst) != 1 || output.RequestBurst[0].Signal == nil {
		t.Fatalf("fixture output=%+v err=%v", output, err)
	}
	store.finalizeResult = FinalizeResult{Effects: []SignalEffect{{
		SignalID: output.RequestBurst[0].Signal.SignalID, Disposition: SignalDuplicate,
		IncidentID: "019f0000-0000-8000-8000-000000000099", IncidentVersion: 7,
	}}}
	result, err := newTestRuntime(t, store).RunOnce(context.Background())
	if err != nil || result.SignalCount != 1 || result.IncidentMutations != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestRuntimeFencesRetryableFinalizeConflictThroughDurableBackoff(t *testing.T) {
	t.Parallel()
	input := completeInput(runtimeTestNow)
	for index := 0; index < detection.RequestBurstThreshold; index++ {
		input.GatewayEvents = append(input.GatewayEvents, gatewayObservation(index, runtimeTestNow))
	}
	store := validFakeStore(input)
	store.finalizeErr = ErrRetryablePersistence
	store.failureFinished = true
	result, err := newTestRuntime(t, store).RunOnce(context.Background())
	if err != nil || result.Outcome != worker.OutcomeRetryScheduled ||
		result.FailureCode != "detection_transaction_retry" || result.RetryAt == nil ||
		store.failure.State != worker.FinishRetry ||
		store.failure.ErrorCode != "detection_transaction_retry" ||
		!digestPattern.MatchString(store.failure.ErrorDigest) {
		t.Fatalf("result=%+v failure=%+v err=%v", result, store.failure, err)
	}
}

func TestRuntimeLoopContinuesAfterRetryableFinalizeConflict(t *testing.T) {
	t.Parallel()
	base := validFakeStore(completeInput(runtimeTestNow))
	base.finalizeErr = ErrRetryablePersistence
	base.failureFinished = true
	ctx, cancel := context.WithCancel(context.Background())
	store := &cancelAfterRetryStore{fakeStore: base, cancel: cancel}
	config := DefaultConfig("detection-test")
	config.LeaseDuration = 30 * time.Second
	runtime, err := New(store, detection.NewDefault(), config, Dependencies{
		Clock:  cancellableClock{now: runtimeTestNow.Add(time.Second)},
		Tokens: fixedTokens{"019f0000-0000-4000-8000-000000000003"}, Jitter: fixedJitter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.Run(ctx); err != nil || store.leaseCalls != 2 ||
		base.failure.ErrorCode != "detection_transaction_retry" {
		t.Fatalf("lease_calls=%d failure=%+v err=%v", store.leaseCalls, base.failure, err)
	}
}

func TestRuntimeDeadLettersRetryableFinalizeConflictAtAttemptBound(t *testing.T) {
	t.Parallel()
	store := validFakeStore(completeInput(runtimeTestNow))
	store.job.Attempt = store.job.MaxAttempts
	store.finalizeErr = ErrRetryablePersistence
	store.failureFinished = true
	result, err := newTestRuntime(t, store).RunOnce(context.Background())
	if err != nil || result.Outcome != worker.OutcomeDeadLettered ||
		result.FailureCode != "detection_transaction_retry" || result.RetryAt != nil ||
		store.failure.State != worker.FinishDead || store.failure.RetryAt != nil {
		t.Fatalf("result=%+v failure=%+v err=%v", result, store.failure, err)
	}
}

func TestRuntimeFencesRetryablePrepareConflictThroughDurableBackoff(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Add(time.Minute)
	store := validFakeStore(completeInput(now))
	store.prepareErr = ErrRetryablePersistence
	store.failureFinished = true
	result, err := newTestRuntimeAt(t, store, now).RunOnce(context.Background())
	if err != nil || result.Outcome != worker.OutcomeRetryScheduled ||
		result.FailureCode != "detection_transaction_retry" || result.RetryAt == nil ||
		store.failure.State != worker.FinishRetry ||
		store.failure.ErrorCode != "detection_transaction_retry" ||
		!digestPattern.MatchString(store.failure.ErrorDigest) {
		t.Fatalf("result=%+v failure=%+v err=%v", result, store.failure, err)
	}
}

func TestRuntimeDeadLettersRetryablePrepareConflictAtAttemptBound(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Add(time.Minute)
	store := validFakeStore(completeInput(now))
	store.job.Attempt = store.job.MaxAttempts
	store.prepareErr = ErrRetryablePersistence
	store.failureFinished = true
	result, err := newTestRuntimeAt(t, store, now).RunOnce(context.Background())
	if err != nil || result.Outcome != worker.OutcomeDeadLettered ||
		result.FailureCode != "detection_transaction_retry" || result.RetryAt != nil ||
		store.failure.State != worker.FinishDead || store.failure.RetryAt != nil {
		t.Fatalf("result=%+v failure=%+v err=%v", result, store.failure, err)
	}
}

func TestPersistenceConflictClassificationIsExactAndRedacted(t *testing.T) {
	t.Parallel()
	for _, code := range []string{"40001", "40P01"} {
		classified := classifyPersistenceError(&pgconn.PgError{Code: code, Message: "secret row"})
		if !errors.Is(classified, ErrRetryablePersistence) || strings.Contains(classified.Error(), "secret") {
			t.Fatalf("code=%s classified=%v", code, classified)
		}
	}
	for _, err := range []error{
		&pgconn.PgError{Code: "23505", Message: "secret row"},
		errors.New("secret transport"),
	} {
		classified := classifyPersistenceError(err)
		if !errors.Is(classified, ErrPersistence) || errors.Is(classified, ErrRetryablePersistence) ||
			strings.Contains(classified.Error(), "secret") {
			t.Fatalf("classified=%v", classified)
		}
	}
}

func validFakeStore(input detection.EvaluationInput) *fakeStore {
	jobID := "019f0000-0000-8000-8000-000000000001"
	batchID := "019f0000-0000-8000-8000-000000000002"
	return &fakeStore{
		leaseFound: true, prepareFound: true, finalizeFound: true,
		job: worker.LeasedJob{Job: worker.Job{
			JobID: jobID, Kind: worker.JobDetect, AggregateType: "ingest_batch",
			AggregateID: batchID, AggregateVersion: 1, Attempt: 1, MaxAttempts: 8,
		}, State: "leased"},
		snapshot: Snapshot{
			JobID: jobID, AggregateType: "ingest_batch", AggregateID: batchID,
			AggregateVersion: 1, BatchID: batchID, EndpointKind: "gateway",
			ServiceLabel: "demo-app", EvaluatedAt: input.Now,
			CandidateSourceIPs: []string{"203.0.113.9"}, Input: input,
		},
	}
}

func newTestRuntime(t *testing.T, store Store) *Runtime {
	return newTestRuntimeAt(t, store, runtimeTestNow.Add(time.Second))
}

func newTestRuntimeAt(t *testing.T, store Store, now time.Time) *Runtime {
	t.Helper()
	config := DefaultConfig("detection-test")
	config.LeaseDuration = 30 * time.Second
	clock := &fakeClock{now: now}
	runtime, err := New(store, detection.NewDefault(), config, Dependencies{
		Clock: clock, Tokens: fixedTokens{"019f0000-0000-4000-8000-000000000003"},
		Jitter: fixedJitter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func completeInput(now time.Time) detection.EvaluationInput {
	return detection.EvaluationInput{
		Now: now,
		GatewayHealth: detection.SourceHealth{
			Source: detection.SourceGateway, Complete: true,
			CoverageStart: now.Add(-5 * time.Minute), CoverageEnd: now,
		},
		AuthHealth: detection.SourceHealth{
			Source: detection.SourceAuth, Complete: true,
			CoverageStart: now.Add(-5 * time.Minute), CoverageEnd: now,
		},
	}
}

func gatewayObservation(index int, now time.Time) detection.GatewayEvent {
	return detection.GatewayEvent{
		EventID:    fmt.Sprintf("019f0000-0000-8000-8000-%012x", index+100),
		OccurredAt: now.Add(-time.Duration(index%9) * time.Millisecond),
		SourceIP:   "203.0.113.9", ServiceLabel: "demo-app", RouteLabel: "public",
		PathCatalogVersion: "path-catalog-v1", SuspiciousPathID: detection.SuspiciousPathNone,
		StatusCode: 200, TimestampTrust: detection.TimestampTrusted,
		AuthenticationMatch: detection.BindingNotApplicable,
	}
}
