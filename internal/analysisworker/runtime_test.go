package analysisworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	testLeaseToken = "00000000-0000-4000-8000-000000000001"
	testJobID      = "019b0000-0000-7000-8000-000000000001"
	testIncidentID = "019b0000-0000-7000-8000-000000000101"
	testAnalysisID = "019b0000-0000-7000-8000-000000000201"
	testSnapshotID = "019b0000-0000-7000-8000-000000000301"
	testSignalID   = "019b0000-0000-7000-8000-000000000401"
	testDigest     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestRuntimePersistsSuccessfulAnalysisAndValidationRequestAtomically(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: true}
	var received []byte
	analyzer := analyzerFunc(func(_ context.Context, input []byte) (ai.Result, error) {
		received = append([]byte(nil), input...)
		return successfulResult(t, input, store.snapshot, ai.Usage{
			InputTokens: 800, CachedInputTokens: 200, OutputTokens: 100, Trusted: true,
		}), nil
	})
	runtime := newTestRuntime(t, store, analyzer, clock)

	result, err := runtime.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.Outcome != worker.OutcomeCompleted || result.State != StateReviewReady {
		t.Fatalf("result = %+v", result)
	}
	prepare := store.onlyPrepare(t)
	if prepare.LeaseToken != testLeaseToken || prepare.Job.JobID != testJobID ||
		prepare.Job.AggregateID != testIncidentID {
		t.Fatalf("prepare request = %+v", prepare)
	}
	final := store.onlyFinalize(t)
	if final.Finish.State != worker.FinishCompleted || final.Finish.LeaseToken != testLeaseToken ||
		final.Mutation == nil || !final.Mutation.ValidationRequested || final.Mutation.Failure != nil {
		t.Fatalf("finalization = %+v", final)
	}
	success := final.Mutation.Success
	if success == nil || success.Model != ai.Model || success.ReasoningEffort != ai.ReasoningEffort ||
		success.ProviderKind != string(ai.ProviderOpenAIResponses) ||
		success.AdapterID != ai.OpenAIResponsesAdapterID ||
		success.RateCardVersion != "operator-v1" || success.InputDigest != digestBytes(received) ||
		success.OutputDigest != digestBytes(success.AnalysisJSON) ||
		success.GeneratedCommandDigest == "" || len(success.PolicyJSON) == 0 ||
		len(success.CommandCandidateJSON) == 0 || !success.Usage.Trusted {
		t.Fatalf("success mutation = %+v", success)
	}
	assertMinimizedInput(t, received)
}

func TestRuntimePersistsDeterministicStubWithoutBillableProvenance(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: true}
	analyzer := identifiedAnalyzer{
		identity: ai.DeterministicStubIdentity(),
		analyze: func(_ context.Context, input []byte) (ai.Result, error) {
			result := successfulResult(t, input, store.snapshot, ai.Usage{})
			result.ResponseID = "stub_" + strings.Repeat("a", 64)
			return result, nil
		},
	}
	runtime, err := New(
		store, analyzer, DefaultConfig("analysis-stub", ""),
		Dependencies{Clock: clock, Tokens: tokenSource{value: testLeaseToken}, Jitter: fixedJitter(0)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	success := store.onlyFinalize(t).Mutation.Success
	if success == nil || success.ProviderKind != string(ai.ProviderDeterministicStub) ||
		success.AdapterID != ai.DeterministicStubAdapterID || success.Model != "" ||
		success.ReasoningEffort != "" || success.RateCardVersion != "" ||
		success.Usage.Trusted || success.Usage.InputTokens != 0 ||
		success.Usage.CachedInputTokens != 0 || success.Usage.OutputTokens != 0 {
		t.Fatalf("stub success provenance=%+v", success)
	}
}

func TestAnalyzerIdentityIsFrozenAndFailClosed(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: true}
	openAI, _ := ai.NewOpenAIResponsesIdentity("operator-v1")
	changing := &changingIdentityAnalyzer{first: openAI, later: ai.DeterministicStubIdentity()}
	runtime, err := New(
		store, changing, DefaultConfig("analysis-01", "operator-v1"),
		Dependencies{Clock: clock, Tokens: tokenSource{value: testLeaseToken}, Jitter: fixedJitter(0)},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.RunOnce(context.Background())
	if err != nil || result.FailureReason != ai.FailureConfiguration || changing.calls.Load() != 0 {
		t.Fatalf("identity mutation result=%+v err=%v calls=%d", result, err, changing.calls.Load())
	}
	if failure := store.onlyFinalize(t).Mutation.Failure; failure == nil ||
		failure.Reason != ai.FailureConfiguration {
		t.Fatalf("identity mutation failure=%+v", failure)
	}

	if _, err = New(store, identifiedAnalyzer{}, DefaultConfig("analysis-01", "operator-v1"), Dependencies{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("zero provider identity error=%v", err)
	}
	stub := identifiedAnalyzer{identity: ai.DeterministicStubIdentity()}
	if _, err = New(store, stub, DefaultConfig("analysis-stub", "operator-v1"), Dependencies{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("stub with paid rate card error=%v", err)
	}
	mismatched, _ := ai.NewOpenAIResponsesIdentity("operator-v2")
	if _, err = New(store, identifiedAnalyzer{identity: mismatched}, DefaultConfig("analysis-01", "operator-v1"), Dependencies{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("OpenAI rate-card mismatch error=%v", err)
	}
}

func TestBudgetExhaustionBecomesCompletedNonEnforcingFailure(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: true}
	runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
		return ai.Result{}, &ai.Failure{Reason: ai.FailureBudgetExhausted, Attempts: 1}
	}), clock)

	result, err := runtime.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.State != StateAnalysisFailed || result.FailureReason != ai.FailureBudgetExhausted ||
		result.Outcome != worker.OutcomeCompleted {
		t.Fatalf("result = %+v", result)
	}
	mutation := store.onlyFinalize(t).Mutation
	if mutation == nil || mutation.State != StateAnalysisFailed || mutation.ValidationRequested ||
		mutation.Success != nil || mutation.Failure == nil || mutation.Failure.RetryEligible {
		t.Fatalf("failure mutation = %+v", mutation)
	}
}

func TestMalformedUsageIsPersistedAsUntrustedAfterConservativeClientSettlement(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: true}
	runtime := newTestRuntime(t, store, analyzerFunc(func(_ context.Context, input []byte) (ai.Result, error) {
		return successfulResult(t, input, store.snapshot, ai.Usage{
			InputTokens: 999999, CachedInputTokens: -4, OutputTokens: 999999, Trusted: false,
		}), nil
	}), clock)

	if _, err := runtime.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	usage := store.onlyFinalize(t).Mutation.Success.Usage
	if usage.Trusted || usage.InputTokens != 0 || usage.CachedInputTokens != 0 || usage.OutputTokens != 0 {
		t.Fatalf("persisted usage = %+v", usage)
	}
}

func TestOpenAIFailuresAreTypedAndDoNotCreateValidationWork(t *testing.T) {
	t.Parallel()
	for _, reason := range []ai.FailureReason{
		ai.FailureNetworkError, ai.FailureHTTP408, ai.FailureHTTP409,
		ai.FailureRateLimited, ai.FailureServerError, ai.FailureTimeout,
		ai.FailureRefused, ai.FailureIncomplete, ai.FailureSchemaInvalid,
		ai.FailureEvidenceInvalid, ai.FailureConfiguration,
	} {
		reason := reason
		t.Run(string(reason), func(t *testing.T) {
			t.Parallel()
			clock := newFakeClock()
			store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: true}
			runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
				return ai.Result{}, &ai.Failure{Reason: reason, Attempts: 2}
			}), clock)
			result, err := runtime.RunOnce(context.Background())
			if err != nil || result.FailureReason != reason {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			mutation := store.onlyFinalize(t).Mutation
			if mutation.ValidationRequested || mutation.Failure == nil || mutation.Failure.Reason != reason {
				t.Fatalf("mutation = %+v", mutation)
			}
			if mutation.Failure.RetryEligible != retryEligible(reason) {
				t.Fatalf("retry eligibility = %v", mutation.Failure.RetryEligible)
			}
		})
	}
}

func TestSnapshotDatabaseFailureRetriesThenDeadLettersWithoutLeakingCause(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		attempt     int32
		maxAttempts int32
		outcome     worker.Outcome
		state       worker.FinishState
	}{
		{name: "retry", attempt: 1, maxAttempts: 3, outcome: worker.OutcomeRetryScheduled, state: worker.FinishRetry},
		{name: "dead", attempt: 3, maxAttempts: 3, outcome: worker.OutcomeDeadLettered, state: worker.FinishDead},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clock := newFakeClock()
			store := &fakeStore{
				snapshot: validSnapshot(clock.Now()), loadErr: errors.New("db password=secret-value"),
				finalizeOK: true, attempt: test.attempt, maxAttempts: test.maxAttempts,
			}
			var calls atomic.Int32
			runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
				calls.Add(1)
				return ai.Result{}, nil
			}), clock)
			result, err := runtime.RunOnce(context.Background())
			if err != nil || result.Outcome != test.outcome || calls.Load() != 0 {
				t.Fatalf("result=%+v calls=%d err=%v", result, calls.Load(), err)
			}
			final := store.onlyFinalize(t)
			if final.Mutation != nil || final.Finish.State != test.state ||
				final.Finish.ErrorCode != "analysis_snapshot_unavailable" ||
				strings.Contains(result.String(), "secret-value") || strings.Contains(final.Finish.ErrorDigest, "secret-value") {
				t.Fatalf("unsafe finalization = %+v result=%s", final, result.String())
			}
		})
	}
}

func TestFinalizeDatabaseErrorIsSanitizedAndLeavesLeaseForRecovery(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{
		snapshot: validSnapshot(clock.Now()), finalizeErr: errors.New("postgres://secret-value"), finalizeOK: true,
	}
	runtime := newTestRuntime(t, store, analyzerFunc(func(_ context.Context, input []byte) (ai.Result, error) {
		return successfulResult(t, input, store.snapshot, ai.Usage{InputTokens: 1, OutputTokens: 1, Trusted: true}), nil
	}), clock)
	_, err := runtime.RunOnce(context.Background())
	if !errors.Is(err, ErrPersistence) || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("RunOnce() error = %v", err)
	}
}

func TestStaleLeaseRollsBackMutationThroughAtomicFinalize(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: false}
	runtime := newTestRuntime(t, store, analyzerFunc(func(_ context.Context, input []byte) (ai.Result, error) {
		return successfulResult(t, input, store.snapshot, ai.Usage{InputTokens: 1, OutputTokens: 1, Trusted: true}), nil
	}), clock)
	result, err := runtime.RunOnce(context.Background())
	if !errors.Is(err, ErrLeaseLost) || result.Outcome != worker.OutcomeLeaseLost {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if store.committedMutations() != 0 || store.onlyFinalize(t).Mutation == nil {
		t.Fatal("fake store did not model atomic stale-lease rollback")
	}
}

func TestAlreadyStartedAttemptNeverCallsProviderOrFinalizes(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{
		snapshot: validSnapshot(clock.Now()), prepareSet: true, prepareOK: false, finalizeOK: true,
	}
	var calls atomic.Int32
	runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
		calls.Add(1)
		return ai.Result{}, nil
	}), clock)
	result, err := runtime.RunOnce(context.Background())
	if !errors.Is(err, ErrLeaseLost) || result.Outcome != worker.OutcomeLeaseLost ||
		calls.Load() != 0 || store.finalizeCount() != 0 {
		t.Fatalf("result=%+v calls=%d finalizations=%d err=%v",
			result, calls.Load(), store.finalizeCount(), err)
	}
}

func TestCancellationDoesNotFinalizeOrLeakAPartialAnalysis(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: true}
	started := make(chan struct{})
	runtime := newTestRuntime(t, store, analyzerFunc(func(ctx context.Context, _ []byte) (ai.Result, error) {
		close(started)
		<-ctx.Done()
		return ai.Result{}, &ai.Failure{Reason: ai.FailureCancelled}
	}), clock)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runtime.RunOnce(ctx)
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if store.finalizeCount() != 0 {
		t.Fatal("canceled analysis was finalized")
	}
}

func TestInvalidSnapshotFailsBeforeAnalyzerAndCannotCreateValidation(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	snapshot := validSnapshot(clock.Now())
	second := snapshot.Signals[0]
	second.SignalID = "019b0000-0000-7000-8000-000000000400"
	snapshot.Signals = append(snapshot.Signals, second)
	store := &fakeStore{snapshot: snapshot, finalizeOK: true}
	var calls atomic.Int32
	runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
		calls.Add(1)
		return ai.Result{}, nil
	}), clock)
	result, err := runtime.RunOnce(context.Background())
	if err != nil || result.FailureReason != ai.FailureEvidenceInvalid || calls.Load() != 0 {
		t.Fatalf("result=%+v calls=%d err=%v", result, calls.Load(), err)
	}
	mutation := store.onlyFinalize(t).Mutation
	if mutation == nil || mutation.ValidationRequested || mutation.Failure == nil {
		t.Fatalf("mutation = %+v", mutation)
	}
}

func TestSignalReferenceLimitAcceptsFiftyWithoutTruncationAndRejectsFiftyOne(t *testing.T) {
	t.Parallel()
	now := newFakeClock().Now()
	fifty := validSnapshot(now)
	fifty.Signals = makeOrderedSignals(50, fifty)
	if reason := validateSnapshot(fifty); reason != "" {
		t.Fatalf("fifty-signal count boundary rejected as %q", reason)
	}
	encoded, reason := buildInput(fifty)
	if reason != ai.FailureInputTooLarge {
		t.Fatalf("fifty-signal byte boundary = %q, want %q", reason, ai.FailureInputTooLarge)
	}
	var document struct {
		Signals      []json.RawMessage `json:"signals"`
		EvidenceRefs []json.RawMessage `json:"evidence_refs"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Signals) != 50 || len(document.EvidenceRefs) != 50 {
		t.Fatalf("fifty-signal input was truncated: signals=%d refs=%d",
			len(document.Signals), len(document.EvidenceRefs))
	}

	fiftyOne := fifty
	fiftyOne.Signals = makeOrderedSignals(51, fiftyOne)
	if _, reason = buildInput(fiftyOne); reason != ai.FailureInputTooLarge {
		t.Fatalf("fifty-one-signal boundary = %q, want %q", reason, ai.FailureInputTooLarge)
	}
	for _, test := range []struct {
		name     string
		snapshot Snapshot
	}{{name: "fifty-byte-cap", snapshot: fifty}, {name: "fifty-one-count-cap", snapshot: fiftyOne}} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{snapshot: test.snapshot, finalizeOK: true}
			var calls atomic.Int32
			runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
				calls.Add(1)
				return ai.Result{}, nil
			}), newFakeClock())
			result, err := runtime.RunOnce(context.Background())
			if err != nil || calls.Load() != 0 || result.FailureReason != ai.FailureInputTooLarge {
				t.Fatalf("runtime result=%+v calls=%d err=%v", result, calls.Load(), err)
			}
			mutation := store.onlyFinalize(t).Mutation
			if mutation == nil || mutation.Failure == nil ||
				mutation.Failure.Reason != ai.FailureInputTooLarge || mutation.ValidationRequested {
				t.Fatalf("failure mutation = %+v", mutation)
			}
		})
	}
}

func TestAnalyzerPanicAndInvalidResultFailClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		analyzer Analyzer
	}{
		{name: "panic", analyzer: analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
			panic("provider secret-value")
		})},
		{name: "invalid result", analyzer: analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
			return ai.Result{Output: []byte(`{}`)}, nil
		})},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clock := newFakeClock()
			store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: true}
			runtime := newTestRuntime(t, store, test.analyzer, clock)
			result, err := runtime.RunOnce(context.Background())
			if err != nil || result.FailureReason != ai.FailureConfiguration && test.name == "panic" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if strings.Contains(result.String(), "secret-value") || store.onlyFinalize(t).Mutation.ValidationRequested {
				t.Fatal("panic detail or validation authority escaped")
			}
		})
	}
}

func TestLeaseValidationAndNoJobBehavior(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	for _, test := range []struct {
		name string
		edit func(*worker.LeasedJob)
		want error
	}{
		{name: "wrong kind", edit: func(job *worker.LeasedJob) { job.Kind = worker.JobDetect }, want: ErrUnexpectedJobKind},
		{name: "wrong token", edit: func(job *worker.LeasedJob) { job.LeaseToken = "00000000-0000-4000-8000-000000000002" }, want: ErrInvalidLease},
		{name: "wrong aggregate", edit: func(job *worker.LeasedJob) { job.AggregateType = "batch" }, want: ErrInvalidLease},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &fakeStore{snapshot: validSnapshot(clock.Now()), finalizeOK: true, editLease: test.edit}
			runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
				return ai.Result{}, nil
			}), clock)
			_, err := runtime.RunOnce(context.Background())
			if !errors.Is(err, test.want) || store.finalizeCount() != 0 {
				t.Fatalf("error=%v finalizations=%d", err, store.finalizeCount())
			}
		})
	}
	store := &fakeStore{found: false}
	runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
		return ai.Result{}, nil
	}), clock)
	result, err := runtime.RunOnce(context.Background())
	if err != nil || result.Outcome != worker.OutcomeNoJob {
		t.Fatalf("no-job result=%+v err=%v", result, err)
	}
}

func TestRunStopsGracefullyOnCancellation(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{found: false}
	runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
		return ai.Result{}, nil
	}), clock)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	clock.waitForSleep(t)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestConfigurationAndEntropyFailures(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{found: false}
	analyzer := analyzerFunc(func(context.Context, []byte) (ai.Result, error) { return ai.Result{}, nil })
	config := DefaultConfig("analysis-01", "operator-v1")
	for _, mutate := range []func(*Config){
		func(c *Config) { c.LeaseOwner = "INVALID" },
		func(c *Config) { c.RateCardVersion = "" },
		func(c *Config) { c.LeaseDuration = worker.MaxLeaseDuration + time.Second },
		func(c *Config) { c.MaxConcurrency = ai.MaxConcurrency + 1 },
		func(c *Config) { c.PollInterval = 0 },
		func(c *Config) { c.Backoff.BaseDelay = 0 },
	} {
		candidate := config
		mutate(&candidate)
		if _, err := New(store, analyzer, candidate, Dependencies{}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New() error = %v for config %+v", err, candidate)
		}
	}
	if _, err := New(nil, analyzer, config, Dependencies{}); !errors.Is(err, ErrAtomicStoreMissing) {
		t.Fatalf("nil store error = %v", err)
	}
	if _, err := New(store, nil, config, Dependencies{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil analyzer error = %v", err)
	}
	runtime, err := New(store, analyzer, config, Dependencies{
		Clock: clock, Tokens: tokenSource{err: errors.New("secret entropy detail")}, Jitter: fixedJitter(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RunOnce(context.Background()); !errors.Is(err, ErrPersistence) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("entropy error = %v", err)
	}
	if _, err := runtime.RunOnce(absentContext()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil context error = %v", err)
	}
	if err := runtime.Run(absentContext()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil run context error = %v", err)
	}
}

func absentContext() context.Context { return nil }

func TestDefaultDependenciesAndSystemClock(t *testing.T) {
	t.Parallel()
	store := &fakeStore{found: false}
	analyzer := analyzerFunc(func(context.Context, []byte) (ai.Result, error) { return ai.Result{}, nil })
	runtime, err := New(store, analyzer, DefaultConfig("analysis-01", "operator-v1"), Dependencies{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if runtime.clock.Now().IsZero() || runtime.tokens == nil || runtime.jitter == nil {
		t.Fatal("default dependencies were not installed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.clock.Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sleep() error = %v", err)
	}
}

func TestLoopReturnsSanitizedStoreFailure(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	store := &fakeStore{leaseErr: errors.New("database secret-value")}
	runtime := newTestRuntime(t, store, analyzerFunc(func(context.Context, []byte) (ai.Result, error) {
		return ai.Result{}, nil
	}), clock)
	err := runtime.loop(context.Background())
	if !errors.Is(err, ErrPersistence) || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("loop() error = %v", err)
	}
}

func assertMinimizedInput(t *testing.T, input []byte) {
	t.Helper()
	var document map[string]json.RawMessage
	if err := json.Unmarshal(input, &document); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"schema_version", "incident_id", "incident_version", "analysis_attempt_id", "generated_at",
		"prompt_version", "output_schema_version", "source_ip", "service_label", "window_start",
		"window_end", "detector_config_version", "source_health_status", "signals", "evidence_refs",
		"historical_impact", "allowed_policy",
	}
	if len(document) != len(want) {
		t.Fatalf("input fields = %v", document)
	}
	for _, key := range want {
		if _, exists := document[key]; !exists {
			t.Fatalf("missing input field %q", key)
		}
	}
	text := string(input)
	for _, forbidden := range []string{
		"exact_path", "query", "cookie", "authorization", "raw_log", "account_hash",
		"secret-value", "/admin?token=secret-value",
	} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("input contains forbidden value %q: %s", forbidden, text)
		}
	}
}

func newTestRuntime(t *testing.T, store Store, analyzer Analyzer, clock *fakeClock) *Runtime {
	t.Helper()
	config := DefaultConfig("analysis-01", "operator-v1")
	runtime, err := New(store, analyzer, config, Dependencies{
		Clock: clock, Tokens: tokenSource{value: testLeaseToken}, Jitter: fixedJitter(0),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return runtime
}

func validSnapshot(now time.Time) Snapshot {
	windowStart := now.Add(-time.Minute)
	return Snapshot{
		IncidentID: testIncidentID, IncidentVersion: 1, AnalysisID: testAnalysisID,
		GeneratedAt:        now,
		EvidenceSnapshotID: testSnapshotID, EvidenceSnapshotDigest: testDigest,
		SourceIP: "203.0.113.20", ServiceLabel: "demo-app",
		WindowStart: windowStart, WindowEnd: now, DetectorConfigVersion: "detector-v1",
		Signals: []Signal{{
			SignalID: testSignalID, RuleID: "path_scan.v1", Classification: "path_scan",
			WindowStart: windowStart, WindowEnd: now, EventCount: 8,
			DistinctSuspiciousPathCount: 8, EvidenceDigest: testDigest,
		}},
		HistoricalImpact: HistoricalImpact{
			LookbackStart: now.Add(-24 * time.Hour), LookbackEnd: now, ImpactDigest: testDigest,
		},
	}
}

func makeOrderedSignals(count int, snapshot Snapshot) []Signal {
	result := make([]Signal, count)
	for index := range result {
		result[index] = snapshot.Signals[0]
		result[index].SignalID = fmt.Sprintf(
			"019b0000-0000-7000-8000-%012x", index+1,
		)
		result[index].EvidenceDigest = fmt.Sprintf("sha256:%064x", index+1)
	}
	return result
}

func successfulResult(t *testing.T, input []byte, snapshot Snapshot, usage ai.Usage) ai.Result {
	t.Helper()
	output := validOutput(t, snapshot)
	return ai.Result{
		ResponseID: "resp_test", Output: output, Usage: usage, Attempts: 1,
		InputDigest: digestBytes(input), InputSchemaDigest: testDigest,
		PromptDigest: testDigest, OutputSchemaDigest: testDigest,
	}
}

func validOutput(t *testing.T, snapshot Snapshot) []byte {
	t.Helper()
	ids := make([]string, len(snapshot.Signals))
	for index := range snapshot.Signals {
		ids[index] = snapshot.Signals[index].SignalID
	}
	document := outputDocument{
		SchemaVersion: OutputSchemaVersion, IncidentSummary: "Deterministic scan signals were observed.",
		Classification: "path_scan", Confidence: 0.9, Uncertainty: "",
		FalsePositiveFactors: []string{"Synthetic demo traffic is possible."}, EvidenceIDs: ids,
		Policy: outputPolicy{
			SchemaVersion: "response-policy-v1", Action: "block_ip", TargetIP: snapshot.SourceIP,
			TTLSeconds: DefaultTTLSeconds, EvidenceIDs: ids, Rationale: "Temporary containment is proportionate.",
		},
		Candidate: outputCandidate{
			SchemaVersion: "nft-blacklist-v1", TargetIP: snapshot.SourceIP, Timeout: "30m",
			EvidenceIDs: ids,
			Command:     "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }",
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type analyzerFunc func(context.Context, []byte) (ai.Result, error)

func (analyzerFunc) Identity() ai.ProviderIdentity {
	identity, _ := ai.NewOpenAIResponsesIdentity("operator-v1")
	return identity
}

func (f analyzerFunc) Analyze(ctx context.Context, input []byte) (ai.Result, error) {
	return f(ctx, input)
}

type identifiedAnalyzer struct {
	identity ai.ProviderIdentity
	analyze  func(context.Context, []byte) (ai.Result, error)
}

func (analyzer identifiedAnalyzer) Identity() ai.ProviderIdentity { return analyzer.identity }
func (analyzer identifiedAnalyzer) Analyze(ctx context.Context, input []byte) (ai.Result, error) {
	if analyzer.analyze == nil {
		return ai.Result{}, &ai.Failure{Reason: ai.FailureConfiguration}
	}
	return analyzer.analyze(ctx, input)
}

type changingIdentityAnalyzer struct {
	first, later ai.ProviderIdentity
	identities   atomic.Int32
	calls        atomic.Int32
}

func (analyzer *changingIdentityAnalyzer) Identity() ai.ProviderIdentity {
	if analyzer.identities.Add(1) == 1 {
		return analyzer.first
	}
	return analyzer.later
}

func (analyzer *changingIdentityAnalyzer) Analyze(context.Context, []byte) (ai.Result, error) {
	analyzer.calls.Add(1)
	return ai.Result{}, nil
}

type tokenSource struct {
	value string
	err   error
}

func (s tokenSource) NewLeaseToken() (string, error) { return s.value, s.err }

type fixedJitter uint64

func (j fixedJitter) Uint64() (uint64, error) { return uint64(j), nil }

type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	sleepCh chan struct{}
}

func newFakeClock() *fakeClock {
	return &fakeClock{
		now: time.Now().UTC().Add(10 * time.Minute), sleepCh: make(chan struct{}, ai.MaxConcurrency),
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, _ time.Duration) error {
	select {
	case c.sleepCh <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func (c *fakeClock) waitForSleep(t *testing.T) {
	t.Helper()
	select {
	case <-c.sleepCh:
	case <-time.After(time.Second):
		t.Fatal("runtime did not enter poll sleep")
	}
}

type fakeStore struct {
	mu            sync.Mutex
	snapshot      Snapshot
	found         bool
	foundSet      bool
	loadErr       error
	prepareOK     bool
	prepareSet    bool
	leaseErr      error
	finalizeErr   error
	finalizeOK    bool
	attempt       int32
	maxAttempts   int32
	editLease     func(*worker.LeasedJob)
	leases        []worker.LeaseRequest
	preparations  []PrepareRequest
	finalizations []FinalizeRequest
	committed     int
}

func (s *fakeStore) Lease(_ context.Context, request worker.LeaseRequest) (worker.LeasedJob, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases = append(s.leases, request)
	if s.leaseErr != nil {
		return worker.LeasedJob{}, false, s.leaseErr
	}
	found := true
	if s.foundSet || !s.found && s.snapshot.IncidentID == "" {
		found = s.found
	}
	if !found {
		return worker.LeasedJob{}, false, nil
	}
	attempt, maxAttempts := s.attempt, s.maxAttempts
	if attempt == 0 {
		attempt = 1
	}
	if maxAttempts == 0 {
		maxAttempts = 3
	}
	job := worker.LeasedJob{
		Job: worker.Job{
			JobID: testJobID, Kind: worker.JobAnalyze, AggregateType: "incident",
			AggregateID: testIncidentID, AggregateVersion: 1,
			Attempt: attempt, MaxAttempts: maxAttempts,
		},
		State: "leased", LeaseToken: request.LeaseToken, LeaseOwner: request.LeaseOwner,
		LeaseGrantedAt: request.Now, LeaseExpiresAt: request.LeaseExpiresAt,
	}
	if s.editLease != nil {
		s.editLease(&job)
	}
	return job, true, nil
}

func (s *fakeStore) Prepare(_ context.Context, request PrepareRequest) (Snapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preparations = append(s.preparations, request)
	prepared := true
	if s.prepareSet {
		prepared = s.prepareOK
	}
	return s.snapshot, prepared, s.loadErr
}

func (s *fakeStore) onlyPrepare(t *testing.T) PrepareRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.preparations) != 1 {
		t.Fatalf("prepare count = %d", len(s.preparations))
	}
	return s.preparations[0]
}

func (s *fakeStore) Finalize(_ context.Context, request FinalizeRequest) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finalizations = append(s.finalizations, request)
	if s.finalizeErr != nil {
		return false, s.finalizeErr
	}
	if s.finalizeOK && request.Mutation != nil {
		s.committed++
	}
	return s.finalizeOK, nil
}

func (s *fakeStore) onlyFinalize(t *testing.T) FinalizeRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.finalizations) != 1 {
		t.Fatalf("finalization count = %d", len(s.finalizations))
	}
	return s.finalizations[0]
}

func (s *fakeStore) finalizeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.finalizations)
}

func (s *fakeStore) committedMutations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.committed
}
