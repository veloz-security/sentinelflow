package validationworker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	testLeaseToken     = "00000000-0000-4000-8000-000000000901"
	testJobID          = "019b0000-0000-7000-8000-000000000901"
	testAttemptID      = "019b0000-0000-7000-8000-000000000902"
	testAnalysisID     = "019b0000-0000-7000-8000-000000000903"
	testIncidentID     = "019b0000-0000-7000-8000-000000000904"
	testEvidenceID     = "019b0000-0000-7000-8000-000000000905"
	testSignalID       = "019b0000-0000-7000-8000-000000000906"
	testEventID        = "019b0000-0000-7000-8000-000000000907"
	testGatewayID      = "019b0000-0000-7000-8000-000000000908"
	testAuthID         = "019b0000-0000-7000-8000-000000000909"
	testPolicyID       = "019b0000-0000-7000-8000-000000000910"
	testCandidateID    = "019b0000-0000-7000-8000-000000000911"
	testValidationID   = "019b0000-0000-7000-8000-000000000912"
	testSchemaDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPromptDigest   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testBinaryDigest   = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testHealthDigest   = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	testSnapshotDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

// context.WithDeadline uses the process clock even when the worker's database
// clock is injected, so keep the frozen database instant safely in the future.
var testNow = time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)

func TestRuntimePublishesValidMutationAfterAllOrderedGates(t *testing.T) {
	t.Parallel()
	snapshot := testSnapshot(t, "8.8.8.8", true)
	store := &testStore{snapshot: snapshot, finalizeOK: true}
	checker := &testSyntaxChecker{}
	runtime := testRuntime(t, store, checker)

	result, err := runtime.RunOnce(context.Background())
	if err != nil || result.Outcome != worker.OutcomeCompleted || result.State != StateValid ||
		result.FailureCode != ValidationFailureNone {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	request := store.finalize(t)
	if request.Finish.State != worker.FinishCompleted || request.Mutation == nil ||
		request.Mutation.State != StateValid || len(request.Mutation.Gates) != 6 ||
		request.Mutation.Validation == nil || request.Mutation.Candidate == nil ||
		request.Mutation.Policy == nil || checker.callCount() != 1 {
		t.Fatalf("finalize=%+v syntax calls=%d", request, checker.callCount())
	}
	for index, gate := range request.Mutation.Gates {
		if gate.Order != uint8(index+1) || !gate.Passed || gate.ResultCode != "ok" {
			t.Fatalf("gate %d = %+v", index, gate)
		}
	}
	if request.Mutation.Validation.ValidUntil.Sub(request.Mutation.Validation.CreatedAt) !=
		validation.ValidationSnapshotLifetime {
		t.Fatal("validation lifetime was not frozen to five minutes")
	}
}

func TestRuntimeFailsClosedAtFirstRejectedGate(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name      string
		mutate    func(*Snapshot, *testSyntaxChecker)
		wantGate  validation.ValidationCheckID
		wantCalls int
		wantCode  string
	}{
		{
			name: "strict output", wantGate: validation.CheckStructuredOutput,
			wantCode: "structured_output_digest_mismatch",
			mutate: func(snapshot *Snapshot, _ *testSyntaxChecker) {
				snapshot.StructuredOutput = append(snapshot.StructuredOutput, ' ')
			},
		},
		{
			name: "consistency health", wantGate: validation.CheckPolicyEvidenceCommandConsistency,
			wantCode: string(validation.ConsistencyFailureEvidenceIncomplete),
			mutate: func(snapshot *Snapshot, _ *testSyntaxChecker) {
				snapshot.Evidence.SourceHealthStatus = "incomplete"
			},
		},
		{
			name: "protected network", wantGate: validation.CheckProtectedNetwork,
			wantCode: string(validation.ReasonBuiltInProtected),
			mutate: func(snapshot *Snapshot, _ *testSyntaxChecker) {
				*snapshot = testSnapshot(t, "10.0.0.1", true)
			},
		},
		{
			name: "fixed nft check", wantGate: validation.CheckOwnedSchemaSyntax,
			wantCode: string(nftcheck.ErrorSyntaxRejected), wantCalls: 1,
			mutate: func(_ *Snapshot, checker *testSyntaxChecker) {
				checker.err = &nftcheck.Error{Code: nftcheck.ErrorSyntaxRejected}
			},
		},
		{
			name: "history coverage", wantGate: validation.CheckHistoricalImpact,
			wantCode: string(validation.HistoryReasonCoverageIncomplete), wantCalls: 1,
			mutate: func(snapshot *Snapshot, _ *testSyntaxChecker) {
				snapshot.History.CoverageComplete = false
			},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			snapshot := testSnapshot(t, "8.8.8.8", true)
			checker := &testSyntaxChecker{}
			testCase.mutate(&snapshot, checker)
			store := &testStore{snapshot: snapshot, finalizeOK: true}
			runtime := testRuntime(t, store, checker)
			result, err := runtime.RunOnce(context.Background())
			if err != nil || result.State != StateInvalid || result.FailedGate != testCase.wantGate ||
				result.FailureCode != testCase.wantCode || checker.callCount() != testCase.wantCalls {
				t.Fatalf("result=%+v calls=%d err=%v", result, checker.callCount(), err)
			}
			mutation := store.finalize(t).Mutation
			if mutation == nil || mutation.Validation != nil ||
				mutation.Gates[len(mutation.Gates)-1].Name != testCase.wantGate ||
				mutation.Gates[len(mutation.Gates)-1].Passed {
				t.Fatalf("mutation=%+v", mutation)
			}
		})
	}
}

func TestRuntimeConvertsGatePanicToTypedRejection(t *testing.T) {
	t.Parallel()
	store := &testStore{snapshot: testSnapshot(t, "8.8.8.8", true), finalizeOK: true}
	checker := &testSyntaxChecker{panicValue: "sensitive panic content"}
	runtime := testRuntime(t, store, checker)
	result, err := runtime.RunOnce(context.Background())
	if err != nil || result.State != StateInvalid || result.FailureCode != "validation_internal_failure" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	mutation := store.finalize(t).Mutation
	encoded, _ := json.Marshal(mutation)
	if bytesContains(encoded, []byte("sensitive")) || len(mutation.Gates) != 1 || mutation.Gates[0].Passed {
		t.Fatalf("unsafe panic mutation=%s", encoded)
	}
}

func TestRuntimeFencesPublicationAndRetriesSnapshotFailure(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name    string
		store   *testStore
		want    worker.Outcome
		wantErr error
		finish  worker.FinishState
	}{
		{
			name: "atomic fence", store: &testStore{snapshot: testSnapshot(t, "8.8.8.8", true)},
			want: worker.OutcomeLeaseLost, wantErr: ErrLeaseLost, finish: worker.FinishCompleted,
		},
		{
			name: "snapshot retry", store: &testStore{
				snapshot: testSnapshot(t, "8.8.8.8", true), prepareErr: errors.New("secret db output"),
				finalizeOK: true, attempt: 1, maxAttempts: 3,
			}, want: worker.OutcomeRetryScheduled, finish: worker.FinishRetry,
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			runtime := testRuntime(t, testCase.store, &testSyntaxChecker{})
			result, err := runtime.RunOnce(context.Background())
			if result.Outcome != testCase.want || !errors.Is(err, testCase.wantErr) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			finalize := testCase.store.finalize(t)
			if finalize.Finish.State != testCase.finish ||
				(testCase.finish != worker.FinishCompleted && finalize.Mutation != nil) {
				t.Fatalf("finalize=%+v", finalize)
			}
		})
	}
}

func TestRuntimeReservesLeaseTimeForTimeoutFinalization(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		attempt     int32
		maximum     int32
		wantOutcome worker.Outcome
		wantFinish  worker.FinishState
	}{
		{
			name: "retry before maximum", attempt: 1, maximum: 2,
			wantOutcome: worker.OutcomeRetryScheduled, wantFinish: worker.FinishRetry,
		},
		{
			name: "dead at maximum", attempt: 2, maximum: 2,
			wantOutcome: worker.OutcomeDeadLettered, wantFinish: worker.FinishDead,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store := &testStore{
				snapshot: testSnapshot(t, "8.8.8.8", true), prepareBlock: true,
				finalizeOK: true, attempt: testCase.attempt, maxAttempts: testCase.maximum,
			}
			runtime := deadlineTestRuntime(t, store, &testSyntaxChecker{}, 500*time.Millisecond)
			started := time.Now()
			result, err := runtime.RunOnce(context.Background())
			if err != nil || result.Outcome != testCase.wantOutcome ||
				result.FailureCode != validationTimeoutCode {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("handler timeout was not bounded: elapsed=%s", elapsed)
			}
			request := store.finalize(t)
			if request.Finish.State != testCase.wantFinish || request.Finish.ErrorCode != validationTimeoutCode ||
				request.Mutation != nil {
				t.Fatalf("finalize=%+v", request)
			}
			leaseDeadline, handlerLimit, _, finalizeLimit := store.deadlines()
			if leaseDeadline.IsZero() || !handlerLimit.Before(leaseDeadline) ||
				!finalizeLimit.Equal(leaseDeadline) {
				t.Fatalf("lease=%s handler=%s finalize=%s", leaseDeadline, handlerLimit, finalizeLimit)
			}
		})
	}
}

func TestRuntimeFailsClosedWhenSyntaxValidatorConsumesHandlerBudget(t *testing.T) {
	checker := &testSyntaxChecker{block: true}
	store := &testStore{
		snapshot: testSnapshot(t, "8.8.8.8", true), finalizeOK: true,
		attempt: 2, maxAttempts: 2,
	}
	runtime := deadlineTestRuntime(t, store, checker, 300*time.Millisecond)
	result, err := runtime.RunOnce(context.Background())
	if err != nil || result.Outcome != worker.OutcomeDeadLettered ||
		result.FailureCode != validationTimeoutCode || checker.callCount() != 1 {
		t.Fatalf("result=%+v calls=%d err=%v", result, checker.callCount(), err)
	}
	request := store.finalize(t)
	if request.Finish.State != worker.FinishDead || request.Mutation != nil {
		t.Fatalf("finalize=%+v", request)
	}
}

func TestRuntimeDoesNotConvertCallerCancellationIntoJobFailure(t *testing.T) {
	store := &testStore{
		snapshot: testSnapshot(t, "8.8.8.8", true), prepareBlock: true,
		finalizeOK: true, attempt: 1, maxAttempts: 2,
	}
	runtime := deadlineTestRuntime(t, store, &testSyntaxChecker{}, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result, err := runtime.RunOnce(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || result.Outcome != "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.finalized) != 0 {
		t.Fatalf("caller cancellation published job failure: %+v", store.finalized)
	}
}

func TestRuntimeConvertsBlockedMutationFinalizeWithinSameLease(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		attempt     int32
		maximum     int32
		wantOutcome worker.Outcome
		wantFinish  worker.FinishState
	}{
		{
			name: "retry before maximum", attempt: 1, maximum: 2,
			wantOutcome: worker.OutcomeRetryScheduled, wantFinish: worker.FinishRetry,
		},
		{
			name: "dead at maximum", attempt: 2, maximum: 2,
			wantOutcome: worker.OutcomeDeadLettered, wantFinish: worker.FinishDead,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store := &testStore{
				snapshot: testSnapshot(t, "8.8.8.8", true), finalizeBlocks: 1,
				finalizeOK: true, attempt: testCase.attempt, maxAttempts: testCase.maximum,
			}
			runtime := deadlineTestRuntime(t, store, &testSyntaxChecker{}, 500*time.Millisecond)
			started := time.Now()
			result, err := runtime.RunOnce(context.Background())
			if err != nil || result.Outcome != testCase.wantOutcome || result.State != "" ||
				result.FailureCode != validationFinalizeTimeoutCode {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("blocked finalize was not bounded: elapsed=%s", elapsed)
			}
			request := store.finalize(t)
			if request.Finish.State != testCase.wantFinish ||
				request.Finish.ErrorCode != validationFinalizeTimeoutCode || request.Mutation != nil {
				t.Fatalf("fallback finalize=%+v", request)
			}
			leaseDeadline, _, firstFinalize, lastFinalize := store.deadlines()
			if leaseDeadline.IsZero() || !firstFinalize.Before(leaseDeadline) ||
				!lastFinalize.Equal(leaseDeadline) {
				t.Fatalf("lease=%s first=%s fallback=%s", leaseDeadline, firstFinalize, lastFinalize)
			}
		})
	}
}

func TestRuntimeConvertsUnavailableMutationFinalizeWithinSameLease(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		attempt     int32
		maximum     int32
		wantOutcome worker.Outcome
		wantFinish  worker.FinishState
	}{
		{
			name: "retry before maximum", attempt: 1, maximum: 2,
			wantOutcome: worker.OutcomeRetryScheduled, wantFinish: worker.FinishRetry,
		},
		{
			name: "dead at maximum", attempt: 2, maximum: 2,
			wantOutcome: worker.OutcomeDeadLettered, wantFinish: worker.FinishDead,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store := &testStore{
				snapshot:     testSnapshot(t, "8.8.8.8", true),
				finalizeErrs: []error{ErrRetryablePersistence}, finalizeOK: true,
				attempt: testCase.attempt, maxAttempts: testCase.maximum,
			}
			runtime := deadlineTestRuntime(t, store, &testSyntaxChecker{}, 500*time.Millisecond)
			result, err := runtime.RunOnce(context.Background())
			if err != nil || result.Outcome != testCase.wantOutcome || result.State != "" ||
				result.FailureCode != validationFinalizeUnavailableCode {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			request := store.finalize(t)
			if request.Finish.State != testCase.wantFinish ||
				request.Finish.ErrorCode != validationFinalizeUnavailableCode || request.Mutation != nil {
				t.Fatalf("fallback finalize=%+v", request)
			}
		})
	}
}

func TestRuntimeTreatsAmbiguousFinalizeFallbackFailureAsLeaseLost(t *testing.T) {
	store := &testStore{
		snapshot:     testSnapshot(t, "8.8.8.8", true),
		finalizeErrs: []error{ErrRetryablePersistence, ErrRetryablePersistence}, finalizeOK: true,
		attempt: 1, maxAttempts: 2,
	}
	runtime := deadlineTestRuntime(t, store, &testSyntaxChecker{}, 500*time.Millisecond)
	result, err := runtime.RunOnce(context.Background())
	if !errors.Is(err, ErrLeaseLost) || result.Outcome != worker.OutcomeLeaseLost ||
		result.FailureCode != validationFinalizeUnavailableCode || store.finalizationCount() != 0 {
		t.Fatalf("result=%+v finalizations=%d err=%v", result, store.finalizationCount(), err)
	}
}

func TestRuntimeDoesNotFallbackGenericFinalizeError(t *testing.T) {
	store := &testStore{
		snapshot:     testSnapshot(t, "8.8.8.8", true),
		finalizeErrs: []error{ErrPersistence}, finalizeOK: true,
		attempt: 1, maxAttempts: 2,
	}
	runtime := deadlineTestRuntime(t, store, &testSyntaxChecker{}, 500*time.Millisecond)
	result, err := runtime.RunOnce(context.Background())
	if !errors.Is(err, ErrPersistence) || result.Outcome != "" ||
		result.State != StateValid || result.FailureCode != ValidationFailureNone ||
		store.finalizationCount() != 0 {
		t.Fatalf("result=%+v finalizations=%d err=%v", result, store.finalizationCount(), err)
	}
}

func TestRuntimeRequiresEnvironmentMatchedVerifiedDemoStore(t *testing.T) {
	t.Parallel()
	config := DefaultConfig("validation-worker", testBinaryDigest, "nftables v1.0.9", testSchemaDigest, testPromptDigest)
	config.LeaseDuration = 30 * time.Second
	config.Environment = validation.EnvironmentDemo
	dependencies := testDependencies(t, &testSyntaxChecker{})
	if runtime, err := New(&testStore{}, config, dependencies); runtime != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unverified demo store runtime=%v err=%v", runtime, err)
	}

	fixture := fixtureDemoHistoryBinding(t)
	fixtureStore := &verifiedDemoTestStore{testStore: &testStore{}, binding: fixture}
	if runtime, err := New(fixtureStore, config, dependencies); runtime != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("public test fixture crossed into demo runtime: runtime=%v err=%v", runtime, err)
	}

	config.Environment = validation.EnvironmentTest
	if runtime, err := New(fixtureStore, config, dependencies); err != nil || runtime == nil || runtime.demoHistory == nil {
		t.Fatalf("explicit test fixture runtime=%v err=%v", runtime, err)
	}
}

func TestRetainedHistoryCannotConflateGeneratedAndHistoricalClock(t *testing.T) {
	t.Parallel()
	snapshot := testSnapshot(t, "8.8.8.8", true)
	snapshot.History.Cutoff = snapshot.GeneratedAt.Add(-time.Hour)
	snapshot.History.WindowStart = snapshot.History.Cutoff.Add(-validation.HistoricalImpactLookback)
	if !validPreparedSnapshot(snapshot) {
		t.Fatal("mode-neutral snapshot validation rejected a structurally valid history window")
	}
	checked := evaluateHistory(snapshot, validation.EnvironmentProduction, "8.8.8.8", nil)
	if checked.Allowed() {
		t.Fatal("retained mode accepted a cutoff different from the real DB generated_at")
	}
}

func TestVerifiedDemoHistoryFailsClosedForUnsignedTargetRows(t *testing.T) {
	t.Parallel()
	binding := fixtureDemoHistoryBinding(t)
	claims, ok := binding.Claims()
	if !ok {
		t.Fatal("verified demo claims unavailable")
	}
	snapshot := testSnapshot(t, "203.0.113.24", true)
	snapshot.History.Cutoff = claims.ClockAt
	snapshot.History.WindowStart = claims.CoverageStart
	snapshot.History.GatewayRecords = nil
	snapshot.History.AuthRecords = nil
	checked := evaluateHistory(snapshot, validation.EnvironmentTest, "203.0.113.24", &binding)
	if checked.Allowed() || checked.Value().ReasonCode != validation.HistoryReasonDemoBindingMismatch {
		t.Fatalf("unexpected demo history result: %+v", checked.Value())
	}
}

func testRuntime(t *testing.T, store *testStore, checker *testSyntaxChecker) *Runtime {
	t.Helper()
	dependencies := testDependencies(t, checker)
	config := DefaultConfig("validation-worker", testBinaryDigest, "nftables v1.0.9", testSchemaDigest, testPromptDigest)
	config.LeaseDuration = 30 * time.Second
	runtime, err := New(store, config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func deadlineTestRuntime(
	t *testing.T,
	store *testStore,
	checker *testSyntaxChecker,
	leaseDuration time.Duration,
) *Runtime {
	t.Helper()
	dependencies := testDependencies(t, checker)
	dependencies.Clock = systemClock{}
	config := DefaultConfig("validation-worker", testBinaryDigest, "nftables v1.0.9", testSchemaDigest, testPromptDigest)
	config.LeaseDuration = leaseDuration
	runtime, err := New(store, config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func testDependencies(t *testing.T, checker *testSyntaxChecker) Dependencies {
	t.Helper()
	contract, err := validation.LoadProtectedContractFile(filepath.Join("..", "..", "contracts", "enforcement", "protected_ipv4_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	gate, err := validation.NewProtectedGate(contract, validation.ProtectedConfig{
		Environment: validation.EnvironmentProduction,
		Demo: validation.DemoExceptionConfig{Profile: validation.DemoExceptionDisabled,
			ClientCIDR: "203.0.113.0/24", AttackSourceIPv4: "203.0.113.20"},
	})
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(filepath.Join("..", "..", "contracts", "enforcement", "nft_base_chain_v1.nft"))
	if err != nil {
		t.Fatal(err)
	}
	live, err := os.ReadFile(filepath.Join("..", "..", "contracts", "enforcement", "nft_base_chain_v1.live.json"))
	if err != nil {
		t.Fatal(err)
	}
	return Dependencies{
		Clock: &testClock{now: testNow}, Tokens: testTokens{}, Jitter: testJitter{},
		ProtectedGate: gate, SyntaxChecker: checker, BaseContract: base, LiveSchema: live,
	}
}

func fixtureDemoHistoryBinding(t *testing.T) validation.VerifiedDemoHistoryBinding {
	t.Helper()
	publicKey, err := base64.RawURLEncoding.DecodeString(validation.PinnedDemoHistoryFixturePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	clockAt := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	verifier, err := validation.NewStrictDemoHistoryManifestVerifier(validation.DemoHistoryManifestVerifierConfig{
		Environment: validation.EnvironmentTest, ExpectedPublicKey: publicKey,
		ExpectedRunScope:                 validation.DemoHistoryFixtureKeyScope,
		ExpectedImportID:                 "019b0000-0000-7000-8000-000000000501",
		ExpectedClockAt:                  clockAt,
		ExpectedImpactSourceHealthDigest: validation.PinnedDemoHistoryImpactSourceHealthDigest,
		AllowPublicTestFixture:           true, TestSecurityNow: clockAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := os.ReadFile(filepath.Join("..", "..", "contracts", "fixtures", "demo_history_manifest_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := verifier.VerifyDemoHistory(context.Background(), validation.DemoHistoryVerificationInput{
		SignedManifestEnvelope: envelope,
		ImportedRowsDigest:     validation.PinnedDemoHistoryImportedRowsDigest,
		ImportedRecordCount:    validation.PinnedDemoHistoryDatasetRecordCount,
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func testSnapshot(t *testing.T, target string, coverage bool) Snapshot {
	t.Helper()
	checkedEvidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:    testEvidenceID, IncidentID: testIncidentID, IncidentVersion: 1,
		SourceIPv4: target, ServiceLabel: "gateway",
		WindowStart: testNow.Add(-time.Minute), WindowEnd: testNow, CreatedAt: testNow,
		SourceHealthDigest: testHealthDigest,
		EventIDs:           []string{testEventID}, SignalIDs: []string{testSignalID},
	})
	if err != nil {
		t.Fatal(err)
	}
	command := "add element inet sentinelflow blacklist_ipv4 { " + target + " timeout 30m }"
	policyValue := map[string]any{
		"schema_version": policy.PolicySchemaVersion, "action": policy.ActionBlockIP,
		"target_ip": target, "ttl_seconds": 1800, "evidence_ids": []string{testSignalID},
		"rationale": "Complete deterministic evidence supports a temporary block.",
	}
	candidateValue := map[string]any{
		"schema_version": policy.CandidateSchemaVersion, "target_ip": target,
		"timeout": "30m", "evidence_ids": []string{testSignalID}, "command": command,
	}
	policyJSON, _ := json.Marshal(policyValue)
	candidateJSON, _ := json.Marshal(candidateValue)
	structured, _ := json.Marshal(map[string]any{
		"schema_version": "sentinelflow_analysis_v1", "incident_summary": "Synthetic test incident.",
		"classification": "path_scan", "confidence": 0.9, "uncertainty": "",
		"false_positive_factors": []string{}, "evidence_ids": []string{testSignalID},
		"policy": policyValue, "nftables_command_candidate": candidateValue,
	})
	return Snapshot{
		ValidationAttemptID: testAttemptID, PolicyID: testPolicyID,
		ValidationID: testValidationID, CommandCandidateID: testCandidateID,
		AnalysisID: testAnalysisID, IncidentID: testIncidentID, IncidentVersion: 1,
		GeneratedAt: testNow, EvidenceSnapshotID: testEvidenceID,
		EvidenceSnapshotDigest: checkedEvidence.Digest(), EvidenceCanonicalBytes: checkedEvidence.CanonicalBytes(),
		AnalysisInputDigest: testHealthDigest,
		OutputSchemaDigest:  testSchemaDigest, PromptDigest: testPromptDigest,
		AnalysisOutputDigest: policy.Digest(structured), GeneratedCommandDigest: policy.Digest([]byte(command)),
		StructuredOutput: structured, PolicyOutput: policyJSON, CommandCandidateOutput: candidateJSON,
		Evidence: EvidenceBinding{
			SourceIPv4: target, ServiceLabel: "gateway", SourceHealthDigest: testHealthDigest,
			SourceHealthStatus: validation.SourceHealthComplete, SignalIDs: []string{testSignalID},
			EventIDs: []string{testEventID}, Signals: []SignalBinding{{
				SignalID: testSignalID, SignalDigest: testHealthDigest, SourceIPv4: target,
				EventIDs: []string{testEventID}, ThresholdReproduced: true,
				SourceHealthStatus: validation.SourceHealthComplete,
			}},
		},
		History: HistorySnapshot{
			Cutoff: testNow, WindowStart: testNow.Add(-24 * time.Hour), CoverageComplete: coverage,
			GatewayRecords: []validation.HistoricalGatewayRecord{{
				EventID: testGatewayID, OccurredAt: testNow.Add(-time.Hour), SourceIPv4: target,
				StatusCode: 404, TimestampTrust: detection.TimestampTrusted,
			}},
			AuthRecords: []validation.HistoricalAuthRecord{{
				EventID: testAuthID, OccurredAt: testNow.Add(-30 * time.Minute), SourceIPv4: target,
				Outcome: events.AuthOutcomeFailed, TimestampTrust: detection.TimestampTrusted,
				Binding: detection.BindingVerified,
			}},
		},
	}
}

type testStore struct {
	mu                    sync.Mutex
	snapshot              Snapshot
	prepareErr            error
	prepareBlock          bool
	finalizeBlocks        int
	finalizeErrs          []error
	finalizeOK            bool
	attempt               int32
	maxAttempts           int32
	finalized             []FinalizeRequest
	leaseDeadline         time.Time
	prepareDeadline       time.Time
	firstFinalizeDeadline time.Time
	finalizeDeadline      time.Time
}

type verifiedDemoTestStore struct {
	*testStore
	binding validation.VerifiedDemoHistoryBinding
}

func (s *verifiedDemoTestStore) VerifiedDemoHistoryBinding() (validation.VerifiedDemoHistoryBinding, bool) {
	return s.binding, true
}

func (s *testStore) Lease(_ context.Context, request worker.LeaseRequest) (worker.LeasedJob, bool, error) {
	s.mu.Lock()
	s.leaseDeadline = request.LeaseExpiresAt
	s.mu.Unlock()
	attempt, maximum := s.attempt, s.maxAttempts
	if attempt == 0 {
		attempt = 1
	}
	if maximum == 0 {
		maximum = 3
	}
	return worker.LeasedJob{Job: worker.Job{
		JobID: testJobID, Kind: worker.JobValidate, AggregateType: ValidationAggregateType,
		AggregateID: testAnalysisID, AggregateVersion: 1, Attempt: attempt, MaxAttempts: maximum,
	}, State: "leased", AvailableAt: request.Now, LeaseToken: request.LeaseToken,
		LeaseOwner: request.LeaseOwner, LeaseGrantedAt: request.Now,
		LeaseExpiresAt: request.LeaseExpiresAt}, true, nil
}

func (s *testStore) Prepare(ctx context.Context, _ PrepareRequest) (Snapshot, bool, error) {
	if deadline, ok := ctx.Deadline(); ok {
		s.mu.Lock()
		s.prepareDeadline = deadline
		s.mu.Unlock()
	}
	if s.prepareBlock {
		<-ctx.Done()
		return Snapshot{}, false, ctx.Err()
	}
	if s.prepareErr != nil {
		return Snapshot{}, false, s.prepareErr
	}
	return s.snapshot, true, nil
}

func (s *testStore) Finalize(ctx context.Context, request FinalizeRequest) (bool, error) {
	block := false
	if deadline, ok := ctx.Deadline(); ok {
		s.mu.Lock()
		if s.firstFinalizeDeadline.IsZero() {
			s.firstFinalizeDeadline = deadline
		}
		s.finalizeDeadline = deadline
		if s.finalizeBlocks > 0 {
			s.finalizeBlocks--
			block = true
		}
		s.mu.Unlock()
	}
	if block {
		<-ctx.Done()
		return false, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.finalizeErrs) > 0 {
		err := s.finalizeErrs[0]
		s.finalizeErrs = s.finalizeErrs[1:]
		return false, err
	}
	s.finalized = append(s.finalized, request)
	return s.finalizeOK, nil
}

func (s *testStore) deadlines() (time.Time, time.Time, time.Time, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leaseDeadline, s.prepareDeadline, s.firstFinalizeDeadline, s.finalizeDeadline
}

func (s *testStore) finalize(t *testing.T) FinalizeRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.finalized) != 1 {
		t.Fatalf("finalizations=%d", len(s.finalized))
	}
	return s.finalized[0]
}

func (s *testStore) finalizationCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.finalized)
}

type testSyntaxChecker struct {
	mu         sync.Mutex
	calls      int
	err        error
	block      bool
	panicValue any
}

func (c *testSyntaxChecker) Check(ctx context.Context, _ nftcheck.Input) (nftcheck.Evidence, error) {
	c.mu.Lock()
	c.calls++
	err, block, panicValue := c.err, c.block, c.panicValue
	c.mu.Unlock()
	if panicValue != nil {
		panic(panicValue)
	}
	if block {
		<-ctx.Done()
		return nftcheck.Evidence{}, ctx.Err()
	}
	return nftcheck.Evidence{NFTVersion: "nftables v1.0.9"}, err
}

func (c *testSyntaxChecker) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time                             { return c.now }
func (c *testClock) Sleep(context.Context, time.Duration) error { return nil }

type testTokens struct{}

func (testTokens) NewLeaseToken() (string, error) { return testLeaseToken, nil }

type testJitter struct{}

func (testJitter) Uint64() (uint64, error) { return 0, nil }

func bytesContains(value, needle []byte) bool {
	return len(needle) > 0 && len(value) >= len(needle) && stringContains(string(value), string(needle))
}

func stringContains(value, needle string) bool {
	for index := 0; index+len(needle) <= len(value); index++ {
		if value[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}
