package analysisstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	testJob      = "019b0000-0000-7000-8000-000000008001"
	testJobTwo   = "019b0000-0000-7000-8000-000000008002"
	testIncident = "019b0000-0000-7000-8000-000000008101"
	testAnalysis = "019b0000-0000-4000-8000-000000008201"
	testSnapshot = "019b0000-0000-7000-8000-000000008301"
	testSignal   = "019b0000-0000-7000-8000-000000008401"
	testToken    = "019b0000-0000-4000-8000-000000008501"
	testDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var testNow = time.Date(2026, 7, 18, 6, 0, 0, 0, time.UTC)

func TestNewPostgreSQLStoreRejectsNil(t *testing.T) {
	t.Parallel()
	if _, err := NewPostgreSQLStore(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v", err)
	}
}

func TestLeaseUsesAnalysisOnlyFunctionAndValidatesRow(t *testing.T) {
	t.Parallel()
	db := &queryStub{row: rowFunc(func(dest ...any) error {
		*dest[0].(*string) = testJob
		*dest[1].(*string) = "analyze"
		*dest[2].(*string) = "incident"
		*dest[3].(*string) = testIncident
		*dest[4].(*int32) = 1
		*dest[5].(*string) = "leased"
		*dest[6].(*time.Time) = testNow
		*dest[7].(*string) = testToken
		*dest[8].(*string) = "analysis-worker"
		*dest[9].(*time.Time) = testNow
		*dest[10].(*time.Time) = testNow.Add(30 * time.Second)
		*dest[11].(*int32) = 1
		*dest[12].(*int32) = 2
		return nil
	})}
	store, _ := NewPostgreSQLStore(db)
	job, found, err := store.Lease(context.Background(), leaseRequest())
	if err != nil || !found || job.Kind != worker.JobAnalyze || job.JobID != testJob {
		t.Fatalf("Lease() job=%+v found=%v err=%v", job, found, err)
	}
	query, args, calls := db.snapshot()
	if calls != 1 || !strings.Contains(query, "lease_analysis_outbox_job") ||
		strings.Contains(query, "FROM sentinelflow.outbox_jobs") || len(args) != 4 {
		t.Fatalf("unsafe query=%q args=%#v calls=%d", query, args, calls)
	}
}

func TestLeaseFailureBoundaries(t *testing.T) {
	t.Parallel()
	for name, testCase := range map[string]struct {
		row       pgx.Row
		wantErr   error
		wantFound bool
	}{
		"empty": {row: rowFunc(func(...any) error { return pgx.ErrNoRows })},
		"database": {
			row:     rowFunc(func(...any) error { return errors.New("secret database detail") }),
			wantErr: ErrPersistence,
		},
		"invalid row": {
			row: rowFunc(func(dest ...any) error {
				for index := range dest {
					setLeaseDestination(dest, index)
				}
				*dest[1].(*string) = "detect"
				return nil
			}), wantErr: ErrInvalidRow,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := NewPostgreSQLStore(&queryStub{row: testCase.row})
			_, found, err := store.Lease(context.Background(), leaseRequest())
			if !errors.Is(err, testCase.wantErr) || found != testCase.wantFound || strings.Contains(errorText(err), "secret") {
				t.Fatalf("found=%v err=%v", found, err)
			}
		})
	}
	db := &queryStub{row: rowFunc(func(...any) error { t.Fatal("query called"); return nil })}
	store, _ := NewPostgreSQLStore(db)
	bad := leaseRequest()
	bad.LeaseOwner = "INVALID OWNER"
	if _, _, err := store.Lease(context.Background(), bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid request error = %v", err)
	}
	//lint:ignore SA1012 This deliberately verifies the defensive nil boundary.
	if _, _, err := store.Lease(nil, leaseRequest()); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, _, calls := db.snapshot(); calls != 0 {
		t.Fatalf("invalid request made %d calls", calls)
	}
}

func TestPrepareDecodesStrictSnapshotAndReturnsDefensiveData(t *testing.T) {
	t.Parallel()
	document := snapshotJSON(t)
	db := &queryStub{row: rowFunc(func(dest ...any) error {
		*dest[0].(*string) = "prepared"
		*dest[1].(*[]byte) = append([]byte(nil), document...)
		return nil
	})}
	store, _ := NewPostgreSQLStore(db)
	snapshot, prepared, err := store.Prepare(context.Background(), prepareRequest())
	if err != nil || !prepared || snapshot.AnalysisID != testAnalysis ||
		len(snapshot.Signals) != 1 || snapshot.Signals[0].SignalID != testSignal {
		t.Fatalf("Prepare() snapshot=%+v prepared=%v err=%v", snapshot, prepared, err)
	}
	snapshot.Signals[0].SignalID = "mutated"
	second, prepared, err := store.Prepare(context.Background(), prepareRequest())
	if err != nil || !prepared || second.Signals[0].SignalID != testSignal {
		t.Fatalf("second Prepare() = %+v prepared=%v err=%v", second, prepared, err)
	}
	query, _, calls := db.snapshot()
	if calls != 2 || !strings.Contains(query, "prepare_analysis_attempt") {
		t.Fatalf("prepare query=%q calls=%d", query, calls)
	}
}

func TestPrepareHandledAndFailureRows(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"interrupted", "no_call", "terminal"} {
		t.Run(status, func(t *testing.T) {
			store, _ := NewPostgreSQLStore(&queryStub{row: rowFunc(func(dest ...any) error {
				*dest[0].(*string) = status
				*dest[1].(*[]byte) = nil
				return nil
			})})
			_, prepared, err := store.Prepare(context.Background(), prepareRequest())
			if err != nil || prepared {
				t.Fatalf("prepared=%v err=%v", prepared, err)
			}
		})
	}
	for name, testCase := range map[string]struct {
		row  pgx.Row
		want error
	}{
		"empty": {row: rowFunc(func(...any) error { return pgx.ErrNoRows })},
		"database": {
			row:  rowFunc(func(...any) error { return errors.New("secret persisted output") }),
			want: ErrPersistence,
		},
		"unknown status": {
			row: rowFunc(func(dest ...any) error {
				*dest[0].(*string) = "unknown"
				*dest[1].(*[]byte) = nil
				return nil
			}), want: ErrInvalidRow,
		},
		"bad json": {
			row: rowFunc(func(dest ...any) error {
				*dest[0].(*string) = "prepared"
				*dest[1].(*[]byte) = []byte(`{"unknown":true}`)
				return nil
			}), want: ErrInvalidRow,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := NewPostgreSQLStore(&queryStub{row: testCase.row})
			_, prepared, err := store.Prepare(context.Background(), prepareRequest())
			if prepared || !errors.Is(err, testCase.want) || strings.Contains(errorText(err), "secret") {
				t.Fatalf("prepared=%v err=%v", prepared, err)
			}
		})
	}
	store, _ := NewPostgreSQLStore(&queryStub{row: rowFunc(func(...any) error {
		t.Fatal("invalid prepare queried database")
		return nil
	})})
	request := prepareRequest()
	request.Job.Kind = worker.JobDetect
	if _, _, err := store.Prepare(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v", err)
	}
}

func TestFinalizeEncodesStrictSuccessAndUsesAtomicFunction(t *testing.T) {
	t.Parallel()
	db := &queryStub{row: rowFunc(func(dest ...any) error {
		*dest[0].(*string) = testJob
		*dest[1].(*string) = "completed"
		return nil
	})}
	store, _ := NewPostgreSQLStore(db)
	request := successFinalize()
	finished, err := store.Finalize(context.Background(), request)
	if err != nil || !finished {
		t.Fatalf("Finalize() finished=%v err=%v", finished, err)
	}
	query, args, calls := db.snapshot()
	if calls != 1 || !strings.Contains(query, "finalize_analysis_attempt") ||
		strings.Contains(query, "UPDATE sentinelflow") || len(args) != 8 {
		t.Fatalf("query=%q args=%#v calls=%d", query, args, calls)
	}
	var payload map[string]any
	if err := json.Unmarshal(args[7].([]byte), &payload); err != nil {
		t.Fatal(err)
	}
	success := payload["success"].(map[string]any)
	usage := success["usage"].(map[string]any)
	_, leaked := usage["InputTokens"]
	if success["analysis_hex"] != "7b7d" || usage["input_tokens"] != float64(12) ||
		success["provider_kind"] != string(ai.ProviderOpenAIResponses) ||
		success["adapter_id"] != ai.OpenAIResponsesAdapterID || leaked {
		t.Fatalf("unexpected wire payload %#v", payload)
	}
	request.Mutation.Success.EvidenceIDs[0] = "mutated"
	if success["evidence_ids"].([]any)[0] != testSignal {
		t.Fatal("wire payload aliased caller evidence")
	}
}

func TestFinalizeEncodesStubWithoutOpenAIOrBillableFields(t *testing.T) {
	t.Parallel()
	request := successFinalize()
	success := request.Mutation.Success
	success.ProviderKind = string(ai.ProviderDeterministicStub)
	success.AdapterID = ai.DeterministicStubAdapterID
	success.Model, success.ReasoningEffort, success.RateCardVersion = "", "", ""
	success.ResponseID = "stub_" + strings.Repeat("a", 64)
	success.Usage = ai.Usage{}
	db := &queryStub{row: rowFunc(func(dest ...any) error {
		*dest[0].(*string) = testJob
		*dest[1].(*string) = "completed"
		return nil
	})}
	store, _ := NewPostgreSQLStore(db)
	finished, err := store.Finalize(context.Background(), request)
	if err != nil || !finished {
		t.Fatalf("stub Finalize() finished=%v err=%v", finished, err)
	}
	_, args, _ := db.snapshot()
	payload := string(args[7].([]byte))
	if !strings.Contains(payload, `"provider_kind":"deterministic_stub"`) ||
		!strings.Contains(payload, `"model":""`) ||
		strings.Contains(payload, ai.Model) || strings.Contains(payload, "operator-v1") ||
		strings.Contains(payload, `"trusted":true`) {
		t.Fatalf("stub wire payload=%s", payload)
	}
}

func TestFinalizeFailureAndErrorBoundaries(t *testing.T) {
	t.Parallel()
	failure := failureFinalize()
	db := &queryStub{row: rowFunc(func(dest ...any) error {
		*dest[0].(*string) = testJob
		*dest[1].(*string) = "completed"
		return nil
	})}
	store, _ := NewPostgreSQLStore(db)
	if finished, err := store.Finalize(context.Background(), failure); err != nil || !finished {
		t.Fatalf("failure finished=%v err=%v", finished, err)
	}
	_, args, _ := db.snapshot()
	if !strings.Contains(string(args[7].([]byte)), `"reason":"timeout"`) {
		t.Fatalf("failure payload=%s", args[7])
	}

	for name, testCase := range map[string]struct {
		row  pgx.Row
		want error
	}{
		"lease lost": {row: rowFunc(func(...any) error { return pgx.ErrNoRows })},
		"database": {
			row:  rowFunc(func(...any) error { return errors.New("secret policy output") }),
			want: ErrPersistence,
		},
		"wrong row": {
			row: rowFunc(func(dest ...any) error {
				*dest[0].(*string) = testJobTwo
				*dest[1].(*string) = "completed"
				return nil
			}), want: ErrInvalidRow,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := NewPostgreSQLStore(&queryStub{row: testCase.row})
			finished, err := store.Finalize(context.Background(), failureFinalize())
			if finished || !errors.Is(err, testCase.want) || strings.Contains(errorText(err), "secret") {
				t.Fatalf("finished=%v err=%v", finished, err)
			}
		})
	}
}

func TestFinalizeRejectsInvalidRequestsWithoutQuery(t *testing.T) {
	t.Parallel()
	db := &queryStub{row: rowFunc(func(...any) error { t.Fatal("query called"); return nil })}
	store, _ := NewPostgreSQLStore(db)
	cases := []analysisworker.FinalizeRequest{successFinalize(), successFinalize(), failureFinalize()}
	cases[0].Finish.LeaseToken = testJob
	cases[1].Mutation.Success.Model = "other-model"
	cases[2].Mutation.Success = cases[1].Mutation.Success
	for _, request := range cases {
		if _, err := store.Finalize(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("error = %v", err)
		}
	}
	//lint:ignore SA1012 This deliberately verifies the defensive nil boundary.
	if _, err := store.Finalize(nil, failureFinalize()); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, _, calls := db.snapshot(); calls != 0 {
		t.Fatalf("invalid finalize made %d calls", calls)
	}
}

func TestMutationValidationRejectsAmbiguousArtifactsAndFailureMetadata(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*analysisworker.FinalizeRequest){
		"duplicate output key": func(request *analysisworker.FinalizeRequest) {
			request.Mutation.Success.AnalysisJSON = []byte(`{"a":1,"a":2}`)
			request.Mutation.Success.OutputDigest = sha256Digest(request.Mutation.Success.AnalysisJSON)
		},
		"output digest mismatch": func(request *analysisworker.FinalizeRequest) {
			request.Mutation.Success.OutputDigest = testDigest
		},
		"candidate evidence mismatch": func(request *analysisworker.FinalizeRequest) {
			request.Mutation.Success.EvidenceIDs = []string{testJobTwo}
		},
		"response whitespace": func(request *analysisworker.FinalizeRequest) {
			request.Mutation.Success.ResponseID = " resp_123"
		},
		"wrong audit action": func(request *analysisworker.FinalizeRequest) {
			request.Mutation.AuditAction = "analysis_failed"
		},
		"unknown provider": func(request *analysisworker.FinalizeRequest) {
			request.Mutation.Success.ProviderKind = "openai"
		},
		"OpenAI missing rate card": func(request *analysisworker.FinalizeRequest) {
			request.Mutation.Success.RateCardVersion = ""
		},
		"stub model spoof": func(request *analysisworker.FinalizeRequest) {
			request.Mutation.Success.ProviderKind = string(ai.ProviderDeterministicStub)
			request.Mutation.Success.AdapterID = ai.DeterministicStubAdapterID
		},
		"stub paid rate card spoof": func(request *analysisworker.FinalizeRequest) {
			request.Mutation.Success.ProviderKind = string(ai.ProviderDeterministicStub)
			request.Mutation.Success.AdapterID = ai.DeterministicStubAdapterID
			request.Mutation.Success.Model = ""
			request.Mutation.Success.ReasoningEffort = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := successFinalize()
			mutate(&request)
			if validMutation(request.Mutation) {
				t.Fatal("unsafe success mutation accepted")
			}
		})
	}
	failure := failureFinalize()
	failure.Mutation.Failure.RetryEligible = false
	if validMutation(failure.Mutation) {
		t.Fatal("retryable failure with false retry metadata accepted")
	}
}

func TestDecodeSnapshotRejectsUnsafeVariants(t *testing.T) {
	t.Parallel()
	valid := snapshotDocumentValue()
	variants := []func(*snapshotDocument){
		func(value *snapshotDocument) { value.SourceIP = "2001:db8::1" },
		func(value *snapshotDocument) { value.Signals[0].SignalID = "" },
		func(value *snapshotDocument) { value.Signals[0].RuleID = "unknown.rule" },
		func(value *snapshotDocument) { value.Signals[0].EventCount = 0 },
		func(value *snapshotDocument) { value.HistoricalImpact.LookbackStart = testNow.Add(-23 * time.Hour) },
	}
	for index, mutate := range variants {
		value := valid
		value.Signals = append([]signalDocument(nil), valid.Signals...)
		mutate(&value)
		document, _ := json.Marshal(value)
		if _, err := decodeSnapshot(document); err == nil {
			t.Fatalf("variant %d accepted", index)
		}
	}
	if _, err := decodeSnapshot([]byte{0xff, 0xfe}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestDecodeSnapshotAcceptsFiftySignalsAndRejectsFiftyOne(t *testing.T) {
	t.Parallel()
	value := snapshotDocumentValue()
	value.Signals = make([]signalDocument, analysisworker.MaxSignals)
	for index := range value.Signals {
		value.Signals[index] = snapshotDocumentValue().Signals[0]
		value.Signals[index].SignalID = fmt.Sprintf(
			"019b0000-0000-7000-8000-%012x", index+1,
		)
		value.Signals[index].EvidenceDigest = fmt.Sprintf("sha256:%064x", index+1)
	}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSnapshot(document)
	if err != nil || len(decoded.Signals) != analysisworker.MaxSignals {
		t.Fatalf("fifty signals decoded=%d err=%v", len(decoded.Signals), err)
	}

	extra := value.Signals[len(value.Signals)-1]
	extra.SignalID = "019b0000-0000-7000-8000-000000000051"
	extra.EvidenceDigest = fmt.Sprintf("sha256:%064x", 51)
	value.Signals = append(value.Signals, extra)
	document, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeSnapshot(document); err == nil {
		t.Fatal("fifty-one signal persistence row was accepted")
	}
}

func leaseRequest() worker.LeaseRequest {
	return worker.LeaseRequest{
		Now: testNow, LeaseToken: testToken, LeaseOwner: "analysis-worker",
		LeaseExpiresAt: testNow.Add(30 * time.Second),
	}
}

func prepareRequest() analysisworker.PrepareRequest {
	return analysisworker.PrepareRequest{Job: worker.Job{
		JobID: testJob, Kind: worker.JobAnalyze, AggregateType: "incident",
		AggregateID: testIncident, AggregateVersion: 1, Attempt: 1, MaxAttempts: 2,
	}, LeaseToken: testToken}
}

func snapshotDocumentValue() snapshotDocument {
	value := snapshotDocument{
		IncidentID: testIncident, IncidentVersion: 1, AnalysisID: testAnalysis,
		GeneratedAt: testNow, EvidenceSnapshotID: testSnapshot,
		EvidenceSnapshotDigest: testDigest, SourceIP: "198.51.100.42",
		ServiceLabel: "demo", WindowStart: testNow.Add(-time.Minute), WindowEnd: testNow,
		DetectorConfigVersion: "detector-config-v1",
		Signals: []signalDocument{{
			SignalID: testSignal, RuleID: "path_scan.v1", Classification: "path_scan",
			WindowStart: testNow.Add(-time.Minute), WindowEnd: testNow,
			EventCount: 8, DistinctSuspiciousPathCount: 8, EvidenceDigest: testDigest,
		}},
	}
	value.HistoricalImpact.LookbackStart = testNow.Add(-24 * time.Hour)
	value.HistoricalImpact.LookbackEnd = testNow
	value.HistoricalImpact.ImpactDigest = testDigest
	return value
}

func snapshotJSON(t *testing.T) []byte {
	t.Helper()
	document, err := json.Marshal(snapshotDocumentValue())
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func successFinalize() analysisworker.FinalizeRequest {
	analysis := []byte(`{}`)
	policy := []byte(`{}`)
	command := "add element inet sentinelflow blacklist_ipv4 { 198.51.100.42 timeout 30m }"
	candidate := []byte(`{"schema_version":"nft-blacklist-v1","target_ip":"198.51.100.42","timeout":"30m","evidence_ids":["` + testSignal + `"],"command":"` + command + `"}`)
	return analysisworker.FinalizeRequest{
		Finish: worker.FinishRequest{
			State: worker.FinishCompleted, Now: testNow, JobID: testJob, LeaseToken: testToken,
		},
		Mutation: &analysisworker.Mutation{
			IncidentID: testIncident, IncidentVersion: 1, AnalysisID: testAnalysis,
			EvidenceSnapshotID: testSnapshot, EvidenceSnapshotDigest: testDigest,
			State: analysisworker.StateReviewReady, AuditAction: "analysis_succeeded",
			ValidationRequested: true,
			Success: &analysisworker.Success{
				ProviderKind: string(ai.ProviderOpenAIResponses),
				AdapterID:    ai.OpenAIResponsesAdapterID,
				Model:        ai.Model, ReasoningEffort: ai.ReasoningEffort,
				RateCardVersion: "operator-v1", ResponseID: "resp_123", Attempts: 1,
				InputBytes: 256, InputDigest: testDigest, InputSchemaDigest: testDigest,
				PromptDigest: testDigest, OutputSchemaDigest: testDigest,
				OutputDigest: sha256Digest(analysis), AnalysisJSON: analysis, PolicyJSON: policy,
				CommandCandidateJSON: candidate, GeneratedCommandDigest: sha256Digest([]byte(command)),
				EvidenceIDs: []string{testSignal},
				Usage:       ai.Usage{InputTokens: 12, CachedInputTokens: 2, OutputTokens: 3, Trusted: true},
			},
		},
	}
}

func failureFinalize() analysisworker.FinalizeRequest {
	request := successFinalize()
	request.Mutation.State = analysisworker.StateAnalysisFailed
	request.Mutation.AuditAction = "analysis_failed"
	request.Mutation.ValidationRequested = false
	request.Mutation.Success = nil
	request.Mutation.Failure = &analysisworker.Failure{
		Reason: ai.FailureTimeout, Attempts: 2, RetryEligible: true,
		InputBytes: 256, InputDigest: testDigest,
	}
	return request
}

func setLeaseDestination(dest []any, index int) {
	switch index {
	case 0:
		*dest[index].(*string) = testJob
	case 1:
		*dest[index].(*string) = "analyze"
	case 2:
		*dest[index].(*string) = "incident"
	case 3:
		*dest[index].(*string) = testIncident
	case 4:
		*dest[index].(*int32) = 1
	case 5:
		*dest[index].(*string) = "leased"
	case 6, 9:
		*dest[index].(*time.Time) = testNow
	case 7:
		*dest[index].(*string) = testToken
	case 8:
		*dest[index].(*string) = "analysis-worker"
	case 10:
		*dest[index].(*time.Time) = testNow.Add(30 * time.Second)
	case 11:
		*dest[index].(*int32) = 1
	case 12:
		*dest[index].(*int32) = 2
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type rowFunc func(...any) error

func (row rowFunc) Scan(dest ...any) error { return row(dest...) }

type queryStub struct {
	query string
	args  []any
	row   pgx.Row
	calls int
}

func (stub *queryStub) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	stub.query = query
	stub.args = append([]any(nil), args...)
	stub.calls++
	return stub.row
}

func (stub *queryStub) snapshot() (string, []any, int) {
	return stub.query, append([]any(nil), stub.args...), stub.calls
}
