package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testAPIKey = "test-openai-key-never-log-this-value"

func TestRequestUsesFrozenResponsesContract(t *testing.T) {
	t.Parallel()
	artifacts := checkedArtifacts(t)
	input := validInput(t, testIDs(2))
	budget := &fakeBudget{}
	clock := &fakeClock{now: time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)}
	var captured *http.Request
	var capturedBody []byte
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		captured = request.Clone(request.Context())
		var err error
		capturedBody, err = io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		return jsonResponse(http.StatusOK, completedResponse(t, validOutput(t, testIDs(2)), true)), nil
	})
	client := newTestClient(t, artifacts, transport, budget, clock)

	result, err := client.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if captured == nil {
		t.Fatal("no request captured")
	}
	if captured.Method != http.MethodPost || captured.URL.Path != ResponsesPath || captured.URL.Host != "api.openai.com" {
		t.Fatalf("unexpected request target: %s %s", captured.Method, captured.URL)
	}
	if got := captured.Header.Get("Authorization"); got != "Bearer "+testAPIKey {
		t.Fatalf("Authorization = %q", got)
	}
	if captured.Header.Get("Content-Type") != "application/json" || captured.Header.Get("Accept") != "application/json" {
		t.Fatalf("unexpected content negotiation headers: %v", captured.Header)
	}
	deadline, ok := captured.Context().Deadline()
	if !ok {
		t.Fatal("request context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining < 29*time.Second || remaining > RequestTimeout {
		t.Fatalf("request deadline remaining = %v, want approximately 30s", remaining)
	}

	var body map[string]any
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if body["model"] != Model || body["store"] != false || body["max_output_tokens"] != float64(MaxOutputTokens) {
		t.Fatalf("frozen request fields differ: %s", capturedBody)
	}
	if _, exists := body["tools"]; exists {
		t.Fatal("tools must be omitted")
	}
	reasoningMap := body["reasoning"].(map[string]any)
	if reasoningMap["effort"] != ReasoningEffort {
		t.Fatalf("reasoning.effort = %v", reasoningMap["effort"])
	}
	textMap := body["text"].(map[string]any)
	format := textMap["format"].(map[string]any)
	if format["type"] != "json_schema" || format["name"] != "sentinelflow_analysis_v1" || format["strict"] != true {
		t.Fatalf("invalid text.format: %#v", format)
	}
	var expectedSchema any
	if err := json.Unmarshal(artifacts.outputSchema, &expectedSchema); err != nil {
		t.Fatal(err)
	}
	if !jsonEquivalent(format["schema"], expectedSchema) {
		t.Fatal("request schema differs from checked-in output schema")
	}
	messages := body["input"].([]any)
	if len(messages) != 2 || messageText(messages[0]) != string(artifacts.systemPrompt) || messageText(messages[1]) != string(input) {
		t.Fatal("prompt or compact input was changed in transit")
	}
	if result.InputDigest != digest(input) || result.InputSchemaDigest != artifacts.inputSchemaDigest || result.PromptDigest != artifacts.promptDigest || result.OutputSchemaDigest != artifacts.outputSchemaDigest {
		t.Fatalf("missing provenance digests: %+v", result)
	}
	if result.Attempts != 1 || !result.Usage.Trusted {
		t.Fatalf("unexpected result attempts/usage: %+v", result)
	}
	requests, reservations := budget.snapshot()
	if len(requests) != 1 || requests[0].Model != Model || requests[0].MaxInputTokenUnits != MaxInputBytes || requests[0].MaxOutputTokens != MaxOutputTokens || requests[0].RateCardVersion != "operator-v1" {
		t.Fatalf("unexpected budget reservation: %+v", requests)
	}
	settlements := reservations[0].snapshot()
	if len(settlements) != 1 || settlements[0].fullCharge || !settlements[0].usage.Trusted {
		t.Fatalf("unexpected settlement: %+v", settlements)
	}
}

func TestRetryOnlyForClassifiedHTTPStatuses(t *testing.T) {
	t.Parallel()
	for _, status := range []int{408, 409, 429, 500, 503, 599} {
		status := status
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			t.Parallel()
			artifacts := checkedArtifacts(t)
			budget := &fakeBudget{}
			clock := &fakeClock{now: time.Unix(0, 0).UTC()}
			var calls atomic.Int32
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					return jsonResponse(status, []byte(`{"error":{"message":"provider-secret-must-not-leak"}}`)), nil
				}
				return jsonResponse(http.StatusOK, completedResponse(t, validOutput(t, testIDs(1)), true)), nil
			})
			client := newTestClient(t, artifacts, transport, budget, clock)
			result, err := client.Analyze(context.Background(), validInput(t, testIDs(1)))
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if result.Attempts != 2 || calls.Load() != 2 || clock.sleepCount() != 1 {
				t.Fatalf("retry evidence: result=%+v calls=%d sleeps=%d", result, calls.Load(), clock.sleepCount())
			}
			requests, reservations := budget.snapshot()
			if len(requests) != 2 || len(reservations) != 2 || !reservations[0].snapshot()[0].fullCharge || reservations[1].snapshot()[0].fullCharge {
				t.Fatalf("retry budget accounting differs: requests=%d reservations=%d", len(requests), len(reservations))
			}
		})
	}
}

func TestDoesNotRetryOtherHTTPOrTransportFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		status     int
		transport  error
		wantReason FailureReason
	}{
		{name: "bad request", status: 400, wantReason: FailureConfiguration},
		{name: "unauthorized", status: 401, wantReason: FailureConfiguration},
		{name: "forbidden", status: 403, wantReason: FailureConfiguration},
		{name: "not found", status: 404, wantReason: FailureConfiguration},
		{name: "unprocessable", status: 422, wantReason: FailureConfiguration},
		{name: "network", transport: errors.New("network detail with secret"), wantReason: FailureNetworkError},
		{name: "deadline", transport: context.DeadlineExceeded, wantReason: FailureTimeout},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				if tt.transport != nil {
					return nil, tt.transport
				}
				return jsonResponse(tt.status, []byte(`{"error":"provider-secret"}`)), nil
			})
			client := newTestClient(t, checkedArtifacts(t), transport, &fakeBudget{}, &fakeClock{})
			_, err := client.Analyze(context.Background(), validInput(t, testIDs(1)))
			assertFailure(t, err, tt.wantReason, 1)
			if calls.Load() != 1 {
				t.Fatalf("RoundTrip calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestResponseFailuresAreTypedAndNonEnforcing(t *testing.T) {
	t.Parallel()
	ids := testIDs(1)
	tests := []struct {
		name       string
		response   func(*testing.T) []byte
		wantReason FailureReason
	}{
		{name: "refusal", wantReason: FailureRefused, response: func(t *testing.T) []byte {
			return mustJSON(t, map[string]any{
				"id":     "resp_refused",
				"status": "completed",
				"output": []any{
					map[string]any{
						"type":   "message",
						"status": "completed",
						"content": []any{
							map[string]any{"type": "refusal", "refusal": "cannot comply"},
						},
					},
				},
			})
		}},
		{name: "incomplete", wantReason: FailureIncomplete, response: func(t *testing.T) []byte {
			return mustJSON(t, map[string]any{"id": "resp_incomplete", "status": "incomplete", "incomplete_details": map[string]any{"reason": "max_output_tokens"}, "output": []any{}})
		}},
		{name: "schema invalid", wantReason: FailureSchemaInvalid, response: func(t *testing.T) []byte {
			return completedResponse(t, []byte(`{"schema_version":"sentinelflow_analysis_v1"}`), true)
		}},
		{name: "evidence mismatch", wantReason: FailureEvidenceInvalid, response: func(t *testing.T) []byte {
			other := []string{"ffffffff-ffff-ffff-ffff-ffffffffffff"}
			return completedResponse(t, validOutput(t, other), true)
		}},
		{name: "duplicate response json", wantReason: FailureSchemaInvalid, response: func(t *testing.T) []byte {
			return []byte(`{"id":"one","id":"two","status":"completed","output":[]}`)
		}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return jsonResponse(http.StatusOK, tt.response(t)), nil
			})
			client := newTestClient(t, checkedArtifacts(t), transport, &fakeBudget{}, &fakeClock{})
			_, err := client.Analyze(context.Background(), validInput(t, ids))
			assertFailure(t, err, tt.wantReason, 1)
			if calls.Load() != 1 {
				t.Fatalf("RoundTrip calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestInputFailuresOccurBeforeBudgetOrNetwork(t *testing.T) {
	t.Parallel()
	valid := validInput(t, testIDs(2))
	oversized := append(bytes.Clone(valid), bytes.Repeat([]byte(" "), MaxInputBytes-len(valid)+1)...)
	outOfOrder := validInput(t, []string{testIDs(2)[1], testIDs(2)[0]})
	duplicateKey := append([]byte(`{"schema_version":"sentinelflow_analysis_input_v1",`), valid[1:]...)
	tooMany := compactInputFixture(t, testIDs(51))
	if len(tooMany) > MaxInputBytes {
		t.Fatalf("51-ref fixture length = %d, cannot isolate reference-count check", len(tooMany))
	}

	tests := []struct {
		name       string
		input      []byte
		wantReason FailureReason
	}{
		{name: "bytes", input: oversized, wantReason: FailureInputTooLarge},
		{name: "references", input: tooMany, wantReason: FailureInputTooLarge},
		{name: "order", input: outOfOrder, wantReason: FailureEvidenceInvalid},
		{name: "duplicate JSON key", input: duplicateKey, wantReason: FailureSchemaInvalid},
		{name: "invalid JSON", input: []byte(`{"schema_version":`), wantReason: FailureSchemaInvalid},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			budget := &fakeBudget{}
			client := newTestClient(t, checkedArtifacts(t), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New("must not be called")
			}), budget, &fakeClock{})
			_, err := client.Analyze(context.Background(), tt.input)
			assertFailure(t, err, tt.wantReason, 0)
			requests, _ := budget.snapshot()
			if calls.Load() != 0 || len(requests) != 0 {
				t.Fatalf("invalid input reached budget/network: calls=%d reservations=%d", calls.Load(), len(requests))
			}
		})
	}
}

func TestBudgetExhaustionPreventsRequest(t *testing.T) {
	t.Parallel()
	for _, budgetErr := range []error{ErrBudgetExhausted, errors.New("ledger-secret-detail")} {
		budgetErr := budgetErr
		t.Run(budgetErr.Error(), func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			budget := &fakeBudget{err: budgetErr}
			client := newTestClient(t, checkedArtifacts(t), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New("must not be called")
			}), budget, &fakeClock{})
			_, err := client.Analyze(context.Background(), validInput(t, testIDs(1)))
			want := FailureConfiguration
			if errors.Is(budgetErr, ErrBudgetExhausted) {
				want = FailureBudgetExhausted
			}
			assertFailure(t, err, want, 1)
			if calls.Load() != 0 || strings.Contains(err.Error(), budgetErr.Error()) {
				t.Fatalf("budget failure leaked or called network: calls=%d err=%q", calls.Load(), err)
			}
		})
	}
}

func TestCancellationBeforeCall(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	budget := &fakeBudget{}
	client := newTestClient(t, checkedArtifacts(t), roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("RoundTrip must not be called")
		return nil, nil
	}), budget, &fakeClock{})
	_, err := client.Analyze(ctx, validInput(t, testIDs(1)))
	assertFailure(t, err, FailureCancelled, 0)
}

func TestAPIKeyAndProviderContentNeverEnterErrorsOrFormatting(t *testing.T) {
	t.Parallel()
	const providerSecret = "provider-body-super-secret"
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return jsonResponse(http.StatusInternalServerError, []byte(providerSecret)), nil
	})
	client := newTestClient(t, checkedArtifacts(t), transport, &fakeBudget{}, &fakeClock{})
	_, err := client.Analyze(context.Background(), validInput(t, testIDs(1)))
	assertFailure(t, err, FailureServerError, 2)
	for _, rendered := range []string{err.Error(), client.String(), fmt.Sprintf("%v", client), fmt.Sprintf("%+v", client), fmt.Sprintf("%#v", client.apiKey)} {
		if strings.Contains(rendered, testAPIKey) || strings.Contains(rendered, providerSecret) {
			t.Fatalf("secret leaked in %q", rendered)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want classified retry", calls.Load())
	}
}

func TestLoadCheckedArtifactsAndRejectInvalidArtifacts(t *testing.T) {
	t.Parallel()
	artifacts := checkedArtifacts(t)
	if artifacts.inputSchemaDigest == "" || artifacts.promptDigest == "" || artifacts.outputSchemaDigest == "" {
		t.Fatal("artifact digests are missing")
	}
	for _, test := range []struct {
		input, prompt, output []byte
	}{
		{nil, []byte("prompt"), []byte(`{"type":"object"}`)},
		{[]byte(`{"type":"object","type":"array"}`), []byte("prompt"), []byte(`{"type":"object"}`)},
		{[]byte(`{"type":"object"}`), []byte{}, []byte(`{"type":"object"}`)},
		{[]byte(`{"type":"object"}`), []byte("prompt"), []byte(`[]`)},
	} {
		_, err := ParseArtifacts(test.input, test.prompt, test.output)
		assertFailure(t, err, FailureConfiguration, 0)
	}
}

func TestNewClientRejectsMissingOrMutableConfiguration(t *testing.T) {
	t.Parallel()
	artifacts := checkedArtifacts(t)
	valid := ClientConfig{APIKey: testAPIKey, RateCardVersion: "operator-v1", Artifacts: artifacts, Budget: &fakeBudget{}}
	tests := []struct {
		name   string
		mutate func(*ClientConfig)
	}{
		{name: "key", mutate: func(c *ClientConfig) { c.APIKey = "" }},
		{name: "key whitespace", mutate: func(c *ClientConfig) { c.APIKey = testAPIKey + " " }},
		{name: "rate card", mutate: func(c *ClientConfig) { c.RateCardVersion = "" }},
		{name: "rate card control", mutate: func(c *ClientConfig) { c.RateCardVersion = "operator\nlog" }},
		{name: "timeout", mutate: func(c *ClientConfig) { c.RequestTimeout = RequestTimeout + time.Nanosecond }},
		{name: "attempts", mutate: func(c *ClientConfig) { c.MaxAttempts = 3 }},
		{name: "budget", mutate: func(c *ClientConfig) { c.Budget = nil }},
		{name: "plaintext base", mutate: func(c *ClientConfig) { c.BaseURL = "http://api.openai.com" }},
		{name: "base path", mutate: func(c *ClientConfig) { c.BaseURL = "https://api.openai.com/other" }},
		{name: "base credentials", mutate: func(c *ClientConfig) { c.BaseURL = "https://user:secret@api.openai.com" }},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			config := valid
			tt.mutate(&config)
			_, err := NewClient(config)
			assertFailure(t, err, FailureConfiguration, 0)
			if strings.Contains(err.Error(), testAPIKey) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("configuration error leaked a value: %v", err)
			}
		})
	}
}

func TestClientExposesFrozenOpenAIProviderIdentity(t *testing.T) {
	t.Parallel()
	client := newTestClient(t, checkedArtifacts(t), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unused")
	}), &fakeBudget{}, &fakeClock{})
	identity := client.Identity()
	if identity.Kind() != ProviderOpenAIResponses ||
		identity.AdapterID() != OpenAIResponsesAdapterID || identity.Model() != Model ||
		identity.ReasoningEffort() != ReasoningEffort ||
		identity.RateCardVersion() != "operator-v1" {
		t.Fatalf("provider identity=%#v", identity)
	}
	if _, ok := ParseProviderIdentity(
		string(ProviderOpenAIResponses), OpenAIResponsesAdapterID,
		Model, ReasoningEffort, "",
	); ok {
		t.Fatal("OpenAI identity without a rate card was accepted")
	}
	if _, ok := ParseProviderIdentity(
		"openai", OpenAIResponsesAdapterID, Model, ReasoningEffort, "operator-v1",
	); ok {
		t.Fatal("unknown provider kind was accepted")
	}
}

func TestConfiguredTimeoutAndNoRetryAreEnforced(t *testing.T) {
	t.Parallel()
	artifacts := checkedArtifacts(t)
	budget := &fakeBudget{}
	clock := &fakeClock{now: time.Unix(0, 0).UTC()}
	var calls atomic.Int32
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Fatal("request deadline missing")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > 2*time.Second {
			t.Fatalf("configured deadline remaining = %v", remaining)
		}
		return jsonResponse(http.StatusTooManyRequests, []byte(`{"error":{"message":"redacted"}}`)), nil
	})
	client, err := NewClient(ClientConfig{
		APIKey: testAPIKey, RateCardVersion: "operator-v1", RequestTimeout: 2 * time.Second,
		MaxAttempts: 1, Artifacts: artifacts, RoundTripper: transport, Clock: clock, Budget: budget,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Analyze(context.Background(), validInput(t, testIDs(1)))
	assertFailure(t, err, FailureRateLimited, 1)
	if calls.Load() != 1 || clock.sleepCount() != 0 {
		t.Fatalf("calls=%d sleeps=%d", calls.Load(), clock.sleepCount())
	}
}

func TestConcurrencyIsBoundedAtTwo(t *testing.T) {
	artifacts := checkedArtifacts(t)
	input := validInput(t, testIDs(1))
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	var active, maximum atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		current := active.Add(1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		active.Add(-1)
		return jsonResponse(http.StatusOK, completedResponse(t, validOutput(t, testIDs(1)), true)), nil
	})
	client := newTestClient(t, artifacts, transport, &fakeBudget{}, &fakeClock{})
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Analyze(context.Background(), input)
			errs <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("two requests did not enter transport")
		}
	}
	select {
	case <-entered:
		t.Fatal("third request bypassed concurrency bound")
	case <-time.After(30 * time.Millisecond):
	}
	release <- struct{}{}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("third request did not proceed after a slot opened")
	}
	release <- struct{}{}
	release <- struct{}{}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Analyze() error = %v", err)
		}
	}
	if maximum.Load() != MaxConcurrency {
		t.Fatalf("maximum concurrency = %d, want %d", maximum.Load(), MaxConcurrency)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
	clock.mu.Lock()
	clock.sleeps = append(clock.sleeps, duration)
	clock.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (clock *fakeClock) sleepCount() int {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return len(clock.sleeps)
}

type fakeBudget struct {
	mu           sync.Mutex
	err          error
	requests     []BudgetRequest
	reservations []*fakeReservation
}

func (budget *fakeBudget) Reserve(_ context.Context, request BudgetRequest) (BudgetReservation, error) {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	budget.requests = append(budget.requests, request)
	if budget.err != nil {
		return nil, budget.err
	}
	reservation := &fakeReservation{}
	budget.reservations = append(budget.reservations, reservation)
	return reservation, nil
}

func (budget *fakeBudget) snapshot() ([]BudgetRequest, []*fakeReservation) {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return append([]BudgetRequest(nil), budget.requests...), append([]*fakeReservation(nil), budget.reservations...)
}

type settlement struct {
	usage      Usage
	fullCharge bool
}

type fakeReservation struct {
	mu          sync.Mutex
	settlements []settlement
	err         error
}

func (reservation *fakeReservation) Settle(_ context.Context, usage Usage, fullCharge bool) error {
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	reservation.settlements = append(reservation.settlements, settlement{usage: usage, fullCharge: fullCharge})
	return reservation.err
}

func (reservation *fakeReservation) snapshot() []settlement {
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	return append([]settlement(nil), reservation.settlements...)
}

func checkedArtifacts(t *testing.T) Artifacts {
	t.Helper()
	root := filepath.Join("..", "..")
	artifacts, err := LoadArtifacts(ArtifactPaths{
		InputSchema:  filepath.Join(root, "contracts", "ai", "sentinelflow_analysis_input_v1.schema.json"),
		SystemPrompt: filepath.Join(root, "contracts", "ai", "sentinelflow_system_prompt_v1.txt"),
		OutputSchema: filepath.Join(root, "contracts", "ai", "sentinelflow_analysis_v1.schema.json"),
	})
	if err != nil {
		t.Fatalf("LoadArtifacts() error = %v", err)
	}
	return artifacts
}

func newTestClient(t *testing.T, artifacts Artifacts, transport http.RoundTripper, budget BudgetGate, clock Clock) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		APIKey:          testAPIKey,
		RateCardVersion: "operator-v1",
		Artifacts:       artifacts,
		RoundTripper:    transport,
		Budget:          budget,
		Clock:           clock,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

func testIDs(count int) []string {
	ids := make([]string, count)
	for index := range ids {
		ids[index] = fmt.Sprintf("00000000-0000-0000-0000-%012x", index+1)
	}
	return ids
}

func validInput(t *testing.T, ids []string) []byte {
	t.Helper()
	digestValue := "sha256:" + strings.Repeat("a", 64)
	signals := make([]map[string]any, len(ids))
	references := make([]map[string]any, len(ids))
	for index, id := range ids {
		signals[index] = map[string]any{
			"signal_id": id, "rule_id": "path_scan.v1", "classification": "path_scan",
			"window_start": "2026-07-18T01:55:00Z", "window_end": "2026-07-18T02:00:00Z",
			"event_count": 8, "distinct_account_count": 0, "distinct_suspicious_path_count": 8,
			"evidence_digest": digestValue,
		}
		references[index] = map[string]any{
			"evidence_id": id, "kind": "deterministic_signal", "rule_id": "path_scan.v1",
			"signal_digest": digestValue, "expanded_event_count": 8,
		}
	}
	return mustJSON(t, map[string]any{
		"schema_version": "sentinelflow_analysis_input_v1", "incident_id": "10000000-0000-0000-0000-000000000001",
		"incident_version": 1, "analysis_attempt_id": "20000000-0000-0000-0000-000000000001",
		"generated_at": "2026-07-18T02:00:00Z", "prompt_version": "sentinelflow_system_prompt_v1",
		"output_schema_version": "sentinelflow_analysis_v1", "source_ip": "203.0.113.20",
		"service_label": "demo-app", "window_start": "2026-07-18T01:55:00Z", "window_end": "2026-07-18T02:00:00Z",
		"detector_config_version": "detector-v1", "source_health_status": "complete", "signals": signals,
		"evidence_refs":     references,
		"historical_impact": map[string]any{"lookback_start": "2026-07-17T02:00:00Z", "lookback_end": "2026-07-18T02:00:00Z", "coverage": "complete", "successful_auth_seen": false, "impact_digest": digestValue},
		"allowed_policy":    map[string]any{"action": "block_ip", "target_ip": "203.0.113.20", "minimum_ttl_seconds": 60, "default_ttl_seconds": 1800, "maximum_ttl_seconds": 86400, "table": "sentinelflow", "set": "blacklist_ipv4"},
	})
}

func compactInputFixture(t *testing.T, ids []string) []byte {
	t.Helper()
	signals := make([]map[string]any, len(ids))
	references := make([]map[string]any, len(ids))
	for index, id := range ids {
		signals[index] = map[string]any{"signal_id": id, "rule_id": "r", "event_count": 1, "evidence_digest": "d"}
		references[index] = map[string]any{"evidence_id": id, "rule_id": "r", "signal_digest": "d", "expanded_event_count": 1}
	}
	return mustJSON(t, map[string]any{
		"schema_version": "sentinelflow_analysis_input_v1", "prompt_version": "sentinelflow_system_prompt_v1",
		"output_schema_version": "sentinelflow_analysis_v1", "source_health_status": "complete",
		"signals": signals, "evidence_refs": references, "allowed_policy": map[string]any{"target_ip": "203.0.113.20"},
	})
}

func validOutput(t *testing.T, ids []string) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"schema_version": "sentinelflow_analysis_v1", "incident_summary": "Synthetic path scan signal.",
		"classification": "path_scan", "confidence": 0.91, "uncertainty": "Synthetic demonstration input.",
		"false_positive_factors": []string{"Authorized scanner"}, "evidence_ids": ids,
		"policy":                     map[string]any{"schema_version": "response-policy-v1", "action": "block_ip", "target_ip": "203.0.113.20", "ttl_seconds": 1800, "evidence_ids": ids, "rationale": "Complete deterministic signal."},
		"nftables_command_candidate": map[string]any{"schema_version": "nft-blacklist-v1", "target_ip": "203.0.113.20", "timeout": "30m", "evidence_ids": ids, "command": "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }"},
	})
}

func completedResponse(t *testing.T, output []byte, withUsage bool) []byte {
	t.Helper()
	response := map[string]any{
		"id": "resp_test", "status": "completed",
		"output": []any{map[string]any{"type": "message", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": string(output)}}}},
	}
	if withUsage {
		response["usage"] = map[string]any{"input_tokens": 100, "output_tokens": 50, "input_tokens_details": map[string]any{"cached_tokens": 10}}
	}
	return mustJSON(t, response)
}

func jsonResponse(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return data
}

func messageText(message any) string {
	object := message.(map[string]any)
	content := object["content"].([]any)
	return content[0].(map[string]any)["text"].(string)
}

func jsonEquivalent(left, right any) bool {
	leftBytes, _ := json.Marshal(left)
	rightBytes, _ := json.Marshal(right)
	return bytes.Equal(leftBytes, rightBytes)
}

func assertFailure(t *testing.T, err error, reason FailureReason, attempts int) {
	t.Helper()
	failure, ok := FailureOf(err)
	if !ok {
		t.Fatalf("error = %T %v, want *Failure", err, err)
	}
	if failure.Reason != reason || failure.Attempts != attempts {
		t.Fatalf("failure = %+v, want reason=%s attempts=%d", failure, reason, attempts)
	}
}
