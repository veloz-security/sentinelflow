package aistub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

const (
	testIncidentID = "019b0000-0000-7000-8000-000000000001"
	testAnalysisID = "019b0000-0000-7000-8000-000000000002"
	testSignalID   = "019b0000-0000-7000-8000-000000000003"
	testDigest     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestAnalyzerProducesDeterministicBoundedCandidate(t *testing.T) {
	t.Parallel()
	input := validInputBytes(t)
	analyzer := New()
	first, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := analyzer.Analyze(context.Background(), append([]byte(nil), input...))
	if err != nil {
		t.Fatal(err)
	}
	if first.ResponseID != second.ResponseID || !bytes.Equal(first.Output, second.Output) ||
		first.InputDigest != digestBytes(input) || first.Attempts != 1 ||
		first.InputSchemaDigest != ai.PinnedInputSchemaDigest ||
		first.PromptDigest != ai.PinnedSystemPromptDigest ||
		first.OutputSchemaDigest != ai.PinnedOutputSchemaDigest || first.Usage.Trusted {
		t.Fatalf("stub result provenance drifted: %#v", first)
	}
	if got := analyzer.String(); got != "aistub("+AdapterID+")" || strings.Contains(got, ai.Model) {
		t.Fatalf("stub identity = %q", got)
	}
	identity := analyzer.Identity()
	if identity.Kind() != ai.ProviderDeterministicStub || identity.AdapterID() != AdapterID ||
		identity.Model() != "" || identity.ReasoningEffort() != "" ||
		identity.RateCardVersion() != "" {
		t.Fatalf("stub provider identity = %#v", identity)
	}

	var output outputDocument
	decoder := json.NewDecoder(bytes.NewReader(first.Output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		t.Fatal(err)
	}
	if output.SchemaVersion != analysisworker.OutputSchemaVersion ||
		output.Classification != "path_scan" || output.Policy.TargetIP != "203.0.113.20" ||
		output.Policy.TTLSeconds != defaultTTLSeconds || output.Candidate.Timeout != "30m" ||
		len(output.EvidenceIDs) != 1 || output.EvidenceIDs[0] != testSignalID {
		t.Fatalf("output = %#v", output)
	}
	artifact, err := nftvalidate.Canonicalize([]byte(output.Candidate.Command), uint32(output.Policy.TTLSeconds))
	if err != nil || artifact.TargetIPv4() != output.Policy.TargetIP || artifact.CanonicalTTLToken() != "30m" {
		t.Fatalf("candidate failed frozen grammar: artifact=%#v err=%v", artifact, err)
	}
	for _, prohibited := range []string{"password", "authorization", "cookie", "query", "/.env", "/login"} {
		if strings.Contains(strings.ToLower(string(first.Output)), prohibited) {
			t.Fatalf("stub output contains prohibited value %q", prohibited)
		}
	}
}

func TestAnalyzerMixedClassificationAndInputBinding(t *testing.T) {
	t.Parallel()
	value := validInputValue()
	secondID := "019b0000-0000-7000-8000-000000000004"
	value.Signals = append(value.Signals, compactSignal{
		SignalID: secondID, RuleID: "request_burst.v1", Classification: "request_burst",
		WindowStart: value.WindowStart, WindowEnd: value.WindowEnd, EventCount: 120,
		EvidenceDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	value.EvidenceRefs = append(value.EvidenceRefs, compactEvidenceRef{
		EvidenceID: secondID, Kind: "deterministic_signal", RuleID: "request_burst.v1",
		SignalDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpandedEventCount: 120,
	})
	input, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	result, err := New().Analyze(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	var output outputDocument
	if err := json.Unmarshal(result.Output, &output); err != nil {
		t.Fatal(err)
	}
	if output.Classification != "mixed" || len(output.EvidenceIDs) != 2 || output.EvidenceIDs[1] != secondID {
		t.Fatalf("mixed output = %#v", output)
	}

	changed := append([]byte(nil), input...)
	changed = bytes.Replace(changed, []byte(`"successful_auth_seen":false`), []byte(`"successful_auth_seen":true`), 1)
	changedResult, err := New().Analyze(context.Background(), changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedResult.InputDigest == result.InputDigest || changedResult.ResponseID == result.ResponseID ||
		!bytes.Equal(changedResult.Output, result.Output) {
		t.Fatal("stub output should be deterministic while response identity binds every input byte")
	}
}

func TestAnalyzerFailsClosedForMalformedOrInconsistentInput(t *testing.T) {
	t.Parallel()
	valid := validInputBytes(t)
	cases := []struct {
		name   string
		input  []byte
		reason ai.FailureReason
	}{
		{name: "empty", input: nil, reason: ai.FailureInputTooLarge},
		{name: "oversized", input: bytes.Repeat([]byte{'x'}, ai.MaxInputBytes+1), reason: ai.FailureInputTooLarge},
		{name: "trailing", input: append(append([]byte(nil), valid...), []byte(" true")...), reason: ai.FailureSchemaInvalid},
		{name: "unknown", input: bytes.Replace(valid, []byte(`"incident_id"`), []byte(`"unknown":1,"incident_id"`), 1), reason: ai.FailureSchemaInvalid},
		{name: "duplicate", input: bytes.Replace(valid, []byte(`"incident_id"`), []byte(`"incident_id":"`+testIncidentID+`","incident_id"`), 1), reason: ai.FailureSchemaInvalid},
		{name: "noninteger", input: bytes.Replace(valid, []byte(`"incident_version":1`), []byte(`"incident_version":1.0`), 1), reason: ai.FailureSchemaInvalid},
		{name: "target mismatch", input: bytes.Replace(valid, []byte(`"target_ip":"203.0.113.20"`), []byte(`"target_ip":"203.0.113.21"`), 1), reason: ai.FailureEvidenceInvalid},
		{name: "invented evidence", input: bytes.Replace(valid, []byte(`"evidence_id":"`+testSignalID+`"`), []byte(`"evidence_id":"019b0000-0000-7000-8000-000000000099"`), 1), reason: ai.FailureEvidenceInvalid},
		{name: "incomplete health", input: bytes.Replace(valid, []byte(`"source_health_status":"complete"`), []byte(`"source_health_status":"incomplete"`), 1), reason: ai.FailureEvidenceInvalid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result, err := New().Analyze(context.Background(), test.input)
			if result.ResponseID != "" || len(result.Output) != 0 || result.Attempts != 0 ||
				result.InputDigest != "" || result.InputSchemaDigest != "" ||
				result.PromptDigest != "" || result.OutputSchemaDigest != "" {
				t.Fatalf("failed input returned result %#v", result)
			}
			failureValue, ok := ai.FailureOf(err)
			if !ok || failureValue.Reason != test.reason ||
				(len(test.input) > 0 && strings.Contains(err.Error(), string(test.input))) {
				t.Fatalf("failure = %#v err=%v", failureValue, err)
			}
		})
	}
}

func TestAnalyzerCancellationAndConcurrentReuse(t *testing.T) {
	t.Parallel()
	input := validInputBytes(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Analyze(ctx, input); failureReason(err) != ai.FailureCancelled {
		t.Fatalf("cancelled error = %v", err)
	}
	//lint:ignore SA1012 This deliberately verifies the analyzer's nil-context fail-closed boundary.
	if _, err := New().Analyze(nil, input); failureReason(err) != ai.FailureConfiguration {
		t.Fatalf("nil-context error = %v", err)
	}

	analyzer := New()
	want, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	errorsCh := make(chan error, 64)
	for range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			got, analyzeErr := analyzer.Analyze(context.Background(), input)
			if analyzeErr != nil {
				errorsCh <- analyzeErr
				return
			}
			if got.ResponseID != want.ResponseID || !bytes.Equal(got.Output, want.Output) {
				errorsCh <- errors.New("concurrent output drifted")
			}
		}()
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
}

func failureReason(err error) ai.FailureReason {
	value, ok := ai.FailureOf(err)
	if !ok {
		return ""
	}
	return value.Reason
}

func validInputBytes(t testing.TB) []byte {
	t.Helper()
	encoded, err := json.Marshal(validInputValue())
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func validInputValue() compactInput {
	generated := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	windowStart := generated.Add(-time.Minute)
	return compactInput{
		SchemaVersion: analysisworker.AnalysisInputSchemaVersion, IncidentID: testIncidentID,
		IncidentVersion: 1, AnalysisAttemptID: testAnalysisID,
		GeneratedAt: generated.Format(time.RFC3339Nano), PromptVersion: analysisworker.PromptVersion,
		OutputSchemaVersion: analysisworker.OutputSchemaVersion, SourceIP: "203.0.113.20",
		ServiceLabel: "demo-app", WindowStart: windowStart.Format(time.RFC3339Nano),
		WindowEnd: generated.Format(time.RFC3339Nano), DetectorVersion: "detector-config-v1",
		SourceHealthStatus: "complete",
		Signals: []compactSignal{{
			SignalID: testSignalID, RuleID: "path_scan.v1", Classification: "path_scan",
			WindowStart: windowStart.Format(time.RFC3339Nano), WindowEnd: generated.Format(time.RFC3339Nano),
			EventCount: 8, DistinctSuspiciousPathCount: 8, EvidenceDigest: testDigest,
		}},
		EvidenceRefs: []compactEvidenceRef{{
			EvidenceID: testSignalID, Kind: "deterministic_signal", RuleID: "path_scan.v1",
			SignalDigest: testDigest, ExpandedEventCount: 8,
		}},
		HistoricalImpact: compactHistory{
			LookbackStart: generated.Add(-24 * time.Hour).Format(time.RFC3339Nano),
			LookbackEnd:   generated.Format(time.RFC3339Nano), Coverage: "complete", ImpactDigest: testDigest,
		},
		AllowedPolicy: compactAllowedPolicy{
			Action: "block_ip", TargetIP: "203.0.113.20",
			MinimumTTLSeconds: analysisworker.DefaultMinimumTTLSeconds,
			DefaultTTLSeconds: defaultTTLSeconds, MaximumTTLSeconds: analysisworker.DefaultMaximumTTLSeconds,
			Table: "sentinelflow", Set: "blacklist_ipv4",
		},
	}
}
