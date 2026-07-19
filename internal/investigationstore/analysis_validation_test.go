package investigationstore

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestAnalysisSummaryStrictStateVariants(t *testing.T) {
	t.Parallel()

	started := validOpenAIAnalysis("started")
	failed := validOpenAIAnalysis("failed")
	succeeded := validOpenAIAnalysis("succeeded")
	stubSucceeded := succeeded
	stubSucceeded.ProviderKind = "deterministic_stub"
	stubSucceeded.AdapterID = "sentinelflow-deterministic-ai-stub-v1"
	stubSucceeded.Model = nil
	stubSucceeded.ReasoningEffort = nil
	stubSucceeded.RateCardVersion = nil

	valid := []struct {
		name string
		item AnalysisSummary
		keys []string
	}{
		{
			name: "started has common fields only",
			item: started,
			keys: []string{
				"adapter_id", "analysis_id", "false_positive_factors", "incident_version",
				"model", "provider_kind", "rate_card_version", "reasoning_effort",
				"result_state", "started_at",
			},
		},
		{
			name: "failed has failure fields only",
			item: failed,
			keys: []string{
				"adapter_id", "analysis_id", "completed_at", "failure_code",
				"false_positive_factors", "incident_version", "model", "provider_kind",
				"rate_card_version", "reasoning_effort", "result_state", "started_at",
			},
		},
		{
			name: "succeeded has success fields only",
			item: succeeded,
			keys: []string{
				"adapter_id", "analysis_id", "classification", "completed_at", "confidence",
				"false_positive_factors", "incident_version", "model", "output_digest",
				"provider_kind", "rate_card_version", "reasoning_effort", "result_state",
				"started_at", "summary", "uncertainty",
			},
		},
		{
			name: "stub succeeded preserves required null provenance",
			item: stubSucceeded,
			keys: []string{
				"adapter_id", "analysis_id", "classification", "completed_at", "confidence",
				"false_positive_factors", "incident_version", "model", "output_digest",
				"provider_kind", "rate_card_version", "reasoning_effort", "result_state",
				"started_at", "summary", "uncertainty",
			},
		},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !validAnalysis(test.item) {
				t.Fatal("strictly valid analysis was rejected")
			}
			raw, err := json.Marshal(test.item)
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]json.RawMessage
			if err = json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(object))
			for key := range object {
				got = append(got, key)
			}
			sort.Strings(got)
			want := append([]string(nil), test.keys...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("JSON fields=%v want=%v payload=%s", got, want, raw)
			}
			if test.item.ProviderKind == "deterministic_stub" {
				for _, field := range []string{"model", "reasoning_effort", "rate_card_version"} {
					if string(object[field]) != "null" {
						t.Fatalf("stub %s=%s want null", field, object[field])
					}
				}
			}
		})
	}
}

func TestAnalysisSummaryRejectsWrongStateFieldsAndProviderSpoofing(t *testing.T) {
	t.Parallel()

	stringValue := func(value string) *string { return &value }
	timeValue := func(value time.Time) *time.Time { return &value }
	tests := []struct {
		name   string
		base   AnalysisSummary
		mutate func(*AnalysisSummary)
	}{
		{"started completed_at", validOpenAIAnalysis("started"), func(v *AnalysisSummary) { v.CompletedAt = timeValue(testNow) }},
		{"started failure_code", validOpenAIAnalysis("started"), func(v *AnalysisSummary) { v.FailureCode = stringValue("timeout") }},
		{"started output_digest", validOpenAIAnalysis("started"), func(v *AnalysisSummary) { v.OutputDigest = stringValue(testDigest) }},
		{"started summary", validOpenAIAnalysis("started"), func(v *AnalysisSummary) { v.Summary = stringValue("leftover") }},
		{"started classification", validOpenAIAnalysis("started"), func(v *AnalysisSummary) { v.Classification = stringValue("path_scan") }},
		{"started confidence", validOpenAIAnalysis("started"), func(v *AnalysisSummary) { v.Confidence = stringValue("0.5") }},
		{"started uncertainty", validOpenAIAnalysis("started"), func(v *AnalysisSummary) { v.Uncertainty = stringValue("") }},
		{"failed output_digest", validOpenAIAnalysis("failed"), func(v *AnalysisSummary) { v.OutputDigest = stringValue(testDigest) }},
		{"failed summary", validOpenAIAnalysis("failed"), func(v *AnalysisSummary) { v.Summary = stringValue("leftover") }},
		{"failed classification", validOpenAIAnalysis("failed"), func(v *AnalysisSummary) { v.Classification = stringValue("path_scan") }},
		{"failed confidence", validOpenAIAnalysis("failed"), func(v *AnalysisSummary) { v.Confidence = stringValue("0.5") }},
		{"failed uncertainty", validOpenAIAnalysis("failed"), func(v *AnalysisSummary) { v.Uncertainty = stringValue("") }},
		{"succeeded failure_code", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.FailureCode = stringValue("timeout") }},
		{"unknown provider", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.ProviderKind = "openai" }},
		{"wrong OpenAI model", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.Model = stringValue("gpt-5.6-terra") }},
		{"missing OpenAI model", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.Model = nil }},
		{"empty OpenAI rate card", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.RateCardVersion = stringValue("") }},
		{"stub strings instead of null", validStubAnalysis(), func(v *AnalysisSummary) {
			v.Model = stringValue("")
			v.ReasoningEffort = stringValue("")
			v.RateCardVersion = stringValue("")
		}},
		{"stub carrying model", validStubAnalysis(), func(v *AnalysisSummary) { v.Model = stringValue("gpt-5.6-sol") }},
		{"nil false positives", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.FalsePositives = nil }},
		{"too many false positives", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) {
			v.FalsePositives = []string{"1", "2", "3", "4", "5", "6"}
		}},
		{"empty false positive", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.FalsePositives = []string{""} }},
		{"oversize false positive", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.FalsePositives = []string{strings.Repeat("a", 241)} }},
		{"schema-invalid confidence exponent", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.Confidence = stringValue("1e-1") }},
		{"schema-invalid confidence leading zero", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) { v.Confidence = stringValue("00.5") }},
		{"schema-invalid confidence length", validOpenAIAnalysis("succeeded"), func(v *AnalysisSummary) {
			v.Confidence = stringValue("0." + strings.Repeat("0", 63))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := test.base
			test.mutate(&candidate)
			if validAnalysis(candidate) {
				t.Fatalf("invalid analysis accepted: %+v", candidate)
			}
		})
	}
}

func TestScanAnalysisRejectsWrongStateOptionalLeftovers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []any
	}{
		{
			name: "started summary",
			values: analysisRowValues(
				"openai_responses", "openai-responses-v1", "gpt-5.6-sol", "medium", "operator-v1",
				"started", nil, nil, "leftover", nil, nil, nil, testNow, nil,
			),
		},
		{
			name: "failed classification",
			values: analysisRowValues(
				"openai_responses", "openai-responses-v1", "gpt-5.6-sol", "medium", "operator-v1",
				"failed", "timeout", nil, nil, "path_scan", nil, nil, testNow, testNow,
			),
		},
		{
			name: "stub non-null provenance",
			values: analysisRowValues(
				"deterministic_stub", "sentinelflow-deterministic-ai-stub-v1", "", "", "",
				"succeeded", nil, testDigest, "summary", "path_scan", "0.5", "", testNow, testNow,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := scanAnalysis(valuesRow(test.values...))
			if !errors.Is(err, ErrInvalidRow) {
				t.Fatalf("scan error=%v want %v", err, ErrInvalidRow)
			}
		})
	}
}

func validOpenAIAnalysis(state string) AnalysisSummary {
	model := "gpt-5.6-sol"
	reasoning := "medium"
	rateCard := "operator-v1"
	result := AnalysisSummary{
		AnalysisID: testAnalysisID, IncidentVersion: 1, ProviderKind: "openai_responses",
		AdapterID: "openai-responses-v1", Model: &model, ReasoningEffort: &reasoning,
		RateCardVersion: &rateCard, ResultState: state, StartedAt: testNow,
		FalsePositives: []string{},
	}
	switch state {
	case "failed":
		failure := "timeout"
		completed := testNow.Add(time.Second)
		result.FailureCode = &failure
		result.CompletedAt = &completed
	case "succeeded":
		digest := testDigest
		summary := "Synthetic analysis"
		classification := "path_scan"
		confidence := "0.90000"
		uncertainty := ""
		completed := testNow.Add(time.Second)
		result.OutputDigest = &digest
		result.Summary = &summary
		result.Classification = &classification
		result.Confidence = &confidence
		result.Uncertainty = &uncertainty
		result.CompletedAt = &completed
	}
	return result
}

func validStubAnalysis() AnalysisSummary {
	result := validOpenAIAnalysis("succeeded")
	result.ProviderKind = "deterministic_stub"
	result.AdapterID = "sentinelflow-deterministic-ai-stub-v1"
	result.Model = nil
	result.ReasoningEffort = nil
	result.RateCardVersion = nil
	return result
}

func analysisRowValues(
	provider, adapter string,
	model, reasoning, rateCard any,
	state string,
	failure, digest, summary, classification, confidence, uncertainty any,
	started time.Time,
	completed any,
) []any {
	return []any{
		testAnalysisID, int32(1), provider, adapter, model, reasoning, rateCard, state,
		failure, digest, summary, classification, confidence, uncertainty, started, completed,
	}
}
