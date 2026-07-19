package tuning

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

func TestComparisonRetainsFrozenBaselineAndRejectsRegressiveCandidates(t *testing.T) {
	corpus := loadCheckedCorpus(t)
	evaluatedAt := time.Date(2026, 7, 18, 5, 0, 0, 0, time.UTC)
	report, err := Compare(corpus, "ops.qa", evaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if report.ActiveRuntimeConfigurationDigest != detection.NewDefault().ConfigurationDigest() ||
		report.ActiveRuntimeConfigurationVersion != detection.DefaultConfigurationVersion ||
		report.Recommendation != "retain_frozen_baseline" || report.SelectedProfileID != "baseline-v1" ||
		report.ActivationPerformed || len(report.Results) != 3 {
		t.Fatalf("report header=%+v", report)
	}
	assertMatrix(t, report.Results[0], ConfusionMatrix{
		TruePositive: 8, TrueNegative: 8, Incomplete: 4,
	}, true, "normal_attack_regression_clear")
	assertMatrix(t, report.Results[1], ConfusionMatrix{
		TruePositive: 2, TrueNegative: 8, FalseNegative: 6, Incomplete: 4,
	}, false, "attack_detection_regression")
	assertMatrix(t, report.Results[2], ConfusionMatrix{
		TruePositive: 8, TrueNegative: 3, FalsePositive: 5, Incomplete: 4,
	}, false, "false_positive_regression")
	for _, profile := range report.Results {
		for _, item := range profile.Cases {
			if item.EvidenceState != EvidenceComplete &&
				(item.Decision != DecisionIncomplete || !item.Correct ||
					item.ExplanationCode != "evidence_guard_fail_closed") {
				t.Fatalf("profile=%s guarded case=%+v", profile.Profile.ProfileID, item)
			}
			if bytes.Contains([]byte(item.CaseID), []byte("duplicates")) &&
				profile.Profile.ProfileID == "baseline-v1" && item.Decision != DecisionMatched {
				t.Fatalf("duplicate case did not use unique evidence: %+v", item)
			}
		}
	}
	if err = VerifyReport(report, corpus); err != nil {
		t.Fatal(err)
	}
	encoded, result, err := EncodeReport(report, corpus)
	if err != nil || result.ReportID != report.ReportID || result.ReportDigest != report.ReportDigest {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	decoded, decodedResult, err := DecodeAndVerifyReport(encoded, corpus)
	if err != nil || decoded.ReportDigest != report.ReportDigest || decodedResult != result {
		t.Fatalf("decoded=%+v result=%+v err=%v", decoded, decodedResult, err)
	}
}

func TestReportMutationAndCorpusSubstitutionFailVerification(t *testing.T) {
	corpus := loadCheckedCorpus(t)
	report, err := Compare(corpus, "ops.qa", time.Date(2026, 7, 18, 5, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	mutated := report
	mutated.Results = append([]ProfileResult(nil), report.Results...)
	mutated.Results[1].Matrix.FalseNegative--
	if err = VerifyReport(mutated, corpus); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("mutation err=%v", err)
	}
	other := corpus
	other.rawDigest = "sha256:" + string(bytes.Repeat([]byte{'f'}, 64))
	if err = VerifyReport(report, other); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("substitution err=%v", err)
	}
	encoded, _, err := EncodeReport(report, corpus)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, []byte("{}\n")...)
	if _, _, err = DecodeAndVerifyReport(encoded, corpus); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("trailing document err=%v", err)
	}
}

func TestCorpusRejectsUnknownFieldsOrderingInvalidFactorsAndMissingCoverage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "samples", "tuning", "threshold_cases_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	cases := document["cases"].([]any)
	tests := map[string]func(map[string]any){
		"unknown field": func(value map[string]any) { value["unexpected"] = true },
		"unsorted": func(value map[string]any) {
			items := value["cases"].([]any)
			items[0], items[1] = items[1], items[0]
		},
		"attack factor": func(value map[string]any) {
			items := value["cases"].([]any)
			items[0].(map[string]any)["false_positive_factors"] = []any{"load_test"}
		},
		"none mixed with factor": func(value map[string]any) {
			items := value["cases"].([]any)
			items[1].(map[string]any)["false_positive_factors"] = []any{"none", "shared_nat"}
		},
		"missing coverage": func(value map[string]any) {
			items := value["cases"].([]any)
			value["cases"] = items[:4]
		},
	}
	_ = cases
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if cloneErr := json.Unmarshal(raw, &value); cloneErr != nil {
				t.Fatal(cloneErr)
			}
			mutate(value)
			candidate, marshalErr := json.Marshal(value)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, loadErr := LoadCorpus(candidate); !errors.Is(loadErr, ErrInvalidCorpus) {
				t.Fatalf("err=%v", loadErr)
			}
		})
	}
}

func loadCheckedCorpus(t *testing.T) Corpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "samples", "tuning", "threshold_cases_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := LoadCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	return corpus
}

func assertMatrix(t *testing.T, result ProfileResult, expected ConfusionMatrix, eligible bool, reason string) {
	t.Helper()
	if result.Matrix != expected || result.GuardFailureCount != 0 ||
		result.ActivationEligible != eligible || result.ActivationReason != reason {
		t.Fatalf("profile=%s matrix=%+v eligible=%v reason=%s", result.Profile.ProfileID,
			result.Matrix, result.ActivationEligible, result.ActivationReason)
	}
}
