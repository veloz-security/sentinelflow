package controlmetrics

import (
	"math"
	"strings"
	"testing"
)

func TestCompleteSampleContractIsExactAndFailsClosed(t *testing.T) {
	t.Parallel()
	baseline := completeContractSamples()
	if expectedSampleCount != 362 || len(baseline) != expectedSampleCount {
		t.Fatalf("sample contract count=%d generated=%d want=362", expectedSampleCount, len(baseline))
	}
	if validated, err := validateCompleteSamples(baseline); err != nil || len(validated) != 362 {
		t.Fatalf("complete contract rejected: samples=%d err=%v", len(validated), err)
	}

	tests := []struct {
		name   string
		mutate func([]Sample) []Sample
	}{
		{name: "missing", mutate: func(samples []Sample) []Sample { return samples[:len(samples)-1] }},
		{name: "duplicate", mutate: func(samples []Sample) []Sample {
			samples[len(samples)-1] = samples[0]
			return samples
		}},
		{name: "negative", mutate: func(samples []Sample) []Sample {
			samples[0].Value = -1
			return samples
		}},
		{name: "nan", mutate: func(samples []Sample) []Sample {
			samples[0].Value = math.NaN()
			return samples
		}},
		{name: "infinity", mutate: func(samples []Sample) []Sample {
			samples[0].Value = math.Inf(1)
			return samples
		}},
		{name: "unknown metric", mutate: func(samples []Sample) []Sample {
			samples[0].Name = "sentinelflow_control_request_identifier"
			return samples
		}},
		{name: "unknown label value", mutate: func(samples []Sample) []Sample {
			for index := range samples {
				if samples[index].Label1Name != "" {
					samples[index].Label1Value = "unbounded-runtime-value"
					break
				}
			}
			return samples
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := append([]Sample(nil), baseline...)
			if _, err := validateCompleteSamples(test.mutate(candidate)); err != ErrInvalidSample {
				t.Fatalf("invalid aggregate disposition=%v", err)
			}
		})
	}
}

func TestLifecycleMetricDimensionsAreClosedAndPrivacySafe(t *testing.T) {
	t.Parallel()
	lifecycleMetrics := []string{
		"sentinelflow_control_lifecycle_schedules",
		"sentinelflow_control_lifecycle_oldest_due_age_seconds",
		"sentinelflow_control_lifecycle_lease_expiry_lag_seconds",
	}
	for _, name := range lifecycleMetrics {
		contract, ok := contracts[name]
		wantSecondName := ""
		wantSecondValues := 0
		if name == lifecycleMetrics[0] {
			wantSecondName = "state"
			wantSecondValues = 6
		}
		if !ok || contract.firstName != "purpose" ||
			len(contract.firstValues) != 3 ||
			contract.secondName != wantSecondName ||
			len(contract.secondValues) != wantSecondValues {
			t.Fatalf("lifecycle contract is not exact: %s %+v", name, contract)
		}
		parts := []string{name, contract.firstName, contract.secondName}
		for value := range contract.firstValues {
			parts = append(parts, value)
		}
		for value := range contract.secondValues {
			parts = append(parts, value)
		}
		for _, part := range parts {
			for _, token := range strings.Split(part, "_") {
				switch token {
				case "id", "ip", "digest", "error", "errorcode", "errortext":
					t.Fatalf("lifecycle metric exposes forbidden dimension token %q in %q", token, part)
				}
			}
		}
	}
}

func completeContractSamples() []Sample {
	samples := make([]Sample, 0, expectedSampleCount)
	for name, contract := range contracts {
		if contract.firstName == "" {
			samples = append(samples, Sample{Name: name})
			continue
		}
		for firstValue := range contract.firstValues {
			if contract.secondName == "" {
				samples = append(samples, Sample{
					Name: name, Label1Name: contract.firstName, Label1Value: firstValue,
				})
				continue
			}
			for secondValue := range contract.secondValues {
				samples = append(samples, Sample{
					Name: name, Label1Name: contract.firstName, Label1Value: firstValue,
					Label2Name: contract.secondName, Label2Value: secondValue,
				})
			}
		}
	}
	return samples
}
