package correlation

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

func FuzzCorrelationPermutationIsDeterministic(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4})
	f.Add([]byte{})
	f.Add([]byte{255, 5, 10, 15})

	f.Fuzz(func(t *testing.T, data []byte) {
		limit := len(data)
		if limit > 40 {
			limit = 40
		}
		rules := []detection.RuleID{
			detection.RulePathScan,
			detection.RuleRequestBurst,
			detection.RuleLoginBruteForce,
			detection.RuleCredentialStuffing,
		}
		signals := make([]detection.Signal, 0, limit)
		for index, value := range data[:limit] {
			start := correlationNow.Add(time.Duration(value%20) * time.Minute)
			signal := testSignal(index+1, rules[int(value)%len(rules)], start, start.Add(time.Second))
			if value%3 == 0 {
				signal.SourceIP = "198.51.100.10"
			}
			if value%5 == 0 {
				signal.ServiceLabel = "other"
			}
			signals = append(signals, signal)
		}
		first, firstErr := Correlate(signals)
		slices.Reverse(signals)
		second, secondErr := Correlate(signals)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("permutation changed error state: %v / %v", firstErr, secondErr)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("permutation changed correlation output")
		}
		for _, group := range first {
			for _, signal := range group.Signals() {
				if signal.SourceIP != group.SourceIP {
					t.Fatal("cross-source signal entered group")
				}
			}
		}
	})
}
