package detection

import (
	"reflect"
	"testing"
	"time"
)

func FuzzEvaluateIsDeterministicAndNeverPanics(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5})
	f.Add([]byte{})
	f.Add([]byte{255, 0, 120, 8, 20, 10})

	f.Fuzz(func(t *testing.T, data []byte) {
		input := validInput()
		limit := len(data)
		if limit > 200 {
			limit = 200
		}
		for index, value := range data[:limit] {
			event := gatewayEvent(index + 1)
			event.OccurredAt = testNow.Add(-time.Duration(value%70) * time.Second)
			event.SourceIP = []string{"198.51.100.9", "198.51.100.10"}[value%2]
			event.ServiceLabel = []string{"app", "other"}[(value/2)%2]
			event.StatusCode = []int{200, 401, 403}[(value/4)%3]
			event.SuspiciousPathID = defaultSuspiciousPathIDs()[int(value)%PathScanThreshold]
			if event.StatusCode == 401 || event.StatusCode == 403 {
				event.RouteLabel = DefaultLoginRouteLabel
				event.AuthenticationMatch = BindingVerified
			}
			input.GatewayEvents = append(input.GatewayEvents, event)
		}

		detector := NewDefault()
		first, firstErr := detector.Evaluate(input)
		second, secondErr := detector.Evaluate(input)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("same input changed error state: %v / %v", firstErr, secondErr)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("same input changed deterministic output")
		}
	})
}
