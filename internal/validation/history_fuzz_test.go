package validation

import (
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/events"
)

func FuzzHistoricalImpactFailsClosed(f *testing.F) {
	f.Add("8.8.8.8", "failed", "verified", "trusted", int64(-60))
	f.Add("8.8.8.8", "succeeded", "pending", "trusted", int64(0))
	f.Add("not-an-ip", "failed", "verified", "trusted", int64(-86_401))
	f.Fuzz(func(t *testing.T, target, outcome, binding, trust string, offsetSeconds int64) {
		// Bound arbitrary duration arithmetic before constructing the typed row.
		offsetSeconds %= 172_801
		input := validHistoricalImpactInput()
		input.TargetIPv4 = target
		input.GatewayRecords = nil
		input.AuthRecords = []HistoricalAuthRecord{{
			EventID:        "019b0000-0000-7000-8000-0000000000f0",
			OccurredAt:     historyTestAt.Add(time.Duration(offsetSeconds) * time.Second),
			SourceIPv4:     target,
			Outcome:        events.AuthOutcome(outcome),
			TimestampTrust: detection.TimestampTrust(trust),
			Binding:        detection.BindingState(binding),
		}}
		result := EvaluateHistoricalImpact(input)
		if result.Allowed() {
			if target != "8.8.8.8" || outcome != "failed" || binding != "verified" || trust != "trusted" ||
				offsetSeconds < -int64(HistoricalImpactLookback/time.Second) || offsetSeconds > 0 {
				t.Fatalf("invalid fuzz input opened the gate: target=%q outcome=%q binding=%q trust=%q offset=%d",
					target, outcome, binding, trust, offsetSeconds)
			}
		}
		if len(result.CanonicalBytes()) == 0 || !validDigest(result.Digest()) {
			t.Fatal("every fuzz decision must remain typed and digestible")
		}
	})
}
