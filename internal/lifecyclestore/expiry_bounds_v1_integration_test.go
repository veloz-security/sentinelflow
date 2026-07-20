package lifecyclestore

import (
	"testing"
	"time"
)

// These test-local bounds freeze the lifecycle interpretation that the store
// must apply once execution-result-v2 persistence is available. nft's JSON
// "expires" value is an integer-second observation, so it is not an exact
// expiry instant. The executor-signed readback bracket makes the safe range:
//
//	lower = readback_started_at + remaining_ttl_seconds
//	upper = readback_completed_at + remaining_ttl_seconds + 1 second
//
// The extra upper-bound second covers the integer projection. An action must
// never be called expired or late-active before upper; an absent observation
// must never be called missing-early unless it completed before lower.
//
// This pure contract test complements the migration-owned database integration
// test. It never substitutes an old v1 result timestamp for readback time.
type expiryBoundsV2 struct {
	lower time.Time
	upper time.Time
}

func deriveExpiryBoundsV2(readbackStarted, readbackCompleted time.Time, remainingTTLSeconds uint64) (expiryBoundsV2, bool) {
	if readbackStarted.IsZero() || readbackCompleted.IsZero() ||
		readbackCompleted.Before(readbackStarted) || remainingTTLSeconds == 0 ||
		remainingTTLSeconds > 86400 {
		return expiryBoundsV2{}, false
	}

	remaining := time.Duration(remainingTTLSeconds) * time.Second
	return expiryBoundsV2{
		lower: readbackStarted.Add(remaining),
		upper: readbackCompleted.Add(remaining + time.Second),
	}, true
}

type expiryObservationV2 string

const (
	expiryObservationActive        expiryObservationV2 = "active"
	expiryObservationExpired       expiryObservationV2 = "expired"
	expiryObservationMissingEarly  expiryObservationV2 = "missing_early"
	expiryObservationIndeterminate expiryObservationV2 = "indeterminate"
	expiryObservationLateActive    expiryObservationV2 = "late_active"
)

func classifyExpiryObservationV2(readbackState string, readbackStarted, readbackCompleted time.Time, bounds expiryBoundsV2) expiryObservationV2 {
	if readbackStarted.IsZero() || readbackCompleted.IsZero() ||
		readbackCompleted.Before(readbackStarted) || bounds.lower.IsZero() || bounds.upper.IsZero() ||
		bounds.upper.Before(bounds.lower) {
		return expiryObservationIndeterminate
	}

	switch readbackState {
	case "active":
		if !readbackStarted.Before(bounds.upper) {
			return expiryObservationLateActive
		}
		return expiryObservationActive
	case "absent":
		if !readbackStarted.Before(bounds.upper) {
			return expiryObservationExpired
		}
		if readbackCompleted.Before(bounds.lower) {
			return expiryObservationMissingEarly
		}
		return expiryObservationIndeterminate
	default:
		return expiryObservationIndeterminate
	}
}

func TestExpiryBoundsV2UseSignedReadbackBracketAndIntegerProjectionGuard(t *testing.T) {
	t.Parallel()
	readbackStarted := time.Date(2026, time.July, 20, 12, 0, 0, 100_000_000, time.UTC)
	readbackCompleted := readbackStarted.Add(200 * time.Millisecond)
	bounds, ok := deriveExpiryBoundsV2(readbackStarted, readbackCompleted, 59)
	if !ok {
		t.Fatal("valid signed readback bracket was rejected")
	}

	if want := time.Date(2026, time.July, 20, 12, 0, 59, 100_000_000, time.UTC); !bounds.lower.Equal(want) {
		t.Fatalf("lower = %s, want %s", bounds.lower, want)
	}
	if want := time.Date(2026, time.July, 20, 12, 1, 0, 300_000_000, time.UTC); !bounds.upper.Equal(want) {
		t.Fatalf("upper = %s, want %s", bounds.upper, want)
	}
	if !bounds.upper.After(bounds.lower) {
		t.Fatalf("unsafe expiry interval: lower=%s upper=%s", bounds.lower, bounds.upper)
	}
}

func TestExpiryBoundsV2ClassifiesOnlySafeAbsentAndLateActiveEdges(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	bounds, ok := deriveExpiryBoundsV2(base, base.Add(200*time.Millisecond), 60)
	if !ok {
		t.Fatal("valid readback bracket was rejected")
	}

	tests := []struct {
		name      string
		state     string
		started   time.Time
		completed time.Time
		want      expiryObservationV2
	}{
		{
			name:  "absent before lower is missing early",
			state: "absent", started: base.Add(30 * time.Second), completed: base.Add(30*time.Second + time.Millisecond),
			want: expiryObservationMissingEarly,
		},
		{
			name:  "absent ending exactly at lower is indeterminate",
			state: "absent", started: bounds.lower.Add(-time.Millisecond), completed: bounds.lower,
			want: expiryObservationIndeterminate,
		},
		{
			name:  "absent straddling lower is indeterminate",
			state: "absent", started: bounds.lower.Add(-time.Millisecond), completed: bounds.lower.Add(time.Millisecond),
			want: expiryObservationIndeterminate,
		},
		{
			name:  "absent at upper start is expired",
			state: "absent", started: bounds.upper, completed: bounds.upper.Add(time.Millisecond),
			want: expiryObservationExpired,
		},
		{
			name:  "active beginning before upper remains active even if it completes after",
			state: "active", started: bounds.upper.Add(-time.Millisecond), completed: bounds.upper.Add(time.Millisecond),
			want: expiryObservationActive,
		},
		{
			name:  "active at upper start is late active",
			state: "active", started: bounds.upper, completed: bounds.upper.Add(time.Millisecond),
			want: expiryObservationLateActive,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyExpiryObservationV2(test.state, test.started, test.completed, bounds); got != test.want {
				t.Fatalf("classification = %q, want %q", got, test.want)
			}
		})
	}
}

func TestExpiryBoundsV2RejectsMissingOrUntrustedReadbackEvidence(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		started   time.Time
		completed time.Time
		ttl       uint64
	}{
		{"zero start", time.Time{}, base, 60},
		{"zero completion", base, time.Time{}, 60},
		{"reversed bracket", base.Add(time.Millisecond), base, 60},
		{"zero ttl", base, base, 0},
		{"ttl above contract", base, base, 86401},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := deriveExpiryBoundsV2(test.started, test.completed, test.ttl); ok {
				t.Fatal("untrusted readback evidence produced lifecycle bounds")
			}
		})
	}
}
