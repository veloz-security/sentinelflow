package worker

import (
	"testing"
	"time"
)

func TestBackoffDelayIsExponentialJitteredAndBounded(t *testing.T) {
	t.Parallel()

	policy := BackoffPolicy{BaseDelay: 8 * time.Second, MaxDelay: 30 * time.Second}
	tests := []struct {
		attempt int32
		jitter  uint64
		want    time.Duration
	}{
		{attempt: 1, jitter: 0, want: 4 * time.Second},
		{attempt: 2, jitter: 0, want: 8 * time.Second},
		{attempt: 3, jitter: 0, want: 15 * time.Second},
		{attempt: 20, jitter: 0, want: 15 * time.Second},
		{attempt: 20, jitter: ^uint64(0), want: 15*time.Second + time.Duration(^uint64(0)%uint64(15*time.Second+1))},
	}
	for _, test := range tests {
		got, err := policy.Delay(test.attempt, test.jitter)
		if err != nil {
			t.Fatalf("Delay(%d): %v", test.attempt, err)
		}
		if got != test.want || got > policy.MaxDelay {
			t.Fatalf("Delay(%d, %d) = %v, want %v", test.attempt, test.jitter, got, test.want)
		}
	}
}

func TestBackoffRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	if _, err := (BackoffPolicy{}).Delay(1, 0); err == nil {
		t.Fatal("invalid policy was accepted")
	}
	if _, err := (BackoffPolicy{BaseDelay: time.Second, MaxDelay: time.Second}).Delay(0, 0); err == nil {
		t.Fatal("zero attempt was accepted")
	}
}
