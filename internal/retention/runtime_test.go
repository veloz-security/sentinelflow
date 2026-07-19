package retention

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type runnerFunc struct {
	now time.Time
	run func(context.Context, string, time.Time, int) (Result, error)
}

func (f runnerFunc) CurrentTime(context.Context) (time.Time, error) { return f.now, nil }
func (f runnerFunc) Run(ctx context.Context, id string, at time.Time, rows int) (Result, error) {
	return f.run(ctx, id, at, rows)
}

func TestRuntimeUsesFreshDigestBoundIdentityAndUTCClock(t *testing.T) {
	t.Parallel()
	runID := "019f0000-0000-4000-8000-000000000023"
	local := time.Date(2026, 7, 18, 11, 12, 13, 0, time.FixedZone("KST", 9*60*60))
	runtime, err := newRuntime(runnerFunc{now: local.UTC(), run: func(_ context.Context, id string, at time.Time, rows int) (Result, error) {
		if id != runID || !at.Equal(local) || at.Location() != time.UTC || rows != 1000 {
			t.Fatalf("runtime inputs id=%s at=%s rows=%d", id, at, rows)
		}
		return Result{RunID: id}, nil
	}}, 1000, func() (string, error) { return runID, nil })
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.RunOnce(context.Background())
	if err != nil || result.RunID != runID {
		t.Fatalf("RunOnce result=%+v err=%v", result, err)
	}
}

func TestRuntimeFailsClosedAndPreservesCancellation(t *testing.T) {
	t.Parallel()
	runID := "019f0000-0000-4000-8000-000000000023"
	secret := "database-secret"
	runtime, err := newRuntime(runnerFunc{now: time.Now(), run: func(context.Context, string, time.Time, int) (Result, error) {
		return Result{}, errors.New(secret)
	}}, 1, func() (string, error) { return runID, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RunOnce(context.Background()); !errors.Is(err, ErrRuntime) || err.Error() == secret {
		t.Fatalf("unsafe runtime error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runtime.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestRuntimePreservesAuditedStaleLiveResult(t *testing.T) {
	t.Parallel()
	runID := "019f0000-0000-4000-8000-000000000023"
	want := Result{
		RunID:        runID,
		Outcome:      "failed",
		FailureCode:  "stale_live_state",
		AnomalyCount: 1,
		RunDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CompletedAt:  time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC),
	}
	runtime, err := newRuntime(runnerFunc{now: time.Now(), run: func(context.Context, string, time.Time, int) (Result, error) {
		return want, ErrStaleLiveState
	}}, 1, func() (string, error) { return runID, nil })
	if err != nil {
		t.Fatal(err)
	}
	got, err := runtime.RunOnce(context.Background())
	if !errors.Is(err, ErrStaleLiveState) || got != want {
		t.Fatalf("stale live result=%+v err=%v", got, err)
	}
}

func TestRuntimeRejectsMismatchedStaleLiveResultIdentity(t *testing.T) {
	t.Parallel()
	runID := "019f0000-0000-4000-8000-000000000023"
	runtime, err := newRuntime(runnerFunc{now: time.Now(), run: func(context.Context, string, time.Time, int) (Result, error) {
		return Result{RunID: "019f0000-0000-4000-8000-000000000024"}, ErrStaleLiveState
	}}, 1, func() (string, error) { return runID, nil })
	if err != nil {
		t.Fatal(err)
	}
	got, err := runtime.RunOnce(context.Background())
	if !errors.Is(err, ErrRuntime) || errors.Is(err, ErrStaleLiveState) || got != (Result{}) {
		t.Fatalf("mismatched stale live result=%+v err=%v", got, err)
	}
}

func TestRuntimeSerializesConcurrentRuns(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	active, maximum := 0, 0
	release := make(chan struct{})
	entered := make(chan struct{}, 2)
	ids := []string{
		"019f0000-0000-4000-8000-000000000023",
		"019f0000-0000-4000-8000-000000000024",
	}
	idIndex := 0
	runtime, err := newRuntime(runnerFunc{now: time.Now(), run: func(_ context.Context, id string, _ time.Time, _ int) (Result, error) {
		mu.Lock()
		active++
		if active > maximum {
			maximum = active
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return Result{RunID: id}, nil
	}}, 1, func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		id := ids[idIndex]
		idIndex++
		return id, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	errorsChannel := make(chan error, 2)
	go func() { _, err := runtime.RunOnce(context.Background()); errorsChannel <- err }()
	go func() { _, err := runtime.RunOnce(context.Background()); errorsChannel <- err }()
	<-entered
	select {
	case <-entered:
		t.Fatal("concurrent run entered before the first completed")
	case <-time.After(25 * time.Millisecond):
	}
	release <- struct{}{}
	<-entered
	release <- struct{}{}
	for range 2 {
		if err := <-errorsChannel; err != nil {
			t.Fatal(err)
		}
	}
	if maximum != 1 {
		t.Fatalf("maximum concurrent runs=%d", maximum)
	}
}

func TestRandomUUIDIsCanonicalVersionFour(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 100)
	for range 100 {
		value, err := randomUUID()
		if err != nil || !uuidPattern.MatchString(value) || value[14] != '4' ||
			(value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b') {
			t.Fatalf("invalid UUID %q err=%v", value, err)
		}
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate UUID %q", value)
		}
		seen[value] = struct{}{}
	}
}
