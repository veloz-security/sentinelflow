package retention

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type rowFunc func(...any) error

func (f rowFunc) Scan(destinations ...any) error { return f(destinations...) }

type queryRecorder struct {
	query string
	args  []any
	row   pgx.Row
}

func (q *queryRecorder) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	q.query, q.args = query, arguments
	return q.row
}

func TestStoreCallsOnlyRetentionFunctionAndValidatesAggregateResult(t *testing.T) {
	t.Parallel()
	runID := "019f0000-0000-4000-8000-000000000023"
	asOf := time.Date(2026, 7, 18, 2, 3, 4, 0, time.FixedZone("KST", 9*60*60))
	completed := asOf.Add(time.Second).UTC()
	recorder := &queryRecorder{row: rowFunc(func(destinations ...any) error {
		*destinations[0].(*string) = runID
		*destinations[1].(*bool) = false
		*destinations[2].(*int64) = 7
		*destinations[3].(*string) = "succeeded"
		*destinations[4].(*string) = ""
		*destinations[5].(*int64) = 0
		*destinations[6].(*int64) = 30
		*destinations[7].(*int64) = 4
		*destinations[8].(*int64) = 90
		*destinations[9].(*string) = "sha256:" + strings.Repeat("a", 64)
		*destinations[10].(*time.Time) = completed
		return nil
	})}
	store, err := NewStore(recorder)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Run(context.Background(), runID, asOf, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(recorder.query, "sentinelflow.run_retention_000023") ||
		strings.Contains(strings.ToUpper(recorder.query), "DELETE ") || len(recorder.args) != 3 ||
		result.EventEvidenceDeleted != 7 || result.ControlPlaneDeleted != 30 ||
		result.TransientDeleted != 4 || result.AuditDeleted != 90 ||
		!result.CompletedAt.Equal(completed) {
		t.Fatalf("unexpected call/result: query=%q args=%v result=%+v", recorder.query, recorder.args, result)
	}
}

func TestStoreFailsClosedWithoutLeakingPersistenceErrors(t *testing.T) {
	t.Parallel()
	runID := "019f0000-0000-4000-8000-000000000023"
	secret := "retention-secret"
	recorder := &queryRecorder{row: rowFunc(func(...any) error { return errors.New(secret) })}
	store, err := NewStore(recorder)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Run(context.Background(), runID, time.Now(), 1)
	if !errors.Is(err, ErrPersistence) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe persistence error: %v", err)
	}

	for _, mutate := range []func([]any){
		func(values []any) { *values[0].(*string) = "019f0000-0000-4000-8000-000000000099" },
		func(values []any) { *values[2].(*int64) = -1 },
		func(values []any) { *values[6].(*int64) = 1 },
		func(values []any) { *values[3].(*string) = "unknown" },
		func(values []any) { *values[5].(*int64) = 1 },
		func(values []any) { *values[9].(*string) = "not-a-digest" },
		func(values []any) { *values[10].(*time.Time) = time.Time{} },
	} {
		recorder.row = validRow(runID, mutate)
		if _, err := store.Run(context.Background(), runID, time.Now(), 1); !errors.Is(err, ErrInvariant) {
			t.Fatalf("invalid result accepted: %v", err)
		}
	}
}

func TestStoreReturnsAuditedStaleLiveFailureAndRejectsUnsafeFailureShapes(t *testing.T) {
	t.Parallel()
	runID := "019f0000-0000-4000-8000-000000000023"
	recorder := &queryRecorder{row: validRow(runID, func(values []any) {
		*values[2].(*int64) = 0
		*values[3].(*string) = "failed"
		*values[4].(*string) = "stale_live_state"
		*values[5].(*int64) = 1
		*values[6].(*int64) = 0
		*values[7].(*int64) = 0
		*values[8].(*int64) = 0
	})}
	store, err := NewStore(recorder)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Run(context.Background(), runID, time.Now(), 1)
	if !errors.Is(err, ErrStaleLiveState) || result.Outcome != "failed" ||
		result.FailureCode != "stale_live_state" || result.AnomalyCount != 1 {
		t.Fatalf("stale live result=%+v err=%v", result, err)
	}

	for _, mutate := range []func([]any){
		func(values []any) { *values[4].(*string) = "secret_detail" },
		func(values []any) { *values[5].(*int64) = 2 },
		func(values []any) { *values[2].(*int64) = 1 },
	} {
		recorder.row = validRow(runID, func(values []any) {
			*values[2].(*int64) = 0
			*values[3].(*string) = "failed"
			*values[4].(*string) = "stale_live_state"
			*values[5].(*int64) = 1
			*values[6].(*int64) = 0
			*values[7].(*int64) = 0
			*values[8].(*int64) = 0
			mutate(values)
		})
		if _, err := store.Run(context.Background(), runID, time.Now(), 1); !errors.Is(err, ErrInvariant) {
			t.Fatalf("unsafe failed result accepted: %v", err)
		}
	}
}

func validRow(runID string, mutate func([]any)) pgx.Row {
	return rowFunc(func(values ...any) error {
		*values[0].(*string) = runID
		*values[1].(*bool) = false
		*values[2].(*int64) = 1
		*values[3].(*string) = "succeeded"
		*values[4].(*string) = ""
		*values[5].(*int64) = 0
		*values[6].(*int64) = 0
		*values[7].(*int64) = 0
		*values[8].(*int64) = 0
		*values[9].(*string) = "sha256:" + strings.Repeat("a", 64)
		*values[10].(*time.Time) = time.Now()
		mutate(values)
		return nil
	})
}
