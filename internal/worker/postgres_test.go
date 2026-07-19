package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPostgreSQLStoreLeasesOnlyThroughSecurityDefinerFunction(t *testing.T) {
	t.Parallel()

	now := testTime()
	request := LeaseRequest{
		Now:            now,
		LeaseToken:     testTokenOne,
		LeaseOwner:     "worker-one",
		LeaseExpiresAt: now.Add(MaxLeaseDuration),
	}
	db := &queryStub{row: scanRow(func(dest ...any) error {
		if len(dest) != 13 {
			t.Fatalf("scan destination count = %d", len(dest))
		}
		*dest[0].(*string) = testJobOne
		*dest[1].(*string) = string(JobDetect)
		*dest[2].(*string) = "incident"
		*dest[3].(*string) = testAggregate
		*dest[4].(*int32) = 1
		*dest[5].(*string) = "leased"
		*dest[6].(*time.Time) = now
		*dest[7].(*string) = testTokenOne
		*dest[8].(*string) = "worker-one"
		*dest[9].(*time.Time) = now
		*dest[10].(*time.Time) = now.Add(MaxLeaseDuration)
		*dest[11].(*int32) = 1
		*dest[12].(*int32) = 8
		return nil
	})}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatalf("NewPostgreSQLStore: %v", err)
	}

	job, found, err := store.Lease(context.Background(), request)
	if err != nil || !found {
		t.Fatalf("Lease found=%v err=%v", found, err)
	}
	if job.JobID != testJobOne || job.Kind != JobDetect || job.LeaseToken != testTokenOne {
		t.Fatalf("unexpected job: %+v", job)
	}
	query, args, calls := db.snapshot()
	if calls != 1 || !strings.Contains(query, "sentinelflow.lease_worker_outbox_job") ||
		strings.Contains(query, "FROM sentinelflow.outbox_jobs") {
		t.Fatalf("unsafe lease query (%d calls): %s", calls, query)
	}
	if len(args) != 4 || args[1] != testTokenOne || args[2] != "worker-one" {
		t.Fatalf("unexpected lease arguments: %#v", args)
	}
}

func TestPostgreSQLStoreFinishUsesFencedFunctionAndNullSuccessEvidence(t *testing.T) {
	t.Parallel()

	now := testTime()
	db := &queryStub{row: scanRow(func(dest ...any) error {
		*dest[0].(*string) = testJobOne
		*dest[1].(*string) = string(FinishCompleted)
		return nil
	})}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	finished, err := store.Finish(context.Background(), FinishRequest{
		State: FinishCompleted, Now: now, JobID: testJobOne, LeaseToken: testTokenOne,
	})
	if err != nil || !finished {
		t.Fatalf("Finish finished=%v err=%v", finished, err)
	}
	query, args, calls := db.snapshot()
	if calls != 1 || !strings.Contains(query, "sentinelflow.finish_worker_outbox_job") ||
		strings.Contains(query, "UPDATE sentinelflow.outbox_jobs") {
		t.Fatalf("unsafe finish query (%d calls): %s", calls, query)
	}
	if len(args) != 7 || args[0] != string(FinishCompleted) ||
		args[1] != nil || args[2] != nil || args[3] != nil ||
		args[5] != testJobOne || args[6] != testTokenOne {
		t.Fatalf("unexpected finish arguments: %#v", args)
	}
}

func TestPostgreSQLStoreTreatsNoFinishRowAsLeaseLossSignal(t *testing.T) {
	t.Parallel()

	db := &queryStub{row: scanRow(func(...any) error { return pgx.ErrNoRows })}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	finished, err := store.Finish(context.Background(), FinishRequest{
		State: FinishCompleted, Now: testTime(), JobID: testJobOne, LeaseToken: testTokenOne,
	})
	if err != nil || finished {
		t.Fatalf("Finish finished=%v err=%v", finished, err)
	}
}

func TestPostgreSQLStoreRejectsMismatchedFinishRow(t *testing.T) {
	t.Parallel()

	db := &queryStub{row: scanRow(func(dest ...any) error {
		*dest[0].(*string) = testJobTwo
		*dest[1].(*string) = string(FinishCompleted)
		return nil
	})}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Finish(context.Background(), FinishRequest{
		State: FinishCompleted, Now: testTime(), JobID: testJobOne, LeaseToken: testTokenOne,
	})
	if !errors.Is(err, ErrInvalidStoreRow) {
		t.Fatalf("error = %v, want ErrInvalidStoreRow", err)
	}
}

func TestPostgreSQLStoreValidatesLeaseBeforeQuery(t *testing.T) {
	t.Parallel()

	now := testTime()
	db := &queryStub{row: scanRow(func(...any) error {
		t.Fatal("invalid lease reached PostgreSQL")
		return nil
	})}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]LeaseRequest{
		"over 60 seconds": {
			Now: now, LeaseToken: testTokenOne, LeaseOwner: "worker-one",
			LeaseExpiresAt: now.Add(MaxLeaseDuration + time.Nanosecond),
		},
		"non v4 token": {
			Now: now, LeaseToken: testJobOne, LeaseOwner: "worker-one",
			LeaseExpiresAt: now.Add(time.Second),
		},
		"invalid owner": {
			Now: now, LeaseToken: testTokenOne, LeaseOwner: "Worker One",
			LeaseExpiresAt: now.Add(time.Second),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := store.Lease(context.Background(), request); err == nil {
				t.Fatal("invalid lease request was accepted")
			}
		})
	}
	if _, _, calls := db.snapshot(); calls != 0 {
		t.Fatalf("invalid requests issued %d queries", calls)
	}
}

func TestPostgreSQLStoreValidatesRetryEvidenceBeforeQuery(t *testing.T) {
	t.Parallel()

	db := &queryStub{row: scanRow(func(...any) error {
		t.Fatal("invalid finish reached PostgreSQL")
		return nil
	})}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := testTime()
	retryAt := now.Add(-time.Nanosecond)
	_, err = store.Finish(context.Background(), FinishRequest{
		State: FinishRetry, RetryAt: &retryAt,
		ErrorCode: "BAD CODE", ErrorDigest: "not-a-digest",
		Now: now, JobID: testJobOne, LeaseToken: testTokenOne,
	})
	if err == nil {
		t.Fatal("invalid retry evidence was accepted")
	}
	if _, _, calls := db.snapshot(); calls != 0 {
		t.Fatalf("invalid finish issued %d queries", calls)
	}
}

type scanRow func(...any) error

func (r scanRow) Scan(dest ...any) error { return r(dest...) }

type queryStub struct {
	query string
	args  []any
	row   pgx.Row
	calls int
}

func (s *queryStub) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	s.query = query
	s.args = append([]any(nil), args...)
	s.calls++
	return s.row
}

func (s *queryStub) snapshot() (string, []any, int) {
	return s.query, append([]any(nil), s.args...), s.calls
}
