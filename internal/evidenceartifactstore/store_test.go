package evidenceartifactstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/jackc/pgx/v5"
)

const (
	testSnapshotID = "019b0000-0000-7000-8000-00000000a001"
	testIncidentID = "019b0000-0000-7000-8000-00000000a002"
	testSignalID   = "019b0000-0000-7000-8000-00000000a003"
	testEventID    = "019b0000-0000-7000-8000-00000000a004"
	testEventRowID = "019b0000-0000-7000-8000-00000000a005"
	testDigest     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var testNow = time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC)

func TestInsertUsesOnlyAtomicCoordinatorAndAcceptsExactReplay(t *testing.T) {
	t.Parallel()
	request := validRequest(t)
	db := &stub{rows: []pgx.Row{
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = testSnapshotID
			*dest[1].(*string) = request.Evidence.Digest()
			*dest[2].(*bool) = true
			return nil
		}),
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = testSnapshotID
			*dest[1].(*string) = request.Evidence.Digest()
			*dest[2].(*bool) = false
			return nil
		}),
	}}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := store.Insert(context.Background(), request)
	if err != nil || !inserted {
		t.Fatalf("inserted=%v err=%v", inserted, err)
	}
	inserted, err = store.Insert(context.Background(), request)
	if err != nil || inserted {
		t.Fatalf("replay inserted=%v err=%v", inserted, err)
	}
	if len(db.queries) != 2 || !strings.Contains(db.queries[0], "insert_exact_evidence_snapshot") ||
		strings.Contains(db.queries[0], "INSERT INTO") {
		t.Fatalf("queries=%q", db.queries)
	}
	request.Signals[0].EvidenceDigest = strings.Replace(testDigest, "a", "b", 1)
	if _, err := store.Insert(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("tamper err=%v", err)
	}
}

func TestInsertRejectsMissingTamperedAndAmbiguousMembership(t *testing.T) {
	t.Parallel()
	for _, mutate := range []func(*InsertRequest){
		func(request *InsertRequest) { request.Evidence = validation.CheckedEvidenceSnapshot{} },
		func(request *InsertRequest) { request.Events[0].EventID = testEventRowID },
		func(request *InsertRequest) { request.Signals[0].ExpandedEventCount = 2 },
		func(request *InsertRequest) { request.ExpiresAt = testNow },
	} {
		request := validRequest(t)
		mutate(&request)
		store, _ := NewPostgreSQLStore(&stub{})
		if _, err := store.Insert(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("err=%v", err)
		}
	}
	store, _ := NewPostgreSQLStore(&stub{rows: []pgx.Row{rowFunc(func(...any) error {
		return errors.New("password=secret")
	})}})
	if _, err := store.Insert(context.Background(), validRequest(t)); !errors.Is(err, ErrPersistence) ||
		strings.Contains(err.Error(), "secret") {
		t.Fatalf("err=%v", err)
	}
}

func validRequest(t *testing.T) InsertRequest {
	t.Helper()
	checked, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:    testSnapshotID, IncidentID: testIncidentID, IncidentVersion: 1,
		SourceIPv4: "8.8.8.8", ServiceLabel: "gateway",
		WindowStart: testNow.Add(-time.Minute), WindowEnd: testNow,
		SourceHealthDigest: testDigest, EventIDs: []string{testEventID},
		SignalIDs: []string{testSignalID}, CreatedAt: testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return InsertRequest{
		Evidence: checked, SourceHealthStatus: validation.SourceHealthComplete,
		ExpiresAt: testNow.Add(24 * time.Hour),
		Signals:   []SignalRow{{testSignalID, testDigest, 1}},
		Events:    []EventRow{{testEventRowID, testSignalID, EventGateway, testEventID, testNow}},
	}
}

type rowFunc func(...any) error

func (row rowFunc) Scan(dest ...any) error { return row(dest...) }

type stub struct {
	queries []string
	args    [][]any
	rows    []pgx.Row
}

func (s *stub) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	s.queries = append(s.queries, query)
	s.args = append(s.args, append([]any(nil), args...))
	if len(s.queries) > len(s.rows) {
		return rowFunc(func(...any) error { return pgx.ErrNoRows })
	}
	return s.rows[len(s.queries)-1]
}
