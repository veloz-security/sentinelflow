package demohistoryactivation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type fenceRow func(...any) error

func (row fenceRow) Scan(destination ...any) error { return row(destination...) }

type fenceDBStub struct {
	queries []string
	rows    []pgx.Row
}

func (db *fenceDBStub) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	db.queries = append(db.queries, query)
	if len(db.rows) == 0 {
		return fenceRow(func(...any) error { return pgx.ErrNoRows })
	}
	row := db.rows[0]
	db.rows = db.rows[1:]
	return row
}

func readyFenceRow(ready bool) pgx.Row {
	return fenceRow(func(destination ...any) error {
		*destination[0].(*bool) = ready
		return nil
	})
}

func TestAuthorityFencesUseCommittedPhaseBeforeSessionFinalizer(t *testing.T) {
	for name, run := range map[string]func(context.Context, FenceDB) error{
		"importer":  FenceImporter,
		"bootstrap": FenceBootstrap,
	} {
		t.Run(name, func(t *testing.T) {
			db := &fenceDBStub{rows: []pgx.Row{readyFenceRow(true), readyFenceRow(true)}}
			if err := run(t.Context(), db); err != nil {
				t.Fatal(err)
			}
			if len(db.queries) != 2 || !strings.Contains(db.queries[0], "fence_demo_history_") ||
				strings.Contains(db.queries[0], "finalize_") || !strings.Contains(db.queries[1], "finalize_") {
				t.Fatalf("unsafe phase order: %#v", db.queries)
			}
		})
	}
}

func TestAuthorityFencesFailClosedAndRedactDatabaseErrors(t *testing.T) {
	secret := "postgres-password-and-query-detail"
	for name, rows := range map[string][]pgx.Row{
		"phase one false": {readyFenceRow(false)},
		"phase one error": {fenceRow(func(...any) error { return errors.New(secret) })},
		"phase two false": {readyFenceRow(true), readyFenceRow(false)},
		"phase two error": {readyFenceRow(true), fenceRow(func(...any) error { return errors.New(secret) })},
	} {
		t.Run(name, func(t *testing.T) {
			db := &fenceDBStub{rows: rows}
			err := FenceBootstrap(t.Context(), db)
			if !errors.Is(err, ErrAuthorityFence) || strings.Contains(err.Error(), secret) {
				t.Fatalf("unsafe fence error: %v", err)
			}
			if strings.HasPrefix(name, "phase one") && len(db.queries) != 1 {
				t.Fatalf("phase two ran after failed phase one: %#v", db.queries)
			}
		})
	}
	//lint:ignore SA1012 Explicit nil-context rejection test.
	if err := FenceImporter(nil, &fenceDBStub{}); !errors.Is(err, ErrAuthorityFence) {
		t.Fatalf("nil context error=%v", err)
	}
}
