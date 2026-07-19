package detectionworker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/worker"
)

type prepareTestDB struct {
	tx  pgx.Tx
	err error
}

func (db prepareTestDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return db.tx, db.err
}

func (prepareTestDB) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected non-transactional query")
}

type prepareTestTx struct {
	pgx.Tx
	row       pgx.Row
	queryErr  error
	commitErr error
}

func (tx *prepareTestTx) QueryRow(context.Context, string, ...any) pgx.Row { return tx.row }

func (tx *prepareTestTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, tx.queryErr
}

func (tx *prepareTestTx) Commit(context.Context) error { return tx.commitErr }
func (*prepareTestTx) Rollback(context.Context) error  { return nil }

type prepareTestRow struct {
	status string
	raw    []byte
	err    error
}

func (row prepareTestRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != 2 {
		return errors.New("unexpected scan shape")
	}
	status, statusOK := dest[0].(*string)
	raw, rawOK := dest[1].(*[]byte)
	if !statusOK || !rawOK {
		return errors.New("unexpected scan destination")
	}
	*status = row.status
	*raw = append((*raw)[:0], row.raw...)
	return nil
}

func TestPrepareClassifiesTransactionConflictsAsRetryableAndRedacted(t *testing.T) {
	t.Parallel()
	job := prepareConflictJob()
	withoutCandidates := prepareDocumentJSON(t, job, nil)
	withCandidate := prepareDocumentJSON(t, job, []string{"203.0.113.20"})
	tests := []struct {
		name string
		db   prepareTestDB
	}{
		{
			name: "begin serialization",
			db:   prepareTestDB{err: &pgconn.PgError{Code: "40001", Message: "secret begin"}},
		},
		{
			name: "prepare deadlock",
			db: prepareTestDB{tx: &prepareTestTx{row: prepareTestRow{
				err: &pgconn.PgError{Code: "40P01", Message: "secret prepare"},
			}}},
		},
		{
			name: "event load serialization",
			db: prepareTestDB{tx: &prepareTestTx{
				row:      prepareTestRow{status: "prepared", raw: withCandidate},
				queryErr: &pgconn.PgError{Code: "40001", Message: "secret event"},
			}},
		},
		{
			name: "commit deadlock",
			db: prepareTestDB{tx: &prepareTestTx{
				row:       prepareTestRow{status: "prepared", raw: withoutCandidates},
				commitErr: &pgconn.PgError{Code: "40P01", Message: "secret commit"},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewPostgreSQLStore(test.db)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = store.Prepare(context.Background(), job)
			if !errors.Is(err, ErrRetryablePersistence) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func prepareConflictJob() worker.LeasedJob {
	return worker.LeasedJob{Job: worker.Job{
		JobID: "019f0000-0000-8000-8000-000000000001", Kind: worker.JobDetect,
		AggregateType: "ingest_batch", AggregateID: "019f0000-0000-8000-8000-000000000002",
		AggregateVersion: 1, Attempt: 1, MaxAttempts: 8,
	}, LeaseToken: "019f0000-0000-4000-8000-000000000003"}
}

func prepareDocumentJSON(t *testing.T, job worker.LeasedJob, candidates []string) []byte {
	t.Helper()
	at := time.Date(2026, 7, 19, 1, 2, 3, 456_000_000, time.UTC)
	raw, err := json.Marshal(prepareDocument{
		JobID: job.JobID, AggregateType: job.AggregateType, AggregateID: job.AggregateID,
		AggregateVersion: job.AggregateVersion, BatchID: job.AggregateID,
		EndpointKind: "gateway", ServiceLabel: "demo-app", EvaluatedAt: at,
		CandidateSourceIPs: candidates,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
