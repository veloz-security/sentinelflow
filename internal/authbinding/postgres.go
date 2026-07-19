package authbinding

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type commandTag interface {
	RowsAffected() int64
}

type row interface {
	Scan(...any) error
}

type rows interface {
	Close()
	Err() error
	Next() bool
	Scan(...any) error
}

type transaction interface {
	Query(context.Context, string, ...any) (rows, error)
	QueryRow(context.Context, string, ...any) row
	Exec(context.Context, string, ...any) (commandTag, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type transactionBeginner interface {
	Begin(context.Context) (transaction, error)
}

type pgxBeginner struct {
	db TransactionBeginner
}

func (p pgxBeginner) Begin(ctx context.Context) (transaction, error) {
	tx, err := p.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	return pgxTransaction{tx: tx}, nil
}

type pgxTransaction struct {
	tx pgx.Tx
}

func (p pgxTransaction) Query(ctx context.Context, sql string, args ...any) (rows, error) {
	return p.tx.Query(ctx, sql, args...)
}

func (p pgxTransaction) QueryRow(ctx context.Context, sql string, args ...any) row {
	return p.tx.QueryRow(ctx, sql, args...)
}

func (p pgxTransaction) Exec(ctx context.Context, sql string, args ...any) (commandTag, error) {
	return p.tx.Exec(ctx, sql, args...)
}

func (p pgxTransaction) Commit(ctx context.Context) error {
	return p.tx.Commit(ctx)
}

func (p pgxTransaction) Rollback(ctx context.Context) error {
	return p.tx.Rollback(ctx)
}
