package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/api"
	"github.com/devwooops/sentinelflow/internal/ingestion"
)

const (
	replayCleanupLimit = 128
	rollbackTimeout    = 5 * time.Second
)

// PostgreSQLBatchStore persists one authenticated batch and all of its effects
// in a single PostgreSQL transaction. It never logs or stores transport
// signatures, raw nonces, keys, or raw request bodies.
type PostgreSQLBatchStore struct {
	db TransactionBeginner
}

var _ api.BatchStore = (*PostgreSQLBatchStore)(nil)

// TransactionBeginner is the minimal pgx pool or connection contract required
// by PostgreSQLBatchStore.
type TransactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func NewPostgreSQLBatchStore(db TransactionBeginner) (*PostgreSQLBatchStore, error) {
	if db == nil {
		return nil, errors.New("repository: PostgreSQL transaction source is required")
	}
	return &PostgreSQLBatchStore{db: db}, nil
}

func (s *PostgreSQLBatchStore) StoreBatch(
	ctx context.Context,
	endpointPath string,
	authenticated ingestion.AuthenticatedBatch,
	receivedAt time.Time,
) (api.StoreOutcome, error) {
	prepared, err := prepareBatch(endpointPath, authenticated, receivedAt)
	if err != nil {
		return "", err
	}

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return "", unavailable(ctx, err)
	}
	committed := false
	defer func() {
		if !committed {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
		}
	}()

	if _, err = tx.Exec(ctx, pruneReplayNoncesSQL, prepared.receivedAt, replayCleanupLimit); err != nil {
		return "", unavailable(ctx, err)
	}
	var nonceExpiresAt time.Time
	if err = tx.QueryRow(ctx, consumeReplayNonceSQL,
		prepared.authenticated.Batch.SenderID,
		prepared.endpointKind,
		endpointPath,
		prepared.nonceDigest,
		prepared.authenticated.AuthenticatedAt,
	).Scan(&nonceExpiresAt); err != nil {
		if isConstraint(err, "ingest_replay_nonces_pkey") {
			return "", rejected(errors.New("authenticated replay nonce was already consumed"))
		}
		return "", classifyWriteError(ctx, err, false)
	}
	expectedNonceExpiry := time.UnixMicro(
		prepared.authenticated.AuthenticatedAt.Add(5 * time.Minute).UnixMicro(),
	)
	if !nonceExpiresAt.Equal(expectedNonceExpiry) {
		return "", unavailable(ctx, errors.New("unexpected replay nonce expiry"))
	}

	batch := prepared.authenticated.Batch
	// API role cannot mutate or row-lock the receiver-owned checkpoint. A
	// transaction-scoped advisory lock serializes all receipts for this bound
	// sender/endpoint before duplicate classification; the SECURITY DEFINER
	// sequence function performs the authoritative checkpoint row lock later.
	if err = lockSenderIngest(ctx, tx, batch.SenderID, prepared.endpointKind); err != nil {
		return "", unavailable(ctx, err)
	}
	if _, err = tx.Exec(ctx, ensureSenderCheckpointSQL,
		batch.SenderID, prepared.endpointKind, batch.SenderEpoch, prepared.receivedAt,
	); err != nil {
		return "", classifyWriteError(ctx, err, false)
	}

	existing, found, err := getExistingBatch(ctx, tx, batch.SenderID, batch.BatchID)
	if err != nil {
		return "", unavailable(ctx, err)
	}
	if found {
		if !existing.matches(prepared) {
			return "", fmt.Errorf("%w: existing batch identity differs", api.ErrBatchConflict)
		}
		if err = tx.Commit(ctx); err != nil {
			return "", unavailable(ctx, err)
		}
		committed = true
		return api.StoreDuplicate, nil
	}

	if _, err = tx.Exec(ctx, insertIngestBatchSQL,
		batch.SenderID,
		batch.SenderEpoch,
		batch.BatchID,
		int64(batch.Sequence),
		prepared.endpointKind,
		stringOrNil(prepared.authenticated.KeyID),
		prepared.authenticated.BodyDigest,
		prepared.authenticated.RawBodySize,
		len(batch.Records),
		batch.SentAt.Time(),
		prepared.receivedAt,
	); err != nil {
		return "", classifyWriteError(ctx, err, true)
	}

	// Sequence registration must precede record persistence. A coverage marker
	// is admissible only after the receiver has made any gap opened by this
	// batch visible in the same transaction.
	var sequenceDisposition string
	if err = tx.QueryRow(ctx, registerIngestSequenceSQL,
		batch.SenderID,
		prepared.endpointKind,
		batch.SenderEpoch,
		int64(batch.Sequence),
		batch.BatchID,
		prepared.authenticated.BodyDigest,
		prepared.receivedAt,
	).Scan(&sequenceDisposition); err != nil {
		return "", classifyWriteError(ctx, err, true)
	}
	if !validSequenceDisposition(sequenceDisposition) {
		return "", unavailable(ctx, errors.New("unknown ingest sequence disposition"))
	}

	for index := range batch.Records {
		if err = insertRecord(ctx, tx, prepared, batch.Records[index], index+1); err != nil {
			return "", classifyWriteError(ctx, err, false)
		}
	}

	outbox := batchOutboxIdentity(batch)
	var storedJobID string
	if err = tx.QueryRow(ctx, insertOutboxSQL,
		batch.SenderID, batch.BatchID, prepared.authenticated.BodyDigest,
		outbox.jobID, outbox.idempotencyKey,
	).Scan(&storedJobID); err != nil {
		return "", classifyWriteError(ctx, err, false)
	}
	if storedJobID != outbox.jobID {
		return "", unavailable(ctx, errors.New("unexpected ingest outbox identity"))
	}

	if err = resolveAuthenticatedGapLosses(ctx, tx, prepared); err != nil {
		return "", classifyWriteError(ctx, err, false)
	}
	if _, err = tx.Exec(ctx, forceDeferredConstraintsSQL); err != nil {
		return "", classifyWriteError(ctx, err, false)
	}

	if err = tx.Commit(ctx); err != nil {
		return "", classifyWriteError(ctx, err, false)
	}
	committed = true
	return api.StoreAccepted, nil
}

type existingBatch struct {
	senderEpoch  string
	sequence     int64
	endpointKind string
	authKeyID    *string
	bodyDigest   string
	rawBodySize  int32
	recordCount  int16
	sentAt       time.Time
}

func getExistingBatch(ctx context.Context, tx pgx.Tx, senderID, batchID string) (existingBatch, bool, error) {
	var existing existingBatch
	err := tx.QueryRow(ctx, getBatchBySenderAndIDSQL, senderID, batchID).Scan(
		&existing.senderEpoch,
		&existing.sequence,
		&existing.endpointKind,
		&existing.authKeyID,
		&existing.bodyDigest,
		&existing.rawBodySize,
		&existing.recordCount,
		&existing.sentAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return existingBatch{}, false, nil
	}
	return existing, err == nil, err
}

func (e existingBatch) matches(prepared preparedBatch) bool {
	batch := prepared.authenticated.Batch
	return e.senderEpoch == batch.SenderEpoch &&
		e.sequence == int64(batch.Sequence) &&
		e.endpointKind == prepared.endpointKind &&
		optionalStringEqual(e.authKeyID, prepared.authenticated.KeyID) &&
		e.bodyDigest == prepared.authenticated.BodyDigest &&
		e.rawBodySize == int32(prepared.authenticated.RawBodySize) &&
		e.recordCount == int16(len(batch.Records)) &&
		e.sentAt.Equal(time.UnixMicro(batch.SentAt.Time().UnixMicro()))
}

func optionalStringEqual(stored *string, presented string) bool {
	if presented == "" {
		return stored == nil
	}
	return stored != nil && *stored == presented
}

func stringOrNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func isConstraint(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.ConstraintName == constraint
}

func classifyWriteError(ctx context.Context, err error, batchIdentity bool) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return api.ErrStoreUnavailable
	}
	if pgErr.Code == "23505" {
		if pgErr.ConstraintName == "ingest_replay_nonces_pkey" {
			return api.ErrBatchRejected
		}
		for _, prefix := range []string{
			"ingest_batches_", "gateway_events_", "auth_events_",
			"source_health_intervals_", "source_coverage_attestations_", "outbox_jobs_",
		} {
			if stringsHasPrefix(pgErr.ConstraintName, prefix) {
				return api.ErrBatchConflict
			}
		}
		if batchIdentity {
			return api.ErrBatchConflict
		}
	}
	switch pgErr.Code {
	case "23502", "23503", "23505", "23514", "22P02", "22003", "22023", "55000":
		return api.ErrBatchRejected
	default:
		return api.ErrStoreUnavailable
	}
}

func unavailable(ctx context.Context, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return api.ErrStoreUnavailable
}

func validSequenceDisposition(value string) bool {
	switch value {
	case "next", "gap", "new_epoch", "new_epoch_gap", "late_gap_closed":
		return true
	default:
		return false
	}
}

func stringsHasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
