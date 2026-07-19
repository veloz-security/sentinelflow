package adminstore

import (
	"context"
	"errors"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	MaxDeleteBatch  = 100
	rollbackTimeout = 2 * time.Second
)

// TransactionBeginner is the smallest production contract implemented by a
// pgxpool.Pool or pgx.Conn. Every transaction uses Read Committed isolation.
type TransactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// PostgreSQLStore persists only SessionRecord values. Its public API has no
// parameter capable of carrying a plaintext token, CSRF value, or password.
type PostgreSQLStore struct {
	db TransactionBeginner
}

func NewPostgreSQLStore(db TransactionBeginner) (*PostgreSQLStore, error) {
	if db == nil {
		return nil, ErrUnavailable
	}
	return &PostgreSQLStore{db: db}, nil
}

// LoadByID returns at most one active session. A missing, expired, idle, or
// revoked session is deliberately indistinguishable as not found.
func (s *PostgreSQLStore) LoadByID(ctx context.Context, id adminauth.SessionID) (adminauth.SessionRecord, error) {
	if ctx == nil || s == nil || s.db == nil {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	if !validUUIDv4(id) {
		return adminauth.SessionRecord{}, ErrNotFound
	}
	tx, done, err := s.begin(ctx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	defer func() { done() }()
	record, err := scanRecord(tx.QueryRow(ctx, loadSessionSQL, id.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.SessionRecord{}, ErrNotFound
	}
	if err != nil || !validRecord(record) {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	// Read the authoritative clock after FOR SHARE succeeds. A clock sampled
	// before a lock wait could incorrectly revive an expired or idle session.
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	if !activeAt(record, now) {
		return adminauth.SessionRecord{}, ErrNotFound
	}
	if err := commit(ctx, tx); err != nil {
		return adminauth.SessionRecord{}, err
	}
	done = noRollback
	return cloneRecord(record), nil
}

// LoadRevokedDecisionReplayParent returns only a recently revoked privileged
// parent whose unique rotation child remains live. It exists solely for exact,
// read-only HIL response recovery; ordinary session loading deliberately keeps
// revoked records indistinguishable from missing records.
func (s *PostgreSQLStore) LoadRevokedDecisionReplayParent(ctx context.Context, id adminauth.SessionID) (adminauth.SessionRecord, error) {
	if ctx == nil || s == nil || s.db == nil {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	if !validUUIDv4(id) {
		return adminauth.SessionRecord{}, ErrNotFound
	}
	tx, done, err := s.begin(ctx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	defer func() { done() }()
	parent, child, err := scanRecordPair(tx.QueryRow(ctx, loadRevokedDecisionReplayParentSQL, id.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.SessionRecord{}, ErrNotFound
	}
	if err != nil || !validRecord(parent) || !validRecord(child) {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	// Sample only after both FOR SHARE locks. A pre-lock clock could revive an
	// expired replay window or a child that went idle while waiting.
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	if !validDecisionReplayRotation(parent, child, now) {
		return adminauth.SessionRecord{}, ErrNotFound
	}
	if err := commit(ctx, tx); err != nil {
		return adminauth.SessionRecord{}, err
	}
	done = noRollback
	return cloneRecord(parent), nil
}

func validDecisionReplayRotation(parent, child adminauth.SessionRecord, now time.Time) bool {
	if parent.RevokedAt == nil || child.RevokedAt != nil || child.RotationParentID == nil ||
		*child.RotationParentID != parent.ID || child.ID == parent.ID ||
		child.ActorID != parent.ActorID || !child.AuthenticatedAt.Equal(parent.AuthenticatedAt) ||
		child.TokenDigest == parent.TokenDigest || child.CSRFDigest == parent.CSRFDigest ||
		!child.ExpiresAt.Equal(child.CreatedAt.Add(adminauth.SessionAbsoluteLifetime)) ||
		child.CreatedAt.Before(parent.LastSeenAt) || !child.CreatedAt.Before(parent.ExpiresAt) ||
		parent.RevokedAt.Before(parent.LastSeenAt) || !parent.RevokedAt.Before(parent.ExpiresAt) ||
		parent.RevokedAt.Before(child.CreatedAt) ||
		!parent.RevokedAt.Before(child.CreatedAt.Add(adminauth.PrivilegedDecisionReplayLifetime)) ||
		now.Before(*parent.RevokedAt) ||
		!now.Before(parent.RevokedAt.Add(adminauth.PrivilegedDecisionReplayLifetime)) ||
		!now.Before(parent.ExpiresAt) || !activeAt(child, now) {
		return false
	}
	return true
}

// InsertLogin stores a newly issued login session and returns PostgreSQL's
// canonical timestamp representation. Database time rejects future or already
// stale caller records.
func (s *PostgreSQLStore) InsertLogin(ctx context.Context, record adminauth.SessionRecord) (adminauth.SessionRecord, error) {
	if ctx == nil || s == nil || s.db == nil {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	record = cloneRecord(record)
	if !validRecord(record) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	tx, done, err := s.begin(ctx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	defer func() { done() }()
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	if !validLogin(record, now) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	inserted, err := scanRecord(tx.QueryRow(ctx, insertSessionSQL, recordArguments(record)...))
	if err != nil {
		return adminauth.SessionRecord{}, classifyWriteError(err)
	}
	if !exactRecord(inserted, record) {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	// A uniqueness wait can outlive the original clock sample. Recheck after
	// insertion so the transaction cannot commit an already-stale login.
	postInsertNow, err := databaseTime(ctx, tx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	if !validLogin(inserted, postInsertNow) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	if err := commit(ctx, tx); err != nil {
		return adminauth.SessionRecord{}, err
	}
	done = noRollback
	return cloneRecord(inserted), nil
}

// Touch advances last_seen_at to PostgreSQL's clock only when expected is the
// exact current live record. It never accepts a caller-selected new time.
func (s *PostgreSQLStore) Touch(ctx context.Context, expected adminauth.SessionRecord) (adminauth.SessionRecord, error) {
	return s.mutateOne(ctx, expected, touchSessionSQL)
}

// Revoke marks an exact current live record revoked at PostgreSQL's clock. It
// never accepts a caller-selected revocation time.
func (s *PostgreSQLStore) Revoke(ctx context.Context, expected adminauth.SessionRecord) (adminauth.SessionRecord, error) {
	return s.mutateOne(ctx, expected, revokeSessionSQL)
}

func (s *PostgreSQLStore) mutateOne(ctx context.Context, expected adminauth.SessionRecord, statement string) (adminauth.SessionRecord, error) {
	if ctx == nil || s == nil || s.db == nil {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	expected = cloneRecord(expected)
	if !validRecord(expected) || expected.RevokedAt != nil {
		return adminauth.SessionRecord{}, ErrConflict
	}
	tx, done, err := s.begin(ctx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	defer func() { done() }()
	current, err := scanRecord(tx.QueryRow(ctx, lockSessionSQL, expected.ID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	if err != nil || !validRecord(current) {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	// Sample after FOR UPDATE to prevent a lock wait from authorizing with a
	// stale database timestamp.
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	if !exactRecord(current, expected) || !activeAt(current, now) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	arguments := append(recordArguments(expected), now.UTC())
	updated, err := scanRecord(tx.QueryRow(ctx, statement, arguments...))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	if err != nil {
		return adminauth.SessionRecord{}, classifyWriteError(err)
	}
	want := cloneRecord(expected)
	if statement == touchSessionSQL {
		want.LastSeenAt = now.UTC()
	} else if statement == revokeSessionSQL {
		value := now.UTC()
		want.RevokedAt = &value
	} else {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	if !exactRecord(updated, want) {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	if err := commit(ctx, tx); err != nil {
		return adminauth.SessionRecord{}, err
	}
	done = noRollback
	return cloneRecord(updated), nil
}

// Rotate atomically revokes expected and inserts replacement. The old row is
// locked and compared in full before either write; replacement must be a fresh
// child record and may only preserve authenticated_at or set it at step-up.
func (s *PostgreSQLStore) Rotate(ctx context.Context, expected, replacement adminauth.SessionRecord) (adminauth.SessionRecord, error) {
	if ctx == nil || s == nil || s.db == nil {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	expected = cloneRecord(expected)
	replacement = cloneRecord(replacement)
	if !validRecord(expected) || expected.RevokedAt != nil || !validRecord(replacement) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	tx, done, err := s.begin(ctx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	defer func() { done() }()
	current, err := scanRecord(tx.QueryRow(ctx, lockSessionSQL, expected.ID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	if err != nil || !validRecord(current) {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	// Sample after FOR UPDATE to prevent a lock wait from authorizing with a
	// stale database timestamp.
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	if !exactRecord(current, expected) || !activeAt(current, now) ||
		!validReplacement(current, replacement, now) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	arguments := append(recordArguments(expected), now.UTC())
	revoked, err := scanRecord(tx.QueryRow(ctx, revokeSessionSQL, arguments...))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	if err != nil {
		return adminauth.SessionRecord{}, classifyWriteError(err)
	}
	wantRevoked := cloneRecord(expected)
	revokedAt := now.UTC()
	wantRevoked.RevokedAt = &revokedAt
	if !exactRecord(revoked, wantRevoked) {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	inserted, err := scanRecord(tx.QueryRow(ctx, insertSessionSQL, recordArguments(replacement)...))
	if err != nil {
		return adminauth.SessionRecord{}, classifyWriteError(err)
	}
	if !exactRecord(inserted, replacement) {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	postInsertNow, err := databaseTime(ctx, tx)
	if err != nil {
		return adminauth.SessionRecord{}, err
	}
	if !activeAt(inserted, postInsertNow) {
		return adminauth.SessionRecord{}, ErrConflict
	}
	if err := commit(ctx, tx); err != nil {
		return adminauth.SessionRecord{}, err
	}
	done = noRollback
	return cloneRecord(inserted), nil
}

// DeleteExpired removes at most limit unreferenced expired/revoked sessions.
// PostgreSQL supplies the cutoff and SKIP LOCKED prevents cleanup contention.
func (s *PostgreSQLStore) DeleteExpired(ctx context.Context, limit int) (int, error) {
	if ctx == nil || s == nil || s.db == nil {
		return 0, ErrUnavailable
	}
	if limit < 1 || limit > MaxDeleteBatch {
		return 0, ErrConflict
	}
	tx, done, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { done() }()
	var deleted int
	if err := tx.QueryRow(ctx, deleteExpiredSQL, limit).Scan(&deleted); err != nil {
		return 0, ErrUnavailable
	}
	if deleted < 0 || deleted > limit {
		return 0, ErrUnavailable
	}
	if err := commit(ctx, tx); err != nil {
		return 0, err
	}
	done = noRollback
	return deleted, nil
}

func (s *PostgreSQLStore) begin(ctx context.Context) (pgx.Tx, func(), error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	done := func() {
		rollbackContext, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rollbackContext)
	}
	return tx, done, nil
}

func noRollback() {}

func commit(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func databaseTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, databaseClockSQL).Scan(&now); err != nil || !validDatabaseTime(now) {
		return time.Time{}, ErrUnavailable
	}
	return now.UTC(), nil
}

func recordArguments(record adminauth.SessionRecord) []any {
	return []any{
		record.ID.String(), record.ActorID, record.TokenDigest.String(), record.CSRFDigest.String(),
		record.AuthenticatedAt.UTC(), record.CreatedAt.UTC(), record.LastSeenAt.UTC(),
		record.ExpiresAt.UTC(), optionalTime(record.RevokedAt), optionalIDString(record.RotationParentID),
	}
}

func scanRecord(row pgx.Row) (adminauth.SessionRecord, error) {
	return scanRecordWithTrailing(row)
}

func scanRecordWithTrailing(row pgx.Row, trailing ...any) (adminauth.SessionRecord, error) {
	var scanned recordScanValue
	destinations := scanned.destinations()
	destinations = append(destinations, trailing...)
	if err := row.Scan(destinations...); err != nil {
		return adminauth.SessionRecord{}, err
	}
	return scanned.recordValue()
}

func scanRecordPair(row pgx.Row) (adminauth.SessionRecord, adminauth.SessionRecord, error) {
	var parent, child recordScanValue
	destinations := append(parent.destinations(), child.destinations()...)
	if err := row.Scan(destinations...); err != nil {
		return adminauth.SessionRecord{}, adminauth.SessionRecord{}, err
	}
	parentRecord, err := parent.recordValue()
	if err != nil {
		return adminauth.SessionRecord{}, adminauth.SessionRecord{}, err
	}
	childRecord, err := child.recordValue()
	if err != nil {
		return adminauth.SessionRecord{}, adminauth.SessionRecord{}, err
	}
	return parentRecord, childRecord, nil
}

type recordScanValue struct {
	record         adminauth.SessionRecord
	id             string
	tokenDigest    string
	csrfDigest     string
	revokedAt      *time.Time
	rotationParent *string
}

func (value *recordScanValue) destinations() []any {
	return []any{
		&value.id, &value.record.ActorID, &value.tokenDigest, &value.csrfDigest,
		&value.record.AuthenticatedAt, &value.record.CreatedAt, &value.record.LastSeenAt,
		&value.record.ExpiresAt, &value.revokedAt, &value.rotationParent,
	}
}

func (value *recordScanValue) recordValue() (adminauth.SessionRecord, error) {
	parsedID, ok := parseSessionID(value.id)
	if !ok {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	value.record.ID = parsedID
	parsedToken, ok := parseDigest(value.tokenDigest)
	if !ok {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	value.record.TokenDigest = parsedToken
	parsedCSRF, ok := parseDigest(value.csrfDigest)
	if !ok {
		return adminauth.SessionRecord{}, ErrUnavailable
	}
	value.record.CSRFDigest = parsedCSRF
	if value.revokedAt != nil {
		revoked := value.revokedAt.UTC()
		value.record.RevokedAt = &revoked
	}
	if value.rotationParent != nil {
		parent, valid := parseSessionID(*value.rotationParent)
		if !valid {
			return adminauth.SessionRecord{}, ErrUnavailable
		}
		value.record.RotationParentID = &parent
	}
	return cloneRecord(value.record), nil
}

func classifyWriteError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && len(postgresError.Code) == 5 && postgresError.Code[:2] == "23" {
		return ErrConflict
	}
	return ErrUnavailable
}
