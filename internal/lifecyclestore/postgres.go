package lifecyclestore

import (
	"context"
	"errors"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
	"github.com/devwooops/sentinelflow/internal/lifecycleruntime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const rollbackTimeout = 2 * time.Second

type transaction interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

// PostgreSQLStore holds no signing material and has no direct table access.
type PostgreSQLStore struct {
	begin  func(context.Context, pgx.TxOptions) (transaction, error)
	config Config
}

func NewPostgreSQLStore(db TransactionBeginner, config Config) (*PostgreSQLStore, error) {
	if db == nil || !validConfig(config) {
		return nil, ErrInvalidInput
	}
	return &PostgreSQLStore{
		begin: func(ctx context.Context, options pgx.TxOptions) (transaction, error) {
			return db.BeginTx(ctx, options)
		},
		config: config,
	}, nil
}

func (*PostgreSQLStore) String() string {
	return "lifecyclestore.PostgreSQLStore{authority:functions-only,artifacts:[REDACTED]}"
}

func (s *PostgreSQLStore) GoString() string { return s.String() }

func (s *PostgreSQLStore) ClaimDue(ctx context.Context) (lifecycleruntime.Claim, bool, error) {
	if ctx == nil || s == nil || s.begin == nil || !validConfig(s.config) {
		return lifecycleruntime.Claim{}, false, ErrInvalidInput
	}
	tx, done, err := s.beginTransaction(ctx)
	if err != nil {
		return lifecycleruntime.Claim{}, false, err
	}
	defer func() { done() }()
	var projection claimProjection
	err = tx.QueryRow(
		ctx, claimScheduleSQL, s.config.SchedulerID, s.config.LeaseOwner,
		int32(s.config.LeaseDuration/time.Second),
	).Scan(
		&projection.scheduleIdentity, &projection.leaseIdentity,
		&projection.authorizationID, &projection.actionID, &projection.actionVersion,
		&projection.policyID, &projection.policyVersion, &projection.targetIPv4,
		&projection.originalAddDigest, &projection.originalAuthorizationDigest,
		&projection.evidenceSnapshotDigest, &projection.validationSnapshotDigest,
		&projection.ownedSchemaDigest, &projection.purpose,
		&projection.requestedAt, &projection.validUntil,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return lifecycleruntime.Claim{}, false, classifyDatabaseError(err)
		}
		done = noRollback
		return lifecycleruntime.Claim{}, false, nil
	}
	if err != nil {
		return lifecycleruntime.Claim{}, false, classifyDatabaseError(err)
	}
	if !validProjection(projection) {
		return lifecycleruntime.Claim{}, false, ErrProjectionInvalid
	}
	claim := projection.claim()
	if err := tx.Commit(ctx); err != nil {
		return lifecycleruntime.Claim{}, false, classifyDatabaseError(err)
	}
	done = noRollback
	return claim, true, nil
}

func (s *PostgreSQLStore) CommitInspection(
	ctx context.Context,
	claim lifecycleruntime.Claim,
	prepared lifecycleruntime.PreparedInspection,
) (lifecycleruntime.CommitDisposition, error) {
	if ctx == nil || s == nil || s.begin == nil || !validConfig(s.config) {
		return "", ErrInvalidInput
	}
	schedule, lease, ok := validStoreIdentity(claim)
	if !ok {
		return "", ErrInvalidInput
	}
	inspectBytes := prepared.Inspect().CanonicalBytes()
	inspect, err := lifecycleartifact.ParseCanonicalInspectArtifact(inspectBytes)
	if err != nil || inspect.Digest() != prepared.Inspect().Digest() {
		return "", ErrContractRejected
	}
	authorizationBytes := prepared.Authorization().CanonicalBytes()
	authorization, err := lifecycleartifact.ParseCanonicalInspectionAuthorization(
		authorizationBytes, inspect,
	)
	if err != nil || authorization.Digest() != prepared.Authorization().Digest() ||
		authorization.Value().SchedulerID != s.config.SchedulerID {
		return "", ErrContractRejected
	}
	tx, done, err := s.beginTransaction(ctx)
	if err != nil {
		return "", err
	}
	defer func() { done() }()
	var disposition string
	err = tx.QueryRow(
		ctx, commitInspectionSQL, schedule, lease, int32(claim.ActionVersion()),
		s.config.SchedulerID, authorization.Value().AuthorizationID,
		inspectBytes, inspect.Digest(), authorizationBytes, authorization.Digest(),
	).Scan(&disposition)
	if err != nil {
		return "", classifyDatabaseError(err)
	}
	if disposition != string(lifecycleruntime.CommitCreated) &&
		disposition != string(lifecycleruntime.CommitReplayed) {
		return "", ErrProjectionInvalid
	}
	if err := tx.Commit(ctx); err != nil {
		return "", classifyDatabaseError(err)
	}
	done = noRollback
	return lifecycleruntime.CommitDisposition(disposition), nil
}

func (s *PostgreSQLStore) FinishFailure(
	ctx context.Context,
	claim lifecycleruntime.Claim,
	failure lifecycleruntime.Failure,
) error {
	if ctx == nil || s == nil || s.begin == nil || !validConfig(s.config) {
		return ErrInvalidInput
	}
	schedule, lease, ok := validStoreIdentity(claim)
	if !ok || !validFailure(failure) {
		return ErrInvalidInput
	}
	tx, done, err := s.beginTransaction(ctx)
	if err != nil {
		return err
	}
	defer func() { done() }()
	var disposition string
	err = tx.QueryRow(
		ctx, finishFailureSQL, schedule, lease, int32(claim.ActionVersion()),
		string(failure.Code()), failure.Digest(), int32(s.config.RetryBackoff/time.Second),
	).Scan(&disposition)
	if err != nil {
		return classifyDatabaseError(err)
	}
	if disposition != "retry" && disposition != "dead" {
		return ErrProjectionInvalid
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyDatabaseError(err)
	}
	done = noRollback
	return nil
}

func validFailure(failure lifecycleruntime.Failure) bool {
	switch failure.Code() {
	case lifecycleruntime.FailureProjectionInvalid,
		lifecycleruntime.FailureContractRejected,
		lifecycleruntime.FailureContextCancelled:
		return digestPattern.MatchString(failure.Digest())
	default:
		return false
	}
}

func (s *PostgreSQLStore) beginTransaction(
	ctx context.Context,
) (transaction, func(), error) {
	tx, err := s.begin(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, noRollback, classifyDatabaseError(err)
	}
	return tx, func() { rollback(tx) }, nil
}

func rollback(tx transaction) {
	ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func noRollback() {}

func classifyDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrUnavailable
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return ErrUnavailable
	}
	switch databaseError.Code {
	case "23505", "23514", "22023", "22P02":
		return ErrConflict
	case "42501", "55000", "40001", "40P01":
		return ErrLeaseLost
	default:
		return ErrUnavailable
	}
}
