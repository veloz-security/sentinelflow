package worker

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
)

const leaseWorkerJobSQL = `
SELECT job_id::text, kind, aggregate_type, aggregate_id::text,
    aggregate_version, state, available_at, lease_token::text,
    lease_owner, updated_at, lease_expires_at, attempts, max_attempts
FROM sentinelflow.lease_worker_outbox_job($1, $2::uuid, $3, $4)`

const finishWorkerJobSQL = `
SELECT job_id::text, state
FROM sentinelflow.finish_worker_outbox_job(
    $1, $2, $3, $4, $5, $6::uuid, $7::uuid
)`

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type QueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// PostgreSQLStore accesses outbox state exclusively through the worker lease
// and finish SECURITY DEFINER functions.
type PostgreSQLStore struct {
	db QueryRower
}

func NewPostgreSQLStore(db QueryRower) (*PostgreSQLStore, error) {
	if db == nil {
		return nil, errors.New("worker: PostgreSQL query source is required")
	}
	return &PostgreSQLStore{db: db}, nil
}

func (s *PostgreSQLStore) Lease(ctx context.Context, request LeaseRequest) (LeasedJob, bool, error) {
	if err := validateLeaseRequest(request); err != nil {
		return LeasedJob{}, false, err
	}

	var (
		job        LeasedJob
		kind       string
		leaseToken string
	)
	err := s.db.QueryRow(ctx, leaseWorkerJobSQL,
		request.Now.UTC(), request.LeaseToken, request.LeaseOwner,
		request.LeaseExpiresAt.UTC(),
	).Scan(
		&job.JobID, &kind, &job.AggregateType, &job.AggregateID,
		&job.AggregateVersion, &job.State, &job.AvailableAt, &leaseToken,
		&job.LeaseOwner, &job.LeaseGrantedAt, &job.LeaseExpiresAt,
		&job.Attempt, &job.MaxAttempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return LeasedJob{}, false, nil
	}
	if err != nil {
		return LeasedJob{}, false, fmt.Errorf("worker: lease query failed: %w", err)
	}
	job.Kind = JobKind(kind)
	job.LeaseToken = leaseToken
	return job, true, nil
}

func (s *PostgreSQLStore) Finish(ctx context.Context, request FinishRequest) (bool, error) {
	if err := validateFinishRequest(request); err != nil {
		return false, err
	}

	var retryAt any
	if request.RetryAt != nil {
		retryAt = request.RetryAt.UTC()
	}
	var errorCode, errorDigest any
	if request.State != FinishCompleted {
		errorCode = request.ErrorCode
		errorDigest = request.ErrorDigest
	}

	var jobID, state string
	err := s.db.QueryRow(ctx, finishWorkerJobSQL,
		string(request.State), retryAt, errorCode, errorDigest,
		request.Now.UTC(), request.JobID, request.LeaseToken,
	).Scan(&jobID, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("worker: finish query failed: %w", err)
	}
	if jobID != request.JobID || state != string(request.State) {
		return false, ErrInvalidStoreRow
	}
	return true, nil
}

func validateLeaseRequest(request LeaseRequest) error {
	if request.Now.IsZero() || request.LeaseExpiresAt.IsZero() ||
		!request.LeaseExpiresAt.After(request.Now) ||
		request.LeaseExpiresAt.Sub(request.Now) > MaxLeaseDuration ||
		!validUUIDV4(request.LeaseToken) ||
		!asciiIDPattern.MatchString(request.LeaseOwner) {
		return fmt.Errorf("worker: invalid lease request")
	}
	return nil
}

func validateFinishRequest(request FinishRequest) error {
	if request.Now.IsZero() || !uuidPattern.MatchString(request.JobID) ||
		!validUUIDV4(request.LeaseToken) {
		return fmt.Errorf("worker: invalid finish request")
	}
	switch request.State {
	case FinishCompleted:
		if request.RetryAt != nil || request.ErrorCode != "" || request.ErrorDigest != "" {
			return fmt.Errorf("worker: invalid completed result")
		}
	case FinishRetry:
		if request.RetryAt == nil || request.RetryAt.Before(request.Now) ||
			!validFailureEvidence(request.ErrorCode, request.ErrorDigest) {
			return fmt.Errorf("worker: invalid retry result")
		}
	case FinishDead:
		if request.RetryAt != nil || !validFailureEvidence(request.ErrorCode, request.ErrorDigest) {
			return fmt.Errorf("worker: invalid dead result")
		}
	default:
		return fmt.Errorf("worker: invalid finish state")
	}
	return nil
}

func validFailureEvidence(code, digest string) bool {
	return asciiIDPattern.MatchString(code) && digestPattern.MatchString(digest)
}

func validUUIDV4(value string) bool {
	return uuidPattern.MatchString(value) && value[14] == '4' &&
		(value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b')
}
