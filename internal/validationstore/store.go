// Package validationstore implements the PostgreSQL persistence boundary for
// deterministic validation of staged AI policy artifacts.
package validationstore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/validationworker"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	leaseSQL = `
SELECT job_id::text, kind, aggregate_type, aggregate_id::text,
    aggregate_version, state, available_at, lease_token::text,
    lease_owner, updated_at, lease_expires_at, attempts, max_attempts
FROM sentinelflow.lease_validation_outbox_job($1, $2::uuid, $3, $4)`
	prepareSQL = `
SELECT status, snapshot, evidence_canonical
FROM sentinelflow.prepare_validation_attempt_exact($1::uuid, $2::uuid)`
	prepareVerifiedDemoSQL = `
SELECT status, snapshot, evidence_canonical
FROM sentinelflow.prepare_validation_attempt_verified_demo_000030(
	$1::uuid, $2::uuid, $3::bytea,
	$4::uuid, $5::uuid, $6::uuid,
	$7, $8, $9, $10, $11, $12, $13, $14, $15,
	$16::timestamptz, $17::timestamptz, $18::timestamptz, $19::timestamptz,
	$20, $21
)`
	finalizeSQL = `
SELECT job_id::text, state
FROM sentinelflow.finalize_validation_attempt_exact(
    $1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::json, $9::bytea
)`
)

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuidV4Pattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	asciiIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	timeoutPattern    = regexp.MustCompile(`^[1-9][0-9]{0,4}[smh]$`)
	nftVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z._-]{0,63})?$`)

	// Errors deliberately contain no PostgreSQL detail or persisted data.
	ErrInvalidRequest = errors.New("validation store: invalid request")
	ErrPersistence    = errors.New("validation store: persistence unavailable")
	ErrInvalidRow     = errors.New("validation store: invalid persistence result")
	ErrEvidenceStale  = errors.New("validation store: incident evidence changed")
)

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// PostgreSQLStore mutates validation state only through SECURITY DEFINER
// functions. In particular, it never writes policy or validation tables
// directly and therefore cannot split publication from outbox completion.
type PostgreSQLStore struct {
	db          queryRower
	demoHistory *validation.VerifiedDemoHistoryBinding
	demoRuntime *validation.ActivatedDemoHistoryBinding
	demoClaims  validation.DemoHistoryBindingClaims
}

func (s *PostgreSQLStore) String() string {
	if s == nil {
		return "validationstore.PostgreSQLStore[INVALID]"
	}
	return "validationstore.PostgreSQLStore[REDACTED]"
}

func (s *PostgreSQLStore) GoString() string { return s.String() }
func (s *PostgreSQLStore) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(s.String()))
}

func NewPostgreSQLStore(db queryRower) (*PostgreSQLStore, error) {
	if db == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgreSQLStore{db: db}, nil
}

// NewPostgreSQLActivatedDemoStore accepts only an opaque, HMAC-bound,
// database-receipted validation activation. Public proof claims alone cannot
// switch the store to demo history.
func NewPostgreSQLActivatedDemoStore(
	db queryRower,
	activation validation.ActivatedDemoHistoryBinding,
) (*PostgreSQLStore, error) {
	if db == nil || activation.Consumer() != validation.DemoHistoryConsumerValidation {
		return nil, ErrInvalidRequest
	}
	binding, bindingOK := activation.Binding()
	claims, claimsOK := activation.Claims()
	secret, secretOK := activation.ActivationSecret()
	clear(secret)
	if !bindingOK || !claimsOK || !secretOK || !validDemoClaims(claims) {
		return nil, ErrInvalidRequest
	}
	bindingCopy := binding
	activationCopy := activation
	return &PostgreSQLStore{
		db: db, demoHistory: &bindingCopy, demoRuntime: &activationCopy, demoClaims: claims,
	}, nil
}

var _ validationworker.Store = (*PostgreSQLStore)(nil)
var _ validationworker.VerifiedDemoHistoryStore = (*PostgreSQLStore)(nil)

func (s *PostgreSQLStore) VerifiedDemoHistoryBinding() (validation.VerifiedDemoHistoryBinding, bool) {
	if s == nil || s.demoHistory == nil {
		return validation.VerifiedDemoHistoryBinding{}, false
	}
	return *s.demoHistory, true
}

func (s *PostgreSQLStore) Lease(
	ctx context.Context,
	request worker.LeaseRequest,
) (worker.LeasedJob, bool, error) {
	if ctx == nil || !validLeaseRequest(request) {
		return worker.LeasedJob{}, false, ErrInvalidRequest
	}
	var job worker.LeasedJob
	var kind, token string
	err := s.db.QueryRow(ctx, leaseSQL,
		request.Now.UTC(), request.LeaseToken, request.LeaseOwner,
		request.LeaseExpiresAt.UTC(),
	).Scan(
		&job.JobID, &kind, &job.AggregateType, &job.AggregateID,
		&job.AggregateVersion, &job.State, &job.AvailableAt, &token,
		&job.LeaseOwner, &job.LeaseGrantedAt, &job.LeaseExpiresAt,
		&job.Attempt, &job.MaxAttempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return worker.LeasedJob{}, false, nil
	}
	if err != nil {
		return worker.LeasedJob{}, false, classifyPersistenceError(err)
	}
	job.Kind = worker.JobKind(kind)
	job.LeaseToken = token
	if !validLeasedRow(job, request) {
		return worker.LeasedJob{}, false, ErrInvalidRow
	}
	return job, true, nil
}

func (s *PostgreSQLStore) Prepare(
	ctx context.Context,
	request validationworker.PrepareRequest,
) (validationworker.Snapshot, bool, error) {
	if ctx == nil || !validPrepareRequest(request) {
		return validationworker.Snapshot{}, false, ErrInvalidRequest
	}
	query := prepareSQL
	arguments := []any{request.Job.JobID, request.LeaseToken}
	if s.demoRuntime != nil {
		secret, ok := s.demoRuntime.ActivationSecret()
		claimsDigest, digestOK := s.demoRuntime.ClaimsDigest()
		if !ok || !digestOK || s.demoRuntime.Consumer() != validation.DemoHistoryConsumerValidation {
			return validationworker.Snapshot{}, false, ErrInvalidRequest
		}
		defer clear(secret)
		query = prepareVerifiedDemoSQL
		arguments = append(arguments, secret)
		arguments = append(arguments, demoPrepareArguments(s.demoClaims)...)
		arguments = append(arguments, claimsDigest)
	}
	var status string
	var document, evidenceCanonical []byte
	err := s.db.QueryRow(ctx, query, arguments...).
		Scan(&status, &document, &evidenceCanonical)
	if errors.Is(err, pgx.ErrNoRows) {
		return validationworker.Snapshot{}, false, nil
	}
	if err != nil {
		if evidenceStale(err) {
			return validationworker.Snapshot{}, false, ErrEvidenceStale
		}
		return validationworker.Snapshot{}, false, classifyPersistenceError(err)
	}
	if status != "prepared" {
		if status == "terminal" || status == "interrupted" {
			return validationworker.Snapshot{}, false, nil
		}
		return validationworker.Snapshot{}, false, ErrInvalidRow
	}
	snapshot, err := decodeSnapshot(document, evidenceCanonical)
	if err != nil || snapshot.AnalysisID != request.Job.AggregateID {
		return validationworker.Snapshot{}, false, ErrInvalidRow
	}
	return snapshot, true, nil
}

func (s *PostgreSQLStore) Finalize(
	ctx context.Context,
	request validationworker.FinalizeRequest,
) (bool, error) {
	if ctx == nil || !validFinish(request.Finish) || !validMutation(request.Mutation) ||
		(request.Mutation == nil) == (request.Finish.State == worker.FinishCompleted) {
		return false, ErrInvalidRequest
	}
	payload, err := encodeMutation(request.Mutation)
	if err != nil {
		return false, ErrInvalidRequest
	}
	var retryAt any
	if request.Finish.RetryAt != nil {
		retryAt = request.Finish.RetryAt.UTC()
	}
	var code, digest any
	if request.Finish.State != worker.FinishCompleted {
		code, digest = request.Finish.ErrorCode, request.Finish.ErrorDigest
	}
	var jobID, state string
	err = s.db.QueryRow(ctx, finalizeSQL,
		request.Finish.JobID, request.Finish.LeaseToken,
		string(request.Finish.State), retryAt, request.Finish.Now.UTC(),
		code, digest, payload, evidenceBytes(request.Mutation),
	).Scan(&jobID, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		if evidenceStale(err) {
			return false, ErrEvidenceStale
		}
		return false, classifyPersistenceError(err)
	}
	if jobID == request.Finish.JobID && request.Finish.State == worker.FinishCompleted &&
		state == string(worker.FinishDead) {
		return false, ErrEvidenceStale
	}
	if jobID != request.Finish.JobID || state != string(request.Finish.State) {
		return false, ErrInvalidRow
	}
	return true, nil
}

func evidenceBytes(mutation *validationworker.Mutation) []byte {
	if mutation == nil {
		return nil
	}
	return append([]byte(nil), mutation.EvidenceCanonicalBytes...)
}

func validLeaseRequest(request worker.LeaseRequest) bool {
	duration := request.LeaseExpiresAt.Sub(request.Now)
	return !request.Now.IsZero() && duration > 0 && duration <= worker.MaxLeaseDuration &&
		uuidV4Pattern.MatchString(request.LeaseToken) && asciiIDPattern.MatchString(request.LeaseOwner)
}

func validLeasedRow(job worker.LeasedJob, request worker.LeaseRequest) bool {
	return uuidPattern.MatchString(job.JobID) && job.Kind == worker.JobValidate &&
		job.AggregateType == validationworker.ValidationAggregateType &&
		uuidPattern.MatchString(job.AggregateID) && job.AggregateVersion == 1 &&
		job.State == "leased" && job.LeaseToken == request.LeaseToken &&
		job.LeaseOwner == request.LeaseOwner && !job.LeaseGrantedAt.IsZero() &&
		job.LeaseExpiresAt.Sub(job.LeaseGrantedAt) == request.LeaseExpiresAt.Sub(request.Now) &&
		job.Attempt > 0 && job.Attempt <= job.MaxAttempts
}

func validPrepareRequest(request validationworker.PrepareRequest) bool {
	return uuidPattern.MatchString(request.Job.JobID) && request.Job.Kind == worker.JobValidate &&
		request.Job.AggregateType == validationworker.ValidationAggregateType &&
		uuidPattern.MatchString(request.Job.AggregateID) && request.Job.AggregateVersion == 1 &&
		request.Job.Attempt > 0 && request.Job.Attempt <= request.Job.MaxAttempts &&
		uuidV4Pattern.MatchString(request.LeaseToken)
}

func validFinish(finish worker.FinishRequest) bool {
	if finish.Now.IsZero() || !uuidPattern.MatchString(finish.JobID) ||
		!uuidV4Pattern.MatchString(finish.LeaseToken) {
		return false
	}
	switch finish.State {
	case worker.FinishCompleted:
		return finish.RetryAt == nil && finish.ErrorCode == "" && finish.ErrorDigest == ""
	case worker.FinishRetry:
		return finish.RetryAt != nil && !finish.RetryAt.Before(finish.Now) &&
			asciiIDPattern.MatchString(finish.ErrorCode) && digestPattern.MatchString(finish.ErrorDigest)
	case worker.FinishDead:
		return finish.RetryAt == nil && asciiIDPattern.MatchString(finish.ErrorCode) &&
			digestPattern.MatchString(finish.ErrorDigest)
	default:
		return false
	}
}

func utc(value time.Time) time.Time { return value.Round(0).UTC() }

func validDemoClaims(value validation.DemoHistoryBindingClaims) bool {
	return value.SchemaVersion == validation.DemoHistoryManifestSchemaVersion &&
		value.Profile == validation.DemoHistoryProfile && !value.FixtureOnly &&
		value.VerificationEnvironment == validation.EnvironmentDemo &&
		uuidPattern.MatchString(value.ManifestID) && value.DatasetID == validation.PinnedDemoHistoryDatasetID &&
		value.DatasetSchemaVersion == validation.DemoHistoryDatasetSchemaVersion &&
		value.DatasetLocator == validation.DemoHistoryDatasetLocator &&
		uuidPattern.MatchString(value.ImportID) && !value.ClockAt.IsZero() &&
		value.CoverageEnd.Equal(value.ClockAt) &&
		value.CoverageStart.Equal(value.ClockAt.Add(-validation.HistoricalImpactLookback)) &&
		!value.IssuedAt.IsZero() && !value.IssuedAt.Before(value.CoverageEnd) &&
		value.PathCatalogVersion == "path-catalog-v1" &&
		value.DatasetRecordCount == validation.PinnedDemoHistoryDatasetRecordCount &&
		value.RawFileDigest == validation.PinnedDemoHistoryRawFileDigest &&
		value.DatasetDigest == validation.PinnedDemoHistoryDatasetDigest &&
		value.ImportedRowsDigest == validation.PinnedDemoHistoryImportedRowsDigest &&
		value.ManifestSourceHealthDigest == validation.PinnedDemoHistorySourceHealthDigest &&
		value.ImpactSourceHealthDigest == validation.PinnedDemoHistoryImpactSourceHealthDigest &&
		digestPattern.MatchString(value.ManifestDigest) &&
		digestPattern.MatchString(value.RunScopeDigest) && digestPattern.MatchString(value.PublicKeyDigest) &&
		digestPattern.MatchString(value.SignatureVerificationDigest)
}

func demoPrepareArguments(value validation.DemoHistoryBindingClaims) []any {
	return []any{
		value.ImportID, value.ManifestID, value.DatasetID,
		value.RawFileDigest, value.DatasetDigest, value.ImportedRowsDigest,
		value.DatasetRecordCount, value.ManifestSourceHealthDigest, value.ManifestDigest,
		value.RunScopeDigest, value.PublicKeyDigest, value.SignatureVerificationDigest,
		utc(value.ClockAt), utc(value.IssuedAt), utc(value.CoverageStart), utc(value.CoverageEnd),
		value.ImpactSourceHealthDigest,
	}
}

func evidenceStale(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) && databaseError.Code == "SF005"
}

func classifyPersistenceError(err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "40001", "40P01", "55P03":
			return validationworker.ErrRetryablePersistence
		}
	}
	return ErrPersistence
}
