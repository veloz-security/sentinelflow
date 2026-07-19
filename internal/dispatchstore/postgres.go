package dispatchstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const rollbackTimeout = 2 * time.Second

// TransactionBeginner is implemented by pgxpool.Pool and pgx.Conn.
type TransactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type transaction interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

// PostgreSQLStore holds only public verification keys and a lease-token entropy
// source. It never has a capability signing key or executor result private key.
type PostgreSQLStore struct {
	begin              func(context.Context, pgx.TxOptions) (transaction, error)
	capabilityVerifier capability.CapabilityVerifier
	resultVerifier     capability.ResultVerifier
	entropy            io.Reader
	entropyMu          sync.Mutex
}

func NewPostgreSQLStore(
	db TransactionBeginner,
	capabilityVerifier capability.CapabilityVerifier,
	resultVerifier capability.ResultVerifier,
	entropy io.Reader,
) (*PostgreSQLStore, error) {
	if db == nil || capabilityVerifier.KeyID() == "" || resultVerifier.KeyID() == "" ||
		capabilityVerifier.ExecutorID() == "" ||
		capabilityVerifier.ExecutorID() != resultVerifier.ExecutorID() ||
		capabilityVerifier.KeyID() == resultVerifier.KeyID() {
		return nil, ErrInvalidInput
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &PostgreSQLStore{
		begin: func(ctx context.Context, options pgx.TxOptions) (transaction, error) {
			return db.BeginTx(ctx, options)
		},
		capabilityVerifier: capabilityVerifier,
		resultVerifier:     resultVerifier,
		entropy:            entropy,
	}, nil
}

func (*PostgreSQLStore) String() string {
	return "dispatchstore.PostgreSQLStore{keys:[PUBLIC-ONLY],entropy:[REDACTED]}"
}
func (s *PostgreSQLStore) GoString() string { return s.String() }

// ListEligible reads only the security-barrier dispatcher view in its frozen
// deterministic order. It does not claim or mutate a job.
func (s *PostgreSQLStore) ListEligible(ctx context.Context, limit int) ([]EligibleJob, error) {
	if ctx == nil || s == nil || s.begin == nil || limit < 1 || limit > MaxListLimit {
		return nil, ErrInvalidInput
	}
	tx, done, err := s.beginTransaction(ctx, pgx.TxOptions{
		IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	defer func() { done() }()
	jobs, err := listJobs(ctx, tx, listEligibleSQL, limit, false)
	if err != nil {
		return nil, err
	}
	if err := commit(ctx, tx); err != nil {
		return nil, err
	}
	done = noRollback
	result := make([]EligibleJob, len(jobs))
	for index := range jobs {
		result[index] = EligibleJob{value: cloneJob(jobs[index])}
	}
	return result, nil
}

// ClaimNext selects a bounded deterministic candidate set, then calls the
// fenced claim function for each candidate until one succeeds. PostgreSQL's
// clock, not a caller timestamp, defines the lease.
func (s *PostgreSQLStore) ClaimNext(ctx context.Context, request ClaimRequest) (ClaimedJob, bool, error) {
	if ctx == nil || s == nil || s.begin == nil || s.entropy == nil || !validClaimRequest(request) {
		return ClaimedJob{}, false, ErrInvalidInput
	}
	token := request.LeaseToken
	if token == "" {
		var err error
		token, err = s.newLeaseToken()
		if err != nil {
			return ClaimedJob{}, false, err
		}
	}
	tx, done, err := s.beginTransaction(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ClaimedJob{}, false, err
	}
	defer func() { done() }()
	jobs, err := listJobs(ctx, tx, listEligibleSQL, request.CandidateLimit, false)
	if err != nil {
		return ClaimedJob{}, false, err
	}
	if len(jobs) == 0 {
		return ClaimedJob{}, false, nil
	}
	claimClock, err := databaseTime(ctx, tx)
	if err != nil {
		return ClaimedJob{}, false, err
	}
	leaseUntil := claimClock.Add(request.LeaseDuration).UTC()
	if !validDatabaseTime(leaseUntil) {
		return ClaimedJob{}, false, ErrInvalidInput
	}
	for _, job := range jobs {
		var claimed bool
		if err := tx.QueryRow(ctx, claimJobSQL,
			job.jobID, token, request.LeaseOwner, leaseUntil,
		).Scan(&claimed); err != nil {
			return ClaimedJob{}, false, classifyDatabaseError(err)
		}
		if !claimed {
			continue
		}
		postClaimClock, err := databaseTime(ctx, tx)
		if err != nil {
			return ClaimedJob{}, false, err
		}
		if !postClaimClock.Before(leaseUntil) {
			return ClaimedJob{}, false, ErrLeaseLost
		}
		result := ClaimedJob{
			job: cloneJob(job), leaseToken: token, leaseOwner: request.LeaseOwner,
			claimedAt: postClaimClock, leaseUntil: leaseUntil,
		}
		result.claimDigest = digestClaim(result)
		if !validClaimedJob(result) {
			return ClaimedJob{}, false, ErrInvalidRow
		}
		if err := commit(ctx, tx); err != nil {
			return ClaimedJob{}, false, err
		}
		done = noRollback
		return result, true, nil
	}
	return ClaimedJob{}, false, nil
}

// ClaimRecoveryNext is the only claim path for a job that already owns exact
// signed capability bytes. PostgreSQL's recovery-only view exposes it only
// after capability expiry. The dedicated claim function does not consume the
// ordinary attempt budget and can never select authority-free work.
func (s *PostgreSQLStore) ClaimRecoveryNext(
	ctx context.Context,
	request ClaimRequest,
) (ClaimedJob, bool, error) {
	if ctx == nil || s == nil || s.begin == nil || s.entropy == nil || !validClaimRequest(request) {
		return ClaimedJob{}, false, ErrInvalidInput
	}
	token := request.LeaseToken
	if token == "" {
		var err error
		token, err = s.newLeaseToken()
		if err != nil {
			return ClaimedJob{}, false, err
		}
	}
	tx, done, err := s.beginTransaction(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ClaimedJob{}, false, err
	}
	defer func() { done() }()
	jobs, err := listJobs(ctx, tx, listRecoveryEligibleSQL, request.CandidateLimit, true)
	if err != nil {
		return ClaimedJob{}, false, err
	}
	if len(jobs) == 0 {
		return ClaimedJob{}, false, nil
	}
	claimClock, err := databaseTime(ctx, tx)
	if err != nil {
		return ClaimedJob{}, false, err
	}
	leaseUntil := claimClock.Add(request.LeaseDuration).UTC()
	if !validDatabaseTime(leaseUntil) {
		return ClaimedJob{}, false, ErrInvalidInput
	}
	for _, job := range jobs {
		var claimed bool
		if err := tx.QueryRow(ctx, claimRecoveryJobSQL,
			job.jobID, token, request.LeaseOwner, leaseUntil,
		).Scan(&claimed); err != nil {
			return ClaimedJob{}, false, classifyDatabaseError(err)
		}
		if !claimed {
			continue
		}
		postClaimClock, err := databaseTime(ctx, tx)
		if err != nil {
			return ClaimedJob{}, false, err
		}
		if !postClaimClock.Before(leaseUntil) {
			return ClaimedJob{}, false, ErrLeaseLost
		}
		result := ClaimedJob{
			job: cloneJob(job), leaseToken: token, leaseOwner: request.LeaseOwner,
			claimedAt: postClaimClock, leaseUntil: leaseUntil,
		}
		result.claimDigest = digestClaim(result)
		if !validClaimedJob(result) || !result.job.recoveryOnly {
			return ClaimedJob{}, false, ErrInvalidRow
		}
		if err := commit(ctx, tx); err != nil {
			return ClaimedJob{}, false, err
		}
		done = noRollback
		return result, true, nil
	}
	return ClaimedJob{}, false, nil
}

// PersistCapability verifies the dispatcher signature with the configured
// public key, reparses the exact artifact contract, binds every field to the
// claimed immutable row, and only then invokes the fenced persistence function.
func (s *PostgreSQLStore) PersistCapability(
	ctx context.Context,
	claim ClaimedJob,
	signed capability.SignedCapability,
) (PersistedCapability, error) {
	if ctx == nil || s == nil || s.begin == nil || !validClaimedJob(claim) {
		return PersistedCapability{}, ErrInvalidInput
	}
	if claim.job.recoveryOnly {
		return PersistedCapability{}, ErrContractRejected
	}
	verified, err := s.capabilityVerifier.Verify(signed)
	if err != nil {
		return PersistedCapability{}, ErrContractRejected
	}
	artifact := signed.ArtifactBytes()
	if !bindCapability(claim, verified, artifact) {
		return PersistedCapability{}, ErrContractRejected
	}
	nonce, ok := nonceDigest(verified.Value().Nonce)
	if !ok {
		return PersistedCapability{}, ErrContractRejected
	}
	tx, done, err := s.beginTransaction(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PersistedCapability{}, err
	}
	defer func() { done() }()
	if err := requireLiveLease(ctx, tx, claim); err != nil {
		return PersistedCapability{}, err
	}
	value := verified.Value()
	var ignored string
	err = tx.QueryRow(ctx, recordCapabilitySQL,
		value.CapabilityID, claim.job.jobID, claim.leaseToken, string(value.Operation),
		value.ActionID, value.PolicyID, int64(value.PolicyVersion), value.TargetIPv4,
		artifact, value.ArtifactDigest, optionalString(claim.job.originalAddDigest),
		value.EvidenceSnapshotDigest, value.ValidationSnapshotDigest,
		value.AuthorizationDigest, value.ActorID, value.ReasonDigest,
		value.OwnedSchemaDigest, verified.CanonicalBytes(), verified.Digest(),
		signed.Signature(), nonce, value.IssuedAt, value.NotBefore, value.ExpiresAt,
	).Scan(&ignored)
	clear(artifact)
	if err != nil {
		return PersistedCapability{}, classifyDatabaseError(err)
	}
	if err := requireLiveLease(ctx, tx, claim); err != nil {
		return PersistedCapability{}, err
	}
	if err := commit(ctx, tx); err != nil {
		return PersistedCapability{}, err
	}
	done = noRollback
	return PersistedCapability{claim: cloneClaim(claim), verified: verified}, nil
}

// PersistResult verifies the executor signature with the distinct result key,
// binds it to the exact already-persisted capability, and persists the original
// signature bytes. Actual recovery timestamps are never rewritten to fit an
// older database constraint.
func (s *PostgreSQLStore) PersistResult(
	ctx context.Context,
	persisted PersistedCapability,
	signed capability.SignedResult,
) (PersistedResult, error) {
	if ctx == nil || s == nil || s.begin == nil || !validPersistedCapability(persisted) {
		return PersistedResult{}, ErrInvalidInput
	}
	verified, err := s.resultVerifier.Verify(signed)
	if err != nil {
		return PersistedResult{}, ErrContractRejected
	}
	bound, err := verified.BindTo(persisted.verified)
	if err != nil || !validBoundResult(persisted, bound.Result().Value()) {
		return PersistedResult{}, ErrContractRejected
	}
	value := bound.Result().Value()
	tx, done, err := s.beginTransaction(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PersistedResult{}, err
	}
	defer func() { done() }()
	if err := requireLiveLease(ctx, tx, persisted.claim); err != nil {
		return PersistedResult{}, err
	}
	var ignored string
	err = tx.QueryRow(ctx, recordResultSQL,
		value.ResultID, persisted.claim.job.jobID, persisted.claim.leaseToken,
		value.CapabilityID, value.CapabilityDigest, string(value.Operation),
		value.ActionID, value.ArtifactDigest, value.TargetIPv4,
		string(value.Classification), optionalEnum(value.NFTExitClass),
		string(value.ReadbackState), nil, optionalUint(value.RemainingTTLSeconds),
		value.OwnedSchemaDigest, value.StartedAt, value.CompletedAt,
		int64(value.JournalSequence), string(value.ErrorCode),
		verified.CanonicalBytes(), verified.Digest(), signed.Signature(),
	).Scan(&ignored)
	if err != nil {
		return PersistedResult{}, classifyDatabaseError(err)
	}
	if err := requireLiveLease(ctx, tx, persisted.claim); err != nil {
		return PersistedResult{}, err
	}
	if err := commit(ctx, tx); err != nil {
		return PersistedResult{}, err
	}
	done = noRollback
	return PersistedResult{
		capability: clonePersistedCapability(persisted), resultID: value.ResultID,
		digest: verified.Digest(),
	}, nil
}

// Recover reads and re-verifies only the exact signed artifacts already bound
// to the currently leased job. It never mints, rewrites, or re-signs bytes.
func (s *PostgreSQLStore) Recover(
	ctx context.Context,
	claim ClaimedJob,
) (RecoveredExecution, error) {
	if ctx == nil || s == nil || s.begin == nil || !validClaimedJob(claim) {
		return RecoveredExecution{}, ErrInvalidInput
	}
	tx, done, err := s.beginTransaction(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RecoveredExecution{}, err
	}
	defer func() { done() }()

	var (
		state               string
		capabilityID        *string
		capabilityJCS       []byte
		capabilityDigest    *string
		capabilitySignature []byte
		artifact            []byte
		resultID            *string
		resultJCS           []byte
		resultDigest        *string
		resultSignature     []byte
	)
	err = tx.QueryRow(ctx, recoverExecutionSQL, claim.job.jobID, claim.leaseToken).Scan(
		&state, &capabilityID, &capabilityJCS, &capabilityDigest,
		&capabilitySignature, &artifact, &resultID, &resultJCS,
		&resultDigest, &resultSignature,
	)
	if err != nil {
		return RecoveredExecution{}, classifyDatabaseError(err)
	}
	recovered := RecoveredExecution{state: RecoveryState(state), claim: cloneClaim(claim)}
	if recovered.state == RecoveryNone {
		if capabilityID != nil || capabilityJCS != nil || capabilityDigest != nil ||
			capabilitySignature != nil || artifact != nil || resultID != nil ||
			resultJCS != nil || resultDigest != nil || resultSignature != nil {
			return RecoveredExecution{}, ErrInvalidRow
		}
		if err := requireLiveLease(ctx, tx, claim); err != nil {
			return RecoveredExecution{}, err
		}
		if err := commit(ctx, tx); err != nil {
			return RecoveredExecution{}, err
		}
		done = noRollback
		return recovered, nil
	}
	if (recovered.state != RecoveryCapability && recovered.state != RecoveryResult) ||
		capabilityID == nil || !validUUID(*capabilityID) || capabilityDigest == nil ||
		!validDigest(*capabilityDigest) || len(capabilityJCS) == 0 ||
		len(capabilitySignature) == 0 || len(artifact) == 0 {
		return RecoveredExecution{}, ErrInvalidRow
	}

	signedCapability := capability.NewUntrustedSignedCapability(
		s.capabilityVerifier.KeyID(), capabilityJCS, capabilitySignature, artifact,
	)
	verifiedCapability, verifyErr := s.capabilityVerifier.Verify(signedCapability)
	clear(artifact)
	if verifyErr != nil {
		return RecoveredExecution{}, ErrContractRejected
	}
	persistedCapability := PersistedCapability{
		claim: cloneClaim(claim), verified: verifiedCapability, recovered: true,
	}
	if verifiedCapability.Value().CapabilityID != *capabilityID ||
		verifiedCapability.Digest() != *capabilityDigest ||
		!bindRecoveredCapability(claim, verifiedCapability, claim.job.artifact) {
		return RecoveredExecution{}, ErrInvalidRow
	}
	recovered.capability = persistedCapability
	recovered.signedCapability = signedCapability

	if recovered.state == RecoveryCapability {
		if resultID != nil || resultJCS != nil || resultDigest != nil || resultSignature != nil {
			return RecoveredExecution{}, ErrInvalidRow
		}
	} else {
		if resultID == nil || !validUUID(*resultID) || resultDigest == nil ||
			!validDigest(*resultDigest) || len(resultJCS) == 0 || len(resultSignature) == 0 {
			return RecoveredExecution{}, ErrInvalidRow
		}
		signedResult := capability.NewUntrustedSignedResult(
			s.resultVerifier.KeyID(), s.resultVerifier.ExecutorID(), resultJCS, resultSignature,
		)
		verifiedResult, resultErr := s.resultVerifier.Verify(signedResult)
		if resultErr != nil {
			return RecoveredExecution{}, ErrContractRejected
		}
		if verifiedResult.Value().ResultID != *resultID ||
			verifiedResult.Digest() != *resultDigest {
			return RecoveredExecution{}, ErrInvalidRow
		}
		bound, bindErr := verifiedResult.BindTo(verifiedCapability)
		if bindErr != nil || !validBoundResult(persistedCapability, bound.Result().Value()) {
			return RecoveredExecution{}, ErrContractRejected
		}
		recovered.result = PersistedResult{
			capability: clonePersistedCapability(persistedCapability),
			resultID:   *resultID, digest: *resultDigest,
		}
		recovered.signedResult = signedResult
	}

	if err := requireLiveLease(ctx, tx, claim); err != nil {
		return RecoveredExecution{}, err
	}
	if err := commit(ctx, tx); err != nil {
		return RecoveredExecution{}, err
	}
	done = noRollback
	return recovered, nil
}

// Finish completes, retries, or dead-letters a job through the fenced function.
// Retry availability is computed from a fresh database timestamp and a bounded
// relative backoff so caller wall-clock skew cannot move work earlier.
func (s *PostgreSQLStore) Finish(
	ctx context.Context,
	claim ClaimedJob,
	request FinishRequest,
) error {
	if ctx == nil || s == nil || s.begin == nil || !validFinishRequest(claim, request) {
		return ErrInvalidInput
	}
	tx, done, err := s.beginTransaction(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { done() }()
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return err
	}
	if !now.Before(claim.leaseUntil) {
		return ErrLeaseLost
	}
	var nextAvailable, errorCode, errorDigest any
	if request.Outcome == FinishRetry {
		nextAvailable = now.Add(request.RetryBackoff).UTC()
	}
	if request.Outcome != FinishCompleted {
		errorCode, errorDigest = request.ErrorCode, request.ErrorDigest
	}
	var finished bool
	var finishErr error
	if claim.job.recoveryOnly {
		if request.Outcome != FinishCompleted {
			return ErrInvalidInput
		}
		finishErr = tx.QueryRow(ctx, finishRecoveryJobSQL,
			claim.job.jobID, claim.leaseToken,
		).Scan(&finished)
	} else {
		finishErr = tx.QueryRow(ctx, finishJobSQL,
			claim.job.jobID, claim.leaseToken, string(request.Outcome), errorCode,
			errorDigest, nextAvailable,
		).Scan(&finished)
	}
	if finishErr != nil {
		return classifyDatabaseError(finishErr)
	}
	if !finished {
		return ErrLeaseLost
	}
	if err := requireBefore(ctx, tx, claim.leaseUntil); err != nil {
		return err
	}
	if err := commit(ctx, tx); err != nil {
		return err
	}
	done = noRollback
	return nil
}

func listJobs(
	ctx context.Context,
	tx transaction,
	query string,
	limit int,
	recoveryOnly bool,
) ([]jobSnapshot, error) {
	rows, err := tx.Query(ctx, query, limit)
	if err != nil {
		return nil, classifyDatabaseError(err)
	}
	defer rows.Close()
	jobs := make([]jobSnapshot, 0, limit)
	for rows.Next() {
		var job jobSnapshot
		var operation string
		var policyVersion int64
		if err := rows.Scan(
			&job.jobID, &job.kind, &job.state, &job.availableAt,
			&job.attempts, &job.maxAttempts, &operation, &job.actionID,
			&job.policyID, &policyVersion, &job.targetIPv4, &job.artifact,
			&job.artifactDigest, &job.originalAddDigest,
			&job.evidenceSnapshotDigest, &job.validationSnapshotDigest,
			&job.authorizationDigest, &job.actorID, &job.reasonDigest,
			&job.ownedSchemaDigest, &job.notBefore, &job.validUntil,
		); err != nil {
			return nil, ErrInvalidRow
		}
		if policyVersion < 1 || policyVersion > 2_147_483_647 {
			return nil, ErrInvalidRow
		}
		job.policyVersion = uint32(policyVersion)
		job.operation = capability.Operation(operation)
		job.recoveryOnly = recoveryOnly
		job = cloneJob(job)
		if !validJob(job) || len(jobs) >= limit ||
			(len(jobs) > 0 && !jobOrderedAfter(jobs[len(jobs)-1], job)) {
			return nil, ErrInvalidRow
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, classifyDatabaseError(err)
	}
	return jobs, nil
}

func jobOrderedAfter(previous, current jobSnapshot) bool {
	return current.availableAt.After(previous.availableAt) ||
		(current.availableAt.Equal(previous.availableAt) && current.jobID > previous.jobID)
}

func databaseTime(ctx context.Context, tx transaction) (time.Time, error) {
	var value time.Time
	if err := tx.QueryRow(ctx, databaseClockSQL).Scan(&value); err != nil {
		return time.Time{}, classifyDatabaseError(err)
	}
	value = value.Round(0).UTC()
	if !validDatabaseTime(value) {
		return time.Time{}, ErrInvalidRow
	}
	return value, nil
}

func requireLiveLease(ctx context.Context, tx transaction, claim ClaimedJob) error {
	return requireBefore(ctx, tx, claim.leaseUntil)
}

func requireBefore(ctx context.Context, tx transaction, deadline time.Time) error {
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return err
	}
	if !now.Before(deadline) {
		return ErrLeaseLost
	}
	return nil
}

func (s *PostgreSQLStore) newLeaseToken() (string, error) {
	var raw [16]byte
	s.entropyMu.Lock()
	_, err := io.ReadFull(s.entropy, raw[:])
	s.entropyMu.Unlock()
	if err != nil {
		clear(raw[:])
		return "", ErrUnavailable
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	value := formatUUID(raw)
	clear(raw[:])
	return value, nil
}

func formatUUID(raw [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

func (s *PostgreSQLStore) beginTransaction(
	ctx context.Context,
	options pgx.TxOptions,
) (transaction, func(), error) {
	tx, err := s.begin(ctx, options)
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

func commit(ctx context.Context, tx transaction) error {
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func noRollback() {}

func classifyDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "SF101":
			return ErrLeaseLost
		case "SF102":
			return ErrInvalidRow
		case "23505":
			return ErrConflict
		case "22000", "22001", "22003", "22007", "22008", "22023", "22P02", "23503", "23514", "42501":
			return ErrPersistenceRejected
		}
	}
	return ErrUnavailable
}

func cloneClaim(value ClaimedJob) ClaimedJob {
	value.job = cloneJob(value.job)
	value.claimedAt = value.claimedAt.Round(0).UTC()
	value.leaseUntil = value.leaseUntil.Round(0).UTC()
	return value
}

func clonePersistedCapability(value PersistedCapability) PersistedCapability {
	value.claim = cloneClaim(value.claim)
	return value
}

func clonePersistedResult(value PersistedResult) PersistedResult {
	value.capability = clonePersistedCapability(value.capability)
	return value
}
