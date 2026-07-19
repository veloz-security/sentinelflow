package hilstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/jackc/pgx/v5"
)

const rollbackTimeout = 2 * time.Second

// TransactionBeginner is implemented by pgxpool.Pool and pgx.Conn.
type TransactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type transaction interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

// PostgreSQLStore issues and commits exact-artifact HIL records through narrow
// SECURITY DEFINER coordinators. It never has direct table mutation authority.
type PostgreSQLStore struct {
	begin     func(context.Context, pgx.TxOptions) (transaction, error)
	entropy   io.Reader
	entropyMu sync.Mutex
}

func NewPostgreSQLStore(db TransactionBeginner, entropy io.Reader) (*PostgreSQLStore, error) {
	if db == nil {
		return nil, ErrUnavailable
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &PostgreSQLStore{
		begin: func(ctx context.Context, options pgx.TxOptions) (transaction, error) {
			return db.BeginTx(ctx, options)
		},
		entropy: entropy,
	}, nil
}

func (*PostgreSQLStore) String() string     { return "hilstore.PostgreSQLStore{entropy:[REDACTED]}" }
func (s *PostgreSQLStore) GoString() string { return s.String() }

func (s *PostgreSQLStore) Issue(ctx context.Context, request IssueRequest) (*IssuedChallenge, error) {
	if ctx == nil || s == nil || s.begin == nil || s.entropy == nil ||
		(request.Operation != hil.OperationApprove && request.Operation != hil.OperationReject) ||
		request.Browser.historicalOnly ||
		!validSessionProjection(request.Browser.session) ||
		!validDigest(request.Browser.idempotency.digest) || !validExactArtifact(request.Artifact) {
		return nil, ErrInvalidInput
	}

	challengeID, nonce, nonceDigest, err := s.newChallengeMaterial()
	if err != nil {
		return nil, err
	}
	keepNonce := false
	defer func() {
		if !keepNonce {
			clear(nonce)
		}
	}()

	tx, done, err := s.beginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { done() }()

	row := tx.QueryRow(ctx, issueChallengeSQL, issueArguments(challengeID, nonceDigest, request)...)
	checked, rowErr := scanChallenge(row, request)
	if errors.Is(rowErr, pgx.ErrNoRows) {
		classified := classifyIssueFailure(ctx, tx, request, challengeID, nonceDigest)
		return nil, classified
	}
	if rowErr != nil {
		return nil, classifyCoordinatorError(rowErr)
	}

	now, err := databaseTime(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !now.Before(checked.Value().ExpiresAt) ||
		!now.Before(checked.Value().ValidationValidUntil) {
		return nil, ErrValidationStale
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ErrUnavailable
	}
	done = noRollback
	keepNonce = true
	return &IssuedChallenge{artifact: checked, nonce: nonce}, nil
}

func (s *PostgreSQLStore) newChallengeMaterial() (string, []byte, string, error) {
	var rawID [16]byte
	nonce := make([]byte, decisionNonceBytes)
	s.entropyMu.Lock()
	defer s.entropyMu.Unlock()
	if _, err := io.ReadFull(s.entropy, rawID[:]); err != nil {
		clear(nonce)
		return "", nil, "", ErrUnavailable
	}
	if _, err := io.ReadFull(s.entropy, nonce); err != nil {
		clear(rawID[:])
		clear(nonce)
		return "", nil, "", ErrUnavailable
	}
	rawID[6] = rawID[6]&0x0f | 0x40
	rawID[8] = rawID[8]&0x3f | 0x80
	challengeID := formatUUID(rawID)
	clear(rawID[:])
	return challengeID, nonce, digestBytes(nonce), nil
}

func (s *PostgreSQLStore) beginTransaction(ctx context.Context) (transaction, func(), error) {
	tx, err := s.begin(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
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

func issueArguments(challengeID, nonceDigest string, request IssueRequest) []any {
	session := request.Browser.session
	artifact := request.Artifact
	return []any{
		challengeID,
		nonceDigest,
		session.ID.String(),
		session.ActorID,
		session.TokenDigest.String(),
		session.CSRFDigest.String(),
		session.AuthenticatedAt.UTC(),
		session.ExpiresAt.UTC(),
		string(request.Operation),
		artifact.PolicyID(),
		artifact.PolicyVersion(),
		artifact.TargetIPv4(),
		artifact.PolicyDigest(),
		artifact.EvidenceSnapshotDigest(),
		artifact.GeneratedArtifactDigest(),
		artifact.CanonicalArtifactDigest(),
		artifact.ValidationSnapshotDigest(),
		request.Browser.idempotency.digest,
		string(artifact.GeneratedBytes()),
		artifact.CanonicalBytes(),
		artifact.ValidationCreatedAt().UTC(),
		artifact.ValidationValidUntil().UTC(),
		artifact.TTLSeconds(),
	}
}

func classifyIssueFailure(ctx context.Context, tx transaction, request IssueRequest, challengeID, nonceDigest string) error {
	session := request.Browser.session
	artifact := request.Artifact
	var code string
	err := tx.QueryRow(ctx, classifyIssueFailureSQL,
		session.ID.String(), session.ActorID, session.TokenDigest.String(),
		session.CSRFDigest.String(), session.AuthenticatedAt.UTC(), session.ExpiresAt.UTC(),
		artifact.PolicyID(), artifact.PolicyVersion(), artifact.TargetIPv4(),
		artifact.PolicyDigest(), artifact.EvidenceSnapshotDigest(),
		artifact.GeneratedArtifactDigest(), artifact.CanonicalArtifactDigest(),
		artifact.TTLSeconds(), artifact.ValidationSnapshotDigest(),
		artifact.ValidationCreatedAt().UTC(), artifact.ValidationValidUntil().UTC(),
		request.Browser.idempotency.digest, challengeID, nonceDigest,
	).Scan(&code)
	if err != nil {
		return ErrUnavailable
	}
	switch ErrorCode(code) {
	case CodeAuthentication:
		return ErrAuthentication
	case CodeStepUpRequired:
		return ErrStepUpRequired
	case CodeConflict:
		return ErrConflict
	case CodeValidationStale:
		return ErrValidationStale
	default:
		return ErrValidationFailed
	}
}

func scanChallenge(row pgx.Row, request IssueRequest) (hil.CheckedChallenge, error) {
	var (
		challenge                  hil.Challenge
		schemaVersion              string
		nonceDigest                string
		sessionID                  string
		sessionDigest              string
		actorID                    string
		operation                  string
		resourceType               string
		resourceVersion            int64
		originalAddDigest          *string
		idempotencyDigest          string
		reauthRequiredAfterSeconds int64
		challengeJCS               []byte
		challengeDigest            string
	)
	if err := row.Scan(
		&challenge.ChallengeID, &schemaVersion, &nonceDigest, &sessionID,
		&sessionDigest, &actorID, &operation, &resourceType,
		&challenge.ResourceID, &resourceVersion, &challenge.TargetIPv4,
		&challenge.PolicyDigest, &challenge.EvidenceSnapshotDigest,
		&challenge.GeneratedArtifactDigest, &challenge.CanonicalArtifactDigest,
		&originalAddDigest, &challenge.ValidationSnapshotDigest,
		&challenge.ValidationValidUntil, &idempotencyDigest,
		&challenge.AuthenticatedAt, &reauthRequiredAfterSeconds,
		&challenge.IssuedAt, &challenge.ExpiresAt, &challengeJCS,
		&challengeDigest,
	); err != nil {
		return hil.CheckedChallenge{}, err
	}
	if resourceVersion < 1 || resourceVersion > 2_147_483_647 ||
		reauthRequiredAfterSeconds != int64(hil.ReauthAfter/time.Second) {
		return hil.CheckedChallenge{}, ErrUnavailable
	}
	challenge.SchemaVersion = schemaVersion
	challenge.SessionDigest = sessionDigest
	challenge.Operation = hil.Operation(operation)
	challenge.ResourceType = resourceType
	challenge.ResourceVersion = uint32(resourceVersion)
	challenge.OriginalAddDigest = originalAddDigest
	challenge.NonceDigest = nonceDigest
	challenge.ReauthRequiredAfterSeconds = uint32(reauthRequiredAfterSeconds)
	checked, err := hil.CheckChallenge(challenge)
	if err != nil {
		return hil.CheckedChallenge{}, err
	}
	if !bytes.Equal(challengeJCS, checked.CanonicalBytes()) || challengeDigest != checked.Digest() {
		return hil.CheckedChallenge{}, ErrUnavailable
	}
	value := checked.Value()
	session := request.Browser.session
	artifact := request.Artifact
	if sessionID != session.ID.String() || actorID != session.ActorID ||
		sessionDigest != session.TokenDigest.String() ||
		idempotencyDigest != request.Browser.idempotency.digest ||
		value.Operation != request.Operation || value.ResourceID != artifact.PolicyID() ||
		value.ResourceVersion != artifact.PolicyVersion() || value.TargetIPv4 != artifact.TargetIPv4() ||
		value.PolicyDigest != artifact.PolicyDigest() ||
		value.EvidenceSnapshotDigest != artifact.EvidenceSnapshotDigest() ||
		value.GeneratedArtifactDigest != artifact.GeneratedArtifactDigest() ||
		value.CanonicalArtifactDigest != artifact.CanonicalArtifactDigest() ||
		value.ValidationSnapshotDigest != artifact.ValidationSnapshotDigest() ||
		!value.ValidationValidUntil.Equal(artifact.ValidationValidUntil()) ||
		!value.AuthenticatedAt.Equal(session.AuthenticatedAt) {
		return hil.CheckedChallenge{}, ErrUnavailable
	}
	return checked, nil
}

func databaseTime(ctx context.Context, tx transaction) (time.Time, error) {
	var value time.Time
	if err := tx.QueryRow(ctx, databaseClockSQL).Scan(&value); err != nil {
		return time.Time{}, ErrUnavailable
	}
	value, ok := normalizeTime(value)
	if !ok {
		return time.Time{}, ErrUnavailable
	}
	return value, nil
}

func formatUUID(raw [16]byte) string {
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], raw[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], raw[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], raw[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], raw[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], raw[10:16])
	return string(encoded)
}
