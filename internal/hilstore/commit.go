package hilstore

import (
	"context"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Commit atomically persists a checked approve/reject decision and its exact
// ordinary privileged session rotation. Fresh commits must rotate; an exact
// in-process/transport replay must retain and reuse the original checked
// rotation candidate, verifies the persisted child, and never rotates again.
// If an HTTP response loss also loses the replacement plaintext secrets, they
// cannot be reconstructed from PostgreSQL; use LookupHistoricalDecision for
// the decision result and require a new login for session recovery.
func (s *PostgreSQLStore) Commit(ctx context.Context, commit PrivilegedDecisionCommit) (StoredDecision, error) {
	if ctx == nil || s == nil || s.begin == nil || s.entropy == nil ||
		!validPrivilegedDecisionCommit(commit) {
		return StoredDecision{}, ErrInvalidInput
	}
	request := commit.lookup
	challenge := request.Challenge.Value()
	session := request.Browser.session
	artifact := request.Artifact
	if challenge.Operation != hil.OperationApprove && challenge.Operation != hil.OperationReject ||
		challenge.SessionDigest != session.TokenDigest.String() ||
		challenge.ResourceID != artifact.PolicyID() ||
		challenge.ResourceVersion != artifact.PolicyVersion() ||
		challenge.TargetIPv4 != artifact.TargetIPv4() ||
		challenge.PolicyDigest != artifact.PolicyDigest() ||
		challenge.EvidenceSnapshotDigest != artifact.EvidenceSnapshotDigest() ||
		challenge.GeneratedArtifactDigest != artifact.GeneratedArtifactDigest() ||
		challenge.CanonicalArtifactDigest != artifact.CanonicalArtifactDigest() ||
		challenge.ValidationSnapshotDigest != artifact.ValidationSnapshotDigest() ||
		!challenge.ValidationValidUntil.Equal(artifact.ValidationValidUntil()) ||
		!challenge.AuthenticatedAt.Equal(session.AuthenticatedAt) ||
		challenge.NonceDigest != request.Nonce.digest {
		return StoredDecision{}, ErrConflict
	}

	tx, done, err := s.beginTransaction(ctx)
	if err != nil {
		return StoredDecision{}, err
	}
	defer func() { done() }()

	now, err := databaseTime(ctx, tx)
	if err != nil {
		return StoredDecision{}, err
	}
	decidedAt := now
	validUntil := minimumTime(decidedAt.Add(hil.DecisionLifetime), challenge.ExpiresAt,
		artifact.ValidationValidUntil(), session.ExpiresAt)
	if !validUntil.After(decidedAt) {
		// The coordinator owns freshness and may still return the original exact
		// decision for a logical retry after expiry. Give that replay path a valid
		// but non-authoritative historical proposal; a fresh expired request still
		// fails closed inside the locked coordinator.
		decidedAt = challenge.IssuedAt
		validUntil = minimumTime(decidedAt.Add(hil.DecisionLifetime), challenge.ExpiresAt,
			artifact.ValidationValidUntil(), session.ExpiresAt)
		if !validUntil.After(decidedAt) {
			return StoredDecision{}, ErrConflict
		}
	}

	identities, err := s.newUUIDs(6)
	if err != nil {
		return StoredDecision{}, err
	}
	decisionValue := hil.DecisionRejected
	if challenge.Operation == hil.OperationApprove {
		decisionValue = hil.DecisionApproved
	}
	decision, err := hil.CheckDecision(hil.Decision{
		SchemaVersion: hil.DecisionSchemaVersion, DecisionID: identities[1],
		ChallengeID: challenge.ChallengeID, SessionDigest: session.TokenDigest.String(),
		Operation: challenge.Operation, Decision: decisionValue, ResourceType: hil.ResourcePolicy,
		ResourceID: artifact.PolicyID(), ResourceVersion: artifact.PolicyVersion(),
		TargetIPv4: artifact.TargetIPv4(), PolicyDigest: artifact.PolicyDigest(),
		GeneratedArtifactDigest:  artifact.GeneratedArtifactDigest(),
		CanonicalArtifactDigest:  artifact.CanonicalArtifactDigest(),
		EvidenceSnapshotDigest:   artifact.EvidenceSnapshotDigest(),
		ValidationSnapshotDigest: artifact.ValidationSnapshotDigest(),
		ActorID:                  session.ActorID, ReasonDigest: request.Reason.Digest(),
		NonceDigest:          request.Nonce.digest,
		IdempotencyKeyDigest: request.Browser.idempotency.digest,
		DecidedAt:            decidedAt, DecisionValidUntil: validUntil,
	})
	if err != nil {
		return StoredDecision{}, ErrInvalidInput
	}

	var authorizationID, actionID, outboxID any
	var authorizationJCS []byte
	var authorizationDigest any
	if challenge.Operation == hil.OperationApprove {
		authorizationID, actionID, outboxID = identities[2], identities[3], identities[4]
		authorizationJCS = marshalAddAuthorization(
			identities[3], session.ActorID, identities[2], artifact, request,
			decidedAt, validUntil,
		)
		authorizationDigest = digestBytes(authorizationJCS)
	}

	arguments := []any{
		session.ID.String(), session.ActorID, session.TokenDigest.String(), session.CSRFDigest.String(),
		session.AuthenticatedAt.UTC(), session.ExpiresAt.UTC(), challenge.ChallengeID,
		request.Challenge.CanonicalBytes(), request.Challenge.Digest(), request.Nonce.digest,
		request.Browser.idempotency.digest, string(challenge.Operation), artifact.PolicyID(),
		artifact.PolicyVersion(), artifact.TargetIPv4(), artifact.PolicyDigest(),
		artifact.EvidenceSnapshotDigest(), artifact.GeneratedArtifactDigest(),
		artifact.CanonicalArtifactDigest(), artifact.ValidationSnapshotDigest(),
		string(artifact.GeneratedBytes()), artifact.CanonicalBytes(), artifact.ValidationCreatedAt().UTC(),
		artifact.ValidationValidUntil().UTC(), artifact.TTLSeconds(), identities[0],
		string(request.Reason.Value().ReasonCode), request.Reason.Value().ReasonText,
		request.Reason.CanonicalBytes(), request.Reason.Digest(), identities[1], decidedAt, validUntil,
		decision.CanonicalBytes(), decision.Digest(), authorizationID, actionID, outboxID,
		authorizationJCS, authorizationDigest, identities[5],
	}
	arguments = append(arguments, privilegedSessionRotationSuffix(commit)...)
	var committedID string
	var replayed bool
	var sessionRotated bool
	if err := tx.QueryRow(ctx, commitDecisionSQL, arguments...).Scan(
		&committedID, &replayed, &sessionRotated,
	); err != nil {
		return StoredDecision{}, classifyCoordinatorError(err)
	}
	if !validUUID(committedID) || sessionRotated == replayed {
		return StoredDecision{}, ErrUnavailable
	}
	if replayed {
		active, verifyErr := retainedRotationChildActive(ctx, tx, commit.replacement)
		if verifyErr != nil {
			return StoredDecision{}, verifyErr
		}
		if !active {
			return StoredDecision{}, ErrAuthentication
		}
	}

	stored, err := scanStoredDecision(
		tx.QueryRow(ctx, lookupDecisionSQL, request.Browser.idempotency.digest), request,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrConflict) {
			return StoredDecision{}, ErrConflict
		}
		return StoredDecision{}, ErrUnavailable
	}
	if stored.Decision().Value().DecisionID != committedID {
		return StoredDecision{}, ErrConflict
	}
	if replayed && stored.Decision().Value().IdempotencyKeyDigest != request.Browser.idempotency.digest {
		return StoredDecision{}, ErrConflict
	}
	stored.sessionRotated = sessionRotated
	if err := tx.Commit(ctx); err != nil {
		return StoredDecision{}, ErrUnavailable
	}
	done = noRollback
	return stored, nil
}

func retainedRotationChildActive(ctx context.Context, tx transaction, replacement adminauth.SessionRecord) (bool, error) {
	if ctx == nil || tx == nil || !validSessionProjection(replacement) || replacement.RotationParentID == nil {
		return false, ErrInvalidInput
	}
	var active bool
	err := tx.QueryRow(ctx, verifyRetainedRotationChildSQL,
		replacement.ID.String(), replacement.ActorID,
		replacement.TokenDigest.String(), replacement.CSRFDigest.String(),
		replacement.AuthenticatedAt.UTC(), replacement.CreatedAt.UTC(),
		replacement.LastSeenAt.UTC(), replacement.ExpiresAt.UTC(),
		replacement.RotationParentID.String(),
	).Scan(&active)
	if err != nil {
		return false, ErrUnavailable
	}
	return active, nil
}

func validPrivilegedDecisionCommit(value PrivilegedDecisionCommit) bool {
	if !validDecisionLookup(value.lookup) || value.lookup.Browser.historicalOnly ||
		!sameSession(value.expected, value.lookup.Browser.session) ||
		value.rotationAt.IsZero() {
		return false
	}
	revoked := value.expected
	revoked.LastSeenAt = value.rotationAt
	revokedAt := value.rotationAt
	revoked.RevokedAt = &revokedAt
	return validPrivilegeRotation(value.expected, revoked, value.replacement)
}

func privilegedSessionRotationSuffix(commit PrivilegedDecisionCommit) []any {
	expected := commit.expected
	replacement := commit.replacement
	var expectedParent any
	if expected.RotationParentID != nil {
		expectedParent = expected.RotationParentID.String()
	}
	return []any{
		expected.CreatedAt.UTC(), expected.LastSeenAt.UTC(), expectedParent,
		commit.rotationAt.UTC(), replacement.ID.String(), replacement.ActorID,
		replacement.TokenDigest.String(), replacement.CSRFDigest.String(), replacement.AuthenticatedAt.UTC(),
		replacement.CreatedAt.UTC(), replacement.LastSeenAt.UTC(), replacement.ExpiresAt.UTC(),
		replacement.RotationParentID.String(),
	}
}

func (s *PostgreSQLStore) newUUIDs(count int) ([]string, error) {
	if s == nil || s.entropy == nil || count < 1 || count > 16 {
		return nil, ErrUnavailable
	}
	result := make([]string, count)
	s.entropyMu.Lock()
	defer s.entropyMu.Unlock()
	for index := range result {
		var raw [16]byte
		if _, err := io.ReadFull(s.entropy, raw[:]); err != nil {
			clear(raw[:])
			return nil, ErrUnavailable
		}
		raw[6] = raw[6]&0x0f | 0x40
		raw[8] = raw[8]&0x3f | 0x80
		result[index] = formatUUID(raw)
		clear(raw[:])
	}
	return result, nil
}

func minimumTime(first time.Time, rest ...time.Time) time.Time {
	result := first
	for _, value := range rest {
		if value.Before(result) {
			result = value
		}
	}
	return result
}

func marshalAddAuthorization(actionID, actorID, authorizationID string, artifact hil.ExactArtifact,
	request DecisionLookup, decidedAt, validUntil time.Time,
) []byte {
	result := make([]byte, 0, 1536)
	result = appendJSONPair(result, "action_id", actionID, true)
	result = appendJSONPair(result, "actor_id", actorID, false)
	result = appendJSONPair(result, "authorization_id", authorizationID, false)
	result = appendJSONPair(result, "authorization_kind", "add", false)
	result = appendJSONPair(result, "canonical_artifact_digest", artifact.CanonicalArtifactDigest(), false)
	result = appendJSONPair(result, "decided_at", decidedAt.Format(time.RFC3339Nano), false)
	result = appendJSONPair(result, "decision", "approve", false)
	result = appendJSONPair(result, "decision_nonce_digest", request.Nonce.digest, false)
	result = appendJSONPair(result, "evidence_snapshot_digest", artifact.EvidenceSnapshotDigest(), false)
	result = appendJSONPair(result, "generated_artifact_digest", artifact.GeneratedArtifactDigest(), false)
	result = appendJSONPair(result, "hil_reason_digest", request.Reason.Digest(), false)
	result = appendJSONPair(result, "idempotency_key_digest", request.Browser.idempotency.digest, false)
	result = append(result, `,"original_add_digest":null`...)
	result = appendJSONPair(result, "policy_digest", artifact.PolicyDigest(), false)
	result = appendJSONPair(result, "policy_id", artifact.PolicyID(), false)
	result = append(result, `,"policy_version":`...)
	result = strconv.AppendUint(result, uint64(artifact.PolicyVersion()), 10)
	result = appendJSONPair(result, "schema_version", "enforcement-authorization-v1", false)
	result = appendJSONPair(result, "target_ipv4", artifact.TargetIPv4(), false)
	result = appendJSONPair(result, "valid_until", validUntil.Format(time.RFC3339Nano), false)
	return append(result, '}')
}

func appendJSONPair(destination []byte, key, value string, first bool) []byte {
	if first {
		destination = append(destination, '{')
	} else {
		destination = append(destination, ',')
	}
	destination = append(destination, '"')
	destination = append(destination, key...)
	destination = append(destination, '"', ':')
	return appendJSONString(destination, value)
}

func appendJSONString(destination []byte, value string) []byte {
	destination = append(destination, '"')
	for _, current := range []byte(value) {
		if current == '"' || current == '\\' {
			destination = append(destination, '\\')
		}
		destination = append(destination, current)
	}
	return append(destination, '"')
}

func classifyCoordinatorError(err error) error {
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return ErrUnavailable
	}
	switch databaseError.Code {
	case "SF001":
		return ErrInvalidInput
	case "SF002":
		return ErrAuthentication
	case "SF003":
		return ErrStepUpRequired
	case "SF004":
		return ErrValidationFailed
	case "SF005":
		return ErrValidationStale
	case "SF006":
		return ErrChallengeExpired
	case "SF007":
		return ErrNotFound
	case "SF008", "23505":
		return ErrConflict
	default:
		return ErrUnavailable
	}
}
