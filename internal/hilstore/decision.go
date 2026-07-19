package hilstore

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/jackc/pgx/v5"
)

// LookupHistoricalDecision returns only an already committed exact decision,
// including after the bound old session was revoked. A caller that retained
// the original checked lookup may use it after response loss when replacement
// secrets/candidate are unavailable; it cannot recover or reissue those
// secrets, and a new client request still requires reauthentication. It is
// explicitly read-only and can neither rotate a session nor create a decision,
// authorization, action, outbox job, or audit event.
func (s *PostgreSQLStore) LookupHistoricalDecision(ctx context.Context, lookup DecisionLookup) (StoredDecision, error) {
	if ctx == nil || s == nil || s.begin == nil || !validDecisionLookup(lookup) {
		return StoredDecision{}, ErrInvalidInput
	}
	tx, done, err := s.beginTransaction(ctx)
	if err != nil {
		return StoredDecision{}, err
	}
	defer func() { done() }()
	stored, err := scanStoredDecision(tx.QueryRow(ctx, lookupDecisionSQL, lookup.Browser.idempotency.digest), lookup)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredDecision{}, ErrNotFound
	}
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return StoredDecision{}, ErrConflict
		}
		return StoredDecision{}, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return StoredDecision{}, ErrUnavailable
	}
	done = noRollback
	return stored, nil
}

func validDecisionLookup(value DecisionLookup) bool {
	challenge := value.Challenge.Value()
	reason := value.Reason.Value()
	browserValid := validSessionProjection(value.Browser.session)
	if value.Browser.historicalOnly {
		browserValid = validHistoricalSessionProjection(value.Browser.session)
	}
	return browserValid &&
		validDigest(value.Browser.idempotency.digest) && validDigest(value.Nonce.digest) &&
		validExactArtifact(value.Artifact) && value.Challenge.Digest() != "" &&
		validUUID(challenge.ChallengeID) && reason.SchemaVersion == hil.ReasonSchemaVersion &&
		validDigest(value.Reason.Digest()) && len(value.Reason.CanonicalBytes()) > 0
}

func scanStoredDecision(row pgx.Row, lookup DecisionLookup) (StoredDecision, error) {
	var (
		decision                    hil.Decision
		operation                   string
		decisionValue               string
		resourceVersion             int64
		originalAddDigest           *string
		challengeSessionID          string
		challengeAuthenticatedAt    time.Time
		challengeValidationUntil    time.Time
		challengeIssuedAt           time.Time
		challengeExpiresAt          time.Time
		challengeConsumedAt         *time.Time
		challengeConsumedDecisionID *string
		reasonActorID               string
		reasonOperation             string
		normalizedReason            string
		policyState                 string
		generatedCommand            string
		canonicalArtifact           []byte
		validationCreatedAt         time.Time
		validationValidUntil        time.Time
		authorizationDigest         *string
		authorizationActionID       *string
		actionID                    *string
		outboxCount                 int
		outboxJobID                 *string
		challengeJCS                []byte
		challengeDigest             string
		reasonCode                  string
		reasonJCS                   []byte
		decisionJCS                 []byte
		decisionDigest              string
		authorizationJCS            []byte
		authorizationID             *string
		authorizationDecidedAt      *time.Time
		authorizationValidUntil     *time.Time
	)
	if err := row.Scan(
		&decision.SchemaVersion, &decision.DecisionID, &decision.ChallengeID,
		&decision.SessionDigest, &operation, &decisionValue, &decision.ResourceType,
		&decision.ResourceID, &resourceVersion, &decision.TargetIPv4,
		&decision.PolicyDigest, &decision.GeneratedArtifactDigest,
		&decision.CanonicalArtifactDigest, &originalAddDigest,
		&decision.EvidenceSnapshotDigest, &decision.ValidationSnapshotDigest,
		&decision.ActorID, &decision.ReasonDigest, &decision.NonceDigest,
		&decision.IdempotencyKeyDigest, &decision.DecidedAt, &decision.DecisionValidUntil,
		&challengeSessionID, &challengeAuthenticatedAt, &challengeValidationUntil,
		&challengeIssuedAt, &challengeExpiresAt, &challengeConsumedAt,
		&challengeConsumedDecisionID, &reasonActorID, &reasonOperation,
		&normalizedReason, &policyState, &generatedCommand, &canonicalArtifact,
		&validationCreatedAt, &validationValidUntil, &authorizationDigest,
		&authorizationActionID, &actionID, &outboxCount, &outboxJobID,
		&challengeJCS, &challengeDigest, &reasonCode, &reasonJCS,
		&decisionJCS, &decisionDigest, &authorizationJCS,
		&authorizationID, &authorizationDecidedAt, &authorizationValidUntil,
	); err != nil {
		return StoredDecision{}, err
	}
	if resourceVersion < 1 || resourceVersion > 2_147_483_647 {
		return StoredDecision{}, ErrUnavailable
	}
	decision.Operation = hil.Operation(operation)
	decision.Decision = hil.DecisionValue(decisionValue)
	decision.ResourceVersion = uint32(resourceVersion)
	decision.OriginalAddDigest = originalAddDigest
	checked, err := hil.CheckDecision(decision)
	if err != nil {
		return StoredDecision{}, ErrUnavailable
	}
	if !bytes.Equal(decisionJCS, checked.CanonicalBytes()) || decisionDigest != checked.Digest() {
		return StoredDecision{}, ErrUnavailable
	}
	storedChallenge, err := hil.ParseCanonicalChallenge(challengeJCS)
	if err != nil || storedChallenge.Digest() != challengeDigest ||
		storedChallenge.Digest() != lookup.Challenge.Digest() ||
		!bytes.Equal(storedChallenge.CanonicalBytes(), lookup.Challenge.CanonicalBytes()) {
		return StoredDecision{}, ErrConflict
	}
	storedReason, err := hil.ParseCanonicalReason(reasonJCS)
	if err != nil || storedReason.Digest() != lookup.Reason.Digest() ||
		!bytes.Equal(storedReason.CanonicalBytes(), lookup.Reason.CanonicalBytes()) ||
		string(storedReason.Value().ReasonCode) != reasonCode {
		return StoredDecision{}, ErrConflict
	}

	challenge := lookup.Challenge.Value()
	session := lookup.Browser.session
	artifact := lookup.Artifact
	reason := lookup.Reason.Value()
	if decision.ChallengeID != challenge.ChallengeID ||
		decision.SessionDigest != session.TokenDigest.String() ||
		decision.Operation != challenge.Operation || decision.ResourceType != hil.ResourcePolicy ||
		decision.ResourceID != artifact.PolicyID() || decision.ResourceVersion != artifact.PolicyVersion() ||
		decision.TargetIPv4 != artifact.TargetIPv4() || decision.PolicyDigest != artifact.PolicyDigest() ||
		decision.GeneratedArtifactDigest != artifact.GeneratedArtifactDigest() ||
		decision.CanonicalArtifactDigest != artifact.CanonicalArtifactDigest() ||
		decision.OriginalAddDigest != nil ||
		decision.EvidenceSnapshotDigest != artifact.EvidenceSnapshotDigest() ||
		decision.ValidationSnapshotDigest != artifact.ValidationSnapshotDigest() ||
		decision.ActorID != session.ActorID || decision.ReasonDigest != lookup.Reason.Digest() ||
		decision.NonceDigest != lookup.Nonce.digest ||
		decision.IdempotencyKeyDigest != lookup.Browser.idempotency.digest ||
		challengeSessionID != session.ID.String() ||
		!challengeAuthenticatedAt.Equal(challenge.AuthenticatedAt) ||
		!challengeValidationUntil.Equal(challenge.ValidationValidUntil) ||
		!challengeIssuedAt.Equal(challenge.IssuedAt) || !challengeExpiresAt.Equal(challenge.ExpiresAt) ||
		challengeConsumedAt == nil || challengeConsumedDecisionID == nil ||
		*challengeConsumedDecisionID != decision.DecisionID ||
		reasonActorID != session.ActorID || reasonOperation != string(challenge.Operation) ||
		normalizedReason != reason.ReasonText ||
		generatedCommand != string(artifact.GeneratedBytes()) ||
		!bytes.Equal(canonicalArtifact, artifact.CanonicalBytes()) ||
		!validationCreatedAt.Equal(artifact.ValidationCreatedAt()) ||
		!validationValidUntil.Equal(artifact.ValidationValidUntil()) {
		return StoredDecision{}, ErrConflict
	}

	approved := decision.Operation == hil.OperationApprove && decision.Decision == hil.DecisionApproved
	rejected := decision.Operation == hil.OperationReject && decision.Decision == hil.DecisionRejected
	if approved {
		if policyState != "approved" && policyState != "queued" && policyState != "active" &&
			policyState != "expired" && policyState != "failed" && policyState != "revoked" &&
			policyState != "indeterminate" {
			return StoredDecision{}, ErrUnavailable
		}
		if authorizationDigest == nil || !validDigest(*authorizationDigest) ||
			authorizationActionID == nil || actionID == nil || *authorizationActionID != *actionID ||
			authorizationID == nil || !validUUID(*authorizationID) ||
			authorizationDecidedAt == nil || authorizationValidUntil == nil ||
			!authorizationDecidedAt.Equal(decision.DecidedAt) ||
			!authorizationValidUntil.Equal(decision.DecisionValidUntil) ||
			!validUUID(*actionID) || outboxCount != 1 || outboxJobID == nil || !validUUID(*outboxJobID) {
			return StoredDecision{}, ErrUnavailable
		}
		checkedValue := checked.Value()
		expectedAuthorization := marshalAddAuthorization(
			*actionID, decision.ActorID, *authorizationID, artifact, lookup,
			checkedValue.DecidedAt, checkedValue.DecisionValidUntil,
		)
		if !bytes.Equal(authorizationJCS, expectedAuthorization) ||
			*authorizationDigest != digestBytes(expectedAuthorization) {
			return StoredDecision{}, ErrUnavailable
		}
		return StoredDecision{
			decision: checked, actionID: *actionID,
			authorizationDigest: *authorizationDigest, outboxJobID: *outboxJobID,
		}, nil
	}
	if !rejected || policyState != "rejected" || authorizationDigest != nil ||
		authorizationActionID != nil || actionID != nil || outboxCount != 0 || outboxJobID != nil ||
		authorizationJCS != nil || authorizationID != nil || authorizationDecidedAt != nil ||
		authorizationValidUntil != nil {
		return StoredDecision{}, ErrUnavailable
	}
	return StoredDecision{decision: checked}, nil
}
