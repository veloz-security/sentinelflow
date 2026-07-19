package hilstore

import (
	"bytes"
	"context"
	"time"

	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
	"github.com/jackc/pgx/v5"
)

// IssueRevocation derives and persists a fresh, exact revoke challenge through
// the database coordinator. PostgreSQL supplies the clock and lifecycle state;
// the returned bytes are reparsed and rebound before they leave this package.
func (s *PostgreSQLStore) IssueRevocation(
	ctx context.Context,
	request RevocationIssueRequest,
) (*IssuedRevocationChallenge, error) {
	if ctx == nil || s == nil || s.begin == nil || s.entropy == nil ||
		!validRevocationIssueRequest(request) {
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
	session := request.Browser.session
	row := tx.QueryRow(ctx, issueRevocationChallengeSQL,
		challengeID, nonceDigest, session.ID.String(), session.ActorID,
		session.TokenDigest.String(), session.CSRFDigest.String(),
		session.AuthenticatedAt.UTC(), session.ExpiresAt.UTC(),
		request.Browser.idempotency.digest, request.ActionID, request.ActionVersion,
		request.TargetIPv4, request.OriginalAddDigest,
	)
	checked, policyID, policyVersion, rowErr := scanRevocationChallenge(row, request)
	if rowErr != nil {
		return nil, classifyCoordinatorError(rowErr)
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !now.Before(checked.Value().ExpiresAt) ||
		!now.Before(checked.EligibilityValidUntil()) {
		return nil, ErrValidationStale
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ErrUnavailable
	}
	done = noRollback
	keepNonce = true
	return &IssuedRevocationChallenge{
		challenge: checked, policyID: policyID, policyVersion: policyVersion,
		nonce: nonce,
	}, nil
}

func scanRevocationChallenge(
	row pgx.Row,
	request RevocationIssueRequest,
) (hil.CheckedRevocationChallenge, string, uint32, error) {
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
		revokeArtifact             []byte
		policyID                   string
		policyVersion              int64
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
		&challengeDigest, &revokeArtifact, &policyID, &policyVersion,
	); err != nil {
		return hil.CheckedRevocationChallenge{}, "", 0, err
	}
	if resourceVersion < 1 || resourceVersion > 2_147_483_647 ||
		policyVersion < 1 || policyVersion > 2_147_483_647 || !validUUID(policyID) ||
		reauthRequiredAfterSeconds != int64(hil.ReauthAfter/time.Second) {
		return hil.CheckedRevocationChallenge{}, "", 0, ErrUnavailable
	}
	challenge.SchemaVersion = schemaVersion
	challenge.SessionDigest = sessionDigest
	challenge.Operation = hil.Operation(operation)
	challenge.ResourceType = resourceType
	challenge.ResourceVersion = uint32(resourceVersion)
	challenge.OriginalAddDigest = originalAddDigest
	challenge.NonceDigest = nonceDigest
	challenge.ReauthRequiredAfterSeconds = uint32(reauthRequiredAfterSeconds)
	checkedChallenge, err := hil.CheckChallenge(challenge)
	if err != nil || !bytes.Equal(challengeJCS, checkedChallenge.CanonicalBytes()) ||
		challengeDigest != checkedChallenge.Digest() {
		return hil.CheckedRevocationChallenge{}, "", 0, ErrUnavailable
	}
	artifact, err := lifecycleartifact.ParseCanonicalRevokeArtifact(revokeArtifact)
	if err != nil || artifact.Digest() != challenge.CanonicalArtifactDigest {
		return hil.CheckedRevocationChallenge{}, "", 0, ErrUnavailable
	}
	session := request.Browser.session
	if sessionID != session.ID.String() || sessionDigest != session.TokenDigest.String() ||
		actorID != session.ActorID || idempotencyDigest != request.Browser.idempotency.digest ||
		challenge.Operation != hil.OperationRevoke ||
		challenge.ResourceType != hil.ResourceEnforcementAction ||
		challenge.ResourceID != request.ActionID ||
		challenge.ResourceVersion != request.ActionVersion ||
		challenge.TargetIPv4 != request.TargetIPv4 ||
		challenge.OriginalAddDigest == nil || challenge.GeneratedArtifactDigest != artifact.Digest() ||
		*challenge.OriginalAddDigest != request.OriginalAddDigest ||
		challenge.CanonicalArtifactDigest != artifact.Digest() ||
		!challenge.AuthenticatedAt.Equal(session.AuthenticatedAt) {
		return hil.CheckedRevocationChallenge{}, "", 0, ErrConflict
	}
	binding, err := hil.CheckRevocationBinding(hil.RevocationBindingInput{
		ActionID: request.ActionID, ActionVersion: request.ActionVersion,
		TargetIPv4: challenge.TargetIPv4, OriginalAddDigest: *challenge.OriginalAddDigest,
		PolicyDigest:             challenge.PolicyDigest,
		EvidenceSnapshotDigest:   challenge.EvidenceSnapshotDigest,
		ValidationSnapshotDigest: challenge.ValidationSnapshotDigest,
		EligibilityValidUntil:    challenge.ValidationValidUntil,
		Session: hil.SessionBinding{
			SessionID: session.ID.String(), SessionDigest: session.TokenDigest.String(),
			ActorID: session.ActorID, AuthenticatedAt: session.AuthenticatedAt,
			ExpiresAt: session.ExpiresAt,
		},
		IdempotencyKeyDigest: request.Browser.idempotency.digest,
		Artifact:             artifact,
	})
	if err != nil {
		return hil.CheckedRevocationChallenge{}, "", 0, ErrUnavailable
	}
	bound, err := hil.BindRevocationChallenge(binding, checkedChallenge)
	if err != nil {
		return hil.CheckedRevocationChallenge{}, "", 0, ErrUnavailable
	}
	return bound, policyID, uint32(policyVersion), nil
}
