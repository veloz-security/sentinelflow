package hilstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"time"

	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/jackc/pgx/v5"
)

// LookupHistoricalRevocation returns an already committed exact revoke result
// for a Boundary-authenticated revoked parent. It performs no mutation,
// challenge issuance, authority creation, or session rotation.
func (s *PostgreSQLStore) LookupHistoricalRevocation(
	ctx context.Context,
	lookup RevocationLookup,
) (StoredRevocation, error) {
	if ctx == nil || s == nil || s.begin == nil || !lookup.Browser.historicalOnly ||
		!validRevocationLookup(lookup) {
		return StoredRevocation{}, ErrInvalidInput
	}
	tx, done, err := s.beginTransaction(ctx)
	if err != nil {
		return StoredRevocation{}, err
	}
	defer func() { done() }()
	stored, err := scanStoredRevocation(
		tx.QueryRow(ctx, lookupRevocationSQL, lookup.Browser.idempotency.digest), lookup,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredRevocation{}, ErrNotFound
	}
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return StoredRevocation{}, ErrConflict
		}
		return StoredRevocation{}, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return StoredRevocation{}, ErrUnavailable
	}
	done = noRollback
	return stored, nil
}

// CommitRevocation atomically consumes one exact revoke challenge, creates a
// version-bound authorization/revocation/outbox/audit set, and rotates the
// administrator session. One checked commit retains its first exact material
// for concurrent and response-loss retries.
func (s *PostgreSQLStore) CommitRevocation(
	ctx context.Context,
	commit PrivilegedRevocationCommit,
) (StoredRevocation, error) {
	if ctx == nil || s == nil || s.begin == nil || s.entropy == nil ||
		!validPrivilegedRevocationCommit(commit) {
		return StoredRevocation{}, ErrInvalidInput
	}
	commit.material.mu.Lock()
	defer commit.material.mu.Unlock()

	lookup := commit.lookup
	challenge := lookup.Challenge.Value()
	session := lookup.Browser.session
	if challenge.Operation != hil.OperationRevoke ||
		challenge.ResourceType != hil.ResourceEnforcementAction ||
		challenge.OriginalAddDigest == nil ||
		challenge.SessionDigest != session.TokenDigest.String() ||
		challenge.NonceDigest != lookup.Nonce.digest ||
		challenge.GeneratedArtifactDigest != lookup.Challenge.RevokeArtifactDigest() ||
		challenge.CanonicalArtifactDigest != lookup.Challenge.RevokeArtifactDigest() ||
		!challenge.AuthenticatedAt.Equal(session.AuthenticatedAt) {
		return StoredRevocation{}, ErrConflict
	}

	tx, done, err := s.beginTransaction(ctx)
	if err != nil {
		return StoredRevocation{}, err
	}
	defer func() { done() }()

	if !commit.material.initialized {
		now, clockErr := databaseTime(ctx, tx)
		if clockErr != nil {
			return StoredRevocation{}, clockErr
		}
		if err := s.initializeRevocationMaterial(commit.material, lookup, now); err != nil {
			return StoredRevocation{}, err
		}
	}
	material := commit.material
	identities := material.identities
	reason := lookup.Reason.Value()
	arguments := []any{
		session.ID.String(), session.ActorID, session.TokenDigest.String(),
		session.CSRFDigest.String(), session.AuthenticatedAt.UTC(), session.ExpiresAt.UTC(),
		challenge.ChallengeID, lookup.Challenge.CanonicalBytes(), lookup.Challenge.Digest(),
		lookup.Nonce.digest, lookup.Browser.idempotency.digest,
		challenge.ResourceID, challenge.ResourceVersion,
		lookup.policyID, lookup.policyVersion,
		lookup.Challenge.RevokeArtifactBytes(), lookup.Challenge.RevokeArtifactDigest(),
		identities[0], string(reason.ReasonCode), reason.ReasonText,
		lookup.Reason.CanonicalBytes(), lookup.Reason.Digest(), identities[1],
		material.decidedAt, material.validUntil, material.decision.CanonicalBytes(),
		material.decision.Digest(), identities[2], material.authorizationJCS,
		material.authorizationDigest, identities[3], identities[4], identities[5],
	}
	arguments = append(arguments, revocationRotationSuffix(commit)...)
	var (
		decisionID, revocationID, authorizationID string
		authorizationDigest, outboxID             string
		replayed, sessionRotated                  bool
	)
	if err := tx.QueryRow(ctx, commitRevocationSQL, arguments...).Scan(
		&decisionID, &revocationID, &authorizationID, &authorizationDigest,
		&outboxID, &replayed, &sessionRotated,
	); err != nil {
		return StoredRevocation{}, classifyCoordinatorError(err)
	}
	if decisionID != identities[1] || revocationID != identities[3] ||
		authorizationID != identities[2] || authorizationDigest != material.authorizationDigest ||
		outboxID != identities[4] || sessionRotated == replayed {
		return StoredRevocation{}, ErrConflict
	}
	if replayed {
		active, verifyErr := retainedRotationChildActive(ctx, tx, commit.replacement)
		if verifyErr != nil {
			return StoredRevocation{}, verifyErr
		}
		if !active {
			return StoredRevocation{}, ErrAuthentication
		}
	}
	stored, err := scanStoredRevocation(
		tx.QueryRow(ctx, lookupRevocationSQL, lookup.Browser.idempotency.digest), lookup,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrConflict) {
			return StoredRevocation{}, ErrConflict
		}
		return StoredRevocation{}, ErrUnavailable
	}
	if stored.Decision().Value().DecisionID != decisionID ||
		stored.RevocationID() != revocationID || stored.AuthorizationID() != authorizationID ||
		stored.AuthorizationDigest() != authorizationDigest || stored.OutboxJobID() != outboxID ||
		stored.AuditEventID() != identities[5] {
		return StoredRevocation{}, ErrConflict
	}
	stored.sessionRotated = sessionRotated
	if err := tx.Commit(ctx); err != nil {
		return StoredRevocation{}, ErrUnavailable
	}
	done = noRollback
	return stored, nil
}

func (s *PostgreSQLStore) initializeRevocationMaterial(
	material *revocationCommitMaterial,
	lookup RevocationLookup,
	now time.Time,
) error {
	if material == nil || material.initialized {
		return ErrInvalidInput
	}
	challenge := lookup.Challenge.Value()
	session := lookup.Browser.session
	decidedAt := now
	validUntil := minimumTime(
		decidedAt.Add(hil.DecisionLifetime), challenge.ExpiresAt,
		lookup.Challenge.EligibilityValidUntil(), session.ExpiresAt,
	)
	if !validUntil.After(decidedAt) {
		return ErrChallengeExpired
	}
	generated, err := s.newUUIDs(5)
	if err != nil {
		return err
	}
	identities := make([]string, 6)
	identities[0] = stableRevocationReasonID(session.ActorID, lookup.Reason.Digest())
	copy(identities[1:], generated)
	originalAddDigest := *challenge.OriginalAddDigest
	decision, err := hil.CheckDecision(hil.Decision{
		SchemaVersion: hil.DecisionSchemaVersion, DecisionID: identities[1],
		ChallengeID: challenge.ChallengeID, SessionDigest: session.TokenDigest.String(),
		Operation: hil.OperationRevoke, Decision: hil.DecisionRevoked,
		ResourceType: hil.ResourceEnforcementAction, ResourceID: challenge.ResourceID,
		ResourceVersion: challenge.ResourceVersion, TargetIPv4: challenge.TargetIPv4,
		PolicyDigest:             challenge.PolicyDigest,
		GeneratedArtifactDigest:  challenge.GeneratedArtifactDigest,
		CanonicalArtifactDigest:  challenge.CanonicalArtifactDigest,
		OriginalAddDigest:        &originalAddDigest,
		EvidenceSnapshotDigest:   challenge.EvidenceSnapshotDigest,
		ValidationSnapshotDigest: challenge.ValidationSnapshotDigest,
		ActorID:                  session.ActorID, ReasonDigest: lookup.Reason.Digest(),
		NonceDigest:          lookup.Nonce.digest,
		IdempotencyKeyDigest: lookup.Browser.idempotency.digest,
		DecidedAt:            decidedAt, DecisionValidUntil: validUntil,
	})
	if err != nil {
		return ErrInvalidInput
	}
	if _, err := hil.BindRevocationDecision(lookup.Challenge, decision, lookup.Reason); err != nil {
		return ErrConflict
	}
	authorizationJCS := marshalRevokeAuthorization(
		challenge.ResourceID, session.ActorID, identities[2], lookup.policyID,
		lookup.policyVersion, lookup, decidedAt, validUntil,
	)
	material.initialized = true
	material.decidedAt = decidedAt
	material.validUntil = validUntil
	material.identities = identities
	material.decision = decision
	material.authorizationJCS = authorizationJCS
	material.authorizationDigest = digestBytes(authorizationJCS)
	return nil
}

func stableRevocationReasonID(actorID, reasonDigest string) string {
	sum := sha256.Sum256([]byte(
		"sentinelflow/revocation-reason-id/v1\x00" + actorID + "\x00revoke\x00" + reasonDigest,
	))
	var raw [16]byte
	copy(raw[:], sum[:16])
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return formatUUID(raw)
}

func marshalRevokeAuthorization(
	actionID, actorID, authorizationID, policyID string,
	policyVersion uint32,
	lookup RevocationLookup,
	decidedAt, validUntil time.Time,
) []byte {
	challenge := lookup.Challenge.Value()
	result := make([]byte, 0, 1536)
	result = appendJSONPair(result, "action_id", actionID, true)
	result = appendJSONPair(result, "actor_id", actorID, false)
	result = appendJSONPair(result, "authorization_id", authorizationID, false)
	result = appendJSONPair(result, "authorization_kind", "revoke", false)
	result = appendJSONPair(result, "canonical_artifact_digest", challenge.CanonicalArtifactDigest, false)
	result = appendJSONPair(result, "decided_at", decidedAt.UTC().Format(time.RFC3339Nano), false)
	result = appendJSONPair(result, "decision", "revoke", false)
	result = appendJSONPair(result, "decision_nonce_digest", lookup.Nonce.digest, false)
	result = appendJSONPair(result, "evidence_snapshot_digest", challenge.EvidenceSnapshotDigest, false)
	result = appendJSONPair(result, "generated_artifact_digest", challenge.GeneratedArtifactDigest, false)
	result = appendJSONPair(result, "hil_reason_digest", lookup.Reason.Digest(), false)
	result = appendJSONPair(result, "idempotency_key_digest", lookup.Browser.idempotency.digest, false)
	result = appendJSONPair(result, "original_add_digest", *challenge.OriginalAddDigest, false)
	result = appendJSONPair(result, "policy_digest", challenge.PolicyDigest, false)
	result = appendJSONPair(result, "policy_id", policyID, false)
	result = append(result, `,"policy_version":`...)
	result = strconv.AppendUint(result, uint64(policyVersion), 10)
	result = appendJSONPair(result, "schema_version", "enforcement-authorization-v1", false)
	result = appendJSONPair(result, "target_ipv4", challenge.TargetIPv4, false)
	result = appendJSONPair(result, "valid_until", validUntil.UTC().Format(time.RFC3339Nano), false)
	return append(result, '}')
}

func scanStoredRevocation(row pgx.Row, lookup RevocationLookup) (StoredRevocation, error) {
	var (
		decision                                                         hil.Decision
		operation, decisionValue                                         string
		resourceVersion                                                  int64
		originalAddDigest                                                *string
		decisionJCS                                                      []byte
		decisionDigest                                                   string
		decisionValidationSnapshotID                                     string
		decisionOwnedSchemaDigest                                        string
		challengeJCS                                                     []byte
		challengeDigest                                                  string
		consumedAt                                                       *time.Time
		consumedDecisionID                                               *string
		reasonID, reasonActorID, reasonOperation, reasonCode, reasonText string
		reasonJCS                                                        []byte
		reasonDigest                                                     string
		authorizationID                                                  string
		authorizationJCS                                                 []byte
		authorizationDigest                                              string
		authorizationDecidedAt, authorizationValidUntil                  time.Time
		revocationID                                                     string
		actionVersion                                                    int64
		revokeArtifact                                                   []byte
		revokeArtifactDigest, revokeOriginalAddDigest, revokeState       string
		outboxID                                                         string
		outboxVersion                                                    int64
		outboxKind, outboxOperation                                      string
		outboxIdempotency                                                string
		dispatchArtifact                                                 []byte
		dispatchArtifactDigest, dispatchOriginalAddDigest                string
		dispatchAuthorizationDigest, dispatchAuthorizationID             string
		dispatchInspectionAuthorizationID                                *string
		dispatchPolicyID                                                 string
		dispatchPolicyVersion                                            int64
		dispatchTargetIPv4, dispatchEvidenceSnapshotDigest               string
		dispatchValidationSnapshotID, dispatchValidationSnapshotDigest   string
		dispatchActorID, dispatchReasonDigest, dispatchOwnedSchemaDigest string
		dispatchNotBefore, dispatchValidUntil                            time.Time
		auditEventID                                                     string
		auditCount                                                       int
	)
	if err := row.Scan(
		&decision.SchemaVersion, &decision.DecisionID, &decision.ChallengeID,
		&decision.SessionDigest, &operation, &decisionValue, &decision.ResourceType,
		&decision.ResourceID, &resourceVersion, &decision.TargetIPv4,
		&decision.PolicyDigest, &decision.GeneratedArtifactDigest,
		&decision.CanonicalArtifactDigest, &originalAddDigest,
		&decision.EvidenceSnapshotDigest, &decision.ValidationSnapshotDigest,
		&decisionValidationSnapshotID, &decisionOwnedSchemaDigest,
		&decision.ActorID, &decision.ReasonDigest, &decision.NonceDigest,
		&decision.IdempotencyKeyDigest, &decision.DecidedAt, &decision.DecisionValidUntil,
		&decisionJCS, &decisionDigest, &challengeJCS, &challengeDigest,
		&consumedAt, &consumedDecisionID, &reasonID, &reasonActorID,
		&reasonOperation, &reasonCode, &reasonText, &reasonJCS, &reasonDigest,
		&authorizationID, &authorizationJCS, &authorizationDigest,
		&authorizationDecidedAt, &authorizationValidUntil, &revocationID,
		&actionVersion, &revokeArtifact, &revokeArtifactDigest,
		&revokeOriginalAddDigest, &revokeState, &outboxID, &outboxVersion,
		&outboxKind, &outboxOperation, &outboxIdempotency,
		&dispatchArtifact, &dispatchArtifactDigest,
		&dispatchOriginalAddDigest, &dispatchAuthorizationDigest,
		&dispatchAuthorizationID, &dispatchInspectionAuthorizationID,
		&dispatchPolicyID, &dispatchPolicyVersion, &dispatchTargetIPv4,
		&dispatchEvidenceSnapshotDigest, &dispatchValidationSnapshotID,
		&dispatchValidationSnapshotDigest, &dispatchActorID,
		&dispatchReasonDigest, &dispatchOwnedSchemaDigest,
		&dispatchNotBefore, &dispatchValidUntil, &auditEventID, &auditCount,
	); err != nil {
		return StoredRevocation{}, err
	}
	if resourceVersion < 1 || resourceVersion > 2_147_483_647 ||
		actionVersion != resourceVersion || outboxVersion != resourceVersion ||
		!validUUID(decisionValidationSnapshotID) || !validDigest(decisionOwnedSchemaDigest) {
		return StoredRevocation{}, ErrUnavailable
	}
	decision.Operation = hil.Operation(operation)
	decision.Decision = hil.DecisionValue(decisionValue)
	decision.ResourceVersion = uint32(resourceVersion)
	decision.OriginalAddDigest = originalAddDigest
	checkedDecision, err := hil.CheckDecision(decision)
	if err != nil || !bytes.Equal(decisionJCS, checkedDecision.CanonicalBytes()) ||
		decisionDigest != checkedDecision.Digest() {
		return StoredRevocation{}, ErrUnavailable
	}
	storedChallenge, err := hil.ParseCanonicalChallenge(challengeJCS)
	if err != nil || storedChallenge.Digest() != challengeDigest ||
		storedChallenge.Digest() != lookup.Challenge.Digest() ||
		!bytes.Equal(storedChallenge.CanonicalBytes(), lookup.Challenge.CanonicalBytes()) {
		return StoredRevocation{}, ErrConflict
	}
	storedReason, err := hil.ParseCanonicalReason(reasonJCS)
	if err != nil || storedReason.Digest() != reasonDigest ||
		storedReason.Digest() != lookup.Reason.Digest() ||
		!bytes.Equal(storedReason.CanonicalBytes(), lookup.Reason.CanonicalBytes()) {
		return StoredRevocation{}, ErrConflict
	}
	boundDecision, err := hil.BindRevocationDecision(lookup.Challenge, checkedDecision, storedReason)
	if err != nil {
		return StoredRevocation{}, ErrConflict
	}
	challenge := lookup.Challenge.Value()
	expectedAuthorization := marshalRevokeAuthorization(
		challenge.ResourceID, decision.ActorID, authorizationID,
		lookup.policyID, lookup.policyVersion, lookup,
		decision.DecidedAt, decision.DecisionValidUntil,
	)
	if decision.ChallengeID != challenge.ChallengeID ||
		decision.SessionDigest != lookup.Browser.session.TokenDigest.String() ||
		decision.Operation != hil.OperationRevoke || decision.Decision != hil.DecisionRevoked ||
		decision.ResourceID != challenge.ResourceID ||
		decision.ResourceVersion != challenge.ResourceVersion ||
		decision.NonceDigest != lookup.Nonce.digest ||
		decision.IdempotencyKeyDigest != lookup.Browser.idempotency.digest ||
		consumedAt == nil || consumedDecisionID == nil || *consumedDecisionID != decision.DecisionID ||
		reasonID != stableRevocationReasonID(decision.ActorID, lookup.Reason.Digest()) ||
		reasonActorID != decision.ActorID || reasonOperation != "revoke" ||
		reasonCode != string(lookup.Reason.Value().ReasonCode) ||
		reasonText != lookup.Reason.Value().ReasonText {
		return StoredRevocation{}, ErrConflict
	}
	if !bytes.Equal(authorizationJCS, expectedAuthorization) ||
		authorizationDigest != digestBytes(expectedAuthorization) ||
		!authorizationDecidedAt.Equal(decision.DecidedAt) ||
		!authorizationValidUntil.Equal(decision.DecisionValidUntil) {
		return StoredRevocation{}, ErrConflict
	}
	if !validUUID(revocationID) || !validUUID(authorizationID) || !validUUID(outboxID) ||
		!validUUID(auditEventID) ||
		!bytes.Equal(revokeArtifact, lookup.Challenge.RevokeArtifactBytes()) ||
		revokeArtifactDigest != lookup.Challenge.RevokeArtifactDigest() ||
		revokeOriginalAddDigest != *challenge.OriginalAddDigest ||
		(revokeState != "authorized" && revokeState != "queued" && revokeState != "revoked" &&
			revokeState != "failed" && revokeState != "indeterminate") {
		return StoredRevocation{}, ErrConflict
	}
	if outboxKind != "dispatch_revoke" || outboxOperation != "revoke" ||
		outboxIdempotency != authorizationDigest ||
		!bytes.Equal(authorizationJCS, expectedAuthorization) ||
		!bytes.Equal(dispatchArtifact, revokeArtifact) ||
		dispatchArtifactDigest != revokeArtifactDigest ||
		dispatchOriginalAddDigest != revokeOriginalAddDigest ||
		dispatchAuthorizationDigest != authorizationDigest ||
		dispatchAuthorizationID != authorizationID ||
		dispatchInspectionAuthorizationID != nil ||
		dispatchPolicyID != lookup.policyID ||
		dispatchPolicyVersion != int64(lookup.policyVersion) ||
		dispatchTargetIPv4 != challenge.TargetIPv4 ||
		dispatchEvidenceSnapshotDigest != challenge.EvidenceSnapshotDigest ||
		dispatchValidationSnapshotID != decisionValidationSnapshotID ||
		dispatchValidationSnapshotDigest != challenge.ValidationSnapshotDigest ||
		dispatchActorID != decision.ActorID || dispatchReasonDigest != decision.ReasonDigest ||
		dispatchOwnedSchemaDigest != decisionOwnedSchemaDigest ||
		!dispatchNotBefore.Equal(authorizationDecidedAt) ||
		!dispatchValidUntil.Equal(authorizationValidUntil) || auditCount != 1 {
		return StoredRevocation{}, ErrConflict
	}
	return StoredRevocation{
		decision: boundDecision, revocationID: revocationID,
		authorizationID: authorizationID, authorizationDigest: authorizationDigest,
		outboxJobID: outboxID, auditEventID: auditEventID,
	}, nil
}
