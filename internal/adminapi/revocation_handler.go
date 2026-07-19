package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/adminstore"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/hilstore"
	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

type revocationRoute uint8

const (
	revocationChallengeRoute revocationRoute = iota + 1
	revocationDecisionRoute
)

const revocationPathPrefix = "/api/v1/enforcement-actions/"

type revocationChallengeEnvelope struct {
	Challenge               json.RawMessage `json:"challenge"`
	ChallengeNonce          string          `json:"challenge_nonce"`
	CanonicalRevokeArtifact string          `json:"canonical_revoke_artifact"`
	PolicyID                string          `json:"policy_id"`
	PolicyVersion           uint32          `json:"policy_version"`
}

func (revocationChallengeEnvelope) String() string {
	return "adminapi.revocationChallengeEnvelope{challenge:[REDACTED],nonce:[REDACTED],artifact:[REDACTED]}"
}

func (value revocationChallengeEnvelope) GoString() string { return value.String() }

type revocationDecisionEnvelope struct {
	Decision            json.RawMessage   `json:"decision"`
	RevocationID        string            `json:"revocation_id"`
	AuthorizationID     string            `json:"authorization_id"`
	AuthorizationDigest string            `json:"authorization_digest"`
	OutboxJobID         string            `json:"outbox_job_id"`
	AuditEventID        string            `json:"audit_event_id"`
	Session             SessionProjection `json:"session"`
	CSRFToken           string            `json:"csrf_token"`
}

func (revocationDecisionEnvelope) String() string {
	return "adminapi.revocationDecisionEnvelope{decision:[REDACTED],csrf:[REDACTED]}"
}

func (value revocationDecisionEnvelope) GoString() string { return value.String() }

type historicalRevocationEnvelope struct {
	Decision                 json.RawMessage `json:"decision"`
	RevocationID             string          `json:"revocation_id"`
	AuthorizationID          string          `json:"authorization_id"`
	AuthorizationDigest      string          `json:"authorization_digest"`
	OutboxJobID              string          `json:"outbox_job_id"`
	AuditEventID             string          `json:"audit_event_id"`
	Replayed                 bool            `json:"replayed"`
	ReauthenticationRequired bool            `json:"reauthentication_required"`
}

func (historicalRevocationEnvelope) String() string {
	return "adminapi.historicalRevocationEnvelope{decision:[REDACTED]}"
}

func (value historicalRevocationEnvelope) GoString() string { return value.String() }

func parseRevocationPath(path string) (string, revocationRoute, bool) {
	if !strings.HasPrefix(path, revocationPathPrefix) {
		return "", 0, false
	}
	remainder := strings.TrimPrefix(path, revocationPathPrefix)
	var suffix string
	var route revocationRoute
	switch {
	case strings.HasSuffix(remainder, "/revocation-challenges"):
		suffix, route = "/revocation-challenges", revocationChallengeRoute
	case strings.HasSuffix(remainder, "/revocations"):
		suffix, route = "/revocations", revocationDecisionRoute
	default:
		return "", 0, false
	}
	actionID := strings.TrimSuffix(remainder, suffix)
	if !policyIDPattern.MatchString(actionID) || strings.Contains(actionID, "/") {
		return "", 0, false
	}
	return actionID, route, true
}

func (handler *Handler) serveRevocationChallenge(
	writer http.ResponseWriter,
	request *http.Request,
	actionID string,
) {
	browser, failure := handler.prepareHILRequest(request)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	idempotency, _, failure := readIdempotencyKey(request)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	input, err := decodeRevocationChallengeRequest(request)
	if err != nil || !validRevocationBindingInput(input) {
		writeError(writer, http.StatusUnprocessableEntity, ErrorSchemaInvalid, 0)
		return
	}
	bound, err := hilstore.BindValidatedBrowserRequest(browser.record, idempotency)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	issued, err := handler.revocations.IssueRevocation(request.Context(), hilstore.RevocationIssueRequest{
		Browser:           bound,
		ActionID:          actionID,
		ActionVersion:     input.actionVersion,
		TargetIPv4:        input.targetIPv4,
		OriginalAddDigest: input.originalAddDigest,
	})
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	challenge, artifact, policyID, policyVersion, ok := checkedRevocationChallengeResponse(
		issued, browser.record, actionID, input,
	)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	nonce, err := issued.TakeNonce()
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	if !nonceMatchesDigest(nonce, challenge.Value().NonceDigest) {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	writeJSON(writer, http.StatusCreated, revocationChallengeEnvelope{
		Challenge:               challenge.CanonicalBytes(),
		ChallengeNonce:          nonce,
		CanonicalRevokeArtifact: string(artifact.CanonicalBytes()),
		PolicyID:                policyID,
		PolicyVersion:           policyVersion,
	})
}

func (handler *Handler) serveRevocationDecision(
	writer http.ResponseWriter,
	request *http.Request,
	actionID string,
) {
	browser, failure := handler.prepareHILRequest(request)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	idempotency, idempotencyDigest, failure := readIdempotencyKey(request)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	input, err := decodeRevocationDecisionRequest(request)
	if err != nil || !validRevocationDecisionInput(input) {
		clearRevocationDecisionInput(&input)
		writeError(writer, http.StatusUnprocessableEntity, ErrorSchemaInvalid, 0)
		return
	}
	defer clearRevocationDecisionInput(&input)
	lookup, challenge, artifact, failure := bindRevocationDecisionLookup(
		browser.record, idempotency, false, actionID, input,
	)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}

	rotation, err := handler.boundary.RotateAfterPrivilege(browser.record, string(browser.presentedToken))
	if err != nil {
		writeFailure(writer, authenticationFailure(err))
		return
	}
	defer rotation.ClearSecrets()
	commit, err := hilstore.BindPrivilegedRevocationCommit(lookup, browser.record, rotation)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	stored, err := handler.revocations.CommitRevocation(request.Context(), commit)
	if err != nil && errors.Is(err, hilstore.ErrUnavailable) {
		// The checked commit owns shared immutable material, so this is exactly
		// one retry of the same candidate IDs, DB-clock decision, and rotation.
		stored, err = handler.revocations.CommitRevocation(request.Context(), commit)
	}
	if err != nil {
		// Once the coordinator has been called, the old credential is unsafe:
		// the transaction may have committed while the response was lost.
		http.SetCookie(writer, handler.cookies.ExpiredCookie())
		historical, recovered, recoveryFailure := handler.recoverUncertainRevocation(
			request.Context(), browser.record, idempotency, idempotencyDigest,
			actionID, input,
		)
		if recoveryFailure != nil {
			writeFailure(writer, *recoveryFailure)
			return
		}
		if recovered {
			writeJSON(writer, http.StatusOK, historicalRevocationResponse(historical))
			return
		}
		writeFailure(writer, hilFailure(err))
		return
	}
	if !storedRevocationMatches(
		stored, browser.record, challenge, artifact, input.reason, idempotencyDigest,
		input.policyID, input.policyVersion,
	) {
		handler.expireSessionAndFail(writer, ErrorServiceUnavailable, http.StatusServiceUnavailable)
		return
	}
	if !stored.SessionRotated() {
		activeChild, loadErr := handler.sessions.LoadByID(request.Context(), rotation.Issued.Record.ID)
		if loadErr != nil {
			http.SetCookie(writer, handler.cookies.ExpiredCookie())
			writeFailure(writer, storeFailure(loadErr, true))
			return
		}
		if !sameSessionRecord(activeChild, rotation.Issued.Record) {
			handler.expireSessionAndFail(writer, ErrorServiceUnavailable, http.StatusServiceUnavailable)
			return
		}
	}
	cookie, err := handler.cookies.IssuedSessionCookie(rotation.Issued)
	if err != nil {
		handler.expireSessionAndFail(writer, ErrorAuthenticationRequired, http.StatusUnauthorized)
		return
	}
	http.SetCookie(writer, cookie)
	writeJSON(writer, http.StatusOK, revocationResponse(stored, rotation))
}

func (handler *Handler) serveHistoricalRevocationReplay(
	writer http.ResponseWriter,
	request *http.Request,
	actionID string,
) {
	browser, ok := authenticatedFromContext(request.Context())
	if !ok || browser.record.RevokedAt == nil {
		writeError(writer, http.StatusUnauthorized, ErrorAuthenticationRequired, 0)
		return
	}
	http.SetCookie(writer, handler.cookies.ExpiredCookie())
	if err := handler.allowDecisionFromContext(request.Context()); err != nil {
		writeFailure(writer, authenticationFailure(err))
		return
	}
	idempotency, idempotencyDigest, failure := readIdempotencyKey(request)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	input, err := decodeRevocationDecisionRequest(request)
	if err != nil || !validRevocationDecisionInput(input) {
		clearRevocationDecisionInput(&input)
		writeError(writer, http.StatusUnprocessableEntity, ErrorSchemaInvalid, 0)
		return
	}
	defer clearRevocationDecisionInput(&input)
	lookup, challenge, artifact, failure := bindRevocationDecisionLookup(
		browser.record, idempotency, true, actionID, input,
	)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	stored, err := handler.revocations.LookupHistoricalRevocation(request.Context(), lookup)
	if err != nil {
		if errors.Is(err, hilstore.ErrNotFound) {
			writeError(writer, http.StatusUnauthorized, ErrorAuthenticationRequired, 0)
			return
		}
		writeFailure(writer, hilFailure(err))
		return
	}
	if stored.SessionRotated() ||
		!storedRevocationMatches(
			stored, browser.record, challenge, artifact, input.reason, idempotencyDigest,
			input.policyID, input.policyVersion,
		) {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	if err := handler.revalidateHistoricalReplayParent(request.Context(), browser.record); err != nil {
		writeFailure(writer, storeFailure(err, true))
		return
	}
	writeJSON(writer, http.StatusOK, historicalRevocationResponse(stored))
}

func (handler *Handler) recoverUncertainRevocation(
	ctx context.Context,
	expected adminauth.SessionRecord,
	idempotency hilstore.IdempotencyKey,
	idempotencyDigest string,
	actionID string,
	input revocationDecisionInput,
) (RevocationStoredResult, bool, *requestFailure) {
	replayStore, ok := handler.sessions.(HistoricalDecisionReplaySessionStore)
	if !ok {
		failure := requestFailure{status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable}
		return nil, false, &failure
	}
	revoked, err := replayStore.LoadRevokedDecisionReplayParent(ctx, expected.ID)
	if err != nil {
		if errors.Is(err, adminstore.ErrNotFound) {
			return nil, false, nil
		}
		failure := storeFailure(err, true)
		return nil, false, &failure
	}
	if !sameReplayParent(expected, revoked) {
		failure := requestFailure{status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable}
		return nil, false, &failure
	}
	lookup, challenge, artifact, failure := bindRevocationDecisionLookup(
		revoked, idempotency, true, actionID, input,
	)
	if failure != nil {
		return nil, false, failure
	}
	stored, err := handler.revocations.LookupHistoricalRevocation(ctx, lookup)
	if err != nil {
		if errors.Is(err, hilstore.ErrNotFound) {
			return nil, false, nil
		}
		mapped := hilFailure(err)
		return nil, false, &mapped
	}
	if stored.SessionRotated() ||
		!storedRevocationMatches(
			stored, revoked, challenge, artifact, input.reason, idempotencyDigest,
			input.policyID, input.policyVersion,
		) {
		failure := requestFailure{status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable}
		return nil, false, &failure
	}
	// The unique-live-child proof is re-read after the potentially slow
	// historical result query, closing logout/expiry/second-rotation races.
	if err := handler.revalidateHistoricalReplayParent(ctx, revoked); err != nil {
		failure := storeFailure(err, true)
		return nil, false, &failure
	}
	return stored, true, nil
}

func bindRevocationDecisionLookup(
	record adminauth.SessionRecord,
	idempotency hilstore.IdempotencyKey,
	historical bool,
	actionID string,
	input revocationDecisionInput,
) (hilstore.RevocationLookup, hil.CheckedChallenge, lifecycleartifact.CheckedRevokeArtifact, *requestFailure) {
	challenge, err := hil.ParseCanonicalChallenge(input.challenge)
	if err != nil {
		failure := hilFailure(err)
		return hilstore.RevocationLookup{}, hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, &failure
	}
	if !nonceMatchesDigest(input.challengeNonce, challenge.Value().NonceDigest) {
		failure := requestFailure{status: http.StatusConflict, code: ErrorDigestMismatch}
		return hilstore.RevocationLookup{}, hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, &failure
	}
	nonce, err := hilstore.CheckDecisionNonce(input.challengeNonce)
	if err != nil {
		failure := hilFailure(err)
		return hilstore.RevocationLookup{}, hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, &failure
	}
	artifact, err := lifecycleartifact.ParseCanonicalRevokeArtifact(input.canonicalRevokeArtifact)
	if err != nil {
		failure := requestFailure{status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid}
		return hilstore.RevocationLookup{}, hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, &failure
	}
	if !revocationRoundTripMatches(record, actionID, input, challenge, artifact) {
		failure := requestFailure{status: http.StatusConflict, code: ErrorDigestMismatch}
		return hilstore.RevocationLookup{}, hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, &failure
	}
	var browser hilstore.BrowserRequest
	if historical {
		browser, err = hilstore.BindHistoricalReplayBrowserRequest(record, idempotency)
	} else {
		browser, err = hilstore.BindValidatedBrowserRequest(record, idempotency)
	}
	if err != nil {
		failure := hilFailure(err)
		return hilstore.RevocationLookup{}, hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, &failure
	}
	lookup, err := hilstore.BindRevocationLookup(hilstore.RevocationDecisionInput{
		Browser:                 browser,
		CanonicalChallenge:      input.challenge,
		CanonicalRevokeArtifact: input.canonicalRevokeArtifact,
		Nonce:                   nonce,
		Reason:                  input.reason,
		PolicyID:                input.policyID,
		PolicyVersion:           input.policyVersion,
	})
	if err != nil {
		failure := hilFailure(err)
		return hilstore.RevocationLookup{}, hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, &failure
	}
	return lookup, challenge, artifact, nil
}

func checkedRevocationChallengeResponse(
	issued RevocationIssuedChallenge,
	record adminauth.SessionRecord,
	actionID string,
	input revocationBindingInput,
) (hil.CheckedChallenge, lifecycleartifact.CheckedRevokeArtifact, string, uint32, bool) {
	if issued == nil {
		return hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, "", 0, false
	}
	bound := issued.Challenge()
	challenge, err := hil.ParseCanonicalChallenge(bound.CanonicalBytes())
	if err != nil || challenge.Digest() != bound.Digest() ||
		!bytes.Equal(challenge.CanonicalBytes(), bound.CanonicalBytes()) {
		return hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, "", 0, false
	}
	artifact, err := lifecycleartifact.ParseCanonicalRevokeArtifact(bound.RevokeArtifactBytes())
	if err != nil || artifact.Digest() != bound.RevokeArtifactDigest() ||
		!bytes.Equal(artifact.CanonicalBytes(), bound.RevokeArtifactBytes()) {
		return hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, "", 0, false
	}
	policyID, policyVersion := issued.PolicyID(), issued.PolicyVersion()
	if !policyIDPattern.MatchString(policyID) || policyVersion == 0 || policyVersion > 2_147_483_647 ||
		!revocationChallengeMatches(record, actionID, input, challenge, artifact, bound.EligibilityValidUntil()) {
		return hil.CheckedChallenge{}, lifecycleartifact.CheckedRevokeArtifact{}, "", 0, false
	}
	return challenge, artifact, policyID, policyVersion, true
}

func revocationChallengeMatches(
	record adminauth.SessionRecord,
	actionID string,
	input revocationBindingInput,
	challenge hil.CheckedChallenge,
	artifact lifecycleartifact.CheckedRevokeArtifact,
	eligibilityValidUntil time.Time,
) bool {
	value := challenge.Value()
	return value.Operation == hil.OperationRevoke && value.ResourceType == hil.ResourceEnforcementAction &&
		value.ResourceID == actionID && value.ResourceVersion == input.actionVersion &&
		value.TargetIPv4 == input.targetIPv4 && value.OriginalAddDigest != nil &&
		equalString(*value.OriginalAddDigest, input.originalAddDigest) &&
		equalString(value.SessionDigest, record.TokenDigest.String()) &&
		value.AuthenticatedAt.Equal(record.AuthenticatedAt) &&
		value.ReauthRequiredAfterSeconds == uint32(hil.ReauthAfter/time.Second) &&
		value.ExpiresAt.After(value.IssuedAt) && !value.ExpiresAt.After(record.ExpiresAt) &&
		value.ValidationValidUntil.Equal(eligibilityValidUntil) &&
		(value.ExpiresAt.Before(eligibilityValidUntil) || value.ExpiresAt.Equal(eligibilityValidUntil)) &&
		artifact.Value().TargetIPv4 == input.targetIPv4 &&
		equalString(value.GeneratedArtifactDigest, artifact.Digest()) &&
		equalString(value.CanonicalArtifactDigest, artifact.Digest()) &&
		sha256Pattern.MatchString(value.PolicyDigest) &&
		sha256Pattern.MatchString(value.EvidenceSnapshotDigest) &&
		sha256Pattern.MatchString(value.ValidationSnapshotDigest)
}

func revocationRoundTripMatches(
	record adminauth.SessionRecord,
	actionID string,
	input revocationDecisionInput,
	challenge hil.CheckedChallenge,
	artifact lifecycleartifact.CheckedRevokeArtifact,
) bool {
	if !validRevocationDecisionInput(input) || artifact.Value().TargetIPv4 != input.targetIPv4 {
		return false
	}
	value := challenge.Value()
	return value.Operation == hil.OperationRevoke && value.ResourceType == hil.ResourceEnforcementAction &&
		value.ResourceID == actionID && value.ResourceVersion == input.actionVersion &&
		value.TargetIPv4 == input.targetIPv4 && value.OriginalAddDigest != nil &&
		equalString(*value.OriginalAddDigest, input.originalAddDigest) &&
		equalString(value.SessionDigest, record.TokenDigest.String()) &&
		value.AuthenticatedAt.Equal(record.AuthenticatedAt) &&
		value.ReauthRequiredAfterSeconds == uint32(hil.ReauthAfter/time.Second) &&
		!value.ExpiresAt.After(record.ExpiresAt) &&
		equalString(value.GeneratedArtifactDigest, artifact.Digest()) &&
		equalString(value.CanonicalArtifactDigest, artifact.Digest()) &&
		value.GeneratedArtifactDigest == value.CanonicalArtifactDigest &&
		value.ValidationValidUntil.After(value.IssuedAt) &&
		!value.ExpiresAt.After(value.ValidationValidUntil)
}

func storedRevocationMatches(
	stored RevocationStoredResult,
	record adminauth.SessionRecord,
	challenge hil.CheckedChallenge,
	artifact lifecycleartifact.CheckedRevokeArtifact,
	reason hil.CheckedReason,
	idempotencyDigest string,
	policyID string,
	policyVersion uint32,
) bool {
	if stored == nil {
		return false
	}
	decision := stored.Decision()
	parsed, err := hil.ParseCanonicalDecision(decision.CanonicalBytes())
	if err != nil || parsed.Digest() != decision.Digest() ||
		!bytes.Equal(parsed.CanonicalBytes(), decision.CanonicalBytes()) ||
		decision.ChallengeDigest() != challenge.Digest() ||
		!bytes.Equal(decision.RevokeArtifactBytes(), artifact.CanonicalBytes()) ||
		decision.RevokeArtifactDigest() != artifact.Digest() ||
		!decision.EligibilityValidUntil().Equal(challenge.Value().ValidationValidUntil) {
		return false
	}
	storedReason, err := hil.ParseCanonicalReason(decision.ReasonCanonicalBytes())
	if err != nil || storedReason.Digest() != reason.Digest() ||
		!bytes.Equal(storedReason.CanonicalBytes(), reason.CanonicalBytes()) {
		return false
	}
	value := decision.Value()
	challengeValue := challenge.Value()
	if value.ChallengeID != challengeValue.ChallengeID ||
		value.SessionDigest != record.TokenDigest.String() ||
		value.Operation != hil.OperationRevoke || value.Decision != hil.DecisionRevoked ||
		value.ResourceType != hil.ResourceEnforcementAction ||
		value.ResourceID != challengeValue.ResourceID || value.ResourceVersion != challengeValue.ResourceVersion ||
		value.TargetIPv4 != challengeValue.TargetIPv4 || value.OriginalAddDigest == nil ||
		challengeValue.OriginalAddDigest == nil ||
		!equalString(*value.OriginalAddDigest, *challengeValue.OriginalAddDigest) ||
		value.ActorID != record.ActorID ||
		!equalString(value.PolicyDigest, challengeValue.PolicyDigest) ||
		!equalString(value.GeneratedArtifactDigest, artifact.Digest()) ||
		!equalString(value.CanonicalArtifactDigest, artifact.Digest()) ||
		!equalString(value.EvidenceSnapshotDigest, challengeValue.EvidenceSnapshotDigest) ||
		!equalString(value.ValidationSnapshotDigest, challengeValue.ValidationSnapshotDigest) ||
		!equalString(value.ReasonDigest, reason.Digest()) ||
		!equalString(value.NonceDigest, challengeValue.NonceDigest) ||
		!equalString(value.IdempotencyKeyDigest, idempotencyDigest) ||
		value.DecidedAt.Before(challengeValue.IssuedAt) || !value.DecidedAt.Before(challengeValue.ExpiresAt) ||
		value.DecisionValidUntil.After(challengeValue.ExpiresAt) ||
		value.DecisionValidUntil.After(challengeValue.ValidationValidUntil) ||
		value.DecisionValidUntil.After(record.ExpiresAt) {
		return false
	}
	ids := []string{
		stored.RevocationID(), stored.AuthorizationID(), stored.OutboxJobID(), stored.AuditEventID(),
	}
	seen := make(map[string]struct{}, len(ids)+1)
	seen[value.DecisionID] = struct{}{}
	for _, id := range ids {
		if !policyIDPattern.MatchString(id) {
			return false
		}
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		seen[id] = struct{}{}
	}
	expectedAuthorizationDigest, ok := revocationAuthorizationDigest(
		value, stored.AuthorizationID(), policyID, policyVersion,
	)
	return ok && equalString(stored.AuthorizationDigest(), expectedAuthorizationDigest)
}

// revocationAuthorizationDigest independently reconstructs the fixed
// enforcement-authorization-v1 JCS document from the checked decision and
// browser-roundtripped policy identity. This keeps adapter output untrusted:
// a different but syntactically valid digest cannot cross this boundary.
func revocationAuthorizationDigest(
	decision hil.Decision,
	authorizationID string,
	policyID string,
	policyVersion uint32,
) (string, bool) {
	if decision.Operation != hil.OperationRevoke || decision.Decision != hil.DecisionRevoked ||
		decision.ResourceType != hil.ResourceEnforcementAction || decision.OriginalAddDigest == nil ||
		!policyIDPattern.MatchString(decision.ResourceID) || !policyIDPattern.MatchString(authorizationID) ||
		!policyIDPattern.MatchString(policyID) || policyVersion == 0 || policyVersion > 2_147_483_647 ||
		!sha256Pattern.MatchString(decision.CanonicalArtifactDigest) ||
		!sha256Pattern.MatchString(decision.NonceDigest) ||
		!sha256Pattern.MatchString(decision.EvidenceSnapshotDigest) ||
		!sha256Pattern.MatchString(decision.GeneratedArtifactDigest) ||
		!sha256Pattern.MatchString(decision.ReasonDigest) ||
		!sha256Pattern.MatchString(decision.IdempotencyKeyDigest) ||
		!sha256Pattern.MatchString(*decision.OriginalAddDigest) ||
		!sha256Pattern.MatchString(decision.PolicyDigest) ||
		decision.DecidedAt.IsZero() || decision.DecisionValidUntil.IsZero() {
		return "", false
	}
	canonical := make([]byte, 0, 1536)
	canonical = appendRevocationAuthorizationPair(canonical, "action_id", decision.ResourceID, true)
	canonical = appendRevocationAuthorizationPair(canonical, "actor_id", decision.ActorID, false)
	canonical = appendRevocationAuthorizationPair(canonical, "authorization_id", authorizationID, false)
	canonical = appendRevocationAuthorizationPair(canonical, "authorization_kind", "revoke", false)
	canonical = appendRevocationAuthorizationPair(canonical, "canonical_artifact_digest", decision.CanonicalArtifactDigest, false)
	canonical = appendRevocationAuthorizationPair(canonical, "decided_at", decision.DecidedAt.UTC().Format(time.RFC3339Nano), false)
	canonical = appendRevocationAuthorizationPair(canonical, "decision", "revoke", false)
	canonical = appendRevocationAuthorizationPair(canonical, "decision_nonce_digest", decision.NonceDigest, false)
	canonical = appendRevocationAuthorizationPair(canonical, "evidence_snapshot_digest", decision.EvidenceSnapshotDigest, false)
	canonical = appendRevocationAuthorizationPair(canonical, "generated_artifact_digest", decision.GeneratedArtifactDigest, false)
	canonical = appendRevocationAuthorizationPair(canonical, "hil_reason_digest", decision.ReasonDigest, false)
	canonical = appendRevocationAuthorizationPair(canonical, "idempotency_key_digest", decision.IdempotencyKeyDigest, false)
	canonical = appendRevocationAuthorizationPair(canonical, "original_add_digest", *decision.OriginalAddDigest, false)
	canonical = appendRevocationAuthorizationPair(canonical, "policy_digest", decision.PolicyDigest, false)
	canonical = appendRevocationAuthorizationPair(canonical, "policy_id", policyID, false)
	canonical = append(canonical, `,"policy_version":`...)
	canonical = strconv.AppendUint(canonical, uint64(policyVersion), 10)
	canonical = appendRevocationAuthorizationPair(canonical, "schema_version", "enforcement-authorization-v1", false)
	canonical = appendRevocationAuthorizationPair(canonical, "target_ipv4", decision.TargetIPv4, false)
	canonical = appendRevocationAuthorizationPair(canonical, "valid_until", decision.DecisionValidUntil.UTC().Format(time.RFC3339Nano), false)
	canonical = append(canonical, '}')
	return digestBytes(canonical), true
}

func appendRevocationAuthorizationPair(destination []byte, key, value string, first bool) []byte {
	if first {
		destination = append(destination, '{')
	} else {
		destination = append(destination, ',')
	}
	destination = append(destination, '"')
	destination = append(destination, key...)
	destination = append(destination, '"', ':', '"')
	for index := range len(value) {
		if value[index] == '"' || value[index] == '\\' {
			destination = append(destination, '\\')
		}
		destination = append(destination, value[index])
	}
	return append(destination, '"')
}

func validRevocationBindingInput(input revocationBindingInput) bool {
	address, err := netip.ParseAddr(input.targetIPv4)
	return input.actionVersion > 0 && input.actionVersion <= 2_147_483_647 &&
		err == nil && address.Is4() && address.String() == input.targetIPv4 &&
		sha256Pattern.MatchString(input.originalAddDigest)
}

func validRevocationDecisionInput(input revocationDecisionInput) bool {
	if !validRevocationBindingInput(input.revocationBindingInput) ||
		!policyIDPattern.MatchString(input.policyID) || input.policyVersion == 0 ||
		input.policyVersion > 2_147_483_647 || len(input.challenge) == 0 ||
		len(input.canonicalRevokeArtifact) == 0 || input.challengeNonce == "" {
		return false
	}
	switch input.reason.Value().ReasonCode {
	case hil.ReasonEmergencyRevoke, hil.ReasonOperatorRequest, hil.ReasonOther:
		return input.reason.Digest() != ""
	default:
		return false
	}
}

func clearRevocationDecisionInput(input *revocationDecisionInput) {
	if input == nil {
		return
	}
	clear(input.challenge)
	clear(input.canonicalRevokeArtifact)
	input.challenge = nil
	input.canonicalRevokeArtifact = nil
	input.challengeNonce = ""
}

func sameReplayParent(expected, revoked adminauth.SessionRecord) bool {
	if expected.RevokedAt != nil || revoked.RevokedAt == nil || expected.ID != revoked.ID {
		return false
	}
	comparison := expected
	revokedAt := revoked.RevokedAt.Round(0).UTC()
	comparison.RevokedAt = &revokedAt
	return sameSessionRecord(comparison, revoked)
}

func revocationResponse(
	stored RevocationStoredResult,
	rotation adminauth.SessionRotation,
) revocationDecisionEnvelope {
	return revocationDecisionEnvelope{
		Decision:            stored.Decision().CanonicalBytes(),
		RevocationID:        stored.RevocationID(),
		AuthorizationID:     stored.AuthorizationID(),
		AuthorizationDigest: stored.AuthorizationDigest(),
		OutboxJobID:         stored.OutboxJobID(),
		AuditEventID:        stored.AuditEventID(),
		Session:             project(rotation.Issued.Record),
		CSRFToken:           rotation.Issued.CSRFToken(),
	}
}

func historicalRevocationResponse(stored RevocationStoredResult) historicalRevocationEnvelope {
	return historicalRevocationEnvelope{
		Decision:                 stored.Decision().CanonicalBytes(),
		RevocationID:             stored.RevocationID(),
		AuthorizationID:          stored.AuthorizationID(),
		AuthorizationDigest:      stored.AuthorizationDigest(),
		OutboxJobID:              stored.OutboxJobID(),
		AuditEventID:             stored.AuditEventID(),
		Replayed:                 true,
		ReauthenticationRequired: true,
	}
}
