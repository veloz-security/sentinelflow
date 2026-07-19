package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/adminstore"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/hilstore"
)

type policyHILRoute uint8

const (
	policyHILChallengeRoute policyHILRoute = iota + 1
	policyHILDecisionRoute
)

const policyHILPathPrefix = "/api/v1/policies/"

var (
	policyIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sha256Pattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type challengeEnvelope struct {
	Challenge      json.RawMessage `json:"challenge"`
	ChallengeNonce string          `json:"challenge_nonce"`
}

func (challengeEnvelope) String() string {
	return "adminapi.challengeEnvelope{challenge:[REDACTED],nonce:[REDACTED]}"
}

func (value challengeEnvelope) GoString() string { return value.String() }

type decisionEnvelope struct {
	Decision            json.RawMessage   `json:"decision"`
	ActionID            *string           `json:"action_id"`
	AuthorizationDigest *string           `json:"authorization_digest"`
	OutboxJobID         *string           `json:"outbox_job_id"`
	Session             SessionProjection `json:"session"`
	CSRFToken           string            `json:"csrf_token"`
}

func (decisionEnvelope) String() string {
	return "adminapi.decisionEnvelope{decision:[REDACTED],csrf:[REDACTED]}"
}

func (value decisionEnvelope) GoString() string { return value.String() }

type historicalDecisionEnvelope struct {
	Decision                 json.RawMessage `json:"decision"`
	ActionID                 *string         `json:"action_id"`
	AuthorizationDigest      *string         `json:"authorization_digest"`
	OutboxJobID              *string         `json:"outbox_job_id"`
	Replayed                 bool            `json:"replayed"`
	ReauthenticationRequired bool            `json:"reauthentication_required"`
}

func (historicalDecisionEnvelope) String() string {
	return "adminapi.historicalDecisionEnvelope{decision:[REDACTED]}"
}

func (value historicalDecisionEnvelope) GoString() string { return value.String() }

func parsePolicyHILPath(path string) (string, policyHILRoute, bool) {
	if !strings.HasPrefix(path, policyHILPathPrefix) {
		return "", 0, false
	}
	remainder := strings.TrimPrefix(path, policyHILPathPrefix)
	var suffix string
	var route policyHILRoute
	switch {
	case strings.HasSuffix(remainder, "/decision-challenges"):
		suffix, route = "/decision-challenges", policyHILChallengeRoute
	case strings.HasSuffix(remainder, "/decisions"):
		suffix, route = "/decisions", policyHILDecisionRoute
	default:
		return "", 0, false
	}
	policyID := strings.TrimSuffix(remainder, suffix)
	if !policyIDPattern.MatchString(policyID) || strings.Contains(policyID, "/") {
		return "", 0, false
	}
	return policyID, route, true
}

func (handler *Handler) servePolicyDecisionChallenge(writer http.ResponseWriter, request *http.Request, policyID string) {
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
	input, err := decodeChallengeRequest(request)
	if err != nil || !validArtifactBindingInput(input) {
		writeError(writer, http.StatusUnprocessableEntity, ErrorSchemaInvalid, 0)
		return
	}
	artifact, failure := handler.loadAndMatchExactArtifact(request.Context(), policyID, input)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	bound, err := hilstore.BindValidatedBrowserRequest(browser.record, idempotency)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	issued, err := handler.hil.Issue(request.Context(), hilstore.IssueRequest{
		Operation: input.operation, Browser: bound, Artifact: artifact,
	})
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	if issued == nil {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	challenge := issued.Challenge()
	if !challengeMatches(challenge, browser.record, artifact, input.operation) {
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
	writeJSON(writer, http.StatusCreated, challengeEnvelope{
		Challenge: challenge.CanonicalBytes(), ChallengeNonce: nonce,
	})
}

func (handler *Handler) servePolicyDecision(writer http.ResponseWriter, request *http.Request, policyID string) {
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
	input, err := decodeDecisionRequest(request)
	if err != nil || !validArtifactBindingInput(input.artifact) {
		writeError(writer, http.StatusUnprocessableEntity, ErrorSchemaInvalid, 0)
		return
	}
	defer clear(input.challenge)
	challenge, err := hil.ParseCanonicalChallenge(input.challenge)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	if !nonceMatchesDigest(input.challengeNonce, challenge.Value().NonceDigest) {
		writeError(writer, http.StatusConflict, ErrorDigestMismatch, 0)
		return
	}
	nonce, err := hilstore.CheckDecisionNonce(input.challengeNonce)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	artifact, artifactFailure := handler.loadAndMatchExactArtifact(request.Context(), policyID, input.artifact)
	if artifactFailure != nil {
		writeFailure(writer, *artifactFailure)
		return
	}
	if !challengeMatches(challenge, browser.record, artifact, input.artifact.operation) {
		writeError(writer, http.StatusConflict, ErrorDigestMismatch, 0)
		return
	}
	bound, err := hilstore.BindValidatedBrowserRequest(browser.record, idempotency)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	lookup := hilstore.DecisionLookup{
		Browser: bound, Challenge: challenge, Nonce: nonce, Artifact: artifact, Reason: input.reason,
	}
	if stored, lookupErr := handler.hil.LookupHistoricalDecision(request.Context(), lookup); lookupErr == nil {
		if !storedDecisionMatches(stored, browser.record, challenge, artifact, input.reason, idempotencyDigest) {
			handler.expireSessionAndFail(writer, ErrorServiceUnavailable, http.StatusServiceUnavailable)
			return
		}
		// An already committed decision cannot coexist with a live old session
		// when the coordinator's atomic rotation invariant holds.
		handler.expireSessionAndFail(writer, ErrorServiceUnavailable, http.StatusServiceUnavailable)
		return
	} else if !errors.Is(lookupErr, hilstore.ErrNotFound) {
		writeFailure(writer, hilFailure(lookupErr))
		return
	}

	rotation, err := handler.boundary.RotateAfterPrivilege(browser.record, string(browser.presentedToken))
	if err != nil {
		writeFailure(writer, authenticationFailure(err))
		return
	}
	defer rotation.ClearSecrets()
	commit, err := hilstore.BindPrivilegedDecisionCommit(lookup, browser.record, rotation)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	stored, err := handler.hil.Commit(request.Context(), commit)
	if err != nil && errors.Is(err, hilstore.ErrUnavailable) {
		// One exact retry is safe: the coordinator either performs the one
		// intended commit or verifies the already persisted rotation child is
		// byte-for-byte the candidate whose plaintext secrets remain in memory.
		stored, err = handler.hil.Commit(request.Context(), commit)
	}
	if err != nil {
		// Once the coordinator was invoked, the browser cannot safely keep using
		// the old cookie: the transaction may have committed even when its result
		// was lost. Force reauthentication on every unresolved outcome.
		http.SetCookie(writer, handler.cookies.ExpiredCookie())
		// If commit state is still uncertain, an exact historical lookup may
		// return only the durable business result. It never fabricates or
		// reconstructs replacement bearer/CSRF credentials.
		if historical, historicalErr := handler.hil.LookupHistoricalDecision(request.Context(), lookup); historicalErr == nil &&
			storedDecisionMatches(historical, browser.record, challenge, artifact, input.reason, idempotencyDigest) {
			if replayErr := handler.revalidateHistoricalReplayParent(request.Context(), browser.record); replayErr != nil {
				writeFailure(writer, storeFailure(replayErr, true))
				return
			}
			writeJSON(writer, http.StatusOK, historicalDecisionResponse(historical))
			return
		}
		writeFailure(writer, hilFailure(err))
		return
	}
	if !storedDecisionMatches(stored, browser.record, challenge, artifact, input.reason, idempotencyDigest) {
		handler.expireSessionAndFail(writer, ErrorServiceUnavailable, http.StatusServiceUnavailable)
		return
	}
	if !stored.SessionRotated() {
		// An exact coordinator retry may return retained replacement secrets only
		// while PostgreSQL still proves that exact child is live. Logout, a second
		// rotation, expiry, idle timeout, mismatch, or store unavailability must
		// never cause stale credentials to be reissued.
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
	// A successful Commit with SessionRotated=false is an exact coordinator
	// replay that verified this same retained replacement candidate. It is safe
	// to return the candidate secrets once; no second rotation occurred.
	cookie, err := handler.cookies.IssuedSessionCookie(rotation.Issued)
	if err != nil {
		handler.expireSessionAndFail(writer, ErrorAuthenticationRequired, http.StatusUnauthorized)
		return
	}
	http.SetCookie(writer, cookie)
	writeJSON(writer, http.StatusOK, decisionResponse(stored, rotation))
}

func (handler *Handler) serveHistoricalPolicyDecisionReplay(writer http.ResponseWriter, request *http.Request, policyID string) {
	browser, ok := authenticatedFromContext(request.Context())
	if !ok || browser.record.RevokedAt == nil {
		writeError(writer, http.StatusUnauthorized, ErrorAuthenticationRequired, 0)
		return
	}
	// The old credential is never useful after this response, including on
	// schema, conflict, or persistence failure.
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
	input, err := decodeDecisionRequest(request)
	if err != nil || !validArtifactBindingInput(input.artifact) {
		writeError(writer, http.StatusUnprocessableEntity, ErrorSchemaInvalid, 0)
		return
	}
	defer clear(input.challenge)
	challenge, err := hil.ParseCanonicalChallenge(input.challenge)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	if !nonceMatchesDigest(input.challengeNonce, challenge.Value().NonceDigest) {
		writeError(writer, http.StatusConflict, ErrorDigestMismatch, 0)
		return
	}
	nonce, err := hilstore.CheckDecisionNonce(input.challengeNonce)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	artifact, artifactFailure := handler.loadAndMatchHistoricalExactArtifact(
		request.Context(), policyID, input.artifact,
	)
	if artifactFailure != nil {
		writeFailure(writer, *artifactFailure)
		return
	}
	if !challengeMatches(challenge, browser.record, artifact, input.artifact.operation) {
		writeError(writer, http.StatusConflict, ErrorDigestMismatch, 0)
		return
	}
	bound, err := hilstore.BindHistoricalReplayBrowserRequest(browser.record, idempotency)
	if err != nil {
		writeFailure(writer, hilFailure(err))
		return
	}
	lookup := hilstore.DecisionLookup{
		Browser: bound, Challenge: challenge, Nonce: nonce, Artifact: artifact, Reason: input.reason,
	}
	stored, err := handler.hil.LookupHistoricalDecision(request.Context(), lookup)
	if err != nil {
		if errors.Is(err, hilstore.ErrNotFound) {
			writeError(writer, http.StatusUnauthorized, ErrorAuthenticationRequired, 0)
			return
		}
		writeFailure(writer, hilFailure(err))
		return
	}
	if stored.SessionRotated() ||
		!storedDecisionMatches(stored, browser.record, challenge, artifact, input.reason, idempotencyDigest) {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	if err := handler.revalidateHistoricalReplayParent(request.Context(), browser.record); err != nil {
		writeFailure(writer, storeFailure(err, true))
		return
	}
	writeJSON(writer, http.StatusOK, historicalDecisionResponse(stored))
}

// revalidateHistoricalReplayParent places the child-active/database-clock
// linearization point after every potentially slow artifact and decision read.
// It accepts an active pre-commit projection only when persistence returns the
// same row with a database-authored revoked_at; an already-revoked projection
// must remain byte-identical. It never converts unavailability into absence.
func (handler *Handler) revalidateHistoricalReplayParent(ctx context.Context, expected adminauth.SessionRecord) error {
	if handler == nil || handler.sessions == nil {
		return adminstore.ErrUnavailable
	}
	store, ok := handler.sessions.(HistoricalDecisionReplaySessionStore)
	if !ok {
		return adminstore.ErrUnavailable
	}
	current, err := store.LoadRevokedDecisionReplayParent(ctx, expected.ID)
	if err != nil {
		return err
	}
	if current.RevokedAt == nil {
		return adminstore.ErrUnavailable
	}
	comparison := expected
	if comparison.RevokedAt == nil {
		revokedAt := current.RevokedAt.Round(0).UTC()
		comparison.RevokedAt = &revokedAt
	}
	if !sameSessionRecord(current, comparison) {
		return adminstore.ErrUnavailable
	}
	return nil
}

func (handler *Handler) prepareHILRequest(request *http.Request) (authenticatedBrowser, *requestFailure) {
	browser, ok := authenticatedFromContext(request.Context())
	if !ok {
		failure := requestFailure{status: http.StatusUnauthorized, code: ErrorAuthenticationRequired}
		return authenticatedBrowser{}, &failure
	}
	if err := handler.allowDecisionFromContext(request.Context()); err != nil {
		failure := authenticationFailure(err)
		return authenticatedBrowser{}, &failure
	}
	required, err := handler.requiresStepUpFromContext(request.Context())
	if err != nil {
		failure := authenticationFailure(err)
		return authenticatedBrowser{}, &failure
	}
	if required {
		failure := requestFailure{status: http.StatusUnauthorized, code: ErrorStepUpRequired}
		return authenticatedBrowser{}, &failure
	}
	return browser, nil
}

func readIdempotencyKey(request *http.Request) (hilstore.IdempotencyKey, string, *requestFailure) {
	if request == nil {
		failure := requestFailure{status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid}
		return hilstore.IdempotencyKey{}, "", &failure
	}
	values := request.Header.Values("Idempotency-Key")
	request.Header.Del("Idempotency-Key")
	if len(values) != 1 {
		failure := requestFailure{status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid}
		return hilstore.IdempotencyKey{}, "", &failure
	}
	raw := []byte(values[0])
	defer clear(raw)
	checked, err := hilstore.CheckIdempotencyKey(raw)
	if err != nil {
		failure := requestFailure{status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid}
		return hilstore.IdempotencyKey{}, "", &failure
	}
	return checked, digestBytes(raw), nil
}

func (handler *Handler) loadAndMatchExactArtifact(ctx context.Context, policyID string, input artifactBindingInput) (hil.ExactArtifact, *requestFailure) {
	artifact, err := handler.exactArtifacts.LoadExactArtifact(ctx, policyID, input.policyVersion)
	if err != nil {
		failure := exactArtifactFailure(err)
		return hil.ExactArtifact{}, &failure
	}
	if artifact.PolicyID() != policyID || artifact.PolicyVersion() != input.policyVersion {
		failure := requestFailure{status: http.StatusConflict, code: ErrorStaleVersion}
		return hil.ExactArtifact{}, &failure
	}
	if !artifactMatchesInput(artifact, input) {
		failure := requestFailure{status: http.StatusConflict, code: ErrorDigestMismatch}
		return hil.ExactArtifact{}, &failure
	}
	return artifact, nil
}

func (handler *Handler) loadAndMatchHistoricalExactArtifact(ctx context.Context, policyID string, input artifactBindingInput) (hil.ExactArtifact, *requestFailure) {
	artifact, err := handler.exactArtifacts.LoadHistoricalExactArtifact(ctx, policyID, input.policyVersion)
	if err != nil {
		failure := exactArtifactFailure(err)
		return hil.ExactArtifact{}, &failure
	}
	if artifact.PolicyID() != policyID || artifact.PolicyVersion() != input.policyVersion {
		failure := requestFailure{status: http.StatusConflict, code: ErrorStaleVersion}
		return hil.ExactArtifact{}, &failure
	}
	if !artifactMatchesInput(artifact, input) {
		failure := requestFailure{status: http.StatusConflict, code: ErrorDigestMismatch}
		return hil.ExactArtifact{}, &failure
	}
	return artifact, nil
}

func validArtifactBindingInput(input artifactBindingInput) bool {
	address, err := netip.ParseAddr(input.targetIPv4)
	return (input.operation == hil.OperationApprove || input.operation == hil.OperationReject) &&
		input.policyVersion >= 1 && input.policyVersion <= 2_147_483_647 &&
		err == nil && address.Is4() && address.String() == input.targetIPv4 &&
		input.ttlSeconds >= 60 && input.ttlSeconds <= 86400 &&
		sha256Pattern.MatchString(input.policyDigest) &&
		sha256Pattern.MatchString(input.generatedArtifactDigest) &&
		sha256Pattern.MatchString(input.canonicalArtifactDigest) &&
		sha256Pattern.MatchString(input.evidenceSnapshotDigest) &&
		sha256Pattern.MatchString(input.validationSnapshotDigest)
}

func artifactMatchesInput(artifact hil.ExactArtifact, input artifactBindingInput) bool {
	return artifact.PolicyVersion() == input.policyVersion && artifact.TargetIPv4() == input.targetIPv4 &&
		artifact.TTLSeconds() == input.ttlSeconds && equalString(artifact.PolicyDigest(), input.policyDigest) &&
		equalString(artifact.GeneratedArtifactDigest(), input.generatedArtifactDigest) &&
		equalString(artifact.CanonicalArtifactDigest(), input.canonicalArtifactDigest) &&
		equalString(artifact.EvidenceSnapshotDigest(), input.evidenceSnapshotDigest) &&
		equalString(artifact.ValidationSnapshotDigest(), input.validationSnapshotDigest)
}

func challengeMatches(challenge hil.CheckedChallenge, record adminauth.SessionRecord, artifact hil.ExactArtifact, operation hil.Operation) bool {
	parsed, err := hil.ParseCanonicalChallenge(challenge.CanonicalBytes())
	if err != nil || parsed.Digest() != challenge.Digest() || !bytes.Equal(parsed.CanonicalBytes(), challenge.CanonicalBytes()) {
		return false
	}
	value := challenge.Value()
	return value.Operation == operation && value.ResourceType == hil.ResourcePolicy && value.ResourceID == artifact.PolicyID() &&
		value.ResourceVersion == artifact.PolicyVersion() && value.TargetIPv4 == artifact.TargetIPv4() &&
		equalString(value.SessionDigest, record.TokenDigest.String()) && value.OriginalAddDigest == nil &&
		equalString(value.PolicyDigest, artifact.PolicyDigest()) &&
		equalString(value.GeneratedArtifactDigest, artifact.GeneratedArtifactDigest()) &&
		equalString(value.CanonicalArtifactDigest, artifact.CanonicalArtifactDigest()) &&
		equalString(value.EvidenceSnapshotDigest, artifact.EvidenceSnapshotDigest()) &&
		equalString(value.ValidationSnapshotDigest, artifact.ValidationSnapshotDigest()) &&
		value.ValidationValidUntil.Equal(artifact.ValidationValidUntil()) &&
		value.AuthenticatedAt.Equal(record.AuthenticatedAt) && !value.ExpiresAt.After(record.ExpiresAt) &&
		value.ReauthRequiredAfterSeconds == uint32(hil.ReauthAfter/time.Second)
}

func storedDecisionMatches(stored HILStoredDecision, record adminauth.SessionRecord, challenge hil.CheckedChallenge,
	artifact hil.ExactArtifact, reason hil.CheckedReason, idempotencyDigest string,
) bool {
	if stored == nil {
		return false
	}
	decision := stored.Decision()
	parsed, err := hil.ParseCanonicalDecision(decision.CanonicalBytes())
	if err != nil || parsed.Digest() != decision.Digest() || !bytes.Equal(parsed.CanonicalBytes(), decision.CanonicalBytes()) {
		return false
	}
	value := decision.Value()
	challengeValue := challenge.Value()
	expectedDecision := hil.DecisionRejected
	if challengeValue.Operation == hil.OperationApprove {
		expectedDecision = hil.DecisionApproved
	}
	if value.ChallengeID != challengeValue.ChallengeID || value.SessionDigest != record.TokenDigest.String() ||
		value.Operation != challengeValue.Operation || value.Decision != expectedDecision ||
		value.ResourceType != hil.ResourcePolicy || value.ResourceID != artifact.PolicyID() ||
		value.ResourceVersion != artifact.PolicyVersion() || value.TargetIPv4 != artifact.TargetIPv4() ||
		value.OriginalAddDigest != nil || value.ActorID != record.ActorID ||
		!equalString(value.PolicyDigest, artifact.PolicyDigest()) ||
		!equalString(value.GeneratedArtifactDigest, artifact.GeneratedArtifactDigest()) ||
		!equalString(value.CanonicalArtifactDigest, artifact.CanonicalArtifactDigest()) ||
		!equalString(value.EvidenceSnapshotDigest, artifact.EvidenceSnapshotDigest()) ||
		!equalString(value.ValidationSnapshotDigest, artifact.ValidationSnapshotDigest()) ||
		!equalString(value.ReasonDigest, reason.Digest()) ||
		!equalString(value.NonceDigest, challengeValue.NonceDigest) ||
		!equalString(value.IdempotencyKeyDigest, idempotencyDigest) ||
		value.DecidedAt.Before(challengeValue.IssuedAt) || !value.DecidedAt.Before(challengeValue.ExpiresAt) ||
		value.DecisionValidUntil.After(challengeValue.ExpiresAt) ||
		value.DecisionValidUntil.After(artifact.ValidationValidUntil()) || value.DecisionValidUntil.After(record.ExpiresAt) {
		return false
	}
	if value.Operation == hil.OperationApprove {
		return policyIDPattern.MatchString(stored.ActionID()) && sha256Pattern.MatchString(stored.AuthorizationDigest()) &&
			policyIDPattern.MatchString(stored.OutboxJobID())
	}
	return stored.ActionID() == "" && stored.AuthorizationDigest() == "" && stored.OutboxJobID() == ""
}

func decisionResponse(stored HILStoredDecision, rotation adminauth.SessionRotation) decisionEnvelope {
	response := decisionEnvelope{
		Decision: stored.Decision().CanonicalBytes(), Session: project(rotation.Issued.Record),
		CSRFToken: rotation.Issued.CSRFToken(),
	}
	if value := stored.ActionID(); value != "" {
		response.ActionID = &value
	}
	if value := stored.AuthorizationDigest(); value != "" {
		response.AuthorizationDigest = &value
	}
	if value := stored.OutboxJobID(); value != "" {
		response.OutboxJobID = &value
	}
	return response
}

func historicalDecisionResponse(stored HILStoredDecision) historicalDecisionEnvelope {
	response := historicalDecisionEnvelope{
		Decision: stored.Decision().CanonicalBytes(), Replayed: true, ReauthenticationRequired: true,
	}
	if value := stored.ActionID(); value != "" {
		response.ActionID = &value
	}
	if value := stored.AuthorizationDigest(); value != "" {
		response.AuthorizationDigest = &value
	}
	if value := stored.OutboxJobID(); value != "" {
		response.OutboxJobID = &value
	}
	return response
}

func (handler *Handler) expireSessionAndFail(writer http.ResponseWriter, code ErrorCode, status int) {
	http.SetCookie(writer, handler.cookies.ExpiredCookie())
	writeError(writer, status, code, 0)
}

func exactArtifactFailure(err error) requestFailure {
	switch {
	case errors.Is(err, ErrExactArtifactNotFound):
		return requestFailure{status: http.StatusNotFound, code: ErrorNotFound}
	case errors.Is(err, ErrExactArtifactStale):
		return requestFailure{status: http.StatusConflict, code: ErrorStaleVersion}
	default:
		return requestFailure{status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable}
	}
}

func hilFailure(err error) requestFailure {
	var limited *adminauth.RateLimitError
	if errors.As(err, &limited) {
		return requestFailure{status: http.StatusTooManyRequests, code: ErrorRateLimited, retryAfter: limited.RetryAfter}
	}
	switch {
	case errors.Is(err, hilstore.ErrAuthentication), hil.IsCode(err, hil.ErrorAuthentication):
		return requestFailure{status: http.StatusUnauthorized, code: ErrorAuthenticationRequired}
	case errors.Is(err, hilstore.ErrStepUpRequired), hil.IsCode(err, hil.ErrorStepUpRequired):
		return requestFailure{status: http.StatusUnauthorized, code: ErrorStepUpRequired}
	case errors.Is(err, hilstore.ErrChallengeExpired), hil.IsCode(err, hil.ErrorChallengeExpired):
		return requestFailure{status: http.StatusUnprocessableEntity, code: ErrorChallengeExpired}
	case hil.IsCode(err, hil.ErrorConsumed):
		return requestFailure{status: http.StatusConflict, code: ErrorChallengeConsumed}
	case errors.Is(err, hilstore.ErrConflict), hil.IsCode(err, hil.ErrorConflict):
		return requestFailure{status: http.StatusConflict, code: ErrorIdempotencyConflict}
	case hil.IsCode(err, hil.ErrorArtifactMismatch), hil.IsCode(err, hil.ErrorChallengeMismatch):
		return requestFailure{status: http.StatusConflict, code: ErrorDigestMismatch}
	case errors.Is(err, hilstore.ErrValidationFailed), errors.Is(err, hilstore.ErrValidationStale),
		hil.IsCode(err, hil.ErrorValidationFailed), hil.IsCode(err, hil.ErrorValidationStale):
		return requestFailure{status: http.StatusUnprocessableEntity, code: ErrorValidationFailed}
	case errors.Is(err, hilstore.ErrInvalidInput), hil.IsCode(err, hil.ErrorSchema),
		hil.IsCode(err, hil.ErrorField), hil.IsCode(err, hil.ErrorDigest), hil.IsCode(err, hil.ErrorTime),
		hil.IsCode(err, hil.ErrorReason), hil.IsCode(err, hil.ErrorArtifact), hil.IsCode(err, hil.ErrorNonce),
		hil.IsCode(err, hil.ErrorIdempotency), hil.IsCode(err, hil.ErrorCanonical), hil.IsCode(err, hil.ErrorEncoding):
		return requestFailure{status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid}
	case errors.Is(err, hilstore.ErrNotFound):
		return requestFailure{status: http.StatusNotFound, code: ErrorNotFound}
	default:
		return requestFailure{status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable}
	}
}

func nonceMatchesDigest(encoded, expected string) bool {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(hil.NonceBytes) {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != hil.NonceBytes || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		clear(raw)
		return false
	}
	digest := digestBytes(raw)
	clear(raw)
	return equalString(digest, expected)
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func equalString(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
