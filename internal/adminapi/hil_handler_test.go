package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/adminstore"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/hilartifactstore"
	"github.com/devwooops/sentinelflow/internal/hilstore"
)

func TestPolicyHILChallengeIssuesOneExactNonceWithFrozenDTO(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	request := postRequest(hilChallengePath(), artifactRequestBody(fixture.artifact, hil.OperationApprove))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("challenge failed: %d %s", response.Code, response.Body.String())
	}
	responseBody := response.Body.String()
	var result challengeEnvelope
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	parsed, err := hil.ParseCanonicalChallenge(result.Challenge)
	if err != nil || parsed.Digest() != fixture.challenge.Digest() || result.ChallengeNonce != fixture.nonce {
		t.Fatalf("wrong challenge response: parsed=%v nonce=%q err=%v", parsed, result.ChallengeNonce, err)
	}
	issued := fixture.hil.issued.(*fakeHILIssuedChallenge)
	if fixture.boundary.decisionCall != 1 || fixture.reader.calls != 1 || fixture.reader.policyID != hilTestPolicyID ||
		fixture.reader.version != fixture.artifact.PolicyVersion() || fixture.hil.issueCalls != 1 ||
		fixture.hil.operation != hil.OperationApprove || fixture.hil.artifact.CanonicalArtifactDigest() != fixture.artifact.CanonicalArtifactDigest() ||
		issued.takes != 1 || fixture.boundary.rotationCall != 0 || len(response.Result().Cookies()) != 0 {
		t.Fatalf("wrong issue path: limiter=%d reader=%d issue=%d takes=%d rotations=%d",
			fixture.boundary.decisionCall, fixture.reader.calls, fixture.hil.issueCalls, issued.takes, fixture.boundary.rotationCall)
	}
	for _, forbidden := range []string{
		fixture.issued.SessionToken(), fixture.issued.CSRFToken(), fixture.idempotency,
		string(fixture.artifact.CanonicalBytes()), string(fixture.artifact.GeneratedBytes()),
	} {
		if strings.Contains(responseBody, forbidden) {
			t.Fatalf("challenge response leaked forbidden value %q", forbidden)
		}
	}
	formatted := fmt.Sprintf("%v %#v %v", result, result, issued)
	if strings.Contains(formatted, fixture.nonce) || !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("challenge formatting leaked nonce: %s", formatted)
	}
}

func TestPolicyHILChallengeFailsClosedBeforePersistence(t *testing.T) {
	tests := []struct {
		name       string
		body       func(*hilHTTPFixture) string
		configure  func(*hilHTTPFixture, *http.Request)
		status     int
		code       ErrorCode
		readerCall int
	}{
		{
			name: "step up", body: validChallengeBody,
			configure: func(fixture *hilHTTPFixture, _ *http.Request) { fixture.boundary.forceStepUp = true },
			status:    http.StatusUnauthorized, code: ErrorStepUpRequired,
		},
		{
			name: "rate limit", body: validChallengeBody,
			configure: func(fixture *hilHTTPFixture, _ *http.Request) {
				fixture.boundary.decisionErr = &adminauth.RateLimitError{Scope: adminauth.RateLimitCapacity, RetryAfter: 2 * time.Second}
			},
			status: http.StatusTooManyRequests, code: ErrorRateLimited,
		},
		{
			name: "missing idempotency", body: validChallengeBody,
			configure: func(_ *hilHTTPFixture, request *http.Request) { request.Header.Del("Idempotency-Key") },
			status:    http.StatusUnprocessableEntity, code: ErrorSchemaInvalid,
		},
		{
			name: "duplicate idempotency", body: validChallengeBody,
			configure: func(_ *hilHTTPFixture, request *http.Request) {
				request.Header.Add("Idempotency-Key", hilTestIdempotency)
			},
			status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid,
		},
		{
			name: "policy version mutation",
			body: func(fixture *hilHTTPFixture) string {
				return strings.Replace(validChallengeBody(fixture), `"policy_version":3`, `"policy_version":4`, 1)
			},
			status: http.StatusConflict, code: ErrorStaleVersion, readerCall: 1,
		},
		{
			name: "target mutation",
			body: func(fixture *hilHTTPFixture) string {
				return strings.Replace(validChallengeBody(fixture), fixture.artifact.TargetIPv4(), "203.0.113.21", 1)
			},
			status: http.StatusConflict, code: ErrorDigestMismatch, readerCall: 1,
		},
		{
			name: "ttl mutation",
			body: func(fixture *hilHTTPFixture) string {
				return strings.Replace(validChallengeBody(fixture), `"ttl_seconds":1800`, `"ttl_seconds":1801`, 1)
			},
			status: http.StatusConflict, code: ErrorDigestMismatch, readerCall: 1,
		},
		{
			name: "digest mutation",
			body: func(fixture *hilHTTPFixture) string {
				return strings.Replace(validChallengeBody(fixture), fixture.artifact.ValidationSnapshotDigest(), hilTestDigest('e'), 1)
			},
			status: http.StatusConflict, code: ErrorDigestMismatch, readerCall: 1,
		},
		{
			name: "malformed digest",
			body: func(fixture *hilHTTPFixture) string {
				return strings.Replace(validChallengeBody(fixture), fixture.artifact.ValidationSnapshotDigest(), "SHA256:BAD", 1)
			},
			status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid,
		},
		{
			name: "unknown field",
			body: func(fixture *hilHTTPFixture) string {
				return strings.TrimSuffix(validChallengeBody(fixture), "}") + `,"override":true}`
			},
			status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHILHTTPFixture(t, hil.OperationApprove)
			request := postRequest(hilChallengePath(), test.body(fixture))
			addHILBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", fixture.idempotency)
			if test.configure != nil {
				test.configure(fixture, request)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertHILError(t, response, test.status, test.code)
			if fixture.reader.calls != test.readerCall || fixture.hil.issueCalls != 0 || fixture.boundary.rotationCall != 0 {
				t.Fatalf("failure crossed gate: reader=%d issue=%d rotation=%d", fixture.reader.calls, fixture.hil.issueCalls, fixture.boundary.rotationCall)
			}
			if strings.Contains(response.Body.String(), fixture.nonce) || strings.Contains(response.Body.String(), fixture.idempotency) {
				t.Fatal("failure reflected nonce or idempotency key")
			}
		})
	}
}

func TestPolicyHILChallengeRechecksPersistenceOutputBeforeTakingNonce(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	alternate := hilHTTPChallenge(t, hil.OperationReject, fixture.sessions.record, fixture.artifact, fixture.nonce, fixture.now)
	issued := fixture.hil.issued.(*fakeHILIssuedChallenge)
	issued.challenge = alternate
	request := postRequest(hilChallengePath(), validChallengeBody(fixture))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	assertHILError(t, response, http.StatusServiceUnavailable, ErrorServiceUnavailable)
	if issued.takes != 0 || strings.Contains(response.Body.String(), fixture.nonce) {
		t.Fatalf("mismatched challenge exposed nonce: takes=%d body=%s", issued.takes, response.Body.String())
	}
}

func TestPolicyHILFreshApproveRotatesOnceAndReturnsExactDecision(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	stored := hilHTTPStoredDecision(t, hil.OperationApprove, fixture.sessions.record, fixture.artifact, fixture.challenge, fixture.idempotency, true)
	fixture.hil.stored = stored
	fixture.hil.lookups = []fakeHILLookupResult{{err: hilstore.ErrNotFound}}
	reason := hilHTTPReason(hil.OperationApprove)
	request := postRequest(hilDecisionPath(), decisionRequestBody(fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce, reason))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("decision failed: %d %s", response.Code, response.Body.String())
	}
	responseBody := response.Body.String()
	var result decisionEnvelope
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	decision, err := hil.ParseCanonicalDecision(result.Decision)
	if err != nil || decision.Digest() != stored.decision.Digest() || result.ActionID == nil || *result.ActionID != hilTestActionID ||
		result.AuthorizationDigest == nil || *result.AuthorizationDigest != stored.authorization ||
		result.OutboxJobID == nil || *result.OutboxJobID != hilTestOutboxID || result.CSRFToken == "" ||
		result.Session.SessionID == fixture.issued.Record.ID.String() {
		t.Fatalf("wrong decision DTO: result=%v err=%v", result, err)
	}
	if fixture.hil.lookupCalls != 1 || fixture.hil.commitCalls != 1 || fixture.boundary.rotationCall != 1 {
		t.Fatalf("wrong decision sequence: lookup=%d commit=%d rotation=%d", fixture.hil.lookupCalls, fixture.hil.commitCalls, fixture.boundary.rotationCall)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || !strings.Contains(cookies[0].Value, result.Session.SessionID) {
		t.Fatalf("replacement cookie missing: %#v", cookies)
	}
	for _, forbidden := range []string{fixture.nonce, fixture.idempotency, reason.ReasonText, fixture.issued.SessionToken(), result.CSRFToken} {
		if forbidden != result.CSRFToken && strings.Contains(responseBody, forbidden) {
			t.Fatalf("decision response leaked %q", forbidden)
		}
	}
	if strings.Count(responseBody, `"csrf_token"`) != 1 || !strings.Contains(responseBody, result.CSRFToken) {
		t.Fatal("replacement CSRF contract missing or duplicated")
	}
	formatted := fmt.Sprintf("%v %#v", result, result)
	if strings.Contains(formatted, result.CSRFToken) || !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("decision formatting leaked CSRF: %s", formatted)
	}
}

func TestPolicyHILRejectCreatesNoAuthorityAndRejectsForgedAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		forge  bool
		status int
	}{
		{name: "rejection", status: http.StatusOK},
		{name: "forged authority", forge: true, status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHILHTTPFixture(t, hil.OperationReject)
			stored := hilHTTPStoredDecision(t, hil.OperationReject, fixture.sessions.record, fixture.artifact, fixture.challenge, fixture.idempotency, true)
			if test.forge {
				stored.actionID = hilTestActionID
				stored.authorization = hilTestDigest('a')
				stored.outboxID = hilTestOutboxID
			}
			fixture.hil.stored = stored
			fixture.hil.lookups = []fakeHILLookupResult{{err: hilstore.ErrNotFound}}
			request := postRequest(hilDecisionPath(), decisionRequestBody(fixture.artifact, hil.OperationReject, fixture.challenge, fixture.nonce, hilHTTPReason(hil.OperationReject)))
			addHILBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", fixture.idempotency)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if test.forge {
				assertHILErrorBody(t, response.Body.Bytes(), ErrorServiceUnavailable)
				return
			}
			var result decisionEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.ActionID != nil || result.AuthorizationDigest != nil || result.OutboxJobID != nil ||
				strings.Contains(response.Body.String(), hilTestActionID) || strings.Contains(response.Body.String(), hilTestOutboxID) {
				t.Fatalf("rejection created authority: %#v body=%s", result, response.Body.String())
			}
		})
	}
}

func TestPolicyHILUncertainCommitReturnsOriginalResultWithoutFabricatingSecrets(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	stored := hilHTTPStoredDecision(t, hil.OperationApprove, fixture.sessions.record, fixture.artifact, fixture.challenge, fixture.idempotency, false)
	fixture.hil.lookups = []fakeHILLookupResult{{err: hilstore.ErrNotFound}, {stored: stored}}
	fixture.hil.commits = []fakeHILLookupResult{{err: hilstore.ErrUnavailable}, {err: hilstore.ErrUnavailable}}
	fixture.hil.lookupHook = func(call int) {
		if call == 2 {
			fixture.sessions.mu.Lock()
			revoked := fixture.sessions.record
			revokedAt := fixture.now
			revoked.RevokedAt = &revokedAt
			fixture.sessions.replayRecord = revoked
			fixture.sessions.mu.Unlock()
		}
	}
	request := postRequest(hilDecisionPath(), decisionRequestBody(fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce, hilHTTPReason(hil.OperationApprove)))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("historical result failed: %d %s", response.Code, response.Body.String())
	}
	var result historicalDecisionEnvelope
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	decision, err := hil.ParseCanonicalDecision(result.Decision)
	if err != nil || decision.Digest() != stored.decision.Digest() || !result.Replayed || !result.ReauthenticationRequired ||
		result.ActionID == nil || *result.ActionID != hilTestActionID ||
		result.AuthorizationDigest == nil || *result.AuthorizationDigest != stored.authorization ||
		result.OutboxJobID == nil || *result.OutboxJobID != hilTestOutboxID {
		t.Fatalf("wrong historical response: result=%v err=%v", result, err)
	}
	if fixture.boundary.rotationCall != 1 || fixture.hil.commitCalls != 2 || fixture.hil.lookupCalls != 2 {
		t.Fatalf("replay sequence: rotations=%d commits=%d lookups=%d", fixture.boundary.rotationCall, fixture.hil.commitCalls, fixture.hil.lookupCalls)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 || strings.Contains(response.Body.String(), "csrf_token") ||
		strings.Contains(response.Body.String(), `"session"`) || strings.Contains(response.Body.String(), fixture.nonce) {
		t.Fatalf("historical replay fabricated credentials: cookies=%#v body=%s", cookies, response.Body.String())
	}
}

func TestPolicyHILUncertainCommitNeverFallsBackAcrossSessionStoreUnavailability(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	stored := hilHTTPStoredDecision(t, hil.OperationApprove, fixture.sessions.record, fixture.artifact, fixture.challenge, fixture.idempotency, false)
	fixture.hil.lookups = []fakeHILLookupResult{{err: hilstore.ErrNotFound}, {stored: stored}}
	fixture.hil.commits = []fakeHILLookupResult{{err: hilstore.ErrUnavailable}, {err: hilstore.ErrUnavailable}}
	fixture.hil.lookupHook = func(call int) {
		if call == 2 {
			fixture.sessions.mu.Lock()
			fixture.sessions.replayErr = adminstore.ErrUnavailable
			fixture.sessions.mu.Unlock()
		}
	}
	request := postRequest(hilDecisionPath(), decisionRequestBody(
		fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce,
		hilHTTPReason(hil.OperationApprove),
	))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	assertHILError(t, response, http.StatusServiceUnavailable, ErrorServiceUnavailable)
	if fixture.hil.commitCalls != 2 || fixture.hil.lookupCalls != 2 || fixture.sessions.replayLoads != 1 {
		t.Fatalf("unavailable store fallback: commits=%d lookups=%d replay_loads=%d",
			fixture.hil.commitCalls, fixture.hil.lookupCalls, fixture.sessions.replayLoads)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 ||
		strings.Contains(response.Body.String(), `"session"`) || strings.Contains(response.Body.String(), "csrf_token") {
		t.Fatalf("uncertain session retained credentials: cookies=%#v body=%s", cookies, response.Body.String())
	}
}

func TestPolicyHILDecisionDoesNotFallbackWhenLiveSessionStoreIsUnavailable(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	fixture.sessions.loadErr = adminstore.ErrUnavailable
	request := postRequest(hilDecisionPath(), decisionRequestBody(
		fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce,
		hilHTTPReason(hil.OperationApprove),
	))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	assertHILError(t, response, http.StatusServiceUnavailable, ErrorServiceUnavailable)
	if fixture.sessions.replayLoads != 0 || fixture.reader.calls != 0 || fixture.hil.lookupCalls != 0 ||
		fixture.hil.commitCalls != 0 || fixture.boundary.rotationCall != 0 {
		t.Fatalf("live store unavailability crossed into replay: replay_loads=%d reader=%d lookups=%d commits=%d rotations=%d",
			fixture.sessions.replayLoads, fixture.reader.calls, fixture.hil.lookupCalls,
			fixture.hil.commitCalls, fixture.boundary.rotationCall)
	}
}

func TestPolicyHILUncertainCommitExactRetryProvesRetainedRotationCandidate(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	stored := hilHTTPStoredDecision(t, hil.OperationApprove, fixture.sessions.record, fixture.artifact, fixture.challenge, fixture.idempotency, false)
	fixture.hil.lookups = []fakeHILLookupResult{{err: hilstore.ErrNotFound}}
	fixture.hil.commits = []fakeHILLookupResult{{err: hilstore.ErrUnavailable}, {stored: stored}}
	fixture.hil.commitHook = func(call int) {
		if call == 2 {
			fixture.sessions.mu.Lock()
			fixture.sessions.record = fixture.boundary.lastRotation.Issued.Record
			fixture.sessions.mu.Unlock()
		}
	}
	request := postRequest(hilDecisionPath(), decisionRequestBody(fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce, hilHTTPReason(hil.OperationApprove)))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || fixture.hil.commitCalls != 2 || fixture.hil.lookupCalls != 1 {
		t.Fatalf("exact retry failed: status=%d commits=%d lookups=%d body=%s", response.Code, fixture.hil.commitCalls, fixture.hil.lookupCalls, response.Body.String())
	}
	var result decisionEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.CSRFToken == "" || result.Session.SessionID == "" {
		t.Fatalf("retained rotation secrets not returned: result=%v err=%v", result, err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge == -1 || !strings.Contains(cookies[0].Value, result.Session.SessionID) {
		t.Fatalf("replacement cookie missing: %#v", cookies)
	}
}

func TestPolicyHILRevokedParentExactReplayReturnsReadOnlyOriginal(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	original := fixture.sessions.record
	revoked := original
	revokedAt := fixture.now
	revoked.RevokedAt = &revokedAt
	fixture.sessions.loadErr = adminstore.ErrNotFound
	fixture.sessions.replayRecord = revoked
	stored := hilHTTPStoredDecision(t, hil.OperationApprove, original, fixture.artifact, fixture.challenge, fixture.idempotency, false)
	fixture.hil.lookups = []fakeHILLookupResult{{stored: stored}}
	request := postRequest(hilDecisionPath(), decisionRequestBody(fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce, hilHTTPReason(hil.OperationApprove)))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("revoked replay failed: %d %s", response.Code, response.Body.String())
	}
	var result historicalDecisionEnvelope
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || !result.Replayed || !result.ReauthenticationRequired {
		t.Fatalf("wrong replay DTO: result=%v err=%v", result, err)
	}
	if fixture.sessions.replayLoads != 2 || fixture.sessions.touches != 0 || fixture.hil.lookupCalls != 1 ||
		fixture.hil.commitCalls != 0 || fixture.boundary.rotationCall != 0 {
		t.Fatalf("replay crossed mutation boundary: replay_loads=%d touches=%d lookups=%d commits=%d rotations=%d",
			fixture.sessions.replayLoads, fixture.sessions.touches, fixture.hil.lookupCalls, fixture.hil.commitCalls, fixture.boundary.rotationCall)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 || strings.Contains(response.Body.String(), "csrf_token") ||
		strings.Contains(response.Body.String(), `"session"`) {
		t.Fatalf("revoked replay minted credentials: cookies=%#v body=%s", cookies, response.Body.String())
	}
}

func TestPolicyHILHistoricalReplayRejectsEveryCrossBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*hilHTTPFixture, *http.Request)
		status int
		code   ErrorCode
	}{
		{
			name: "actor",
			mutate: func(fixture *hilHTTPFixture, _ *http.Request) {
				fixture.sessions.replayRecord.ActorID = "other-administrator"
			},
			status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable,
		},
		{
			name: "session digest",
			mutate: func(fixture *hilHTTPFixture, _ *http.Request) {
				fixture.sessions.replayRecord.TokenDigest[0] ^= 1
			},
			status: http.StatusConflict, code: ErrorDigestMismatch,
		},
		{
			name: "challenge id",
			mutate: func(fixture *hilHTTPFixture, request *http.Request) {
				value := fixture.challenge.Value()
				value.ChallengeID = "019b0000-0000-4000-8000-000000000199"
				alternate, err := hil.CheckChallenge(value)
				if err != nil {
					t.Fatal(err)
				}
				request.Body = io.NopCloser(strings.NewReader(decisionRequestBody(
					fixture.artifact, hil.OperationApprove, alternate, fixture.nonce,
					hilHTTPReason(hil.OperationApprove),
				)))
			},
			status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable,
		},
		{
			name: "policy version",
			mutate: func(_ *hilHTTPFixture, request *http.Request) {
				body := readRequestBody(t, request)
				request.Body = io.NopCloser(strings.NewReader(strings.Replace(body, `"policy_version":3`, `"policy_version":4`, 1)))
			},
			status: http.StatusConflict, code: ErrorStaleVersion,
		},
		{
			name: "evidence digest",
			mutate: func(fixture *hilHTTPFixture, request *http.Request) {
				body := readRequestBody(t, request)
				request.Body = io.NopCloser(strings.NewReader(strings.Replace(
					body, fixture.artifact.EvidenceSnapshotDigest(), hilTestDigest('e'), 1,
				)))
			},
			status: http.StatusConflict, code: ErrorDigestMismatch,
		},
		{
			name: "validation digest",
			mutate: func(fixture *hilHTTPFixture, request *http.Request) {
				body := readRequestBody(t, request)
				request.Body = io.NopCloser(strings.NewReader(strings.Replace(
					body, fixture.artifact.ValidationSnapshotDigest(), hilTestDigest('f'), 1,
				)))
			},
			status: http.StatusConflict, code: ErrorDigestMismatch,
		},
		{
			name: "canonical command digest",
			mutate: func(fixture *hilHTTPFixture, request *http.Request) {
				body := readRequestBody(t, request)
				request.Body = io.NopCloser(strings.NewReader(strings.Replace(
					body, fixture.artifact.CanonicalArtifactDigest(), hilTestDigest('c'), 1,
				)))
			},
			status: http.StatusConflict, code: ErrorDigestMismatch,
		},
		{
			name: "reason",
			mutate: func(fixture *hilHTTPFixture, request *http.Request) {
				changed := hilHTTPReason(hil.OperationApprove)
				changed.ReasonText = "Different synthetic operator rationale"
				request.Body = io.NopCloser(strings.NewReader(decisionRequestBody(
					fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce, changed,
				)))
			},
			status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable,
		},
		{
			name: "idempotency",
			mutate: func(_ *hilHTTPFixture, request *http.Request) {
				request.Header.Set("Idempotency-Key", "fedcba9876543210-other-hil-http")
			},
			status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHILHTTPFixture(t, hil.OperationApprove)
			original := configureHistoricalReplay(t, fixture, hil.OperationApprove)
			stored := hilHTTPStoredDecision(t, hil.OperationApprove, original, fixture.artifact, fixture.challenge, fixture.idempotency, false)
			fixture.hil.lookups = []fakeHILLookupResult{{stored: stored}}
			request := postRequest(hilDecisionPath(), decisionRequestBody(
				fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce,
				hilHTTPReason(hil.OperationApprove),
			))
			addHILBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", fixture.idempotency)
			test.mutate(fixture, request)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertHILError(t, response, test.status, test.code)
			if fixture.hil.commitCalls != 0 || fixture.boundary.rotationCall != 0 || fixture.sessions.touches != 0 {
				t.Fatalf("cross-binding reached mutation: commits=%d rotations=%d touches=%d",
					fixture.hil.commitCalls, fixture.boundary.rotationCall, fixture.sessions.touches)
			}
			if strings.Contains(response.Body.String(), fixture.nonce) ||
				strings.Contains(response.Body.String(), hilHTTPReason(hil.OperationApprove).ReasonText) {
				t.Fatal("cross-binding error leaked replay inputs")
			}
		})
	}
}

func TestPolicyHILHistoricalReplayRechecksChildAfterDecisionRead(t *testing.T) {
	for _, test := range []struct {
		name     string
		finalErr error
		status   int
		code     ErrorCode
	}{
		{name: "child logout", finalErr: adminstore.ErrNotFound, status: http.StatusUnauthorized, code: ErrorAuthenticationRequired},
		{name: "child second rotation", finalErr: adminstore.ErrNotFound, status: http.StatusUnauthorized, code: ErrorAuthenticationRequired},
		{name: "window expiry", finalErr: adminstore.ErrNotFound, status: http.StatusUnauthorized, code: ErrorAuthenticationRequired},
		{name: "store unavailable", finalErr: adminstore.ErrUnavailable, status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHILHTTPFixture(t, hil.OperationApprove)
			original := configureHistoricalReplay(t, fixture, hil.OperationApprove)
			stored := hilHTTPStoredDecision(t, hil.OperationApprove, original, fixture.artifact, fixture.challenge, fixture.idempotency, false)
			fixture.hil.lookups = []fakeHILLookupResult{{stored: stored}}
			fixture.hil.lookupHook = func(call int) {
				if call == 1 {
					fixture.sessions.mu.Lock()
					fixture.sessions.replayErr = test.finalErr
					fixture.sessions.mu.Unlock()
				}
			}
			request := postRequest(hilDecisionPath(), decisionRequestBody(
				fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce,
				hilHTTPReason(hil.OperationApprove),
			))
			addHILBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", fixture.idempotency)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertHILError(t, response, test.status, test.code)
			if fixture.sessions.replayLoads != 2 || fixture.hil.lookupCalls != 1 ||
				fixture.hil.commitCalls != 0 || fixture.boundary.rotationCall != 0 {
				t.Fatalf("unsafe final replay state: replay_loads=%d lookups=%d commits=%d rotations=%d",
					fixture.sessions.replayLoads, fixture.hil.lookupCalls,
					fixture.hil.commitCalls, fixture.boundary.rotationCall)
			}
			cookies := response.Result().Cookies()
			if len(cookies) != 1 || cookies[0].MaxAge != -1 ||
				strings.Contains(response.Body.String(), `"session"`) || strings.Contains(response.Body.String(), "csrf_token") {
				t.Fatalf("failed replay retained credentials: cookies=%#v body=%s", cookies, response.Body.String())
			}
		})
	}
}

func TestPolicyHILExactCommitRetryNeverReissuesInactiveChildCredentials(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	stored := hilHTTPStoredDecision(t, hil.OperationApprove, fixture.sessions.record, fixture.artifact, fixture.challenge, fixture.idempotency, false)
	fixture.hil.lookups = []fakeHILLookupResult{{err: hilstore.ErrNotFound}}
	fixture.hil.commits = []fakeHILLookupResult{{err: hilstore.ErrUnavailable}, {stored: stored}}
	fixture.hil.commitHook = func(call int) {
		if call == 2 {
			fixture.sessions.mu.Lock()
			fixture.sessions.loadErr = adminstore.ErrNotFound
			fixture.sessions.mu.Unlock()
		}
	}
	request := postRequest(hilDecisionPath(), decisionRequestBody(
		fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce,
		hilHTTPReason(hil.OperationApprove),
	))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	assertHILError(t, response, http.StatusUnauthorized, ErrorAuthenticationRequired)
	if fixture.hil.commitCalls != 2 || fixture.boundary.rotationCall != 1 || fixture.sessions.loads != 2 {
		t.Fatalf("inactive child was not rechecked: commits=%d rotations=%d loads=%d",
			fixture.hil.commitCalls, fixture.boundary.rotationCall, fixture.sessions.loads)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 ||
		strings.Contains(response.Body.String(), `"session"`) || strings.Contains(response.Body.String(), "csrf_token") {
		t.Fatalf("inactive child credentials escaped: cookies=%#v body=%s", cookies, response.Body.String())
	}
}

func TestPolicyHILHistoricalRejectUsesExplicitNullAuthorityWithoutFreshFields(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationReject)
	original := configureHistoricalReplay(t, fixture, hil.OperationReject)
	stored := hilHTTPStoredDecision(t, hil.OperationReject, original, fixture.artifact, fixture.challenge, fixture.idempotency, false)
	fixture.hil.lookups = []fakeHILLookupResult{{stored: stored}}
	request := postRequest(hilDecisionPath(), decisionRequestBody(
		fixture.artifact, hil.OperationReject, fixture.challenge, fixture.nonce,
		hilHTTPReason(hil.OperationReject),
	))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("historical reject failed: %d %s", response.Code, response.Body.String())
	}
	responseBytes := append([]byte(nil), response.Body.Bytes()...)
	var result historicalDecisionEnvelope
	decoder := json.NewDecoder(bytes.NewReader(responseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || !result.Replayed || !result.ReauthenticationRequired ||
		result.ActionID != nil || result.AuthorizationDigest != nil || result.OutboxJobID != nil {
		t.Fatalf("historical reject field mixing: result=%v err=%v", result, err)
	}
	body := string(responseBytes)
	for _, field := range []string{`"action_id":null`, `"authorization_digest":null`, `"outbox_job_id":null`} {
		if !strings.Contains(body, field) {
			t.Fatalf("historical reject omitted explicit null %s: %s", field, body)
		}
	}
	if strings.Contains(body, `"session"`) || strings.Contains(body, "csrf_token") {
		t.Fatalf("historical reject mixed fresh fields: %s", body)
	}
}

func TestPolicyHILHistoricalReplayRejectsFreshOrForgedStoreFieldMixing(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation hil.Operation
		mutate    func(*fakeHILStoredDecision)
	}{
		{
			name: "fresh session rotation flag", operation: hil.OperationApprove,
			mutate: func(stored *fakeHILStoredDecision) { stored.sessionRotated = true },
		},
		{
			name: "authority on rejection", operation: hil.OperationReject,
			mutate: func(stored *fakeHILStoredDecision) {
				stored.actionID = hilTestActionID
				stored.authorization = hilTestDigest('a')
				stored.outboxID = hilTestOutboxID
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHILHTTPFixture(t, test.operation)
			original := configureHistoricalReplay(t, fixture, test.operation)
			stored := hilHTTPStoredDecision(t, test.operation, original, fixture.artifact, fixture.challenge, fixture.idempotency, false)
			test.mutate(&stored)
			fixture.hil.lookups = []fakeHILLookupResult{{stored: stored}}
			request := postRequest(hilDecisionPath(), decisionRequestBody(
				fixture.artifact, test.operation, fixture.challenge, fixture.nonce,
				hilHTTPReason(test.operation),
			))
			addHILBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", fixture.idempotency)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertHILError(t, response, http.StatusServiceUnavailable, ErrorServiceUnavailable)
			if fixture.hil.commitCalls != 0 || fixture.boundary.rotationCall != 0 ||
				strings.Contains(response.Body.String(), `"session"`) || strings.Contains(response.Body.String(), "csrf_token") {
				t.Fatalf("store field mixing crossed replay boundary: body=%s", response.Body.String())
			}
		})
	}
}

func configureHistoricalReplay(t *testing.T, fixture *hilHTTPFixture, operation hil.Operation) adminauth.SessionRecord {
	t.Helper()
	original := fixture.sessions.record
	revoked := original
	revokedAt := fixture.now
	revoked.RevokedAt = &revokedAt
	fixture.sessions.loadErr = adminstore.ErrNotFound
	fixture.sessions.replayRecord = revoked
	if operation != fixture.challenge.Value().Operation {
		t.Fatalf("fixture operation mismatch: %s != %s", operation, fixture.challenge.Value().Operation)
	}
	return original
}

func readRequestBody(t *testing.T, request *http.Request) string {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	request.Body.Close()
	return string(body)
}

func TestPolicyHILLiveSessionWithHistoricalDecisionFailsInvariant(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	stored := hilHTTPStoredDecision(t, hil.OperationApprove, fixture.sessions.record, fixture.artifact, fixture.challenge, fixture.idempotency, false)
	fixture.hil.lookups = []fakeHILLookupResult{{stored: stored}}
	request := postRequest(hilDecisionPath(), decisionRequestBody(fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce, hilHTTPReason(hil.OperationApprove)))
	addHILBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", fixture.idempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	assertHILError(t, response, http.StatusServiceUnavailable, ErrorServiceUnavailable)
	if fixture.hil.commitCalls != 0 || fixture.boundary.rotationCall != 0 {
		t.Fatal("live/historical invariant failure reached mutation")
	}
}

func TestPolicyHILDecisionRejectsChallengeNonceReasonAndIdempotencyMismatch(t *testing.T) {
	tests := []struct {
		name      string
		body      func(*hilHTTPFixture) string
		configure func(*hilHTTPFixture)
		status    int
		code      ErrorCode
		reader    int
	}{
		{
			name: "nonce mismatch",
			body: func(fixture *hilHTTPFixture) string {
				other := base64RawURL(bytes.Repeat([]byte{0x6b}, hil.NonceBytes))
				return decisionRequestBody(fixture.artifact, hil.OperationApprove, fixture.challenge, other, hilHTTPReason(hil.OperationApprove))
			},
			status: http.StatusConflict, code: ErrorDigestMismatch,
		},
		{
			name: "noncanonical challenge",
			body: func(fixture *hilHTTPFixture) string {
				body := decisionRequestBody(fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce, hilHTTPReason(hil.OperationApprove))
				return strings.Replace(body, `"challenge":{`, `"challenge":{ `, 1)
			},
			status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid,
		},
		{
			name: "challenge artifact mutation",
			body: func(fixture *hilHTTPFixture) string {
				alternate := hilHTTPChallenge(t, hil.OperationReject, fixture.sessions.record, fixture.artifact, fixture.nonce, fixture.now)
				return decisionRequestBody(fixture.artifact, hil.OperationApprove, alternate, fixture.nonce, hilHTTPReason(hil.OperationApprove))
			},
			status: http.StatusConflict, code: ErrorDigestMismatch, reader: 1,
		},
		{
			name: "invalid reason",
			body: func(fixture *hilHTTPFixture) string {
				return decisionRequestBody(fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce,
					hil.Reason{SchemaVersion: hil.ReasonSchemaVersion, ReasonCode: "override", ReasonText: "unsafe"})
			},
			status: http.StatusUnprocessableEntity, code: ErrorSchemaInvalid,
		},
		{
			name: "idempotency conflict", body: validDecisionBody,
			configure: func(fixture *hilHTTPFixture) {
				fixture.hil.lookups = []fakeHILLookupResult{{err: hilstore.ErrConflict}}
			},
			status: http.StatusConflict, code: ErrorIdempotencyConflict, reader: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHILHTTPFixture(t, hil.OperationApprove)
			if test.configure != nil {
				test.configure(fixture)
			}
			request := postRequest(hilDecisionPath(), test.body(fixture))
			addHILBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", fixture.idempotency)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertHILError(t, response, test.status, test.code)
			if fixture.reader.calls != test.reader || fixture.hil.commitCalls != 0 || fixture.boundary.rotationCall != 0 {
				t.Fatalf("mismatch crossed mutation boundary: reader=%d commit=%d rotation=%d", fixture.reader.calls, fixture.hil.commitCalls, fixture.boundary.rotationCall)
			}
			if strings.Contains(response.Body.String(), fixture.nonce) || strings.Contains(response.Body.String(), hilHTTPReason(hil.OperationApprove).ReasonText) {
				t.Fatal("mismatch reflected nonce or reason")
			}
		})
	}
}

func TestPolicyHILRoutesRequireStrictPathEnvelopeAndPrivateContext(t *testing.T) {
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	for _, test := range []struct {
		name   string
		method string
		path   string
		mutate func(*http.Request)
		status int
	}{
		{name: "method", method: http.MethodGet, path: hilChallengePath(), status: http.StatusMethodNotAllowed},
		{name: "uppercase UUID", method: http.MethodPost, path: strings.Replace(hilChallengePath(), "019b", "019B", 1), status: http.StatusNotFound},
		{name: "trailing slash", method: http.MethodPost, path: hilChallengePath() + "/", status: http.StatusNotFound},
		{name: "query", method: http.MethodPost, path: hilChallengePath(), mutate: func(request *http.Request) { request.URL.RawQuery = "override=1" }, status: http.StatusBadRequest},
		{name: "content type parameter", method: http.MethodPost, path: hilChallengePath(), mutate: func(request *http.Request) { request.Header.Set("Content-Type", "application/json; charset=utf-8") }, status: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://api.example.test"+test.path, strings.NewReader(validChallengeBody(fixture)))
			request.RemoteAddr = "192.0.2.50:41234"
			request.Header.Set("Content-Type", "application/json")
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status || fixture.reader.calls != 0 || fixture.hil.issueCalls != 0 {
				t.Fatalf("route status=%d reader=%d issue=%d", response.Code, fixture.reader.calls, fixture.hil.issueCalls)
			}
		})
	}

	direct := postRequest(hilChallengePath(), validChallengeBody(fixture))
	direct.Header.Set("Idempotency-Key", fixture.idempotency)
	directResponse := httptest.NewRecorder()
	fixture.handler.servePolicyDecisionChallenge(directResponse, direct, hilTestPolicyID)
	assertHILError(t, directResponse, http.StatusUnauthorized, ErrorAuthenticationRequired)
	if fixture.reader.calls != 0 || fixture.hil.issueCalls != 0 {
		t.Fatal("direct internal call bypassed package-private browser context")
	}
}

func TestAuthenticatedSessionCSRFRecoveryFailsClosedWithoutCookie(t *testing.T) {
	fixture := newFixture(t)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, getRequest(SessionPath))
	assertHILError(t, response, http.StatusUnauthorized, ErrorAuthenticationRequired)
	if strings.Contains(response.Body.String(), "csrf_token") || strings.Contains(response.Body.String(), fixture.issued.CSRFToken()) {
		t.Fatal("unauthenticated session response exposed CSRF")
	}
}

func TestHILAndExactArtifactErrorsUseFrozenStatusMapping(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   ErrorCode
	}{
		{name: "authentication", err: hilstore.ErrAuthentication, status: 401, code: ErrorAuthenticationRequired},
		{name: "step up", err: hilstore.ErrStepUpRequired, status: 401, code: ErrorStepUpRequired},
		{name: "expired", err: hilstore.ErrChallengeExpired, status: 422, code: ErrorChallengeExpired},
		{name: "consumed", err: &hil.Error{Code: hil.ErrorConsumed}, status: 409, code: ErrorChallengeConsumed},
		{name: "conflict", err: hilstore.ErrConflict, status: 409, code: ErrorIdempotencyConflict},
		{name: "artifact mismatch", err: &hil.Error{Code: hil.ErrorArtifactMismatch}, status: 409, code: ErrorDigestMismatch},
		{name: "challenge mismatch", err: &hil.Error{Code: hil.ErrorChallengeMismatch}, status: 409, code: ErrorDigestMismatch},
		{name: "validation", err: hilstore.ErrValidationFailed, status: 422, code: ErrorValidationFailed},
		{name: "stale validation", err: hilstore.ErrValidationStale, status: 422, code: ErrorValidationFailed},
		{name: "schema", err: &hil.Error{Code: hil.ErrorSchema}, status: 422, code: ErrorSchemaInvalid},
		{name: "nonce", err: &hil.Error{Code: hil.ErrorNonce}, status: 422, code: ErrorSchemaInvalid},
		{name: "invalid store input", err: hilstore.ErrInvalidInput, status: 422, code: ErrorSchemaInvalid},
		{name: "not found", err: hilstore.ErrNotFound, status: 404, code: ErrorNotFound},
		{name: "unavailable", err: hilstore.ErrUnavailable, status: 503, code: ErrorServiceUnavailable},
		{name: "rate", err: &adminauth.RateLimitError{Scope: adminauth.RateLimitDecision, RetryAfter: time.Second}, status: 429, code: ErrorRateLimited},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := hilFailure(test.err)
			if failure.status != test.status || failure.code != test.code {
				t.Fatalf("failure=%#v", failure)
			}
		})
	}
	for _, test := range []struct {
		err    error
		status int
		code   ErrorCode
	}{
		{err: ErrExactArtifactNotFound, status: 404, code: ErrorNotFound},
		{err: ErrExactArtifactStale, status: 409, code: ErrorStaleVersion},
		{err: ErrExactArtifactUnavailable, status: 503, code: ErrorServiceUnavailable},
	} {
		failure := exactArtifactFailure(test.err)
		if failure.status != test.status || failure.code != test.code {
			t.Fatalf("exact artifact failure=%#v", failure)
		}
	}
}

type fakeExactArtifactStoreAdapterTarget struct {
	artifact hil.ExactArtifact
	err      error
	now      time.Time
}

func (store *fakeExactArtifactStoreAdapterTarget) Load(_ context.Context, _ string, _ uint32, now time.Time) (hil.ExactArtifact, error) {
	store.now = now
	return store.artifact, store.err
}

func (store *fakeExactArtifactStoreAdapterTarget) LoadHistorical(_ context.Context, _ string, _ uint32) (hil.ExactArtifact, error) {
	return store.artifact, store.err
}

type fakeRawHILStore struct {
	issueErr  error
	lookupErr error
	commitErr error
}

func (store *fakeRawHILStore) Issue(context.Context, hilstore.IssueRequest) (*hilstore.IssuedChallenge, error) {
	return nil, store.issueErr
}

func (store *fakeRawHILStore) LookupHistoricalDecision(context.Context, hilstore.DecisionLookup) (hilstore.StoredDecision, error) {
	return hilstore.StoredDecision{}, store.lookupErr
}

func (store *fakeRawHILStore) Commit(context.Context, hilstore.PrivilegedDecisionCommit) (hilstore.StoredDecision, error) {
	return hilstore.StoredDecision{}, store.commitErr
}

func TestHILStoreAndExactArtifactAdaptersRemainNarrow(t *testing.T) {
	if _, err := NewExactArtifactStoreAdapter(nil, &testClock{}); err == nil {
		t.Fatal("nil exact store accepted")
	}
	if _, err := NewHILStoreAdapter(nil); err == nil {
		t.Fatal("nil HIL store accepted")
	}
	fixture := newHILHTTPFixture(t, hil.OperationApprove)
	clock := &testClock{now: fixture.now}
	for _, test := range []struct {
		storeErr error
		wantErr  error
	}{
		{wantErr: nil},
		{storeErr: hilartifactstore.ErrNotFound, wantErr: ErrExactArtifactNotFound},
		{storeErr: hilartifactstore.ErrStale, wantErr: ErrExactArtifactStale},
		{storeErr: hilartifactstore.ErrCorrupt, wantErr: ErrExactArtifactUnavailable},
	} {
		target := &fakeExactArtifactStoreAdapterTarget{artifact: fixture.artifact, err: test.storeErr}
		reader, err := NewExactArtifactStoreAdapter(target, clock)
		if err != nil {
			t.Fatal(err)
		}
		artifact, loadErr := reader.LoadExactArtifact(context.Background(), hilTestPolicyID, fixture.artifact.PolicyVersion())
		if test.wantErr == nil {
			if loadErr != nil || artifact.CanonicalArtifactDigest() != fixture.artifact.CanonicalArtifactDigest() || !target.now.Equal(fixture.now) {
				t.Fatalf("adapter result=%v err=%v now=%s", artifact, loadErr, target.now)
			}
		} else if !errors.Is(loadErr, test.wantErr) {
			t.Fatalf("adapter err=%v want=%v", loadErr, test.wantErr)
		}
		if formatted := fmt.Sprintf("%v %#v", reader, reader); strings.Contains(formatted, string(fixture.artifact.CanonicalBytes())) {
			t.Fatal("exact adapter formatting exposed artifact bytes")
		}
	}

	raw := &fakeRawHILStore{issueErr: hilstore.ErrConflict, lookupErr: hilstore.ErrUnavailable, commitErr: hilstore.ErrChallengeExpired}
	adapted, err := NewHILStoreAdapter(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, callErr := adapted.Issue(context.Background(), hilstore.IssueRequest{}); !errors.Is(callErr, raw.issueErr) {
		t.Fatalf("issue err=%v", callErr)
	}
	if _, callErr := adapted.LookupHistoricalDecision(context.Background(), hilstore.DecisionLookup{}); !errors.Is(callErr, raw.lookupErr) {
		t.Fatalf("lookup err=%v", callErr)
	}
	if _, callErr := adapted.Commit(context.Background(), hilstore.PrivilegedDecisionCommit{}); !errors.Is(callErr, raw.commitErr) {
		t.Fatalf("commit err=%v", callErr)
	}
	if formatted := fmt.Sprintf("%v %#v", adapted, adapted); !strings.Contains(formatted, "configured") {
		t.Fatalf("unexpected adapter formatting: %s", formatted)
	}
	var nilAdapter *hilStoreAdapter
	if _, err := nilAdapter.Issue(context.Background(), hilstore.IssueRequest{}); !errors.Is(err, hilstore.ErrUnavailable) {
		t.Fatalf("nil adapter err=%v", err)
	}
}

func validChallengeBody(fixture *hilHTTPFixture) string {
	return artifactRequestBody(fixture.artifact, hil.OperationApprove)
}

func validDecisionBody(fixture *hilHTTPFixture) string {
	return decisionRequestBody(fixture.artifact, hil.OperationApprove, fixture.challenge, fixture.nonce, hilHTTPReason(hil.OperationApprove))
}

func assertHILError(t *testing.T, response *httptest.ResponseRecorder, status int, code ErrorCode) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	assertHILErrorBody(t, response.Body.Bytes(), code)
}

func assertHILErrorBody(t *testing.T, body []byte, code ErrorCode) {
	t.Helper()
	var result errorResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Code != code || result.Message == "" || !testUUIDPattern.MatchString(result.TraceID) || result.Details == nil || len(result.Details) != 0 {
		t.Fatalf("invalid frozen error: %#v", result)
	}
	for _, forbidden := range []string{"nonce", "reason_text", "postgres", "credential", "idempotency_key"} {
		if strings.Contains(strings.ToLower(string(body)), forbidden) {
			t.Fatalf("error leaked internal data %q: %s", forbidden, body)
		}
	}
}
