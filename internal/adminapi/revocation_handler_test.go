package adminapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/adminstore"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/hilstore"
)

func TestRevocationChallengeReturnsOnlyReboundExactArtifact(t *testing.T) {
	fixture := newRevocationHTTPFixture(t)
	request := postRequest(revocationChallengePath(fixture), revocationChallengeBody(fixture))
	addRevocationBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", revocationTestIdempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("challenge status=%d body=%s", response.Code, response.Body.String())
	}
	var result revocationChallengeEnvelope
	decodeRevocationHTTP(t, response.Body.Bytes(), &result)
	parsed, err := hil.ParseCanonicalChallenge(result.Challenge)
	if err != nil || parsed.Digest() != fixture.challenge.Digest() ||
		result.ChallengeNonce != fixture.nonce ||
		result.CanonicalRevokeArtifact != string(fixture.artifact.CanonicalBytes()) ||
		result.PolicyID != fixture.policyID || result.PolicyVersion != fixture.policyVersion {
		t.Fatalf("wrong challenge response: %+v err=%v", result, err)
	}
	if fixture.store.issueCalls != 1 || fixture.issuedChallenge.takes != 1 ||
		fixture.store.request.ActionID != fixture.actionID ||
		fixture.store.request.ActionVersion != fixture.actionVersion ||
		fixture.store.request.TargetIPv4 != revocationTestTarget ||
		fixture.store.request.OriginalAddDigest != fixture.originalDigest ||
		fixture.boundary.decisionCall != 1 || fixture.boundary.rotationCall != 0 ||
		len(response.Result().Cookies()) != 0 {
		t.Fatalf("wrong issue path issue=%d takes=%d limiter=%d rotation=%d request=%+v",
			fixture.store.issueCalls, fixture.issuedChallenge.takes,
			fixture.boundary.decisionCall, fixture.boundary.rotationCall, fixture.store.request)
	}
	formatted := fmt.Sprintf("%v %#v %v", result, result, fixture.issuedChallenge)
	if strings.Contains(formatted, fixture.nonce) || strings.Contains(formatted, string(fixture.artifact.CanonicalBytes())) ||
		!strings.Contains(formatted, "REDACTED") {
		t.Fatalf("formatted challenge leaked secret material: %s", formatted)
	}
	assertRevocationNoLeak(t, response.Body.Bytes(), fixture.issuedSession.SessionToken(),
		fixture.issuedSession.CSRFToken(), revocationTestIdempotency)
}

func TestRevocationChallengeRejectsUntrustedStoreOutputBeforeNonceRelease(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*testing.T, *revocationHTTPFixture)
		takes     int
	}{
		{name: "nil", configure: func(_ *testing.T, fixture *revocationHTTPFixture) {
			fixture.store.issued = nil
		}},
		{name: "zero challenge", configure: func(_ *testing.T, fixture *revocationHTTPFixture) {
			fixture.issuedChallenge.challenge = hil.CheckedRevocationChallenge{}
		}},
		{name: "invalid policy id", configure: func(_ *testing.T, fixture *revocationHTTPFixture) {
			fixture.issuedChallenge.policyID = "not-a-uuid"
		}},
		{name: "zero policy version", configure: func(_ *testing.T, fixture *revocationHTTPFixture) {
			fixture.issuedChallenge.policyVersion = 0
		}},
		{name: "changed action", configure: func(t *testing.T, fixture *revocationHTTPFixture) {
			_, challenge := revocationHTTPChallenge(t, fixture.sessions.record,
				"019b0000-0000-4000-8000-000000000299", fixture.actionVersion,
				revocationTestTarget, fixture.originalDigest, revocationTestIdempotency,
				fixture.nonce, fixture.now)
			fixture.issuedChallenge.challenge = challenge
		}},
		{name: "changed target artifact", configure: func(t *testing.T, fixture *revocationHTTPFixture) {
			_, challenge := revocationHTTPChallenge(t, fixture.sessions.record,
				fixture.actionID, fixture.actionVersion, "198.51.100.25",
				fixture.originalDigest, revocationTestIdempotency, fixture.nonce, fixture.now)
			fixture.issuedChallenge.challenge = challenge
		}},
		{name: "changed original digest", configure: func(t *testing.T, fixture *revocationHTTPFixture) {
			_, challenge := revocationHTTPChallenge(t, fixture.sessions.record,
				fixture.actionID, fixture.actionVersion, revocationTestTarget,
				hilTestDigest('8'), revocationTestIdempotency, fixture.nonce, fixture.now)
			fixture.issuedChallenge.challenge = challenge
		}},
		{name: "nonce digest mismatch", takes: 1, configure: func(_ *testing.T, fixture *revocationHTTPFixture) {
			fixture.issuedChallenge.nonce = base64RawURL(bytes.Repeat([]byte{0x7b}, hil.NonceBytes))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRevocationHTTPFixture(t)
			test.configure(t, fixture)
			request := postRequest(revocationChallengePath(fixture), revocationChallengeBody(fixture))
			addRevocationBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", revocationTestIdempotency)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || fixture.issuedChallenge.takes != test.takes {
				t.Fatalf("status=%d takes=%d body=%s", response.Code, fixture.issuedChallenge.takes, response.Body.String())
			}
			assertRevocationNoLeak(t, response.Body.Bytes(), fixture.nonce,
				string(fixture.artifact.CanonicalBytes()), fixture.originalDigest)
		})
	}
}

func TestRevocationRoutesAndEnvelopesFailClosed(t *testing.T) {
	fixture := newRevocationHTTPFixture(t)
	validPath := revocationChallengePath(fixture)
	for _, path := range []string{
		revocationPathPrefix + "NOT-A-UUID/revocations",
		revocationPathPrefix + strings.ToUpper(fixture.actionID) + "/revocations",
		revocationPathPrefix + fixture.actionID + "//revocations",
		revocationPathPrefix + fixture.actionID + "/revocations/",
		revocationPathPrefix + fixture.actionID + "/revocation-challenges/extra",
	} {
		request := postRequest(path, `{}`)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("malformed path %q status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	get := getRequest(validPath)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, get)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("method status=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
	rawPath := postRequest(validPath, revocationChallengeBody(fixture))
	rawPath.URL.RawPath = strings.Replace(validPath, "enforcement-actions", "enforcement%2Dactions", 1)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, rawPath)
	if response.Code != http.StatusNotFound {
		t.Fatalf("raw path status=%d", response.Code)
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "x=1" }},
		{name: "force query", mutate: func(request *http.Request) { request.URL.ForceQuery = true }},
		{name: "missing content type", mutate: func(request *http.Request) { request.Header.Del("Content-Type") }},
		{name: "duplicate content type", mutate: func(request *http.Request) { request.Header.Add("Content-Type", "application/json") }},
		{name: "compressed", mutate: func(request *http.Request) { request.Header.Set("Content-Encoding", "gzip") }},
		{name: "chunked", mutate: func(request *http.Request) {
			request.ContentLength = -1
			request.TransferEncoding = []string{"chunked"}
		}},
		{name: "oversize declared", mutate: func(request *http.Request) { request.ContentLength = MaxHILRequestBodyBytes + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := postRequest(validPath, revocationChallengeBody(fixture))
			test.mutate(request)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}

	for name, test := range map[string]struct {
		body   string
		status int
	}{
		"missing":   {body: `{"action_version":3,"target_ipv4":"203.0.113.20"}`, status: http.StatusUnprocessableEntity},
		"unknown":   {body: strings.TrimSuffix(revocationChallengeBody(fixture), "}") + `,"unknown":true}`, status: http.StatusUnprocessableEntity},
		"duplicate": {body: strings.TrimSuffix(revocationChallengeBody(fixture), "}") + `,"action_version":3}`, status: http.StatusUnprocessableEntity},
		"malformed": {body: `{"action_version":`, status: http.StatusUnprocessableEntity},
		"oversize":  {body: `{"padding":"` + strings.Repeat("x", int(MaxHILRequestBodyBytes)+1) + `"}`, status: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			local := newRevocationHTTPFixture(t)
			request := postRequest(revocationChallengePath(local), test.body)
			addRevocationBrowserCredential(t, request, local)
			request.Header.Set("Idempotency-Key", revocationTestIdempotency)
			response := httptest.NewRecorder()
			local.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if local.store.issueCalls != 0 {
				t.Fatal("invalid JSON reached persistence")
			}
		})
	}
}

func TestRevocationDecisionCommitsOneExactRotationAndFrozenDTO(t *testing.T) {
	fixture := newRevocationHTTPFixture(t)
	stored := revocationHTTPStored(t, fixture, fixture.sessions.record, revocationReason(), true)
	fixture.store.stored = stored
	request := postRequest(revocationDecisionPath(fixture), revocationDecisionBody(fixture, revocationReason()))
	addRevocationBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", revocationTestIdempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("decision status=%d body=%s", response.Code, response.Body.String())
	}
	var result revocationDecisionEnvelope
	decodeRevocationHTTP(t, response.Body.Bytes(), &result)
	decision, err := hil.ParseCanonicalDecision(result.Decision)
	if err != nil || decision.Digest() != stored.decision.Digest() ||
		result.RevocationID != revocationTestRevocationID ||
		result.AuthorizationID != revocationTestAuthorizationID ||
		result.AuthorizationDigest != stored.authorizationDigest ||
		result.OutboxJobID != revocationTestOutboxID || result.AuditEventID != revocationTestAuditID ||
		result.Session.SessionID != fixture.boundary.lastRotation.Issued.Record.ID.String() ||
		result.CSRFToken != fixture.boundary.lastRotation.Issued.CSRFToken() {
		t.Fatalf("wrong decision response: %+v err=%v", result, err)
	}
	if fixture.store.commitCalls != 1 || fixture.store.lookupCalls != 0 ||
		fixture.boundary.rotationCall != 1 || !stored.sessionRotated {
		t.Fatalf("commit=%d lookup=%d rotations=%d", fixture.store.commitCalls,
			fixture.store.lookupCalls, fixture.boundary.rotationCall)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("missing safe replacement cookie: %+v", cookies)
	}
	assertRevocationNoLeak(t, response.Body.Bytes(), revocationReason().ReasonText,
		fixture.nonce, fixture.issuedSession.SessionToken(),
		string(fixture.artifact.CanonicalBytes()))
	formatted := fmt.Sprintf("%v %#v %v", result, result, stored)
	if strings.Contains(formatted, result.CSRFToken) || strings.Contains(formatted, revocationReason().ReasonText) ||
		!strings.Contains(formatted, "REDACTED") {
		t.Fatalf("formatted response leaked secret: %s", formatted)
	}
}

func TestRevocationDecisionRejectsRoundTripSubstitutionBeforeCommit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any, *revocationHTTPFixture)
		status int
		code   ErrorCode
	}{
		{name: "version", mutate: func(value map[string]any, _ *revocationHTTPFixture) { value["action_version"] = 4 }, status: 409, code: ErrorDigestMismatch},
		{name: "target", mutate: func(value map[string]any, _ *revocationHTTPFixture) { value["target_ipv4"] = "198.51.100.25" }, status: 409, code: ErrorDigestMismatch},
		{name: "original", mutate: func(value map[string]any, _ *revocationHTTPFixture) {
			value["original_add_digest"] = hilTestDigest('8')
		}, status: 409, code: ErrorDigestMismatch},
		{name: "nonce", mutate: func(value map[string]any, _ *revocationHTTPFixture) {
			value["challenge_nonce"] = base64RawURL(bytes.Repeat([]byte{0x33}, hil.NonceBytes))
		}, status: 409, code: ErrorDigestMismatch},
		{name: "add artifact", mutate: func(value map[string]any, _ *revocationHTTPFixture) {
			value["canonical_revoke_artifact"] = "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n"
		}, status: 422, code: ErrorSchemaInvalid},
		{name: "inspect artifact", mutate: func(value map[string]any, _ *revocationHTTPFixture) {
			value["canonical_revoke_artifact"] = `{"schema_version":"nft-inspect-v1"}`
		}, status: 422, code: ErrorSchemaInvalid},
		{name: "extra newline", mutate: func(value map[string]any, fixture *revocationHTTPFixture) {
			value["canonical_revoke_artifact"] = string(fixture.artifact.CanonicalBytes()) + "\n"
		}, status: 422, code: ErrorSchemaInvalid},
		{name: "extra statement", mutate: func(value map[string]any, fixture *revocationHTTPFixture) {
			value["canonical_revoke_artifact"] = string(fixture.artifact.CanonicalBytes()) + string(fixture.artifact.CanonicalBytes())
		}, status: 422, code: ErrorSchemaInvalid},
		{name: "bad policy id", mutate: func(value map[string]any, _ *revocationHTTPFixture) { value["policy_id"] = "bad" }, status: 422, code: ErrorSchemaInvalid},
		{name: "zero policy version", mutate: func(value map[string]any, _ *revocationHTTPFixture) { value["policy_version"] = 0 }, status: 422, code: ErrorSchemaInvalid},
		{name: "add reason code", mutate: func(value map[string]any, _ *revocationHTTPFixture) {
			value["reason"].(map[string]any)["reason_code"] = string(hil.ReasonThreatConfirmed)
		}, status: 422, code: ErrorSchemaInvalid},
		{name: "non NFC reason", mutate: func(value map[string]any, _ *revocationHTTPFixture) {
			value["reason"].(map[string]any)["reason_text"] = "Cafe\u0301 removal"
		}, status: 422, code: ErrorSchemaInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRevocationHTTPFixture(t)
			document := revocationDecisionDocument(fixture, revocationReason())
			test.mutate(document, fixture)
			body, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			path := revocationDecisionPath(fixture)
			if test.name == "version" {
				// Keep the path fixed; the body/challenge version mismatch is the assertion.
			}
			request := postRequest(path, string(body))
			addRevocationBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", revocationTestIdempotency)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertRevocationError(t, response, test.status, test.code)
			if fixture.store.commitCalls != 0 || fixture.boundary.rotationCall != 0 {
				t.Fatalf("invalid substitution reached commit=%d rotation=%d", fixture.store.commitCalls, fixture.boundary.rotationCall)
			}
			assertRevocationNoLeak(t, response.Body.Bytes(), fixture.nonce,
				string(fixture.artifact.CanonicalBytes()), revocationReason().ReasonText)
		})
	}

	t.Run("path action", func(t *testing.T) {
		fixture := newRevocationHTTPFixture(t)
		path := revocationPathPrefix + "019b0000-0000-4000-8000-000000000299/revocations"
		request := postRequest(path, revocationDecisionBody(fixture, revocationReason()))
		addRevocationBrowserCredential(t, request, fixture)
		request.Header.Set("Idempotency-Key", revocationTestIdempotency)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		assertRevocationError(t, response, http.StatusConflict, ErrorDigestMismatch)
		if fixture.store.commitCalls != 0 {
			t.Fatal("path mismatch reached commit")
		}
	})
}

func TestRevocationDecisionAuthAndCoordinatorErrorsAreStableAndRedacted(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*revocationHTTPFixture, *http.Request)
		status    int
		code      ErrorCode
	}{
		{name: "origin", configure: func(_ *revocationHTTPFixture, request *http.Request) {
			request.Header.Set("Origin", "https://evil.example.test")
		}, status: 403, code: ErrorPermissionDenied},
		{name: "csrf", configure: func(_ *revocationHTTPFixture, request *http.Request) { request.Header.Set("X-CSRF-Token", "wrong") }, status: 403, code: ErrorCSRFInvalid},
		{name: "step up", configure: func(fixture *revocationHTTPFixture, _ *http.Request) { fixture.boundary.forceStepUp = true }, status: 401, code: ErrorStepUpRequired},
		{name: "rate", configure: func(fixture *revocationHTTPFixture, _ *http.Request) {
			fixture.boundary.decisionErr = &adminauth.RateLimitError{Scope: adminauth.RateLimitDecision, RetryAfter: time.Second}
		}, status: 429, code: ErrorRateLimited},
		{name: "expired", configure: func(fixture *revocationHTTPFixture, _ *http.Request) {
			fixture.store.commits = []fakeRevocationResult{{err: hilstore.ErrChallengeExpired}}
		}, status: 422, code: ErrorChallengeExpired},
		{name: "replayed or changed body", configure: func(fixture *revocationHTTPFixture, _ *http.Request) {
			fixture.store.commits = []fakeRevocationResult{{err: hilstore.ErrConflict}}
		}, status: 409, code: ErrorIdempotencyConflict},
		{name: "validation stale", configure: func(fixture *revocationHTTPFixture, _ *http.Request) {
			fixture.store.commits = []fakeRevocationResult{{err: hilstore.ErrValidationStale}}
		}, status: 422, code: ErrorValidationFailed},
		{name: "unavailable", configure: func(fixture *revocationHTTPFixture, _ *http.Request) {
			fixture.store.commits = []fakeRevocationResult{{err: hilstore.ErrUnavailable}, {err: hilstore.ErrUnavailable}}
		}, status: 503, code: ErrorServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRevocationHTTPFixture(t)
			request := postRequest(revocationDecisionPath(fixture), revocationDecisionBody(fixture, revocationReason()))
			addRevocationBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", revocationTestIdempotency)
			test.configure(fixture, request)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertRevocationError(t, response, test.status, test.code)
			if test.name == "unavailable" && fixture.store.commitCalls != 2 {
				t.Fatalf("unavailable retries=%d", fixture.store.commitCalls)
			}
			assertRevocationNoLeak(t, response.Body.Bytes(), fixture.nonce,
				fixture.originalDigest, string(fixture.artifact.CanonicalBytes()),
				revocationReason().ReasonText, fixture.issuedSession.SessionToken(),
				fixture.issuedSession.CSRFToken())
		})
	}
}

func TestRevocationStoredResultCorruptionFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeStoredRevocation)
	}{
		{name: "revocation id", mutate: func(value *fakeStoredRevocation) { value.revocationID = "bad" }},
		{name: "authorization id", mutate: func(value *fakeStoredRevocation) { value.authorizationID = "bad" }},
		{name: "authorization digest", mutate: func(value *fakeStoredRevocation) { value.authorizationDigest = "bad" }},
		{name: "valid changed authorization digest", mutate: func(value *fakeStoredRevocation) { value.authorizationDigest = hilTestDigest('a') }},
		{name: "outbox id", mutate: func(value *fakeStoredRevocation) { value.outboxID = "bad" }},
		{name: "audit id", mutate: func(value *fakeStoredRevocation) { value.auditID = "bad" }},
		{name: "duplicate ids", mutate: func(value *fakeStoredRevocation) { value.auditID = value.outboxID }},
		{name: "decision", mutate: func(value *fakeStoredRevocation) { value.decision = hil.CheckedRevocationDecision{} }},
		{name: "decision reason", mutate: func(value *fakeStoredRevocation) {
			// Filled per-test below because constructing checked values needs the fixture.
		}},
		{name: "session rotated", mutate: func(value *fakeStoredRevocation) { value.sessionRotated = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRevocationHTTPFixture(t)
			stored := revocationHTTPStored(t, fixture, fixture.sessions.record, revocationReason(), true)
			if test.name == "decision reason" {
				changed := revocationReason()
				changed.ReasonText = "A different operator reason"
				stored = revocationHTTPStored(t, fixture, fixture.sessions.record, changed, true)
			}
			test.mutate(&stored)
			fixture.store.stored = stored
			request := postRequest(revocationDecisionPath(fixture), revocationDecisionBody(fixture, revocationReason()))
			addRevocationBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", revocationTestIdempotency)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code < 400 || response.Code >= 600 {
				t.Fatalf("corrupt result succeeded: status=%d body=%s", response.Code, response.Body.String())
			}
			if !hasExpiredSessionCookie(response.Result().Cookies()) {
				t.Fatalf("corrupt result did not expire old credential: %+v", response.Result().Cookies())
			}
		})
	}
}

func TestRevocationAuthorizationDigestGolden(t *testing.T) {
	originalAddDigest := hilTestDigest('1')
	decision := hil.Decision{
		Operation:               hil.OperationRevoke,
		Decision:                hil.DecisionRevoked,
		ResourceType:            hil.ResourceEnforcementAction,
		ResourceID:              "019b0000-0000-4000-8000-000000000301",
		ActorID:                 "administrator",
		CanonicalArtifactDigest: hilTestDigest('a'),
		NonceDigest:             hilTestDigest('b'),
		EvidenceSnapshotDigest:  hilTestDigest('c'),
		GeneratedArtifactDigest: hilTestDigest('d'),
		ReasonDigest:            hilTestDigest('e'),
		IdempotencyKeyDigest:    hilTestDigest('f'),
		OriginalAddDigest:       &originalAddDigest,
		PolicyDigest:            hilTestDigest('2'),
		TargetIPv4:              "203.0.113.77",
		DecidedAt:               time.Date(2026, 7, 19, 1, 2, 3, 123456000, time.UTC),
		DecisionValidUntil:      time.Date(2026, 7, 19, 1, 7, 3, 654321000, time.UTC),
	}
	got, ok := revocationAuthorizationDigest(
		decision,
		"019b0000-0000-4000-8000-000000000302",
		"019b0000-0000-4000-8000-000000000303",
		7,
	)
	const expected = "sha256:db4c1891903d7b91b906ee5ed111741e511fc68868116693eaff11eb81b9b7f3"
	if !ok || got != expected {
		t.Fatalf("authorization golden digest=%q ok=%t want=%q", got, ok, expected)
	}
}

func TestRevocationUnavailableRetryReusesExactCommitAndRetainedLiveChild(t *testing.T) {
	fixture := newRevocationHTTPFixture(t)
	stored := revocationHTTPStored(t, fixture, fixture.sessions.record, revocationReason(), false)
	fixture.store.commits = []fakeRevocationResult{
		{err: hilstore.ErrUnavailable},
		{stored: stored},
	}
	fixture.store.commitHook = func(call int) {
		if call == 1 {
			// Model the atomic coordinator commit whose first response was lost.
			// The exact retained replacement is the sole live child.
			fixture.sessions.record = fixture.boundary.lastRotation.Issued.Record
		}
	}
	request := postRequest(revocationDecisionPath(fixture), revocationDecisionBody(fixture, revocationReason()))
	addRevocationBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", revocationTestIdempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("exact retry status=%d body=%s", response.Code, response.Body.String())
	}
	if fixture.store.commitCalls != 2 || len(fixture.store.commitSeen) != 2 ||
		!reflect.DeepEqual(fixture.store.commitSeen[0], fixture.store.commitSeen[1]) {
		t.Fatalf("retry did not reuse exact checked commit: calls=%d seen=%d",
			fixture.store.commitCalls, len(fixture.store.commitSeen))
	}
	var result revocationDecisionEnvelope
	decodeRevocationHTTP(t, response.Body.Bytes(), &result)
	if result.Session.SessionID != fixture.boundary.lastRotation.Issued.Record.ID.String() ||
		result.CSRFToken != fixture.boundary.lastRotation.Issued.CSRFToken() ||
		!issuedCredentialCookie(response.Result().Cookies()) {
		t.Fatalf("exact retry omitted retained child credentials: %+v", result)
	}
}

func TestRevocationDecisionStrictJSONNeverReachesRotation(t *testing.T) {
	base := newRevocationHTTPFixture(t)
	valid := revocationDecisionBody(base, revocationReason())
	tests := map[string]struct {
		body   string
		status int
	}{
		"missing reason": {
			body:   strings.Replace(valid, `,"reason":{"reason_code":"operator_request","reason_text":"Remove the synthetic block","schema_version":"hil-reason-v1"}`, "", 1),
			status: http.StatusUnprocessableEntity,
		},
		"unknown": {
			body:   strings.TrimSuffix(valid, "}") + `,"unknown":"database-secret"}`,
			status: http.StatusUnprocessableEntity,
		},
		"duplicate": {
			body:   strings.TrimSuffix(valid, "}") + `,"policy_version":3}`,
			status: http.StatusUnprocessableEntity,
		},
		"oversize": {
			body:   `{"padding":"` + strings.Repeat("x", int(MaxHILRequestBodyBytes)+1) + `"}`,
			status: http.StatusBadRequest,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newRevocationHTTPFixture(t)
			request := postRequest(revocationDecisionPath(fixture), test.body)
			addRevocationBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", revocationTestIdempotency)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if fixture.boundary.rotationCall != 0 || fixture.store.commitCalls != 0 {
				t.Fatalf("invalid JSON reached rotation=%d commit=%d",
					fixture.boundary.rotationCall, fixture.store.commitCalls)
			}
			assertRevocationNoLeak(t, response.Body.Bytes(), "database-secret",
				fixture.nonce, revocationReason().ReasonText)
		})
	}
}

func TestRevocationHistoricalReplayRequiresUniqueLiveChildProof(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   ErrorCode
	}{
		{name: "missing or inactive child", err: adminstore.ErrNotFound, status: http.StatusUnauthorized, code: ErrorAuthenticationRequired},
		{name: "ambiguous store", err: adminstore.ErrUnavailable, status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable},
		{name: "mutated parent", err: adminstore.ErrConflict, status: http.StatusConflict, code: ErrorStaleVersion},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRevocationHTTPFixture(t)
			fixture.sessions.loadErr = adminstore.ErrNotFound
			fixture.sessions.replayErr = test.err
			request := postRequest(revocationDecisionPath(fixture), revocationDecisionBody(fixture, revocationReason()))
			addRevocationBrowserCredential(t, request, fixture)
			request.Header.Set("Idempotency-Key", revocationTestIdempotency)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertRevocationError(t, response, test.status, test.code)
			if fixture.store.lookupCalls != 0 || fixture.store.commitCalls != 0 {
				t.Fatalf("unproved child reached persistence lookup=%d commit=%d",
					fixture.store.lookupCalls, fixture.store.commitCalls)
			}
		})
	}
}

func TestRevocationUncertainCommitUsesHistoricalOnlyReplayAndRevalidatesParent(t *testing.T) {
	fixture := newRevocationHTTPFixture(t)
	stored := revocationHTTPStored(t, fixture, fixture.sessions.record, revocationReason(), false)
	fixture.store.commits = []fakeRevocationResult{{err: hilstore.ErrUnavailable}, {err: hilstore.ErrUnavailable}}
	fixture.store.lookups = []fakeRevocationResult{{stored: stored}}
	fixture.store.commitHook = func(call int) {
		if call != 1 {
			return
		}
		revoked := fixture.sessions.record
		revokedAt := *fixture.boundary.lastRotation.Revoked.RevokedAt
		revoked.RevokedAt = &revokedAt
		fixture.sessions.replayRecord = revoked
	}
	request := postRequest(revocationDecisionPath(fixture), revocationDecisionBody(fixture, revocationReason()))
	addRevocationBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", revocationTestIdempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("uncertain recovery status=%d body=%s", response.Code, response.Body.String())
	}
	var result historicalRevocationEnvelope
	decodeRevocationHTTP(t, response.Body.Bytes(), &result)
	if !result.Replayed || !result.ReauthenticationRequired || result.RevocationID != revocationTestRevocationID ||
		fixture.store.commitCalls != 2 || fixture.store.lookupCalls != 1 || fixture.sessions.replayLoads != 2 {
		t.Fatalf("wrong recovery result=%+v commits=%d lookups=%d replay-loads=%d",
			result, fixture.store.commitCalls, fixture.store.lookupCalls, fixture.sessions.replayLoads)
	}
	if !hasExpiredSessionCookie(response.Result().Cookies()) ||
		bytes.Contains(response.Body.Bytes(), []byte(`"session"`)) ||
		bytes.Contains(response.Body.Bytes(), []byte(`"csrf_token"`)) {
		t.Fatalf("uncertain replay returned credentials: cookies=%+v body=%s", response.Result().Cookies(), response.Body.String())
	}
}

func TestRevocationHistoricalReplayRejectsParentMutationAfterSlowLookup(t *testing.T) {
	fixture := newRevocationHTTPFixture(t)
	revoked := fixture.sessions.record
	revokedAt := fixture.now.Add(time.Second)
	revoked.RevokedAt = &revokedAt
	fixture.sessions.replayRecord = revoked
	fixture.sessions.loadErr = adminstore.ErrNotFound
	stored := revocationHTTPStored(t, fixture, revoked, revocationReason(), false)
	fixture.store.lookups = []fakeRevocationResult{{stored: stored}}
	fixture.store.lookupHook = func(_ int) {
		mutated := fixture.sessions.replayRecord
		mutated.ExpiresAt = mutated.ExpiresAt.Add(-time.Second)
		fixture.sessions.replayRecord = mutated
	}
	request := postRequest(revocationDecisionPath(fixture), revocationDecisionBody(fixture, revocationReason()))
	addRevocationBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", revocationTestIdempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	assertRevocationError(t, response, http.StatusServiceUnavailable, ErrorServiceUnavailable)
	if fixture.store.commitCalls != 0 || fixture.store.lookupCalls != 1 || fixture.sessions.replayLoads != 2 ||
		!hasExpiredSessionCookie(response.Result().Cookies()) {
		t.Fatalf("mutation path commit=%d lookup=%d replay-load=%d cookies=%+v",
			fixture.store.commitCalls, fixture.store.lookupCalls, fixture.sessions.replayLoads,
			response.Result().Cookies())
	}
}

func TestRevocationDirectOldParentReplayReturnsNoCredentialMaterial(t *testing.T) {
	fixture := newRevocationHTTPFixture(t)
	revoked := fixture.sessions.record
	revokedAt := fixture.now.Add(time.Second)
	revoked.RevokedAt = &revokedAt
	fixture.sessions.replayRecord = revoked
	fixture.sessions.loadErr = adminstore.ErrNotFound
	stored := revocationHTTPStored(t, fixture, revoked, revocationReason(), false)
	fixture.store.lookups = []fakeRevocationResult{{stored: stored}}
	request := postRequest(revocationDecisionPath(fixture), revocationDecisionBody(fixture, revocationReason()))
	addRevocationBrowserCredential(t, request, fixture)
	request.Header.Set("Idempotency-Key", revocationTestIdempotency)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("historical status=%d body=%s", response.Code, response.Body.String())
	}
	var result historicalRevocationEnvelope
	decodeRevocationHTTP(t, response.Body.Bytes(), &result)
	if !result.Replayed || !result.ReauthenticationRequired ||
		fixture.store.commitCalls != 0 || fixture.store.lookupCalls != 1 || fixture.sessions.replayLoads != 2 {
		t.Fatalf("wrong historical replay: %+v", result)
	}
	if bytes.Contains(response.Body.Bytes(), []byte(`"session"`)) ||
		bytes.Contains(response.Body.Bytes(), []byte(`"csrf_token"`)) ||
		!hasExpiredSessionCookie(response.Result().Cookies()) {
		t.Fatalf("historical replay leaked credential: %s %+v", response.Body.String(), response.Result().Cookies())
	}
}

func revocationDecisionDocument(fixture *revocationHTTPFixture, reason hil.Reason) map[string]any {
	return map[string]any{
		"action_version":            fixture.actionVersion,
		"target_ipv4":               revocationTestTarget,
		"original_add_digest":       fixture.originalDigest,
		"challenge":                 json.RawMessage(fixture.challenge.CanonicalBytes()),
		"challenge_nonce":           fixture.nonce,
		"canonical_revoke_artifact": string(fixture.artifact.CanonicalBytes()),
		"policy_id":                 fixture.policyID,
		"policy_version":            fixture.policyVersion,
		"reason": map[string]any{
			"schema_version": reason.SchemaVersion,
			"reason_code":    string(reason.ReasonCode),
			"reason_text":    reason.ReasonText,
		},
	}
}

func assertRevocationError(t *testing.T, response *httptest.ResponseRecorder, status int, code ErrorCode) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	var value errorResponse
	decodeRevocationHTTP(t, response.Body.Bytes(), &value)
	if value.Code != code || value.Message == "" || value.TraceID == "" || value.Details == nil {
		t.Fatalf("wrong error response: %+v", value)
	}
}

func assertRevocationNoLeak(t *testing.T, body []byte, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if value != "" && bytes.Contains(body, []byte(value)) {
			t.Fatalf("response leaked forbidden value %q: %s", value, body)
		}
	}
}

func decodeRevocationHTTP(t *testing.T, body []byte, destination any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode response: %v body=%s", err, body)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing response: %v", err)
	}
}

func hasExpiredSessionCookie(cookies []*http.Cookie) bool {
	for _, cookie := range cookies {
		if cookie != nil && cookie.MaxAge < 0 && cookie.Value == "" {
			return true
		}
	}
	return false
}

func issuedCredentialCookie(cookies []*http.Cookie) bool {
	for _, cookie := range cookies {
		if cookie != nil && cookie.MaxAge >= 0 && cookie.Value != "" && cookie.HttpOnly && cookie.Secure {
			return true
		}
	}
	return false
}
