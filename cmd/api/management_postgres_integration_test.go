//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminapi"
	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/hil"
)

type managementHTTPServer struct {
	server *httptest.Server
	client *http.Client
	jar    http.CookieJar
	base   *url.URL
}

type sessionResponse struct {
	Session struct {
		ActorID         string    `json:"actor_id"`
		SessionID       string    `json:"session_id"`
		AuthenticatedAt time.Time `json:"authenticated_at"`
		ExpiresAt       time.Time `json:"expires_at"`
	} `json:"session"`
	CSRFToken string `json:"csrf_token"`
}

type challengeResponse struct {
	Challenge      json.RawMessage `json:"challenge"`
	ChallengeNonce string          `json:"challenge_nonce"`
}

type decisionResponse struct {
	Decision            json.RawMessage `json:"decision"`
	ActionID            *string         `json:"action_id"`
	AuthorizationDigest *string         `json:"authorization_digest"`
	OutboxJobID         *string         `json:"outbox_job_id"`
	Session             struct {
		ActorID         string    `json:"actor_id"`
		SessionID       string    `json:"session_id"`
		AuthenticatedAt time.Time `json:"authenticated_at"`
		ExpiresAt       time.Time `json:"expires_at"`
	} `json:"session"`
	CSRFToken string `json:"csrf_token"`
	Replayed  bool   `json:"replayed"`
	Reauth    bool   `json:"reauthentication_required"`
}

type httpResult struct {
	status  int
	header  http.Header
	body    []byte
	cookies []*http.Cookie
}

func TestManagementHILHTTPAgainstPostgreSQL17(t *testing.T) {
	fixture := newManagementPGFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	approve := managementExactFixture(t, 1, now)
	reject := managementExactFixture(t, 2, now)
	concurrent := managementExactFixture(t, 3, now)
	staleBefore := managementExactFixture(t, 4, now)
	staleBetween := managementExactFixture(t, 5, now)
	negative := managementExactFixture(t, 7, now)
	for _, exact := range []exactFixture{approve, reject, concurrent, staleBefore, staleBetween, negative} {
		seedManagementExactFixture(t, fixture, exact, now)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := startManagementHTTPServer(t, fixture, jar)

	// The direct TCP peer, not spoofed forwarding headers, owns the source-rate
	// bucket. Five bad passwords are generic authentication failures and a
	// sixth request with another X-Forwarded-For is still rate-limited.
	for attempt := 1; attempt <= 6; attempt++ {
		body := mustJSON(t, map[string]any{"username": integrationAdminUser, "password": "wrong-password"})
		result := server.do(t, http.MethodPost, adminapi.LoginPath, body, requestOptions{
			origin: integrationOrigin, forwardedFor: fmt.Sprintf("198.51.100.%d", attempt),
		})
		if attempt <= 5 {
			assertHTTPError(t, result, http.StatusUnauthorized, "authentication_required", "wrong-password")
		} else {
			assertHTTPError(t, result, http.StatusTooManyRequests, "rate_limited", "wrong-password")
			if result.header.Get("Retry-After") == "" {
				t.Fatal("login rate limit omitted Retry-After")
			}
		}
	}
	server.close()
	server = startManagementHTTPServer(t, fixture, jar)

	loginBody := mustJSON(t, map[string]any{"username": integrationAdminUser, "password": integrationAdminPass})
	login := server.do(t, http.MethodPost, adminapi.LoginPath, loginBody, requestOptions{origin: integrationOrigin})
	if login.status != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.status, login.body)
	}
	var session sessionResponse
	decodeHTTP(t, login.body, &session)
	if session.Session.ActorID != "administrator" || session.Session.SessionID == "" || session.CSRFToken == "" {
		t.Fatalf("invalid login projection: %+v", session)
	}
	loginCookie := issuedSecureCookie(t, login.cookies)
	if !loginCookie.Secure || !loginCookie.HttpOnly || loginCookie.SameSite != http.SameSiteStrictMode || loginCookie.Path != "/" {
		t.Fatalf("unsafe session cookie: %+v", loginCookie)
	}

	// Age authenticated_at beyond the strict 15-minute boundary while keeping
	// the opaque session live. Challenge issuance must require a password
	// step-up, which rotates both the session and CSRF values.
	if _, err = fixture.owner.Exec(fixture.ctx, `
WITH fixed AS (SELECT clock_timestamp() - interval '16 minutes' AS moment)
UPDATE sentinelflow.admin_sessions
SET created_at = fixed.moment, authenticated_at = fixed.moment,
    expires_at = fixed.moment + interval '8 hours'
FROM fixed
WHERE session_id = $1::uuid`, session.Session.SessionID); err != nil {
		t.Fatalf("age authenticated session: %v", err)
	}
	challengeBody := artifactRequestBody(t, approve.Exact, hil.OperationApprove)
	stepRequired := server.do(t, http.MethodPost, challengePath(approve), challengeBody, requestOptions{
		origin: integrationOrigin, csrf: session.CSRFToken, idempotency: "step-required-challenge-key-0001",
	})
	assertHTTPError(t, stepRequired, http.StatusUnauthorized, "step_up_required", integrationAdminPass)
	step := server.do(t, http.MethodPost, adminapi.StepUpPath,
		mustJSON(t, map[string]any{"password": integrationAdminPass}),
		requestOptions{origin: integrationOrigin, csrf: session.CSRFToken})
	if step.status != http.StatusOK {
		t.Fatalf("step-up status=%d body=%s", step.status, step.body)
	}
	var stepped sessionResponse
	decodeHTTP(t, step.body, &stepped)
	if stepped.Session.SessionID == session.Session.SessionID || stepped.CSRFToken == session.CSRFToken ||
		time.Since(stepped.Session.AuthenticatedAt) > time.Minute {
		t.Fatalf("step-up did not rotate and refresh authentication: %+v", stepped)
	}
	session = stepped

	// Origin, CSRF, anonymous access, strict JSON, body bounds, and exact
	// artifact binding all fail before authority can be created.
	anonymous := server.doWithoutJar(t, http.MethodPost, challengePath(approve), challengeBody,
		requestOptions{origin: integrationOrigin, csrf: session.CSRFToken, idempotency: "anonymous-challenge-key-0001"})
	assertHTTPError(t, anonymous, http.StatusUnauthorized, "authentication_required", integrationAdminPass)
	wrongOrigin := server.do(t, http.MethodPost, challengePath(approve), challengeBody,
		requestOptions{origin: "https://evil.example.test", csrf: session.CSRFToken, idempotency: "origin-challenge-key-0001"})
	assertHTTPError(t, wrongOrigin, http.StatusForbidden, "permission_denied", integrationAdminPass)
	wrongCSRF := server.do(t, http.MethodPost, challengePath(approve), challengeBody,
		requestOptions{origin: integrationOrigin, csrf: "wrong-csrf-token", idempotency: "csrf-challenge-key-000001"})
	assertHTTPError(t, wrongCSRF, http.StatusForbidden, "csrf_invalid", integrationAdminPass)
	for name, body := range map[string][]byte{
		"malformed": []byte(`{"operation":`),
		"unknown":   append(challengeBody[:len(challengeBody)-1], []byte(`,"unknown":"secret-body-value"}`)...),
		"oversize":  []byte(`{"padding":"` + strings.Repeat("x", int(adminapi.MaxHILRequestBodyBytes)+1) + `"}`),
	} {
		result := server.do(t, http.MethodPost, challengePath(approve), body, requestOptions{
			origin: integrationOrigin, csrf: session.CSRFToken, idempotency: "strict-json-" + name + "-00000001",
		})
		if result.status < 400 || result.status >= 500 {
			t.Fatalf("%s status=%d body=%s", name, result.status, result.body)
		}
		assertNoLeak(t, result.body, integrationAdminPass, "secret-body-value")
	}
	server.close()
	server = startManagementHTTPServer(t, fixture, jar)

	// Five authenticated HIL attempts are allowed for the exact session; the
	// sixth is rejected before parsing despite changing request bodies.
	badBinding := mutateArtifactBody(t, approve.Exact, hil.OperationApprove, "policy_digest", managementDigest('9'))
	for attempt := 1; attempt <= 6; attempt++ {
		result := server.do(t, http.MethodPost, challengePath(approve), badBinding, requestOptions{
			origin: integrationOrigin, csrf: session.CSRFToken,
			idempotency: fmt.Sprintf("decision-rate-key-%020d", attempt),
		})
		if attempt <= 5 {
			assertHTTPError(t, result, http.StatusConflict, "digest_mismatch", integrationAdminPass)
		} else {
			assertHTTPError(t, result, http.StatusTooManyRequests, "rate_limited", integrationAdminPass)
		}
	}
	server.close()
	server = startManagementHTTPServer(t, fixture, jar)

	// Issue a negative-only challenge and prove swapped nonce/operation/reason,
	// missing idempotency, and duplicate challenge idempotency do not consume it.
	negativeIssueKey := "negative-issue-idempotency-key-0001"
	issuedNegative := issueChallenge(t, server, negative, hil.OperationApprove, session.CSRFToken, negativeIssueKey)
	parsedNegative, err := hil.ParseCanonicalChallenge(issuedNegative.Challenge)
	if err != nil {
		t.Fatalf("parse bounded challenge: %v", err)
	}
	negativeValue := parsedNegative.Value()
	expectedNegativeExpiry := negativeValue.IssuedAt.Add(hil.ChallengeLifetime)
	if negativeValue.ValidationValidUntil.Before(expectedNegativeExpiry) {
		expectedNegativeExpiry = negativeValue.ValidationValidUntil
	}
	if !negativeValue.ExpiresAt.Equal(expectedNegativeExpiry) ||
		!negativeValue.ExpiresAt.After(negativeValue.IssuedAt) {
		t.Fatalf("challenge lifetime drift: value=%+v err=%v", parsedNegative.Value(), err)
	}
	duplicateIssue := server.do(t, http.MethodPost, challengePath(negative), artifactRequestBody(t, negative.Exact, hil.OperationApprove),
		requestOptions{origin: integrationOrigin, csrf: session.CSRFToken, idempotency: negativeIssueKey})
	assertHTTPError(t, duplicateIssue, http.StatusConflict, "idempotency_conflict", issuedNegative.ChallengeNonce)
	missingID := server.do(t, http.MethodPost, decisionPath(negative),
		decisionRequestBody(t, negative.Exact, hil.OperationApprove, issuedNegative, "Confirmed synthetic threat"),
		requestOptions{origin: integrationOrigin, csrf: session.CSRFToken})
	assertHTTPError(t, missingID, http.StatusUnprocessableEntity, "schema_invalid", issuedNegative.ChallengeNonce)
	badNonce := issuedNegative
	badNonce.ChallengeNonce = strings.Repeat("A", len(issuedNegative.ChallengeNonce))
	for name, body := range map[string][]byte{
		"nonce":     decisionRequestBody(t, negative.Exact, hil.OperationApprove, badNonce, "Confirmed synthetic threat"),
		"operation": decisionRequestBody(t, negative.Exact, hil.OperationReject, issuedNegative, "Synthetic traffic was benign"),
		"reason":    decisionRequestBody(t, negative.Exact, hil.OperationApprove, issuedNegative, ""),
	} {
		result := server.do(t, http.MethodPost, decisionPath(negative), body, requestOptions{
			origin: integrationOrigin, csrf: session.CSRFToken, idempotency: "negative-decision-" + name + "-000001",
		})
		if result.status < 400 || result.status >= 500 {
			t.Fatalf("negative %s status=%d body=%s", name, result.status, result.body)
		}
		assertNoLeak(t, result.body, issuedNegative.ChallengeNonce, integrationAdminPass, "Confirmed synthetic threat")
	}
	server.close()
	server = startManagementHTTPServer(t, fixture, jar)

	// Approval commits one exact authority and rotates the session. Reissuing
	// the same challenge idempotency conflicts, while response-loss replay with
	// the revoked parent returns only immutable historical fields.
	approveKey := "approve-issue-idempotency-key-000001"
	approveChallenge := issueChallenge(t, server, approve, hil.OperationApprove, session.CSRFToken, approveKey)
	oldCookie := currentCookie(t, server)
	oldCSRF := session.CSRFToken
	approveDecisionBody := decisionRequestBody(t, approve.Exact, hil.OperationApprove, approveChallenge, "Confirmed synthetic threat")
	approvedResult := server.do(t, http.MethodPost, decisionPath(approve), approveDecisionBody,
		requestOptions{origin: integrationOrigin, csrf: oldCSRF, idempotency: approveKey})
	approved := requireDecisionAuthority(t, approvedResult)
	if approved.CSRFToken == "" || approved.Session.SessionID == "" {
		t.Fatalf("approval omitted replacement session: %+v", approved)
	}
	session.CSRFToken = approved.CSRFToken
	session.Session.SessionID = approved.Session.SessionID
	historical := server.doWithCookie(t, http.MethodPost, decisionPath(approve), approveDecisionBody,
		requestOptions{origin: integrationOrigin, csrf: oldCSRF, idempotency: approveKey}, oldCookie)
	if historical.status != http.StatusOK {
		t.Fatalf("historical replay status=%d body=%s", historical.status, historical.body)
	}
	var replay decisionResponse
	decodeHTTP(t, historical.body, &replay)
	if !replay.Replayed || !replay.Reauth || replay.ActionID == nil || replay.CSRFToken != "" || replay.Session.SessionID != "" {
		t.Fatalf("historical replay mixed credentials or omitted authority: %+v", replay)
	}
	conflictBody := decisionRequestBody(t, approve.Exact, hil.OperationApprove, approveChallenge, "Different operator reason")
	conflict := server.doWithCookie(t, http.MethodPost, decisionPath(approve), conflictBody,
		requestOptions{origin: integrationOrigin, csrf: oldCSRF, idempotency: approveKey}, oldCookie)
	assertHTTPError(t, conflict, http.StatusConflict, "idempotency_conflict", "Different operator reason", oldCookie.Value)

	// Rejection is a durable human decision and audit event, but creates no
	// authorization, enforcement action, or dispatcher outbox authority.
	rejectKey := "reject-issue-idempotency-key-0000001"
	rejectChallenge := issueChallenge(t, server, reject, hil.OperationReject, session.CSRFToken, rejectKey)
	rejectedResult := server.do(t, http.MethodPost, decisionPath(reject),
		decisionRequestBody(t, reject.Exact, hil.OperationReject, rejectChallenge, "Synthetic traffic was benign"),
		requestOptions{origin: integrationOrigin, csrf: session.CSRFToken, idempotency: rejectKey})
	if rejectedResult.status != http.StatusOK {
		t.Fatalf("rejection status=%d body=%s", rejectedResult.status, rejectedResult.body)
	}
	var rejected decisionResponse
	decodeHTTP(t, rejectedResult.body, &rejected)
	if rejected.ActionID != nil || rejected.AuthorizationDigest != nil || rejected.OutboxJobID != nil || rejected.CSRFToken == "" {
		t.Fatalf("rejection created authority: %+v", rejected)
	}
	session.CSRFToken = rejected.CSRFToken
	session.Session.SessionID = rejected.Session.SessionID

	// Two simultaneous HTTP decisions using the same exact session/challenge
	// can produce only one authority-bearing response and one database action.
	concurrentKey := "concurrent-issue-idempotency-key-0001"
	concurrentChallenge := issueChallenge(t, server, concurrent, hil.OperationApprove, session.CSRFToken, concurrentKey)
	concurrentCookie := currentCookie(t, server)
	concurrentBody := decisionRequestBody(t, concurrent.Exact, hil.OperationApprove, concurrentChallenge, "Concurrent exact approval")
	type concurrentResult struct {
		http     httpResult
		decision decisionResponse
	}
	results := make(chan concurrentResult, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result := server.doWithCookie(t, http.MethodPost, decisionPath(concurrent), concurrentBody,
				requestOptions{origin: integrationOrigin, csrf: session.CSRFToken, idempotency: concurrentKey},
				concurrentCookie)
			var decoded decisionResponse
			if result.status == http.StatusOK {
				_ = json.Unmarshal(result.body, &decoded)
			}
			results <- concurrentResult{http: result, decision: decoded}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	authorityResponses := 0
	var winning concurrentResult
	for result := range results {
		if result.http.status == http.StatusOK && result.decision.ActionID != nil {
			authorityResponses++
			winning = result
		} else if result.http.status < 400 {
			t.Fatalf("concurrent loser unexpectedly succeeded: status=%d body=%s", result.http.status, result.http.body)
		}
	}
	if authorityResponses != 1 {
		t.Fatalf("authority-bearing concurrent responses=%d", authorityResponses)
	}
	server.jar.SetCookies(server.base, winning.http.cookies)
	session.CSRFToken = winning.decision.CSRFToken
	session.Session.SessionID = winning.decision.Session.SessionID

	// A near-expiry validation produces a short challenge that becomes stale
	// naturally; no database clock or immutable challenge row is rewritten.
	// The exact-artifact boundary rejects the now-stale version before the HIL
	// coordinator can consume the challenge.
	expiryBase := time.Now().UTC().Add(-4*time.Minute - 56*time.Second).Truncate(time.Microsecond)
	expiring := managementExactFixture(t, 6, expiryBase)
	seedManagementExactFixture(t, fixture, expiring, expiryBase)
	expiringKey := "expiring-issue-idempotency-key-00001"
	expiringChallenge := issueChallenge(t, server, expiring, hil.OperationApprove, session.CSRFToken, expiringKey)
	checkedExpiry, err := hil.ParseCanonicalChallenge(expiringChallenge.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	wait := time.Until(checkedExpiry.Value().ExpiresAt) + 150*time.Millisecond
	if wait < 0 || wait > 6*time.Second {
		t.Fatalf("unexpected expiry wait %s", wait)
	}
	time.Sleep(wait)
	expired := server.do(t, http.MethodPost, decisionPath(expiring),
		decisionRequestBody(t, expiring.Exact, hil.OperationApprove, expiringChallenge, "Expired challenge must fail"),
		requestOptions{origin: integrationOrigin, csrf: session.CSRFToken, idempotency: expiringKey})
	assertHTTPError(t, expired, http.StatusConflict, "stale_version", expiringChallenge.ChallengeNonce)

	// SF005 before challenge issuance and between challenge/decision is exposed
	// as the same stable non-2xx contract and cannot mint dispatch authority.
	if _, err = fixture.owner.Exec(fixture.ctx, `UPDATE sentinelflow.incidents SET evidence_version = 2 WHERE incident_id = $1::uuid`, staleBefore.IDs.Incident); err != nil {
		t.Fatal(err)
	}
	staleIssue := server.do(t, http.MethodPost, challengePath(staleBefore), artifactRequestBody(t, staleBefore.Exact, hil.OperationApprove),
		requestOptions{origin: integrationOrigin, csrf: session.CSRFToken, idempotency: "stale-before-idempotency-key-0001"})
	assertHTTPError(t, staleIssue, http.StatusUnprocessableEntity, "validation_failed", integrationAdminPass)
	staleBetweenKey := "stale-between-issue-key-000000001"
	staleChallenge := issueChallenge(t, server, staleBetween, hil.OperationApprove, session.CSRFToken, staleBetweenKey)
	if _, err = fixture.owner.Exec(fixture.ctx, `UPDATE sentinelflow.incidents SET evidence_version = 2 WHERE incident_id = $1::uuid`, staleBetween.IDs.Incident); err != nil {
		t.Fatal(err)
	}
	preOutageCookie := currentCookie(t, server)
	preOutageCSRF := session.CSRFToken
	staleDecision := server.do(t, http.MethodPost, decisionPath(staleBetween),
		decisionRequestBody(t, staleBetween.Exact, hil.OperationApprove, staleChallenge, "Stale evidence must fail"),
		requestOptions{origin: integrationOrigin, csrf: session.CSRFToken, idempotency: staleBetweenKey})
	assertHTTPError(t, staleDecision, http.StatusUnprocessableEntity, "validation_failed", staleChallenge.ChallengeNonce)

	assertManagementDatabaseState(t, fixture, approve, reject, concurrent, staleBefore, staleBetween, negative, expiring)

	// An unavailable database maps to a stable 503 and never reflects the URL,
	// cookie, CSRF, password, or request body.
	fixture.pool.Close()
	outage := server.doWithCookie(t, http.MethodGet, adminapi.SessionPath, nil,
		requestOptions{}, preOutageCookie)
	assertHTTPError(t, outage, http.StatusServiceUnavailable, "service_unavailable",
		integrationAPIPassword, integrationAdminPass, preOutageCookie.Value, preOutageCSRF)
	server.close()
}

type requestOptions struct {
	origin, csrf, idempotency, forwardedFor string
}

func startManagementHTTPServer(t *testing.T, fixture *managementPGFixture, jar http.CookieJar) *managementHTTPServer {
	t.Helper()
	handler, err := configureManagementAPIWithClock(fixture.config, fixture.pool, fixture.clock)
	if err != nil {
		t.Fatalf("configure production management API: %v", err)
	}
	_, management := newServers(fixture.config, http.NotFoundHandler(), handler, fixture.pool)
	server := httptest.NewTLSServer(management.Handler)
	base, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	client.Timeout = 10 * time.Second
	return &managementHTTPServer{server: server, client: client, jar: jar, base: base}
}

func (server *managementHTTPServer) close() { server.server.Close() }

func (server *managementHTTPServer) do(t *testing.T, method, path string, body []byte, options requestOptions) httpResult {
	t.Helper()
	return server.request(t, server.client, method, path, body, options, nil)
}

func (server *managementHTTPServer) doWithoutJar(t *testing.T, method, path string, body []byte, options requestOptions) httpResult {
	t.Helper()
	client := &http.Client{Transport: server.client.Transport, Timeout: 10 * time.Second}
	return server.request(t, client, method, path, body, options, nil)
}

func (server *managementHTTPServer) doWithCookie(t *testing.T, method, path string, body []byte, options requestOptions, cookie *http.Cookie) httpResult {
	t.Helper()
	client := &http.Client{Transport: server.client.Transport, Timeout: 10 * time.Second}
	return server.request(t, client, method, path, body, options, cookie)
}

func (server *managementHTTPServer) request(
	t *testing.T,
	client *http.Client,
	method, path string,
	body []byte,
	options requestOptions,
	cookie *http.Cookie,
) httpResult {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, server.server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if options.origin != "" {
		request.Header.Set("Origin", options.origin)
	}
	if options.csrf != "" {
		request.Header.Set("X-CSRF-Token", options.csrf)
	}
	if options.idempotency != "" {
		request.Header.Set("Idempotency-Key", options.idempotency)
	}
	if options.forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", options.forwardedFor)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("HTTP %s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return httpResult{status: response.StatusCode, header: response.Header.Clone(), body: responseBody, cookies: response.Cookies()}
}

func issueChallenge(
	t *testing.T,
	server *managementHTTPServer,
	exact exactFixture,
	operation hil.Operation,
	csrf, idempotency string,
) challengeResponse {
	t.Helper()
	result := server.do(t, http.MethodPost, challengePath(exact), artifactRequestBody(t, exact.Exact, operation),
		requestOptions{origin: integrationOrigin, csrf: csrf, idempotency: idempotency})
	if result.status != http.StatusCreated {
		t.Fatalf("issue challenge status=%d body=%s", result.status, result.body)
	}
	var challenge challengeResponse
	decodeHTTP(t, result.body, &challenge)
	if len(challenge.Challenge) == 0 || challenge.ChallengeNonce == "" {
		t.Fatalf("invalid challenge response: %+v", challenge)
	}
	return challenge
}

func artifactRequestBody(t *testing.T, exact hil.ExactArtifact, operation hil.Operation) []byte {
	t.Helper()
	return mustJSON(t, artifactRequestMap(exact, operation))
}

func mutateArtifactBody(t *testing.T, exact hil.ExactArtifact, operation hil.Operation, field string, value any) []byte {
	t.Helper()
	document := artifactRequestMap(exact, operation)
	document[field] = value
	return mustJSON(t, document)
}

func artifactRequestMap(exact hil.ExactArtifact, operation hil.Operation) map[string]any {
	return map[string]any{
		"operation": operation, "policy_version": exact.PolicyVersion(), "target_ipv4": exact.TargetIPv4(),
		"ttl_seconds": exact.TTLSeconds(), "policy_digest": exact.PolicyDigest(),
		"generated_artifact_digest":  exact.GeneratedArtifactDigest(),
		"canonical_artifact_digest":  exact.CanonicalArtifactDigest(),
		"evidence_snapshot_digest":   exact.EvidenceSnapshotDigest(),
		"validation_snapshot_digest": exact.ValidationSnapshotDigest(),
	}
}

func decisionRequestBody(
	t *testing.T,
	exact hil.ExactArtifact,
	operation hil.Operation,
	challenge challengeResponse,
	reason string,
) []byte {
	t.Helper()
	document := artifactRequestMap(exact, operation)
	document["challenge"] = challenge.Challenge
	document["challenge_nonce"] = challenge.ChallengeNonce
	reasonCode := hil.ReasonThreatConfirmed
	if operation == hil.OperationReject {
		reasonCode = hil.ReasonFalsePositive
	}
	document["reason"] = map[string]any{
		"schema_version": hil.ReasonSchemaVersion, "reason_code": reasonCode, "reason_text": reason,
	}
	return mustJSON(t, document)
}

func challengePath(exact exactFixture) string {
	return "/api/v1/policies/" + exact.Exact.PolicyID() + "/decision-challenges"
}

func decisionPath(exact exactFixture) string {
	return "/api/v1/policies/" + exact.Exact.PolicyID() + "/decisions"
}

func requireDecisionAuthority(t *testing.T, result httpResult) decisionResponse {
	t.Helper()
	if result.status != http.StatusOK {
		t.Fatalf("decision status=%d body=%s", result.status, result.body)
	}
	var decision decisionResponse
	decodeHTTP(t, result.body, &decision)
	if decision.ActionID == nil || decision.AuthorizationDigest == nil || decision.OutboxJobID == nil {
		t.Fatalf("approval omitted exact authority: %+v", decision)
	}
	return decision
}

func issuedSecureCookie(t *testing.T, cookies []*http.Cookie) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie != nil && cookie.Value != "" && cookie.MaxAge >= 0 {
			copy := *cookie
			return &copy
		}
	}
	t.Fatal("response omitted issued session cookie")
	return nil
}

func currentCookie(t *testing.T, server *managementHTTPServer) *http.Cookie {
	t.Helper()
	cookies := server.jar.Cookies(server.base)
	if len(cookies) != 1 {
		t.Fatalf("current cookie count=%d", len(cookies))
	}
	copy := *cookies[0]
	return &copy
}

func sessionIDFromCookie(t *testing.T, cookie *http.Cookie) string {
	t.Helper()
	if cookie == nil {
		t.Fatal("session cookie is nil")
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		t.Fatal("session cookie payload is malformed")
	}
	id, err := adminauth.ParseSessionID(parts[1])
	if err != nil {
		t.Fatal("session cookie ID is malformed")
	}
	return id.String()
}

func requireCurrentSessionCookie(
	t *testing.T,
	server *managementHTTPServer,
	wantSessionID string,
) *http.Cookie {
	t.Helper()
	cookie := currentCookie(t, server)
	if got := sessionIDFromCookie(t, cookie); got != wantSessionID {
		t.Fatalf("current cookie session ID=%s want=%s", got, wantSessionID)
	}
	return cookie
}

func assertHTTPError(t *testing.T, result httpResult, status int, code string, forbidden ...string) {
	t.Helper()
	if result.status != status {
		t.Fatalf("status=%d want=%d body=%s", result.status, status, result.body)
	}
	var value struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		TraceID string         `json:"trace_id"`
		Details map[string]any `json:"details"`
	}
	decodeHTTP(t, result.body, &value)
	if value.Code != code || value.Message == "" || value.TraceID == "" || value.Details == nil {
		t.Fatalf("error contract=%+v", value)
	}
	assertNoLeak(t, result.body, forbidden...)
}

func assertNoLeak(t *testing.T, body []byte, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if value != "" && bytes.Contains(body, []byte(value)) {
			t.Fatalf("response leaked forbidden value: %q", value)
		}
	}
}

func assertManagementDatabaseState(
	t *testing.T,
	fixture *managementPGFixture,
	approve, reject, concurrent, staleBefore, staleBetween, negative, expiring exactFixture,
) {
	t.Helper()
	assertPolicyShape := func(exact exactFixture, state, operation string, decisions, authorizations, actions, outbox, audits, eligible int) {
		t.Helper()
		var gotState string
		var gotDecisions, gotAuthorizations, gotActions, gotOutbox, gotAudits, gotEligible int
		err := fixture.owner.QueryRow(fixture.ctx, `
SELECT policy.state,
       (SELECT count(*)::integer FROM sentinelflow.approval_decisions decision
         WHERE decision.policy_id = policy.policy_id AND decision.policy_version = policy.version
           AND decision.operation = $3),
	       (SELECT count(*)::integer FROM sentinelflow.enforcement_authorizations authz
	         WHERE authz.policy_id = policy.policy_id AND authz.policy_version = policy.version),
       (SELECT count(*)::integer FROM sentinelflow.enforcement_actions action
         WHERE action.policy_id = policy.policy_id AND action.policy_version = policy.version),
       (SELECT count(*)::integer FROM sentinelflow.outbox_jobs job
         WHERE job.aggregate_type = 'enforcement_action' AND job.aggregate_id IN (
           SELECT action.action_id FROM sentinelflow.enforcement_actions action
           WHERE action.policy_id = policy.policy_id AND action.policy_version = policy.version)),
       (SELECT count(*)::integer FROM sentinelflow.audit_events audit
         WHERE audit.policy_id = policy.policy_id AND audit.policy_version = policy.version
           AND audit.action IN ('policy_approved', 'policy_rejected')),
       (SELECT count(*)::integer FROM sentinelflow.dispatcher_approved_outbox eligible
         WHERE eligible.policy_id = policy.policy_id AND eligible.policy_version = policy.version)
FROM sentinelflow.policy_proposals policy
WHERE policy.policy_id = $1::uuid AND policy.version = $2`,
			exact.Exact.PolicyID(), exact.Exact.PolicyVersion(), operation).Scan(
			&gotState, &gotDecisions, &gotAuthorizations, &gotActions, &gotOutbox, &gotAudits, &gotEligible)
		if err != nil || gotState != state || gotDecisions != decisions || gotAuthorizations != authorizations ||
			gotActions != actions || gotOutbox != outbox || gotAudits != audits || gotEligible != eligible {
			t.Fatalf("policy %s state=%s/%s decision=%d/%d auth=%d/%d action=%d/%d outbox=%d/%d audit=%d/%d eligible=%d/%d err=%v",
				exact.Exact.PolicyID(), gotState, state, gotDecisions, decisions, gotAuthorizations, authorizations,
				gotActions, actions, gotOutbox, outbox, gotAudits, audits, gotEligible, eligible, err)
		}
	}
	assertPolicyShape(approve, "approved", "approve", 1, 1, 1, 1, 1, 1)
	assertPolicyShape(reject, "rejected", "reject", 1, 0, 0, 0, 1, 0)
	assertPolicyShape(concurrent, "approved", "approve", 1, 1, 1, 1, 1, 1)
	for _, exact := range []exactFixture{staleBefore, staleBetween, negative, expiring} {
		assertPolicyShape(exact, "valid", "approve", 0, 0, 0, 0, 0, 0)
	}
	var replayCount int
	if err := fixture.owner.QueryRow(fixture.ctx, `SELECT count(*)::integer FROM sentinelflow.approval_decisions
WHERE policy_id = $1::uuid AND policy_version = $2`, approve.Exact.PolicyID(), approve.Exact.PolicyVersion()).Scan(&replayCount); err != nil || replayCount != 1 {
		t.Fatalf("approval replay duplicated decision count=%d err=%v", replayCount, err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodeHTTP(t *testing.T, body []byte, destination any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode HTTP response: %v body=%s", err, body)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("trailing HTTP response: %v", err)
	}
}
