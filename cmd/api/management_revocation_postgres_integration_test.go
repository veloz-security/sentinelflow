//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminapi"
	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/adminstore"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/hilstore"
)

type revocationHTTPChallengeResponse struct {
	Challenge               json.RawMessage `json:"challenge"`
	ChallengeNonce          string          `json:"challenge_nonce"`
	CanonicalRevokeArtifact string          `json:"canonical_revoke_artifact"`
	PolicyID                string          `json:"policy_id"`
	PolicyVersion           uint32          `json:"policy_version"`
}

type revocationHTTPDecisionResponse struct {
	Decision                 json.RawMessage `json:"decision"`
	RevocationID             string          `json:"revocation_id"`
	AuthorizationID          string          `json:"authorization_id"`
	AuthorizationDigest      string          `json:"authorization_digest"`
	OutboxJobID              string          `json:"outbox_job_id"`
	AuditEventID             string          `json:"audit_event_id"`
	Replayed                 bool            `json:"replayed"`
	ReauthenticationRequired bool            `json:"reauthentication_required"`
}

// responseLossRevocationPersistence invokes the real coordinator on both
// exact attempts but deliberately discards each successful result. This
// proves the HTTP handler cannot use a live lookup after an uncertain commit;
// it must recover through a DB-authored revoked parent and historical-only
// lookup without issuing replacement browser credentials.
type responseLossRevocationPersistence struct {
	delegate adminapi.RevocationPersistence
	mu       sync.Mutex
	commits  int
}

func (store *responseLossRevocationPersistence) IssueRevocation(
	ctx context.Context,
	request hilstore.RevocationIssueRequest,
) (adminapi.RevocationIssuedChallenge, error) {
	return store.delegate.IssueRevocation(ctx, request)
}

func (store *responseLossRevocationPersistence) LookupHistoricalRevocation(
	ctx context.Context,
	lookup hilstore.RevocationLookup,
) (adminapi.RevocationStoredResult, error) {
	return store.delegate.LookupHistoricalRevocation(ctx, lookup)
}

func (store *responseLossRevocationPersistence) CommitRevocation(
	ctx context.Context,
	commit hilstore.PrivilegedRevocationCommit,
) (adminapi.RevocationStoredResult, error) {
	result, err := store.delegate.CommitRevocation(ctx, commit)
	store.mu.Lock()
	store.commits++
	call := store.commits
	store.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if call <= 2 {
		return nil, hilstore.ErrUnavailable
	}
	return result, nil
}

func (store *responseLossRevocationPersistence) commitCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.commits
}

func TestManagementRevocationHTTPAgainstPostgreSQL17(t *testing.T) {
	fixture := newManagementPGFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	exact := managementExactFixture(t, 31, now)
	seedManagementExactFixture(t, fixture, exact, now)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := startManagementHTTPServer(t, fixture, jar)
	defer server.close()
	login := server.do(t, http.MethodPost, adminapi.LoginPath,
		mustJSON(t, map[string]any{"username": integrationAdminUser, "password": integrationAdminPass}),
		requestOptions{origin: integrationOrigin})
	if login.status != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.status, login.body)
	}
	var session sessionResponse
	decodeHTTP(t, login.body, &session)
	if session.CSRFToken == "" {
		t.Fatal("login omitted CSRF")
	}
	requireCurrentSessionCookie(t, server, session.Session.SessionID)

	approveKey := "revocation-http-add-key-0000000001"
	approveChallenge := issueChallenge(t, server, exact, hil.OperationApprove, session.CSRFToken, approveKey)
	approvedResult := server.do(t, http.MethodPost, decisionPath(exact),
		decisionRequestBody(t, exact.Exact, hil.OperationApprove, approveChallenge, "Approve synthetic action for revocation HTTP coverage"),
		requestOptions{origin: integrationOrigin, csrf: session.CSRFToken, idempotency: approveKey})
	approved := requireDecisionAuthority(t, approvedResult)
	if approved.ActionID == nil || approved.CSRFToken == "" {
		t.Fatalf("approval omitted action/session: %+v", approved)
	}
	actionID := *approved.ActionID
	session.CSRFToken = approved.CSRFToken
	session.Session.SessionID = approved.Session.SessionID
	approvedCookie := issuedSecureCookie(t, approvedResult.cookies)
	if got := sessionIDFromCookie(t, approvedCookie); got != session.Session.SessionID {
		t.Fatalf("approval cookie session ID=%s want=%s", got, session.Session.SessionID)
	}
	requireCurrentSessionCookie(t, server, session.Session.SessionID)

	actionVersion := activateManagementActionForRevocation(t, fixture, exact, actionID)
	if actionVersion != 3 {
		t.Fatalf("active action version=%d want=3", actionVersion)
	}

	lossHandler, lossStore := newResponseLossRevocationHandler(t, fixture)
	lossServer := startManagementHandlerServer(t, lossHandler, jar)
	defer lossServer.close()
	requireCurrentSessionCookie(t, lossServer, session.Session.SessionID)
	revokeKey := "revocation-http-decision-key-0000001"
	challengeBody := mustJSON(t, map[string]any{
		"action_version":      actionVersion,
		"target_ipv4":         exact.Exact.TargetIPv4(),
		"original_add_digest": exact.Exact.CanonicalArtifactDigest(),
	})
	challengeResult := lossServer.doWithCookie(t, http.MethodPost,
		"/api/v1/enforcement-actions/"+actionID+"/revocation-challenges",
		challengeBody, requestOptions{origin: integrationOrigin, csrf: session.CSRFToken, idempotency: revokeKey},
		approvedCookie)
	if challengeResult.status != http.StatusCreated {
		t.Fatalf("revoke challenge status=%d body=%s", challengeResult.status, challengeResult.body)
	}
	var challenge revocationHTTPChallengeResponse
	decodeHTTP(t, challengeResult.body, &challenge)
	checkedChallenge, err := hil.ParseCanonicalChallenge(challenge.Challenge)
	if err != nil || checkedChallenge.Value().ResourceID != actionID ||
		checkedChallenge.Value().ResourceVersion != uint32(actionVersion) ||
		challenge.PolicyID != exact.Exact.PolicyID() ||
		challenge.PolicyVersion != exact.Exact.PolicyVersion() ||
		challenge.CanonicalRevokeArtifact != "delete element inet sentinelflow blacklist_ipv4 { "+exact.Exact.TargetIPv4()+" }\n" {
		t.Fatalf("invalid revoke challenge=%+v err=%v", challenge, err)
	}

	// The privileged revocation flow is pinned to the exact cookie returned by
	// the approval rotation. The shared jar remains only an independent
	// equivalence assertion across the production and response-loss servers.
	requireCurrentSessionCookie(t, lossServer, session.Session.SessionID)
	oldCookie := approvedCookie
	oldCSRF := session.CSRFToken
	decisionBody := mustJSON(t, map[string]any{
		"action_version": actionVersion, "target_ipv4": exact.Exact.TargetIPv4(),
		"original_add_digest": exact.Exact.CanonicalArtifactDigest(),
		"challenge":           challenge.Challenge, "challenge_nonce": challenge.ChallengeNonce,
		"canonical_revoke_artifact": challenge.CanonicalRevokeArtifact,
		"policy_id":                 challenge.PolicyID, "policy_version": challenge.PolicyVersion,
		"reason": map[string]any{
			"schema_version": hil.ReasonSchemaVersion,
			"reason_code":    hil.ReasonOperatorRequest,
			"reason_text":    "Remove the synthetic active block",
		},
	})
	uncertain := lossServer.doWithCookie(t, http.MethodPost,
		"/api/v1/enforcement-actions/"+actionID+"/revocations", decisionBody,
		requestOptions{origin: integrationOrigin, csrf: oldCSRF, idempotency: revokeKey}, oldCookie)
	if uncertain.status != http.StatusOK {
		t.Fatalf("uncertain revoke recovery status=%d body=%s", uncertain.status, uncertain.body)
	}
	var recovered revocationHTTPDecisionResponse
	decodeHTTP(t, uncertain.body, &recovered)
	if !recovered.Replayed || !recovered.ReauthenticationRequired ||
		recovered.RevocationID == "" || recovered.AuthorizationID == "" ||
		recovered.AuthorizationDigest == "" || recovered.OutboxJobID == "" ||
		recovered.AuditEventID == "" || lossStore.commitCount() != 2 {
		t.Fatalf("incomplete uncertain recovery=%+v commits=%d", recovered, lossStore.commitCount())
	}
	if jsonContainsKey(uncertain.body, "session") || jsonContainsKey(uncertain.body, "csrf_token") ||
		!responseExpiredCookie(uncertain.cookies) {
		t.Fatalf("uncertain recovery returned credentials: cookies=%+v body=%s", uncertain.cookies, uncertain.body)
	}
	assertNoLeak(t, uncertain.body, challenge.ChallengeNonce, oldCookie.Value,
		oldCSRF, "Remove the synthetic active block")

	// The same lost-response browser request can only read the immutable
	// historical business result. It neither rotates again nor duplicates any
	// durable decision, authorization, revocation, outbox, dispatch, or audit.
	directReplay := lossServer.doWithCookie(t, http.MethodPost,
		"/api/v1/enforcement-actions/"+actionID+"/revocations", decisionBody,
		requestOptions{origin: integrationOrigin, csrf: oldCSRF, idempotency: revokeKey}, oldCookie)
	if directReplay.status != http.StatusOK {
		t.Fatalf("direct historical replay status=%d body=%s", directReplay.status, directReplay.body)
	}
	var replayed revocationHTTPDecisionResponse
	decodeHTTP(t, directReplay.body, &replayed)
	if !replayed.Replayed || !replayed.ReauthenticationRequired ||
		replayed.RevocationID != recovered.RevocationID ||
		replayed.AuthorizationID != recovered.AuthorizationID ||
		replayed.AuthorizationDigest != recovered.AuthorizationDigest ||
		replayed.OutboxJobID != recovered.OutboxJobID || replayed.AuditEventID != recovered.AuditEventID ||
		lossStore.commitCount() != 2 || jsonContainsKey(directReplay.body, "session") ||
		jsonContainsKey(directReplay.body, "csrf_token") || !responseExpiredCookie(directReplay.cookies) {
		t.Fatalf("unsafe direct replay=%+v commits=%d body=%s", replayed, lossStore.commitCount(), directReplay.body)
	}

	assertRevocationDurableCounts(t, fixture, actionID, revokeKey, recovered)
}

func activateManagementActionForRevocation(
	t *testing.T,
	fixture *managementPGFixture,
	exact exactFixture,
	actionID string,
) int {
	t.Helper()
	statements := []struct {
		query string
		args  []any
	}{
		{`UPDATE sentinelflow.policy_proposals
SET state = 'queued', state_revision = state_revision + 1, updated_at = clock_timestamp()
WHERE policy_id = $1::uuid AND version = $2 AND state = 'approved'`,
			[]any{exact.Exact.PolicyID(), exact.Exact.PolicyVersion()}},
		{`UPDATE sentinelflow.enforcement_actions
SET state = 'queued', queued_at = clock_timestamp(), version = version + 1,
    updated_at = clock_timestamp()
WHERE action_id = $1::uuid AND state = 'approved'`, []any{actionID}},
		{`UPDATE sentinelflow.policy_proposals
SET state = 'active', state_revision = state_revision + 1, updated_at = clock_timestamp()
WHERE policy_id = $1::uuid AND version = $2 AND state = 'queued'`,
			[]any{exact.Exact.PolicyID(), exact.Exact.PolicyVersion()}},
		{`UPDATE sentinelflow.enforcement_actions
SET state = 'active', applied_at = clock_timestamp(),
    expected_expires_at = clock_timestamp() + interval '20 minutes',
    version = version + 1, updated_at = clock_timestamp()
WHERE action_id = $1::uuid AND state = 'queued'`, []any{actionID}},
	}
	for index, statement := range statements {
		result, err := fixture.owner.Exec(fixture.ctx, statement.query, statement.args...)
		if err != nil || result.RowsAffected() != 1 {
			t.Fatalf("activate action step %d affected=%d err=%v", index+1, result.RowsAffected(), err)
		}
	}
	var version int
	if err := fixture.owner.QueryRow(fixture.ctx, `
SELECT version FROM sentinelflow.enforcement_actions
WHERE action_id = $1::uuid AND state = 'active'`, actionID).Scan(&version); err != nil {
		t.Fatalf("load active action version: %v", err)
	}
	return version
}

func newResponseLossRevocationHandler(
	t *testing.T,
	fixture *managementPGFixture,
) (http.Handler, *responseLossRevocationPersistence) {
	t.Helper()
	cfg := fixture.config
	credentials, err := adminauth.NewCredentialVerifier(
		cfg.Admin.Username, "administrator", cfg.Admin.PasswordArgon2idHash.Reveal(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey, err := decodeSessionHMACKey(cfg.Admin.SessionHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(sessionKey)
	sessions, err := adminauth.NewSessionManager(sessionKey, rand.Reader, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	loginLimiter, err := adminauth.NewLoginLimiter(fixture.clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	decisionLimiter, err := adminauth.NewDecisionLimiter(fixture.clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	origins, err := adminauth.NewOriginPolicy(cfg.Admin.AllowedOrigins)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := adminauth.NewBoundary(credentials, sessions, loginLimiter, decisionLimiter, origins)
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := adminauth.NewCookiePolicy(cfg.Admin.SessionCookieName, cookieTransport(cfg.Admin.CookieTransport))
	if err != nil {
		t.Fatal(err)
	}
	sessionStore, err := adminstore.NewPostgreSQLStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	postgresStore, err := hilstore.NewPostgreSQLStore(fixture.pool, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegate, err := adminapi.NewRevocationStoreAdapter(postgresStore)
	if err != nil {
		t.Fatal(err)
	}
	loss := &responseLossRevocationPersistence{delegate: delegate}
	handler, err := adminapi.NewHandler(adminapi.Config{
		Boundary: boundary, Sessions: sessionStore, Cookies: cookies, Revocations: loss,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, loss
}

func startManagementHandlerServer(
	t *testing.T,
	handler http.Handler,
	jar http.CookieJar,
) *managementHTTPServer {
	t.Helper()
	server := httptest.NewTLSServer(handler)
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

func assertRevocationDurableCounts(
	t *testing.T,
	fixture *managementPGFixture,
	actionID string,
	idempotency string,
	response revocationHTTPDecisionResponse,
) {
	t.Helper()
	var decisions, authorizations, revocations, outbox, dispatches, audits, challenges int
	var revokedParents, liveChildren int
	err := fixture.owner.QueryRow(fixture.ctx, `
SELECT
 (SELECT count(*)::integer FROM sentinelflow.approval_decisions
   WHERE action_id = $1::uuid AND operation = 'revoke' AND decision = 'revoked'),
 (SELECT count(*)::integer FROM sentinelflow.enforcement_authorizations
   WHERE action_id = $1::uuid AND authorization_kind = 'revoke'),
 (SELECT count(*)::integer FROM sentinelflow.revocation_operations
   WHERE action_id = $1::uuid),
 (SELECT count(*)::integer FROM sentinelflow.outbox_jobs
   WHERE aggregate_id = $1::uuid AND kind = 'dispatch_revoke' AND operation = 'revoke'),
 (SELECT count(*)::integer FROM sentinelflow.dispatch_operations
   WHERE action_id = $1::uuid AND operation = 'revoke'),
 (SELECT count(*)::integer FROM sentinelflow.audit_events
   WHERE enforcement_action_id = $1::uuid AND action = 'enforcement_revoke_authorized'),
 (SELECT count(*)::integer FROM sentinelflow.decision_challenges
   WHERE resource_id = $1::uuid AND operation = 'revoke' AND consumed_at IS NOT NULL),
 (SELECT count(*)::integer FROM sentinelflow.admin_sessions parent
   WHERE parent.revoked_at IS NOT NULL AND EXISTS (
     SELECT 1 FROM sentinelflow.admin_sessions child
     WHERE child.rotation_parent_id = parent.session_id AND child.revoked_at IS NULL)),
 (SELECT count(*)::integer FROM sentinelflow.admin_sessions child
   WHERE child.rotation_parent_id IS NOT NULL AND child.revoked_at IS NULL)`, actionID).Scan(
		&decisions, &authorizations, &revocations, &outbox, &dispatches,
		&audits, &challenges, &revokedParents, &liveChildren,
	)
	if err != nil || decisions != 1 || authorizations != 1 || revocations != 1 ||
		outbox != 1 || dispatches != 1 || audits != 1 || challenges != 1 ||
		revokedParents < 1 || liveChildren != 1 {
		t.Fatalf("durable revoke counts decision=%d auth=%d revoke=%d outbox=%d dispatch=%d audit=%d challenge=%d parent=%d child=%d err=%v",
			decisions, authorizations, revocations, outbox, dispatches, audits,
			challenges, revokedParents, liveChildren, err)
	}
	var revocationID, authorizationID, authorizationDigest, outboxID, auditID string
	if err = fixture.owner.QueryRow(fixture.ctx, `
SELECT revoke.revocation_id::text, auth.authorization_id::text,
       auth.authorization_digest::text, job.job_id::text, audit.event_id::text
FROM sentinelflow.revocation_operations revoke
JOIN sentinelflow.enforcement_authorizations auth
  ON auth.authorization_id = revoke.authorization_id
JOIN sentinelflow.outbox_jobs job
  ON job.aggregate_id = revoke.action_id AND job.kind = 'dispatch_revoke'
JOIN sentinelflow.audit_events audit
  ON audit.object_id = revoke.revocation_id AND audit.action = 'enforcement_revoke_authorized'
WHERE revoke.action_id = $1::uuid`, actionID).Scan(
		&revocationID, &authorizationID, &authorizationDigest, &outboxID, &auditID,
	); err != nil || revocationID != response.RevocationID ||
		authorizationID != response.AuthorizationID || authorizationDigest != response.AuthorizationDigest ||
		outboxID != response.OutboxJobID || auditID != response.AuditEventID {
		t.Fatalf("durable IDs mismatch response=%+v db=%s/%s/%s/%s/%s err=%v idem=%s",
			response, revocationID, authorizationID, authorizationDigest, outboxID, auditID,
			err, idempotency)
	}
}

func jsonContainsKey(body []byte, key string) bool {
	var value map[string]json.RawMessage
	return json.Unmarshal(body, &value) == nil && value[key] != nil
}

func responseExpiredCookie(cookies []*http.Cookie) bool {
	for _, cookie := range cookies {
		if cookie != nil && cookie.Value == "" && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

var _ adminapi.RevocationPersistence = (*responseLossRevocationPersistence)(nil)
