package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/adminstore"
)

const testOrigin = "https://admin.example.test"

var testUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Add(delta time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(delta)
}

type fakeBoundary struct {
	mu sync.Mutex

	issued   adminauth.IssuedSession
	rotation adminauth.SessionRotation

	originErr    error
	loginErr     error
	sessionErr   error
	browserErr   error
	stepUpErr    error
	decisionErr  error
	wantOrigin   string
	wantToken    string
	wantCSRF     string
	loginCalls   int
	stepCalls    int
	decisionCall int
	sessionCall  int
	browserCall  int
	lastSource   netip.Addr
	loginSecret  []byte
	stepSecret   []byte
}

func (boundary *fakeBoundary) ValidateOrigin(origin string) error {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if boundary.originErr != nil || origin != boundary.wantOrigin {
		if boundary.originErr != nil {
			return boundary.originErr
		}
		return adminauth.ErrBrowserRequest
	}
	return nil
}

func (boundary *fakeBoundary) Login(source netip.Addr, _ string, password []byte) (adminauth.IssuedSession, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.loginCalls++
	boundary.lastSource = source
	boundary.loginSecret = password
	return boundary.issued, boundary.loginErr
}

func (boundary *fakeBoundary) ValidateSession(_ adminauth.SessionRecord, token string) (adminauth.SessionRecord, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.sessionCall++
	if boundary.sessionErr != nil || token != boundary.wantToken {
		if boundary.sessionErr != nil {
			return adminauth.SessionRecord{}, boundary.sessionErr
		}
		return adminauth.SessionRecord{}, adminauth.ErrSessionInvalid
	}
	return boundary.issued.Record, nil
}

func (boundary *fakeBoundary) ValidateBrowserRequest(record adminauth.SessionRecord, token, csrf, origin string) (adminauth.SessionRecord, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.browserCall++
	if boundary.browserErr != nil || token != boundary.wantToken || csrf != boundary.wantCSRF || origin != boundary.wantOrigin {
		if boundary.browserErr != nil {
			return adminauth.SessionRecord{}, boundary.browserErr
		}
		return adminauth.SessionRecord{}, adminauth.ErrBrowserRequest
	}
	return record, nil
}

func (boundary *fakeBoundary) ValidateRevokedBrowserReplay(record adminauth.SessionRecord, token, csrf, origin string) (adminauth.SessionRecord, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.browserCall++
	if record.RevokedAt == nil || boundary.browserErr != nil || token != boundary.wantToken || csrf != boundary.wantCSRF || origin != boundary.wantOrigin {
		if boundary.browserErr != nil {
			return adminauth.SessionRecord{}, boundary.browserErr
		}
		return adminauth.SessionRecord{}, adminauth.ErrBrowserRequest
	}
	return record, nil
}

func (boundary *fakeBoundary) RecoverCSRFToken(record adminauth.SessionRecord, token string) (string, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if token != boundary.wantToken {
		return "", adminauth.ErrSessionInvalid
	}
	if record.ID == boundary.issued.Record.ID {
		return boundary.issued.CSRFToken(), nil
	}
	if record.ID == boundary.rotation.Issued.Record.ID {
		return boundary.rotation.Issued.CSRFToken(), nil
	}
	return "", adminauth.ErrSessionInvalid
}

func (boundary *fakeBoundary) RequiresStepUp(adminauth.SessionRecord) (bool, error) {
	return false, nil
}

func (boundary *fakeBoundary) StepUp(_ adminauth.SessionRecord, token string, password []byte) (adminauth.SessionRotation, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.stepCalls++
	boundary.stepSecret = password
	if token != boundary.wantToken {
		return adminauth.SessionRotation{}, adminauth.ErrSessionInvalid
	}
	return boundary.rotation, boundary.stepUpErr
}

func (boundary *fakeBoundary) RotateAfterPrivilege(_ adminauth.SessionRecord, token string) (adminauth.SessionRotation, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if token != boundary.wantToken {
		return adminauth.SessionRotation{}, adminauth.ErrSessionInvalid
	}
	return boundary.rotation, nil
}

func (boundary *fakeBoundary) AllowDecision(_ adminauth.SessionID) error {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.decisionCall++
	return boundary.decisionErr
}

type fakeStore struct {
	mu sync.Mutex

	record       adminauth.SessionRecord
	replayRecord adminauth.SessionRecord

	loadErr   error
	insertErr error
	touchErr  error
	revokeErr error
	rotateErr error
	replayErr error

	loads       int
	inserts     int
	touches     int
	revokes     int
	rotates     int
	replayLoads int
}

func (store *fakeStore) LoadByID(_ context.Context, id adminauth.SessionID) (adminauth.SessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.loads++
	if store.loadErr != nil {
		return adminauth.SessionRecord{}, store.loadErr
	}
	if store.record.ID != id {
		return adminauth.SessionRecord{}, adminstore.ErrNotFound
	}
	return store.record, nil
}

func (store *fakeStore) LoadRevokedDecisionReplayParent(_ context.Context, id adminauth.SessionID) (adminauth.SessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.replayLoads++
	if store.replayErr != nil {
		return adminauth.SessionRecord{}, store.replayErr
	}
	if store.replayRecord.ID != id || store.replayRecord.RevokedAt == nil {
		return adminauth.SessionRecord{}, adminstore.ErrNotFound
	}
	return store.replayRecord, nil
}

func (store *fakeStore) InsertLogin(_ context.Context, record adminauth.SessionRecord) (adminauth.SessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.inserts++
	if store.insertErr != nil {
		return adminauth.SessionRecord{}, store.insertErr
	}
	store.record = record
	return store.record, nil
}

func (store *fakeStore) Touch(_ context.Context, expected adminauth.SessionRecord) (adminauth.SessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.touches++
	if store.touchErr != nil {
		return adminauth.SessionRecord{}, store.touchErr
	}
	if !sameSessionRecord(store.record, expected) {
		return adminauth.SessionRecord{}, adminstore.ErrConflict
	}
	store.record.LastSeenAt = store.record.LastSeenAt.Add(time.Microsecond)
	return store.record, nil
}

func (store *fakeStore) Revoke(_ context.Context, expected adminauth.SessionRecord) (adminauth.SessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revokes++
	if store.revokeErr != nil {
		return adminauth.SessionRecord{}, store.revokeErr
	}
	if !sameSessionRecord(store.record, expected) {
		return adminauth.SessionRecord{}, adminstore.ErrConflict
	}
	now := expected.LastSeenAt.Add(time.Microsecond)
	store.record.RevokedAt = &now
	return store.record, nil
}

func (store *fakeStore) Rotate(_ context.Context, expected, replacement adminauth.SessionRecord) (adminauth.SessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.rotates++
	if store.rotateErr != nil {
		return adminauth.SessionRecord{}, store.rotateErr
	}
	if !sameSessionRecord(store.record, expected) {
		return adminauth.SessionRecord{}, adminstore.ErrConflict
	}
	store.record = replacement
	return store.record, nil
}

type fixture struct {
	handler  *Handler
	boundary *fakeBoundary
	store    *fakeStore
	policy   adminauth.CookiePolicy
	issued   adminauth.IssuedSession
	rotation adminauth.SessionRotation
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)}
	entropy := make([]byte, 256)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	manager, err := adminauth.NewSessionManager(bytes.Repeat([]byte{0x45}, 32), bytes.NewReader(entropy), clock)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	rotation, err := manager.RotateAfterPrivilege(issued.Record, issued.SessionToken())
	if err != nil {
		t.Fatal(err)
	}
	rotation.Issued.Record.AuthenticatedAt = rotation.Issued.Record.CreatedAt
	policy, err := adminauth.NewCookiePolicy("__Host-sentinelflow", adminauth.CookieTransportTLS)
	if err != nil {
		t.Fatal(err)
	}
	boundary := &fakeBoundary{
		issued: issued, rotation: rotation, wantOrigin: testOrigin,
		wantToken: issued.SessionToken(), wantCSRF: issued.CSRFToken(),
	}
	store := &fakeStore{record: issued.Record}
	handler, err := NewHandler(Config{Boundary: boundary, Sessions: store, Cookies: policy})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{handler: handler, boundary: boundary, store: store, policy: policy, issued: issued, rotation: rotation}
}

func postRequest(path, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://api.example.test"+path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", testOrigin)
	request.RemoteAddr = "192.0.2.50:41234"
	return request
}

func getRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "https://api.example.test"+path, nil)
	request.RemoteAddr = "192.0.2.50:41234"
	return request
}

func addCredential(t *testing.T, request *http.Request, policy adminauth.CookiePolicy, issued adminauth.IssuedSession) {
	t.Helper()
	cookie, err := policy.IssuedSessionCookie(issued)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(cookie)
}

func addBrowserCredential(t *testing.T, request *http.Request, fixture *fixture) {
	t.Helper()
	addCredential(t, request, fixture.policy, fixture.issued)
	request.Header.Set("X-CSRF-Token", fixture.issued.CSRFToken())
}

func TestLoginUsesDirectPeerPersistsThenReturnsOneCSRF(t *testing.T) {
	fixture := newFixture(t)
	fixture.store.record = adminauth.SessionRecord{}
	request := postRequest(LoginPath, `{"username":"admin","password":"top-secret"}`)
	request.Header.Set("Forwarded", "for=198.51.100.9")
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", response.Code, response.Body.String())
	}
	if fixture.boundary.lastSource.String() != "192.0.2.50" || fixture.boundary.loginCalls != 1 || fixture.store.inserts != 1 {
		t.Fatalf("wrong direct-peer/login ordering: source=%s calls=%d inserts=%d", fixture.boundary.lastSource, fixture.boundary.loginCalls, fixture.store.inserts)
	}
	if !allZero(fixture.boundary.loginSecret) {
		t.Fatal("password byte buffer was not cleared")
	}
	assertSecurityHeaders(t, response)
	responseBody := response.Body.String()
	result := decodeSessionEnvelope(t, response)
	if result.CSRFToken != fixture.issued.CSRFToken() || result.Session.SessionID != fixture.issued.Record.ID.String() {
		t.Fatalf("wrong login response: %#v", result)
	}
	if strings.Count(responseBody, `"csrf_token"`) != 1 || strings.Contains(responseBody, fixture.issued.SessionToken()) || strings.Contains(responseBody, "top-secret") {
		t.Fatal("login response leaked or duplicated a secret")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" || cookies[0].Domain != "" {
		t.Fatalf("unsafe login cookie: %#v", cookies)
	}
}

func TestLoginRejectsMalformedEnvelopeBeforePasswordWork(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
		body   string
		status int
	}{
		{name: "missing content type", body: `{"username":"admin","password":"x"}`, mutate: func(r *http.Request) { r.Header.Del("Content-Type") }, status: 400},
		{name: "content type parameter", body: `{"username":"admin","password":"x"}`, mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, status: 400},
		{name: "duplicate content type", body: `{"username":"admin","password":"x"}`, mutate: func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, status: 400},
		{name: "query", body: `{"username":"admin","password":"x"}`, mutate: func(r *http.Request) { r.URL.RawQuery = "x=1" }, status: 400},
		{name: "unknown", body: `{"username":"admin","password":"x","role":"root"}`, status: 400},
		{name: "duplicate", body: `{"username":"admin","password":"x","password":"y"}`, status: 400},
		{name: "escaped duplicate", body: `{"username":"admin","password":"x","pass\\u0077ord":"y"}`, status: 400},
		{name: "trailing", body: `{"username":"admin","password":"x"}{}`, status: 400},
		{name: "array", body: `[]`, status: 400},
		{name: "encoded", body: `{"username":"admin","password":"x"}`, mutate: func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, status: 400},
		{name: "noncanonical peer", body: `{"username":"admin","password":"x"}`, mutate: func(r *http.Request) { r.RemoteAddr = "192.0.2.50:04123" }, status: 400},
		{name: "bad origin", body: `{"username":"admin","password":"x"}`, mutate: func(r *http.Request) { r.Header.Set("Origin", "https://evil.example.test") }, status: 403},
		{name: "duplicate origin", body: `{"username":"admin","password":"x"}`, mutate: func(r *http.Request) { r.Header.Add("Origin", testOrigin) }, status: 403},
		{name: "oversized", body: `{"username":"admin","password":"` + strings.Repeat("x", 5000) + `"}`, status: 400},
		{name: "chunked oversized", body: `{"username":"admin","password":"` + strings.Repeat("x", 5000) + `"}`, mutate: func(r *http.Request) {
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
		}, status: 400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			request := postRequest(LoginPath, test.body)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status || fixture.boundary.loginCalls != 0 || fixture.store.inserts != 0 {
				t.Fatalf("unsafe result: status=%d login=%d insert=%d body=%s", response.Code, fixture.boundary.loginCalls, fixture.store.inserts, response.Body.String())
			}
			assertSecurityHeaders(t, response)
		})
	}
}

func TestLoginRateLimitIsGenericAndRetryAfterBounded(t *testing.T) {
	fixture := newFixture(t)
	fixture.boundary.loginErr = &adminauth.RateLimitError{Scope: adminauth.RateLimitLoginSource, RetryAfter: 5 * time.Minute}
	request := postRequest(LoginPath, `{"username":"admin","password":"secret"}`)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "60" || fixture.store.inserts != 0 {
		t.Fatalf("wrong rate-limit response: %d retry=%q", response.Code, response.Header().Get("Retry-After"))
	}
	if strings.Contains(response.Body.String(), "login_source") || strings.Contains(response.Body.String(), "secret") {
		t.Fatal("rate-limit response leaked internal scope or password")
	}
	if !allZero(fixture.boundary.loginSecret) {
		t.Fatal("rate-limited password was not cleared")
	}
}

func TestLoginPersistenceFailureSetsNoCookieOrCSRF(t *testing.T) {
	for _, storeErr := range []error{adminstore.ErrConflict, adminstore.ErrUnavailable} {
		fixture := newFixture(t)
		fixture.store.record = adminauth.SessionRecord{}
		fixture.store.insertErr = storeErr
		request := postRequest(LoginPath, `{"username":"admin","password":"secret"}`)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code < 400 || len(response.Result().Cookies()) != 0 || strings.Contains(response.Body.String(), "csrf_token") || !allZero(fixture.boundary.loginSecret) {
			t.Fatalf("failed login changed browser state: status=%d cookies=%#v body=%s", response.Code, response.Result().Cookies(), response.Body.String())
		}
	}
}

func TestLoginErrorsNeverReflectWrappedSecrets(t *testing.T) {
	fixture := newFixture(t)
	fixture.boundary.loginErr = fmt.Errorf("backend included forbidden password %s", "top-secret")
	request := postRequest(LoginPath, `{"username":"admin","password":"top-secret"}`)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "top-secret") || strings.Contains(response.Body.String(), "backend") {
		t.Fatalf("authentication detail reflected: %d %s", response.Code, response.Body.String())
	}
}

func TestFrozenExternalErrorContractAndRedaction(t *testing.T) {
	tests := []struct {
		name   string
		build  func(*fixture) *http.Request
		setup  func(*fixture)
		status int
		code   ErrorCode
	}{
		{name: "schema", build: func(*fixture) *http.Request { return postRequest(LoginPath, `{"username":"admin"}`) }, status: 400, code: ErrorSchemaInvalid},
		{name: "authentication", build: func(*fixture) *http.Request { return getRequest(SessionPath) }, status: 401, code: ErrorAuthenticationRequired},
		{name: "permission", build: func(f *fixture) *http.Request {
			request := postRequest(LogoutPath, `{}`)
			addBrowserCredential(t, request, f)
			request.Header.Set("Origin", "https://evil.example.test")
			return request
		}, status: 403, code: ErrorPermissionDenied},
		{name: "csrf", build: func(f *fixture) *http.Request {
			request := postRequest(LogoutPath, `{}`)
			addCredential(t, request, f.policy, f.issued)
			return request
		}, status: 403, code: ErrorCSRFInvalid},
		{name: "rate", build: func(*fixture) *http.Request {
			return postRequest(LoginPath, `{"username":"admin","password":"secret"}`)
		}, setup: func(f *fixture) {
			f.boundary.loginErr = &adminauth.RateLimitError{Scope: adminauth.RateLimitLoginGlobal, RetryAfter: time.Second}
		}, status: 429, code: ErrorRateLimited},
		{name: "stale", build: func(f *fixture) *http.Request {
			request := getRequest(SessionPath)
			addCredential(t, request, f.policy, f.issued)
			return request
		}, setup: func(f *fixture) { f.store.touchErr = adminstore.ErrConflict }, status: 409, code: ErrorStaleVersion},
		{name: "service", build: func(f *fixture) *http.Request {
			request := getRequest(SessionPath)
			addCredential(t, request, f.policy, f.issued)
			return request
		}, setup: func(f *fixture) { f.store.loadErr = errors.New("postgres dsn=password=forbidden credential=secret") }, status: 503, code: ErrorServiceUnavailable},
		{name: "not found", build: func(*fixture) *http.Request { return getRequest("/api/v1/missing") }, status: 404, code: ErrorNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			if test.setup != nil {
				test.setup(fixture)
			}
			request := test.build(fixture)
			request.Header.Set("X-SentinelFlow-Trace-ID", "client-controlled-trace")
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var payload errorResponse
			decoder := json.NewDecoder(response.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload.Code != test.code || payload.Message == "" || len(payload.Message) > 500 || !testUUIDPattern.MatchString(payload.TraceID) ||
				payload.TraceID == "client-controlled-trace" || response.Header().Get("X-SentinelFlow-Trace-ID") != payload.TraceID ||
				payload.Details == nil || len(payload.Details) != 0 {
				t.Fatalf("invalid error contract: %#v headers=%#v", payload, response.Header())
			}
			encoded, _ := json.Marshal(payload)
			if bytes.Contains(encoded, []byte("postgres")) || bytes.Contains(encoded, []byte("password")) || bytes.Contains(encoded, []byte("credential")) || bytes.Contains(encoded, []byte("secret")) {
				t.Fatalf("error response leaked internal detail: %s", encoded)
			}
		})
	}
}

func TestSessionReadTouchesExactRowAndRecoversOnlyCurrentCSRF(t *testing.T) {
	fixture := newFixture(t)
	request := getRequest(SessionPath)
	addCredential(t, request, fixture.policy, fixture.issued)
	request.Header.Set("X-Forwarded-For", "203.0.113.1")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || fixture.store.loads != 1 || fixture.store.touches != 1 || fixture.boundary.sessionCall != 1 {
		t.Fatalf("session read failed: %d loads=%d touches=%d validates=%d", response.Code, fixture.store.loads, fixture.store.touches, fixture.boundary.sessionCall)
	}
	responseBody := response.Body.String()
	result := decodeSessionEnvelope(t, response)
	if result.CSRFToken != fixture.issued.CSRFToken() || strings.Count(responseBody, `"csrf_token"`) != 1 ||
		strings.Contains(responseBody, fixture.issued.SessionToken()) || strings.Contains(responseBody, fixture.issued.Record.TokenDigest.String()) {
		t.Fatal("session projection exposed secret material")
	}
}

func TestSessionRejectsCookieConfusionExpiryAndCASConflict(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*fixture, *http.Request)
		status int
	}{
		{name: "missing", status: 401},
		{name: "duplicate", setup: func(f *fixture, r *http.Request) {
			addCredential(t, r, f.policy, f.issued)
			addCredential(t, r, f.policy, f.issued)
		}, status: 401},
		{name: "wrong version", setup: func(f *fixture, r *http.Request) {
			r.Header.Set("Cookie", "__Host-sentinelflow=v2."+f.issued.Record.ID.String()+"."+f.issued.SessionToken())
		}, status: 401},
		{name: "padded token", setup: func(f *fixture, r *http.Request) {
			r.Header.Set("Cookie", "__Host-sentinelflow=v1."+f.issued.Record.ID.String()+"."+f.issued.SessionToken()+"=")
		}, status: 401},
		{name: "absolute expired", setup: func(f *fixture, r *http.Request) {
			addCredential(t, r, f.policy, f.issued)
			f.store.loadErr = adminstore.ErrNotFound
		}, status: 401},
		{name: "idle expired", setup: func(f *fixture, r *http.Request) {
			addCredential(t, r, f.policy, f.issued)
			f.store.loadErr = adminstore.ErrNotFound
		}, status: 401},
		{name: "store unavailable", setup: func(f *fixture, r *http.Request) {
			addCredential(t, r, f.policy, f.issued)
			f.store.loadErr = adminstore.ErrUnavailable
		}, status: 503},
		{name: "touch conflict", setup: func(f *fixture, r *http.Request) {
			addCredential(t, r, f.policy, f.issued)
			f.store.touchErr = adminstore.ErrConflict
		}, status: 409},
		{name: "token mismatch", setup: func(f *fixture, r *http.Request) {
			addCredential(t, r, f.policy, f.rotation.Issued)
			f.store.record = f.rotation.Issued.Record
		}, status: 401},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			request := getRequest(SessionPath)
			if test.setup != nil {
				test.setup(fixture, request)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("got %d: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestLogoutRequiresOriginCSRFAndRevokesBeforeExpiringCookie(t *testing.T) {
	fx := newFixture(t)
	request := postRequest(LogoutPath, `{}`)
	addBrowserCredential(t, request, fx)
	response := httptest.NewRecorder()
	fx.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || fx.store.revokes != 1 {
		t.Fatalf("logout failed: %d revokes=%d body=%s", response.Code, fx.store.revokes, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe expired cookie: %#v", cookies)
	}

	for _, mutate := range []func(*fixture, *http.Request){
		func(_ *fixture, r *http.Request) { r.Header.Del("Origin") },
		func(_ *fixture, r *http.Request) { r.Header.Del("X-CSRF-Token") },
		func(_ *fixture, r *http.Request) { r.Header.Add("X-CSRF-Token", "duplicate") },
		func(_ *fixture, r *http.Request) {
			r.Body = ioBody(`{"unexpected":true}`)
			r.ContentLength = int64(len(`{"unexpected":true}`))
		},
		func(f *fixture, _ *http.Request) { f.store.revokeErr = adminstore.ErrConflict },
	} {
		fixture := newFixture(t)
		original := fixture.store.record
		request := postRequest(LogoutPath, `{}`)
		addBrowserCredential(t, request, fixture)
		mutate(fixture, request)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code < 400 || len(response.Result().Cookies()) != 0 {
			t.Fatalf("failed logout changed cookie: status=%d cookies=%#v", response.Code, response.Result().Cookies())
		}
		if !sameSessionRecord(fixture.store.record, original) {
			t.Fatal("failed logout changed persisted session")
		}
	}
}

func TestStepUpRotatesOnlyAfterPasswordAndStoreSuccess(t *testing.T) {
	fixture := newFixture(t)
	request := postRequest(StepUpPath, `{"password":"step-secret"}`)
	addBrowserCredential(t, request, fixture)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || fixture.store.rotates != 1 || fixture.boundary.stepCalls != 1 {
		t.Fatalf("step-up failed: %d rotates=%d steps=%d body=%s", response.Code, fixture.store.rotates, fixture.boundary.stepCalls, response.Body.String())
	}
	if !allZero(fixture.boundary.stepSecret) {
		t.Fatal("step-up password buffer was not cleared")
	}
	result := decodeSessionEnvelope(t, response)
	if result.Session.SessionID != fixture.rotation.Issued.Record.ID.String() || result.CSRFToken != fixture.rotation.Issued.CSRFToken() ||
		!result.Session.AuthenticatedAt.Equal(fixture.rotation.Issued.Record.CreatedAt) {
		t.Fatalf("wrong rotation result: %#v", result)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !strings.Contains(cookies[0].Value, fixture.rotation.Issued.Record.ID.String()) {
		t.Fatalf("replacement cookie missing: %#v", cookies)
	}
}

func TestStepUpFailureNeverChangesSessionOrCookie(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fixture)
		code  int
	}{
		{name: "wrong password", setup: func(f *fixture) { f.boundary.stepUpErr = adminauth.ErrInvalidCredentials }, code: 401},
		{name: "session invalid", setup: func(f *fixture) { f.boundary.browserErr = adminauth.ErrBrowserRequest }, code: 403},
		{name: "rotate conflict", setup: func(f *fixture) { f.store.rotateErr = adminstore.ErrConflict }, code: 409},
		{name: "database unavailable", setup: func(f *fixture) { f.store.rotateErr = adminstore.ErrUnavailable }, code: 503},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			original := fixture.store.record
			test.setup(fixture)
			request := postRequest(StepUpPath, `{"password":"step-secret"}`)
			addBrowserCredential(t, request, fixture)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.code || len(response.Result().Cookies()) != 0 || strings.Contains(response.Body.String(), "csrf_token") {
				t.Fatalf("failure changed browser state: code=%d cookies=%#v body=%s", response.Code, response.Result().Cookies(), response.Body.String())
			}
			if test.name == "wrong password" && fixture.store.rotates != 0 {
				t.Fatal("wrong password reached store rotation")
			}
			if !sameSessionRecord(fixture.store.record, original) {
				t.Fatal("failed step-up changed persisted session")
			}
		})
	}
}

func TestSessionAndMutationMiddlewareContextIsPrivateAndCleared(t *testing.T) {
	fixture := newFixture(t)
	request := getRequest("/protected")
	addCredential(t, request, fixture.policy, fixture.issued)
	request.Header.Set("Authorization", "forbidden-downstream-secret")
	request.Header.Set("Forwarded", "for=198.51.100.20")
	request.Header.Set("X-SentinelFlow-Trace-ID", "client-controlled-trace")
	var captured []byte
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Cookie") != "" || request.Header.Get("X-CSRF-Token") != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Forwarded") != "" || request.Header.Get("X-SentinelFlow-Trace-ID") != "" {
			t.Fatal("downstream request retained browser credentials")
		}
		projection, ok := SessionFromContext(request.Context())
		if !ok || projection.ActorID != "administrator" || projection.SessionID != fixture.issued.Record.ID.String() {
			t.Fatalf("missing safe projection: %#v", projection)
		}
		browser, ok := authenticatedFromContext(request.Context())
		if !ok || !sameSessionRecord(browser.record, fixture.store.record) || string(browser.presentedToken) != fixture.issued.SessionToken() {
			t.Fatal("missing exact private browser context")
		}
		captured = browser.presentedToken
		formatted := fmt.Sprintf("%v %#v", browser, browser)
		if strings.Contains(formatted, fixture.issued.SessionToken()) {
			t.Fatal("formatting exposed presented token")
		}
		if encoded, err := json.Marshal(browser); err == nil || bytes.Contains(encoded, []byte(fixture.issued.SessionToken())) {
			t.Fatal("JSON exposed private browser context")
		}
		if err := fixture.handler.allowDecisionFromContext(request.Context()); err != nil {
			t.Fatalf("decision limiter rejected authenticated context: %v", err)
		}
		if required, err := fixture.handler.requiresStepUpFromContext(request.Context()); err != nil || required {
			t.Fatalf("fresh authenticated context required step-up: required=%v err=%v", required, err)
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	fixture.handler.SessionMiddleware(next).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !allZero(captured) || fixture.boundary.decisionCall != 1 {
		t.Fatalf("middleware token lifetime escaped request: status=%d token=%x", response.Code, captured)
	}
	if err := fixture.handler.allowDecisionFromContext(context.Background()); !errors.Is(err, adminauth.ErrSessionInvalid) {
		t.Fatalf("anonymous decision limiter context accepted: %v", err)
	}
	if _, err := fixture.handler.requiresStepUpFromContext(context.Background()); !errors.Is(err, adminauth.ErrSessionInvalid) {
		t.Fatalf("anonymous step-up context accepted: %v", err)
	}

	fixture = newFixture(t)
	mutation := postRequest("/protected", `{}`)
	addBrowserCredential(t, mutation, fixture)
	called := false
	response = httptest.NewRecorder()
	fixture.handler.BrowserMutationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(response, mutation)
	if !called || fixture.store.touches != 1 || fixture.boundary.browserCall != 1 {
		t.Fatalf("mutation middleware failed: called=%v touches=%d browser=%d", called, fixture.store.touches, fixture.boundary.browserCall)
	}
}

func TestGETAndMutationMiddlewareRejectAmbiguousRequests(t *testing.T) {
	for _, mutate := range []func(*http.Request){
		func(request *http.Request) { request.URL.RawQuery = "x=1" },
		func(request *http.Request) { request.Header.Set("Content-Type", "application/json") },
		func(request *http.Request) {
			request.Body = ioBody("x")
			request.ContentLength = 1
		},
	} {
		fixture := newFixture(t)
		request := getRequest(SessionPath)
		addCredential(t, request, fixture.policy, fixture.issued)
		mutate(request)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || fixture.store.loads != 0 {
			t.Fatalf("ambiguous GET reached store: status=%d loads=%d", response.Code, fixture.store.loads)
		}
	}

	fixture := newFixture(t)
	request := postRequest("/protected", `{}`)
	addBrowserCredential(t, request, fixture)
	request.Header.Set("Origin", "https://evil.example.test")
	called := false
	response := httptest.NewRecorder()
	fixture.handler.BrowserMutationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || called || fixture.store.loads != 0 || fixture.store.touches != 0 {
		t.Fatalf("bad origin reached mutation boundary: status=%d called=%v loads=%d touches=%d", response.Code, called, fixture.store.loads, fixture.store.touches)
	}

	fixture = newFixture(t)
	request = postRequest("/protected", `{}`)
	addBrowserCredential(t, request, fixture)
	fixture.store.touchErr = adminstore.ErrConflict
	response = httptest.NewRecorder()
	fixture.handler.BrowserMutationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(response, request)
	if response.Code != http.StatusConflict || fixture.store.touches != 1 {
		t.Fatalf("mutation CAS conflict did not fail closed: status=%d touches=%d", response.Code, fixture.store.touches)
	}
}

func TestCanonicalDirectPeerRejectsAmbiguousAddressForms(t *testing.T) {
	for _, accepted := range []string{"192.0.2.1:1", "[2001:db8::1]:65535", "[::1]:443"} {
		if _, ok := canonicalDirectPeer(accepted); !ok {
			t.Fatalf("canonical direct peer rejected: %q", accepted)
		}
	}
	for _, rejected := range []string{
		"", "192.0.2.1", "192.0.2.1:0", "192.0.2.1:01", "192.0.2.01:443",
		"[2001:0db8::1]:443", "[fe80::1%en0]:443", "[::ffff:192.0.2.1]:443",
		"0.0.0.0:443", "224.0.0.1:443", "[ff02::1]:443",
	} {
		if _, ok := canonicalDirectPeer(rejected); ok {
			t.Fatalf("ambiguous direct peer accepted: %q", rejected)
		}
	}
}

func TestStrictMethodsPathsAndConstructor(t *testing.T) {
	fixture := newFixture(t)
	for _, test := range []struct {
		method string
		path   string
		allow  string
		status int
	}{
		{method: http.MethodGet, path: LoginPath, allow: http.MethodPost, status: 405},
		{method: http.MethodPost, path: SessionPath, allow: http.MethodGet, status: 405},
		{method: http.MethodGet, path: "/api/v1/session/", status: 404},
		{method: http.MethodGet, path: "/api%2fv1/session", status: 404},
	} {
		request := httptest.NewRequest(test.method, "https://api.example.test"+test.path, nil)
		request.RemoteAddr = "192.0.2.50:41234"
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != test.status || response.Header().Get("Allow") != test.allow {
			t.Fatalf("route %s %s: status=%d allow=%q", test.method, test.path, response.Code, response.Header().Get("Allow"))
		}
	}
	if _, err := NewHandler(Config{}); err == nil {
		t.Fatal("incomplete handler configuration accepted")
	}
	var nilHandler *Handler
	nilResponse := httptest.NewRecorder()
	nilHandler.ServeHTTP(nilResponse, getRequest(SessionPath))
	if nilResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil handler did not fail closed: %d", nilResponse.Code)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", fixture.handler, fixture.handler), fixture.issued.SessionToken()) {
		t.Fatal("handler formatting exposed secret")
	}
}

func decodeSessionEnvelope(t *testing.T, response *httptest.ResponseRecorder) sessionEnvelope {
	t.Helper()
	var result sessionEnvelope
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Referrer-Policy") != "no-referrer" ||
		!testUUIDPattern.MatchString(response.Header().Get("X-SentinelFlow-Trace-ID")) {
		t.Fatalf("missing security headers: %#v", response.Header())
	}
}

func TestCommonHeadersPreserveExistingServerTrace(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	traceID := "019b0000-0000-4000-8000-000000000001"
	response.Header().Set("X-SentinelFlow-Trace-ID", traceID)
	setCommonHeaders(response)
	setCommonHeaders(response)
	if got := response.Header().Get("X-SentinelFlow-Trace-ID"); got != traceID {
		t.Fatalf("trace ID changed across nested middleware: %q", got)
	}
}

func allZero(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func ioBody(value string) *readCloser { return &readCloser{Reader: strings.NewReader(value)} }

type readCloser struct{ *strings.Reader }

func (reader *readCloser) Close() error { return nil }

var _ = errors.Is
