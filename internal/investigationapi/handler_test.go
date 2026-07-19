package investigationapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/investigationstore"
)

const (
	testSessionID  = "019b0000-0000-4000-8000-00000000a001"
	testIncidentID = "019b0000-0000-7000-8000-00000000a101"
	testPolicyID   = "019b0000-0000-7000-8000-00000000a201"
	testActionID   = "019b0000-0000-7000-8000-00000000a301"
)

var apiTestNow = time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC)

func TestHandlerRequiresAlreadyValidatedPrincipal(t *testing.T) {
	t.Parallel()
	reader := &readerStub{listIncidents: func(context.Context, investigationstore.IncidentQuery) (investigationstore.IncidentPage, error) {
		t.Fatal("reader called without principal")
		return investigationstore.IncidentPage{}, nil
	}}
	handler := newTestHandler(t, reader, principalStub{}, newNumericSource())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if strings.Contains(response.Body.String(), testSessionID) || strings.Contains(response.Body.String(), "cookie") {
		t.Fatalf("authentication response leaked state: %s", response.Body.String())
	}
}

func TestHandlerRejectsExpiredPrincipalBeforeAnyRead(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	principal := principalStub{value: Principal{
		ActorID: "admin", SessionID: testSessionID,
		ValidatedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Minute),
	}, ok: true}
	reader := &readerStub{listIncidents: func(context.Context, investigationstore.IncidentQuery) (investigationstore.IncidentPage, error) {
		t.Fatal("expired principal reached store")
		return investigationstore.IncidentPage{}, nil
	}}
	handler := newTestHandler(t, reader, principal, newNumericSource())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerActorIDMatchesCanonical128ByteBoundary(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	readerCalls := 0
	reader := &readerStub{listIncidents: func(context.Context, investigationstore.IncidentQuery) (investigationstore.IncidentPage, error) {
		readerCalls++
		return investigationstore.IncidentPage{Items: []investigationstore.IncidentSummary{}}, nil
	}}
	for _, test := range []struct {
		name       string
		actorID    string
		wantStatus int
	}{
		{name: "128 accepted", actorID: strings.Repeat("a", 128), wantStatus: http.StatusOK},
		{name: "129 rejected", actorID: strings.Repeat("a", 129), wantStatus: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal := principalStub{value: Principal{
				ActorID: test.actorID, SessionID: testSessionID,
				ValidatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
			}, ok: true}
			handler := newTestHandler(t, reader, principal, newNumericSource())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil))
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
	if readerCalls != 1 {
		t.Fatalf("reader calls=%d, want one authorized request", readerCalls)
	}
}

func TestHandlerStrictRequestBoundary(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), newNumericSource())
	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		headers    map[string]string
		wantStatus int
	}{
		{name: "method", method: http.MethodPost, target: "/api/v1/incidents", wantStatus: 405},
		{name: "body", method: http.MethodGet, target: "/api/v1/incidents", body: `{}`, headers: map[string]string{"Content-Type": "application/json"}, wantStatus: 400},
		{name: "accept", method: http.MethodGet, target: "/api/v1/incidents", headers: map[string]string{"Accept": "text/html"}, wantStatus: 406},
		{name: "nan accept quality", method: http.MethodGet, target: "/api/v1/incidents", headers: map[string]string{"Accept": "application/json;q=NaN"}, wantStatus: 406},
		{name: "duplicate", method: http.MethodGet, target: "/api/v1/incidents?limit=1&limit=2", wantStatus: 400},
		{name: "unknown query", method: http.MethodGet, target: "/api/v1/incidents?debug=true", wantStatus: 400},
		{name: "bad path id", method: http.MethodGet, target: "/api/v1/incidents/019B0000-0000-7000-8000-00000000A101", wantStatus: 404},
		{name: "trailing slash", method: http.MethodGet, target: "/api/v1/incidents/", wantStatus: 404},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var body *strings.Reader
			if test.body != "" {
				body = strings.NewReader(test.body)
			} else {
				body = strings.NewReader("")
			}
			request := httptest.NewRequest(test.method, test.target, body)
			for key, value := range test.headers {
				request.Header.Set(key, value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if response.Header().Get("Cache-Control") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("missing safety headers: %v", response.Header())
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	request.Body = io.NopCloser(strings.NewReader(`{}`))
	request.ContentLength = -1
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown-length body status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestErrorResponseMatchesRegisteredFrontendContract(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	writeError(response, http.StatusBadRequest, "unregistered_backend_code", "")
	var value errorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value.Code != "internal_error" || !uuidPattern.MatchString(value.TraceID) || value.Details == nil ||
		!registeredAPIErrorCode(value.Code) {
		t.Fatalf("error contract=%+v", value)
	}
}

func TestIncidentListParsesBoundedFilters(t *testing.T) {
	t.Parallel()
	called := false
	reader := &readerStub{listIncidents: func(_ context.Context, query investigationstore.IncidentQuery) (investigationstore.IncidentPage, error) {
		called = true
		if query.State != "open" || query.Kind != "request_burst" || query.SourceIP != "203.0.113.20" ||
			query.ServiceLabel != "demo" || query.Limit != 10 || query.From == nil || query.Until == nil {
			t.Fatalf("query=%+v", query)
		}
		return investigationstore.IncidentPage{Items: []investigationstore.IncidentSummary{}}, nil
	}}
	handler := newTestHandler(t, reader, validPrincipalStub(), newNumericSource())
	target := "/api/v1/incidents?state=open&kind=request_burst&source=203.0.113.20&service=demo" +
		"&from=2026-07-18T08%3A00%3A00Z&until=2026-07-18T09%3A00%3A00Z&limit=10"
	request := httptest.NewRequest(http.MethodGet, target, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !called || response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("status=%d called=%v headers=%v body=%s", response.Code, called, response.Header(), response.Body.String())
	}
}

func TestAuditListParsesActorObjectTraceAndTimeFilters(t *testing.T) {
	t.Parallel()
	traceID := "019b0000-0000-7000-8000-00000000a401"
	called := false
	reader := &readerStub{listAudit: func(_ context.Context, query investigationstore.AuditQuery) (investigationstore.AuditPage, error) {
		called = true
		if query.IncidentID != testIncidentID || query.PolicyID != testPolicyID || query.ActionID != testActionID ||
			query.ActorType != "administrator" || query.ActorID != "admin" || query.ObjectType != "policy" ||
			query.ObjectID != testPolicyID || query.TraceID != traceID || query.Limit != 25 ||
			query.From == nil || query.Until == nil {
			t.Fatalf("query=%+v", query)
		}
		return investigationstore.AuditPage{Items: []investigationstore.AuditEvent{}}, nil
	}}
	handler := newTestHandler(t, reader, validPrincipalStub(), newNumericSource())
	target := "/api/v1/audit-events?incident_id=" + testIncidentID + "&policy_id=" + testPolicyID +
		"&action_id=" + testActionID + "&actor_type=administrator&actor_id=admin&object_type=policy" +
		"&object_id=" + testPolicyID + "&trace_id=" + traceID +
		"&from=2026-07-18T08%3A00%3A00Z&until=2026-07-18T09%3A00%3A00Z&limit=25"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
	if response.Code != http.StatusOK || !called {
		t.Fatalf("status=%d called=%v body=%s", response.Code, called, response.Body.String())
	}
}

func TestStoreFailuresAreGenericAndNotFoundIsStable(t *testing.T) {
	t.Parallel()
	secret := errors.New("postgresql://admin:secret@10.0.0.9 private row")
	reader := &readerStub{getPolicy: func(context.Context, string) (investigationstore.PolicyDetail, error) {
		return investigationstore.PolicyDetail{}, secret
	}}
	handler := newTestHandler(t, reader, validPrincipalStub(), newNumericSource())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/policies/"+testPolicyID, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
	for _, forbidden := range []string{"postgresql", "secret", "10.0.0.9", "private row"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("error leaked %q: %s", forbidden, response.Body.String())
		}
	}

	reader.getPolicy = func(context.Context, string) (investigationstore.PolicyDetail, error) {
		return investigationstore.PolicyDetail{}, investigationstore.ErrNotFound
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("not found status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestValidationAttemptTerminalBindingFailureReturnsGeneric503(t *testing.T) {
	t.Parallel()
	reader := &readerStub{getPolicy: func(context.Context, string) (investigationstore.PolicyDetail, error) {
		return investigationstore.PolicyDetail{}, investigationstore.ErrUnavailable
	}}
	handler := newTestHandler(t, reader, validPrincipalStub(), newNumericSource())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/policies/"+testPolicyID, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if strings.Contains(response.Body.String(), "terminal binding") ||
		strings.Contains(response.Body.String(), "validation_attempt") {
		t.Fatalf("terminal binding detail leaked: %s", response.Body.String())
	}
}

func TestPolicyResponseIncludesFailClosedValidationAttemptEvidence(t *testing.T) {
	t.Parallel()
	failure := "history_demo_binding_mismatch"
	failedGate := "historical_impact"
	terminalDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	reader := &readerStub{getPolicy: func(context.Context, string) (investigationstore.PolicyDetail, error) {
		return investigationstore.PolicyDetail{
			PolicyID: testPolicyID,
			ValidationAttempt: &investigationstore.ValidationAttemptSummary{
				ValidationAttemptID: "019b0000-0000-7000-8000-00000000b001",
				PolicyID:            testPolicyID,
				AnalysisID:          "019b0000-0000-4000-8000-00000000b002",
				IncidentID:          testIncidentID,
				IncidentVersion:     2,
				State:               "invalid", FailureCode: &failure, FailedGate: &failedGate,
				PreparedSnapshotDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				TerminalMutationDigest: &terminalDigest,
				CompletedAt:            time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC),
				Gates:                  []investigationstore.ValidationAttemptGate{},
			},
		}, nil
	}}
	handler := newTestHandler(t, reader, validPrincipalStub(), newNumericSource())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/policies/"+testPolicyID, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	attempt, ok := payload["latest_validation_attempt"].(map[string]any)
	if !ok || attempt["state"] != "invalid" || attempt["failure_code"] != failure ||
		attempt["failed_gate"] != failedGate || payload["latest_validation"] != nil {
		t.Fatalf("policy response=%v", payload)
	}
	for _, prohibited := range []string{`"prepared_snapshot":`, `"terminal_mutation":`, "structured_output"} {
		if strings.Contains(response.Body.String(), prohibited) {
			t.Fatalf("policy response exposed %q: %s", prohibited, response.Body.String())
		}
	}
}

func TestIncidentResponseOmitsLatestAnalysisWhenCurrentEvidenceHasNone(t *testing.T) {
	t.Parallel()
	reader := &readerStub{getIncident: func(context.Context, string) (investigationstore.IncidentDetail, error) {
		return investigationstore.IncidentDetail{
			Incident: investigationstore.IncidentSummary{IncidentID: testIncidentID},
			Signals:  []investigationstore.SignalSummary{},
			Policies: []investigationstore.PolicySummary{},
			Analysis: nil,
		}, nil
	}}
	handler := newTestHandler(t, reader, validPrincipalStub(), newNumericSource())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+testIncidentID, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if _, exposed := payload["latest_analysis"]; exposed {
		t.Fatalf("response exposed stale/latest analysis placeholder: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "evidence_version") {
		t.Fatalf("response exposed internal evidence version: %s", response.Body.String())
	}
}

func TestRoutesDispatchOnlyReadOperations(t *testing.T) {
	t.Parallel()
	reader := &readerStub{
		getIncident: func(_ context.Context, id string) (investigationstore.IncidentDetail, error) {
			if id != testIncidentID {
				t.Fatalf("incident id=%s", id)
			}
			return investigationstore.IncidentDetail{Signals: []investigationstore.SignalSummary{}, Policies: []investigationstore.PolicySummary{}}, nil
		},
		getAction: func(_ context.Context, id string) (investigationstore.EnforcementActionDetail, error) {
			if id != testActionID {
				t.Fatalf("action id=%s", id)
			}
			return investigationstore.EnforcementActionDetail{ActionID: id}, nil
		},
		listAudit: func(_ context.Context, query investigationstore.AuditQuery) (investigationstore.AuditPage, error) {
			if query.ActionID != testActionID {
				t.Fatalf("audit query=%+v", query)
			}
			return investigationstore.AuditPage{Items: []investigationstore.AuditEvent{}}, nil
		},
	}
	handler := newTestHandler(t, reader, validPrincipalStub(), newNumericSource())
	for _, target := range []string{
		"/api/v1/incidents/" + testIncidentID,
		"/api/v1/enforcement-actions/" + testActionID,
		"/api/v1/audit-events?action_id=" + testActionID,
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("target=%s status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
}

type principalStub struct {
	value Principal
	ok    bool
}

func (stub principalStub) Principal(context.Context) (Principal, bool) { return stub.value, stub.ok }

func validPrincipalStub() principalStub {
	now := time.Now().UTC()
	return principalStub{value: Principal{
		ActorID: "admin", SessionID: testSessionID, ValidatedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}, ok: true}
}

type readerStub struct {
	listIncidents func(context.Context, investigationstore.IncidentQuery) (investigationstore.IncidentPage, error)
	getIncident   func(context.Context, string) (investigationstore.IncidentDetail, error)
	listEvents    func(context.Context, investigationstore.IncidentEventQuery) (investigationstore.IncidentEventPage, error)
	getPolicy     func(context.Context, string) (investigationstore.PolicyDetail, error)
	getAction     func(context.Context, string) (investigationstore.EnforcementActionDetail, error)
	listAudit     func(context.Context, investigationstore.AuditQuery) (investigationstore.AuditPage, error)
}

func (stub *readerStub) ListIncidents(ctx context.Context, query investigationstore.IncidentQuery) (investigationstore.IncidentPage, error) {
	if stub.listIncidents == nil {
		return investigationstore.IncidentPage{}, investigationstore.ErrNotFound
	}
	return stub.listIncidents(ctx, query)
}
func (stub *readerStub) GetIncident(ctx context.Context, id string) (investigationstore.IncidentDetail, error) {
	if stub.getIncident == nil {
		return investigationstore.IncidentDetail{}, investigationstore.ErrNotFound
	}
	return stub.getIncident(ctx, id)
}
func (stub *readerStub) ListIncidentEvents(ctx context.Context, query investigationstore.IncidentEventQuery) (investigationstore.IncidentEventPage, error) {
	if stub.listEvents == nil {
		return investigationstore.IncidentEventPage{}, investigationstore.ErrNotFound
	}
	return stub.listEvents(ctx, query)
}
func (stub *readerStub) GetPolicy(ctx context.Context, id string) (investigationstore.PolicyDetail, error) {
	if stub.getPolicy == nil {
		return investigationstore.PolicyDetail{}, investigationstore.ErrNotFound
	}
	return stub.getPolicy(ctx, id)
}
func (stub *readerStub) GetEnforcementAction(ctx context.Context, id string) (investigationstore.EnforcementActionDetail, error) {
	if stub.getAction == nil {
		return investigationstore.EnforcementActionDetail{}, investigationstore.ErrNotFound
	}
	return stub.getAction(ctx, id)
}
func (stub *readerStub) ListAuditEvents(ctx context.Context, query investigationstore.AuditQuery) (investigationstore.AuditPage, error) {
	if stub.listAudit == nil {
		return investigationstore.AuditPage{}, investigationstore.ErrNotFound
	}
	return stub.listAudit(ctx, query)
}

func newTestHandler(t *testing.T, reader Reader, principals PrincipalProvider, events EventSource) *Handler {
	return newTestHandlerWithLeases(t, reader, principals, events, &leaseStub{})
}

const testProcessInstance = "019b0000-0000-4000-8000-00000000f0aa"

func newTestHandlerWithLeases(
	t *testing.T,
	reader Reader,
	principals PrincipalProvider,
	events EventSource,
	leases ClientLeaseStore,
) *Handler {
	t.Helper()
	handler, err := NewHandler(Config{
		Reader: reader, Principals: principals, Events: events,
		Leases: leases, ProcessInstance: testProcessInstance,
		PollInterval: 5 * time.Millisecond, HeartbeatInterval: 10 * time.Millisecond,
		WriteTimeout: 20 * time.Millisecond, SourceTimeout: 5 * time.Millisecond,
		MaxConnectionLifetime: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
