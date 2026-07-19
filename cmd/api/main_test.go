package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	controlapi "github.com/devwooops/sentinelflow/internal/api"
	"github.com/devwooops/sentinelflow/internal/authbinding"
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
	"github.com/devwooops/sentinelflow/internal/repository"
	"github.com/jackc/pgx/v5"
)

type stubPing struct {
	err error
}

type countingPing struct {
	calls atomic.Int32
	err   error
}

type roleRow struct {
	role string
	err  error
}

func (row roleRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != 1 {
		return errors.New("unexpected role destination")
	}
	pointer, ok := destinations[0].(*string)
	if !ok {
		return errors.New("unexpected role destination type")
	}
	*pointer = row.role
	return nil
}

type roleReader struct{ row roleRow }

func (reader roleReader) QueryRow(context.Context, string, ...any) pgx.Row { return reader.row }

func (p stubPing) Ping(context.Context) error { return p.err }

func (p *countingPing) Ping(context.Context) error {
	p.calls.Add(1)
	return p.err
}

type stubIngest struct {
	calls int
}

type stubManagement struct {
	calls int
}

type ingestStoreSpy struct {
	calls atomic.Int32
}

func (store *ingestStoreSpy) StoreBatch(
	context.Context,
	string,
	ingestion.AuthenticatedBatch,
	time.Time,
) (controlapi.StoreOutcome, error) {
	store.calls.Add(1)
	return controlapi.StoreAccepted, nil
}

func (h *stubManagement) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	h.calls++
	writer.WriteHeader(http.StatusTeapot)
}

type stubBindingReconciler struct {
	calls   atomic.Int32
	started chan struct{}
	err     error
}

type stubSourceRegistrar struct {
	inputs []repository.ExpectedSourceBinding
	errAt  int
}

func (r *stubSourceRegistrar) Register(_ context.Context, input repository.ExpectedSourceBinding) (repository.RegisteredSourceBinding, error) {
	r.inputs = append(r.inputs, input)
	if r.errAt > 0 && len(r.inputs) == r.errAt {
		return repository.RegisteredSourceBinding{}, repository.ErrSourceBindingConflict
	}
	return repository.RegisteredSourceBinding{ExpectedSourceBinding: input, EffectiveAt: time.Now().UTC()}, nil
}

func (r *stubBindingReconciler) Reconcile(context.Context) (authbinding.Result, error) {
	r.calls.Add(1)
	select {
	case r.started <- struct{}{}:
	default:
	}
	return authbinding.Result{}, r.err
}

func (h *stubIngest) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	h.calls++
	writer.WriteHeader(http.StatusAccepted)
}

func signedGatewayIngestFixture(
	t *testing.T,
) (*controlapi.IngestHandler, *ingestStoreSpy, *http.Request) {
	t.Helper()
	key := bytes.Repeat([]byte{9}, 32)
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	timestamp, err := events.NewTimestamp(now)
	if err != nil {
		t.Fatal(err)
	}
	eventDigest := sha256.Sum256([]byte("chi-routing-raw-path-test"))
	event := events.GatewayHTTPV1{
		SchemaVersion:      events.GatewayHTTPV1Schema,
		EventID:            "019b0000-0000-7000-8000-000000000101",
		RequestID:          "019b0000-0000-7000-8000-000000000102",
		TraceID:            "019b0000-0000-7000-8000-000000000103",
		IdempotencyKey:     "sha256:" + hex.EncodeToString(eventDigest[:]),
		StartedAt:          timestamp,
		CompletedAt:        timestamp,
		SourceIP:           "203.0.113.20",
		Method:             http.MethodGet,
		Protocol:           "HTTP/1.1",
		RouteLabel:         "other",
		PathCatalogVersion: events.PathCatalogV1,
		SuspiciousPathID:   events.SuspiciousPathNone,
		Host:               "app.example.test",
		ServiceLabel:       "demo-app",
		StatusCode:         http.StatusOK,
	}
	batch := events.EventBatchV1{
		SchemaVersion: events.EventBatchV1Schema,
		SenderID:      "gateway-01",
		SenderEpoch:   "AQEBAQEBAQEBAQEBAQEBAQ",
		BatchID:       "019b0000-0000-7000-8000-000000000110",
		Sequence:      1,
		SentAt:        timestamp,
		Records:       []events.EventRecordV1{events.GatewayHTTPRecord(event)},
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := ingestion.NewRegistry([]ingestion.Binding{{
		SenderID: "gateway-01", EndpointPath: ingestion.GatewayEventsPath, Key: key,
	}})
	if err != nil {
		t.Fatal(err)
	}
	store := &ingestStoreSpy{}
	handler, err := controlapi.NewIngestHandler(controlapi.IngestConfig{
		Registry: registry,
		Store:    store,
		Clock:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{7}, 16)
	headers, err := ingestion.Sign(ingestion.GatewayEventsPath, "gateway-01", key, body, nonce, now)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, ingestion.GatewayEventsPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Sentinel-Sender-ID", headers.SenderID)
	request.Header.Set("X-Sentinel-Timestamp", headers.Timestamp)
	request.Header.Set("X-Sentinel-Nonce", headers.Nonce)
	request.Header.Set("X-Sentinel-Signature", headers.Signature)
	return handler, store, request
}

func TestDecodeHMACKey(t *testing.T) {
	t.Parallel()
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg, err := config.LoadFrom(config.RoleGateway, func(name string) (string, bool) {
		if name == "GATEWAY_EVENT_HMAC_KEY" {
			return valid, true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	decoded, err := decodeHMACKey(cfg.Events.GatewayHMACKey)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decodeHMACKey() = (%d bytes, %v), want 32 bytes", len(decoded), err)
	}
}

func TestRequireDatabaseRoleRejectsUnexpectedAuthority(t *testing.T) {
	t.Parallel()
	if err := requireDatabaseRole(t.Context(), roleReader{row: roleRow{role: "sentinelflow_api"}}, "sentinelflow_api"); err != nil {
		t.Fatalf("expected role rejected: %v", err)
	}
	for _, reader := range []databaseRoleReader{
		roleReader{row: roleRow{role: "postgres"}},
		roleReader{row: roleRow{err: errors.New("database detail")}},
	} {
		if err := requireDatabaseRole(t.Context(), reader, "sentinelflow_api"); err == nil || strings.Contains(err.Error(), "database detail") {
			t.Fatalf("unsafe role result: %v", err)
		}
	}
}

func TestRegisterExpectedSourceBindingsUsesExactReceiverAuthority(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		Gateway: config.GatewayConfig{ServiceLabel: "demo-app"},
		Events: config.EventConfig{
			GatewaySenderID:         "gateway-01",
			GatewayHMACKeyID:        "gateway-key-v1",
			GatewaySourceBindingID:  "11111111-1111-4111-8111-111111111111",
			GatewaySourceConfigHash: strings.Repeat("1", 64),
			AuthSenderID:            "demo-app",
			AuthServiceLabel:        "demo-app",
			AuthHMACKeyID:           "auth-key-v1",
			AuthSourceBindingID:     "22222222-2222-4222-8222-222222222222",
			AuthSourceConfigHash:    strings.Repeat("2", 64),
		},
	}
	registrar := &stubSourceRegistrar{}
	if err := registerExpectedSourceBindings(t.Context(), registrar, cfg); err != nil {
		t.Fatalf("registerExpectedSourceBindings() error = %v", err)
	}
	want := []repository.ExpectedSourceBinding{
		{
			BindingID:    cfg.Events.GatewaySourceBindingID,
			SenderID:     cfg.Events.GatewaySenderID,
			EndpointKind: repository.SourceEndpointGateway,
			ServiceLabel: cfg.Gateway.ServiceLabel,
			KeyID:        cfg.Events.GatewayHMACKeyID,
			ConfigDigest: "sha256:" + cfg.Events.GatewaySourceConfigHash,
		},
		{
			BindingID:    cfg.Events.AuthSourceBindingID,
			SenderID:     cfg.Events.AuthSenderID,
			EndpointKind: repository.SourceEndpointAuth,
			ServiceLabel: cfg.Events.AuthServiceLabel,
			KeyID:        cfg.Events.AuthHMACKeyID,
			ConfigDigest: "sha256:" + cfg.Events.AuthSourceConfigHash,
		},
	}
	if len(registrar.inputs) != len(want) {
		t.Fatalf("registered %d bindings, want %d", len(registrar.inputs), len(want))
	}
	for index := range want {
		if registrar.inputs[index] != want[index] {
			t.Fatalf("binding %d = %+v, want %+v", index, registrar.inputs[index], want[index])
		}
	}

	failing := &stubSourceRegistrar{errAt: 2}
	err := registerExpectedSourceBindings(t.Context(), failing, cfg)
	if !errors.Is(err, repository.ErrSourceBindingConflict) || len(failing.inputs) != 2 {
		t.Fatalf("conflicting registration = (%d calls, %v)", len(failing.inputs), err)
	}
	if err := registerExpectedSourceBindings(t.Context(), nil, cfg); err == nil {
		t.Fatal("nil registrar accepted")
	}
}

func TestListenerRoutesAreSeparated(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		Listeners: config.ListenerConfig{
			InternalAPIIngestAddr: "127.0.0.1:0",
			APIManagementAddr:     "127.0.0.1:0",
		},
	}
	ingest := &stubIngest{}
	managementAPI := &stubManagement{}
	internal, management := newServers(cfg, ingest, managementAPI, stubPing{})

	assertStatus(t, internal.Handler, http.MethodPost, "/internal/v1/gateway-events", http.StatusAccepted)
	assertStatus(t, internal.Handler, http.MethodPost, "/internal/v1/auth-events", http.StatusAccepted)
	assertStatus(t, internal.Handler, http.MethodGet, "/health/live", http.StatusNoContent)
	assertStatus(t, internal.Handler, http.MethodHead, "/health/live", http.StatusNoContent)
	assertStatus(t, internal.Handler, http.MethodGet, "/health/ready", http.StatusNoContent)
	assertStatus(t, internal.Handler, http.MethodHead, "/health/ready", http.StatusNoContent)
	assertStatus(t, internal.Handler, http.MethodGet, "/readyz", http.StatusNoContent)
	assertStatus(t, management.Handler, http.MethodGet, "/health/live", http.StatusNoContent)
	assertStatus(t, management.Handler, http.MethodHead, "/health/live", http.StatusNoContent)
	assertStatus(t, management.Handler, http.MethodGet, "/health/ready", http.StatusNoContent)
	assertStatus(t, management.Handler, http.MethodHead, "/health/ready", http.StatusNoContent)
	assertStatus(t, management.Handler, http.MethodGet, "/healthz", http.StatusNoContent)
	assertStatus(t, management.Handler, http.MethodPost, "/internal", http.StatusNotFound)
	assertStatus(t, management.Handler, http.MethodPost, "/internal/", http.StatusNotFound)
	assertStatus(t, management.Handler, http.MethodPost, "/internal/v1/gateway-events", http.StatusNotFound)
	assertStatus(t, management.Handler, http.MethodPost, "/internal/v1/gateway-events/extra", http.StatusNotFound)
	assertStatus(t, management.Handler, http.MethodPost, "/healthz", http.StatusMethodNotAllowed)
	assertStatus(t, management.Handler, http.MethodGet, "/api/v1/incidents", http.StatusTeapot)
	assertStatus(t, management.Handler, http.MethodGet, "/api/v1/events/stream", http.StatusTeapot)
	if ingest.calls != 2 {
		t.Fatalf("ingest calls = %d, want 2 internal-only calls", ingest.calls)
	}
	if managementAPI.calls != 2 {
		t.Fatalf("management API calls = %d, want 2 management-only calls", managementAPI.calls)
	}
	if management.WriteTimeout != 0 || internal.WriteTimeout == 0 {
		t.Fatalf("server write timeouts internal=%s management=%s", internal.WriteTimeout, management.WriteTimeout)
	}
}

func TestChiRoutersRejectNonCanonicalPathAliases(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Listeners: config.ListenerConfig{
		InternalAPIIngestAddr: "127.0.0.1:0",
		APIManagementAddr:     "127.0.0.1:0",
	}}
	ingest := &stubIngest{}
	admin := &recordingHandler{status: http.StatusCreated}
	investigation := &recordingHandler{status: http.StatusOK}
	internal, management := newServers(
		cfg,
		ingest,
		&managementRouter{admin: admin, investigation: investigation},
		stubPing{},
	)

	for _, test := range []struct {
		name    string
		handler http.Handler
		method  string
		path    string
		rawPath string
	}{
		{name: "internal trailing slash", handler: internal.Handler, method: http.MethodPost, path: ingestion.GatewayEventsPath + "/"},
		{name: "health trailing slash", handler: internal.Handler, method: http.MethodGet, path: "/health/live/"},
		{name: "internal encoded segment", handler: internal.Handler, method: http.MethodPost, path: ingestion.GatewayEventsPath, rawPath: "/internal/v1/gateway%2Devents"},
		{name: "health encoded segment", handler: internal.Handler, method: http.MethodGet, path: "/health/live", rawPath: "/health/l%69ve"},
		{name: "management trailing slash", handler: management.Handler, method: http.MethodGet, path: "/api/v1/session/"},
		{name: "management encoded segment", handler: management.Handler, method: http.MethodGet, path: "/api/v1/session", rawPath: "/api/v1/sess%69on"},
		{name: "encoded internal namespace", handler: management.Handler, method: http.MethodPost, path: ingestion.GatewayEventsPath, rawPath: "/internal%2Fv1/gateway-events"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request.URL.RawPath = test.rawPath
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("status=%d want=%d", response.Code, http.StatusNotFound)
			}
			if location := response.Header().Get("Location"); location != "" {
				t.Fatalf("unexpected path redirect %q", location)
			}
		})
	}
	if ingest.calls != 0 || admin.calls != 0 || investigation.calls != 0 {
		t.Fatalf("non-canonical path reached handler: ingest=%d admin=%d investigation=%d",
			ingest.calls, admin.calls, investigation.calls)
	}
}

func TestChiInternalRouterRejectsRawPathBeforeAuthenticationAndStore(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Listeners: config.ListenerConfig{
		InternalAPIIngestAddr: "127.0.0.1:0",
		APIManagementAddr:     "127.0.0.1:0",
	}}

	baselineHandler, baselineStore, baselineRequest := signedGatewayIngestFixture(t)
	baseline, _ := newServers(cfg, baselineHandler, nil, stubPing{})
	baselineResponse := httptest.NewRecorder()
	baseline.Handler.ServeHTTP(baselineResponse, baselineRequest)
	if baselineResponse.Code != http.StatusAccepted || baselineStore.calls.Load() != 1 {
		t.Fatalf("canonical signed request status=%d store calls=%d",
			baselineResponse.Code, baselineStore.calls.Load())
	}

	for _, rawPath := range []string{
		"/internal/v1/gateway%2Devents",
		"/internal%2Fv1/gateway-events",
	} {
		t.Run(rawPath, func(t *testing.T) {
			handler, store, request := signedGatewayIngestFixture(t)
			request.URL.RawPath = rawPath
			internal, _ := newServers(cfg, handler, nil, stubPing{})
			response := httptest.NewRecorder()
			internal.Handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || store.calls.Load() != 0 {
				t.Fatalf("raw path %q status=%d store calls=%d",
					rawPath, response.Code, store.calls.Load())
			}
		})
	}
}

func TestChiRoutersPreserveMethodAllowAndRequestEnvelope(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Listeners: config.ListenerConfig{
		InternalAPIIngestAddr: "127.0.0.1:0",
		APIManagementAddr:     "127.0.0.1:0",
	}}

	var ingestCalls int
	ingest := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ingestCalls++
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", http.MethodPost)
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writer.WriteHeader(http.StatusAccepted)
	})

	var managementCalls int
	managementAPI := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		managementCalls++
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read delegated body: %v", err)
		}
		if request.URL.RawQuery != "cursor=opaque" || string(body) != `{"probe":true}` {
			t.Fatalf("delegated request query=%q body=%q", request.URL.RawQuery, body)
		}
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	})
	internal, management := newServers(cfg, ingest, managementAPI, stubPing{})

	ingestResponse := httptest.NewRecorder()
	internal.Handler.ServeHTTP(ingestResponse, httptest.NewRequest(http.MethodGet, ingestion.GatewayEventsPath, nil))
	if ingestResponse.Code != http.StatusMethodNotAllowed || ingestResponse.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("ingest mismatch status=%d allow=%q", ingestResponse.Code, ingestResponse.Header().Get("Allow"))
	}
	healthResponse := httptest.NewRecorder()
	internal.Handler.ServeHTTP(healthResponse, httptest.NewRequest(http.MethodPost, "/health/live", nil))
	if healthResponse.Code != http.StatusMethodNotAllowed || healthResponse.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("health mismatch status=%d allow=%q", healthResponse.Code, healthResponse.Header().Get("Allow"))
	}

	managementRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/incidents?cursor=opaque",
		bytes.NewBufferString(`{"probe":true}`),
	)
	managementResponse := httptest.NewRecorder()
	management.Handler.ServeHTTP(managementResponse, managementRequest)
	if managementResponse.Code != http.StatusMethodNotAllowed || managementResponse.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("management mismatch status=%d allow=%q",
			managementResponse.Code, managementResponse.Header().Get("Allow"))
	}
	if ingestCalls != 1 || managementCalls != 1 {
		t.Fatalf("delegation calls ingest=%d management=%d", ingestCalls, managementCalls)
	}
}

func TestChiRoutersPreserveExtensionMethodSemantics(t *testing.T) {
	t.Parallel()
	const extensionMethod = "PROPFIND"
	cfg := config.Config{Listeners: config.ListenerConfig{
		InternalAPIIngestAddr: "127.0.0.1:0",
		APIManagementAddr:     "127.0.0.1:0",
	}}

	var ingestCalls int
	ingest := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ingestCalls++
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", http.MethodPost)
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writer.WriteHeader(http.StatusAccepted)
	})
	var managementCalls int
	managementAPI := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		managementCalls++
		if request.URL.Path != "/api/v1/session" || request.Method != extensionMethod {
			t.Fatalf("management extension request=%s %s", request.Method, request.URL.Path)
		}
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	})
	internal, management := newServers(cfg, ingest, managementAPI, stubPing{})

	assertResponse := func(handler http.Handler, path string, wantStatus int, wantAllow string) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(extensionMethod, path, nil))
		if response.Code != wantStatus || response.Header().Get("Allow") != wantAllow {
			t.Fatalf("%s %s status=%d allow=%q want=(%d,%q)",
				extensionMethod, path, response.Code, response.Header().Get("Allow"), wantStatus, wantAllow)
		}
	}

	assertResponse(internal.Handler, ingestion.GatewayEventsPath, http.StatusMethodNotAllowed, http.MethodPost)
	assertResponse(internal.Handler, "/health/live", http.StatusMethodNotAllowed, "GET, HEAD")
	assertResponse(internal.Handler, "/unknown", http.StatusNotFound, "")
	assertResponse(management.Handler, "/api/v1/session", http.StatusMethodNotAllowed, http.MethodGet)
	assertResponse(management.Handler, "/internal", http.StatusNotFound, "")
	assertResponse(management.Handler, "/internal/v1/gateway-events", http.StatusNotFound, "")
	if ingestCalls != 1 || managementCalls != 1 {
		t.Fatalf("extension delegation calls ingest=%d management=%d", ingestCalls, managementCalls)
	}
}

func TestChiRouterReadinessPingsDatabaseButLivenessDoesNot(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Listeners: config.ListenerConfig{
		InternalAPIIngestAddr: "127.0.0.1:0",
		APIManagementAddr:     "127.0.0.1:0",
	}}
	ping := &countingPing{}
	internal, management := newServers(cfg, &stubIngest{}, &stubManagement{}, ping)

	assertStatus(t, internal.Handler, http.MethodGet, "/health/live", http.StatusNoContent)
	assertStatus(t, management.Handler, http.MethodHead, "/healthz", http.StatusNoContent)
	if calls := ping.calls.Load(); calls != 0 {
		t.Fatalf("liveness ping calls=%d want=0", calls)
	}
	assertStatus(t, internal.Handler, http.MethodGet, "/health/ready", http.StatusNoContent)
	assertStatus(t, management.Handler, http.MethodHead, "/readyz", http.StatusNoContent)
	if calls := ping.calls.Load(); calls != 2 {
		t.Fatalf("readiness ping calls=%d want=2", calls)
	}

	ping.err = errors.New("database unavailable")
	assertStatus(t, internal.Handler, http.MethodGet, "/readyz", http.StatusServiceUnavailable)
	assertStatus(t, management.Handler, http.MethodGet, "/health/ready", http.StatusServiceUnavailable)
	if calls := ping.calls.Load(); calls != 4 {
		t.Fatalf("failed readiness ping calls=%d want=4", calls)
	}

	withoutDatabase, _ := newServers(cfg, &stubIngest{}, &stubManagement{}, nil)
	assertStatus(t, withoutDatabase.Handler, http.MethodGet, "/readyz", http.StatusServiceUnavailable)
}

func TestReadinessFailsClosed(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Listeners: config.ListenerConfig{
		InternalAPIIngestAddr: "127.0.0.1:0",
		APIManagementAddr:     "127.0.0.1:0",
	}}
	internal, management := newServers(cfg, &stubIngest{}, &stubManagement{}, stubPing{err: errors.New("database unavailable")})
	assertStatus(t, internal.Handler, http.MethodGet, "/readyz", http.StatusServiceUnavailable)
	assertStatus(t, management.Handler, http.MethodGet, "/readyz", http.StatusServiceUnavailable)
	assertStatus(t, internal.Handler, http.MethodGet, "/health/ready", http.StatusServiceUnavailable)
	assertStatus(t, management.Handler, http.MethodGet, "/health/ready", http.StatusServiceUnavailable)
}

func TestAuthBindingLoopStopsCleanlyOnCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	reconciler := &stubBindingReconciler{started: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() { done <- runAuthBinding(ctx, reconciler, time.Millisecond) }()
	select {
	case <-reconciler.started:
	case <-time.After(time.Second):
		t.Fatal("auth binding reconciliation did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancelled loop error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("auth binding reconciliation did not stop")
	}
}

func TestAuthBindingLoopFailsClosed(t *testing.T) {
	t.Parallel()
	reconciler := &stubBindingReconciler{started: make(chan struct{}, 1), err: errors.New("database detail")}
	err := runAuthBinding(t.Context(), reconciler, time.Millisecond)
	if err == nil || err.Error() != "api: auth binding reconciliation failed" || reconciler.calls.Load() != 1 {
		t.Fatalf("runAuthBinding() calls=%d error=%v", reconciler.calls.Load(), err)
	}
	if err := runAuthBinding(t.Context(), nil, time.Millisecond); err == nil {
		t.Fatal("nil reconciler accepted")
	}
}

func assertStatus(t *testing.T, handler http.Handler, method, path string, want int) {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != want {
		t.Fatalf("%s %s status = %d, want %d", method, path, recorder.Code, want)
	}
}
