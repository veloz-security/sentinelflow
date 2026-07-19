package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/config"
)

type recordingHandler struct {
	status int
	calls  int
}

func (handler *recordingHandler) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	handler.calls++
	writer.WriteHeader(handler.status)
}

func TestManagementRouterSeparatesMutationAndInvestigationRoutes(t *testing.T) {
	t.Parallel()
	admin := &recordingHandler{status: http.StatusCreated}
	investigation := &recordingHandler{status: http.StatusOK}
	router := &managementRouter{admin: admin, investigation: investigation}

	tests := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodPost, "/api/v1/session/login", http.StatusCreated},
		{http.MethodGet, "/api/v1/session", http.StatusCreated},
		{http.MethodPost, "/api/v1/policies/019b0000-0000-4000-8000-000000000001/decision-challenges", http.StatusCreated},
		{http.MethodPost, "/api/v1/policies/019b0000-0000-4000-8000-000000000001/decisions", http.StatusCreated},
		{http.MethodPost, "/api/v1/enforcement-actions/019b0000-0000-4000-8000-000000000001/revocation-challenges", http.StatusCreated},
		{http.MethodPost, "/api/v1/enforcement-actions/019b0000-0000-4000-8000-000000000001/revocations", http.StatusCreated},
		{http.MethodPost, "/api/v1/enforcement-actions/not-a-uuid/revocations", http.StatusCreated},
		{http.MethodGet, "/api/v1/incidents", http.StatusOK},
		{http.MethodGet, "/api/v1/incidents/019b0000-0000-4000-8000-000000000001", http.StatusOK},
		{http.MethodGet, "/api/v1/policies/019b0000-0000-4000-8000-000000000001", http.StatusOK},
		{http.MethodGet, "/api/v1/enforcement-actions/019b0000-0000-4000-8000-000000000001", http.StatusOK},
		{http.MethodGet, "/api/v1/events/stream", http.StatusOK},
		{http.MethodPost, "/internal/v1/gateway-events", http.StatusNotFound},
		{http.MethodGet, "/api/v1/unknown", http.StatusNotFound},
	}
	for _, test := range tests {
		request := httptest.NewRequest(test.method, test.path, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s %s status=%d want=%d", test.method, test.path, response.Code, test.status)
		}
	}
	if admin.calls != 7 || investigation.calls != 5 {
		t.Fatalf("route calls admin=%d investigation=%d", admin.calls, investigation.calls)
	}
}

func TestManagementProductionClockAndConfigurationWrapper(t *testing.T) {
	t.Parallel()
	before := time.Now().UTC()
	current := (managementClock{}).Now()
	after := time.Now().UTC()
	if current.Location() != time.UTC || current.Before(before) || current.After(after) {
		t.Fatalf("production management clock=%s outside [%s,%s] UTC", current, before, after)
	}
	if _, err := configureManagementAPI(config.Config{}, nil); err == nil ||
		err.Error() != "api: management database is required" {
		t.Fatalf("production configuration wrapper error=%v", err)
	}
}

func TestDecodeSessionHMACKeyIsStrictAndRedacted(t *testing.T) {
	t.Parallel()
	key := strings.Repeat("k", 32)
	cfg, err := config.LoadFrom(config.RoleGateway, func(name string) (string, bool) {
		if name == "GATEWAY_EVENT_HMAC_KEY" {
			return base64.StdEncoding.EncodeToString([]byte(key)), true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSessionHMACKey(cfg.Events.GatewayHMACKey)
	if err != nil || string(decoded) != key {
		t.Fatalf("decode length=%d err=%v", len(decoded), err)
	}
	clear(decoded)
	_, err = decodeSessionHMACKey(config.Secret{})
	if err == nil || strings.Contains(err.Error(), key) {
		t.Fatalf("unsafe decode error: %v", err)
	}
}
