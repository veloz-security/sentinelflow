package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
)

type fakeBatchStore struct {
	mu      sync.Mutex
	calls   int
	path    string
	batch   ingestion.AuthenticatedBatch
	outcome StoreOutcome
	err     error
}

func (s *fakeBatchStore) StoreBatch(_ context.Context, path string, batch ingestion.AuthenticatedBatch, _ time.Time) (StoreOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.path = path
	s.batch = batch
	return s.outcome, s.err
}

func (s *fakeBatchStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func testBatch(t *testing.T) ([]byte, time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	timestamp, err := events.NewTimestamp(now)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("event"))
	event := events.GatewayHTTPV1{
		SchemaVersion:      events.GatewayHTTPV1Schema,
		EventID:            "019b0000-0000-7000-8000-000000000001",
		RequestID:          "019b0000-0000-7000-8000-000000000002",
		TraceID:            "019b0000-0000-7000-8000-000000000003",
		IdempotencyKey:     "sha256:" + hex.EncodeToString(digest[:]),
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
		BatchID:       "019b0000-0000-7000-8000-000000000010",
		Sequence:      1,
		SentAt:        timestamp,
		Records:       []events.EventRecordV1{events.GatewayHTTPRecord(event)},
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return body, now
}

func signedRequest(t *testing.T, path string, body, key []byte, now time.Time) *http.Request {
	t.Helper()
	nonce := bytes.Repeat([]byte{7}, 16)
	headers, err := ingestion.Sign(path, "gateway-01", key, body, nonce, now)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Sentinel-Sender-ID", headers.SenderID)
	request.Header.Set("X-Sentinel-Timestamp", headers.Timestamp)
	request.Header.Set("X-Sentinel-Nonce", headers.Nonce)
	request.Header.Set("X-Sentinel-Signature", headers.Signature)
	return request
}

func newTestHandler(t *testing.T, key []byte, store BatchStore, now time.Time) *IngestHandler {
	t.Helper()
	registry, err := ingestion.NewRegistry([]ingestion.Binding{
		{SenderID: "gateway-01", EndpointPath: ingestion.GatewayEventsPath, Key: key},
		{SenderID: "auth-app", EndpointPath: ingestion.AuthEventsPath, Key: bytes.Repeat([]byte{8}, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewIngestHandler(IngestConfig{Registry: registry, Store: store, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestIngestHandlerAuthenticatesAndReturnsBoundAcknowledgement(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{9}, 32)
	body, now := testBatch(t)
	for _, outcome := range []StoreOutcome{StoreAccepted, StoreDuplicate} {
		t.Run(string(outcome), func(t *testing.T) {
			store := &fakeBatchStore{outcome: outcome}
			handler := newTestHandler(t, key, store, now)
			request := signedRequest(t, ingestion.GatewayEventsPath, body, key, now)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusAccepted || store.callCount() != 1 {
				t.Fatalf("status=%d store calls=%d body=%s", recorder.Code, store.callCount(), recorder.Body.String())
			}
			var acknowledgement batchAcknowledgement
			decoder := json.NewDecoder(recorder.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&acknowledgement); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			if acknowledgement.Status != outcome || acknowledgement.SenderID != "gateway-01" ||
				acknowledgement.SenderEpoch != "AQEBAQEBAQEBAQEBAQEBAQ" || acknowledgement.Sequence != 1 ||
				acknowledgement.BodyDigest != "sha256:"+hex.EncodeToString(sum[:]) {
				t.Fatalf("acknowledgement = %#v", acknowledgement)
			}
		})
	}
}

func TestIngestHandlerRejectsBeforeStore(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{9}, 32)
	body, now := testBatch(t)
	tests := []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"bad signature", func(r *http.Request) { r.Header.Set("X-Sentinel-Signature", strings.Repeat("0", 64)) }, http.StatusUnprocessableEntity},
		{"duplicate sender", func(r *http.Request) { r.Header["X-Sentinel-Sender-Id"] = []string{"gateway-01", "gateway-01"} }, http.StatusUnprocessableEntity},
		{"wrong content type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, http.StatusUnprocessableEntity},
		{"content encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, http.StatusUnprocessableEntity},
		{"wrong endpoint", func(r *http.Request) { r.URL.Path = ingestion.AuthEventsPath }, http.StatusUnprocessableEntity},
		{"wrong method", func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
		{"unknown path", func(r *http.Request) { r.URL.Path = "/internal/v1/unknown" }, http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeBatchStore{outcome: StoreAccepted}
			handler := newTestHandler(t, key, store, now)
			request := signedRequest(t, ingestion.GatewayEventsPath, body, key, now)
			test.mutate(request)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.status || store.callCount() != 0 {
				t.Fatalf("status=%d want=%d store calls=%d", recorder.Code, test.status, store.callCount())
			}
		})
	}

	store := &fakeBatchStore{outcome: StoreAccepted}
	handler := newTestHandler(t, key, store, now)
	oversized := bytes.Repeat([]byte{'x'}, events.MaxEventBatchBodyBytes+1)
	request := httptest.NewRequest(http.MethodPost, ingestion.GatewayEventsPath, bytes.NewReader(oversized))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity || store.callCount() != 0 {
		t.Fatalf("oversized status=%d calls=%d", recorder.Code, store.callCount())
	}
}

func TestIngestHandlerMapsAtomicStoreOutcomes(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{9}, 32)
	body, now := testBatch(t)
	tests := []struct {
		name    string
		outcome StoreOutcome
		err     error
		status  int
	}{
		{"conflict", "", ErrBatchConflict, http.StatusConflict},
		{"rejected", "", ErrBatchRejected, http.StatusUnprocessableEntity},
		{"unavailable", "", ErrStoreUnavailable, http.StatusServiceUnavailable},
		{"unknown failure", "", errors.New("secret database detail"), http.StatusServiceUnavailable},
		{"invalid success", "unexpected", nil, http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeBatchStore{outcome: test.outcome, err: test.err}
			handler := newTestHandler(t, key, store, now)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, signedRequest(t, ingestion.GatewayEventsPath, body, key, now))
			if recorder.Code != test.status || strings.Contains(recorder.Body.String(), "database") {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestNewIngestHandlerRequiresAtomicDependencies(t *testing.T) {
	t.Parallel()
	if _, err := NewIngestHandler(IngestConfig{}); err == nil {
		t.Fatal("missing dependencies accepted")
	}
}
