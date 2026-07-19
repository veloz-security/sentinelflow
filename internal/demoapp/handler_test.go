package demoapp

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
)

const (
	testRequestID = "019b0000-0000-7000-8000-000000000101"
	testTraceID   = "019b0000-0000-7000-8000-000000000102"
)

func TestLoginEmitsOnlyMinimizedFailedAuthEvent(t *testing.T) {
	t.Parallel()
	sink := &captureSink{result: events.EnqueueAccepted}
	handler := newTestHandler(t, sink)
	request := gatewayRequest(http.MethodPost, "/login", "account=demo-user&password=synthetic-demo-input")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "demo-user") || strings.Contains(response.Body.String(), "synthetic-demo-input") {
		t.Fatalf("unsafe login response: status=%d body=%q", response.Code, response.Body.String())
	}
	event, count := sink.last()
	if count != 1 || event.SchemaVersion != events.AuthEventV1Schema || event.EventID != testEventID(1) ||
		event.GatewayRequestID != testRequestID || event.TraceID != testTraceID || event.SourceIP != "203.0.113.20" ||
		event.ServiceLabel != "demo-app" || event.RouteLabel != "login" || event.Outcome != events.AuthOutcomeFailed ||
		!strings.HasPrefix(event.AccountHash, "hmac-sha256:") || event.Validate() != nil {
		t.Fatalf("unexpected event: %+v count=%d", event, count)
	}
	printed := fmt.Sprintf("%+v %s", event, handler)
	if strings.Contains(printed, "demo-user") || strings.Contains(printed, "synthetic-demo-input") || strings.Contains(printed, "/login") {
		t.Fatalf("event or handler leaked login input/path: %s", printed)
	}
}

func TestAccountHashIsStableScopedAndKeyed(t *testing.T) {
	t.Parallel()
	one := newTestHandler(t, &captureSink{})
	two, err := New(Config{
		GatewayPeerCIDRs: []netip.Prefix{netip.MustParsePrefix("172.30.0.2/32")},
		AccountHashKey:   bytes.Repeat([]byte{2}, 32),
		Sink:             &captureSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := one.accountHash("demo-user")
	repeated := one.accountHash(strings.Join([]string{"demo", "user"}, "-"))
	if first != repeated || first == one.accountHash("demo-user-2") ||
		first == two.accountHash("demo-user") {
		t.Fatal("account HMAC is not stable, scoped, and keyed")
	}
}

func TestDirectOrSpoofedOriginRequestsFailBeforeBodyOrSink(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"outside peer", func(request *http.Request) { request.RemoteAddr = "172.30.0.3:40100" }},
		{"missing peer port", func(request *http.Request) { request.RemoteAddr = "172.30.0.2" }},
		{"spoofed forwarding chain", func(request *http.Request) { request.Header.Set("X-Forwarded-For", "203.0.113.20, 10.0.0.1") }},
		{"duplicate forwarded", func(request *http.Request) { request.Header.Add("X-Forwarded-For", "203.0.113.21") }},
		{"private source", func(request *http.Request) { request.Header.Set("X-Forwarded-For", "127.0.0.1") }},
		{"noncanonical source", func(request *http.Request) { request.Header.Set("X-Forwarded-For", "203.0.113.020") }},
		{"bad request ID", func(request *http.Request) { request.Header.Set("X-SentinelFlow-Request-ID", "spoofed") }},
		{"duplicate trace", func(request *http.Request) { request.Header.Add("X-SentinelFlow-Trace-ID", testTraceID) }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sink := &captureSink{}
			handler := newTestHandler(t, sink)
			request := gatewayRequest(http.MethodPost, "/login", "account=demo-user&password=synthetic-demo-input")
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden && response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", response.Code)
			}
			if _, count := sink.last(); count != 0 {
				t.Fatal("invalid request emitted auth event")
			}
		})
	}
}

func TestLoginBodyAndFieldBoundsFailClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		body        string
		contentType string
		path        string
	}{
		{"empty", "", "application/x-www-form-urlencoded", "/login"},
		{"unknown", "account=a&password=synthetic-demo-input&extra=x", "application/x-www-form-urlencoded", "/login"},
		{"duplicate", "account=a&account=b&password=synthetic-demo-input", "application/x-www-form-urlencoded", "/login"},
		{"wrong password", "account=a&password=real-looking", "application/x-www-form-urlencoded", "/login"},
		{"unsafe account", "account=user%40example.test&password=synthetic-demo-input", "application/x-www-form-urlencoded", "/login"},
		{"wrong type", "account=a&password=synthetic-demo-input", "application/json", "/login"},
		{"query", "account=a&password=synthetic-demo-input", "application/x-www-form-urlencoded", "/login?x=1"},
		{"oversize", strings.Repeat("x", maxLoginBodyBytes+1), "application/x-www-form-urlencoded", "/login"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sink := &captureSink{}
			handler := newTestHandler(t, sink)
			request := gatewayRequest(http.MethodPost, test.path, test.body)
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body=%q", response.Code, response.Body.String())
			}
			if _, count := sink.last(); count != 0 {
				t.Fatal("invalid body emitted auth event")
			}
		})
	}
}

func TestReadOnlyRoutesAndIntermittentFailure(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, &captureSink{})
	for _, path := range []string{"/", "/health", "/products", "/products/featured", "/account"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, gatewayRequest(http.MethodGet, path, ""))
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, response.Code)
		}
	}
	for index, want := range []int{http.StatusServiceUnavailable, http.StatusOK} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, gatewayRequest(http.MethodGet, "/demo/intermittent-error", ""))
		if response.Code != want {
			t.Fatalf("intermittent call %d status=%d want=%d", index, response.Code, want)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, gatewayRequest(http.MethodGet, "/.env", ""))
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), ".env") {
		t.Fatalf("suspicious path response = %d %q", response.Code, response.Body.String())
	}
}

func TestConcurrentLoginEventsRemainIndependent(t *testing.T) {
	t.Parallel()
	sink := &captureSink{result: events.EnqueueAccepted}
	var ids atomic.Uint64
	handler, err := New(Config{
		GatewayPeerCIDRs: []netip.Prefix{netip.MustParsePrefix("172.30.0.2/32")},
		AccountHashKey:   bytes.Repeat([]byte{1}, 32),
		Sink:             sink,
		Clock:            func() time.Time { return time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC) },
		NewID:            func() (string, error) { return testEventID(ids.Add(1)), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for index := range 40 {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := gatewayRequest(http.MethodPost, "/login", fmt.Sprintf("account=user-%d&password=synthetic-demo-input", index))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Errorf("status = %d", response.Code)
			}
		}(index)
	}
	wait.Wait()
	if _, count := sink.last(); count != 40 {
		t.Fatalf("events = %d", count)
	}
}

func TestConfigurationIsStrictAndDefensive(t *testing.T) {
	t.Parallel()
	valid := Config{
		GatewayPeerCIDRs: []netip.Prefix{netip.MustParsePrefix("172.30.0.2/32")},
		AccountHashKey:   bytes.Repeat([]byte{1}, 32),
		Sink:             &captureSink{},
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.Sink = nil },
		func(config *Config) { config.AccountHashKey = []byte("short") },
		func(config *Config) { config.GatewayPeerCIDRs = nil },
		func(config *Config) { config.GatewayPeerCIDRs = []netip.Prefix{netip.MustParsePrefix("172.30.0.1/24")} },
		func(config *Config) {
			config.GatewayPeerCIDRs = []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24"), netip.MustParsePrefix("172.30.0.2/32")}
		},
		func(config *Config) {
			config.GatewayPeerCIDRs = []netip.Prefix{netip.MustParsePrefix("2001:db8::/128")}
		},
	} {
		config := valid
		config.GatewayPeerCIDRs = append([]netip.Prefix(nil), valid.GatewayPeerCIDRs...)
		config.AccountHashKey = bytes.Clone(valid.AccountHashKey)
		mutate(&config)
		if _, err := New(config); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid config error = %v", err)
		}
	}
	handler, err := New(valid)
	if err != nil {
		t.Fatal(err)
	}
	valid.AccountHashKey[0] ^= 0xff
	valid.GatewayPeerCIDRs[0] = netip.MustParsePrefix("172.31.0.2/32")
	if handler.accountHash("demo") == (&Handler{accountHashKey: valid.AccountHashKey}).accountHash("demo") ||
		!handler.gatewayPeerAllowed("172.30.0.2:1") {
		t.Fatal("handler retained caller-mutable configuration")
	}
}

func newTestHandler(t *testing.T, sink AuthEventSink) *Handler {
	t.Helper()
	var sequence atomic.Uint64
	handler, err := New(Config{
		GatewayPeerCIDRs: []netip.Prefix{netip.MustParsePrefix("172.30.0.2/32")},
		AccountHashKey:   bytes.Repeat([]byte{1}, 32),
		Sink:             sink,
		Clock:            func() time.Time { return time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC) },
		NewID:            func() (string, error) { return testEventID(sequence.Add(1)), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func gatewayRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, "http://demo-app"+target, strings.NewReader(body))
	request.RemoteAddr = "172.30.0.2:40100"
	request.Header.Set("X-Forwarded-For", "203.0.113.20")
	request.Header.Set("X-SentinelFlow-Request-ID", testRequestID)
	request.Header.Set("X-SentinelFlow-Trace-ID", testTraceID)
	if body != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return request
}

func testEventID(value uint64) string {
	return fmt.Sprintf("019b0000-0000-7000-8000-%012x", value)
}

type captureSink struct {
	mu     sync.Mutex
	events []events.AuthEventV1
	result events.EnqueueResult
}

func (sink *captureSink) TryEnqueue(event events.AuthEventV1) events.EnqueueResult {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, event)
	return sink.result
}

func (sink *captureSink) last() (events.AuthEventV1, int) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		return events.AuthEventV1{}, 0
	}
	return sink.events[len(sink.events)-1], len(sink.events)
}
