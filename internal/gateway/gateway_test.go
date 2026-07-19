package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type captureSink struct {
	mu     sync.Mutex
	events []events.GatewayEvent
	result events.EnqueueResult
}

func (s *captureSink) TryEnqueue(event events.GatewayEvent) events.EnqueueResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return s.result
}

func (s *captureSink) all() []events.GatewayEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]events.GatewayEvent(nil), s.events...)
}

func testConfig(t *testing.T) Config {
	t.Helper()
	upstream, err := url.Parse("http://demo.internal:8081")
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		PublicHosts:           []string{"app.example.test"},
		ServiceLabel:          "demo-app",
		UpstreamURL:           upstream,
		UpstreamHost:          "demo.internal",
		OriginCIDRs:           []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")},
		MaxRequestTarget:      4096,
		MaxClassificationPath: 2048,
		MaxBodyBytes:          16,
		RequestTimeout:        50 * time.Millisecond,
		UpstreamTimeout:       50 * time.Millisecond,
		PathCatalogVersion:    "path-catalog-v1",
		LoginRoutePath:        "/login",
		LoginRouteLabel:       "login",
	}
}

func idSequence() func() (string, error) {
	ids := []string{
		"019b0000-0000-7000-8000-000000000001",
		"019b0000-0000-7000-8000-000000000002",
		"019b0000-0000-7000-8000-000000000003",
		"019b0000-0000-7000-8000-000000000004",
	}
	index := 0
	return func() (string, error) {
		if index >= len(ids) {
			return "", errors.New("test ID sequence exhausted")
		}
		value := ids[index]
		index++
		return value, nil
	}
}

func TestGatewayForwardsOnlySanitizedFixedOriginRequest(t *testing.T) {
	t.Parallel()
	sink := &captureSink{result: events.EnqueueDegraded}
	var observed *http.Request
	var observedBody string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		observed = request.Clone(context.Background())
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		observedBody = string(body)
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header: http.Header{
				"Content-Type": []string{"text/plain"},
				"Connection":   []string{"X-Origin-Hop"},
				"X-Origin-Hop": []string{"secret-hop"},
				"Trailer":      []string{"X-Origin-Trailer"},
			},
			Body:    io.NopCloser(strings.NewReader("created")),
			Trailer: http.Header{"X-Origin-Trailer": []string{"secret-trailer"}},
			Request: request,
		}, nil
	})
	clockValues := []time.Time{
		time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 18, 2, 0, 0, int(7*time.Millisecond), time.UTC),
	}
	clockIndex := 0
	gateway, err := New(testConfig(t), Dependencies{
		Sink: sink, Transport: transport, InstanceID: "019b0000-0000-7000-8000-000000000099",
		NewID: idSequence(), Clock: func() time.Time {
			value := clockValues[clockIndex]
			clockIndex++
			return value
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/login?credential=must-not-persist", strings.NewReader("hello"))
	request.Host = "APP.EXAMPLE.TEST."
	request.RemoteAddr = "[::ffff:203.0.113.20]:45000"
	request.Header.Set("Forwarded", "for=198.51.100.2")
	request.Header.Set("X-Forwarded-For", "198.51.100.3")
	request.Header.Set("X-SentinelFlow-Request-ID", "spoofed-request")
	request.Header.Set("X-SentinelFlow-Trace-ID", "spoofed-trace")
	request.Header.Set("X-Request-ID", "spoofed-generic")
	request.Header.Set("traceparent", "spoofed-w3c")
	request.Header.Set("Connection", "X-Remove-Me")
	request.Header.Set("X-Remove-Me", "hop-secret")
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated || recorder.Body.String() != "created" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("X-Origin-Hop") != "" || recorder.Header().Get("Trailer") != "" {
		t.Fatalf("response leaked hop/trailer headers: %#v", recorder.Header())
	}
	if observed == nil {
		t.Fatal("origin request was not observed")
	}
	if observed.URL.Scheme != "http" || observed.URL.Host != "demo.internal:8081" || observed.Host != "demo.internal" {
		t.Fatalf("dynamic origin: URL=%s host=%q", observed.URL, observed.Host)
	}
	if observed.URL.Path != "/login" || observed.URL.RawQuery != "credential=must-not-persist" || observedBody != "hello" {
		t.Fatalf("origin behavior changed: URL=%s body=%q", observed.URL, observedBody)
	}
	if got := observed.Header.Get("X-Forwarded-For"); got != "203.0.113.20" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
	if got := observed.Header.Get("Forwarded"); got != `for=203.0.113.20;host="app.example.test";proto=http` {
		t.Fatalf("Forwarded = %q", got)
	}
	if observed.Header.Get("X-Forwarded-Host") != "app.example.test" || observed.Header.Get("X-Forwarded-Proto") != "http" {
		t.Fatalf("trusted forwarding headers = %#v", observed.Header)
	}
	if observed.Header.Get("X-SentinelFlow-Request-ID") != "019b0000-0000-7000-8000-000000000001" ||
		observed.Header.Get("X-SentinelFlow-Trace-ID") != "019b0000-0000-7000-8000-000000000002" {
		t.Fatalf("generated IDs not propagated: %#v", observed.Header)
	}
	for _, name := range []string{"X-Request-ID", "Traceparent", "X-Remove-Me"} {
		if observed.Header.Get(name) != "" {
			t.Fatalf("untrusted header %s crossed boundary", name)
		}
	}

	captured := sink.all()
	if len(captured) != 1 {
		t.Fatalf("events = %d, want 1", len(captured))
	}
	event := captured[0]
	if err := event.Validate(); err != nil {
		t.Fatalf("event validation: %v", err)
	}
	if event.SourceIP != "203.0.113.20" || event.Host != "app.example.test" || event.RouteLabel != "login" ||
		event.SuspiciousPathID != events.SuspiciousPathNone || event.StatusCode != http.StatusCreated ||
		event.RequestBytes != 5 || event.ResponseBytes != 7 || event.LatencyMS != 7 {
		t.Fatalf("event = %#v", event)
	}
	if strings.Contains(event.IdempotencyKey, "credential") {
		t.Fatal("event retained query data")
	}
}

func TestGatewayStaticRejectionsNeverReachOrigin(t *testing.T) {
	t.Parallel()
	base := testConfig(t)
	tests := []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"http10", func(r *http.Request) { r.Proto = "HTTP/1.0"; r.ProtoMinor = 0 }, http.StatusHTTPVersionNotSupported},
		{"absolute-form", func(r *http.Request) { r.URL.Scheme = "http"; r.URL.Host = "evil.test" }, http.StatusBadRequest},
		{"connect", func(r *http.Request) { r.Method = http.MethodConnect }, http.StatusBadRequest},
		{"unknown-host", func(r *http.Request) { r.Host = "other.example.test" }, http.StatusMisdirectedRequest},
		{"ip-host", func(r *http.Request) { r.Host = "127.0.0.1" }, http.StatusBadRequest},
		{"unsupported-expect", func(r *http.Request) { r.Header.Set("Expect", "magic") }, http.StatusExpectationFailed},
		{"upgrade", func(r *http.Request) { r.Header.Set("Connection", "upgrade"); r.Header.Set("Upgrade", "websocket") }, http.StatusBadRequest},
		{"sensitive-connection-token", func(r *http.Request) { r.Header.Set("Connection", "X-Forwarded-For") }, http.StatusBadRequest},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"X-Late": nil} }, http.StatusBadRequest},
		{"encoded-slash", func(r *http.Request) { r.RequestURI = "/admin%2fsecret" }, http.StatusRequestURITooLong},
		{"encoded-backslash", func(r *http.Request) { r.RequestURI = "/admin%5Csecret" }, http.StatusRequestURITooLong},
		{"dot-segment", func(r *http.Request) { r.RequestURI = "/safe/%2e%2e/secret" }, http.StatusRequestURITooLong},
		{"malformed-query-escape", func(r *http.Request) { r.RequestURI = "/safe?x=%zz" }, http.StatusRequestURITooLong},
		{"encoded-query-control", func(r *http.Request) { r.RequestURI = "/safe?x=%0a" }, http.StatusRequestURITooLong},
		{"oversized-target", func(r *http.Request) { r.RequestURI = "/" + strings.Repeat("a", 4096) }, http.StatusRequestURITooLong},
		{"invalid-peer", func(r *http.Request) { r.RemoteAddr = "not-an-address" }, http.StatusBadRequest},
		{"ipv6-peer", func(r *http.Request) { r.RemoteAddr = "[2001:db8::1]:22" }, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			gateway, err := New(base, Dependencies{
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					called = true
					return nil, errors.New("must not be called")
				}),
				InstanceID: "019b0000-0000-7000-8000-000000000099",
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/safe", nil)
			request.Host = "app.example.test"
			request.RemoteAddr = "203.0.113.20:1234"
			test.mutate(request)
			recorder := httptest.NewRecorder()
			gateway.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
			if called {
				t.Fatal("rejected request reached origin")
			}
		})
	}
}

func TestGatewayBodyBoundsAndTimeout(t *testing.T) {
	t.Parallel()
	t.Run("declared length", func(t *testing.T) {
		sink := &captureSink{}
		called := false
		gateway, err := New(testConfig(t), Dependencies{Sink: sink, Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("must not be called")
		})})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", 17)))
		request.Host = "app.example.test"
		request.RemoteAddr = "203.0.113.20:1234"
		recorder := httptest.NewRecorder()
		gateway.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusRequestEntityTooLarge || called || len(sink.all()) != 1 {
			t.Fatalf("status=%d called=%v events=%d", recorder.Code, called, len(sink.all()))
		}
	})
	t.Run("unknown length", func(t *testing.T) {
		gateway, err := New(testConfig(t), Dependencies{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			_, err := io.ReadAll(request.Body)
			return nil, err
		})})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/upload", io.NopCloser(strings.NewReader(strings.Repeat("x", 17))))
		request.ContentLength = -1
		request.TransferEncoding = []string{"chunked"}
		request.Host = "app.example.test"
		request.RemoteAddr = "203.0.113.20:1234"
		recorder := httptest.NewRecorder()
		gateway.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d", recorder.Code)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		gateway, err := New(testConfig(t), Dependencies{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		})})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/slow", nil)
		request.Host = "app.example.test"
		request.RemoteAddr = "203.0.113.20:1234"
		recorder := httptest.NewRecorder()
		gateway.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusGatewayTimeout {
			t.Fatalf("status = %d", recorder.Code)
		}
	})
}

func TestGatewayHealthAndHTTPServerPolicy(t *testing.T) {
	t.Parallel()
	gateway, err := New(testConfig(t), Dependencies{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") }),
		Readiness: func(context.Context) error { return errors.New("origin unavailable") },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/health/live", http.StatusOK},
		{"/health/ready", http.StatusServiceUnavailable},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		recorder := httptest.NewRecorder()
		gateway.ServeHTTP(recorder, request)
		if recorder.Code != test.status {
			t.Fatalf("%s status = %d", test.path, recorder.Code)
		}
	}
	server := NewHTTPServer(":8080", gateway, 32768, 5*time.Second, 60*time.Second)
	if server.MaxHeaderBytes != 32768 || server.ReadHeaderTimeout != 5*time.Second || server.IdleTimeout != 60*time.Second {
		t.Fatalf("server bounds = %#v", server)
	}
	if server.TLSConfig == nil || len(server.TLSConfig.NextProtos) != 1 || server.TLSConfig.NextProtos[0] != "http/1.1" || server.TLSNextProto == nil {
		t.Fatalf("HTTP/2 was not explicitly disabled: %#v", server)
	}
}

func TestNormalizeHostAndPathCatalog(t *testing.T) {
	t.Parallel()
	hosts := []struct {
		input string
		tls   bool
		want  string
		ok    bool
	}{
		{"APP.Example.Test.", false, "app.example.test", true},
		{"app.example.test:80", false, "app.example.test", true},
		{"app.example.test:443", true, "app.example.test", true},
		{"app.example.test:8443", true, "app.example.test:8443", true},
		{"127.0.0.1", false, "", false},
		{"[::1]:443", true, "", false},
		{"app..example", false, "", false},
		{"user@app.example", false, "", false},
		{"app.example,evil.example", false, "", false},
		{"éxample.test", false, "", false},
	}
	for _, test := range hosts {
		got, err := normalizeRequestHost(test.input, test.tls)
		if (err == nil) != test.ok || got != test.want {
			t.Errorf("normalizeRequestHost(%q) = %q, %v", test.input, got, err)
		}
	}

	paths := []struct {
		input      string
		canonical  string
		suspicious events.SuspiciousPathID
		ok         bool
	}{
		{"/safe//%7euser?ignored=1", "/safe/~user", events.SuspiciousPathNone, true},
		{"/.ENV", "/.ENV", events.SuspiciousPathEnvFile, true},
		{"/wp-admin/setup", "/wp-admin/setup", events.SuspiciousPathWPAdmin, true},
		{"/files/db.BACKUP", "/files/db.BACKUP", events.SuspiciousPathBackupArchive, true},
		{"/%252e%252e/safe", "/%252e%252e/safe", events.SuspiciousPathNone, true},
		{"/a/%2e%2e/b", "", events.SuspiciousPathNone, false},
		{"/a%2fb", "", events.SuspiciousPathNone, false},
		{"/a\\b", "", events.SuspiciousPathNone, false},
	}
	for _, test := range paths {
		got, err := validateTarget(test.input, 4096, 2048)
		if (err == nil) != test.ok || got != test.canonical {
			t.Errorf("validateTarget(%q) = %q, %v", test.input, got, err)
			continue
		}
		if test.ok {
			_, suspicious := classifyPath(got, "/login", "login")
			if suspicious != test.suspicious {
				t.Errorf("classifyPath(%q) = %q", got, suspicious)
			}
		}
	}
}

type statusHistoryWriter struct {
	header   http.Header
	statuses []int
	body     strings.Builder
}

func (w *statusHistoryWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *statusHistoryWriter) WriteHeader(status int) { w.statuses = append(w.statuses, status) }

func (w *statusHistoryWriter) Write(payload []byte) (int, error) {
	if len(w.statuses) == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(payload)
}

func TestGatewaySuppressesUntrustedUpstreamInformationalResponses(t *testing.T) {
	t.Parallel()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if trace := httptrace.ContextClientTrace(request.Context()); trace != nil && trace.Got1xxResponse != nil {
			if err := trace.Got1xxResponse(http.StatusEarlyHints, textproto.MIMEHeader{"Link": {"</secret-path>; rel=preload"}}); err != nil {
				return nil, err
			}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    request,
		}, nil
	})
	gateway, err := New(testConfig(t), Dependencies{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/safe", nil)
	request.Host = "app.example.test"
	request.RemoteAddr = "203.0.113.20:1234"
	writer := &statusHistoryWriter{}
	gateway.ServeHTTP(writer, request)
	if len(writer.statuses) != 1 || writer.statuses[0] != http.StatusOK {
		t.Fatalf("upstream informational response crossed boundary: %v", writer.statuses)
	}
	if writer.Header().Get("Link") != "" || writer.body.String() != "ok" {
		t.Fatalf("unexpected response header/body: %#v %q", writer.Header(), writer.body.String())
	}
}
