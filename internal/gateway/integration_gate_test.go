package gateway

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
)

const (
	gatePublicHost       = "app.example.test"
	gatePrivateAuthority = "172.30.0.10:8081"
)

type gateSinkMode uint32

const (
	gateSinkAccepted gateSinkMode = iota
	gateSinkDropped
	gateSinkPanics
)

type gateCountingSink struct {
	mode     atomic.Uint32
	accepted atomic.Uint64
	dropped  atomic.Uint64
}

func (s *gateCountingSink) TryEnqueue(events.GatewayEvent) events.EnqueueResult {
	switch gateSinkMode(s.mode.Load()) {
	case gateSinkDropped:
		s.dropped.Add(1)
		return events.EnqueueDropped
	case gateSinkPanics:
		panic("synthetic unavailable event sink")
	default:
		s.accepted.Add(1)
		return events.EnqueueAccepted
	}
}

func (s *gateCountingSink) reset(mode gateSinkMode) {
	s.accepted.Store(0)
	s.dropped.Store(0)
	s.mode.Store(uint32(mode))
}

type gateConnGauge struct {
	current atomic.Int64
	peak    atomic.Int64
}

func (g *gateConnGauge) observe(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		current := g.current.Add(1)
		for {
			peak := g.peak.Load()
			if current <= peak || g.peak.CompareAndSwap(peak, current) {
				break
			}
		}
	case http.StateHijacked, http.StateClosed:
		g.current.Add(-1)
	}
}

type gateOriginObservation struct {
	host             string
	path             string
	header           http.Header
	transferEncoding []string
	contentLength    int64
	request          int64
}

type gateOrigin struct {
	server       *http.Server
	listener     net.Listener
	url          string
	observations chan gateOriginObservation
	requests     atomic.Int64
	connections  gateConnGauge
}

func startGateOrigin(t *testing.T) *gateOrigin {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := &gateOrigin{
		listener:     listener,
		url:          "http://" + listener.Addr().String(),
		observations: make(chan gateOriginObservation, 32),
	}
	origin.server = &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       10 * time.Second,
		ConnState:         origin.connections.observe,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.Copy(io.Discard, io.LimitReader(request.Body, DefaultMaxBodyBytes+1))
			sequence := origin.requests.Add(1)
			observation := gateOriginObservation{
				host:             request.Host,
				path:             request.URL.RequestURI(),
				header:           request.Header.Clone(),
				transferEncoding: append([]string(nil), request.TransferEncoding...),
				contentLength:    request.ContentLength,
				request:          sequence,
			}
			select {
			case origin.observations <- observation:
			default:
			}
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.Header().Set("X-SentinelFlow-Synthetic-Origin", "v1")
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, "ok\n")
		}),
	}
	done := make(chan error, 1)
	go func() { done <- origin.server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = origin.server.Shutdown(ctx)
		if serveErr := <-done; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("origin server: %v", serveErr)
		}
	})
	return origin
}

// newGateOriginTransport maps the contract-required RFC1918 authority to a
// process-local origin. It is deliberately test-only: the requested authority
// must remain the one frozen private target, while no host route or firewall is
// changed by the gate.
func newGateOriginTransport(t *testing.T, origin *gateOrigin, maxConnections int) *http.Transport {
	t.Helper()
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   false,
		DisableCompression:  true,
		MaxIdleConns:        maxConnections,
		MaxIdleConnsPerHost: maxConnections,
		MaxConnsPerHost:     maxConnections,
		IdleConnTimeout:     10 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" {
				return nil, errors.New("synthetic origin received a non-TCP dial")
			}
			if address != gatePrivateAuthority {
				return nil, errors.New("synthetic origin rejected a dynamic authority")
			}
			return dialer.DialContext(ctx, "tcp4", origin.listener.Addr().String())
		},
	}
}

func gateConfig(t *testing.T) Config {
	t.Helper()
	upstream, err := url.Parse("http://" + gatePrivateAuthority)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		PublicHosts:           []string{gatePublicHost},
		ServiceLabel:          "demo-app",
		UpstreamURL:           upstream,
		UpstreamHost:          "demo.internal",
		OriginCIDRs:           []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")},
		MaxRequestTarget:      DefaultMaxRequestTargetBytes,
		MaxClassificationPath: DefaultMaxPathBytes,
		MaxBodyBytes:          DefaultMaxBodyBytes,
		RequestTimeout:        5 * time.Second,
		UpstreamTimeout:       5 * time.Second,
		PathCatalogVersion:    "path-catalog-v1",
		LoginRoutePath:        "/login",
		LoginRouteLabel:       "login",
	}
}

type gateServer struct {
	server      *http.Server
	listener    net.Listener
	url         string
	connections gateConnGauge
}

func startGateServer(t *testing.T, handler http.Handler) *gateServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := NewHTTPServer(listener.Addr().String(), handler, DefaultMaxHeaderBytes, 5*time.Second, 60*time.Second)
	result := &gateServer{server: server, listener: listener, url: "http://" + listener.Addr().String()}
	server.ConnState = result.connections.observe
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		if serveErr := <-done; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("gateway server: %v", serveErr)
		}
	})
	return result
}

func rawGatewayExchange(t *testing.T, address, request string) *http.Response {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, request); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = connection.Close()
		t.Fatalf("read raw response: %v", err)
	}
	t.Cleanup(func() {
		_ = response.Body.Close()
		_ = connection.Close()
	})
	return response
}

func TestGatewayTCPBoundaryRejectsAmbiguityAndRegeneratesIdentity(t *testing.T) {
	origin := startGateOrigin(t)
	transport := newGateOriginTransport(t, origin, 8)
	t.Cleanup(transport.CloseIdleConnections)
	sink := &gateCountingSink{}
	handler, err := New(gateConfig(t), Dependencies{Sink: sink, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	server := startGateServer(t, handler)

	valid := "GET /login?synthetic_case=identity HTTP/1.1\r\n" +
		"Host: APP.EXAMPLE.TEST.\r\n" +
		"Forwarded: for=198.51.100.9\r\n" +
		"X-Forwarded-For: 198.51.100.10\r\n" +
		"X-SentinelFlow-Request-ID: forged-request\r\n" +
		"X-SentinelFlow-Trace-ID: forged-trace\r\n" +
		"Connection: X-Synthetic-Hop, close\r\n" +
		"X-Synthetic-Hop: must-not-cross\r\n\r\n"
	response := rawGatewayExchange(t, server.listener.Addr().String(), valid)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("valid response status = %d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok\n" {
		t.Fatalf("valid response body = %q, %v", body, err)
	}

	select {
	case observed := <-origin.observations:
		if observed.host != "demo.internal" || observed.path != "/login?synthetic_case=identity" {
			t.Fatalf("origin target changed: host=%q path=%q", observed.host, observed.path)
		}
		if got := observed.header.Get("X-Forwarded-For"); got != "127.0.0.1" {
			t.Fatalf("canonical peer = %q", got)
		}
		if got := observed.header.Get("Forwarded"); got != `for=127.0.0.1;host="app.example.test";proto=http` {
			t.Fatalf("Forwarded = %q", got)
		}
		if observed.header.Get("X-Forwarded-Host") != gatePublicHost || observed.header.Get("X-Forwarded-Proto") != "http" {
			t.Fatalf("regenerated forwarding headers = %#v", observed.header)
		}
		requestID := observed.header.Get("X-SentinelFlow-Request-ID")
		traceID := observed.header.Get("X-SentinelFlow-Trace-ID")
		if requestID == "" || traceID == "" || requestID == "forged-request" || traceID == "forged-trace" {
			t.Fatalf("request/trace identity was not regenerated: request=%q trace=%q", requestID, traceID)
		}
		if observed.header.Get("X-Synthetic-Hop") != "" {
			t.Fatal("connection-nominated hop header crossed the Gateway")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("private origin did not receive the valid request")
	}

	originCount := origin.requests.Load()
	rejected := []struct {
		name    string
		request string
		status  int
	}{
		{
			name:    "absolute form",
			request: "GET http://evil.example/synthetic HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
			status:  http.StatusBadRequest,
		},
		{
			name:    "conflicting content length",
			request: "POST /upload HTTP/1.1\r\nHost: app.example.test\r\nContent-Length: 4\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde",
			status:  http.StatusBadRequest,
		},
		{
			name:    "unsupported expect",
			request: "POST /upload HTTP/1.1\r\nHost: app.example.test\r\nExpect: synthetic\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			status:  http.StatusExpectationFailed,
		},
		{
			name:    "declared body over limit",
			request: "POST /upload HTTP/1.1\r\nHost: app.example.test\r\nContent-Length: 10485761\r\nConnection: close\r\n\r\n",
			status:  http.StatusRequestEntityTooLarge,
		},
		{
			name:    "request target over limit",
			request: "GET /" + strings.Repeat("a", DefaultMaxRequestTargetBytes) + " HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
			status:  http.StatusRequestURITooLong,
		},
	}
	for _, test := range rejected {
		t.Run(test.name, func(t *testing.T) {
			response := rawGatewayExchange(t, server.listener.Addr().String(), test.request)
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
		})
	}

	// Go net/http is the sole framing parser. For this input it removes the
	// conflicting Content-Length and exposes one unambiguous chunked request;
	// the Gateway must not reinterpret it or create a second origin request.
	normalized := "POST /upload HTTP/1.1\r\nHost: app.example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0\r\n\r\n"
	response = rawGatewayExchange(t, server.listener.Addr().String(), normalized)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("safely normalized framing status = %d", response.StatusCode)
	}
	select {
	case observed := <-origin.observations:
		if len(observed.transferEncoding) != 1 || observed.transferEncoding[0] != "chunked" ||
			observed.contentLength != -1 || observed.header.Get("Content-Length") != "" {
			t.Fatalf("origin framing was not normalized once: TE=%v CL=%d header=%q",
				observed.transferEncoding, observed.contentLength, observed.header.Get("Content-Length"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("safely normalized request did not reach the origin exactly once")
	}

	oversized := "GET / HTTP/1.1\r\nHost: app.example.test\r\nX-Synthetic-Large: " + strings.Repeat("a", 40*1024) + "\r\nConnection: close\r\n\r\n"
	response = rawGatewayExchange(t, server.listener.Addr().String(), oversized)
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized header status = %d", response.StatusCode)
	}
	if origin.requests.Load() != originCount+1 {
		t.Fatalf("rejected or normalized traffic origin count: before=%d after=%d", originCount, origin.requests.Load())
	}
	if sink.accepted.Load() != 3 || sink.dropped.Load() != 0 {
		t.Fatalf("event sink accepted=%d dropped=%d", sink.accepted.Load(), sink.dropped.Load())
	}
}

func TestGatewayEventSinkFailureNeverBlocksForwarding(t *testing.T) {
	origin := startGateOrigin(t)
	transport := newGateOriginTransport(t, origin, 4)
	t.Cleanup(transport.CloseIdleConnections)
	sink := &gateCountingSink{}
	sink.reset(gateSinkDropped)
	handler, err := New(gateConfig(t), Dependencies{Sink: sink, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	request := httptestRequest(http.MethodGet, "/safe", nil)
	recorder := newGateRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK || recorder.body.String() != "ok\n" || sink.dropped.Load() != 1 {
		t.Fatalf("dropped sink changed forwarding: status=%d body=%q drops=%d", recorder.status, recorder.body.String(), sink.dropped.Load())
	}

	sink.reset(gateSinkPanics)
	request = httptestRequest(http.MethodGet, "/safe", nil)
	recorder = newGateRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK || recorder.body.String() != "ok\n" {
		t.Fatalf("panicking sink changed forwarding: status=%d body=%q", recorder.status, recorder.body.String())
	}
}

type gateRecorder struct {
	header http.Header
	body   strings.Builder
	status int
}

func newGateRecorder() *gateRecorder { return &gateRecorder{header: make(http.Header)} }

func (r *gateRecorder) Header() http.Header { return r.header }

func (r *gateRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *gateRecorder) Write(payload []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(payload)
}

func httptestRequest(method, target string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, target, body)
	request.Host = gatePublicHost
	request.RemoteAddr = "203.0.113.20:40000"
	request.Proto = "HTTP/1.1"
	request.ProtoMajor = 1
	request.ProtoMinor = 1
	return request
}
