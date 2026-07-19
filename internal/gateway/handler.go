package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/observability"
)

var (
	errBodyTooLarge              = errors.New("gateway request body exceeds the configured limit")
	errUnsupportedOriginResponse = errors.New("unsupported upstream informational response")
	methodRE                     = regexp.MustCompile(`^[A-Z]{1,16}$`)
	tokenRE                      = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)
)

// EventSink must return immediately. The Gateway never waits for persistence,
// analysis, HIL, or enforcement.
type EventSink interface {
	TryEnqueue(events.GatewayEvent) events.EnqueueResult
}

type Dependencies struct {
	Sink       EventSink
	Metrics    *observability.Metrics
	Transport  http.RoundTripper
	Readiness  func(context.Context) error
	Clock      func() time.Time
	NewID      func() (string, error)
	InstanceID string
	Resolver   Resolver
}

type Gateway struct {
	config      Config
	publicHosts map[string]string
	proxy       *httputil.ReverseProxy
	sink        EventSink
	readiness   func(context.Context) error
	clock       func() time.Time
	newID       func() (string, error)
	instanceID  string
	metrics     *observability.Metrics
}

type requestMetadata struct {
	peer      string
	host      string
	scheme    string
	requestID string
	traceID   string
}

type requestContextKey struct{}

func New(input Config, dependencies Dependencies) (*Gateway, error) {
	input.setDefaults()
	if err := input.validate(); err != nil {
		return nil, err
	}

	transport := dependencies.Transport
	readiness := dependencies.Readiness
	if transport == nil {
		originAddress := input.UpstreamURL.Host
		if input.UpstreamURL.Port() == "" {
			originAddress = net.JoinHostPort(input.UpstreamURL.Hostname(), "80")
		}
		policy, err := NewOriginPolicy(originAddress, input.OriginCIDRs, dependencies.Resolver)
		if err != nil {
			return nil, err
		}
		startupContext, cancel := context.WithTimeout(context.Background(), minDuration(input.UpstreamTimeout, 5*time.Second))
		err = policy.Check(startupContext)
		cancel()
		if err != nil {
			return nil, err
		}
		transport = NewOriginTransport(policy, input.UpstreamTimeout)
		readiness = policy.Check
	}
	if dependencies.Clock == nil {
		dependencies.Clock = func() time.Time { return time.Now().UTC() }
	}
	if dependencies.NewID == nil {
		dependencies.NewID = newUUID
	}
	if dependencies.InstanceID == "" {
		var err error
		dependencies.InstanceID, err = dependencies.NewID()
		if err != nil {
			return nil, errors.New("gateway: generate instance ID")
		}
	}
	if dependencies.Sink == nil {
		dependencies.Sink = discardSink{}
	}
	if dependencies.Metrics == nil {
		dependencies.Metrics = observability.New(observability.Config{})
	}

	publicHosts := make(map[string]string, len(input.PublicHosts))
	for _, host := range input.PublicHosts {
		publicHosts[host] = host
	}
	gateway := &Gateway{
		config:      input,
		publicHosts: publicHosts,
		sink:        dependencies.Sink,
		readiness:   readiness,
		clock:       dependencies.Clock,
		newID:       dependencies.NewID,
		instanceID:  dependencies.InstanceID,
		metrics:     dependencies.Metrics,
	}
	gateway.proxy = gateway.newProxy(transport)
	return gateway, nil
}

func (g *Gateway) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if g.serveHealth(writer, request) {
		return
	}
	metricsStartedAt := time.Now()
	recorder := &responseRecorder{ResponseWriter: writer}
	defer func() {
		g.metrics.ObserveGatewayRequest(recorder.Status(), time.Since(metricsStartedAt))
	}()
	startedAt := g.clock().UTC()

	if request.ProtoMajor != 1 || request.ProtoMinor != 1 {
		g.reject(observability.RejectProtocol)
		writeStaticError(recorder, http.StatusHTTPVersionNotSupported)
		return
	}
	if !methodRE.MatchString(request.Method) || request.Method == http.MethodConnect ||
		request.RequestURI == "*" || request.URL == nil || request.URL.IsAbs() || request.URL.Host != "" ||
		request.URL.Opaque != "" || !strings.HasPrefix(request.RequestURI, "/") {
		g.reject(observability.RejectTargetForm)
		writeStaticError(recorder, http.StatusBadRequest)
		return
	}
	requestID, err := g.newID()
	if err != nil {
		g.reject(observability.RejectIdentityGeneration)
		writeStaticError(recorder, http.StatusInternalServerError)
		return
	}
	traceID, err := g.newID()
	if err != nil {
		g.reject(observability.RejectIdentityGeneration)
		writeStaticError(recorder, http.StatusInternalServerError)
		return
	}
	peer, err := canonicalPeer(request.RemoteAddr)
	if err != nil {
		g.reject(observability.RejectPeerAddress)
		writeStaticError(recorder, http.StatusBadRequest)
		return
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	normalizedHost, err := normalizeRequestHost(request.Host, request.TLS != nil)
	if err != nil {
		g.reject(observability.RejectHostSyntax)
		writeStaticError(recorder, http.StatusBadRequest)
		return
	}
	matchedHost, allowed := g.publicHosts[normalizedHost]
	if !allowed {
		g.reject(observability.RejectHostNotAllowed)
		writeStaticError(recorder, http.StatusMisdirectedRequest)
		return
	}
	if code, reason := validateRequestHeaders(request); code != 0 {
		g.reject(reason)
		writeStaticError(recorder, code)
		return
	}
	comparisonPath, err := validateTarget(request.RequestURI, g.config.MaxRequestTarget, g.config.MaxClassificationPath)
	if err != nil {
		g.reject(observability.RejectRequestTarget)
		writeStaticError(recorder, http.StatusRequestURITooLong)
		return
	}
	route, suspicious := classifyPath(comparisonPath, g.config.LoginRoutePath, g.config.LoginRouteLabel)

	body := &boundedReadCloser{reader: request.Body, limit: g.config.MaxBodyBytes}
	if request.Body == nil {
		body.reader = http.NoBody
	}
	defer func() {
		g.emitEvent(eventDetails{
			startedAt:     startedAt,
			method:        request.Method,
			peer:          peer.String(),
			host:          matchedHost,
			route:         route,
			suspicious:    suspicious,
			requestID:     requestID,
			traceID:       traceID,
			requestBytes:  body.count.Load(),
			statusCode:    recorder.Status(),
			responseBytes: recorder.bytes.Load(),
		})
	}()

	if request.ContentLength > g.config.MaxBodyBytes {
		g.reject(observability.RejectBodyLimit)
		writeStaticError(recorder, http.StatusRequestEntityTooLarge)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), g.config.RequestTimeout)
	defer cancel()
	request = request.Clone(ctx)
	request.Header = request.Header.Clone()
	stripInboundHeaders(request.Header)
	request.Body = body
	request = request.WithContext(context.WithValue(request.Context(), requestContextKey{}, requestMetadata{
		peer: peer.String(), host: matchedHost, scheme: scheme, requestID: requestID, traceID: traceID,
	}))
	g.proxy.ServeHTTP(recorder, request)
}

func (g *Gateway) newProxy(transport http.RoundTripper) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		Transport: suppressInformationalTransport{base: transport, metrics: g.metrics},
		ErrorLog:  log.New(io.Discard, "", 0),
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			metadata, _ := proxyRequest.In.Context().Value(requestContextKey{}).(requestMetadata)
			proxyRequest.Out.URL.Scheme = g.config.UpstreamURL.Scheme
			proxyRequest.Out.URL.Host = g.config.UpstreamURL.Host
			proxyRequest.Out.Host = g.config.UpstreamHost
			stripInboundHeaders(proxyRequest.Out.Header)
			proxyRequest.Out.Header.Set("Forwarded", fmt.Sprintf(`for=%s;host="%s";proto=%s`, metadata.peer, metadata.host, metadata.scheme))
			proxyRequest.Out.Header.Set("X-Forwarded-For", metadata.peer)
			proxyRequest.Out.Header.Set("X-Forwarded-Host", metadata.host)
			proxyRequest.Out.Header.Set("X-Forwarded-Proto", metadata.scheme)
			proxyRequest.Out.Header.Set("X-SentinelFlow-Request-ID", metadata.requestID)
			proxyRequest.Out.Header.Set("X-SentinelFlow-Trace-ID", metadata.traceID)
		},
		ModifyResponse: func(response *http.Response) error {
			if response.StatusCode < 200 || response.StatusCode == http.StatusSwitchingProtocols {
				return errUnsupportedOriginResponse
			}
			stripConnectionHeaders(response.Header)
			stripHopHeaders(response.Header)
			response.Trailer = nil
			return nil
		},
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
		status := http.StatusBadGateway
		if body, ok := request.Body.(*boundedReadCloser); ok && body.exceeded.Load() {
			g.metrics.ObserveGatewayProxyError(observability.ProxyErrorBodyLimit)
			g.reject(observability.RejectBodyLimit)
			status = http.StatusRequestEntityTooLarge
		} else if errors.Is(proxyErr, context.DeadlineExceeded) || errors.Is(request.Context().Err(), context.DeadlineExceeded) {
			g.metrics.ObserveGatewayProxyError(observability.ProxyErrorTimeout)
			status = http.StatusGatewayTimeout
		} else if errors.Is(proxyErr, errUnsupportedOriginResponse) {
			g.metrics.ObserveGatewayProxyError(observability.ProxyErrorResponse)
		} else {
			g.metrics.ObserveGatewayProxyError(observability.ProxyErrorUpstream)
		}
		if recorder, ok := writer.(*responseRecorder); ok && recorder.committed.Load() {
			return
		}
		writeStaticError(writer, status)
	}
	return proxy
}

func (g *Gateway) serveHealth(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodGet || (request.URL.Path != "/health/live" && request.URL.Path != "/health/ready") {
		return false
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	if request.URL.Path == "/health/ready" && g.readiness != nil {
		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		err := g.readiness(ctx)
		cancel()
		if err != nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(writer, "not ready\n")
			return true
		}
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, "ok\n")
	return true
}

type eventDetails struct {
	startedAt     time.Time
	method        string
	peer          string
	host          string
	route         string
	suspicious    events.SuspiciousPathID
	requestID     string
	traceID       string
	requestBytes  int64
	statusCode    int
	responseBytes int64
}

func (g *Gateway) emitEvent(details eventDetails) {
	completedAt := g.clock().UTC()
	if completedAt.Before(details.startedAt) {
		completedAt = details.startedAt
	}
	eventID, err := g.newID()
	if err != nil {
		return
	}
	started, err := events.NewTimestamp(details.startedAt.UTC())
	if err != nil {
		return
	}
	completed, err := events.NewTimestamp(completedAt.UTC())
	if err != nil {
		return
	}
	hash := sha256.Sum256([]byte(events.GatewayHTTPV1Schema + "\n" + g.instanceID + "\n" + eventID))
	latency := completedAt.Sub(details.startedAt).Milliseconds()
	if latency < 0 {
		latency = 0
	}
	if latency > 30000 {
		latency = 30000
	}
	event := events.GatewayEvent{
		SchemaVersion:      events.GatewayHTTPV1Schema,
		EventID:            eventID,
		RequestID:          details.requestID,
		TraceID:            details.traceID,
		IdempotencyKey:     "sha256:" + hex.EncodeToString(hash[:]),
		StartedAt:          started,
		CompletedAt:        completed,
		SourceIP:           details.peer,
		Method:             details.method,
		Protocol:           "HTTP/1.1",
		RouteLabel:         details.route,
		PathCatalogVersion: g.config.PathCatalogVersion,
		SuspiciousPathID:   details.suspicious,
		Host:               details.host,
		ServiceLabel:       g.config.ServiceLabel,
		StatusCode:         details.statusCode,
		RequestBytes:       uint64(maxInt64(details.requestBytes, 0)),
		ResponseBytes:      uint64(maxInt64(details.responseBytes, 0)),
		LatencyMS:          uint64(latency),
	}
	if event.Validate() != nil {
		return
	}
	func() {
		defer func() { _ = recover() }()
		_ = g.sink.TryEnqueue(event)
	}()
}

func validateRequestHeaders(request *http.Request) (int, observability.GatewayRejectionReason) {
	if len(request.Trailer) != 0 || request.Header.Get("Trailer") != "" {
		return http.StatusBadRequest, observability.RejectTrailer
	}
	if len(request.TransferEncoding) > 1 || (len(request.TransferEncoding) == 1 && !strings.EqualFold(request.TransferEncoding[0], "chunked")) ||
		(len(request.TransferEncoding) != 0 && request.ContentLength >= 0) {
		return http.StatusBadRequest, observability.RejectTransferEncoding
	}
	expectations := request.Header.Values("Expect")
	if len(expectations) > 1 || (len(expectations) == 1 && !strings.EqualFold(strings.TrimSpace(expectations[0]), "100-continue")) {
		return http.StatusExpectationFailed, observability.RejectExpectation
	}
	tokens, err := connectionTokens(request.Header)
	if err != nil {
		return http.StatusBadRequest, observability.RejectConnectionHeader
	}
	if request.Header.Get("Upgrade") != "" {
		return http.StatusBadRequest, observability.RejectUpgrade
	}
	for _, token := range tokens {
		if strings.EqualFold(token, "upgrade") || securitySensitiveConnectionToken(token) {
			if strings.EqualFold(token, "upgrade") {
				return http.StatusBadRequest, observability.RejectUpgrade
			}
			return http.StatusBadRequest, observability.RejectConnectionHeader
		}
	}
	return 0, observability.RejectProtocol
}

func (g *Gateway) reject(reason observability.GatewayRejectionReason) {
	g.metrics.ObserveGatewayRejection(reason)
}

func securitySensitiveConnectionToken(token string) bool {
	switch strings.ToLower(token) {
	case "host", "connection", "content-length", "transfer-encoding", "trailer", "upgrade",
		"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
		"x-sentinelflow-request-id", "x-sentinelflow-trace-id", "x-request-id", "x-trace-id",
		"traceparent", "tracestate", "authorization", "proxy-authorization":
		return true
	default:
		return false
	}
}

func stripInboundHeaders(header http.Header) {
	stripConnectionHeaders(header)
	stripHopHeaders(header)
	for _, name := range []string{
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP",
		"X-SentinelFlow-Request-ID", "X-SentinelFlow-Trace-ID", "X-Request-ID", "X-Trace-ID",
		"Traceparent", "Tracestate",
	} {
		header.Del(name)
	}
}

func stripConnectionHeaders(header http.Header) {
	tokens, _ := connectionTokens(header)
	for _, token := range tokens {
		header.Del(textproto.CanonicalMIMEHeaderKey(token))
	}
}

func stripHopHeaders(header http.Header) {
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}

func connectionTokens(header http.Header) ([]string, error) {
	var result []string
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token == "" || !tokenRE.MatchString(token) {
				return nil, errors.New("invalid Connection token")
			}
			result = append(result, token)
		}
	}
	return result, nil
}

type boundedReadCloser struct {
	reader   io.ReadCloser
	limit    int64
	count    atomic.Int64
	exceeded atomic.Bool
}

func (b *boundedReadCloser) Read(buffer []byte) (int, error) {
	remaining := b.limit - b.count.Load()
	if remaining < 0 {
		b.exceeded.Store(true)
		return 0, errBodyTooLarge
	}
	if int64(len(buffer)) > remaining+1 {
		buffer = buffer[:remaining+1]
	}
	n, err := b.reader.Read(buffer)
	if int64(n) > remaining {
		if remaining > 0 {
			b.count.Add(remaining)
		}
		b.exceeded.Store(true)
		return int(remaining), errBodyTooLarge
	}
	b.count.Add(int64(n))
	return n, err
}

func (b *boundedReadCloser) Close() error { return b.reader.Close() }

type responseRecorder struct {
	http.ResponseWriter
	status    atomic.Int64
	bytes     atomic.Int64
	committed atomic.Bool
}

func (r *responseRecorder) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		r.ResponseWriter.WriteHeader(status)
		return
	}
	if !r.committed.CompareAndSwap(false, true) {
		return
	}
	r.status.Store(int64(status))
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(payload []byte) (int, error) {
	if !r.committed.Load() {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(payload)
	r.bytes.Add(int64(n))
	return n, err
}

func (r *responseRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *responseRecorder) Status() int {
	status := int(r.status.Load())
	if status == 0 {
		return http.StatusOK
	}
	return status
}

type discardSink struct{}

func (discardSink) TryEnqueue(events.GatewayEvent) events.EnqueueResult { return events.EnqueueDropped }

// valueStrippedContext keeps cancellation and deadlines while hiding the
// ReverseProxy's Got1xxResponse trace from the origin transport. Arbitrary
// upstream informational headers therefore cannot cross the edge boundary.
type valueStrippedContext struct{ context.Context }

func (valueStrippedContext) Value(any) any { return nil }

type suppressInformationalTransport struct {
	base    http.RoundTripper
	metrics *observability.Metrics
}

func (t suppressInformationalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(valueStrippedContext{request.Context()})
	startedAt := time.Now()
	response, err := t.base.RoundTrip(request)
	t.metrics.ObserveGatewayUpstreamRoundTrip(time.Since(startedAt))
	return response, err
}

func writeStaticError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, strings.ToLower(http.StatusText(status))+"\n")
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func maxInt64(value, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

// NewHTTPServer applies the frozen Go-parser bounds and disables automatic
// HTTP/2 configuration. TLS callers must use ListenAndServeTLS.
func NewHTTPServer(address string, handler http.Handler, maxHeaderBytes int, readHeaderTimeout, idleTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		MaxHeaderBytes:    maxHeaderBytes,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
}
