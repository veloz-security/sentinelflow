package observability

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func (c *testClock) set(value time.Time) {
	c.mu.Lock()
	c.now = value
	c.mu.Unlock()
}

func renderMetrics(t *testing.T, metrics *Metrics) string {
	t.Helper()
	var output strings.Builder
	if _, err := metrics.WriteOpenMetrics(&output); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func requireMetricLine(t *testing.T, output, expected string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if line == expected {
			return
		}
	}
	t.Fatalf("missing exact metric line %q", expected)
}

func TestOpenMetricsSnapshotIsExactDeterministicAndSecretSafe(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)}
	metrics := New(Config{Clock: clock.read})
	metrics.ObserveGatewayRequest(http.StatusNoContent, 3*time.Millisecond)
	metrics.ObserveGatewayRequest(http.StatusServiceUnavailable, 40*time.Millisecond)
	metrics.ObserveGatewayRequest(42, -time.Second)
	metrics.ObserveGatewayUpstreamRoundTrip(3 * time.Millisecond)
	metrics.ObserveGatewayUpstreamRoundTrip(40 * time.Millisecond)
	metrics.ObserveGatewayRejection(RejectHostNotAllowed)
	metrics.ObserveGatewayProxyError(ProxyErrorTimeout)
	metrics.SetEventQueue(7, 10)
	metrics.ObserveEnqueue(EnqueueAccepted)
	metrics.ObserveEnqueue(EnqueueDropped)
	metrics.ObserveBatchAttempt(BatchAccepted, BatchErrorNone, 9*time.Millisecond)
	metrics.ObserveBatchAttempt(BatchRetryableError, BatchErrorNetwork, 20*time.Millisecond)
	metrics.ObserveBatchRetry()
	metrics.SetSenderDegraded(true)
	clock.advance(2500 * time.Millisecond)
	metrics.ObserveCheckpoint(CheckpointLoad, CheckpointMissing)
	metrics.ObserveCheckpoint(CheckpointStore, CheckpointSuccess)
	metrics.SetLastAcknowledgedSequence(42)
	metrics.ObserveSequenceGap(GapQueueOverflow, 3)

	first := renderMetrics(t, metrics)
	second := renderMetrics(t, metrics)
	if first != second {
		t.Fatal("unchanged metrics rendered non-deterministically")
	}
	if !strings.HasSuffix(first, "# EOF\n") || strings.Contains(first, "\n\n") {
		t.Fatal("OpenMetrics termination or line ordering is invalid")
	}

	for _, line := range []string{
		`sentinelflow_gateway_requests_total{status_class="2xx"} 1`,
		`sentinelflow_gateway_requests_total{status_class="5xx"} 1`,
		`sentinelflow_gateway_requests_total{status_class="invalid"} 1`,
		`sentinelflow_gateway_request_duration_seconds_bucket{le="0.005000000"} 2`,
		`sentinelflow_gateway_request_duration_seconds_bucket{le="0.050000000"} 3`,
		`sentinelflow_gateway_request_duration_seconds_sum 0.043000000`,
		`sentinelflow_gateway_request_duration_seconds_count 3`,
		`sentinelflow_gateway_upstream_round_trip_duration_seconds_bucket{le="0.005000000"} 1`,
		`sentinelflow_gateway_upstream_round_trip_duration_seconds_bucket{le="0.050000000"} 2`,
		`sentinelflow_gateway_upstream_round_trip_duration_seconds_sum 0.043000000`,
		`sentinelflow_gateway_upstream_round_trip_duration_seconds_count 2`,
		`sentinelflow_gateway_proxy_errors_total{reason="timeout"} 1`,
		`sentinelflow_gateway_rejections_total{reason="host_not_allowed"} 1`,
		`sentinelflow_event_queue_depth 7`,
		`sentinelflow_event_queue_capacity 10`,
		`sentinelflow_event_enqueue_total{outcome="accepted"} 1`,
		`sentinelflow_event_enqueue_total{outcome="dropped"} 1`,
		`sentinelflow_event_dropped_total 1`,
		`sentinelflow_event_batch_attempts_total{outcome="accepted"} 1`,
		`sentinelflow_event_batch_attempts_total{outcome="retryable_error"} 1`,
		`sentinelflow_event_batch_errors_total{reason="network"} 1`,
		`sentinelflow_event_batch_retries_total 1`,
		`sentinelflow_event_batch_duration_seconds_sum 0.029000000`,
		`sentinelflow_event_sender_degraded 1`,
		`sentinelflow_event_sender_degraded_seconds_total 2.500000000`,
		`sentinelflow_event_checkpoint_operations_total{operation="load",outcome="missing"} 1`,
		`sentinelflow_event_checkpoint_operations_total{operation="store",outcome="success"} 1`,
		`sentinelflow_event_last_acknowledged_sequence 42`,
		`sentinelflow_event_sequence_gaps_total{cause="queue_overflow"} 1`,
		`sentinelflow_event_gap_records_total{cause="queue_overflow"} 3`,
	} {
		requireMetricLine(t, first, line)
	}

	families := []string{
		"sentinelflow_gateway_requests_total",
		"sentinelflow_gateway_request_duration_seconds",
		"sentinelflow_gateway_upstream_round_trip_duration_seconds",
		"sentinelflow_gateway_proxy_errors_total",
		"sentinelflow_gateway_rejections_total",
		"sentinelflow_gateway_active_connections",
		"sentinelflow_event_queue_depth",
		"sentinelflow_event_queue_capacity",
		"sentinelflow_event_enqueue_total",
		"sentinelflow_event_dropped_total",
		"sentinelflow_event_batch_attempts_total",
		"sentinelflow_event_batch_errors_total",
		"sentinelflow_event_batch_retries_total",
		"sentinelflow_event_batch_duration_seconds",
		"sentinelflow_event_sender_degraded",
		"sentinelflow_event_sender_degraded_seconds_total",
		"sentinelflow_event_checkpoint_operations_total",
		"sentinelflow_event_last_acknowledged_sequence",
		"sentinelflow_event_sequence_gaps_total",
		"sentinelflow_event_gap_records_total",
	}
	previous := -1
	for _, family := range families {
		position := strings.Index(first, "# HELP "+family+" ")
		if position <= previous {
			t.Fatalf("metric family %q is absent or out of order", family)
		}
		previous = position
	}

	for _, prohibited := range []string{
		"203.0.113.20", "app.example.test", "/login", "request-id", "trace-id", "account", "authorization", "cookie",
		"session-id", "sha256:0123456789abcdef",
	} {
		if strings.Contains(strings.ToLower(first), prohibited) {
			t.Fatalf("metrics exposed prohibited value %q", prohibited)
		}
	}
	allowedLabelNames := map[string]bool{
		"status_class": true, "le": true, "reason": true, "outcome": true, "operation": true, "cause": true,
	}
	for _, line := range strings.Split(first, "\n") {
		left := strings.IndexByte(line, '{')
		right := strings.IndexByte(line, '}')
		if left < 0 || right < left {
			continue
		}
		for _, pair := range strings.Split(line[left+1:right], ",") {
			name, _, found := strings.Cut(pair, "=")
			if !found || !allowedLabelNames[name] {
				t.Fatalf("unbounded or malformed metric label in %q", line)
			}
		}
	}
}

func TestMetricsHandlerIsExactPathReadOnlyAndDoesNotEchoInput(t *testing.T) {
	metrics := New(Config{})
	handler := metrics.Handler()

	request := httptest.NewRequest(http.MethodGet, "http://metrics.internal/metrics", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != openMetricsContentType ||
		recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasSuffix(recorder.Body.String(), "# EOF\n") {
		t.Fatalf("metrics response = %d %#v %q", recorder.Code, recorder.Header(), recorder.Body.String())
	}

	tests := []struct {
		name   string
		method string
		target string
		body   io.Reader
		status int
	}{
		{"query", http.MethodGet, "http://metrics.internal/metrics?source_ip=203.0.113.20", nil, http.StatusNotFound},
		{"empty-query", http.MethodGet, "http://metrics.internal/metrics?", nil, http.StatusNotFound},
		{"other-path", http.MethodGet, "http://metrics.internal/metrics/extra", nil, http.StatusNotFound},
		{"body", http.MethodGet, "http://metrics.internal/metrics", strings.NewReader("secret"), http.StatusNotFound},
		{"post", http.MethodPost, "http://metrics.internal/metrics", nil, http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, test.body)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
			if strings.Contains(recorder.Body.String(), "203.0.113.20") || strings.Contains(recorder.Body.String(), "secret") {
				t.Fatal("metrics error response echoed untrusted input")
			}
		})
	}
}

func TestHistogramSnapshotAndDegradedTotalRemainCoherent(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)}
	metrics := New(Config{Clock: clock.read})
	metrics.SetSenderDegraded(true)
	clock.advance(5 * time.Second)
	first := renderMetrics(t, metrics)
	requireMetricLine(t, first, "sentinelflow_event_sender_degraded_seconds_total 5.000000000")
	clock.set(time.Date(2026, 7, 18, 1, 59, 0, 0, time.UTC))
	second := renderMetrics(t, metrics)
	requireMetricLine(t, second, "sentinelflow_event_sender_degraded_seconds_total 5.000000000")
	metrics.SetSenderDegraded(false)
	requireMetricLine(t, renderMetrics(t, metrics), "sentinelflow_event_sender_degraded_seconds_total 5.000000000")

	for index := 0; index < 1000; index++ {
		metrics.ObserveGatewayRequest(http.StatusOK, time.Duration(index%100)*time.Millisecond)
		metrics.ObserveGatewayUpstreamRoundTrip(time.Duration(index%100) * time.Millisecond)
	}
	snapshot := metrics.requestLatency.snapshot()
	previous := uint64(0)
	for index, bucket := range snapshot.buckets {
		if bucket < previous || bucket > snapshot.count {
			t.Fatalf("incoherent cumulative histogram bucket[%d]=%d previous=%d count=%d", index, bucket, previous, snapshot.count)
		}
		previous = bucket
	}
	upstreamSnapshot := metrics.upstreamLatency.snapshot()
	if len(upstreamSnapshot.bounds) != len(snapshot.bounds) {
		t.Fatalf("upstream bounds=%d request bounds=%d", len(upstreamSnapshot.bounds), len(snapshot.bounds))
	}
	for index := range snapshot.bounds {
		if upstreamSnapshot.bounds[index] != snapshot.bounds[index] {
			t.Fatalf("upstream bound[%d]=%s request bound=%s", index, upstreamSnapshot.bounds[index], snapshot.bounds[index])
		}
	}
	if upstreamSnapshot.count != 1000 {
		t.Fatalf("upstream count=%d, want 1000", upstreamSnapshot.count)
	}
}

func TestMetricsConcurrentUpdatesAndConnectionTransitions(t *testing.T) {
	metrics := New(Config{})
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	metrics.ObserveConnectionState(left, http.StateNew)
	metrics.ObserveConnectionState(left, http.StateActive)
	metrics.ObserveConnectionState(left, http.StateActive)
	requireMetricLine(t, renderMetrics(t, metrics), "sentinelflow_gateway_active_connections 1")
	metrics.ObserveConnectionState(left, http.StateIdle)
	metrics.ObserveConnectionState(left, http.StateActive)
	metrics.ObserveConnectionState(left, http.StateClosed)
	requireMetricLine(t, renderMetrics(t, metrics), "sentinelflow_gateway_active_connections 0")
	// net.Conn does not require a comparable concrete type. Unsupported value
	// implementations are ignored instead of reaching a map-key panic.
	metrics.ObserveConnectionState(uncomparableConn{storage: []byte{1}}, http.StateActive)
	requireMetricLine(t, renderMetrics(t, metrics), "sentinelflow_gateway_active_connections 0")

	const workers = 32
	const iterations = 400
	var wait sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := 0; index < 100; index++ {
			_ = renderMetrics(t, metrics)
		}
	}()
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range iterations {
				metrics.ObserveGatewayRequest(http.StatusOK, time.Millisecond)
				metrics.ObserveGatewayUpstreamRoundTrip(time.Millisecond)
				metrics.ObserveGatewayRejection(RejectRequestTarget)
				metrics.ObserveGatewayProxyError(ProxyErrorUpstream)
				metrics.ObserveEnqueue(EnqueueAccepted)
				metrics.ObserveBatchAttempt(BatchAccepted, BatchErrorNone, time.Millisecond)
				metrics.ObserveCheckpoint(CheckpointStore, CheckpointSuccess)
				metrics.ObserveSequenceGap(GapRejectedBatch, 1)
			}
		}()
	}
	wait.Wait()
	<-done
	want := workers * iterations
	output := renderMetrics(t, metrics)
	for _, line := range []string{
		"sentinelflow_gateway_requests_total{status_class=\"2xx\"} " + decimal(want),
		"sentinelflow_gateway_upstream_round_trip_duration_seconds_count " + decimal(want),
		"sentinelflow_gateway_rejections_total{reason=\"request_target\"} " + decimal(want),
		"sentinelflow_gateway_proxy_errors_total{reason=\"upstream\"} " + decimal(want),
		"sentinelflow_event_enqueue_total{outcome=\"accepted\"} " + decimal(want),
		"sentinelflow_event_batch_attempts_total{outcome=\"accepted\"} " + decimal(want),
		"sentinelflow_event_checkpoint_operations_total{operation=\"store\",outcome=\"success\"} " + decimal(want),
		"sentinelflow_event_sequence_gaps_total{cause=\"rejected_batch\"} " + decimal(want),
		"sentinelflow_event_gap_records_total{cause=\"rejected_batch\"} " + decimal(want),
	} {
		requireMetricLine(t, output, line)
	}
}

type uncomparableConn struct{ storage []byte }

func (uncomparableConn) Read([]byte) (int, error)          { return 0, io.EOF }
func (uncomparableConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (uncomparableConn) Close() error                      { return nil }
func (uncomparableConn) LocalAddr() net.Addr               { return inertAddr("local") }
func (uncomparableConn) RemoteAddr() net.Addr              { return inertAddr("remote") }
func (uncomparableConn) SetDeadline(time.Time) error       { return nil }
func (uncomparableConn) SetReadDeadline(time.Time) error   { return nil }
func (uncomparableConn) SetWriteDeadline(time.Time) error  { return nil }

type inertAddr string

func (inertAddr) Network() string  { return "inert" }
func (a inertAddr) String() string { return string(a) }

func decimal(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic write failure") }

func TestWriteFailureAndNilInstrumentationAreHarmless(t *testing.T) {
	metrics := New(Config{})
	if _, err := metrics.WriteOpenMetrics(failingWriter{}); err == nil {
		t.Fatal("write failure was hidden")
	}
	var absent *Metrics
	absent.ObserveGatewayRequest(http.StatusOK, time.Second)
	absent.ObserveGatewayUpstreamRoundTrip(time.Second)
	absent.ObserveGatewayRejection(RejectProtocol)
	absent.ObserveGatewayProxyError(ProxyErrorUpstream)
	absent.ObserveConnectionState(nil, http.StateActive)
	absent.SetEventQueue(1, 1)
	absent.ObserveEnqueue(EnqueueDropped)
	absent.ObserveBatchAttempt(BatchPermanentError, BatchErrorInternal, time.Second)
	absent.ObserveBatchRetry()
	absent.SetSenderDegraded(true)
	absent.ObserveCheckpoint(CheckpointStore, CheckpointError)
	absent.SetLastAcknowledgedSequence(1)
	absent.ObserveSequenceGap(GapQueueOverflow, 1)
}
