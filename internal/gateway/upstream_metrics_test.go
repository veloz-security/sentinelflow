package gateway

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/observability"
)

const upstreamRoundTripMetric = "sentinelflow_gateway_upstream_round_trip_duration_seconds"

func metricSample(t *testing.T, output, name string) string {
	t.Helper()
	prefix := name + " "
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("missing metric sample %q", name)
	return ""
}

func TestGatewayUpstreamRoundTripMetricObservesSuccessAndErrorExactlyOnce(t *testing.T) {
	tests := []struct {
		name       string
		result     func(*http.Request) (*http.Response, error)
		wantStatus int
	}{
		{
			name: "success",
			result: func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("origin\n")),
					Request:    request,
				}, nil
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "transport error",
			result: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("synthetic origin unavailable")
			},
			wantStatus: http.StatusBadGateway,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metrics := observability.New(observability.Config{})
			var calls atomic.Int64
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls.Add(1)
				return test.result(request)
			})
			handler, err := New(testConfig(t), Dependencies{Transport: transport, Metrics: metrics})
			if err != nil {
				t.Fatal(err)
			}

			recorder := serveObservedRequest(handler, http.MethodGet, "/safe", "app.example.test", nil)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d, want %d", recorder.Code, test.wantStatus)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("origin RoundTrip calls=%d, want 1", got)
			}
			output := metricsText(t, metrics)
			if got := metricSample(t, output, upstreamRoundTripMetric+"_count"); got != "1" {
				t.Fatalf("upstream observations=%s, want 1", got)
			}
		})
	}
}

type gatedResponseBody struct {
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
	delivered bool
}

func newGatedResponseBody() *gatedResponseBody {
	return &gatedResponseBody{started: make(chan struct{}), release: make(chan struct{})}
}

func (b *gatedResponseBody) Read(destination []byte) (int, error) {
	b.startOnce.Do(func() { close(b.started) })
	<-b.release
	if b.delivered {
		return 0, io.EOF
	}
	b.delivered = true
	return copy(destination, "streamed-origin-body\n"), io.EOF
}

func (*gatedResponseBody) Close() error { return nil }

func TestGatewayUpstreamRoundTripMetricExcludesResponseBodyStreaming(t *testing.T) {
	metrics := observability.New(observability.Config{})
	body := newGatedResponseBody()
	handler, err := New(testConfig(t), Dependencies{
		Metrics: metrics,
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       body,
				Request:    request,
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan int, 1)
	go func() {
		done <- serveObservedRequest(handler, http.MethodGet, "/stream", "app.example.test", nil).Code
	}()
	select {
	case <-body.started:
	case <-time.After(2 * time.Second):
		t.Fatal("Gateway did not begin response-body streaming")
	}
	select {
	case status := <-done:
		t.Fatalf("Gateway completed before response-body release: %d", status)
	default:
	}

	before := metricsText(t, metrics)
	if got := metricSample(t, before, upstreamRoundTripMetric+"_count"); got != "1" {
		t.Fatalf("observation count before stream release=%s, want 1", got)
	}
	beforeSum := metricSample(t, before, upstreamRoundTripMetric+"_sum")
	time.Sleep(50 * time.Millisecond)
	duringSum := metricSample(t, metricsText(t, metrics), upstreamRoundTripMetric+"_sum")
	if duringSum != beforeSum {
		t.Fatalf("upstream duration changed while response body streamed: before=%s during=%s", beforeSum, duringSum)
	}

	close(body.release)
	select {
	case status := <-done:
		if status != http.StatusOK {
			t.Fatalf("status=%d, want 200", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Gateway did not complete after response-body release")
	}
	after := metricsText(t, metrics)
	if got := metricSample(t, after, upstreamRoundTripMetric+"_count"); got != "1" {
		t.Fatalf("observation count after stream=%s, want 1", got)
	}
	if afterSum := metricSample(t, after, upstreamRoundTripMetric+"_sum"); afterSum != beforeSum {
		t.Fatalf("upstream duration included response-body streaming: before=%s after=%s", beforeSum, afterSum)
	}
}

func TestGatewayUpstreamRoundTripMetricIsConcurrentAndPrivate(t *testing.T) {
	metrics := observability.New(observability.Config{})
	var calls atomic.Int64
	handler, err := New(testConfig(t), Dependencies{
		Metrics: metrics,
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
				Body:       http.NoBody,
				Request:    request,
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	const requests = 128
	var wait sync.WaitGroup
	var badStatus atomic.Int64
	for range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if recorder := serveObservedRequest(handler, http.MethodGet, "/private-path", "app.example.test", nil); recorder.Code != http.StatusNoContent {
				badStatus.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := badStatus.Load(); got != 0 {
		t.Fatalf("failed concurrent responses=%d", got)
	}
	if got := calls.Load(); got != requests {
		t.Fatalf("origin RoundTrip calls=%d, want %d", got, requests)
	}
	output := metricsText(t, metrics)
	if got := metricSample(t, output, upstreamRoundTripMetric+"_count"); got != "128" {
		t.Fatalf("upstream observations=%s, want 128", got)
	}
	for _, prohibited := range []string{
		"203.0.113.20", "app.example.test", "/private-path", "request-id-value", "trace-id-value",
		"session-id-value", "sha256:0123456789abcdef",
	} {
		if strings.Contains(output, prohibited) {
			t.Fatalf("metrics exposed prohibited request data %q", prohibited)
		}
	}
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, upstreamRoundTripMetric+"{") && !strings.HasPrefix(line, upstreamRoundTripMetric+"_") {
			continue
		}
		if strings.Contains(line, "{") && !strings.Contains(line, "{le=") {
			t.Fatalf("upstream metric has a non-bucket label: %q", line)
		}
	}
}

func TestUpstreamRoundTripInstrumentationWithNilMetricsDoesNotAffectForwarding(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://origin.example.test/safe", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := suppressInformationalTransport{
		base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody, Request: request}, nil
		}),
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d, want 204", response.StatusCode)
	}
}
