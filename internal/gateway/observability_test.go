package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devwooops/sentinelflow/internal/observability"
)

func metricsText(t *testing.T, metrics *observability.Metrics) string {
	t.Helper()
	var output strings.Builder
	if _, err := metrics.WriteOpenMetrics(&output); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func serveObservedRequest(gateway *Gateway, method, target, host string, body io.Reader) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, body)
	request.Host = host
	request.RemoteAddr = "203.0.113.20:42000"
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	return recorder
}

func TestGatewayMetricsCoverForwardingRejectionsAndProxyFailuresWithoutPublicMetricsRoute(t *testing.T) {
	metrics := observability.New(observability.Config{})
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/upstream-error":
			return nil, errors.New("synthetic upstream unavailable")
		case "/upstream-timeout":
			return nil, context.DeadlineExceeded
		case "/upstream-response-error":
			return &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("unsupported")),
				Request:    request,
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("origin-response")),
				Request:    request,
			}, nil
		}
	})
	handler, err := New(testConfig(t), Dependencies{Transport: transport, Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}

	if recorder := serveObservedRequest(handler, http.MethodGet, "/safe", "app.example.test", nil); recorder.Code != http.StatusNoContent {
		t.Fatalf("safe status = %d", recorder.Code)
	}
	publicMetrics := serveObservedRequest(handler, http.MethodGet, "/metrics", "app.example.test", nil)
	if publicMetrics.Code != http.StatusNoContent || strings.Contains(publicMetrics.Header().Get("Content-Type"), "openmetrics") ||
		strings.Contains(publicMetrics.Body.String(), "sentinelflow_gateway_requests") {
		t.Fatalf("public /metrics was not treated as ordinary protected traffic: %d %#v %q",
			publicMetrics.Code, publicMetrics.Header(), publicMetrics.Body.String())
	}
	if recorder := serveObservedRequest(handler, http.MethodGet, "/safe", "other.example.test", nil); recorder.Code != http.StatusMisdirectedRequest {
		t.Fatalf("host rejection status = %d", recorder.Code)
	}
	if recorder := serveObservedRequest(handler, http.MethodPost, "/upload", "app.example.test", strings.NewReader("0123456789abcdefg")); recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body rejection status = %d", recorder.Code)
	}
	if recorder := serveObservedRequest(handler, http.MethodGet, "/upstream-error", "app.example.test", nil); recorder.Code != http.StatusBadGateway {
		t.Fatalf("upstream status = %d", recorder.Code)
	}
	if recorder := serveObservedRequest(handler, http.MethodGet, "/upstream-timeout", "app.example.test", nil); recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("timeout status = %d", recorder.Code)
	}
	if recorder := serveObservedRequest(handler, http.MethodGet, "/upstream-response-error", "app.example.test", nil); recorder.Code != http.StatusBadGateway {
		t.Fatalf("response validation status = %d", recorder.Code)
	}

	// Health checks are readiness probes, not protected-traffic request metrics.
	if recorder := serveObservedRequest(handler, http.MethodGet, "/health/live", "untrusted.invalid", nil); recorder.Code != http.StatusOK {
		t.Fatalf("health status = %d", recorder.Code)
	}

	output := metricsText(t, metrics)
	for _, expected := range []string{
		`sentinelflow_gateway_requests_total{status_class="2xx"} 2`,
		`sentinelflow_gateway_requests_total{status_class="4xx"} 2`,
		`sentinelflow_gateway_requests_total{status_class="5xx"} 3`,
		`sentinelflow_gateway_rejections_total{reason="host_not_allowed"} 1`,
		`sentinelflow_gateway_rejections_total{reason="body_limit"} 1`,
		`sentinelflow_gateway_proxy_errors_total{reason="upstream"} 1`,
		`sentinelflow_gateway_proxy_errors_total{reason="timeout"} 1`,
		`sentinelflow_gateway_proxy_errors_total{reason="response"} 1`,
	} {
		if !strings.Contains(output, expected+"\n") {
			t.Fatalf("missing exact metric %q", expected)
		}
	}
	for _, prohibited := range []string{"203.0.113.20", "app.example.test", "/upstream-error", "/metrics"} {
		if strings.Contains(output, prohibited) {
			t.Fatalf("Gateway metrics exposed request-derived value %q", prohibited)
		}
	}
}

func TestGatewayOmittedMetricsDependencyInstallsSafePrivateCollector(t *testing.T) {
	handler, err := New(testConfig(t), Dependencies{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("origin\n")),
			Request:    request,
		}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if handler.metrics == nil {
		t.Fatal("omitted metrics dependency remained nil")
	}
	recorder := serveObservedRequest(handler, http.MethodGet, "/metrics", "app.example.test", nil)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "origin\n" ||
		strings.Contains(recorder.Body.String(), "sentinelflow_gateway_requests") {
		t.Fatalf("omitted collector changed public forwarding: %d %q", recorder.Code, recorder.Body.String())
	}
	if output := metricsText(t, handler.metrics); !strings.Contains(output, `sentinelflow_gateway_requests_total{status_class="2xx"} 1`+"\n") {
		t.Fatal("installed collector did not observe the forwarded request")
	}
}
