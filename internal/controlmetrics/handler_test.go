package controlmetrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type collectorFunc func(context.Context) ([]Sample, error)

func (f collectorFunc) Collect(ctx context.Context) ([]Sample, error) { return f(ctx) }

func TestHandlerServesOnlyExactBoundedMetrics(t *testing.T) {
	t.Parallel()
	handler, err := Handler(collectorFunc(func(context.Context) ([]Sample, error) {
		return []Sample{
			{Name: "sentinelflow_control_ai_failures_5m", Value: 2},
			{Name: "sentinelflow_control_analysis_success_retained", Label1Name: "provider", Label1Value: "openai_responses", Value: 7},
		}, nil
	}), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://metrics.internal/metrics", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(response.Body.String(), `sentinelflow_control_analysis_success_retained{provider="openai_responses"} 7`) ||
		!strings.HasSuffix(response.Body.String(), "# EOF\n") {
		t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
	for _, rawURL := range []string{"/", "/metrics?x=1", "/metrics/"} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, rawURL, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d", rawURL, response.Code)
		}
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("post status=%d", response.Code)
	}
}

func TestHandlerHealthIsExactAndDoesNotQueryDatabase(t *testing.T) {
	t.Parallel()
	queries := 0
	handler, err := Handler(collectorFunc(func(context.Context) ([]Sample, error) {
		queries++
		return nil, errors.New("must not be called")
	}), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil))
	if response.Code != http.StatusOK || response.Body.String() != "ok\n" || queries != 0 {
		t.Fatalf("status=%d body=%q queries=%d", response.Code, response.Body.String(), queries)
	}
	for _, rawURL := range []string{"/health/", "/health?probe=1"} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, rawURL, nil))
		if response.Code != http.StatusNotFound || queries != 0 {
			t.Fatalf("%s status=%d queries=%d", rawURL, response.Code, queries)
		}
	}
}

func TestHandlerFailsClosedBeforeWritingOnDatabaseErrorTimeoutOrUnknownSeries(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		collector Collector
	}{
		{name: "database", collector: collectorFunc(func(context.Context) ([]Sample, error) {
			return nil, errors.New("database-secret")
		})},
		{name: "unknown", collector: collectorFunc(func(context.Context) ([]Sample, error) {
			return []Sample{{Name: "request_derived_metric", Label1Name: "ip", Label1Value: "192.0.2.1", Value: 1}}, nil
		})},
		{name: "timeout", collector: collectorFunc(func(ctx context.Context) ([]Sample, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			timeout := time.Second
			if test.name == "timeout" {
				timeout = 100 * time.Millisecond
			}
			handler, err := Handler(test.collector, timeout)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "database-secret") || strings.Contains(response.Body.String(), "192.0.2.1") {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestSampleContractsRejectUnboundedLabelsAndValues(t *testing.T) {
	t.Parallel()
	valid := Sample{Name: "sentinelflow_control_outbox_jobs", Label1Name: "kind", Label1Value: "dispatch_add", Label2Name: "state", Label2Value: "pending", Value: 1}
	if !validSample(valid) {
		t.Fatal("valid fixed sample rejected")
	}
	for _, mutation := range []func(*Sample){
		func(sample *Sample) { sample.Label1Value = "request-derived" },
		func(sample *Sample) { sample.Label2Name = "actor" },
		func(sample *Sample) { sample.Value = -1 },
		func(sample *Sample) { sample.Name = "sentinelflow_incident_id" },
	} {
		candidate := valid
		mutation(&candidate)
		if validSample(candidate) {
			t.Fatalf("unsafe sample accepted: %+v", candidate)
		}
	}
}
