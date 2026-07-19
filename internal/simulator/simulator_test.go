package simulator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFrozenScenarioPlansAndSafeShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		scenario Scenario
		shape    ExpectedShape
	}{
		{ScenarioNormal, ExpectedShape{
			ExpectedClassification: "none", GatewayRequestCount: 8, BrowseRequestCount: 5,
			LoginFailureCount: 1, DistinctAccountCount: 1, SuspiciousPathIDs: []string{},
			IntermittentErrorRequests: 2,
		}},
		{ScenarioCredentialStuffing, ExpectedShape{
			ExpectedClassification: "credential_stuffing", GatewayRequestCount: 20,
			LoginFailureCount: 20, DistinctAccountCount: 8, SuspiciousPathIDs: []string{}, BoundaryWindowSeconds: 300,
		}},
		{ScenarioBruteForce, ExpectedShape{
			ExpectedClassification: "brute_force", GatewayRequestCount: 10,
			LoginFailureCount: 10, DistinctAccountCount: 1, SuspiciousPathIDs: []string{}, BoundaryWindowSeconds: 60,
		}},
		{ScenarioPathScan, ExpectedShape{
			ExpectedClassification: "path_scan", GatewayRequestCount: 8,
			SuspiciousPathIDs: []string{
				"admin_console", "env_file", "git_config", "wp_admin", "phpmyadmin", "server_status", "actuator_env", "backup_archive",
			},
			BoundaryWindowSeconds: 60,
		}},
		{ScenarioRequestBurst, ExpectedShape{
			ExpectedClassification: "request_burst", GatewayRequestCount: 120,
			BrowseRequestCount: 120, SuspiciousPathIDs: []string{}, BoundaryWindowSeconds: 10,
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.scenario), func(t *testing.T) {
			t.Parallel()
			first, err := BuildPlan(test.scenario, DefaultSeed)
			if err != nil {
				t.Fatal(err)
			}
			second, err := BuildPlan(test.scenario, DefaultSeed)
			if err != nil {
				t.Fatal(err)
			}
			if first.RequestCount() != test.shape.GatewayRequestCount || first.Digest() == "" ||
				first.Digest() != second.Digest() || !reflect.DeepEqual(first.requests, second.requests) ||
				!reflect.DeepEqual(first.ExpectedShape(), test.shape) {
				t.Fatalf("same-seed plan or shape is not deterministic")
			}
			changed, err := BuildPlan(test.scenario, DefaultSeed+1)
			if err != nil {
				t.Fatal(err)
			}
			if changed.Digest() == first.Digest() {
				t.Fatal("changed seed did not produce a distinct run marker")
			}
			seedChangesPayload := test.scenario == ScenarioNormal || test.scenario == ScenarioCredentialStuffing ||
				test.scenario == ScenarioBruteForce
			if seedChangesPayload == reflect.DeepEqual(first.requests, changed.requests) {
				t.Fatal("changed-seed payload behavior drifted")
			}

			printed := first.String() + " " + fmt.Sprint(first.ExpectedShape())
			assertPrivateValuesAbsent(t, printed, "")
		})
	}

	pathPlan, err := BuildPlan(ScenarioPathScan, DefaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	copyShape := pathPlan.ExpectedShape()
	copyShape.SuspiciousPathIDs[0] = "mutated"
	if pathPlan.ExpectedShape().SuspiciousPathIDs[0] == "mutated" {
		t.Fatal("ExpectedShape returned mutable plan state")
	}
}

func TestFrozenThresholdRequestShapes(t *testing.T) {
	t.Parallel()

	stuffing, err := BuildPlan(ScenarioCredentialStuffing, 5)
	if err != nil {
		t.Fatal(err)
	}
	stuffingAccounts := make(map[string]int)
	for _, request := range stuffing.requests {
		values, parseErr := url.ParseQuery(request.body)
		if parseErr != nil || request.method != http.MethodPost || request.path != "/login" ||
			request.acceptedStatusCodes != ([2]int{http.StatusUnauthorized}) {
			t.Fatal("credential-stuffing request contract drifted")
		}
		stuffingAccounts[values.Get("account")]++
		if values.Get("password") != "synthetic-demo-input" || len(values) != 2 {
			t.Fatal("credential-stuffing synthetic form contract drifted")
		}
	}
	if len(stuffing.requests) != 20 || len(stuffingAccounts) != 8 {
		t.Fatalf("credential-stuffing boundary = %d events/%d accounts", len(stuffing.requests), len(stuffingAccounts))
	}

	brute, err := BuildPlan(ScenarioBruteForce, 5)
	if err != nil {
		t.Fatal(err)
	}
	bruteAccounts := make(map[string]struct{})
	for _, request := range brute.requests {
		values, parseErr := url.ParseQuery(request.body)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		bruteAccounts[values.Get("account")] = struct{}{}
	}
	if len(brute.requests) != 10 || len(bruteAccounts) != 1 {
		t.Fatalf("brute-force boundary = %d events/%d accounts", len(brute.requests), len(bruteAccounts))
	}

	pathScan, err := BuildPlan(ScenarioPathScan, 5)
	if err != nil {
		t.Fatal(err)
	}
	pathIDs := make([]string, 0, len(pathScan.requests))
	for _, request := range pathScan.requests {
		if request.method != http.MethodGet || request.body != "" || request.acceptedStatusCodes != ([2]int{http.StatusNotFound}) {
			t.Fatal("path-scan request contract drifted")
		}
		pathIDs = append(pathIDs, request.suspiciousPathID)
	}
	if !reflect.DeepEqual(pathIDs, pathScan.ExpectedShape().SuspiciousPathIDs) || len(pathIDs) != 8 {
		t.Fatal("path-scan did not cover each fixed path-catalog-v1 identifier exactly once")
	}

	burst, err := BuildPlan(ScenarioRequestBurst, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range burst.requests {
		if request.method != http.MethodGet || request.path != "/" || request.body != "" ||
			request.acceptedStatusCodes != ([2]int{http.StatusOK}) {
			t.Fatal("request-burst request contract drifted")
		}
	}
	if len(burst.requests) != 120 {
		t.Fatalf("request-burst boundary = %d", len(burst.requests))
	}

	normal, err := BuildPlan(ScenarioNormal, 5)
	if err != nil {
		t.Fatal(err)
	}
	shape := normal.ExpectedShape()
	if len(normal.requests) >= 120 || shape.LoginFailureCount >= 10 || shape.DistinctAccountCount >= 8 ||
		len(shape.SuspiciousPathIDs) >= 8 || shape.BrowseRequestCount != 5 || shape.IntermittentErrorRequests != 2 {
		t.Fatal("normal traffic no longer stays below every frozen detector threshold")
	}
}

func TestRunnerExercisesRealHTTPForEveryScenario(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	server := newSyntheticGateway(t, &hits)
	defer server.Close()

	runner, err := NewRunner(RunnerConfig{BaseURL: server.URL, Concurrency: 8, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	runner.client.CloseIdleConnections()
	wantStatuses := map[Scenario][]StatusCount{
		ScenarioNormal:             {{Class: "2xx", Count: 6}, {Class: "4xx", Count: 1}, {Class: "5xx", Count: 1}},
		ScenarioCredentialStuffing: {{Class: "4xx", Count: 20}},
		ScenarioBruteForce:         {{Class: "4xx", Count: 10}},
		ScenarioPathScan:           {{Class: "4xx", Count: 8}},
		ScenarioRequestBurst:       {{Class: "2xx", Count: 120}},
	}
	for _, scenario := range []Scenario{
		ScenarioNormal, ScenarioCredentialStuffing, ScenarioBruteForce, ScenarioPathScan, ScenarioRequestBurst,
	} {
		plan, buildErr := BuildPlan(scenario, 9)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		report, runErr := runner.Run(context.Background(), plan)
		if runErr != nil {
			t.Fatalf("scenario %s failed: %v", scenario, runErr)
		}
		if report.Result != "passed" || report.Attempted != plan.RequestCount() || report.Completed != plan.RequestCount() ||
			report.Failed != 0 || !reflect.DeepEqual(report.StatusCounts, wantStatuses[scenario]) ||
			!reflect.DeepEqual(report.ExpectedShape, plan.ExpectedShape()) {
			t.Fatalf("scenario %s report contract drifted: %s", scenario, report)
		}
		encoded, encodeErr := json.Marshal(report)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		assertPrivateValuesAbsent(t, string(encoded)+" "+report.String()+" "+runner.String(), server.URL)
	}
	if hits.Load() != 166 {
		t.Fatalf("Gateway request count = %d, want 166", hits.Load())
	}
}

func TestNormalReportIsReproducibleAcrossIntermittentFailureState(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	server := newSyntheticGateway(t, &hits)
	defer server.Close()
	runner, err := NewRunner(RunnerConfig{BaseURL: server.URL, Concurrency: 4, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(ScenarioNormal, 72)
	if err != nil {
		t.Fatal(err)
	}
	first, err := runner.Run(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runner.Run(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || hits.Load() != 16 {
		t.Fatalf("same-seed normal reports were not reproducible")
	}
}

func TestRunnerDisablesEnvironmentProxyAndRedirects(t *testing.T) {
	var proxyHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		writer.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	var gatewayHits atomic.Int64
	gateway := newSyntheticGateway(t, &gatewayHits)
	defer gateway.Close()
	runner, err := NewRunner(RunnerConfig{BaseURL: gateway.URL, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := runner.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.ForceAttemptHTTP2 || len(transport.TLSNextProto) != 0 ||
		transport.MaxConnsPerHost != 2 || transport.MaxResponseHeaderBytes != maxResponseHeaderBytes {
		t.Fatal("runner transport is not the frozen bounded no-proxy HTTP/1.1 transport")
	}
	plan, _ := BuildPlan(ScenarioPathScan, 1)
	if _, err := runner.Run(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if proxyHits.Load() != 0 || gatewayHits.Load() != 8 {
		t.Fatalf("proxy/gateway hits = %d/%d", proxyHits.Load(), gatewayHits.Load())
	}

	var redirectedHits atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedHits.Add(1)
	}))
	defer destination.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", destination.URL+"/redirect-target?secret=synthetic")
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	redirectRunner, err := NewRunner(RunnerConfig{BaseURL: redirector.URL, Concurrency: 3})
	if err != nil {
		t.Fatal(err)
	}
	report, runErr := redirectRunner.Run(context.Background(), plan)
	if !errors.Is(runErr, ErrRunFailed) || redirectedHits.Load() != 0 || report.Completed != 0 || report.Failed != 8 ||
		len(report.StatusCounts) != 0 || report.Result != "failed" {
		t.Fatalf("redirect result = %s, destination hits = %d, err = %v", report, redirectedHits.Load(), runErr)
	}
	assertPrivateValuesAbsent(t, report.String()+" "+runErr.Error(), destination.URL)
}

func TestRunnerSeparatesValidatedGatewayHostFromDialTarget(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	var wrongHost atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hits.Add(1)
		if request.Host != "localhost:8080" {
			wrongHost.Store(true)
		}
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, "{}")
	}))
	defer server.Close()
	runner, err := NewRunner(RunnerConfig{
		BaseURL: server.URL, HostHeader: "localhost:8080", Concurrency: 2, RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := BuildPlan(ScenarioPathScan, 8)
	report, err := runner.Run(context.Background(), plan)
	if err != nil || report.Result != "passed" || hits.Load() != 8 || wrongHost.Load() {
		t.Fatalf("separate Gateway Host contract failed: %s, hits=%d, wrong=%t, err=%v", report, hits.Load(), wrongHost.Load(), err)
	}
	assertPrivateValuesAbsent(t, runner.String()+" "+report.String(), server.URL)
}

func TestRunnerCountsPartialFailuresAndBoundsResponses(t *testing.T) {
	t.Parallel()
	var sequence atomic.Int64
	partial := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if sequence.Add(1) <= 5 {
			writer.WriteHeader(http.StatusInternalServerError)
		} else {
			writer.WriteHeader(http.StatusUnauthorized)
		}
		_, _ = io.WriteString(writer, "{}")
	}))
	defer partial.Close()
	runner, err := NewRunner(RunnerConfig{BaseURL: partial.URL, Concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := BuildPlan(ScenarioCredentialStuffing, 3)
	report, runErr := runner.Run(context.Background(), plan)
	if !errors.Is(runErr, ErrRunFailed) || report.Completed != 15 || report.Failed != 5 ||
		!reflect.DeepEqual(report.StatusCounts, []StatusCount{{Class: "4xx", Count: 15}}) {
		t.Fatalf("partial failure report = %s, statuses = %+v, err = %v", report, report.StatusCounts, runErr)
	}

	oversized := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, strings.Repeat("x", maxResponseBodyBytes+1))
	}))
	defer oversized.Close()
	boundedRunner, err := NewRunner(RunnerConfig{BaseURL: oversized.URL, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	pathPlan, _ := BuildPlan(ScenarioPathScan, 3)
	boundedReport, boundedErr := boundedRunner.Run(context.Background(), pathPlan)
	if !errors.Is(boundedErr, ErrRunFailed) || boundedReport.Completed != 0 || boundedReport.Failed != 8 {
		t.Fatalf("oversized response report = %s, err = %v", boundedReport, boundedErr)
	}
}

func TestRunnerCancellationTimeoutAndPlanIntegrity(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	server := newSyntheticGateway(t, &hits)
	defer server.Close()
	runner, err := NewRunner(RunnerConfig{BaseURL: server.URL, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := BuildPlan(ScenarioRequestBurst, 1)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	report, runErr := runner.Run(cancelled, plan)
	if !errors.Is(runErr, ErrRunFailed) || report.Attempted != 120 || report.Completed != 0 || report.Failed != 120 ||
		hits.Load() != 0 {
		t.Fatalf("pre-cancelled report = %s, hits = %d, err = %v", report, hits.Load(), runErr)
	}

	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer slow.Close()
	timeoutRunner, err := NewRunner(RunnerConfig{BaseURL: slow.URL, Concurrency: 4, RequestTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	pathPlan, _ := BuildPlan(ScenarioPathScan, 1)
	timeoutReport, timeoutErr := timeoutRunner.Run(context.Background(), pathPlan)
	if !errors.Is(timeoutErr, ErrRunFailed) || timeoutReport.Completed != 0 || timeoutReport.Failed != 8 {
		t.Fatalf("timeout report = %s, err = %v", timeoutReport, timeoutErr)
	}

	tampered, _ := BuildPlan(ScenarioNormal, 1)
	tampered.requests[0].path = "/tampered-synthetic-path"
	tampered.digest = planDigest(tampered.scenario, tampered.seed, tampered.requests)
	before := hits.Load()
	if _, integrityErr := runner.Run(context.Background(), tampered); !errors.Is(integrityErr, ErrRunFailed) || hits.Load() != before {
		t.Fatalf("canonical plan integrity check = %v, hits = %d/%d", integrityErr, before, hits.Load())
	}
	var nilRunner *Runner
	if _, nilRunnerErr := nilRunner.Run(context.Background(), plan); !errors.Is(nilRunnerErr, ErrRunFailed) {
		t.Fatalf("nil runner error = %v", nilRunnerErr)
	}
}

func TestRunnerRejectsHostileGatewayURLsWithoutDisclosure(t *testing.T) {
	t.Parallel()
	invalidURLs := []string{
		"", " ftp://gateway", "ftp://gateway", "http://user:synthetic-secret@gateway", "http://gateway/path",
		"http://gateway?target=origin", "http://gateway#fragment", "http://gateway?", "http://gateway/#",
		"http://gateway:0", "http://gateway:65536", "http://gateway:08080", "http://GATEWAY", "http://gateway.",
		"http://-gateway", "http://gateway_1", "http://[::1]", "http://gateway/%2e%2e", "http://gateway\n.invalid",
	}
	for index, raw := range invalidURLs {
		if _, err := NewRunner(RunnerConfig{BaseURL: raw, Concurrency: 1}); !errors.Is(err, ErrInvalidRunner) ||
			(raw != "" && strings.Contains(err.Error(), raw)) || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatalf("hostile Gateway URL case %d was accepted or disclosed", index)
		}
	}
	for _, config := range []RunnerConfig{
		{BaseURL: "http://gateway", Concurrency: 0},
		{BaseURL: "http://gateway", Concurrency: maxConcurrency + 1},
		{BaseURL: "http://gateway", Concurrency: 1, RequestTimeout: time.Millisecond},
		{BaseURL: "http://gateway", Concurrency: 1, RequestTimeout: 31 * time.Second},
		{BaseURL: "http://gateway", HostHeader: "user:secret@gateway", Concurrency: 1},
		{BaseURL: "http://gateway", HostHeader: "GATEWAY:8080", Concurrency: 1},
		{BaseURL: "http://gateway", HostHeader: "gateway:08080", Concurrency: 1},
		{BaseURL: "http://gateway", HostHeader: "[::1]:8080", Concurrency: 1},
		{BaseURL: "http://gateway", HostHeader: "gateway\r\n.invalid", Concurrency: 1},
	} {
		if _, err := NewRunner(config); !errors.Is(err, ErrInvalidRunner) {
			t.Fatalf("unsafe runner configuration error = %v", err)
		}
	}
	for _, raw := range []string{"http://gateway", "http://gateway:8080/", "http://127.0.0.1:8080", "https://gateway.example:443"} {
		if _, err := NewRunner(RunnerConfig{BaseURL: raw, Concurrency: 1}); err != nil {
			t.Fatalf("safe Gateway URL rejected: %v", err)
		}
	}
}

func TestRunnerIsRaceSafeForConcurrentReuse(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	server := newSyntheticGateway(t, &hits)
	defer server.Close()
	runner, err := NewRunner(RunnerConfig{BaseURL: server.URL, Concurrency: 4, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := BuildPlan(ScenarioPathScan, 44)
	const runs = 8
	reports := make(chan Report, runs)
	errorsSeen := make(chan error, runs)
	var group sync.WaitGroup
	for range runs {
		group.Add(1)
		go func() {
			defer group.Done()
			report, runErr := runner.Run(context.Background(), plan)
			reports <- report
			errorsSeen <- runErr
		}()
	}
	group.Wait()
	close(reports)
	close(errorsSeen)
	for runErr := range errorsSeen {
		if runErr != nil {
			t.Fatal(runErr)
		}
	}
	var first *Report
	for report := range reports {
		if first == nil {
			value := report
			first = &value
			continue
		}
		if !reflect.DeepEqual(report, *first) {
			t.Fatal("concurrent reuse produced nondeterministic reports")
		}
	}
	if hits.Load() != runs*8 {
		t.Fatalf("concurrent Gateway hits = %d", hits.Load())
	}
}

func TestParseScenarioAndPlanValidation(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"unknown", "mixed", "path-scanning", "", "normal "} {
		if _, err := ParseScenario(value); !errors.Is(err, ErrInvalidPlan) {
			t.Fatalf("scenario %q error = %v", value, err)
		}
	}
	if _, err := BuildPlan(ScenarioNormal, -1); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("negative seed error = %v", err)
	}
}

func newSyntheticGateway(t *testing.T, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	var intermittent atomic.Int64
	suspicious := map[string]struct{}{
		"/admin": {}, "/.env": {}, "/.git/config": {}, "/wp-admin": {},
		"/phpmyadmin": {}, "/server-status": {}, "/actuator/env": {}, "/archive.zip": {},
	}
	safe := map[string]struct{}{"/": {}, "/health": {}, "/products": {}, "/products/featured": {}, "/account": {}}
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hits.Add(1)
		if request.ProtoMajor != 1 || request.Header.Get("User-Agent") != userAgent ||
			request.URL.RawQuery != "" || request.Header.Get("Proxy-Authorization") != "" {
			t.Error("simulator request transport contract drifted")
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, maxBodyBytes+1))
		if err != nil || len(body) > maxBodyBytes {
			t.Error("simulator request body exceeded its bound")
		}
		status := http.StatusNotFound
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/login":
			values, parseErr := url.ParseQuery(string(body))
			if parseErr != nil || len(values) != 2 || values.Get("password") != "synthetic-demo-input" ||
				values.Get("account") == "" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("synthetic login request contract drifted")
			}
			status = http.StatusUnauthorized
		case request.Method == http.MethodGet && request.URL.Path == "/demo/intermittent-error":
			if intermittent.Add(1)%2 == 1 {
				status = http.StatusServiceUnavailable
			} else {
				status = http.StatusOK
			}
		case request.Method == http.MethodGet:
			if _, ok := safe[request.URL.Path]; ok {
				status = http.StatusOK
			} else if _, ok := suspicious[request.URL.Path]; !ok {
				t.Error("simulator sent a path outside the reviewed synthetic catalog")
			}
		default:
			t.Error("simulator sent an unsupported method")
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, "{}")
	}))
}

func assertPrivateValuesAbsent(t *testing.T, value, baseURL string) {
	t.Helper()
	for _, restricted := range []string{
		baseURL, "synthetic-demo-input", "account=", "password=", "/login", "/.env", "/.git/config",
		"/admin", "/wp-admin", "/phpmyadmin", "/server-status", "/actuator/env", "/archive.zip",
		"demo-normal", "demo-stuff", "demo-brute",
	} {
		if restricted != "" && strings.Contains(value, restricted) {
			t.Fatal("simulator output disclosed restricted request or endpoint data")
		}
	}
}
