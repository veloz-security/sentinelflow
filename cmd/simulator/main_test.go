package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devwooops/sentinelflow/internal/simulator"
)

func TestRunEmitsMachineCheckableSuccessReport(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "localhost:8080" {
			t.Error("CLI did not use the frozen allowlisted Gateway Host")
		}
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, "{}")
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runTo(context.Background(), []string{
		"-gateway-url", server.URL, "-seed", "7", "-concurrency", "2", "path-scan",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	var report simulator.Report
	if decodeErr := json.Unmarshal(output.Bytes(), &report); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if report.SchemaVersion != "simulator-report-v1" || report.Result != "passed" ||
		report.Scenario != simulator.ScenarioPathScan || report.Seed != 7 ||
		report.Attempted != 8 || report.Completed != 8 || report.Failed != 0 ||
		report.ExpectedShape.ExpectedClassification != "path_scan" || len(report.ExpectedShape.SuspiciousPathIDs) != 8 {
		t.Fatalf("unexpected report: %s", report)
	}
	assertCommandOutputSafe(t, output.String(), server.URL)
}

func TestRunEmitsSafeFailureReportIncludingUnstartedCancellation(t *testing.T) {
	t.Parallel()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	err := runTo(cancelled, []string{
		"-gateway-url", "http://127.0.0.1:1", "-seed", "11", "request-burst",
	}, &output)
	if !errors.Is(err, simulator.ErrRunFailed) {
		t.Fatalf("cancelled run error = %v", err)
	}
	var report simulator.Report
	if decodeErr := json.Unmarshal(output.Bytes(), &report); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if report.Result != "failed" || report.Attempted != 120 || report.Completed != 0 || report.Failed != 120 {
		t.Fatalf("cancelled report = %s", report)
	}
	assertCommandOutputSafe(t, output.String()+" "+err.Error(), "http://127.0.0.1:1")
}

func TestRunRejectsMissingUnknownAndNonCanonicalScenariosBeforeNetwork(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"mixed"},
		{"path-scanning"},
		{"normal", "extra"},
		{"-concurrency", "0", "normal"},
		{"-gateway-url", "http://user:synthetic-secret@gateway", "normal"},
	} {
		var output bytes.Buffer
		if err := runTo(context.Background(), args, &output); err == nil || output.Len() != 0 ||
			strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatalf("run accepted an unsafe invocation or disclosed it")
		}
	}
}

func TestRunHandlesInvalidOutputAndInvocationSafely(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	err := runTo(context.Background(), []string{"-gateway-url", server.URL, "path-scan"}, failingWriter{})
	if err == nil || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("output failure error = %v", err)
	}
	if err := runTo(context.Background(), []string{"normal"}, nil); err == nil {
		t.Fatal("nil output accepted")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic writer detail must not propagate")
}

func assertCommandOutputSafe(t *testing.T, value, baseURL string) {
	t.Helper()
	for _, restricted := range []string{
		baseURL, "synthetic-demo-input", "account=", "password=", "/login", "/.env", "/.git/config",
		"/admin", "/wp-admin", "/phpmyadmin", "/server-status", "/actuator/env", "/archive.zip",
		"demo-normal", "demo-stuff", "demo-brute",
	} {
		if strings.Contains(value, restricted) {
			t.Fatal("command output disclosed request or endpoint data")
		}
	}
}
