package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const validResult = "GATE_RESULT mode=development duration=5s rps=500 direct_p95_us=200 gateway_p95_us=450 added_p95_us=250 outage_direct_p95_us=300 outage_gateway_p95_us=700 outage_added_p95_us=400 accepted=2500 dropped=1500"
const validReleaseResult = "GATE_RESULT mode=five-minute duration=5m0s rps=500 direct_p95_us=574 gateway_p95_us=1236 added_p95_us=662 outage_direct_p95_us=363 outage_gateway_p95_us=784 outage_added_p95_us=421 accepted=150000 dropped=5000"

func TestGatewayPerformanceWrapperRejectsResultAndThresholdManipulation(t *testing.T) {
	for _, test := range []struct {
		name       string
		result     string
		extra      string
		mode       string
		wantStatus int
		want       string
	}{
		{name: "valid", result: validResult, wantStatus: 0, want: "GATE_VERDICT=non_release_smoke"},
		{name: "release-non-reference-host", result: validReleaseResult, mode: "release", wantStatus: 3, want: "GATE_VERDICT=unverified"},
		{name: "wrong-rps", result: strings.Replace(validResult, "rps=500", "rps=499", 1), wantStatus: 1, want: "workload identity drifted"},
		{name: "threshold", result: strings.Replace(validResult, "added_p95_us=250", "added_p95_us=5001", 1), wantStatus: 1, want: "exceeds 5000 microseconds"},
		{name: "duplicate-line", result: validResult, extra: validResult, wantStatus: 1, want: "exactly one GATE_RESULT"},
		{name: "missing-line", result: "", wantStatus: 1, want: "exactly one GATE_RESULT"},
		{name: "duplicate-field", result: validResult + " rps=500", wantStatus: 1, want: "duplicate GATE_RESULT field"},
		{name: "unknown-field", result: validResult + " threshold_us=9000", wantStatus: 1, want: "unreviewed GATE_RESULT field"},
		{name: "invalid-mode", result: validResult, mode: "quick", wantStatus: 1, want: "must be release or smoke"},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, status := runWrapper(t, test.result, test.extra, test.mode, nil)
			if status != test.wantStatus || !strings.Contains(output, test.want) {
				t.Fatalf("status=%d output=%q, want status=%d containing %q", status, output, test.wantStatus, test.want)
			}
		})
	}
}

func TestGatewayPerformanceWrapperRejectsDurationAndGoFlagOverrides(t *testing.T) {
	output, status := runWrapper(t, validResult, "", "", map[string]string{
		"SENTINELFLOW_GATEWAY_PERF_DURATION": "1s",
	})
	if status != 1 || !strings.Contains(output, "is fixed") {
		t.Fatalf("duration override status=%d output=%q", status, output)
	}

	output, status = runWrapper(t, validResult, "", "", map[string]string{
		"GOFLAGS": "-run=^$",
	})
	if status != 0 || !strings.Contains(output, "GATE_VERDICT=non_release_smoke") {
		t.Fatalf("inherited GOFLAGS changed the fixed test status=%d output=%q", status, output)
	}
}

func runWrapper(t *testing.T, result, extra, mode string, additions map[string]string) (string, int) {
	t.Helper()
	directory := t.TempDir()
	fakeGo := filepath.Join(directory, "go")
	payload := `#!/bin/sh
case "$*" in
  *TestGatewayPerformanceGate*)
    printf '%s\n' '=== RUN   TestGatewayPerformanceGate'
    printf '%s\n' '    performance_gate_test.go:325: direct-origin: scheduled=2500 missed=0 rate=500.10 rps p95=200us p99=300us errors=0 status=0 parity=0'
    printf '%s\n' '    performance_gate_test.go:326: gateway: scheduled=2500 missed=0 rate=500.10 rps p95=450us p99=600us errors=0 status=0 parity=0'
    printf '%s\n' '    performance_gate_test.go:353: resources: heap_before=1 heap_peak=2 heap_delta=1 goroutines_peak=3 gateway_connections_peak=2 origin_connections_peak=3'
    if [ -n "$SYNTHETIC_GATE_RESULT" ]; then printf '%s\n' "$SYNTHETIC_GATE_RESULT"; fi
    if [ -n "$SYNTHETIC_EXTRA_RESULT" ]; then printf '%s\n' "$SYNTHETIC_EXTRA_RESULT"; fi
    printf '%s\n' '--- PASS: TestGatewayPerformanceGate (0.01s)' 'PASS'
    ;;
  *)
    printf '%s\n' 'ok synthetic prerequisite'
    ;;
esac
`
	if err := os.WriteFile(fakeGo, []byte(payload), 0o700); err != nil {
		t.Fatal(err)
	}
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path unavailable")
	}
	script := filepath.Join(filepath.Dir(current), "check-gateway-performance.sh")
	command := exec.Command("/bin/bash", script)
	environment := append([]string{}, os.Environ()...)
	environment = append(environment,
		"PATH="+directory+":"+os.Getenv("PATH"),
		"SENTINELFLOW_GATEWAY_PERF_MODE=smoke",
		"SYNTHETIC_GATE_RESULT="+result,
		"SYNTHETIC_EXTRA_RESULT="+extra,
	)
	if mode != "" {
		environment = append(environment, "SENTINELFLOW_GATEWAY_PERF_MODE="+mode)
	}
	for name, value := range additions {
		environment = append(environment, name+"="+value)
	}
	command.Env = environment
	payloadOut, err := command.CombinedOutput()
	if err == nil {
		return string(payloadOut), 0
	}
	if exitError, ok := err.(*exec.ExitError); ok {
		return string(payloadOut), exitError.ExitCode()
	}
	t.Fatalf("wrapper did not execute: %v", err)
	return "", -1
}
