package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devwooops/sentinelflow/internal/ai"
)

const fakeKey = "test-live-smoke-key-never-print"

func TestDisabledByDefaultAndMissingKeyNeverReachArtifactsOrNetwork(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		env  map[string]string
		code failureCode
	}{
		{name: "disabled", env: map[string]string{keyEnvironment: fakeKey}, code: failureDisabled},
		{name: "missing key", env: map[string]string{optInEnvironment: "1"}, code: failureKeyMissing},
		{name: "blank key", env: map[string]string{optInEnvironment: "1", keyEnvironment: "  "}, code: failureKeyMissing},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var artifactCalls atomic.Int32
			var networkCalls atomic.Int32
			deps := dependencies{
				lookupEnvironment: mapLookup(test.env),
				resolveArtifacts: func() (ai.ArtifactPaths, error) {
					artifactCalls.Add(1)
					return testArtifactPaths(), nil
				},
				baseURL: "https://unit.invalid",
				transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					networkCalls.Add(1)
					return nil, errors.New("must not be called")
				}),
			}
			var stdout, stderr bytes.Buffer
			if exit := runCLI(context.Background(), &stdout, &stderr, deps); exit != 1 {
				t.Fatalf("exit = %d, want 1", exit)
			}
			assertFailureOutput(t, stdout.String(), stderr.String(), test.code)
			if artifactCalls.Load() != 0 || networkCalls.Load() != 0 {
				t.Fatalf("disabled gate reached artifacts=%d network=%d", artifactCalls.Load(), networkCalls.Load())
			}
		})
	}
}

func TestOneSyntheticRequestUsesFrozenBoundsAndPrintsOnlySafeMetadata(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != ai.ResponsesPath {
			t.Errorf("request target = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+fakeKey {
			t.Error("authorization header was not passed to the production client")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if bytes.Contains(body, []byte(fakeKey)) {
			t.Error("request JSON contains the API key")
		}
		assertFrozenRequest(t, body)
		writeJSON(t, writer, http.StatusOK, completedResponse(validOutput("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }")))
	}))
	defer server.Close()

	deps := liveTestDependencies(server)
	var stdout, stderr bytes.Buffer
	if exit := runCLI(context.Background(), &stdout, &stderr, deps); exit != 0 {
		t.Fatalf("exit = %d stderr=%s", exit, stderr.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want exactly 1", calls.Load())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr = %q", stderr.String())
	}
	output := stdout.String()
	for _, forbidden := range []string{
		fakeKey,
		"Synthetic path scan signal",
		"Authorized scanner",
		"Complete deterministic signal",
		"add element inet",
		"resp_live_smoke",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("safe output contains forbidden provider/input material")
		}
	}
	var report successReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Status != "ok" || report.Provider != string(ai.ProviderOpenAIResponses) ||
		report.Model != ai.Model || report.Classification != "path_scan" ||
		report.EvidenceCount != 1 || report.Attempts != 1 {
		t.Fatalf("unexpected safe report: %+v", report)
	}
	for name, value := range map[string]string{
		"input": report.InputDigest, "input_schema": report.InputSchemaDigest,
		"prompt": report.PromptDigest, "output_schema": report.OutputSchemaDigest,
		"generated": report.GeneratedCommandDigest, "canonical": report.CanonicalCommandDigest,
	} {
		if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
			t.Fatalf("%s digest is not redacted provenance: %q", name, value)
		}
	}
}

func TestProviderAndValidationFailuresAreStableRedactedAndSingleCall(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		status     int
		response   any
		wantCode   failureCode
		secretText string
	}{
		{name: "permission", status: http.StatusForbidden, response: map[string]any{"error": "provider-permission-secret"}, wantCode: failurePermission, secretText: "provider-permission-secret"},
		{name: "model", status: http.StatusNotFound, response: map[string]any{"error": "model-detail-secret"}, wantCode: failureModelUnavailable, secretText: "model-detail-secret"},
		{name: "refusal", status: http.StatusOK, response: refusalResponse("refusal-prose-secret"), wantCode: failureRefused, secretText: "refusal-prose-secret"},
		{name: "incomplete", status: http.StatusOK, response: incompleteResponse("incomplete-detail-secret"), wantCode: failureIncomplete, secretText: "incomplete-detail-secret"},
		{name: "schema", status: http.StatusOK, response: completedResponse([]byte(`{"unexpected":"provider-output-secret"}`)), wantCode: failureSchema, secretText: "provider-output-secret"},
		{name: "grammar", status: http.StatusOK, response: completedResponse(validOutput("add element inet sentinelflow wrong_set { 203.0.113.20 timeout 30m }")), wantCode: failureGrammar, secretText: "wrong_set"},
		{name: "substituted classification", status: http.StatusOK, response: completedResponse(mutatedValidOutput(func(output map[string]any) {
			output["classification"] = "mixed"
		})), wantCode: failureSemantic, secretText: "mixed"},
		{name: "substituted ttl", status: http.StatusOK, response: completedResponse(mutatedValidOutput(func(output map[string]any) {
			output["policy"].(map[string]any)["ttl_seconds"] = 3600
			candidate := output["nftables_command_candidate"].(map[string]any)
			candidate["timeout"] = "1h"
			candidate["command"] = "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1h }"
		})), wantCode: failureSemantic, secretText: "timeout 1h"},
		{name: "substituted target", status: http.StatusOK, response: completedResponse(mutatedValidOutput(func(output map[string]any) {
			output["policy"].(map[string]any)["target_ip"] = "198.51.100.10"
			candidate := output["nftables_command_candidate"].(map[string]any)
			candidate["target_ip"] = "198.51.100.10"
			candidate["command"] = "add element inet sentinelflow blacklist_ipv4 { 198.51.100.10 timeout 30m }"
		})), wantCode: failureEvidence, secretText: "198.51.100.10"},
		{name: "substituted evidence", status: http.StatusOK, response: completedResponse(mutatedValidOutput(func(output map[string]any) {
			replacement := []string{"00000000-0000-0000-0000-000000000002"}
			output["evidence_ids"] = replacement
			output["policy"].(map[string]any)["evidence_ids"] = replacement
			output["nftables_command_candidate"].(map[string]any)["evidence_ids"] = replacement
		})), wantCode: failureEvidence, secretText: "00000000-0000-0000-0000-000000000002"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writeJSON(t, writer, test.status, test.response)
			}))
			defer server.Close()

			var stdout, stderr bytes.Buffer
			exit := runCLI(context.Background(), &stdout, &stderr, liveTestDependencies(server))
			if exit != 1 {
				t.Fatalf("exit = %d, want 1", exit)
			}
			assertFailureOutput(t, stdout.String(), stderr.String(), test.wantCode)
			if strings.Contains(stderr.String(), fakeKey) || strings.Contains(stderr.String(), test.secretText) {
				t.Fatal("failure output leaked a key or provider content")
			}
			if calls.Load() != 1 {
				t.Fatalf("provider calls = %d, want exactly 1", calls.Load())
			}
		})
	}
}

func TestNetworkFailureIsStableRedactedAndSingleCall(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	deps := dependencies{
		lookupEnvironment: mapLookup(map[string]string{optInEnvironment: "1", keyEnvironment: fakeKey}),
		resolveArtifacts:  func() (ai.ArtifactPaths, error) { return testArtifactPaths(), nil },
		baseURL:           "https://unit.invalid",
		transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, errors.New("network-provider-secret")
		}),
	}
	var stdout, stderr bytes.Buffer
	if exit := runCLI(context.Background(), &stdout, &stderr, deps); exit != 1 {
		t.Fatalf("exit = %d, want 1", exit)
	}
	assertFailureOutput(t, stdout.String(), stderr.String(), failureNetwork)
	if calls.Load() != 1 || strings.Contains(stderr.String(), "network-provider-secret") || strings.Contains(stderr.String(), fakeKey) {
		t.Fatal("network failure call count or redaction differs")
	}
}

func TestSyntheticInputIsCompactDocumentationRangeOnly(t *testing.T) {
	t.Parallel()
	input := syntheticInput()
	if len(input) == 0 || len(input) > ai.MaxInputBytes {
		t.Fatalf("synthetic input bytes = %d, max %d", len(input), ai.MaxInputBytes)
	}
	text := string(input)
	if !strings.Contains(text, `"source_ip":"203.0.113.20"`) || !strings.Contains(text, `"target_ip":"203.0.113.20"`) {
		t.Fatal("synthetic input is not fixed to the documentation-range address")
	}
	for _, forbidden := range []string{"Authorization", "Cookie", "password", "account_hash", "query_string", "request_body", "response_body"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("synthetic input contains prohibited field %q", forbidden)
		}
	}
}

func TestCommandHasNoPersistenceApprovalDispatchOrEnforcementReachability(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range parsed.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"database/sql", "os/exec", "syscall", "unsafe",
				"/internal/enforcement", "/internal/dispatcher", "/internal/hil", "github.com/jackc/pgx",
			} {
				if name == forbidden || strings.Contains(name, forbidden) {
					t.Fatalf("%s imports forbidden mutation dependency %q", path, name)
				}
			}
		}
	}
}

func assertFrozenRequest(t *testing.T, body []byte) {
	t.Helper()
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if request["model"] != ai.Model || request["store"] != false || request["max_output_tokens"] != float64(ai.MaxOutputTokens) {
		t.Fatal("frozen Responses request bounds differ")
	}
	if _, exists := request["tools"]; exists {
		t.Fatal("live smoke request must not contain tools")
	}
	reasoning, ok := request["reasoning"].(map[string]any)
	if !ok || reasoning["effort"] != ai.ReasoningEffort {
		t.Fatal("reasoning contract differs")
	}
	messages, ok := request["input"].([]any)
	if !ok || len(messages) != 2 {
		t.Fatal("request must contain only frozen system and compact synthetic user messages")
	}
	user := messageText(t, messages[1])
	if len(user) > ai.MaxInputBytes || !strings.Contains(user, "203.0.113.20") {
		t.Fatal("compact input bounds or synthetic target differ")
	}
	var compact map[string]any
	if err := json.Unmarshal([]byte(user), &compact); err != nil {
		t.Fatal("compact input is not JSON")
	}
	evidence, ok := compact["evidence_refs"].([]any)
	if !ok || len(evidence) != 1 || len(evidence) > ai.MaxEvidenceRefs {
		t.Fatal("synthetic evidence bounds differ")
	}
}

func messageText(t *testing.T, value any) string {
	t.Helper()
	message, ok := value.(map[string]any)
	if !ok {
		t.Fatal("message is not an object")
	}
	content, ok := message["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatal("message content differs")
	}
	part, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("message part differs")
	}
	text, ok := part["text"].(string)
	if !ok {
		t.Fatal("message text differs")
	}
	return text
}

func liveTestDependencies(server *httptest.Server) dependencies {
	return dependencies{
		lookupEnvironment: mapLookup(map[string]string{optInEnvironment: "1", keyEnvironment: fakeKey}),
		resolveArtifacts:  func() (ai.ArtifactPaths, error) { return testArtifactPaths(), nil },
		baseURL:           server.URL,
		transport:         server.Client().Transport,
	}
}

func testArtifactPaths() ai.ArtifactPaths {
	return artifactPaths(filepath.Clean(filepath.Join("..", "..")))
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func validOutput(command string) []byte {
	return mustJSON(map[string]any{
		"schema_version": "sentinelflow_analysis_v1", "incident_summary": "Synthetic path scan signal.",
		"classification": syntheticClassification, "confidence": 0.91, "uncertainty": "Synthetic demonstration input.",
		"false_positive_factors": []string{"Authorized scanner"}, "evidence_ids": []string{syntheticEvidenceID},
		"policy": map[string]any{
			"schema_version": "response-policy-v1", "action": "block_ip", "target_ip": syntheticTargetIPv4,
			"ttl_seconds": syntheticTTLSeconds, "evidence_ids": []string{syntheticEvidenceID}, "rationale": "Complete deterministic signal.",
		},
		"nftables_command_candidate": map[string]any{
			"schema_version": "nft-blacklist-v1", "target_ip": syntheticTargetIPv4, "timeout": "30m",
			"evidence_ids": []string{syntheticEvidenceID}, "command": command,
		},
	})
}

func mutatedValidOutput(mutate func(map[string]any)) []byte {
	var output map[string]any
	if err := json.Unmarshal(validOutput("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }"), &output); err != nil {
		panic(err)
	}
	mutate(output)
	return mustJSON(output)
}

func completedResponse(output []byte) map[string]any {
	return map[string]any{
		"id": "resp_live_smoke", "status": "completed",
		"output": []any{map[string]any{
			"type": "message", "status": "completed",
			"content": []any{map[string]any{"type": "output_text", "text": string(output)}},
		}},
		"usage": map[string]any{"input_tokens": 100, "output_tokens": 50, "input_tokens_details": map[string]any{"cached_tokens": 10}},
	}
}

func refusalResponse(text string) map[string]any {
	return map[string]any{
		"id": "resp_refusal", "status": "completed",
		"output": []any{map[string]any{
			"type": "message", "status": "completed",
			"content": []any{map[string]any{"type": "refusal", "refusal": text}},
		}},
	}
}

func incompleteResponse(detail string) map[string]any {
	return map[string]any{
		"id": "resp_incomplete", "status": "incomplete",
		"incomplete_details": map[string]any{"reason": detail}, "output": []any{},
	}
}

func assertFailureOutput(t *testing.T, stdout, stderr string, code failureCode) {
	t.Helper()
	if stdout != "" {
		t.Fatalf("failure wrote stdout")
	}
	var report failureReport
	if err := json.Unmarshal([]byte(stderr), &report); err != nil {
		t.Fatalf("decode failure report: %v", err)
	}
	if report.Status != "failed" || report.Code != code {
		t.Fatalf("failure report = %+v, want code %s", report, code)
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func mustJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
