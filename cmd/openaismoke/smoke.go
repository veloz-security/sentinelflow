package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/policy"
)

const (
	optInEnvironment        = "SENTINELFLOW_OPENAI_LIVE_SMOKE"
	keyEnvironment          = "OPENAI_API_KEY"
	rateCardVersion         = "live-smoke-one-shot-v1"
	syntheticClassification = "path_scan"
	syntheticTargetIPv4     = "203.0.113.20"
	syntheticEvidenceID     = "00000000-0000-0000-0000-000000000001"
	syntheticTTLSeconds     = uint32(1800)
)

type failureCode string

const (
	failureDisabled         failureCode = "disabled"
	failureKeyMissing       failureCode = "key_missing"
	failureConfiguration    failureCode = "configuration_error"
	failurePermission       failureCode = "permission_denied"
	failureModelUnavailable failureCode = "model_unavailable"
	failureRequestRejected  failureCode = "request_rejected"
	failureNetwork          failureCode = "network_error"
	failureTimeout          failureCode = "timeout"
	failureRateLimited      failureCode = "rate_limited"
	failureServer           failureCode = "server_error"
	failureRefused          failureCode = "refused"
	failureIncomplete       failureCode = "incomplete"
	failureSchema           failureCode = "schema_invalid"
	failureEvidence         failureCode = "evidence_invalid"
	failureGrammar          failureCode = "grammar_invalid"
	failureSemantic         failureCode = "semantic_invalid"
	failureBudget           failureCode = "budget_exhausted"
	failureCancelled        failureCode = "cancelled"
	failureProvenance       failureCode = "provenance_invalid"
)

type dependencies struct {
	lookupEnvironment func(string) (string, bool)
	resolveArtifacts  func() (ai.ArtifactPaths, error)
	baseURL           string
	transport         http.RoundTripper
}

type successReport struct {
	Status                 string `json:"status"`
	Provider               string `json:"provider"`
	Model                  string `json:"model"`
	Classification         string `json:"classification"`
	EvidenceCount          int    `json:"evidence_count"`
	Attempts               int    `json:"attempts"`
	InputDigest            string `json:"input_digest"`
	InputSchemaDigest      string `json:"input_schema_digest"`
	PromptDigest           string `json:"prompt_digest"`
	OutputSchemaDigest     string `json:"output_schema_digest"`
	GeneratedCommandDigest string `json:"generated_command_digest"`
	CanonicalCommandDigest string `json:"canonical_command_digest"`
}

type failureReport struct {
	Status string      `json:"status"`
	Code   failureCode `json:"code"`
}

func productionDependencies() dependencies {
	return dependencies{
		lookupEnvironment: os.LookupEnv,
		resolveArtifacts:  discoverArtifacts,
	}
}

func runCLI(ctx context.Context, stdout, stderr io.Writer, deps dependencies) int {
	report, code := runSmoke(ctx, deps)
	if code != "" {
		if stderr != nil {
			_ = json.NewEncoder(stderr).Encode(failureReport{Status: "failed", Code: code})
		}
		return 1
	}
	if stdout == nil || json.NewEncoder(stdout).Encode(report) != nil {
		if stderr != nil {
			_ = json.NewEncoder(stderr).Encode(failureReport{Status: "failed", Code: failureConfiguration})
		}
		return 1
	}
	return 0
}

func runSmoke(ctx context.Context, deps dependencies) (successReport, failureCode) {
	if ctx == nil || deps.lookupEnvironment == nil || deps.resolveArtifacts == nil {
		return successReport{}, failureConfiguration
	}
	if value, _ := deps.lookupEnvironment(optInEnvironment); value != "1" {
		return successReport{}, failureDisabled
	}
	key, present := deps.lookupEnvironment(keyEnvironment)
	if !present || !usableCredential(key) {
		return successReport{}, failureKeyMissing
	}

	paths, err := deps.resolveArtifacts()
	if err != nil {
		return successReport{}, failureConfiguration
	}
	artifacts, err := ai.LoadArtifacts(paths)
	if err != nil {
		return successReport{}, failureConfiguration
	}
	budget := &oneShotBudget{}
	client, err := ai.NewClient(ai.ClientConfig{
		APIKey:          key,
		BaseURL:         deps.baseURL,
		RateCardVersion: rateCardVersion,
		RequestTimeout:  ai.RequestTimeout,
		MaxAttempts:     1,
		Artifacts:       artifacts,
		RoundTripper:    deps.transport,
		Budget:          budget,
	})
	if err != nil {
		return successReport{}, failureConfiguration
	}
	identity := client.Identity()
	if identity.Kind() != ai.ProviderOpenAIResponses || identity.AdapterID() != ai.OpenAIResponsesAdapterID ||
		identity.Model() != ai.Model || identity.ReasoningEffort() != ai.ReasoningEffort ||
		identity.RateCardVersion() != rateCardVersion {
		return successReport{}, failureProvenance
	}

	input := syntheticInput()
	result, err := client.Analyze(ctx, input)
	if err != nil {
		return successReport{}, classifyFailure(err)
	}
	if result.Attempts != 1 || budget.reservations.Load() != 1 || budget.settlements.Load() != 1 ||
		result.ResponseID == "" || !result.Usage.Trusted || result.InputDigest != byteDigest(input) ||
		result.InputSchemaDigest != artifacts.InputSchemaDigest() || result.PromptDigest != artifacts.PromptDigest() ||
		result.OutputSchemaDigest != artifacts.OutputSchemaDigest() {
		return successReport{}, failureProvenance
	}

	classification, artifact, evidenceCount, err := validateCandidate(result.Output)
	if err != nil {
		if errors.Is(err, errSmokeSemantic) {
			return successReport{}, failureSemantic
		}
		return successReport{}, failureGrammar
	}
	return successReport{
		Status:                 "ok",
		Provider:               string(identity.Kind()),
		Model:                  identity.Model(),
		Classification:         classification,
		EvidenceCount:          evidenceCount,
		Attempts:               result.Attempts,
		InputDigest:            result.InputDigest,
		InputSchemaDigest:      result.InputSchemaDigest,
		PromptDigest:           result.PromptDigest,
		OutputSchemaDigest:     result.OutputSchemaDigest,
		GeneratedCommandDigest: artifact.GeneratedDigest(),
		CanonicalCommandDigest: artifact.CanonicalDigest(),
	}, ""
}

func usableCredential(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func discoverArtifacts() (ai.ArtifactPaths, error) {
	directory, err := os.Getwd()
	if err != nil {
		return ai.ArtifactPaths{}, errors.New("artifact root unavailable")
	}
	for {
		paths := artifactPaths(directory)
		if regularFiles(paths.InputSchema, paths.SystemPrompt, paths.OutputSchema) {
			return paths, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return ai.ArtifactPaths{}, errors.New("contract artifacts unavailable")
		}
		directory = parent
	}
}

func artifactPaths(root string) ai.ArtifactPaths {
	return ai.ArtifactPaths{
		InputSchema:  filepath.Join(root, "contracts", "ai", "sentinelflow_analysis_input_v1.schema.json"),
		SystemPrompt: filepath.Join(root, "contracts", "ai", "sentinelflow_system_prompt_v1.txt"),
		OutputSchema: filepath.Join(root, "contracts", "ai", "sentinelflow_analysis_v1.schema.json"),
	}
}

func regularFiles(paths ...string) bool {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
}

func syntheticInput() []byte {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	value := map[string]any{
		"schema_version":          "sentinelflow_analysis_input_v1",
		"incident_id":             "10000000-0000-0000-0000-000000000001",
		"incident_version":        1,
		"analysis_attempt_id":     "20000000-0000-0000-0000-000000000001",
		"generated_at":            "2026-07-18T02:00:00Z",
		"prompt_version":          "sentinelflow_system_prompt_v1",
		"output_schema_version":   "sentinelflow_analysis_v1",
		"source_ip":               syntheticTargetIPv4,
		"service_label":           "live-smoke",
		"window_start":            "2026-07-18T01:55:00Z",
		"window_end":              "2026-07-18T02:00:00Z",
		"detector_config_version": "detector-v1",
		"source_health_status":    "complete",
		"signals": []any{map[string]any{
			"signal_id": syntheticEvidenceID, "rule_id": "path_scan.v1", "classification": syntheticClassification,
			"window_start": "2026-07-18T01:55:00Z", "window_end": "2026-07-18T02:00:00Z",
			"event_count": 8, "distinct_account_count": 0, "distinct_suspicious_path_count": 8,
			"evidence_digest": digest,
		}},
		"evidence_refs": []any{map[string]any{
			"evidence_id": syntheticEvidenceID, "kind": "deterministic_signal", "rule_id": "path_scan.v1",
			"signal_digest": digest, "expanded_event_count": 8,
		}},
		"historical_impact": map[string]any{
			"lookback_start": "2026-07-17T02:00:00Z", "lookback_end": "2026-07-18T02:00:00Z",
			"coverage": "complete", "successful_auth_seen": false, "impact_digest": digest,
		},
		"allowed_policy": map[string]any{
			"action": "block_ip", "target_ip": syntheticTargetIPv4, "minimum_ttl_seconds": 60,
			"default_ttl_seconds": syntheticTTLSeconds, "maximum_ttl_seconds": 86400,
			"table": "sentinelflow", "set": "blacklist_ipv4",
		},
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("static synthetic input is not JSON encodable")
	}
	return encoded
}

type candidateOutput struct {
	Classification string   `json:"classification"`
	EvidenceIDs    []string `json:"evidence_ids"`
	Policy         struct {
		SchemaVersion string   `json:"schema_version"`
		Action        string   `json:"action"`
		TargetIP      string   `json:"target_ip"`
		TTLSeconds    uint32   `json:"ttl_seconds"`
		EvidenceIDs   []string `json:"evidence_ids"`
	} `json:"policy"`
	Candidate struct {
		SchemaVersion string   `json:"schema_version"`
		TargetIP      string   `json:"target_ip"`
		Timeout       string   `json:"timeout"`
		EvidenceIDs   []string `json:"evidence_ids"`
		Command       string   `json:"command"`
	} `json:"nftables_command_candidate"`
}

var errSmokeSemantic = errors.New("live smoke output differs from the fixed synthetic scenario")

func validateCandidate(output []byte) (string, policy.Artifact, int, error) {
	var parsed candidateOutput
	if err := json.Unmarshal(output, &parsed); err != nil {
		return "", policy.Artifact{}, 0, errors.New("validated output cannot be decoded")
	}
	artifact, err := policy.BuildArtifact(policy.Policy{
		SchemaVersion: parsed.Policy.SchemaVersion,
		Action:        parsed.Policy.Action,
		TargetIPv4:    parsed.Policy.TargetIP,
		TTLSeconds:    parsed.Policy.TTLSeconds,
		EvidenceIDs:   parsed.Policy.EvidenceIDs,
	}, policy.Candidate{
		SchemaVersion:  parsed.Candidate.SchemaVersion,
		TargetIPv4:     parsed.Candidate.TargetIP,
		TimeoutToken:   parsed.Candidate.Timeout,
		EvidenceIDs:    parsed.Candidate.EvidenceIDs,
		GeneratedBytes: []byte(parsed.Candidate.Command),
	})
	if err != nil || len(parsed.EvidenceIDs) != len(artifact.EvidenceIDs()) {
		return "", policy.Artifact{}, 0, errors.New("candidate grammar rejected")
	}
	artifactEvidence := artifact.EvidenceIDs()
	for index, evidenceID := range parsed.EvidenceIDs {
		if artifactEvidence[index] != evidenceID {
			return "", policy.Artifact{}, 0, errors.New("candidate evidence differs")
		}
	}
	if parsed.Classification != syntheticClassification || artifact.AST().TargetIPv4() != syntheticTargetIPv4 ||
		artifact.AST().TTLSeconds() != syntheticTTLSeconds || len(artifactEvidence) != 1 ||
		artifactEvidence[0] != syntheticEvidenceID {
		return "", policy.Artifact{}, 0, errSmokeSemantic
	}
	return parsed.Classification, artifact, len(parsed.EvidenceIDs), nil
}

func classifyFailure(err error) failureCode {
	failure, ok := ai.FailureOf(err)
	if !ok {
		return failureConfiguration
	}
	switch failure.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return failurePermission
	case http.StatusNotFound:
		return failureModelUnavailable
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return failureRequestRejected
	}
	switch failure.Reason {
	case ai.FailureBudgetExhausted:
		return failureBudget
	case ai.FailureNetworkError:
		return failureNetwork
	case ai.FailureHTTP408, ai.FailureTimeout:
		return failureTimeout
	case ai.FailureHTTP409, ai.FailureServerError:
		return failureServer
	case ai.FailureRateLimited:
		return failureRateLimited
	case ai.FailureRefused:
		return failureRefused
	case ai.FailureIncomplete:
		return failureIncomplete
	case ai.FailureSchemaInvalid:
		return failureSchema
	case ai.FailureEvidenceInvalid:
		return failureEvidence
	case ai.FailureCancelled:
		return failureCancelled
	default:
		return failureConfiguration
	}
}

func byteDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type oneShotBudget struct {
	reservations atomic.Int32
	settlements  atomic.Int32
}

func (budget *oneShotBudget) Reserve(_ context.Context, request ai.BudgetRequest) (ai.BudgetReservation, error) {
	if budget == nil || request.Model != ai.Model || request.RateCardVersion != rateCardVersion ||
		request.MaxInputTokenUnits != ai.MaxInputBytes || request.MaxOutputTokens != ai.MaxOutputTokens ||
		request.ReservedAt.IsZero() || budget.reservations.Add(1) != 1 {
		return nil, errors.New("one-shot budget rejected")
	}
	return &oneShotReservation{budget: budget}, nil
}

type oneShotReservation struct {
	budget  *oneShotBudget
	settled atomic.Bool
}

func (reservation *oneShotReservation) Settle(_ context.Context, _ ai.Usage, _ bool) error {
	if reservation == nil || reservation.budget == nil || !reservation.settled.CompareAndSwap(false, true) {
		return errors.New("one-shot settlement rejected")
	}
	reservation.budget.settlements.Add(1)
	return nil
}
