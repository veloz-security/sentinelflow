// Package aistub implements the deterministic, offline analyzer used by
// integration tests. It has no network, credential, budget, HIL, or executor
// authority and must never be presented as a real OpenAI response.
package aistub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
)

const (
	// AdapterID is deliberately not an OpenAI model identifier. Persistence
	// wiring must record this identity before the stub may be used outside an
	// isolated test.
	AdapterID = ai.DeterministicStubAdapterID

	maximumInputBytes = ai.MaxInputBytes
	defaultTTLSeconds = analysisworker.DefaultTTLSeconds
)

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
)

var ruleClassifications = map[string]string{
	"path_scan.v1":           "path_scan",
	"request_burst.v1":       "request_burst",
	"login_bruteforce.v1":    "brute_force",
	"credential_stuffing.v1": "credential_stuffing",
}

// Analyzer is stateless and safe for concurrent use.
type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (*Analyzer) Identity() ai.ProviderIdentity { return ai.DeterministicStubIdentity() }

func (*Analyzer) String() string     { return "aistub(" + AdapterID + ")" }
func (a *Analyzer) GoString() string { return a.String() }

// Analyze consumes only the frozen compact analysis input and emits one
// deterministic, schema-shaped policy and command candidate. The returned
// usage is intentionally untrusted/zero because no provider was called.
func (*Analyzer) Analyze(ctx context.Context, input []byte) (ai.Result, error) {
	if ctx == nil {
		return ai.Result{}, failure(ai.FailureConfiguration)
	}
	select {
	case <-ctx.Done():
		return ai.Result{}, failure(ai.FailureCancelled)
	default:
	}
	if len(input) == 0 || len(input) > maximumInputBytes {
		return ai.Result{}, failure(ai.FailureInputTooLarge)
	}
	frozen := append([]byte(nil), input...)
	request, err := decodeInput(frozen)
	if err != nil {
		return ai.Result{}, failure(ai.FailureSchemaInvalid)
	}
	if !validInput(request) {
		return ai.Result{}, failure(ai.FailureEvidenceInvalid)
	}
	select {
	case <-ctx.Done():
		return ai.Result{}, failure(ai.FailureCancelled)
	default:
	}

	evidenceIDs := make([]string, len(request.EvidenceRefs))
	classes := make(map[string]struct{}, len(request.Signals))
	for index, reference := range request.EvidenceRefs {
		evidenceIDs[index] = reference.EvidenceID
		classes[request.Signals[index].Classification] = struct{}{}
	}
	classification := request.Signals[0].Classification
	if len(classes) > 1 {
		classification = "mixed"
	}
	output := outputDocument{
		SchemaVersion:   analysisworker.OutputSchemaVersion,
		IncidentSummary: "Deterministic security signals exceeded the reviewed threshold.",
		Classification:  classification,
		Confidence:      0.75,
		Uncertainty:     "The deterministic signal may still reflect authorized synthetic or administrative activity.",
		FalsePositiveFactors: []string{
			"Authorized testing or maintenance can reproduce the observed threshold.",
		},
		EvidenceIDs: evidenceIDs,
		Policy: outputPolicy{
			SchemaVersion: "response-policy-v1",
			Action:        "block_ip",
			TargetIP:      request.SourceIP,
			TTLSeconds:    defaultTTLSeconds,
			EvidenceIDs:   evidenceIDs,
			Rationale:     "A temporary single-address block is bounded and reviewable.",
		},
		Candidate: outputCandidate{
			SchemaVersion: "nft-blacklist-v1",
			TargetIP:      request.SourceIP,
			Timeout:       "30m",
			EvidenceIDs:   evidenceIDs,
			Command: "add element inet sentinelflow blacklist_ipv4 { " +
				request.SourceIP + " timeout 30m }",
		},
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return ai.Result{}, failure(ai.FailureConfiguration)
	}
	inputDigest := digestBytes(frozen)
	responseSuffix := strings.TrimPrefix(inputDigest, "sha256:")
	return ai.Result{
		ResponseID:         "stub_" + responseSuffix,
		Output:             encoded,
		Usage:              ai.Usage{},
		Attempts:           1,
		InputDigest:        inputDigest,
		InputSchemaDigest:  ai.PinnedInputSchemaDigest,
		PromptDigest:       ai.PinnedSystemPromptDigest,
		OutputSchemaDigest: ai.PinnedOutputSchemaDigest,
	}, nil
}

func failure(reason ai.FailureReason) error {
	return &ai.Failure{Reason: reason, Attempts: 0}
}

type compactInput struct {
	SchemaVersion       string               `json:"schema_version"`
	IncidentID          string               `json:"incident_id"`
	IncidentVersion     int32                `json:"incident_version"`
	AnalysisAttemptID   string               `json:"analysis_attempt_id"`
	GeneratedAt         string               `json:"generated_at"`
	PromptVersion       string               `json:"prompt_version"`
	OutputSchemaVersion string               `json:"output_schema_version"`
	SourceIP            string               `json:"source_ip"`
	ServiceLabel        string               `json:"service_label"`
	WindowStart         string               `json:"window_start"`
	WindowEnd           string               `json:"window_end"`
	DetectorVersion     string               `json:"detector_config_version"`
	SourceHealthStatus  string               `json:"source_health_status"`
	Signals             []compactSignal      `json:"signals"`
	EvidenceRefs        []compactEvidenceRef `json:"evidence_refs"`
	HistoricalImpact    compactHistory       `json:"historical_impact"`
	AllowedPolicy       compactAllowedPolicy `json:"allowed_policy"`
}

type compactSignal struct {
	SignalID                    string `json:"signal_id"`
	RuleID                      string `json:"rule_id"`
	Classification              string `json:"classification"`
	WindowStart                 string `json:"window_start"`
	WindowEnd                   string `json:"window_end"`
	EventCount                  int64  `json:"event_count"`
	DistinctAccountCount        int64  `json:"distinct_account_count"`
	DistinctSuspiciousPathCount int64  `json:"distinct_suspicious_path_count"`
	EvidenceDigest              string `json:"evidence_digest"`
}

type compactEvidenceRef struct {
	EvidenceID         string `json:"evidence_id"`
	Kind               string `json:"kind"`
	RuleID             string `json:"rule_id"`
	SignalDigest       string `json:"signal_digest"`
	ExpandedEventCount int64  `json:"expanded_event_count"`
}

type compactHistory struct {
	LookbackStart      string `json:"lookback_start"`
	LookbackEnd        string `json:"lookback_end"`
	Coverage           string `json:"coverage"`
	SuccessfulAuthSeen bool   `json:"successful_auth_seen"`
	ImpactDigest       string `json:"impact_digest"`
}

type compactAllowedPolicy struct {
	Action            string `json:"action"`
	TargetIP          string `json:"target_ip"`
	MinimumTTLSeconds int    `json:"minimum_ttl_seconds"`
	DefaultTTLSeconds int    `json:"default_ttl_seconds"`
	MaximumTTLSeconds int    `json:"maximum_ttl_seconds"`
	Table             string `json:"table"`
	Set               string `json:"set"`
}

type outputDocument struct {
	SchemaVersion        string          `json:"schema_version"`
	IncidentSummary      string          `json:"incident_summary"`
	Classification       string          `json:"classification"`
	Confidence           float64         `json:"confidence"`
	Uncertainty          string          `json:"uncertainty"`
	FalsePositiveFactors []string        `json:"false_positive_factors"`
	EvidenceIDs          []string        `json:"evidence_ids"`
	Policy               outputPolicy    `json:"policy"`
	Candidate            outputCandidate `json:"nftables_command_candidate"`
}

type outputPolicy struct {
	SchemaVersion string   `json:"schema_version"`
	Action        string   `json:"action"`
	TargetIP      string   `json:"target_ip"`
	TTLSeconds    int      `json:"ttl_seconds"`
	EvidenceIDs   []string `json:"evidence_ids"`
	Rationale     string   `json:"rationale"`
}

type outputCandidate struct {
	SchemaVersion string   `json:"schema_version"`
	TargetIP      string   `json:"target_ip"`
	Timeout       string   `json:"timeout"`
	EvidenceIDs   []string `json:"evidence_ids"`
	Command       string   `json:"command"`
}

func validInput(value compactInput) bool {
	address, addressErr := netip.ParseAddr(value.SourceIP)
	generatedAt, generatedErr := parseTime(value.GeneratedAt)
	windowStart, startErr := parseTime(value.WindowStart)
	windowEnd, endErr := parseTime(value.WindowEnd)
	lookbackStart, lookbackStartErr := parseTime(value.HistoricalImpact.LookbackStart)
	lookbackEnd, lookbackEndErr := parseTime(value.HistoricalImpact.LookbackEnd)
	if value.SchemaVersion != analysisworker.AnalysisInputSchemaVersion ||
		value.PromptVersion != analysisworker.PromptVersion ||
		value.OutputSchemaVersion != analysisworker.OutputSchemaVersion ||
		!uuidPattern.MatchString(value.IncidentID) || value.IncidentVersion < 1 ||
		!uuidPattern.MatchString(value.AnalysisAttemptID) ||
		generatedErr != nil || startErr != nil || endErr != nil ||
		lookbackStartErr != nil || lookbackEndErr != nil ||
		windowEnd.Before(windowStart) || lookbackEnd.Before(lookbackStart) ||
		generatedAt.Before(windowEnd) || addressErr != nil || !address.Is4() ||
		address.String() != value.SourceIP || !identifierPattern.MatchString(value.ServiceLabel) ||
		!identifierPattern.MatchString(value.DetectorVersion) || value.SourceHealthStatus != "complete" ||
		value.HistoricalImpact.Coverage != "complete" ||
		!digestPattern.MatchString(value.HistoricalImpact.ImpactDigest) ||
		len(value.Signals) == 0 || len(value.Signals) > ai.MaxEvidenceRefs ||
		len(value.EvidenceRefs) != len(value.Signals) ||
		value.AllowedPolicy.Action != "block_ip" || value.AllowedPolicy.TargetIP != value.SourceIP ||
		value.AllowedPolicy.MinimumTTLSeconds != analysisworker.DefaultMinimumTTLSeconds ||
		value.AllowedPolicy.DefaultTTLSeconds != defaultTTLSeconds ||
		value.AllowedPolicy.MaximumTTLSeconds != analysisworker.DefaultMaximumTTLSeconds ||
		value.AllowedPolicy.Table != "sentinelflow" || value.AllowedPolicy.Set != "blacklist_ipv4" {
		return false
	}

	previous := ""
	for index, signal := range value.Signals {
		reference := value.EvidenceRefs[index]
		signalStart, signalStartErr := parseTime(signal.WindowStart)
		signalEnd, signalEndErr := parseTime(signal.WindowEnd)
		expectedClass, knownRule := ruleClassifications[signal.RuleID]
		if !uuidPattern.MatchString(signal.SignalID) || signal.SignalID <= previous || !knownRule ||
			signal.Classification != expectedClass || signalStartErr != nil || signalEndErr != nil ||
			signalEnd.Before(signalStart) || signalStart.Before(windowStart) || signalEnd.After(windowEnd) ||
			signal.EventCount < 1 || signal.EventCount > 1_000_000 ||
			signal.DistinctAccountCount < 0 || signal.DistinctAccountCount > 1_000_000 ||
			signal.DistinctSuspiciousPathCount < 0 || signal.DistinctSuspiciousPathCount > 8 ||
			!digestPattern.MatchString(signal.EvidenceDigest) ||
			reference.EvidenceID != signal.SignalID || reference.Kind != "deterministic_signal" ||
			reference.RuleID != signal.RuleID || reference.SignalDigest != signal.EvidenceDigest ||
			reference.ExpandedEventCount != signal.EventCount {
			return false
		}
		previous = signal.SignalID
	}
	return sort.StringsAreSorted(evidenceIDs(value.EvidenceRefs))
}

func evidenceIDs(values []compactEvidenceRef) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.EvidenceID
	}
	return result
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errInvalidInput
	}
	return parsed, nil
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, current := range value {
		if current < 0x20 || current == 0x7f {
			return false
		}
	}
	return true
}
