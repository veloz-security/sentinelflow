package analysisworker

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"time"

	"github.com/devwooops/sentinelflow/internal/ai"
)

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	servicePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	versionPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
)

var ruleClassifications = map[string]string{
	"path_scan.v1":           "path_scan",
	"request_burst.v1":       "request_burst",
	"login_bruteforce.v1":    "brute_force",
	"credential_stuffing.v1": "credential_stuffing",
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

func buildInput(snapshot Snapshot) ([]byte, ai.FailureReason) {
	if reason := validateSnapshot(snapshot); reason != "" {
		return nil, reason
	}
	input := compactInput{
		SchemaVersion: AnalysisInputSchemaVersion, IncidentID: snapshot.IncidentID,
		IncidentVersion: snapshot.IncidentVersion, AnalysisAttemptID: snapshot.AnalysisID,
		GeneratedAt: snapshot.GeneratedAt.UTC().Format(time.RFC3339Nano), PromptVersion: PromptVersion,
		OutputSchemaVersion: OutputSchemaVersion, SourceIP: snapshot.SourceIP,
		ServiceLabel: snapshot.ServiceLabel, WindowStart: timestamp(snapshot.WindowStart),
		WindowEnd: timestamp(snapshot.WindowEnd), DetectorVersion: snapshot.DetectorConfigVersion,
		SourceHealthStatus: "complete",
		Signals:            make([]compactSignal, 0, len(snapshot.Signals)),
		EvidenceRefs:       make([]compactEvidenceRef, 0, len(snapshot.Signals)),
		HistoricalImpact: compactHistory{
			LookbackStart: timestamp(snapshot.HistoricalImpact.LookbackStart),
			LookbackEnd:   timestamp(snapshot.HistoricalImpact.LookbackEnd), Coverage: "complete",
			SuccessfulAuthSeen: false, ImpactDigest: snapshot.HistoricalImpact.ImpactDigest,
		},
		AllowedPolicy: compactAllowedPolicy{
			Action: "block_ip", TargetIP: snapshot.SourceIP,
			MinimumTTLSeconds: DefaultMinimumTTLSeconds, DefaultTTLSeconds: DefaultTTLSeconds,
			MaximumTTLSeconds: DefaultMaximumTTLSeconds, Table: "sentinelflow", Set: "blacklist_ipv4",
		},
	}
	for _, signal := range snapshot.Signals {
		input.Signals = append(input.Signals, compactSignal{
			SignalID: signal.SignalID, RuleID: signal.RuleID, Classification: signal.Classification,
			WindowStart: timestamp(signal.WindowStart), WindowEnd: timestamp(signal.WindowEnd),
			EventCount: signal.EventCount, DistinctAccountCount: signal.DistinctAccountCount,
			DistinctSuspiciousPathCount: signal.DistinctSuspiciousPathCount,
			EvidenceDigest:              signal.EvidenceDigest,
		})
		input.EvidenceRefs = append(input.EvidenceRefs, compactEvidenceRef{
			EvidenceID: signal.SignalID, Kind: "deterministic_signal", RuleID: signal.RuleID,
			SignalDigest: signal.EvidenceDigest, ExpandedEventCount: signal.EventCount,
		})
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, ai.FailureConfiguration
	}
	if len(encoded) > ai.MaxInputBytes {
		return encoded, ai.FailureInputTooLarge
	}
	return encoded, ""
}

func validateSnapshot(snapshot Snapshot) ai.FailureReason {
	address, addressErr := netip.ParseAddr(snapshot.SourceIP)
	if !uuidPattern.MatchString(snapshot.IncidentID) || snapshot.IncidentVersion < 1 ||
		!uuidPattern.MatchString(snapshot.AnalysisID) || !uuidPattern.MatchString(snapshot.EvidenceSnapshotID) ||
		!digestPattern.MatchString(snapshot.EvidenceSnapshotDigest) || addressErr != nil ||
		!address.Is4() || address.String() != snapshot.SourceIP ||
		!servicePattern.MatchString(snapshot.ServiceLabel) ||
		!versionPattern.MatchString(snapshot.DetectorConfigVersion) || snapshot.GeneratedAt.IsZero() ||
		!orderedWindow(snapshot.WindowStart, snapshot.WindowEnd) || len(snapshot.Signals) == 0 {
		return ai.FailureSchemaInvalid
	}
	if len(snapshot.Signals) > MaxSignals || len(snapshot.Signals) > ai.MaxEvidenceRefs {
		return ai.FailureInputTooLarge
	}
	if !orderedWindow(snapshot.HistoricalImpact.LookbackStart, snapshot.HistoricalImpact.LookbackEnd) ||
		!digestPattern.MatchString(snapshot.HistoricalImpact.ImpactDigest) {
		return ai.FailureEvidenceInvalid
	}
	previous := ""
	for index, signal := range snapshot.Signals {
		expectedClass, knownRule := ruleClassifications[signal.RuleID]
		if !uuidPattern.MatchString(signal.SignalID) || (index > 0 && signal.SignalID <= previous) ||
			!knownRule || signal.Classification != expectedClass ||
			!orderedWindow(signal.WindowStart, signal.WindowEnd) ||
			signal.WindowStart.Before(snapshot.WindowStart) || signal.WindowEnd.After(snapshot.WindowEnd) ||
			signal.EventCount < 1 || signal.EventCount > 1_000_000 ||
			signal.DistinctAccountCount < 0 || signal.DistinctAccountCount > 1_000_000 ||
			signal.DistinctSuspiciousPathCount < 0 || signal.DistinctSuspiciousPathCount > 8 ||
			!digestPattern.MatchString(signal.EvidenceDigest) {
			return ai.FailureEvidenceInvalid
		}
		previous = signal.SignalID
	}
	return ""
}

func orderedWindow(start, end time.Time) bool {
	return !start.IsZero() && !end.IsZero() && !end.Before(start)
}

func timestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
