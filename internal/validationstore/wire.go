package validationstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/validationworker"
)

type snapshotDocument struct {
	ValidationAttemptID    string `json:"validation_attempt_id"`
	PolicyID               string `json:"policy_id"`
	ValidationID           string `json:"validation_id"`
	CommandCandidateID     string `json:"command_candidate_id"`
	AnalysisID             string `json:"analysis_id"`
	IncidentID             string `json:"incident_id"`
	IncidentVersion        uint32 `json:"incident_version"`
	GeneratedAt            string `json:"generated_at"`
	EvidenceSnapshotID     string `json:"evidence_snapshot_id"`
	EvidenceSnapshotDigest string `json:"evidence_snapshot_digest"`
	AnalysisInputDigest    string `json:"analysis_input_digest"`
	OutputSchemaDigest     string `json:"output_schema_digest"`
	PromptDigest           string `json:"prompt_digest"`
	AnalysisOutputDigest   string `json:"analysis_output_digest"`
	GeneratedCommandDigest string `json:"generated_command_digest"`
	StructuredOutputHex    string `json:"structured_output_hex"`
	PolicyOutputHex        string `json:"policy_output_hex"`
	CandidateOutputHex     string `json:"command_candidate_output_hex"`
	Evidence               struct {
		SourceIPv4         string           `json:"source_ipv4"`
		ServiceLabel       string           `json:"service_label"`
		SourceHealthDigest string           `json:"source_health_digest"`
		SourceHealthStatus string           `json:"source_health_status"`
		SignalIDs          []string         `json:"signal_ids"`
		EventIDs           []string         `json:"event_ids"`
		Signals            []signalDocument `json:"signals"`
	} `json:"evidence"`
	History struct {
		Cutoff           string            `json:"cutoff"`
		WindowStart      string            `json:"window_start"`
		CoverageComplete bool              `json:"coverage_complete"`
		GatewayRecords   []gatewayDocument `json:"gateway_records"`
		AuthRecords      []authDocument    `json:"auth_records"`
	} `json:"history"`
}

type signalDocument struct {
	SignalID            string   `json:"signal_id"`
	SignalDigest        string   `json:"signal_digest"`
	SourceIPv4          string   `json:"source_ipv4"`
	EventIDs            []string `json:"event_ids"`
	ThresholdReproduced bool     `json:"threshold_reproduced"`
	SourceHealthStatus  string   `json:"source_health_status"`
}

type gatewayDocument struct {
	EventID        string `json:"event_id"`
	OccurredAt     string `json:"occurred_at"`
	SourceIPv4     string `json:"source_ipv4"`
	StatusCode     int    `json:"status_code"`
	TimestampTrust string `json:"timestamp_trust"`
}

type authDocument struct {
	EventID        string `json:"event_id"`
	OccurredAt     string `json:"occurred_at"`
	SourceIPv4     string `json:"source_ipv4"`
	Outcome        string `json:"outcome"`
	TimestampTrust string `json:"timestamp_trust"`
	Binding        string `json:"binding"`
}

func decodeSnapshot(document, evidenceCanonical []byte) (validationworker.Snapshot, error) {
	if len(document) < 2 || len(document) > validationworker.MaxPreparedSnapshotBytes ||
		!utf8.Valid(document) || hasDuplicateJSONName(document) {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var decoded snapshotDocument
	if err := decoder.Decode(&decoded); err != nil {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	generatedAt, ok := parseTime(decoded.GeneratedAt)
	if !ok {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	cutoff, ok := parseTime(decoded.History.Cutoff)
	if !ok {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	windowStart, ok := parseTime(decoded.History.WindowStart)
	if !ok {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	structured, ok := decodeHex(decoded.StructuredOutputHex, 2, 1<<20)
	if !ok {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	policyOutput, ok := decodeHex(decoded.PolicyOutputHex, 2, 64*1024)
	if !ok {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	candidateOutput, ok := decodeHex(decoded.CandidateOutputHex, 2, 64*1024)
	if !ok {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	signals := make([]validationworker.SignalBinding, len(decoded.Evidence.Signals))
	for index, item := range decoded.Evidence.Signals {
		signals[index] = validationworker.SignalBinding{
			SignalID: item.SignalID, SignalDigest: item.SignalDigest,
			SourceIPv4: item.SourceIPv4, EventIDs: clone(item.EventIDs),
			ThresholdReproduced: item.ThresholdReproduced,
			SourceHealthStatus:  item.SourceHealthStatus,
		}
	}
	gateway := make([]validation.HistoricalGatewayRecord, len(decoded.History.GatewayRecords))
	for index, item := range decoded.History.GatewayRecords {
		at, valid := parseTime(item.OccurredAt)
		if !valid {
			return validationworker.Snapshot{}, ErrInvalidRow
		}
		gateway[index] = validation.HistoricalGatewayRecord{
			EventID: item.EventID, OccurredAt: at, SourceIPv4: item.SourceIPv4,
			StatusCode: item.StatusCode, TimestampTrust: detection.TimestampTrust(item.TimestampTrust),
		}
	}
	auth := make([]validation.HistoricalAuthRecord, len(decoded.History.AuthRecords))
	for index, item := range decoded.History.AuthRecords {
		at, valid := parseTime(item.OccurredAt)
		if !valid {
			return validationworker.Snapshot{}, ErrInvalidRow
		}
		auth[index] = validation.HistoricalAuthRecord{
			EventID: item.EventID, OccurredAt: at, SourceIPv4: item.SourceIPv4,
			Outcome: events.AuthOutcome(item.Outcome), TimestampTrust: detection.TimestampTrust(item.TimestampTrust),
			Binding: detection.BindingState(item.Binding),
		}
	}
	snapshot := validationworker.Snapshot{
		ValidationAttemptID: decoded.ValidationAttemptID,
		PolicyID:            decoded.PolicyID, ValidationID: decoded.ValidationID,
		CommandCandidateID: decoded.CommandCandidateID, AnalysisID: decoded.AnalysisID,
		IncidentID: decoded.IncidentID, IncidentVersion: decoded.IncidentVersion,
		GeneratedAt: generatedAt, EvidenceSnapshotID: decoded.EvidenceSnapshotID,
		EvidenceSnapshotDigest: decoded.EvidenceSnapshotDigest,
		EvidenceCanonicalBytes: bytes.Clone(evidenceCanonical),
		AnalysisInputDigest:    decoded.AnalysisInputDigest,
		OutputSchemaDigest:     decoded.OutputSchemaDigest, PromptDigest: decoded.PromptDigest,
		AnalysisOutputDigest:   decoded.AnalysisOutputDigest,
		GeneratedCommandDigest: decoded.GeneratedCommandDigest,
		StructuredOutput:       structured, PolicyOutput: policyOutput,
		CommandCandidateOutput: candidateOutput,
		Evidence: validationworker.EvidenceBinding{
			SourceIPv4: decoded.Evidence.SourceIPv4, ServiceLabel: decoded.Evidence.ServiceLabel,
			SourceHealthDigest: decoded.Evidence.SourceHealthDigest,
			SourceHealthStatus: decoded.Evidence.SourceHealthStatus,
			SignalIDs:          clone(decoded.Evidence.SignalIDs), EventIDs: clone(decoded.Evidence.EventIDs),
			Signals: signals,
		},
		History: validationworker.HistorySnapshot{
			Cutoff: cutoff, WindowStart: windowStart,
			CoverageComplete: decoded.History.CoverageComplete,
			GatewayRecords:   gateway, AuthRecords: auth,
		},
	}
	if !validSnapshot(snapshot) {
		return validationworker.Snapshot{}, ErrInvalidRow
	}
	return snapshot, nil
}

func validSnapshot(value validationworker.Snapshot) bool {
	if !uuidPattern.MatchString(value.ValidationAttemptID) || !uuidPattern.MatchString(value.PolicyID) ||
		!uuidPattern.MatchString(value.ValidationID) || !uuidPattern.MatchString(value.CommandCandidateID) ||
		!uuidPattern.MatchString(value.AnalysisID) || !uuidPattern.MatchString(value.IncidentID) ||
		value.IncidentVersion < 1 || value.GeneratedAt.IsZero() ||
		!uuidPattern.MatchString(value.EvidenceSnapshotID) ||
		!allDigests(value.EvidenceSnapshotDigest, value.AnalysisInputDigest,
			value.OutputSchemaDigest, value.PromptDigest, value.AnalysisOutputDigest,
			value.GeneratedCommandDigest, value.Evidence.SourceHealthDigest) ||
		(value.Evidence.SourceHealthStatus != validation.SourceHealthComplete &&
			value.Evidence.SourceHealthStatus != "incomplete") ||
		!canonicalIPv4(value.Evidence.SourceIPv4) || !asciiIDPattern.MatchString(value.Evidence.ServiceLabel) ||
		!orderedUUIDs(value.Evidence.SignalIDs, policy.MaxEvidenceIDs) ||
		!orderedUUIDs(value.Evidence.EventIDs, 0) || len(value.Evidence.Signals) != len(value.Evidence.SignalIDs) ||
		len(value.History.GatewayRecords) > validationworker.MaxHistoricalGatewayRows ||
		len(value.History.AuthRecords) > validationworker.MaxHistoricalAuthRows ||
		value.History.Cutoff.IsZero() ||
		!value.History.WindowStart.Equal(value.History.Cutoff.Add(-validation.HistoricalImpactLookback)) ||
		digest(value.StructuredOutput) != value.AnalysisOutputDigest {
		return false
	}
	checkedEvidence, err := validation.ParseCanonicalEvidenceSnapshot(value.EvidenceCanonicalBytes)
	if err != nil || checkedEvidence.Digest() != value.EvidenceSnapshotDigest {
		return false
	}
	evidence := checkedEvidence.Value()
	if evidence.SnapshotID != value.EvidenceSnapshotID || evidence.IncidentID != value.IncidentID ||
		evidence.IncidentVersion != value.IncidentVersion || evidence.SourceIPv4 != value.Evidence.SourceIPv4 ||
		evidence.ServiceLabel != value.Evidence.ServiceLabel ||
		evidence.SourceHealthDigest != value.Evidence.SourceHealthDigest ||
		!sameStrings(evidence.SignalIDs, value.Evidence.SignalIDs) ||
		!sameStrings(evidence.EventIDs, value.Evidence.EventIDs) {
		return false
	}
	for index, signal := range value.Evidence.Signals {
		if signal.SignalID != value.Evidence.SignalIDs[index] ||
			!digestPattern.MatchString(signal.SignalDigest) || signal.SourceIPv4 != value.Evidence.SourceIPv4 ||
			!orderedUUIDs(signal.EventIDs, 0) ||
			(signal.SourceHealthStatus != validation.SourceHealthComplete && signal.SourceHealthStatus != "incomplete") {
			return false
		}
	}
	previous := ""
	for _, record := range value.History.GatewayRecords {
		if !uuidPattern.MatchString(record.EventID) || record.EventID <= previous ||
			record.OccurredAt.Before(value.History.WindowStart) || record.OccurredAt.After(value.History.Cutoff) ||
			record.SourceIPv4 != value.Evidence.SourceIPv4 || record.StatusCode < 100 || record.StatusCode > 599 ||
			(record.TimestampTrust != detection.TimestampTrusted && record.TimestampTrust != detection.TimestampUntrusted) {
			return false
		}
		previous = record.EventID
	}
	previous = ""
	for _, record := range value.History.AuthRecords {
		if !uuidPattern.MatchString(record.EventID) || record.EventID <= previous ||
			record.OccurredAt.Before(value.History.WindowStart) || record.OccurredAt.After(value.History.Cutoff) ||
			record.SourceIPv4 != value.Evidence.SourceIPv4 ||
			(record.Outcome != events.AuthOutcomeFailed && record.Outcome != events.AuthOutcomeSucceeded) ||
			(record.TimestampTrust != detection.TimestampTrusted && record.TimestampTrust != detection.TimestampUntrusted) ||
			(record.Binding != detection.BindingVerified && record.Binding != detection.BindingPending &&
				record.Binding != detection.BindingUntrusted) {
			return false
		}
		previous = record.EventID
	}
	return true
}

type mutationWire struct {
	ValidationAttemptID string          `json:"validation_attempt_id"`
	AnalysisID          string          `json:"analysis_id"`
	IncidentID          string          `json:"incident_id"`
	IncidentVersion     uint32          `json:"incident_version"`
	State               string          `json:"state"`
	FailureCode         string          `json:"failure_code"`
	AuditAction         string          `json:"audit_action"`
	Gates               []gateWire      `json:"gates"`
	Candidate           *candidateWire  `json:"candidate"`
	Policy              *policyWire     `json:"policy"`
	Validation          *validationWire `json:"validation"`
}

type gateWire struct {
	Order        uint8  `json:"order"`
	Name         string `json:"name"`
	Passed       bool   `json:"passed"`
	ResultCode   string `json:"result_code"`
	InputDigest  string `json:"input_digest"`
	ResultDigest string `json:"result_digest"`
}

type candidateWire struct {
	SchemaVersion   string `json:"schema_version"`
	TargetIPv4      string `json:"target_ipv4"`
	TimeoutToken    string `json:"timeout_token"`
	TTLSeconds      uint32 `json:"ttl_seconds"`
	GeneratedHex    string `json:"generated_hex"`
	GeneratedDigest string `json:"generated_digest"`
	CanonicalHex    string `json:"canonical_hex"`
	CanonicalDigest string `json:"canonical_digest"`
}

type policyWire struct {
	SchemaVersion string `json:"schema_version"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion uint32 `json:"policy_version"`
	CanonicalHex  string `json:"canonical_hex"`
	PolicyDigest  string `json:"policy_digest"`
	TargetIPv4    string `json:"target_ipv4"`
	TTLSeconds    uint32 `json:"ttl_seconds"`
	Rationale     string `json:"rationale"`
}

type validationWire struct {
	CanonicalHex                       string `json:"canonical_hex"`
	SnapshotDigest                     string `json:"snapshot_digest"`
	PolicyDigest                       string `json:"policy_digest"`
	EvidenceSnapshotDigest             string `json:"evidence_snapshot_digest"`
	AnalysisInputDigest                string `json:"analysis_input_digest"`
	AnalysisOutputSchemaDigest         string `json:"analysis_output_schema_digest"`
	PromptDigest                       string `json:"prompt_digest"`
	GeneratedCandidateDigest           string `json:"generated_candidate_digest"`
	CanonicalArtifactDigest            string `json:"canonical_artifact_digest"`
	GrammarVersion                     string `json:"grammar_version"`
	ParserVersion                      string `json:"parser_version"`
	ValidatorVersion                   string `json:"validator_version"`
	BaseChainContractRawDigest         string `json:"base_chain_contract_raw_digest"`
	LiveOwnedSchemaDigest              string `json:"live_owned_schema_digest"`
	ProtectedIPv4StaticDigest          string `json:"protected_ipv4_static_digest"`
	ProtectedIPv4EffectiveConfigDigest string `json:"protected_ipv4_effective_config_digest"`
	NFTBinaryDigest                    string `json:"nft_binary_digest"`
	NFTVersion                         string `json:"nft_version"`
	HistoricalImpactDigest             string `json:"historical_impact_digest"`
	TargetIPv4                         string `json:"target_ipv4"`
	TTLSeconds                         uint32 `json:"ttl_seconds"`
	SourceHealthStatus                 string `json:"source_health_status"`
	CreatedAt                          string `json:"created_at"`
	ValidUntil                         string `json:"valid_until"`
}

func encodeMutation(value *validationworker.Mutation) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	wire := mutationWire{
		ValidationAttemptID: value.ValidationAttemptID, AnalysisID: value.AnalysisID,
		IncidentID: value.IncidentID, IncidentVersion: value.IncidentVersion,
		State: string(value.State), FailureCode: value.FailureCode, AuditAction: value.AuditAction,
		Gates: make([]gateWire, len(value.Gates)),
	}
	for index, gate := range value.Gates {
		wire.Gates[index] = gateWire{gate.Order, string(gate.Name), gate.Passed, gate.ResultCode, gate.InputDigest, gate.ResultDigest}
	}
	if value.Candidate != nil {
		wire.Candidate = &candidateWire{
			SchemaVersion: value.Candidate.SchemaVersion, TargetIPv4: value.Candidate.TargetIPv4,
			TimeoutToken: value.Candidate.TimeoutToken, TTLSeconds: value.Candidate.TTLSeconds,
			GeneratedHex:    hex.EncodeToString(value.Candidate.GeneratedBytes),
			GeneratedDigest: value.Candidate.GeneratedDigest,
			CanonicalHex:    hex.EncodeToString(value.Candidate.CanonicalBytes),
			CanonicalDigest: value.Candidate.CanonicalDigest,
		}
	}
	if value.Policy != nil {
		wire.Policy = &policyWire{
			SchemaVersion: value.Policy.SchemaVersion, PolicyID: value.Policy.PolicyID,
			PolicyVersion: value.Policy.PolicyVersion,
			CanonicalHex:  hex.EncodeToString(value.Policy.CanonicalBytes), PolicyDigest: value.Policy.PolicyDigest,
			TargetIPv4: value.Policy.TargetIPv4, TTLSeconds: value.Policy.TTLSeconds,
			Rationale: value.Policy.Rationale,
		}
	}
	if value.Validation != nil {
		item := value.Validation
		wire.Validation = &validationWire{
			CanonicalHex: hex.EncodeToString(item.CanonicalBytes), SnapshotDigest: item.SnapshotDigest,
			PolicyDigest: item.PolicyDigest, EvidenceSnapshotDigest: item.EvidenceSnapshotDigest,
			AnalysisInputDigest:        item.AnalysisInputDigest,
			AnalysisOutputSchemaDigest: item.AnalysisOutputSchemaDigest, PromptDigest: item.PromptDigest,
			GeneratedCandidateDigest: item.GeneratedCandidateDigest,
			CanonicalArtifactDigest:  item.CanonicalArtifactDigest,
			GrammarVersion:           item.GrammarVersion, ParserVersion: item.ParserVersion,
			ValidatorVersion:                   item.ValidatorVersion,
			BaseChainContractRawDigest:         item.BaseChainContractRawDigest,
			LiveOwnedSchemaDigest:              item.LiveOwnedSchemaDigest,
			ProtectedIPv4StaticDigest:          item.ProtectedIPv4StaticDigest,
			ProtectedIPv4EffectiveConfigDigest: item.ProtectedIPv4EffectiveConfigDigest,
			NFTBinaryDigest:                    item.NFTBinaryDigest, NFTVersion: item.NFTVersion,
			HistoricalImpactDigest: item.HistoricalImpactDigest, TargetIPv4: item.TargetIPv4,
			TTLSeconds: item.TTLSeconds, SourceHealthStatus: item.SourceHealthStatus,
			CreatedAt:  utc(item.CreatedAt).Format("2006-01-02T15:04:05.999999999Z07:00"),
			ValidUntil: utc(item.ValidUntil).Format("2006-01-02T15:04:05.999999999Z07:00"),
		}
	}
	return json.Marshal(wire)
}

func validMutation(value *validationworker.Mutation) bool {
	if value == nil {
		return true
	}
	if !uuidPattern.MatchString(value.ValidationAttemptID) || !uuidPattern.MatchString(value.AnalysisID) ||
		!uuidPattern.MatchString(value.IncidentID) || value.IncidentVersion == 0 ||
		!asciiIDPattern.MatchString(value.FailureCode) || len(value.Gates) < 1 || len(value.Gates) > 6 {
		return false
	}
	checkedEvidence, err := validation.ParseCanonicalEvidenceSnapshot(value.EvidenceCanonicalBytes)
	if err != nil || checkedEvidence.Value().IncidentID != value.IncidentID ||
		checkedEvidence.Value().IncidentVersion != value.IncidentVersion {
		return false
	}
	ordered := [...]validation.ValidationCheckID{
		validation.CheckStructuredOutput, validation.CheckCommandGrammar,
		validation.CheckPolicyEvidenceCommandConsistency, validation.CheckProtectedNetwork,
		validation.CheckOwnedSchemaSyntax, validation.CheckHistoricalImpact,
	}
	for index, gate := range value.Gates {
		if gate.Order != uint8(index+1) || gate.Name != ordered[index] ||
			!asciiIDPattern.MatchString(gate.ResultCode) ||
			!allDigests(gate.InputDigest, gate.ResultDigest) || (!gate.Passed && index != len(value.Gates)-1) ||
			(gate.Passed && gate.ResultCode != "ok") {
			return false
		}
	}
	last := value.Gates[len(value.Gates)-1]
	if value.State == validationworker.StateValid {
		return len(value.Gates) == 6 && last.Passed && value.FailureCode == validationworker.ValidationFailureNone &&
			value.AuditAction == validationworker.ValidationAuditSucceeded &&
			validCandidate(value.Candidate) && validPolicy(value.Policy, value.Candidate) &&
			validValidation(value.Validation, value.Policy, value.Candidate) &&
			value.Validation.EvidenceSnapshotDigest == checkedEvidence.Digest()
	}
	if value.State != validationworker.StateInvalid || last.Passed || value.FailureCode != last.ResultCode ||
		value.FailureCode == validationworker.ValidationFailureNone ||
		value.AuditAction != validationworker.ValidationAuditRejected || value.Validation != nil {
		return false
	}
	if len(value.Gates) <= 2 {
		return value.Candidate == nil && value.Policy == nil
	}
	return validCandidate(value.Candidate) && validPolicy(value.Policy, value.Candidate)
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validCandidate(value *validationworker.CandidateRecord) bool {
	return value != nil && value.SchemaVersion == policy.CandidateSchemaVersion &&
		canonicalIPv4(value.TargetIPv4) && value.TTLSeconds >= policy.MinTTLSeconds &&
		value.TTLSeconds <= policy.MaxTTLSeconds && len(value.GeneratedBytes) > 0 &&
		len(value.GeneratedBytes) <= policy.MaxGeneratedBytes && len(value.CanonicalBytes) > 0 &&
		len(value.CanonicalBytes) <= policy.MaxGeneratedBytes &&
		digest(value.GeneratedBytes) == value.GeneratedDigest &&
		digest(value.CanonicalBytes) == value.CanonicalDigest &&
		timeoutPattern.MatchString(value.TimeoutToken)
}

func validPolicy(value *validationworker.PolicyRecord, candidate *validationworker.CandidateRecord) bool {
	return value != nil && candidate != nil && value.SchemaVersion == policy.PolicySchemaVersion &&
		uuidPattern.MatchString(value.PolicyID) && value.PolicyVersion == 1 &&
		len(value.CanonicalBytes) > 0 && digest(value.CanonicalBytes) == value.PolicyDigest &&
		value.TargetIPv4 == candidate.TargetIPv4 && value.TTLSeconds == candidate.TTLSeconds &&
		utf8.ValidString(value.Rationale) && len([]rune(value.Rationale)) >= 1 && len([]rune(value.Rationale)) <= 800
}

func validValidation(value *validationworker.ValidationRecord, proposal *validationworker.PolicyRecord, candidate *validationworker.CandidateRecord) bool {
	if value == nil || proposal == nil || candidate == nil || len(value.CanonicalBytes) == 0 ||
		digest(value.CanonicalBytes) != value.SnapshotDigest || value.PolicyDigest != proposal.PolicyDigest ||
		value.GeneratedCandidateDigest != candidate.GeneratedDigest ||
		value.CanonicalArtifactDigest != candidate.CanonicalDigest || value.TargetIPv4 != candidate.TargetIPv4 ||
		value.TTLSeconds != candidate.TTLSeconds || value.GrammarVersion != policy.CandidateSchemaVersion ||
		value.ParserVersion != validationworker.ValidationParserVersion ||
		value.ValidatorVersion != validationworker.ValidationValidatorVersion ||
		!nftVersionPattern.MatchString(value.NFTVersion) ||
		value.SourceHealthStatus != validation.SourceHealthComplete || value.CreatedAt.IsZero() ||
		!value.ValidUntil.Equal(value.CreatedAt.Add(validation.ValidationSnapshotLifetime)) {
		return false
	}
	return allDigests(value.SnapshotDigest, value.PolicyDigest, value.EvidenceSnapshotDigest,
		value.AnalysisInputDigest, value.AnalysisOutputSchemaDigest, value.PromptDigest,
		value.GeneratedCandidateDigest, value.CanonicalArtifactDigest,
		value.BaseChainContractRawDigest, value.LiveOwnedSchemaDigest,
		value.ProtectedIPv4StaticDigest, value.ProtectedIPv4EffectiveConfigDigest,
		value.NFTBinaryDigest, value.HistoricalImpactDigest)
}

func hasDuplicateJSONName(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSON(decoder, 0); err != nil {
		return true
	}
	_, err := decoder.Token()
	return !errors.Is(err, io.EOF)
}

func scanJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalidRow
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return ErrInvalidRow
			}
			if _, exists := seen[name]; exists {
				return ErrInvalidRow
			}
			seen[name] = struct{}{}
			if err := scanJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidRow
		}
	case '[':
		for decoder.More() {
			if err := scanJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidRow
		}
	default:
		return ErrInvalidRow
	}
	return nil
}

func parseTime(value string) (timeValue time.Time, valid bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.Year() < 2000 || parsed.Year() > 9999 {
		return time.Time{}, false
	}
	return utc(parsed), true
}

func decodeHex(value string, minimum, maximum int) ([]byte, bool) {
	if len(value)%2 != 0 || len(value) < minimum*2 || len(value) > maximum*2 {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	return decoded, err == nil
}

func orderedUUIDs(values []string, maximum int) bool {
	if len(values) == 0 || (maximum > 0 && len(values) > maximum) {
		return false
	}
	previous := ""
	for _, value := range values {
		if !uuidPattern.MatchString(value) || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func canonicalIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func allDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func clone(values []string) []string { return append([]string(nil), values...) }
