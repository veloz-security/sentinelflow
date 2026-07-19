package ai

import (
	"bytes"
	"encoding/json"
	"regexp"
	"unicode/utf8"
)

var stableIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type compactInput struct {
	SchemaVersion       string          `json:"schema_version"`
	PromptVersion       string          `json:"prompt_version"`
	OutputSchemaVersion string          `json:"output_schema_version"`
	SourceHealthStatus  string          `json:"source_health_status"`
	Signals             []compactSignal `json:"signals"`
	EvidenceRefs        []evidenceRef   `json:"evidence_refs"`
	AllowedPolicy       struct {
		TargetIP string `json:"target_ip"`
	} `json:"allowed_policy"`
}

type compactSignal struct {
	SignalID       string `json:"signal_id"`
	RuleID         string `json:"rule_id"`
	EventCount     int64  `json:"event_count"`
	EvidenceDigest string `json:"evidence_digest"`
}

type evidenceRef struct {
	EvidenceID         string `json:"evidence_id"`
	RuleID             string `json:"rule_id"`
	SignalDigest       string `json:"signal_digest"`
	ExpandedEventCount int64  `json:"expanded_event_count"`
}

type validatedInput struct {
	bytes       []byte
	digest      string
	evidenceIDs map[string]struct{}
	targetIP    string
}

func validateInput(input []byte) (validatedInput, error) {
	if len(input) > MaxInputBytes {
		return validatedInput{}, &Failure{Reason: FailureInputTooLarge}
	}
	if len(input) == 0 || !utf8.Valid(input) || validateJSONDocument(input, true) != nil {
		return validatedInput{}, &Failure{Reason: FailureSchemaInvalid}
	}

	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var parsed compactInput
	if err := decoder.Decode(&parsed); err != nil {
		// Full checked-schema validation is owned by M4-001. This transport
		// boundary still requires its security-relevant envelope and rejects
		// duplicate JSON before any network call.
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(input, &envelope); err != nil {
			return validatedInput{}, &Failure{Reason: FailureSchemaInvalid}
		}
		if err := json.Unmarshal(envelope["schema_version"], &parsed.SchemaVersion); err != nil ||
			json.Unmarshal(envelope["prompt_version"], &parsed.PromptVersion) != nil ||
			json.Unmarshal(envelope["output_schema_version"], &parsed.OutputSchemaVersion) != nil ||
			json.Unmarshal(envelope["source_health_status"], &parsed.SourceHealthStatus) != nil ||
			json.Unmarshal(envelope["signals"], &parsed.Signals) != nil ||
			json.Unmarshal(envelope["evidence_refs"], &parsed.EvidenceRefs) != nil {
			return validatedInput{}, &Failure{Reason: FailureSchemaInvalid}
		}
		var allowed struct {
			TargetIP string `json:"target_ip"`
		}
		if json.Unmarshal(envelope["allowed_policy"], &allowed) != nil {
			return validatedInput{}, &Failure{Reason: FailureSchemaInvalid}
		}
		parsed.AllowedPolicy.TargetIP = allowed.TargetIP
	}

	if parsed.SchemaVersion != "sentinelflow_analysis_input_v1" ||
		parsed.PromptVersion != "sentinelflow_system_prompt_v1" ||
		parsed.OutputSchemaVersion != "sentinelflow_analysis_v1" ||
		parsed.SourceHealthStatus != "complete" {
		return validatedInput{}, &Failure{Reason: FailureSchemaInvalid}
	}
	if len(parsed.EvidenceRefs) > MaxEvidenceRefs {
		return validatedInput{}, &Failure{Reason: FailureInputTooLarge}
	}
	if len(parsed.EvidenceRefs) == 0 || len(parsed.Signals) != len(parsed.EvidenceRefs) {
		return validatedInput{}, &Failure{Reason: FailureEvidenceInvalid}
	}

	ids := make(map[string]struct{}, len(parsed.EvidenceRefs))
	previousRef, previousSignal := "", ""
	for index, ref := range parsed.EvidenceRefs {
		signal := parsed.Signals[index]
		if !stableIDPattern.MatchString(ref.EvidenceID) || !stableIDPattern.MatchString(signal.SignalID) ||
			(index > 0 && (ref.EvidenceID <= previousRef || signal.SignalID <= previousSignal)) ||
			ref.EvidenceID != signal.SignalID || ref.RuleID == "" || ref.RuleID != signal.RuleID ||
			ref.SignalDigest == "" || ref.SignalDigest != signal.EvidenceDigest ||
			ref.ExpandedEventCount < 1 || ref.ExpandedEventCount != signal.EventCount {
			return validatedInput{}, &Failure{Reason: FailureEvidenceInvalid}
		}
		if _, duplicate := ids[ref.EvidenceID]; duplicate {
			return validatedInput{}, &Failure{Reason: FailureEvidenceInvalid}
		}
		ids[ref.EvidenceID] = struct{}{}
		previousRef, previousSignal = ref.EvidenceID, signal.SignalID
	}
	if parsed.AllowedPolicy.TargetIP == "" {
		return validatedInput{}, &Failure{Reason: FailureSchemaInvalid}
	}
	return validatedInput{
		bytes:       bytes.Clone(input),
		digest:      digest(input),
		evidenceIDs: ids,
		targetIP:    parsed.AllowedPolicy.TargetIP,
	}, nil
}
