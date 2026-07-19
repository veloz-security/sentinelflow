package validationworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/netip"
	"regexp"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/policy"
	"golang.org/x/text/unicode/norm"
)

var timeoutTokenPattern = regexp.MustCompile(`^[1-9][0-9]{0,4}[smh]$`)

type structuredOutputWire struct {
	SchemaVersion        string        `json:"schema_version"`
	IncidentSummary      string        `json:"incident_summary"`
	Classification       string        `json:"classification"`
	Confidence           float64       `json:"confidence"`
	Uncertainty          string        `json:"uncertainty"`
	FalsePositiveFactors []string      `json:"false_positive_factors"`
	EvidenceIDs          []string      `json:"evidence_ids"`
	Policy               policyWire    `json:"policy"`
	Candidate            candidateWire `json:"nftables_command_candidate"`
}

type policyWire struct {
	SchemaVersion string   `json:"schema_version"`
	Action        string   `json:"action"`
	TargetIP      string   `json:"target_ip"`
	TTLSeconds    uint32   `json:"ttl_seconds"`
	EvidenceIDs   []string `json:"evidence_ids"`
	Rationale     string   `json:"rationale"`
}

type candidateWire struct {
	SchemaVersion string   `json:"schema_version"`
	TargetIP      string   `json:"target_ip"`
	Timeout       string   `json:"timeout"`
	EvidenceIDs   []string `json:"evidence_ids"`
	Command       string   `json:"command"`
}

type stagedOutput struct {
	structured      structuredOutputWire
	checkedPolicy   policy.CheckedResponsePolicy
	rationale       string
	policyForParser policy.Policy
	candidate       policy.Candidate
}

func checkStructuredOutput(snapshot Snapshot) (stagedOutput, string) {
	if len(snapshot.StructuredOutput) < 2 || len(snapshot.StructuredOutput) > 1<<20 ||
		len(snapshot.PolicyOutput) < 2 || len(snapshot.PolicyOutput) > 64*1024 ||
		len(snapshot.CommandCandidateOutput) < 2 || len(snapshot.CommandCandidateOutput) > 64*1024 ||
		policy.Digest(snapshot.StructuredOutput) != snapshot.AnalysisOutputDigest {
		return stagedOutput{}, "structured_output_digest_mismatch"
	}
	var output structuredOutputWire
	if !decodeStrictJSON(snapshot.StructuredOutput, &output) {
		return stagedOutput{}, "structured_output_invalid"
	}
	var policyChild policyWire
	if !decodeStrictJSON(snapshot.PolicyOutput, &policyChild) || !equalPolicyWire(policyChild, output.Policy) {
		return stagedOutput{}, "policy_output_mismatch"
	}
	var candidateChild candidateWire
	if !decodeStrictJSON(snapshot.CommandCandidateOutput, &candidateChild) ||
		!equalCandidateWire(candidateChild, output.Candidate) {
		return stagedOutput{}, "command_output_mismatch"
	}
	if output.SchemaVersion != validationOutputSchemaVersion ||
		!boundedText(output.IncidentSummary, 1, 1600) ||
		!validClassification(output.Classification) ||
		math.IsNaN(output.Confidence) || math.IsInf(output.Confidence, 0) ||
		output.Confidence < 0 || output.Confidence > 1 ||
		!boundedText(output.Uncertainty, 0, 800) || len(output.FalsePositiveFactors) > 5 ||
		!validEvidenceIDs(output.EvidenceIDs) {
		return stagedOutput{}, "structured_output_invalid"
	}
	for _, factor := range output.FalsePositiveFactors {
		if !boundedText(factor, 1, 240) {
			return stagedOutput{}, "structured_output_invalid"
		}
	}
	address, err := netip.ParseAddr(output.Policy.TargetIP)
	if err != nil || !address.Is4() || address.String() != output.Policy.TargetIP ||
		output.Policy.SchemaVersion != policy.PolicySchemaVersion ||
		output.Policy.Action != policy.ActionBlockIP ||
		output.Policy.TTLSeconds < policy.MinTTLSeconds || output.Policy.TTLSeconds > policy.MaxTTLSeconds ||
		!equalStrings(output.Policy.EvidenceIDs, output.EvidenceIDs) ||
		!boundedText(output.Policy.Rationale, 1, 800) {
		return stagedOutput{}, "policy_schema_invalid"
	}
	candidateAddress, err := netip.ParseAddr(output.Candidate.TargetIP)
	if err != nil || !candidateAddress.Is4() || candidateAddress.String() != output.Candidate.TargetIP ||
		output.Candidate.SchemaVersion != policy.CandidateSchemaVersion ||
		output.Candidate.TargetIP != output.Policy.TargetIP ||
		!timeoutTokenPattern.MatchString(output.Candidate.Timeout) ||
		!equalStrings(output.Candidate.EvidenceIDs, output.EvidenceIDs) ||
		!boundedText(output.Candidate.Command, 1, policy.MaxGeneratedBytes) {
		return stagedOutput{}, "command_schema_invalid"
	}
	if output.Policy.TargetIP != snapshot.Evidence.SourceIPv4 ||
		!equalStrings(output.EvidenceIDs, snapshot.Evidence.SignalIDs) {
		return stagedOutput{}, "evidence_binding_mismatch"
	}
	generated := []byte(output.Candidate.Command)
	if policy.Digest(generated) != snapshot.GeneratedCommandDigest {
		return stagedOutput{}, "generated_command_digest_mismatch"
	}
	rationale := norm.NFC.String(output.Policy.Rationale)
	checked, err := policy.CheckResponsePolicy(policy.ResponsePolicy{
		SchemaVersion: policy.PolicySchemaVersion,
		PolicyID:      snapshot.PolicyID, PolicyVersion: 1,
		IncidentID: snapshot.IncidentID, AnalysisID: snapshot.AnalysisID,
		Action: output.Policy.Action, TargetIPv4: output.Policy.TargetIP,
		TTLSeconds:             output.Policy.TTLSeconds,
		EvidenceSnapshotDigest: snapshot.EvidenceSnapshotDigest,
		EvidenceIDs:            append([]string(nil), output.EvidenceIDs...),
		RationaleDigest:        policy.Digest([]byte(rationale)),
		CreatedAt:              snapshot.GeneratedAt,
	})
	if err != nil {
		return stagedOutput{}, "policy_contract_invalid"
	}
	return stagedOutput{
		structured: output, checkedPolicy: checked, rationale: rationale,
		policyForParser: policy.Policy{
			SchemaVersion: output.Policy.SchemaVersion, Action: output.Policy.Action,
			TargetIPv4: output.Policy.TargetIP, TTLSeconds: output.Policy.TTLSeconds,
			EvidenceIDs: append([]string(nil), output.Policy.EvidenceIDs...),
		},
		candidate: policy.Candidate{
			SchemaVersion: output.Candidate.SchemaVersion, TargetIPv4: output.Candidate.TargetIP,
			TimeoutToken:   output.Candidate.Timeout,
			EvidenceIDs:    append([]string(nil), output.Candidate.EvidenceIDs...),
			GeneratedBytes: append([]byte(nil), generated...),
		},
	}, ""
}

const validationOutputSchemaVersion = "sentinelflow_analysis_v1"

func decodeStrictJSON(data []byte, destination any) bool {
	if !utf8.Valid(data) || hasDuplicateJSONName(data) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func hasDuplicateJSONName(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return true
	}
	_, err := decoder.Token()
	return !errors.Is(err, io.EOF)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("json depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("json name")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate json name")
			}
			seen[name] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("json object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("json array")
		}
	default:
		return errors.New("json delimiter")
	}
	return nil
}

func validEvidenceIDs(values []string) bool {
	return validOrderedUUIDs(values, policy.MaxEvidenceIDs)
}

func validOrderedUUIDs(values []string, maximum int) bool {
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

func validClassification(value string) bool {
	switch value {
	case "credential_stuffing", "brute_force", "path_scan", "request_burst", "mixed", "unknown":
		return true
	default:
		return false
	}
}

func boundedText(value string, minimum, maximum int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= minimum && length <= maximum
}

func equalPolicyWire(left, right policyWire) bool {
	return left.SchemaVersion == right.SchemaVersion && left.Action == right.Action &&
		left.TargetIP == right.TargetIP && left.TTLSeconds == right.TTLSeconds &&
		left.Rationale == right.Rationale && equalStrings(left.EvidenceIDs, right.EvidenceIDs)
}

func equalCandidateWire(left, right candidateWire) bool {
	return left.SchemaVersion == right.SchemaVersion && left.TargetIP == right.TargetIP &&
		left.Timeout == right.Timeout && left.Command == right.Command &&
		equalStrings(left.EvidenceIDs, right.EvidenceIDs)
}

func equalStrings(left, right []string) bool {
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
