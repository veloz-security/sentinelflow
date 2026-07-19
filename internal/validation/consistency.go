package validation

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/policy"
	"golang.org/x/text/unicode/norm"
)

const (
	SchemaGatePassed       = "passed"
	SourceHealthComplete   = "complete"
	AnalysisOutputSchemaV1 = "sentinelflow_analysis_v1"
)

var consistencyUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type ConsistencyFailureCode string

const (
	ConsistencyFailureNone               ConsistencyFailureCode = "none"
	ConsistencyFailurePrerequisite       ConsistencyFailureCode = "schema_or_parser_prerequisite_failed"
	ConsistencyFailureAnalysis           ConsistencyFailureCode = "analysis_binding_mismatch"
	ConsistencyFailureEvidenceSnapshot   ConsistencyFailureCode = "evidence_snapshot_mismatch"
	ConsistencyFailureEvidenceMembership ConsistencyFailureCode = "evidence_membership_mismatch"
	ConsistencyFailureEvidenceTarget     ConsistencyFailureCode = "evidence_target_mismatch"
	ConsistencyFailureEvidenceIncomplete ConsistencyFailureCode = "evidence_incomplete"
	ConsistencyFailurePolicy             ConsistencyFailureCode = "policy_mismatch"
	ConsistencyFailureCandidate          ConsistencyFailureCode = "command_candidate_mismatch"
	ConsistencyFailureRationale          ConsistencyFailureCode = "rationale_digest_mismatch"
	ConsistencyFailureOutput             ConsistencyFailureCode = "analysis_output_invalid"
)

// SchemaGateBinding is the immutable output of the preceding strict schema
// gate. Consistency refuses to infer or repair a missing prerequisite.
type SchemaGateBinding struct {
	Status               string
	AnalysisOutputDigest string
	OutputSchemaDigest   string
}

type AnalysisBinding struct {
	AnalysisID          string
	IncidentID          string
	IncidentVersion     uint32
	AnalysisInputDigest string
	OutputSchemaDigest  string
	Output              []byte
}

// SignalEvidenceBinding expands one model-visible signal/evidence reference to
// the complete retained event set used to reproduce the deterministic rule.
type SignalEvidenceBinding struct {
	SignalID            string
	SignalDigest        string
	SourceIPv4          string
	EventIDs            []string
	ThresholdReproduced bool
	SourceHealthStatus  string
}

// EvidenceSnapshotBinding is a checked persistence projection. M5-010 owns its
// complete JCS snapshot; this gate verifies membership, target, health, and
// exact digest/analysis bindings without inventing missing evidence.
type EvidenceSnapshotBinding struct {
	SnapshotDigest      string
	IncidentID          string
	IncidentVersion     uint32
	AnalysisInputDigest string
	SourceIPv4          string
	SourceHealthDigest  string
	SourceHealthStatus  string
	SignalIDs           []string
	EventIDs            []string
	Signals             []SignalEvidenceBinding
}

type ConsistencyInput struct {
	ExpectedOutputSchemaDigest string
	SchemaGate                 SchemaGateBinding
	Analysis                   AnalysisBinding
	Policy                     policy.CheckedResponsePolicy
	Candidate                  policy.Artifact
	Evidence                   EvidenceSnapshotBinding
}

type analysisOutput struct {
	SchemaVersion        string   `json:"schema_version"`
	IncidentSummary      string   `json:"incident_summary"`
	Classification       string   `json:"classification"`
	Confidence           float64  `json:"confidence"`
	Uncertainty          string   `json:"uncertainty"`
	FalsePositiveFactors []string `json:"false_positive_factors"`
	EvidenceIDs          []string `json:"evidence_ids"`
	Policy               struct {
		SchemaVersion string   `json:"schema_version"`
		Action        string   `json:"action"`
		TargetIP      string   `json:"target_ip"`
		TTLSeconds    uint32   `json:"ttl_seconds"`
		EvidenceIDs   []string `json:"evidence_ids"`
		Rationale     string   `json:"rationale"`
	} `json:"policy"`
	Candidate struct {
		SchemaVersion string   `json:"schema_version"`
		TargetIP      string   `json:"target_ip"`
		Timeout       string   `json:"timeout"`
		EvidenceIDs   []string `json:"evidence_ids"`
		Command       string   `json:"command"`
	} `json:"nftables_command_candidate"`
}

// CheckConsistency implements the policy/evidence/command consistency gate.
// It returns only typed, content-free failure codes and safe immutable digests.
func CheckConsistency(input ConsistencyInput) ConsistencyResult {
	result := ConsistencyResult{Status: ConsistencyFailed, FailureCode: ConsistencyFailurePrerequisite}
	policyValue := input.Policy.Value()
	policyDigest := input.Policy.Digest()
	generatedDigest := input.Candidate.GeneratedDigest()
	canonicalDigest := input.Candidate.CanonicalDigest()
	if input.SchemaGate.Status != SchemaGatePassed ||
		!validDigest(input.SchemaGate.AnalysisOutputDigest) ||
		!validDigest(input.SchemaGate.OutputSchemaDigest) ||
		!validDigest(input.ExpectedOutputSchemaDigest) ||
		input.SchemaGate.AnalysisOutputDigest != digestBytes(input.Analysis.Output) ||
		input.SchemaGate.OutputSchemaDigest != input.Analysis.OutputSchemaDigest ||
		input.SchemaGate.OutputSchemaDigest != input.ExpectedOutputSchemaDigest ||
		len(input.Policy.CanonicalBytes()) == 0 || !validDigest(policyDigest) ||
		len(input.Candidate.GeneratedBytes()) == 0 || len(input.Candidate.CanonicalBytes()) == 0 ||
		!validDigest(generatedDigest) || !validDigest(canonicalDigest) {
		return result
	}
	result.PolicyDigest = policyDigest
	result.GeneratedCommandDigest = generatedDigest
	result.CanonicalCommandDigest = canonicalDigest
	result.AnalysisOutputDigest = input.SchemaGate.AnalysisOutputDigest

	if !consistencyUUIDPattern.MatchString(input.Analysis.AnalysisID) ||
		input.Analysis.AnalysisID != policyValue.AnalysisID ||
		input.Analysis.IncidentID != policyValue.IncidentID ||
		input.Analysis.IncidentID != input.Evidence.IncidentID ||
		input.Analysis.IncidentVersion == 0 ||
		input.Analysis.IncidentVersion != input.Evidence.IncidentVersion ||
		!validDigest(input.Analysis.AnalysisInputDigest) ||
		input.Analysis.AnalysisInputDigest != input.Evidence.AnalysisInputDigest {
		result.FailureCode = ConsistencyFailureAnalysis
		return result
	}
	result.AnalysisInputDigest = input.Analysis.AnalysisInputDigest

	if !validDigest(input.Evidence.SnapshotDigest) ||
		input.Evidence.SnapshotDigest != policyValue.EvidenceSnapshotDigest ||
		input.Evidence.IncidentID != policyValue.IncidentID ||
		input.Evidence.IncidentVersion == 0 ||
		!canonicalIPv4Equals(input.Evidence.SourceIPv4, policyValue.TargetIPv4) ||
		!validDigest(input.Evidence.SourceHealthDigest) {
		result.FailureCode = ConsistencyFailureEvidenceSnapshot
		return result
	}
	result.EvidenceSnapshotDigest = input.Evidence.SnapshotDigest
	result.TargetIPv4 = policyValue.TargetIPv4

	if input.Evidence.SourceHealthStatus != SourceHealthComplete || len(input.Evidence.Signals) == 0 {
		result.FailureCode = ConsistencyFailureEvidenceIncomplete
		return result
	}
	if !validOrderedUUIDs(input.Evidence.SignalIDs, policy.MaxEvidenceIDs) ||
		!validOrderedUUIDs(input.Evidence.EventIDs, 0) ||
		!equalStringSlices(input.Evidence.SignalIDs, policyValue.EvidenceIDs) ||
		!equalStringSlices(input.Candidate.EvidenceIDs(), policyValue.EvidenceIDs) ||
		len(input.Evidence.Signals) != len(input.Evidence.SignalIDs) {
		result.FailureCode = ConsistencyFailureEvidenceMembership
		return result
	}

	eventUnion := make(map[string]struct{}, len(input.Evidence.EventIDs))
	for index, signal := range input.Evidence.Signals {
		if signal.SignalID != input.Evidence.SignalIDs[index] || !validDigest(signal.SignalDigest) ||
			!validOrderedUUIDs(signal.EventIDs, 0) {
			result.FailureCode = ConsistencyFailureEvidenceMembership
			return result
		}
		if !canonicalIPv4Equals(signal.SourceIPv4, policyValue.TargetIPv4) {
			result.FailureCode = ConsistencyFailureEvidenceTarget
			return result
		}
		if !signal.ThresholdReproduced || signal.SourceHealthStatus != SourceHealthComplete {
			result.FailureCode = ConsistencyFailureEvidenceIncomplete
			return result
		}
		for _, eventID := range signal.EventIDs {
			eventUnion[eventID] = struct{}{}
		}
	}
	unionIDs := make([]string, 0, len(eventUnion))
	for eventID := range eventUnion {
		unionIDs = append(unionIDs, eventID)
	}
	sort.Strings(unionIDs)
	if !equalStringSlices(unionIDs, input.Evidence.EventIDs) {
		result.FailureCode = ConsistencyFailureEvidenceMembership
		return result
	}

	output, ok := decodeAnalysisOutput(input.Analysis.Output)
	if !ok || output.SchemaVersion != AnalysisOutputSchemaV1 {
		result.FailureCode = ConsistencyFailureOutput
		return result
	}
	if !equalStringSlices(output.EvidenceIDs, policyValue.EvidenceIDs) ||
		!equalStringSlices(output.Policy.EvidenceIDs, policyValue.EvidenceIDs) ||
		!equalStringSlices(output.Candidate.EvidenceIDs, policyValue.EvidenceIDs) {
		result.FailureCode = ConsistencyFailureEvidenceMembership
		return result
	}
	if output.Policy.SchemaVersion != policy.PolicySchemaVersion || output.Policy.Action != policy.ActionBlockIP ||
		output.Policy.Action != policyValue.Action || output.Policy.TargetIP != policyValue.TargetIPv4 ||
		output.Policy.TTLSeconds != policyValue.TTLSeconds {
		result.FailureCode = ConsistencyFailurePolicy
		return result
	}
	rationale := norm.NFC.String(output.Policy.Rationale)
	if rationale == "" || !utf8.ValidString(rationale) || digestBytes([]byte(rationale)) != policyValue.RationaleDigest {
		result.FailureCode = ConsistencyFailureRationale
		return result
	}
	result.RationaleDigest = policyValue.RationaleDigest

	ast := input.Candidate.AST()
	if output.Candidate.SchemaVersion != policy.CandidateSchemaVersion ||
		output.Candidate.TargetIP != policyValue.TargetIPv4 ||
		output.Candidate.TargetIP != ast.TargetIPv4() ||
		output.Candidate.Timeout != ast.InputTTLToken() ||
		ast.TTLSeconds() != policyValue.TTLSeconds ||
		!bytes.Equal([]byte(output.Candidate.Command), input.Candidate.GeneratedBytes()) {
		result.FailureCode = ConsistencyFailureCandidate
		return result
	}
	canonicalToken, err := policy.CanonicalTTL(policyValue.TTLSeconds)
	if err != nil || canonicalToken != input.Candidate.CanonicalTTLToken() {
		result.FailureCode = ConsistencyFailureCandidate
		return result
	}

	result.Status = ConsistencyPassed
	result.FailureCode = ConsistencyFailureNone
	return result
}

func decodeAnalysisOutput(data []byte) (analysisOutput, bool) {
	if len(data) == 0 || !utf8.Valid(data) || rejectDuplicateNames(data) != nil {
		return analysisOutput{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var output analysisOutput
	if err := decoder.Decode(&output); err != nil {
		return analysisOutput{}, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return analysisOutput{}, false
	}
	return output, true
}

func rejectDuplicateNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInvalidConsistencyJSON
	}
	return nil
}

var errInvalidConsistencyJSON = &consistencyJSONError{}

type consistencyJSONError struct{}

func (*consistencyJSONError) Error() string { return "invalid consistency JSON" }

func scanJSON(decoder *json.Decoder) error {
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
				return errInvalidConsistencyJSON
			}
			if _, duplicate := seen[name]; duplicate {
				return errInvalidConsistencyJSON
			}
			seen[name] = struct{}{}
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidConsistencyJSON
		}
	case '[':
		for decoder.More() {
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidConsistencyJSON
		}
	default:
		return errInvalidConsistencyJSON
	}
	return nil
}

func validOrderedUUIDs(values []string, maximum int) bool {
	if len(values) == 0 || maximum > 0 && len(values) > maximum {
		return false
	}
	previous := ""
	for index, value := range values {
		if !consistencyUUIDPattern.MatchString(value) || index > 0 && value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func equalStringSlices(left, right []string) bool {
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

func canonicalIPv4Equals(left, right string) bool {
	address, err := netip.ParseAddr(left)
	return err == nil && address.Is4() && address.String() == left && left == right
}

func digestBytes(value []byte) string {
	return policy.Digest(value)
}
