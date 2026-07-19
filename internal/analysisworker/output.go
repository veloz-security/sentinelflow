package analysisworker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/netip"
	"regexp"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/ai"
)

var timeoutPattern = regexp.MustCompile(`^[1-9][0-9]{0,4}[smh]$`)

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

type parsedOutput struct {
	analysisJSON           []byte
	policyJSON             []byte
	candidateJSON          []byte
	outputDigest           string
	generatedCommandDigest string
	evidenceIDs            []string
}

func parseOutput(data []byte, snapshot Snapshot) (parsedOutput, error) {
	if len(data) == 0 || len(data) > 1<<20 || !utf8.Valid(data) || strictJSON(data) != nil {
		return parsedOutput{}, ErrInvalidAnalyzer
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document outputDocument
	if err := decoder.Decode(&document); err != nil {
		return parsedOutput{}, ErrInvalidAnalyzer
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return parsedOutput{}, ErrInvalidAnalyzer
	}
	if !validOutputDocument(document, snapshot) {
		return parsedOutput{}, ErrInvalidAnalyzer
	}
	policy, err := json.Marshal(document.Policy)
	if err != nil {
		return parsedOutput{}, ErrInvalidAnalyzer
	}
	candidate, err := json.Marshal(document.Candidate)
	if err != nil {
		return parsedOutput{}, ErrInvalidAnalyzer
	}
	return parsedOutput{
		analysisJSON: append([]byte(nil), data...), policyJSON: policy, candidateJSON: candidate,
		outputDigest: digestBytes(data), generatedCommandDigest: digestBytes([]byte(document.Candidate.Command)),
		evidenceIDs: append([]string(nil), document.EvidenceIDs...),
	}, nil
}

func validOutputDocument(document outputDocument, snapshot Snapshot) bool {
	if document.SchemaVersion != OutputSchemaVersion ||
		!boundedText(document.IncidentSummary, 1, 1600) ||
		!validClassification(document.Classification) || math.IsNaN(document.Confidence) ||
		math.IsInf(document.Confidence, 0) || document.Confidence < 0 || document.Confidence > 1 ||
		!boundedText(document.Uncertainty, 0, 800) || len(document.FalsePositiveFactors) > 5 ||
		!validEvidence(document.EvidenceIDs, snapshot.Signals) {
		return false
	}
	for _, factor := range document.FalsePositiveFactors {
		if !boundedText(factor, 1, 240) {
			return false
		}
	}
	policy := document.Policy
	candidate := document.Candidate
	policyAddress, policyErr := netip.ParseAddr(policy.TargetIP)
	candidateAddress, candidateErr := netip.ParseAddr(candidate.TargetIP)
	return policy.SchemaVersion == "response-policy-v1" && policy.Action == "block_ip" &&
		policyErr == nil && policyAddress.Is4() && policyAddress.String() == policy.TargetIP &&
		policy.TargetIP == snapshot.SourceIP && policy.TTLSeconds >= DefaultMinimumTTLSeconds &&
		policy.TTLSeconds <= DefaultMaximumTTLSeconds &&
		equalStrings(policy.EvidenceIDs, document.EvidenceIDs) && boundedText(policy.Rationale, 1, 800) &&
		candidate.SchemaVersion == "nft-blacklist-v1" && candidateErr == nil && candidateAddress.Is4() &&
		candidateAddress.String() == candidate.TargetIP && candidate.TargetIP == snapshot.SourceIP &&
		timeoutPattern.MatchString(candidate.Timeout) && equalStrings(candidate.EvidenceIDs, document.EvidenceIDs) &&
		boundedText(candidate.Command, 1, 256)
}

func validEvidence(ids []string, signals []Signal) bool {
	if len(ids) != len(signals) || len(ids) == 0 || len(ids) > ai.MaxEvidenceRefs {
		return false
	}
	for index := range ids {
		if ids[index] != signals[index].SignalID || (index > 0 && ids[index] <= ids[index-1]) {
			return false
		}
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

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func strictJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalidAnalyzer
	}
	if err := consumeJSON(decoder, token); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidAnalyzer
	}
	return nil
}

func consumeJSON(decoder *json.Decoder, token json.Token) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrInvalidAnalyzer
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidAnalyzer
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidAnalyzer
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil || consumeJSON(decoder, value) != nil {
				return ErrInvalidAnalyzer
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidAnalyzer
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil || consumeJSON(decoder, value) != nil {
				return ErrInvalidAnalyzer
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidAnalyzer
		}
	default:
		return ErrInvalidAnalyzer
	}
	return nil
}
