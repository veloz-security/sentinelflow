package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/netip"
	"regexp"
	"time"
)

const (
	// PolicyDigestDomain is carried inside every canonical policy as the
	// required schema_version value. The digest input is therefore the exact
	// versioned JCS object, rather than an untyped JSON fragment.
	PolicyDigestDomain = PolicySchemaVersion
	MaxPolicyBytes     = 8 * 1024
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ResponsePolicy is the complete immutable response-policy-v1 object. Human
// rationale text is deliberately absent: only its separately normalized and
// checked digest crosses this boundary.
type ResponsePolicy struct {
	SchemaVersion          string
	PolicyID               string
	PolicyVersion          uint32
	IncidentID             string
	AnalysisID             string
	Action                 string
	TargetIPv4             string
	TTLSeconds             uint32
	EvidenceSnapshotDigest string
	EvidenceIDs            []string
	RationaleDigest        string
	CreatedAt              time.Time
}

// CheckedResponsePolicy owns immutable copies of the domain object, its exact
// RFC 8785/JCS bytes, and its lowercase SHA-256 digest.
type CheckedResponsePolicy struct {
	value     ResponsePolicy
	canonical []byte
	digest    string
}

func (p CheckedResponsePolicy) Value() ResponsePolicy {
	result := p.value
	result.EvidenceIDs = append([]string(nil), p.value.EvidenceIDs...)
	return result
}

func (p CheckedResponsePolicy) CanonicalBytes() []byte {
	return bytes.Clone(p.canonical)
}

// DigestInput returns the exact versioned JCS bytes hashed by Digest. The
// required schema_version field is the digest domain separator.
func (p CheckedResponsePolicy) DigestInput() []byte {
	return bytes.Clone(p.canonical)
}

func (p CheckedResponsePolicy) Digest() string { return p.digest }

type PolicyErrorCode string

const (
	PolicyErrorEncoding      PolicyErrorCode = "policy_encoding_invalid"
	PolicyErrorCanonical     PolicyErrorCode = "policy_not_canonical"
	PolicyErrorSchema        PolicyErrorCode = "policy_schema_invalid"
	PolicyErrorID            PolicyErrorCode = "policy_id_invalid"
	PolicyErrorVersion       PolicyErrorCode = "policy_version_invalid"
	PolicyErrorIncident      PolicyErrorCode = "policy_incident_invalid"
	PolicyErrorAnalysis      PolicyErrorCode = "policy_analysis_invalid"
	PolicyErrorAction        PolicyErrorCode = "policy_action_invalid"
	PolicyErrorTarget        PolicyErrorCode = "policy_target_invalid"
	PolicyErrorTTL           PolicyErrorCode = "policy_ttl_invalid"
	PolicyErrorDigest        PolicyErrorCode = "policy_digest_invalid"
	PolicyErrorEvidence      PolicyErrorCode = "policy_evidence_invalid"
	PolicyErrorCreatedAt     PolicyErrorCode = "policy_created_at_invalid"
	PolicyErrorRevision      PolicyErrorCode = "policy_revision_invalid"
	PolicyErrorState         PolicyErrorCode = "policy_state_invalid"
	PolicyErrorTransition    PolicyErrorCode = "policy_transition_invalid"
	PolicyErrorStateRevision PolicyErrorCode = "policy_state_revision_conflict"
)

// PolicyError is content-free and safe for logs. It never embeds JSON,
// identifiers, evidence, command bytes, or rationale material.
type PolicyError struct{ Code PolicyErrorCode }

func (e *PolicyError) Error() string {
	if e == nil {
		return "response-policy-v1 rejected"
	}
	return "response-policy-v1 rejected: " + string(e.Code)
}

func rejectPolicy(code PolicyErrorCode) error { return &PolicyError{Code: code} }

// CheckResponsePolicy validates a typed policy and freezes its canonical form.
// It does not run protected-target, nft, history, or HIL validation.
func CheckResponsePolicy(value ResponsePolicy) (CheckedResponsePolicy, error) {
	if value.SchemaVersion != PolicySchemaVersion {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorSchema)
	}
	if !evidenceIDPattern.MatchString(value.PolicyID) {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorID)
	}
	if value.PolicyVersion == 0 || value.PolicyVersion > math.MaxInt32 {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorVersion)
	}
	if !evidenceIDPattern.MatchString(value.IncidentID) {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorIncident)
	}
	if !evidenceIDPattern.MatchString(value.AnalysisID) {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorAnalysis)
	}
	if value.Action != ActionBlockIP {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorAction)
	}
	address, err := netip.ParseAddr(value.TargetIPv4)
	if err != nil || !address.Is4() || address.String() != value.TargetIPv4 {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorTarget)
	}
	if value.TTLSeconds < MinTTLSeconds || value.TTLSeconds > MaxTTLSeconds {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorTTL)
	}
	if !digestPattern.MatchString(value.EvidenceSnapshotDigest) || !digestPattern.MatchString(value.RationaleDigest) {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorDigest)
	}
	if !validEvidenceIDs(value.EvidenceIDs) {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorEvidence)
	}
	if value.CreatedAt.IsZero() || value.CreatedAt.Year() < 1 || value.CreatedAt.Year() > 9999 {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorCreatedAt)
	}

	frozen := value
	frozen.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	frozen.CreatedAt = value.CreatedAt.UTC()
	canonical := marshalResponsePolicyJCS(frozen)
	return CheckedResponsePolicy{
		value:     frozen,
		canonical: canonical,
		digest:    Digest(canonical),
	}, nil
}

type responsePolicyWire struct {
	SchemaVersion          string   `json:"schema_version"`
	PolicyID               string   `json:"policy_id"`
	PolicyVersion          uint32   `json:"policy_version"`
	IncidentID             string   `json:"incident_id"`
	AnalysisID             string   `json:"analysis_id"`
	Action                 string   `json:"action"`
	TargetIPv4             string   `json:"target_ipv4"`
	TTLSeconds             uint32   `json:"ttl_seconds"`
	EvidenceSnapshotDigest string   `json:"evidence_snapshot_digest"`
	EvidenceIDs            []string `json:"evidence_ids"`
	RationaleDigest        string   `json:"rationale_digest"`
	CreatedAt              string   `json:"created_at"`
}

// ParseCanonicalResponsePolicy accepts only the byte-exact JCS encoding. It
// rejects duplicate/unknown fields and non-canonical-but-equivalent JSON rather
// than silently repairing an artifact that may later be digest-bound.
func ParseCanonicalResponsePolicy(data []byte) (CheckedResponsePolicy, error) {
	if len(data) == 0 || len(data) > MaxPolicyBytes {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorEncoding)
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorEncoding)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire responsePolicyWire
	if err := decoder.Decode(&wire); err != nil {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorEncoding)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorEncoding)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorCreatedAt)
	}
	checked, err := CheckResponsePolicy(ResponsePolicy{
		SchemaVersion:          wire.SchemaVersion,
		PolicyID:               wire.PolicyID,
		PolicyVersion:          wire.PolicyVersion,
		IncidentID:             wire.IncidentID,
		AnalysisID:             wire.AnalysisID,
		Action:                 wire.Action,
		TargetIPv4:             wire.TargetIPv4,
		TTLSeconds:             wire.TTLSeconds,
		EvidenceSnapshotDigest: wire.EvidenceSnapshotDigest,
		EvidenceIDs:            wire.EvidenceIDs,
		RationaleDigest:        wire.RationaleDigest,
		CreatedAt:              createdAt,
	})
	if err != nil {
		return CheckedResponsePolicy{}, err
	}
	if !bytes.Equal(data, checked.canonical) {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorCanonical)
	}
	return checked, nil
}

// ReviseResponsePolicy creates the next immutable version of the same policy.
// Revisions cannot rewrite incident history and must advance creation time.
func ReviseResponsePolicy(previous CheckedResponsePolicy, next ResponsePolicy) (CheckedResponsePolicy, error) {
	prior := previous.value
	if len(previous.canonical) == 0 || previous.digest == "" ||
		next.PolicyID != prior.PolicyID || next.IncidentID != prior.IncidentID ||
		prior.PolicyVersion == math.MaxInt32 || next.PolicyVersion != prior.PolicyVersion+1 ||
		!next.CreatedAt.After(prior.CreatedAt) {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorRevision)
	}
	checked, err := CheckResponsePolicy(next)
	if err != nil {
		return CheckedResponsePolicy{}, err
	}
	if checked.digest == previous.digest || bytes.Equal(checked.canonical, previous.canonical) {
		return CheckedResponsePolicy{}, rejectPolicy(PolicyErrorRevision)
	}
	return checked, nil
}

func marshalResponsePolicyJCS(value ResponsePolicy) []byte {
	// Keys are written in RFC 8785 UTF-16 lexicographic order. Every dynamic
	// string has already been restricted to an ASCII contract alphabet.
	result := make([]byte, 0, 768)
	result = append(result, `{"action":`...)
	result = appendJSONString(result, value.Action)
	result = append(result, `,"analysis_id":`...)
	result = appendJSONString(result, value.AnalysisID)
	result = append(result, `,"created_at":`...)
	result = appendJSONString(result, value.CreatedAt.UTC().Format(time.RFC3339Nano))
	result = append(result, `,"evidence_ids":[`...)
	for index, id := range value.EvidenceIDs {
		if index > 0 {
			result = append(result, ',')
		}
		result = appendJSONString(result, id)
	}
	result = append(result, `],"evidence_snapshot_digest":`...)
	result = appendJSONString(result, value.EvidenceSnapshotDigest)
	result = append(result, `,"incident_id":`...)
	result = appendJSONString(result, value.IncidentID)
	result = append(result, `,"policy_id":`...)
	result = appendJSONString(result, value.PolicyID)
	result = append(result, `,"policy_version":`...)
	result = appendUint32(result, value.PolicyVersion)
	result = append(result, `,"rationale_digest":`...)
	result = appendJSONString(result, value.RationaleDigest)
	result = append(result, `,"schema_version":`...)
	result = appendJSONString(result, value.SchemaVersion)
	result = append(result, `,"target_ipv4":`...)
	result = appendJSONString(result, value.TargetIPv4)
	result = append(result, `,"ttl_seconds":`...)
	result = appendUint32(result, value.TTLSeconds)
	result = append(result, '}')
	return result
}

func appendJSONString(destination []byte, value string) []byte {
	encoded, _ := json.Marshal(value)
	return append(destination, encoded...)
}

func appendUint32(destination []byte, value uint32) []byte {
	const digits = "0123456789"
	if value == 0 {
		return append(destination, '0')
	}
	var buffer [10]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = digits[value%10]
		value /= 10
	}
	return append(destination, buffer[position:]...)
}

func rejectDuplicateJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
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
				return rejectPolicy(PolicyErrorEncoding)
			}
			if _, duplicate := seen[name]; duplicate {
				return rejectPolicy(PolicyErrorEncoding)
			}
			seen[name] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return rejectPolicy(PolicyErrorEncoding)
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return rejectPolicy(PolicyErrorEncoding)
		}
	default:
		return rejectPolicy(PolicyErrorEncoding)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return rejectPolicy(PolicyErrorEncoding)
	}
	return nil
}
