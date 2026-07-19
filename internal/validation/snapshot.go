package validation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"time"

	"github.com/devwooops/sentinelflow/internal/policy"
)

const (
	EvidenceSnapshotSchemaVersion   = "evidence-snapshot-v1"
	ValidationSnapshotSchemaVersion = "validation-snapshot-v1"
	ValidationSnapshotLifetime      = 5 * time.Minute
	MaxEvidenceEventIDs             = 1_000_000
	MaxEvidenceSignalIDs            = policy.MaxEvidenceIDs
	MaxEvidenceSnapshotBytes        = 64 * 1024 * 1024
	MaxValidationSnapshotBytes      = 32 * 1024
)

var (
	snapshotLabelPattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	snapshotVersionPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	nftVersionPattern      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$`)
)

type SnapshotErrorCode string

const (
	SnapshotErrorEncoding  SnapshotErrorCode = "snapshot_encoding_invalid"
	SnapshotErrorCanonical SnapshotErrorCode = "snapshot_not_canonical"
	SnapshotErrorSchema    SnapshotErrorCode = "snapshot_schema_invalid"
	SnapshotErrorID        SnapshotErrorCode = "snapshot_id_invalid"
	SnapshotErrorField     SnapshotErrorCode = "snapshot_field_invalid"
	SnapshotErrorEvidence  SnapshotErrorCode = "snapshot_evidence_invalid"
	SnapshotErrorDigest    SnapshotErrorCode = "snapshot_digest_invalid"
	SnapshotErrorTime      SnapshotErrorCode = "snapshot_time_invalid"
	SnapshotErrorChecks    SnapshotErrorCode = "snapshot_checks_invalid"
	SnapshotErrorValidity  SnapshotErrorCode = "snapshot_validity_invalid"
)

// SnapshotError is content-free so rejected evidence, commands, and IDs never
// become log material through an error string.
type SnapshotError struct{ Code SnapshotErrorCode }

func (e *SnapshotError) Error() string {
	if e == nil {
		return "immutable snapshot rejected"
	}
	return "immutable snapshot rejected: " + string(e.Code)
}

func rejectSnapshot(code SnapshotErrorCode) error { return &SnapshotError{Code: code} }

type EvidenceSnapshot struct {
	SchemaVersion      string
	SnapshotID         string
	IncidentID         string
	IncidentVersion    uint32
	SourceIPv4         string
	ServiceLabel       string
	WindowStart        time.Time
	WindowEnd          time.Time
	SourceHealthDigest string
	EventIDs           []string
	SignalIDs          []string
	CreatedAt          time.Time
}

type CheckedEvidenceSnapshot struct {
	value     EvidenceSnapshot
	canonical []byte
	digest    string
}

func (s CheckedEvidenceSnapshot) Value() EvidenceSnapshot {
	value := s.value
	value.EventIDs = append([]string(nil), s.value.EventIDs...)
	value.SignalIDs = append([]string(nil), s.value.SignalIDs...)
	return value
}

func (s CheckedEvidenceSnapshot) CanonicalBytes() []byte { return bytes.Clone(s.canonical) }
func (s CheckedEvidenceSnapshot) DigestInput() []byte    { return bytes.Clone(s.canonical) }
func (s CheckedEvidenceSnapshot) Digest() string         { return s.digest }

type evidenceSnapshotWire struct {
	SchemaVersion      string   `json:"schema_version"`
	SnapshotID         string   `json:"snapshot_id"`
	IncidentID         string   `json:"incident_id"`
	IncidentVersion    uint32   `json:"incident_version"`
	SourceIPv4         string   `json:"source_ipv4"`
	ServiceLabel       string   `json:"service_label"`
	WindowStart        string   `json:"window_start"`
	WindowEnd          string   `json:"window_end"`
	SourceHealthDigest string   `json:"source_health_digest"`
	EventIDs           []string `json:"event_ids"`
	SignalIDs          []string `json:"signal_ids"`
	CreatedAt          string   `json:"created_at"`
}

func CheckEvidenceSnapshot(value EvidenceSnapshot) (CheckedEvidenceSnapshot, error) {
	if value.SchemaVersion != EvidenceSnapshotSchemaVersion {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorSchema)
	}
	if !consistencyUUIDPattern.MatchString(value.SnapshotID) ||
		!consistencyUUIDPattern.MatchString(value.IncidentID) || value.IncidentVersion == 0 ||
		value.IncidentVersion > 2_147_483_647 {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorID)
	}
	address, err := netip.ParseAddr(value.SourceIPv4)
	if err != nil || !address.Is4() || address.String() != value.SourceIPv4 ||
		!snapshotLabelPattern.MatchString(value.ServiceLabel) {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorField)
	}
	if !validDigest(value.SourceHealthDigest) {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorDigest)
	}
	if !validOrderedUUIDs(value.EventIDs, MaxEvidenceEventIDs) ||
		!validOrderedUUIDs(value.SignalIDs, MaxEvidenceSignalIDs) {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorEvidence)
	}
	if !validSnapshotTime(value.WindowStart) || !validSnapshotTime(value.WindowEnd) ||
		!validSnapshotTime(value.CreatedAt) || value.WindowEnd.Before(value.WindowStart) ||
		value.CreatedAt.Before(value.WindowEnd) {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorTime)
	}

	frozen := value
	frozen.WindowStart = value.WindowStart.Round(0).UTC()
	frozen.WindowEnd = value.WindowEnd.Round(0).UTC()
	frozen.CreatedAt = value.CreatedAt.Round(0).UTC()
	frozen.EventIDs = append([]string(nil), value.EventIDs...)
	frozen.SignalIDs = append([]string(nil), value.SignalIDs...)
	canonical, err := marshalSnapshotJCS(evidenceSnapshotToWire(frozen))
	if err != nil || len(canonical) > MaxEvidenceSnapshotBytes {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorEncoding)
	}
	return CheckedEvidenceSnapshot{value: frozen, canonical: canonical, digest: digestBytes(canonical)}, nil
}

func ParseCanonicalEvidenceSnapshot(data []byte) (CheckedEvidenceSnapshot, error) {
	if len(data) == 0 || len(data) > MaxEvidenceSnapshotBytes || strictJSON(data) != nil {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorEncoding)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire evidenceSnapshotWire
	if err := decoder.Decode(&wire); err != nil || requireSnapshotEOF(decoder) != nil {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorEncoding)
	}
	windowStart, err := time.Parse(time.RFC3339Nano, wire.WindowStart)
	if err != nil {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorTime)
	}
	windowEnd, err := time.Parse(time.RFC3339Nano, wire.WindowEnd)
	if err != nil {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorTime)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorTime)
	}
	checked, err := CheckEvidenceSnapshot(EvidenceSnapshot{
		SchemaVersion:      wire.SchemaVersion,
		SnapshotID:         wire.SnapshotID,
		IncidentID:         wire.IncidentID,
		IncidentVersion:    wire.IncidentVersion,
		SourceIPv4:         wire.SourceIPv4,
		ServiceLabel:       wire.ServiceLabel,
		WindowStart:        windowStart,
		WindowEnd:          windowEnd,
		SourceHealthDigest: wire.SourceHealthDigest,
		EventIDs:           wire.EventIDs,
		SignalIDs:          wire.SignalIDs,
		CreatedAt:          createdAt,
	})
	if err != nil {
		return CheckedEvidenceSnapshot{}, err
	}
	if !bytes.Equal(data, checked.canonical) {
		return CheckedEvidenceSnapshot{}, rejectSnapshot(SnapshotErrorCanonical)
	}
	return checked, nil
}

func evidenceSnapshotToWire(value EvidenceSnapshot) evidenceSnapshotWire {
	return evidenceSnapshotWire{
		SchemaVersion:      value.SchemaVersion,
		SnapshotID:         value.SnapshotID,
		IncidentID:         value.IncidentID,
		IncidentVersion:    value.IncidentVersion,
		SourceIPv4:         value.SourceIPv4,
		ServiceLabel:       value.ServiceLabel,
		WindowStart:        value.WindowStart.Format(time.RFC3339Nano),
		WindowEnd:          value.WindowEnd.Format(time.RFC3339Nano),
		SourceHealthDigest: value.SourceHealthDigest,
		EventIDs:           value.EventIDs,
		SignalIDs:          value.SignalIDs,
		CreatedAt:          value.CreatedAt.Format(time.RFC3339Nano),
	}
}

type ValidationCheckID string

const (
	CheckStructuredOutput                 ValidationCheckID = "structured_output"
	CheckCommandGrammar                   ValidationCheckID = "command_grammar"
	CheckPolicyEvidenceCommandConsistency ValidationCheckID = "policy_evidence_command_consistency"
	CheckProtectedNetwork                 ValidationCheckID = "protected_network"
	CheckOwnedSchemaSyntax                ValidationCheckID = "owned_schema_syntax"
	CheckHistoricalImpact                 ValidationCheckID = "historical_impact"
)

var orderedValidationCheckIDs = [...]ValidationCheckID{
	CheckStructuredOutput,
	CheckCommandGrammar,
	CheckPolicyEvidenceCommandConsistency,
	CheckProtectedNetwork,
	CheckOwnedSchemaSyntax,
	CheckHistoricalImpact,
}

type ValidationCheck struct {
	CheckID     ValidationCheckID
	Result      string
	ReasonCode  string
	InputDigest string
}

type ValidationSnapshot struct {
	SchemaVersion                      string
	ValidationID                       string
	PolicyDigest                       string
	EvidenceSnapshotDigest             string
	AnalysisInputDigest                string
	AnalysisOutputSchemaDigest         string
	PromptDigest                       string
	GeneratedCandidateDigest           string
	CanonicalArtifactDigest            string
	GrammarVersion                     string
	ParserVersion                      string
	ValidatorVersion                   string
	BaseChainContractRawDigest         string
	LiveOwnedSchemaDigest              string
	ProtectedIPv4StaticDigest          string
	ProtectedIPv4EffectiveConfigDigest string
	NFTBinaryDigest                    string
	NFTVersion                         string
	HistoricalImpactDigest             string
	Checks                             []ValidationCheck
	CreatedAt                          time.Time
	ValidUntil                         time.Time
}

type CheckedValidationSnapshot struct {
	value     ValidationSnapshot
	canonical []byte
	digest    string
}

func (s CheckedValidationSnapshot) Value() ValidationSnapshot {
	value := s.value
	value.Checks = append([]ValidationCheck(nil), s.value.Checks...)
	return value
}

func (s CheckedValidationSnapshot) CanonicalBytes() []byte { return bytes.Clone(s.canonical) }
func (s CheckedValidationSnapshot) DigestInput() []byte    { return bytes.Clone(s.canonical) }
func (s CheckedValidationSnapshot) Digest() string         { return s.digest }

// FreshAt is intentionally strict at both boundaries. A future-created or
// exactly-expired snapshot is not eligible for HIL or capability minting.
func (s CheckedValidationSnapshot) FreshAt(now time.Time) bool {
	if len(s.canonical) == 0 || now.IsZero() {
		return false
	}
	now = now.Round(0).UTC()
	return !now.Before(s.value.CreatedAt) && now.Before(s.value.ValidUntil)
}

type validationCheckWire struct {
	CheckID     ValidationCheckID `json:"check_id"`
	Result      string            `json:"result"`
	ReasonCode  string            `json:"reason_code"`
	InputDigest string            `json:"input_digest"`
}

type validationSnapshotWire struct {
	SchemaVersion                      string                `json:"schema_version"`
	ValidationID                       string                `json:"validation_id"`
	PolicyDigest                       string                `json:"policy_digest"`
	EvidenceSnapshotDigest             string                `json:"evidence_snapshot_digest"`
	AnalysisInputDigest                string                `json:"analysis_input_digest"`
	AnalysisOutputSchemaDigest         string                `json:"analysis_output_schema_digest"`
	PromptDigest                       string                `json:"prompt_digest"`
	GeneratedCandidateDigest           string                `json:"generated_candidate_digest"`
	CanonicalArtifactDigest            string                `json:"canonical_artifact_digest"`
	GrammarVersion                     string                `json:"grammar_version"`
	ParserVersion                      string                `json:"parser_version"`
	ValidatorVersion                   string                `json:"validator_version"`
	BaseChainContractRawDigest         string                `json:"base_chain_contract_raw_digest"`
	LiveOwnedSchemaDigest              string                `json:"live_owned_schema_digest"`
	ProtectedIPv4StaticDigest          string                `json:"protected_ipv4_static_digest"`
	ProtectedIPv4EffectiveConfigDigest string                `json:"protected_ipv4_effective_config_digest"`
	NFTBinaryDigest                    string                `json:"nft_binary_digest"`
	NFTVersion                         string                `json:"nft_version"`
	HistoricalImpactDigest             string                `json:"historical_impact_digest"`
	Checks                             []validationCheckWire `json:"checks"`
	CreatedAt                          string                `json:"created_at"`
	ValidUntil                         string                `json:"valid_until"`
}

func CheckValidationSnapshot(value ValidationSnapshot) (CheckedValidationSnapshot, error) {
	if value.SchemaVersion != ValidationSnapshotSchemaVersion || value.GrammarVersion != policy.CandidateSchemaVersion {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorSchema)
	}
	if !consistencyUUIDPattern.MatchString(value.ValidationID) {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorID)
	}
	if !snapshotVersionPattern.MatchString(value.ParserVersion) ||
		!snapshotVersionPattern.MatchString(value.ValidatorVersion) ||
		!nftVersionPattern.MatchString(value.NFTVersion) {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorField)
	}
	digests := [...]string{
		value.PolicyDigest,
		value.EvidenceSnapshotDigest,
		value.AnalysisInputDigest,
		value.AnalysisOutputSchemaDigest,
		value.PromptDigest,
		value.GeneratedCandidateDigest,
		value.CanonicalArtifactDigest,
		value.BaseChainContractRawDigest,
		value.LiveOwnedSchemaDigest,
		value.ProtectedIPv4StaticDigest,
		value.ProtectedIPv4EffectiveConfigDigest,
		value.NFTBinaryDigest,
		value.HistoricalImpactDigest,
	}
	for _, digest := range digests {
		if !validDigest(digest) {
			return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorDigest)
		}
	}
	if len(value.Checks) != len(orderedValidationCheckIDs) {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorChecks)
	}
	for index, check := range value.Checks {
		if check.CheckID != orderedValidationCheckIDs[index] || check.Result != "pass" ||
			check.ReasonCode != "ok" || !validDigest(check.InputDigest) {
			return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorChecks)
		}
	}
	if !validSnapshotTime(value.CreatedAt) || !validSnapshotTime(value.ValidUntil) {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorTime)
	}
	createdAt := value.CreatedAt.Round(0).UTC()
	validUntil := value.ValidUntil.Round(0).UTC()
	if !validUntil.Equal(createdAt.Add(ValidationSnapshotLifetime)) {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorValidity)
	}

	frozen := value
	frozen.CreatedAt = createdAt
	frozen.ValidUntil = validUntil
	frozen.Checks = append([]ValidationCheck(nil), value.Checks...)
	canonical, err := marshalSnapshotJCS(validationSnapshotToWire(frozen))
	if err != nil || len(canonical) > MaxValidationSnapshotBytes {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorEncoding)
	}
	return CheckedValidationSnapshot{value: frozen, canonical: canonical, digest: digestBytes(canonical)}, nil
}

func ParseCanonicalValidationSnapshot(data []byte) (CheckedValidationSnapshot, error) {
	if len(data) == 0 || len(data) > MaxValidationSnapshotBytes || strictJSON(data) != nil {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorEncoding)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire validationSnapshotWire
	if err := decoder.Decode(&wire); err != nil || requireSnapshotEOF(decoder) != nil {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorEncoding)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorTime)
	}
	validUntil, err := time.Parse(time.RFC3339Nano, wire.ValidUntil)
	if err != nil {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorTime)
	}
	checks := make([]ValidationCheck, len(wire.Checks))
	for index, check := range wire.Checks {
		checks[index] = ValidationCheck(check)
	}
	checked, err := CheckValidationSnapshot(ValidationSnapshot{
		SchemaVersion:                      wire.SchemaVersion,
		ValidationID:                       wire.ValidationID,
		PolicyDigest:                       wire.PolicyDigest,
		EvidenceSnapshotDigest:             wire.EvidenceSnapshotDigest,
		AnalysisInputDigest:                wire.AnalysisInputDigest,
		AnalysisOutputSchemaDigest:         wire.AnalysisOutputSchemaDigest,
		PromptDigest:                       wire.PromptDigest,
		GeneratedCandidateDigest:           wire.GeneratedCandidateDigest,
		CanonicalArtifactDigest:            wire.CanonicalArtifactDigest,
		GrammarVersion:                     wire.GrammarVersion,
		ParserVersion:                      wire.ParserVersion,
		ValidatorVersion:                   wire.ValidatorVersion,
		BaseChainContractRawDigest:         wire.BaseChainContractRawDigest,
		LiveOwnedSchemaDigest:              wire.LiveOwnedSchemaDigest,
		ProtectedIPv4StaticDigest:          wire.ProtectedIPv4StaticDigest,
		ProtectedIPv4EffectiveConfigDigest: wire.ProtectedIPv4EffectiveConfigDigest,
		NFTBinaryDigest:                    wire.NFTBinaryDigest,
		NFTVersion:                         wire.NFTVersion,
		HistoricalImpactDigest:             wire.HistoricalImpactDigest,
		Checks:                             checks,
		CreatedAt:                          createdAt,
		ValidUntil:                         validUntil,
	})
	if err != nil {
		return CheckedValidationSnapshot{}, err
	}
	if !bytes.Equal(data, checked.canonical) {
		return CheckedValidationSnapshot{}, rejectSnapshot(SnapshotErrorCanonical)
	}
	return checked, nil
}

func validationSnapshotToWire(value ValidationSnapshot) validationSnapshotWire {
	checks := make([]validationCheckWire, len(value.Checks))
	for index, check := range value.Checks {
		checks[index] = validationCheckWire(check)
	}
	return validationSnapshotWire{
		SchemaVersion:                      value.SchemaVersion,
		ValidationID:                       value.ValidationID,
		PolicyDigest:                       value.PolicyDigest,
		EvidenceSnapshotDigest:             value.EvidenceSnapshotDigest,
		AnalysisInputDigest:                value.AnalysisInputDigest,
		AnalysisOutputSchemaDigest:         value.AnalysisOutputSchemaDigest,
		PromptDigest:                       value.PromptDigest,
		GeneratedCandidateDigest:           value.GeneratedCandidateDigest,
		CanonicalArtifactDigest:            value.CanonicalArtifactDigest,
		GrammarVersion:                     value.GrammarVersion,
		ParserVersion:                      value.ParserVersion,
		ValidatorVersion:                   value.ValidatorVersion,
		BaseChainContractRawDigest:         value.BaseChainContractRawDigest,
		LiveOwnedSchemaDigest:              value.LiveOwnedSchemaDigest,
		ProtectedIPv4StaticDigest:          value.ProtectedIPv4StaticDigest,
		ProtectedIPv4EffectiveConfigDigest: value.ProtectedIPv4EffectiveConfigDigest,
		NFTBinaryDigest:                    value.NFTBinaryDigest,
		NFTVersion:                         value.NFTVersion,
		HistoricalImpactDigest:             value.HistoricalImpactDigest,
		Checks:                             checks,
		CreatedAt:                          value.CreatedAt.Format(time.RFC3339Nano),
		ValidUntil:                         value.ValidUntil.Format(time.RFC3339Nano),
	}
}

func marshalSnapshotJCS(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(raw)
}

func requireSnapshotEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("trailing JSON")
}

func validSnapshotTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}
