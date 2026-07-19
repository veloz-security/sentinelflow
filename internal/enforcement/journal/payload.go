package journal

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
)

const (
	journalTimeLayout = "2006-01-02T15:04:05.000Z"
	phaseStarted      = "started"
	phaseTerminal     = "terminal"
)

// recordPayload fields are declared in lexical JSON-key order. Every value is
// an integer, null, or contract-bounded ASCII string, so json.Marshal emits the
// exact RFC 8785/JCS representation required by executor-journal-record-v1.
type recordPayload struct {
	ArtifactB64URL                string  `json:"artifact_b64url"`
	ArtifactDigest                string  `json:"artifact_digest"`
	CapabilityDigest              string  `json:"capability_digest"`
	CapabilityID                  string  `json:"capability_id"`
	CapabilityJCSB64URL           string  `json:"capability_jcs_b64url"`
	CapabilitySignatureB64URL     string  `json:"capability_signature_b64url"`
	Deadline                      string  `json:"deadline"`
	JournalSequence               uint64  `json:"journal_sequence"`
	Operation                     string  `json:"operation"`
	OwnedSchemaDigest             string  `json:"owned_schema_digest"`
	Phase                         string  `json:"phase"`
	PreviousRecordDigest          *string `json:"previous_record_digest"`
	ReceivedAt                    string  `json:"received_at"`
	RecordChecksum                string  `json:"record_checksum"`
	SchemaVersion                 string  `json:"schema_version"`
	TargetIPv4                    string  `json:"target_ipv4"`
	TerminalResultDigest          *string `json:"terminal_result_digest"`
	TerminalResultJCSB64URL       *string `json:"terminal_result_jcs_b64url"`
	TerminalResultSignatureB64URL *string `json:"terminal_result_signature_b64url"`
}

// recordChecksumPayload is the same lexical object with record_checksum
// omitted, exactly matching the checked-in schema's checksum preimage.
type recordChecksumPayload struct {
	ArtifactB64URL                string  `json:"artifact_b64url"`
	ArtifactDigest                string  `json:"artifact_digest"`
	CapabilityDigest              string  `json:"capability_digest"`
	CapabilityID                  string  `json:"capability_id"`
	CapabilityJCSB64URL           string  `json:"capability_jcs_b64url"`
	CapabilitySignatureB64URL     string  `json:"capability_signature_b64url"`
	Deadline                      string  `json:"deadline"`
	JournalSequence               uint64  `json:"journal_sequence"`
	Operation                     string  `json:"operation"`
	OwnedSchemaDigest             string  `json:"owned_schema_digest"`
	Phase                         string  `json:"phase"`
	PreviousRecordDigest          *string `json:"previous_record_digest"`
	ReceivedAt                    string  `json:"received_at"`
	SchemaVersion                 string  `json:"schema_version"`
	TargetIPv4                    string  `json:"target_ipv4"`
	TerminalResultDigest          *string `json:"terminal_result_digest"`
	TerminalResultJCSB64URL       *string `json:"terminal_result_jcs_b64url"`
	TerminalResultSignatureB64URL *string `json:"terminal_result_signature_b64url"`
}

type startedRecord struct {
	sequence uint64
	signed   capability.SignedCapability
	verified capability.VerifiedCapability
	received time.Time
	deadline time.Time
	terminal *terminalRecord
}

type terminalRecord struct {
	sequence uint64
	signed   capability.SignedResult
	verified capability.VerifiedResult
}

func newStartedPayload(
	signed capability.SignedCapability,
	verified capability.VerifiedCapability,
	received, deadline time.Time,
	sequence uint64,
	previous string,
) recordPayload {
	value := verified.Value()
	return recordPayload{
		ArtifactB64URL: encodeBytes(signed.ArtifactBytes()), ArtifactDigest: value.ArtifactDigest,
		CapabilityDigest: verified.Digest(), CapabilityID: value.CapabilityID,
		CapabilityJCSB64URL:       encodeBytes(signed.CanonicalBytes()),
		CapabilitySignatureB64URL: encodeBytes(signed.Signature()),
		Deadline:                  formatTime(deadline), JournalSequence: sequence, Operation: string(value.Operation),
		OwnedSchemaDigest: value.OwnedSchemaDigest, Phase: phaseStarted,
		PreviousRecordDigest: optionalDigest(previous), ReceivedAt: formatTime(received),
		SchemaVersion: SchemaRecordV1, TargetIPv4: value.TargetIPv4,
	}
}

func newTerminalPayload(
	start *startedRecord,
	signed capability.SignedResult,
	verified capability.VerifiedResult,
	sequence uint64,
	previous string,
) recordPayload {
	value := start.verified.Value()
	resultDigest := verified.Digest()
	resultJCS := encodeBytes(signed.CanonicalBytes())
	resultSignature := encodeBytes(signed.Signature())
	return recordPayload{
		ArtifactB64URL: encodeBytes(start.signed.ArtifactBytes()), ArtifactDigest: value.ArtifactDigest,
		CapabilityDigest: start.verified.Digest(), CapabilityID: value.CapabilityID,
		CapabilityJCSB64URL:       encodeBytes(start.signed.CanonicalBytes()),
		CapabilitySignatureB64URL: encodeBytes(start.signed.Signature()),
		Deadline:                  formatTime(start.deadline), JournalSequence: sequence, Operation: string(value.Operation),
		OwnedSchemaDigest: value.OwnedSchemaDigest, Phase: phaseTerminal,
		PreviousRecordDigest: optionalDigest(previous), ReceivedAt: formatTime(start.received),
		SchemaVersion: SchemaRecordV1, TargetIPv4: value.TargetIPv4,
		TerminalResultDigest: &resultDigest, TerminalResultJCSB64URL: &resultJCS,
		TerminalResultSignatureB64URL: &resultSignature,
	}
}

func marshalRecordPayload(payload recordPayload) ([]byte, string, error) {
	if payload.RecordChecksum != "" {
		return nil, "", reject(ErrorCorrupt)
	}
	checksumInput, err := json.Marshal(checksumPayload(payload))
	if err != nil {
		return nil, "", reject(ErrorCorrupt)
	}
	payload.RecordChecksum = digestPayload(checksumInput)
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxPayloadBytes {
		return nil, "", reject(ErrorCorrupt)
	}
	return encoded, digestPayload(encoded), nil
}

func parseRecordPayload(data []byte, recordType byte, sequence uint64, previous string) (recordPayload, string, error) {
	var payload recordPayload
	if err := strictPayload(data, &payload); err != nil || !validRecordShape(payload, recordType, sequence) {
		return recordPayload{}, "", reject(ErrorCorrupt)
	}
	checksumInput, err := json.Marshal(checksumPayload(payload))
	if err != nil || !digestEqual(payload.RecordChecksum, digestPayload(checksumInput)) {
		return recordPayload{}, "", reject(ErrorCorrupt)
	}
	if sequence == 1 {
		if previous != "" || payload.PreviousRecordDigest != nil {
			return recordPayload{}, "", reject(ErrorCorrupt)
		}
	} else if previous == "" || payload.PreviousRecordDigest == nil || !digestEqual(*payload.PreviousRecordDigest, previous) {
		return recordPayload{}, "", reject(ErrorCorrupt)
	}
	return payload, digestPayload(data), nil
}

func validRecordShape(payload recordPayload, recordType byte, sequence uint64) bool {
	if payload.SchemaVersion != SchemaRecordV1 || payload.JournalSequence != sequence || sequence == 0 ||
		payload.CapabilityID == "" || payload.TargetIPv4 == "" ||
		!validDigest(payload.CapabilityDigest) || !validDigest(payload.ArtifactDigest) ||
		!validDigest(payload.OwnedSchemaDigest) || !validDigest(payload.RecordChecksum) ||
		(payload.PreviousRecordDigest != nil && !validDigest(*payload.PreviousRecordDigest)) {
		return false
	}
	if payload.Operation != string(capability.OperationAdd) && payload.Operation != string(capability.OperationRevoke) &&
		payload.Operation != string(capability.OperationInspect) {
		return false
	}
	if _, ok := decodeBytes(payload.CapabilityJCSB64URL, capability.MaxCapabilityBytes); !ok {
		return false
	}
	if signature, ok := decodeBytes(payload.CapabilitySignatureB64URL, 64); !ok || len(signature) != 64 {
		return false
	}
	if _, ok := decodeBytes(payload.ArtifactB64URL, capability.MaxArtifactBytes); !ok {
		return false
	}
	received, receivedOK := parseTime(payload.ReceivedAt)
	deadline, deadlineOK := parseTime(payload.Deadline)
	if !receivedOK || !deadlineOK || !deadline.After(received) || deadline.Sub(received) > MaxDeadline {
		return false
	}
	switch payload.Phase {
	case phaseStarted:
		return recordType == recordStarted && payload.TerminalResultDigest == nil &&
			payload.TerminalResultJCSB64URL == nil && payload.TerminalResultSignatureB64URL == nil
	case phaseTerminal:
		if recordType != recordTerminal || payload.PreviousRecordDigest == nil || payload.TerminalResultDigest == nil ||
			payload.TerminalResultJCSB64URL == nil || payload.TerminalResultSignatureB64URL == nil ||
			!validDigest(*payload.TerminalResultDigest) {
			return false
		}
		if _, ok := decodeBytes(*payload.TerminalResultJCSB64URL, capability.MaxResultBytes); !ok {
			return false
		}
		signature, ok := decodeBytes(*payload.TerminalResultSignatureB64URL, 64)
		return ok && len(signature) == 64
	default:
		return false
	}
}

func parseStartedPayload(payload recordPayload, verifier CapabilityVerifier, sequence uint64) (*startedRecord, error) {
	canonical, canonicalOK := decodeBytes(payload.CapabilityJCSB64URL, capability.MaxCapabilityBytes)
	signature, signatureOK := decodeBytes(payload.CapabilitySignatureB64URL, 64)
	artifact, artifactOK := decodeBytes(payload.ArtifactB64URL, capability.MaxArtifactBytes)
	if !canonicalOK || !signatureOK || !artifactOK || verifier.KeyID() == "" {
		return nil, reject(ErrorCorrupt)
	}
	signed := capability.NewUntrustedSignedCapability(verifier.KeyID(), canonical, signature, artifact)
	verified, err := verifier.Verify(signed)
	if err != nil {
		return nil, reject(ErrorVerification)
	}
	value := verified.Value()
	if payload.CapabilityID != value.CapabilityID || payload.CapabilityDigest != verified.Digest() ||
		payload.ArtifactDigest != value.ArtifactDigest || payload.OwnedSchemaDigest != value.OwnedSchemaDigest ||
		payload.Operation != string(value.Operation) || payload.TargetIPv4 != value.TargetIPv4 {
		return nil, reject(ErrorVerification)
	}
	received, receivedOK := parseTime(payload.ReceivedAt)
	deadline, deadlineOK := parseTime(payload.Deadline)
	if !receivedOK || !deadlineOK || !deadline.After(received) || deadline.Sub(received) > MaxDeadline ||
		deadline.After(value.ExpiresAt) {
		return nil, reject(ErrorTime)
	}
	return &startedRecord{sequence: sequence, signed: signed, verified: verified, received: received, deadline: deadline}, nil
}

func parseTerminalPayload(payload recordPayload, verifier ResultVerifier, sequence uint64, start *startedRecord) (*terminalRecord, error) {
	capabilityJCS, capabilityOK := decodeBytes(payload.CapabilityJCSB64URL, capability.MaxCapabilityBytes)
	capabilitySignature, signatureOK := decodeBytes(payload.CapabilitySignatureB64URL, 64)
	artifact, artifactOK := decodeBytes(payload.ArtifactB64URL, capability.MaxArtifactBytes)
	if !capabilityOK || !signatureOK || !artifactOK ||
		!bytes.Equal(capabilityJCS, start.signed.CanonicalBytes()) ||
		!bytes.Equal(capabilitySignature, start.signed.Signature()) ||
		!bytes.Equal(artifact, start.signed.ArtifactBytes()) ||
		payload.CapabilityID != start.verified.Value().CapabilityID ||
		payload.CapabilityDigest != start.verified.Digest() ||
		payload.ArtifactDigest != start.verified.Value().ArtifactDigest ||
		payload.OwnedSchemaDigest != start.verified.Value().OwnedSchemaDigest ||
		payload.Operation != string(start.verified.Value().Operation) ||
		payload.TargetIPv4 != start.verified.Value().TargetIPv4 ||
		payload.ReceivedAt != formatTime(start.received) || payload.Deadline != formatTime(start.deadline) {
		return nil, reject(ErrorVerification)
	}
	canonical, canonicalOK := decodeBytes(*payload.TerminalResultJCSB64URL, capability.MaxResultBytes)
	signature, resultSignatureOK := decodeBytes(*payload.TerminalResultSignatureB64URL, 64)
	if !canonicalOK || !resultSignatureOK || verifier.KeyID() == "" || verifier.ExecutorID() == "" {
		return nil, reject(ErrorCorrupt)
	}
	signed := capability.NewUntrustedSignedResult(verifier.KeyID(), verifier.ExecutorID(), canonical, signature)
	verified, err := verifier.Verify(signed)
	if err != nil {
		return nil, reject(ErrorVerification)
	}
	if _, err := verified.BindTo(start.verified); err != nil {
		return nil, reject(ErrorVerification)
	}
	value := verified.Value()
	if value.JournalSequence != start.sequence || *payload.TerminalResultDigest != verified.Digest() {
		return nil, reject(ErrorVerification)
	}
	return &terminalRecord{sequence: sequence, signed: signed, verified: verified}, nil
}

func checksumPayload(payload recordPayload) recordChecksumPayload {
	return recordChecksumPayload{
		ArtifactB64URL: payload.ArtifactB64URL, ArtifactDigest: payload.ArtifactDigest,
		CapabilityDigest: payload.CapabilityDigest, CapabilityID: payload.CapabilityID,
		CapabilityJCSB64URL:       payload.CapabilityJCSB64URL,
		CapabilitySignatureB64URL: payload.CapabilitySignatureB64URL,
		Deadline:                  payload.Deadline, JournalSequence: payload.JournalSequence, Operation: payload.Operation,
		OwnedSchemaDigest: payload.OwnedSchemaDigest, Phase: payload.Phase,
		PreviousRecordDigest: cloneStringPointer(payload.PreviousRecordDigest), ReceivedAt: payload.ReceivedAt,
		SchemaVersion: payload.SchemaVersion, TargetIPv4: payload.TargetIPv4,
		TerminalResultDigest:          cloneStringPointer(payload.TerminalResultDigest),
		TerminalResultJCSB64URL:       cloneStringPointer(payload.TerminalResultJCSB64URL),
		TerminalResultSignatureB64URL: cloneStringPointer(payload.TerminalResultSignatureB64URL),
	}
}

func strictPayload(data []byte, destination any) error {
	if len(data) == 0 || len(data) > MaxPayloadBytes {
		return reject(ErrorCorrupt)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return reject(ErrorCorrupt)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return reject(ErrorCorrupt)
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, data) {
		return reject(ErrorCorrupt)
	}
	return nil
}

func optionalDigest(value string) *string {
	if value == "" {
		return nil
	}
	copyValue := value
	return &copyValue
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func digestPayload(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == sha256.Size
}

func digestEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func encodeBytes(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func decodeBytes(value string, maximum int) ([]byte, bool) {
	if value == "" {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum || encodeBytes(decoded) != value {
		return nil, false
	}
	return decoded, true
}

func formatTime(value time.Time) string { return value.UTC().Format(journalTimeLayout) }

func parseTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(journalTimeLayout, value)
	return parsed, err == nil && formatTime(parsed) == value
}
