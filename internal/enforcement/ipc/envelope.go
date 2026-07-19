package ipc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const (
	RequestEnvelopeSchemaVersion  = "executor-request-envelope-v1"
	RecoveryRequestSchemaVersion  = "executor-recovery-request-envelope-v1"
	ResponseEnvelopeSchemaVersion = "executor-response-envelope-v1"
	maxEncodedFieldLength         = 21_846
)

var (
	ErrEnvelopeInvalid      = errors.New("executor IPC envelope is invalid")
	ErrEnvelopeNonCanonical = errors.New("executor IPC envelope is not canonical")
)

type RequestEnvelope struct {
	capabilityJCS       []byte
	capabilitySignature []byte
	artifact            []byte
	recoveryOnly        bool
}

func (e RequestEnvelope) CapabilityJCS() []byte       { return bytes.Clone(e.capabilityJCS) }
func (e RequestEnvelope) CapabilitySignature() []byte { return bytes.Clone(e.capabilitySignature) }
func (e RequestEnvelope) Artifact() []byte            { return bytes.Clone(e.artifact) }
func (e RequestEnvelope) RecoveryOnly() bool          { return e.recoveryOnly }

type ResponseEnvelope struct {
	resultJCS       []byte
	resultSignature []byte
}

func (e ResponseEnvelope) ResultJCS() []byte       { return bytes.Clone(e.resultJCS) }
func (e ResponseEnvelope) ResultSignature() []byte { return bytes.Clone(e.resultSignature) }

// Fields are declared in RFC 8785 lexical key order. Their values contain only
// the contract's ASCII base64url alphabet and schema constant, so json.Marshal
// emits the exact JCS envelope representation.
type requestEnvelopeWire struct {
	ArtifactB64URL            string `json:"artifact_b64url"`
	CapabilityJCSB64URL       string `json:"capability_jcs_b64url"`
	CapabilitySignatureB64URL string `json:"capability_signature_b64url"`
	SchemaVersion             string `json:"schema_version"`
}

type responseEnvelopeWire struct {
	ResultJCSB64URL       string `json:"result_jcs_b64url"`
	ResultSignatureB64URL string `json:"result_signature_b64url"`
	SchemaVersion         string `json:"schema_version"`
}

func NewRequestEnvelope(capabilityJCS, signature, artifact []byte) (RequestEnvelope, error) {
	return newRequestEnvelope(capabilityJCS, signature, artifact, false)
}

// NewRecoveryRequestEnvelope marks an exact persisted-capability exchange.
// The executor handles it with journal lookup/recovery only and can never
// create a started frame or release a mutation permit.
func NewRecoveryRequestEnvelope(capabilityJCS, signature, artifact []byte) (RequestEnvelope, error) {
	return newRequestEnvelope(capabilityJCS, signature, artifact, true)
}

func newRequestEnvelope(capabilityJCS, signature, artifact []byte, recoveryOnly bool) (RequestEnvelope, error) {
	if !validJSONObject(capabilityJCS) || len(signature) != 64 || len(artifact) == 0 {
		return RequestEnvelope{}, ErrEnvelopeInvalid
	}
	return RequestEnvelope{
		capabilityJCS:       bytes.Clone(capabilityJCS),
		capabilitySignature: bytes.Clone(signature),
		artifact:            bytes.Clone(artifact),
		recoveryOnly:        recoveryOnly,
	}, nil
}

func NewResponseEnvelope(resultJCS, signature []byte) (ResponseEnvelope, error) {
	if !validJSONObject(resultJCS) || len(signature) != 64 {
		return ResponseEnvelope{}, ErrEnvelopeInvalid
	}
	return ResponseEnvelope{resultJCS: bytes.Clone(resultJCS), resultSignature: bytes.Clone(signature)}, nil
}

func EncodeRequestEnvelope(value RequestEnvelope) ([]byte, error) {
	if !validJSONObject(value.capabilityJCS) || len(value.capabilitySignature) != 64 || len(value.artifact) == 0 {
		return nil, ErrEnvelopeInvalid
	}
	wire := requestEnvelopeWire{
		ArtifactB64URL:            base64.RawURLEncoding.EncodeToString(value.artifact),
		CapabilityJCSB64URL:       base64.RawURLEncoding.EncodeToString(value.capabilityJCS),
		CapabilitySignatureB64URL: base64.RawURLEncoding.EncodeToString(value.capabilitySignature),
		SchemaVersion:             RequestEnvelopeSchemaVersion,
	}
	if value.recoveryOnly {
		wire.SchemaVersion = RecoveryRequestSchemaVersion
	}
	return marshalBoundedEnvelope(wire)
}

func EncodeResponseEnvelope(value ResponseEnvelope) ([]byte, error) {
	if !validJSONObject(value.resultJCS) || len(value.resultSignature) != 64 {
		return nil, ErrEnvelopeInvalid
	}
	wire := responseEnvelopeWire{
		ResultJCSB64URL:       base64.RawURLEncoding.EncodeToString(value.resultJCS),
		ResultSignatureB64URL: base64.RawURLEncoding.EncodeToString(value.resultSignature),
		SchemaVersion:         ResponseEnvelopeSchemaVersion,
	}
	return marshalBoundedEnvelope(wire)
}

func DecodeRequestEnvelope(payload []byte) (RequestEnvelope, error) {
	if len(payload) == 0 || len(payload) > MaxFramePayloadBytes || !json.Valid(payload) {
		return RequestEnvelope{}, ErrEnvelopeInvalid
	}
	var wire requestEnvelopeWire
	if err := json.Unmarshal(payload, &wire); err != nil ||
		(wire.SchemaVersion != RequestEnvelopeSchemaVersion && wire.SchemaVersion != RecoveryRequestSchemaVersion) {
		return RequestEnvelope{}, ErrEnvelopeInvalid
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) {
		return RequestEnvelope{}, ErrEnvelopeNonCanonical
	}
	capability, err := decodeRawURLField(wire.CapabilityJCSB64URL)
	if err != nil || !validJSONObject(capability) {
		return RequestEnvelope{}, ErrEnvelopeInvalid
	}
	signature, err := decodeRawURLField(wire.CapabilitySignatureB64URL)
	if err != nil || len(wire.CapabilitySignatureB64URL) != 86 || len(signature) != 64 {
		return RequestEnvelope{}, ErrEnvelopeInvalid
	}
	artifact, err := decodeRawURLField(wire.ArtifactB64URL)
	if err != nil || len(artifact) == 0 {
		return RequestEnvelope{}, ErrEnvelopeInvalid
	}
	return newRequestEnvelope(
		capability, signature, artifact, wire.SchemaVersion == RecoveryRequestSchemaVersion,
	)
}

func DecodeResponseEnvelope(payload []byte) (ResponseEnvelope, error) {
	if len(payload) == 0 || len(payload) > MaxFramePayloadBytes || !json.Valid(payload) {
		return ResponseEnvelope{}, ErrEnvelopeInvalid
	}
	var wire responseEnvelopeWire
	if err := json.Unmarshal(payload, &wire); err != nil || wire.SchemaVersion != ResponseEnvelopeSchemaVersion {
		return ResponseEnvelope{}, ErrEnvelopeInvalid
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) {
		return ResponseEnvelope{}, ErrEnvelopeNonCanonical
	}
	result, err := decodeRawURLField(wire.ResultJCSB64URL)
	if err != nil || !validJSONObject(result) {
		return ResponseEnvelope{}, ErrEnvelopeInvalid
	}
	signature, err := decodeRawURLField(wire.ResultSignatureB64URL)
	if err != nil || len(wire.ResultSignatureB64URL) != 86 || len(signature) != 64 {
		return ResponseEnvelope{}, ErrEnvelopeInvalid
	}
	return NewResponseEnvelope(result, signature)
}

func marshalBoundedEnvelope(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, ErrEnvelopeInvalid
	}
	if err = validateFramePayload(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodeRawURLField(value string) ([]byte, error) {
	if len(value) == 0 || len(value) > maxEncodedFieldLength {
		return nil, ErrEnvelopeInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, ErrEnvelopeInvalid
	}
	return decoded, nil
}

func validJSONObject(value []byte) bool {
	if len(value) < 2 || value[0] != '{' || value[len(value)-1] != '}' || !json.Valid(value) {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(value, &object) == nil && object != nil
}
