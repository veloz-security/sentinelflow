package ipc

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func TestContractEnvelopeVectors(t *testing.T) {
	t.Parallel()
	vectors := loadIPCVectors(t)
	requestPayload := decodeRawVector(t, vectors.Vectors.Request.PayloadJCSB64)
	request, err := DecodeRequestEnvelope(requestPayload)
	if err != nil {
		t.Fatalf("DecodeRequestEnvelope(vector) error = %v", err)
	}
	encodedRequest, err := EncodeRequestEnvelope(request)
	if err != nil || !bytes.Equal(encodedRequest, requestPayload) {
		t.Fatalf("request round trip changed contract bytes: %v", err)
	}
	responsePayload := decodeRawVector(t, vectors.Vectors.Response.PayloadJCSB64)
	response, err := DecodeResponseEnvelope(responsePayload)
	if err != nil {
		t.Fatalf("DecodeResponseEnvelope(vector) error = %v", err)
	}
	encodedResponse, err := EncodeResponseEnvelope(response)
	if err != nil || !bytes.Equal(encodedResponse, responsePayload) {
		t.Fatalf("response round trip changed contract bytes: %v", err)
	}
}

func TestEnvelopeRejectsNonCanonicalAndInvalidInput(t *testing.T) {
	t.Parallel()
	vectors := loadIPCVectors(t)
	payload := decodeRawVector(t, vectors.Vectors.Request.PayloadJCSB64)

	var reordered bytes.Buffer
	reordered.WriteString("{\"schema_version\":\"executor-request-envelope-v1\",")
	reordered.Write(payload[1 : len(payload)-1])
	reordered.WriteByte('}')
	for _, test := range []struct {
		name    string
		payload []byte
		want    error
	}{
		{"leading whitespace", append([]byte{' '}, payload...), ErrEnvelopeNonCanonical},
		{"reordered keys", reordered.Bytes(), ErrEnvelopeNonCanonical},
		{"unknown field", append(append([]byte(nil), payload[:len(payload)-1]...), []byte(",\"unknown\":\"x\"}")...), ErrEnvelopeNonCanonical},
		{"duplicate field", append(append([]byte(nil), payload[:len(payload)-1]...), []byte(",\"schema_version\":\"executor-request-envelope-v1\"}")...), ErrEnvelopeNonCanonical},
		{"malformed", []byte("{\"schema_version\":"), ErrEnvelopeInvalid},
		{"empty", nil, ErrEnvelopeInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, got := DecodeRequestEnvelope(test.payload)
			if !errors.Is(got, test.want) {
				t.Fatalf("DecodeRequestEnvelope() error = %v, want %v", got, test.want)
			}
		})
	}
}

func TestEnvelopeRejectsPaddedAndMalformedFields(t *testing.T) {
	t.Parallel()
	capability := []byte("{\"schema_version\":\"execution-capability-v1\"}")
	signature := make([]byte, 64)
	artifact := []byte("add element")
	request, err := NewRequestEnvelope(capability, signature, artifact)
	if err != nil {
		t.Fatalf("NewRequestEnvelope() error = %v", err)
	}
	payload, _ := EncodeRequestEnvelope(request)
	padded := bytes.Replace(payload,
		[]byte(base64.RawURLEncoding.EncodeToString(artifact)),
		[]byte(base64.URLEncoding.EncodeToString(artifact)), 1)
	if _, err = DecodeRequestEnvelope(padded); err == nil {
		t.Fatal("padded base64url was accepted")
	}
	if _, err = NewRequestEnvelope([]byte("not-json"), signature, artifact); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatalf("invalid capability error = %v", err)
	}
	if _, err = NewRequestEnvelope(capability, signature[:63], artifact); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatalf("short signature error = %v", err)
	}
	if _, err = NewRequestEnvelope(capability, signature, nil); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatalf("empty artifact error = %v", err)
	}
}

func TestEnvelopeAccessorsAreDefensive(t *testing.T) {
	t.Parallel()
	capability := []byte("{\"schema_version\":\"execution-capability-v1\"}")
	signature := make([]byte, 64)
	artifact := []byte("artifact")
	request, err := NewRequestEnvelope(capability, signature, artifact)
	if err != nil {
		t.Fatalf("NewRequestEnvelope() error = %v", err)
	}
	request.CapabilityJCS()[0] = 'x'
	request.CapabilitySignature()[0] = 1
	request.Artifact()[0] = 'x'
	encoded, err := EncodeRequestEnvelope(request)
	if err != nil {
		t.Fatalf("EncodeRequestEnvelope() error = %v", err)
	}
	decoded, err := DecodeRequestEnvelope(encoded)
	if err != nil || !bytes.Equal(decoded.CapabilityJCS(), capability) ||
		!bytes.Equal(decoded.CapabilitySignature(), signature) || !bytes.Equal(decoded.Artifact(), artifact) {
		t.Fatal("accessor mutation changed the sealed envelope")
	}
}

func TestRecoveryRequestEnvelopeHasDistinctCanonicalSchema(t *testing.T) {
	t.Parallel()
	capabilityJCS := []byte(`{"schema_version":"execution-capability-v1"}`)
	signature := make([]byte, 64)
	artifact := []byte("artifact")
	recovery, err := NewRecoveryRequestEnvelope(capabilityJCS, signature, artifact)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeRequestEnvelope(recovery)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(`"schema_version":"executor-recovery-request-envelope-v1"`)) {
		t.Fatalf("recovery schema missing: %s", payload)
	}
	decoded, err := DecodeRequestEnvelope(payload)
	if err != nil || !decoded.RecoveryOnly() {
		t.Fatalf("recovery envelope lost discriminator: %v", err)
	}
	ordinary, err := NewRequestEnvelope(capabilityJCS, signature, artifact)
	if err != nil || ordinary.RecoveryOnly() {
		t.Fatalf("ordinary envelope gained recovery authority: %v", err)
	}
}
