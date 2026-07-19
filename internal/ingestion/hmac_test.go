package ingestion

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type vectorBundle struct {
	Vectors struct {
		EventBatch struct {
			Positive []hmacVector `json:"positive_cases"`
			Negative []struct {
				CaseID            string `json:"case_id"`
				SourceCaseID      string `json:"source_case_id"`
				PresentedEndpoint string `json:"presented_endpoint_path"`
				PresentedSender   string `json:"presented_sender_id"`
				Signature         string `json:"presented_signature_hex"`
			} `json:"negative_cases"`
		} `json:"event_batch_hmac_v1"`
	} `json:"vectors"`
}

type hmacVector struct {
	CaseID       string `json:"case_id"`
	EndpointPath string `json:"endpoint_path"`
	KeyBase64    string `json:"key_base64"`
	Headers      struct {
		SenderID  string `json:"X-Sentinel-Sender-ID"`
		Timestamp string `json:"X-Sentinel-Timestamp"`
		Nonce     string `json:"X-Sentinel-Nonce"`
		Signature string `json:"X-Sentinel-Signature"`
	} `json:"headers"`
	RawBodyBase64URL string `json:"raw_body_b64url"`
	BodyDigest       string `json:"raw_body_sha256"`
}

func TestContractHMACVectors(t *testing.T) {
	t.Parallel()
	bundle := loadVectors(t)
	positiveByID := make(map[string]hmacVector, len(bundle.Vectors.EventBatch.Positive))

	for _, vector := range bundle.Vectors.EventBatch.Positive {
		vector := vector
		positiveByID[vector.CaseID] = vector
		t.Run(vector.CaseID, func(t *testing.T) {
			t.Parallel()
			key := decodeBase64(t, vector.KeyBase64)
			body := decodeBase64URL(t, vector.RawBodyBase64URL)
			registry, err := NewRegistry([]Binding{{SenderID: vector.Headers.SenderID, EndpointPath: vector.EndpointPath, Key: key}})
			if err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			result, err := registry.Authenticate(vector.EndpointPath, headersFor(vector), body, time.Unix(1784257200, 0))
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
			if result.BodyDigest != vector.BodyDigest {
				t.Fatalf("BodyDigest = %q, want %q", result.BodyDigest, vector.BodyDigest)
			}
			if result.RawBodySize != len(body) {
				t.Fatalf("RawBodySize = %d, want exact authenticated size %d", result.RawBodySize, len(body))
			}
		})
	}

	for _, negative := range bundle.Vectors.EventBatch.Negative {
		negative := negative
		t.Run(negative.CaseID, func(t *testing.T) {
			t.Parallel()
			source := positiveByID[negative.SourceCaseID]
			key := decodeBase64(t, source.KeyBase64)
			body := decodeBase64URL(t, source.RawBodyBase64URL)
			registry, err := NewRegistry([]Binding{{SenderID: negative.PresentedSender, EndpointPath: negative.PresentedEndpoint, Key: key}})
			if err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			headers := headersFor(source)
			headers.SenderID = negative.PresentedSender
			headers.Signature = negative.Signature
			_, err = registry.Authenticate(negative.PresentedEndpoint, headers, body, time.Unix(1784257200, 0))
			if !IsCode(err, ErrorSignature) {
				t.Fatalf("Authenticate() error = %v, want signature mismatch", err)
			}
		})
	}
}

func TestSignAndAuthenticateRoundTrip(t *testing.T) {
	t.Parallel()
	bundle := loadVectors(t)
	vector := bundle.Vectors.EventBatch.Positive[0]
	key := decodeBase64(t, vector.KeyBase64)
	body := decodeBase64URL(t, vector.RawBodyBase64URL)
	nonce := decodeBase64URL(t, vector.Headers.Nonce)
	now := time.Unix(1784257200, 0).UTC()

	headers, err := Sign(vector.EndpointPath, vector.Headers.SenderID, key, body, nonce, now)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if headers.Signature != vector.Headers.Signature {
		t.Fatalf("signature = %q, want contract vector", headers.Signature)
	}
	registry, _ := NewRegistry([]Binding{{
		SenderID: headers.SenderID, EndpointPath: vector.EndpointPath, KeyID: "gateway-key-01", Key: key,
	}})
	authenticated, err := registry.Authenticate(vector.EndpointPath, headers, body, now)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authenticated.KeyID != "gateway-key-01" {
		t.Fatalf("authenticated key ID = %q", authenticated.KeyID)
	}
}

func TestAuthenticationOrderAndBoundaries(t *testing.T) {
	t.Parallel()
	bundle := loadVectors(t)
	vector := bundle.Vectors.EventBatch.Positive[0]
	key := decodeBase64(t, vector.KeyBase64)
	body := decodeBase64URL(t, vector.RawBodyBase64URL)
	now := time.Unix(1784257200, 0).UTC()
	registry, _ := NewRegistry([]Binding{{SenderID: vector.Headers.SenderID, EndpointPath: vector.EndpointPath, Key: key}})

	tests := []struct {
		name    string
		headers Headers
		body    []byte
		now     time.Time
		code    ErrorCode
	}{
		{name: "bad sender syntax", headers: withHeader(vector, func(h *Headers) { h.SenderID = "Gateway" }), body: body, now: now, code: ErrorInvalidHeader},
		{name: "unknown sender", headers: withHeader(vector, func(h *Headers) { h.SenderID = "other" }), body: body, now: now, code: ErrorUnknownSender},
		{name: "future skew", headers: headersFor(vector), body: body, now: now.Add(-61 * time.Second), code: ErrorTimestampSkew},
		{name: "past skew", headers: headersFor(vector), body: body, now: now.Add(61 * time.Second), code: ErrorTimestampSkew},
		{name: "bad nonce", headers: withHeader(vector, func(h *Headers) { h.Nonce = strings.Repeat("a", 22) }), body: body, now: now, code: ErrorInvalidHeader},
		{name: "uppercase signature", headers: withHeader(vector, func(h *Headers) { h.Signature = strings.ToUpper(h.Signature) }), body: body, now: now, code: ErrorInvalidHeader},
		{name: "signature before JSON", headers: withHeader(vector, func(h *Headers) { h.Signature = strings.Repeat("0", 64) }), body: []byte("not-json"), now: now, code: ErrorSignature},
		{name: "oversized before signature", headers: headersFor(vector), body: make([]byte, 256*1024+1), now: now, code: ErrorBodyTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := registry.Authenticate(vector.EndpointPath, tt.headers, tt.body, tt.now)
			if !IsCode(err, tt.code) {
				t.Fatalf("error = %v, want %s", err, tt.code)
			}
			if err != nil && strings.Contains(err.Error(), vector.Headers.Signature) {
				t.Fatal("error leaked authentication material")
			}
		})
	}
}

func TestRegistryRejectsUnsafeBindings(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	for _, binding := range []Binding{
		{SenderID: "UPPER", EndpointPath: GatewayEventsPath, Key: key},
		{SenderID: "gateway", EndpointPath: "/wrong", Key: key},
		{SenderID: "gateway", EndpointPath: GatewayEventsPath, KeyID: "INVALID KEY", Key: key},
		{SenderID: "gateway", EndpointPath: GatewayEventsPath, Key: key[:31]},
	} {
		if _, err := NewRegistry([]Binding{binding}); err == nil {
			t.Fatalf("NewRegistry(%+v) unexpectedly succeeded", binding)
		}
	}
	if _, err := NewRegistry([]Binding{
		{SenderID: "shared", EndpointPath: GatewayEventsPath, Key: key},
		{SenderID: "shared", EndpointPath: AuthEventsPath, Key: key},
	}); err == nil {
		t.Fatal("one sender ID was bound to two endpoints")
	}
}

func headersFor(vector hmacVector) Headers {
	return Headers{
		SenderID:  vector.Headers.SenderID,
		Timestamp: vector.Headers.Timestamp,
		Nonce:     vector.Headers.Nonce,
		Signature: vector.Headers.Signature,
	}
}

func withHeader(vector hmacVector, mutate func(*Headers)) Headers {
	headers := headersFor(vector)
	mutate(&headers)
	return headers
}

func loadVectors(t *testing.T) vectorBundle {
	t.Helper()
	data, err := os.ReadFile("../../contracts/vectors/contract_vectors_v1.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var bundle vectorBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	return bundle
}

func decodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatalf("base64 decode error = %v", err)
	}
	return decoded
}

func decodeBase64URL(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatalf("base64url decode error = %v", err)
	}
	return decoded
}
