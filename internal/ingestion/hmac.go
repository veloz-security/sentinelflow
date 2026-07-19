// Package ingestion authenticates SentinelFlow's internal event batches before
// they reach persistence. It deliberately does not own replay-store or database
// transactions; callers must consume ReplayNonceDigest atomically with storage.
package ingestion

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
)

const (
	GatewayEventsPath = "/internal/v1/gateway-events"
	AuthEventsPath    = "/internal/v1/auth-events"

	maxAuthenticationSkew = 60 * time.Second
)

var senderIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type ErrorCode string

const (
	ErrorInvalidHeader   ErrorCode = "invalid_header"
	ErrorUnknownSender   ErrorCode = "unknown_sender"
	ErrorTimestampSkew   ErrorCode = "timestamp_skew"
	ErrorBodyTooLarge    ErrorCode = "body_too_large"
	ErrorSignature       ErrorCode = "signature_mismatch"
	ErrorInvalidBody     ErrorCode = "invalid_body"
	ErrorSenderMismatch  ErrorCode = "sender_mismatch"
	ErrorRecordForbidden ErrorCode = "record_schema_not_allowed"
)

// AuthError intentionally excludes supplied header and body values.
type AuthError struct {
	Code ErrorCode
}

func (e *AuthError) Error() string { return "event batch authentication failed: " + string(e.Code) }

func IsCode(err error, code ErrorCode) bool {
	var authErr *AuthError
	return errors.As(err, &authErr) && authErr.Code == code
}

func authError(code ErrorCode) error { return &AuthError{Code: code} }

type Headers struct {
	SenderID  string
	Timestamp string
	Nonce     string
	Signature string
}

// Binding binds one sender identity to exactly one endpoint and key.
type Binding struct {
	SenderID     string
	EndpointPath string
	// KeyID is non-secret rotation identity carried into authenticated receiver
	// state. Empty remains valid for legacy non-coverage ingestion, but cannot
	// satisfy a positive source-coverage binding.
	KeyID string
	Key   []byte
}

type Registry struct {
	bindings map[string]Binding
}

func NewRegistry(bindings []Binding) (*Registry, error) {
	registry := &Registry{bindings: make(map[string]Binding, len(bindings))}
	seenSenderIDs := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if !senderIDPattern.MatchString(binding.SenderID) {
			return nil, fmt.Errorf("invalid sender binding")
		}
		if binding.EndpointPath != GatewayEventsPath && binding.EndpointPath != AuthEventsPath {
			return nil, fmt.Errorf("invalid endpoint binding")
		}
		if binding.KeyID != "" && !senderIDPattern.MatchString(binding.KeyID) {
			return nil, fmt.Errorf("invalid key identity")
		}
		if len(binding.Key) < 32 {
			return nil, fmt.Errorf("sender key must be at least 32 bytes")
		}
		// Persistent batch identity is sender-global. Binding one sender ID to
		// multiple endpoints would make independent epoch/batch/sequence values
		// collide in storage and weaken the endpoint-specific authority model.
		if _, exists := seenSenderIDs[binding.SenderID]; exists {
			return nil, fmt.Errorf("sender ID must be bound to exactly one endpoint")
		}
		seenSenderIDs[binding.SenderID] = struct{}{}
		lookupKey := bindingKey(binding.EndpointPath, binding.SenderID)
		if _, exists := registry.bindings[lookupKey]; exists {
			return nil, fmt.Errorf("duplicate sender binding")
		}
		binding.Key = append([]byte(nil), binding.Key...)
		registry.bindings[lookupKey] = binding
	}
	return registry, nil
}

type AuthenticatedBatch struct {
	Batch      events.EventBatchV1
	BodyDigest string
	// KeyID is receiver-local authentication metadata, never sender-controlled
	// wire data and never a key or verifier.
	KeyID string
	// RawBodySize is captured from the exact HMAC-authenticated byte slice. A
	// persistence layer must not re-encode Batch to guess this value because
	// equivalent JSON can have different authenticated bytes and sizes.
	RawBodySize       int
	ReplayNonceDigest [sha256.Size]byte
	AuthenticatedAt   time.Time
}

// Authenticate follows the ordered contract: header syntax, bound-key lookup,
// timestamp, body bound/digest, HMAC, strict JSON, sender equality, record set.
func (r *Registry) Authenticate(endpointPath string, headers Headers, rawBody []byte, now time.Time) (AuthenticatedBatch, error) {
	timestamp, nonce, presentedSignature, err := parseHeaders(headers)
	if err != nil {
		return AuthenticatedBatch{}, err
	}

	binding, ok := r.bindings[bindingKey(endpointPath, headers.SenderID)]
	if !ok {
		return AuthenticatedBatch{}, authError(ErrorUnknownSender)
	}

	now = now.UTC()
	if delta := now.Sub(timestamp); delta > maxAuthenticationSkew || delta < -maxAuthenticationSkew {
		return AuthenticatedBatch{}, authError(ErrorTimestampSkew)
	}
	if len(rawBody) > events.MaxEventBatchBodyBytes {
		return AuthenticatedBatch{}, authError(ErrorBodyTooLarge)
	}

	bodySum := sha256.Sum256(rawBody)
	input := signingInput(endpointPath, headers.SenderID, headers.Timestamp, headers.Nonce, bodySum)
	expected := hmacSHA256(binding.Key, input)
	if !hmac.Equal(presentedSignature, expected) {
		return AuthenticatedBatch{}, authError(ErrorSignature)
	}

	batch, decodeErr := events.DecodeEventBatchV1(rawBody)
	if decodeErr != nil {
		return AuthenticatedBatch{}, authError(ErrorInvalidBody)
	}
	if batch.SenderID != headers.SenderID {
		return AuthenticatedBatch{}, authError(ErrorSenderMismatch)
	}
	if !recordsAllowed(endpointPath, headers.SenderID, batch.Records) {
		return AuthenticatedBatch{}, authError(ErrorRecordForbidden)
	}

	return AuthenticatedBatch{
		Batch:             batch,
		BodyDigest:        "sha256:" + hex.EncodeToString(bodySum[:]),
		KeyID:             binding.KeyID,
		RawBodySize:       len(rawBody),
		ReplayNonceDigest: sha256.Sum256(nonce),
		AuthenticatedAt:   now,
	}, nil
}

// Sign produces the exact four transport headers. The raw body must be reused
// byte-for-byte on retry; a caller supplies a fresh nonce and timestamp.
func Sign(endpointPath, senderID string, key, rawBody, nonce []byte, now time.Time) (Headers, error) {
	if endpointPath != GatewayEventsPath && endpointPath != AuthEventsPath {
		return Headers{}, fmt.Errorf("invalid endpoint")
	}
	if !senderIDPattern.MatchString(senderID) || len(key) < 32 || len(nonce) != 16 {
		return Headers{}, fmt.Errorf("invalid signing input")
	}
	if len(rawBody) > events.MaxEventBatchBodyBytes {
		return Headers{}, fmt.Errorf("body exceeds 256 KiB")
	}

	timestamp := strconv.FormatInt(now.UTC().Unix(), 10)
	encodedNonce := base64.RawURLEncoding.EncodeToString(nonce)
	bodySum := sha256.Sum256(rawBody)
	input := signingInput(endpointPath, senderID, timestamp, encodedNonce, bodySum)
	signature := hmacSHA256(key, input)
	return Headers{
		SenderID:  senderID,
		Timestamp: timestamp,
		Nonce:     encodedNonce,
		Signature: hex.EncodeToString(signature),
	}, nil
}

func parseHeaders(headers Headers) (time.Time, []byte, []byte, error) {
	if !senderIDPattern.MatchString(headers.SenderID) {
		return time.Time{}, nil, nil, authError(ErrorInvalidHeader)
	}
	if len(headers.Timestamp) < 1 || len(headers.Timestamp) > 12 || strings.Trim(headers.Timestamp, "0123456789") != "" {
		return time.Time{}, nil, nil, authError(ErrorInvalidHeader)
	}
	unixSeconds, err := strconv.ParseInt(headers.Timestamp, 10, 64)
	if err != nil || unixSeconds < 0 {
		return time.Time{}, nil, nil, authError(ErrorInvalidHeader)
	}
	if len(headers.Nonce) != 22 || strings.Contains(headers.Nonce, "=") {
		return time.Time{}, nil, nil, authError(ErrorInvalidHeader)
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(headers.Nonce)
	if err != nil || len(nonce) != 16 {
		return time.Time{}, nil, nil, authError(ErrorInvalidHeader)
	}
	if len(headers.Signature) != 64 || strings.ToLower(headers.Signature) != headers.Signature {
		return time.Time{}, nil, nil, authError(ErrorInvalidHeader)
	}
	signature, err := hex.DecodeString(headers.Signature)
	if err != nil || len(signature) != sha256.Size {
		return time.Time{}, nil, nil, authError(ErrorInvalidHeader)
	}
	return time.Unix(unixSeconds, 0).UTC(), nonce, signature, nil
}

func recordsAllowed(endpointPath, senderID string, records []events.EventRecordV1) bool {
	for _, record := range records {
		switch endpointPath {
		case GatewayEventsPath:
			if record.GatewayHTTP == nil && record.SourceHealth == nil && record.SourceCoverage == nil {
				return false
			}
		case AuthEventsPath:
			if record.AuthEvent == nil && record.SourceHealth == nil && record.SourceCoverage == nil {
				return false
			}
		default:
			return false
		}
		if record.SourceHealth != nil && record.SourceHealth.SourceID != senderID {
			return false
		}
		if record.SourceCoverage != nil && record.SourceCoverage.SourceID != senderID {
			return false
		}
	}
	return true
}

func signingInput(endpointPath, senderID, timestamp, nonce string, bodySum [sha256.Size]byte) []byte {
	return []byte(endpointPath + "\n" + senderID + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(bodySum[:]))
}

func hmacSHA256(key, input []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	return mac.Sum(nil)
}

func bindingKey(endpointPath, senderID string) string { return endpointPath + "\x00" + senderID }
