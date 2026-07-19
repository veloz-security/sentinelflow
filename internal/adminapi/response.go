package adminapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

type ErrorCode string

const (
	ErrorAuthenticationRequired ErrorCode = "authentication_required"
	ErrorPermissionDenied       ErrorCode = "permission_denied"
	ErrorCSRFInvalid            ErrorCode = "csrf_invalid"
	ErrorStepUpRequired         ErrorCode = "step_up_required"
	ErrorRateLimited            ErrorCode = "rate_limited"
	ErrorStaleVersion           ErrorCode = "stale_version"
	ErrorDigestMismatch         ErrorCode = "digest_mismatch"
	ErrorChallengeExpired       ErrorCode = "challenge_expired"
	ErrorChallengeConsumed      ErrorCode = "challenge_consumed"
	ErrorIdempotencyConflict    ErrorCode = "idempotency_conflict"
	ErrorValidationFailed       ErrorCode = "validation_failed"
	ErrorSchemaInvalid          ErrorCode = "schema_invalid"
	ErrorNotFound               ErrorCode = "not_found"
	ErrorServiceUnavailable     ErrorCode = "service_unavailable"
	ErrorInternal               ErrorCode = "internal_error"
)

type errorResponse struct {
	Code    ErrorCode      `json:"code"`
	Message string         `json:"message"`
	TraceID string         `json:"trace_id"`
	Details map[string]any `json:"details"`
}

type sessionEnvelope struct {
	Session   SessionProjection `json:"session"`
	CSRFToken string            `json:"csrf_token,omitempty"`
}

func setCommonHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	// Nested authentication/HIL middleware shares one response trace. Do not
	// replace the outer trace when another package-owned layer reapplies the
	// same hardening headers.
	if writer.Header().Get("X-SentinelFlow-Trace-ID") == "" {
		writer.Header().Set("X-SentinelFlow-Trace-ID", newTraceID())
	}
}

func writeError(writer http.ResponseWriter, status int, code ErrorCode, retryAfter time.Duration) {
	if status == http.StatusUnauthorized {
		writer.Header().Set("WWW-Authenticate", `Session realm="sentinelflow-admin"`)
	}
	if status == http.StatusTooManyRequests {
		seconds := int((retryAfter + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		if seconds > 60 {
			seconds = 60
		}
		writer.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	message := map[ErrorCode]string{
		ErrorAuthenticationRequired: "authentication is required",
		ErrorPermissionDenied:       "permission is denied",
		ErrorCSRFInvalid:            "CSRF validation failed",
		ErrorStepUpRequired:         "password step-up is required",
		ErrorRateLimited:            "request rate limit exceeded",
		ErrorStaleVersion:           "resource version is stale",
		ErrorDigestMismatch:         "artifact digest does not match",
		ErrorChallengeExpired:       "challenge has expired",
		ErrorChallengeConsumed:      "challenge was already consumed",
		ErrorIdempotencyConflict:    "idempotency key conflicts with an existing request",
		ErrorValidationFailed:       "request validation failed",
		ErrorSchemaInvalid:          "request does not match the API contract",
		ErrorNotFound:               "resource was not found",
		ErrorServiceUnavailable:     "service is temporarily unavailable",
		ErrorInternal:               "request could not be completed",
	}[code]
	if message == "" {
		code = ErrorInternal
		message = "request could not be completed"
	}
	traceID := writer.Header().Get("X-SentinelFlow-Trace-ID")
	if traceID == "" {
		traceID = newTraceID()
		writer.Header().Set("X-SentinelFlow-Trace-ID", traceID)
	}
	writeJSON(writer, status, errorResponse{Code: code, Message: message, TraceID: traceID, Details: map[string]any{}})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}

var fallbackTraceCounter atomic.Uint64

func newTraceID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		var seed [16]byte
		binary.BigEndian.PutUint64(seed[:8], uint64(time.Now().UTC().UnixNano()))
		binary.BigEndian.PutUint64(seed[8:], fallbackTraceCounter.Add(1))
		digest := sha256.Sum256(seed[:])
		copy(value[:], digest[:len(value)])
		clear(seed[:])
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	raw := hex.EncodeToString(value[:])
	clear(value[:])
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
}
