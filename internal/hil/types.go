package hil

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"time"
)

const (
	ChallengeSchemaVersion = "hil-challenge-v1"
	DecisionSchemaVersion  = "hil-decision-v1"
	ReasonSchemaVersion    = "hil-reason-v1"

	ResourcePolicy            = "policy"
	ResourceEnforcementAction = "enforcement_action"

	ChallengeLifetime = 5 * time.Minute
	DecisionLifetime  = 5 * time.Minute
	ReauthAfter       = 15 * time.Minute

	MaxChallengeBytes      = 8 * 1024
	MaxDecisionBytes       = 8 * 1024
	MaxReasonBytes         = 4 * 1024
	MaxReasonRunes         = 500
	MinIdempotencyKeyBytes = 16
	MaxIdempotencyKeyBytes = 256
	NonceBytes             = 32
)

type Operation string

const (
	OperationApprove Operation = "approve"
	OperationReject  Operation = "reject"
	OperationRevoke  Operation = "revoke"
)

type DecisionValue string

const (
	DecisionApproved DecisionValue = "approved"
	DecisionRejected DecisionValue = "rejected"
	DecisionRevoked  DecisionValue = "revoked"
)

type ReasonCode string

const (
	ReasonThreatConfirmed   ReasonCode = "threat_confirmed"
	ReasonFalsePositive     ReasonCode = "false_positive"
	ReasonBusinessException ReasonCode = "business_exception"
	ReasonEmergencyRevoke   ReasonCode = "emergency_revoke"
	ReasonOperatorRequest   ReasonCode = "operator_request"
	ReasonOther             ReasonCode = "other"
)

type ErrorCode string

const (
	ErrorConfiguration     ErrorCode = "configuration_invalid"
	ErrorEncoding          ErrorCode = "encoding_invalid"
	ErrorCanonical         ErrorCode = "artifact_not_canonical"
	ErrorSchema            ErrorCode = "schema_invalid"
	ErrorField             ErrorCode = "field_invalid"
	ErrorDigest            ErrorCode = "digest_invalid"
	ErrorTime              ErrorCode = "time_invalid"
	ErrorReason            ErrorCode = "reason_invalid"
	ErrorArtifact          ErrorCode = "exact_artifact_invalid"
	ErrorArtifactMismatch  ErrorCode = "exact_artifact_mismatch"
	ErrorValidationFailed  ErrorCode = "validation_failed"
	ErrorValidationStale   ErrorCode = "validation_stale"
	ErrorAuthentication    ErrorCode = "authentication_invalid"
	ErrorStepUpRequired    ErrorCode = "step_up_required"
	ErrorChallengeExpired  ErrorCode = "challenge_expired"
	ErrorChallengeMismatch ErrorCode = "challenge_mismatch"
	ErrorNonce             ErrorCode = "nonce_invalid"
	ErrorNonceUnavailable  ErrorCode = "nonce_unavailable"
	ErrorIdempotency       ErrorCode = "idempotency_invalid"
	ErrorConsumed          ErrorCode = "challenge_consumed"
	ErrorConflict          ErrorCode = "decision_conflict"
	ErrorEntropy           ErrorCode = "entropy_unavailable"
)

// Error contains only a stable code. It intentionally never embeds actor,
// session, nonce, reason, command, evidence, or provider error material.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "HIL artifact rejected"
	}
	return "HIL artifact rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }

func IsCode(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.Code == code
}

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	actorIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

// Clock is injected so security freshness can be tested deterministically.
// Implementations used concurrently must make Now safe for concurrent calls.
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// SessionBinding is the already-authenticated server-side session state. Raw
// session and CSRF tokens never enter this package.
type SessionBinding struct {
	SessionID       string
	SessionDigest   string
	ActorID         string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}

func checkSession(value SessionBinding, now time.Time) (SessionBinding, error) {
	if !uuidPattern.MatchString(value.SessionID) || !digestPattern.MatchString(value.SessionDigest) ||
		!actorIDPattern.MatchString(value.ActorID) {
		return SessionBinding{}, reject(ErrorAuthentication)
	}
	authenticatedAt, ok := normalizedTime(value.AuthenticatedAt)
	if !ok {
		return SessionBinding{}, reject(ErrorAuthentication)
	}
	expiresAt, ok := normalizedTime(value.ExpiresAt)
	if !ok || !expiresAt.After(authenticatedAt) {
		return SessionBinding{}, reject(ErrorAuthentication)
	}
	now, ok = normalizedTime(now)
	if !ok || now.Before(authenticatedAt) || !now.Before(expiresAt) {
		return SessionBinding{}, reject(ErrorAuthentication)
	}
	if now.After(authenticatedAt.Add(ReauthAfter)) {
		return SessionBinding{}, reject(ErrorStepUpRequired)
	}
	value.AuthenticatedAt = authenticatedAt
	value.ExpiresAt = expiresAt
	return value, nil
}

func sameSession(left, right SessionBinding) bool {
	return left.SessionID == right.SessionID &&
		constantStringEqual(left.SessionDigest, right.SessionDigest) &&
		left.ActorID == right.ActorID &&
		left.AuthenticatedAt.Equal(right.AuthenticatedAt) &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

func validOperation(value Operation) bool {
	return validPolicyOperation(value) || value == OperationRevoke
}

func validPolicyOperation(value Operation) bool {
	return value == OperationApprove || value == OperationReject
}

func validDecision(operation Operation, value DecisionValue) bool {
	return operation == OperationApprove && value == DecisionApproved ||
		operation == OperationReject && value == DecisionRejected ||
		operation == OperationRevoke && value == DecisionRevoked
}

func validChallengeBranch(operation Operation, resourceType string, originalAddDigest *string) bool {
	switch operation {
	case OperationApprove, OperationReject:
		return resourceType == ResourcePolicy && originalAddDigest == nil
	case OperationRevoke:
		return resourceType == ResourceEnforcementAction && originalAddDigest != nil
	default:
		return false
	}
}

func validDecisionBranch(operation Operation, decision DecisionValue, resourceType string, originalAddDigest *string) bool {
	return validDecision(operation, decision) &&
		validChallengeBranch(operation, resourceType, originalAddDigest)
}

func cloneOptionalString(value *string) *string {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func validUUID(value string) bool { return uuidPattern.MatchString(value) }

func validCanonicalIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func normalizedTime(value time.Time) (time.Time, bool) {
	if value.IsZero() || value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, false
	}
	return value.Round(0).UTC(), true
}

func minTime(first time.Time, rest ...time.Time) time.Time {
	result := first
	for _, candidate := range rest {
		if candidate.Before(result) {
			result = candidate
		}
	}
	return result
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func constantStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func readEntropy(reader io.Reader, destination []byte) error {
	if reader == nil {
		return reject(ErrorConfiguration)
	}
	if _, err := io.ReadFull(reader, destination); err != nil {
		clear(destination)
		return reject(ErrorEntropy)
	}
	return nil
}

func formatUUID(raw [16]byte) string {
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], raw[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], raw[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], raw[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], raw[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], raw[10:16])
	return string(encoded)
}

func makeUUID(reader io.Reader) (string, error) {
	var raw [16]byte
	if err := readEntropy(reader, raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return formatUUID(raw), nil
}
