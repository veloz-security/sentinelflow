// Package hilstore persists exact-artifact HIL challenges and reads durable
// decisions without accepting browser secrets or weakening database gates.
package hilstore

import "errors"

// ErrorCode is a stable, detail-free failure classification. PostgreSQL
// messages, identifiers, artifact bytes, reasons, and secret material are
// deliberately never attached to Error.
type ErrorCode string

const (
	CodeInvalidInput     ErrorCode = "invalid_input"
	CodeAuthentication   ErrorCode = "authentication_invalid"
	CodeStepUpRequired   ErrorCode = "step_up_required"
	CodeValidationFailed ErrorCode = "validation_failed"
	CodeValidationStale  ErrorCode = "validation_stale"
	CodeChallengeExpired ErrorCode = "challenge_expired"
	CodeNotFound         ErrorCode = "not_found"
	CodeConflict         ErrorCode = "conflict"
	CodeUnavailable      ErrorCode = "unavailable"
)

// Error contains no underlying error because driver and constraint text can
// expose schema or exact-artifact details at an HTTP boundary.
type Error struct{ code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "HIL store unavailable"
	}
	switch e.code {
	case CodeInvalidInput:
		return "HIL request is invalid"
	case CodeAuthentication:
		return "administrator session is invalid"
	case CodeStepUpRequired:
		return "administrator password step-up is required"
	case CodeValidationFailed:
		return "exact-artifact validation is invalid"
	case CodeValidationStale:
		return "exact-artifact validation is stale"
	case CodeChallengeExpired:
		return "HIL challenge is expired"
	case CodeNotFound:
		return "HIL record was not found"
	case CodeConflict:
		return "HIL request conflicts with durable state"
	default:
		return "HIL store unavailable"
	}
}

// Code returns the safe classification.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return CodeUnavailable
	}
	return e.code
}

// Is supports errors.Is without retaining or exposing a database error.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && other != nil && e.code == other.code
}

var (
	ErrInvalidInput     = &Error{code: CodeInvalidInput}
	ErrAuthentication   = &Error{code: CodeAuthentication}
	ErrStepUpRequired   = &Error{code: CodeStepUpRequired}
	ErrValidationFailed = &Error{code: CodeValidationFailed}
	ErrValidationStale  = &Error{code: CodeValidationStale}
	ErrChallengeExpired = &Error{code: CodeChallengeExpired}
	ErrNotFound         = &Error{code: CodeNotFound}
	ErrConflict         = &Error{code: CodeConflict}
	ErrUnavailable      = &Error{code: CodeUnavailable}
)

func isCode(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.Code() == code
}
