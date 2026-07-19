package lifecyclestore

import "errors"

type ErrorCode string

const (
	CodeInvalidInput      ErrorCode = "invalid_input"
	CodeUnavailable       ErrorCode = "store_unavailable"
	CodeConflict          ErrorCode = "conflict"
	CodeLeaseLost         ErrorCode = "lease_lost"
	CodeProjectionInvalid ErrorCode = "projection_invalid"
	CodeContractRejected  ErrorCode = "contract_rejected"
)

// Error deliberately contains no database message, target, identifier, or
// artifact bytes. Callers may log only this stable classification.
type Error struct{ code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "lifecycle store error"
	}
	return "lifecycle store: " + string(e.code)
}

func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

var (
	ErrInvalidInput      = &Error{code: CodeInvalidInput}
	ErrUnavailable       = &Error{code: CodeUnavailable}
	ErrConflict          = &Error{code: CodeConflict}
	ErrLeaseLost         = &Error{code: CodeLeaseLost}
	ErrProjectionInvalid = &Error{code: CodeProjectionInvalid}
	ErrContractRejected  = &Error{code: CodeContractRejected}
)

func IsCode(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.code == code
}
