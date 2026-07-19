// Package dispatchruntime implements the non-privileged bridge from the
// restricted dispatcher outbox to the isolated executor UDS.
package dispatchruntime

import (
	"context"
	"errors"
)

// ErrorCode is a stable, redacted dispatcher-runtime failure class.
type ErrorCode string

const (
	CodeInvalidConfiguration ErrorCode = "invalid_configuration"
	CodeKeyRejected          ErrorCode = "key_rejected"
	CodeEntropyUnavailable   ErrorCode = "entropy_unavailable"
	CodeContractRejected     ErrorCode = "contract_rejected"
	CodeSocketBoundary       ErrorCode = "socket_boundary_rejected"
	CodeTransport            ErrorCode = "transport_failed"
	CodeResponseRejected     ErrorCode = "response_rejected"
	CodeUnavailable          ErrorCode = "unavailable"
	CodeLeaseLost            ErrorCode = "lease_lost"
	CodeRecoverRequired      ErrorCode = "recover_required"
	CodeCancelled            ErrorCode = "cancelled"
)

// Error deliberately carries no key bytes, database details, socket path,
// target address, or exact artifact.
type Error struct{ code ErrorCode }

func (e *Error) Error() string { return "dispatcher runtime failed: " + string(e.Code()) }

func (e *Error) Code() ErrorCode {
	if e == nil {
		return CodeUnavailable
	}
	return e.code
}

func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && other != nil && e.code == other.code
}

var (
	ErrInvalidConfiguration = &Error{code: CodeInvalidConfiguration}
	ErrKeyRejected          = &Error{code: CodeKeyRejected}
	ErrEntropyUnavailable   = &Error{code: CodeEntropyUnavailable}
	ErrContractRejected     = &Error{code: CodeContractRejected}
	ErrSocketBoundary       = &Error{code: CodeSocketBoundary}
	ErrTransport            = &Error{code: CodeTransport}
	ErrResponseRejected     = &Error{code: CodeResponseRejected}
	ErrUnavailable          = &Error{code: CodeUnavailable}
	ErrLeaseLost            = &Error{code: CodeLeaseLost}
	ErrRecoverRequired      = &Error{code: CodeRecoverRequired}
	ErrCancelled            = &Error{code: CodeCancelled}
)

func contextError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrCancelled
	}
	return nil
}
