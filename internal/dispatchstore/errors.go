package dispatchstore

// ErrorCode is a stable, detail-free dispatcher persistence classification.
// Database messages, identifiers, IP addresses, artifacts, signatures, and
// lease material are deliberately never attached to Error.
type ErrorCode string

const (
	CodeInvalidInput        ErrorCode = "invalid_input"
	CodeInvalidRow          ErrorCode = "invalid_row"
	CodeContractRejected    ErrorCode = "contract_rejected"
	CodePersistenceRejected ErrorCode = "persistence_rejected"
	CodeConflict            ErrorCode = "conflict"
	CodeLeaseLost           ErrorCode = "lease_lost"
	CodeUnavailable         ErrorCode = "unavailable"
)

// Error contains no wrapped driver error because PostgreSQL details can expose
// exact artifacts or durable identifiers at an operational boundary.
type Error struct{ code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "dispatcher store unavailable"
	}
	switch e.code {
	case CodeInvalidInput:
		return "dispatcher request is invalid"
	case CodeInvalidRow:
		return "dispatcher projection is invalid"
	case CodeContractRejected:
		return "dispatcher execution contract was rejected"
	case CodePersistenceRejected:
		return "dispatcher persistence contract was rejected"
	case CodeConflict:
		return "dispatcher persistence conflicts with durable state"
	case CodeLeaseLost:
		return "dispatcher lease is no longer held"
	default:
		return "dispatcher store unavailable"
	}
}

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
	ErrInvalidInput        = &Error{code: CodeInvalidInput}
	ErrInvalidRow          = &Error{code: CodeInvalidRow}
	ErrContractRejected    = &Error{code: CodeContractRejected}
	ErrPersistenceRejected = &Error{code: CodePersistenceRejected}
	ErrConflict            = &Error{code: CodeConflict}
	ErrLeaseLost           = &Error{code: CodeLeaseLost}
	ErrUnavailable         = &Error{code: CodeUnavailable}
)
