// Package adminstore persists administrator session records without ever
// accepting or retaining the corresponding plaintext session or CSRF tokens.
package adminstore

// ErrorCode is a stable, detail-free persistence failure classification.
// PostgreSQL messages and row contents are deliberately never attached.
type ErrorCode string

const (
	CodeNotFound    ErrorCode = "not_found"
	CodeConflict    ErrorCode = "conflict"
	CodeUnavailable ErrorCode = "unavailable"
)

// Error is a generic store error. It carries no SQL, PostgreSQL, session, actor,
// digest, or timestamp detail.
type Error struct {
	code ErrorCode
}

func (e *Error) Error() string {
	if e == nil {
		return "administrator session store unavailable"
	}
	switch e.code {
	case CodeNotFound:
		return "administrator session not found"
	case CodeConflict:
		return "administrator session conflict"
	default:
		return "administrator session store unavailable"
	}
}

// Code returns the stable generic classification.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return CodeUnavailable
	}
	return e.code
}

// Is permits errors.Is matching by safe classification without wrapping a
// database error that could be exposed by an outer adapter.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && other != nil && e.code == other.code
}

var (
	ErrNotFound    = &Error{code: CodeNotFound}
	ErrConflict    = &Error{code: CodeConflict}
	ErrUnavailable = &Error{code: CodeUnavailable}
)
