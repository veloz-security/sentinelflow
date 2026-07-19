package demohistory

// ErrorCode is a stable, content-free reason that a demo-history dataset was
// rejected. Errors deliberately omit rejected values and raw JSON.
type ErrorCode string

const (
	ErrorInputBounds ErrorCode = "demo_history_input_bounds"
	ErrorEncoding    ErrorCode = "demo_history_encoding"
	ErrorJSON        ErrorCode = "demo_history_json"
	ErrorShape       ErrorCode = "demo_history_shape"
	ErrorContract    ErrorCode = "demo_history_contract"
	ErrorCoverage    ErrorCode = "demo_history_coverage"
	ErrorOrdering    ErrorCode = "demo_history_ordering"
	ErrorDuplicate   ErrorCode = "demo_history_duplicate"
	ErrorBinding     ErrorCode = "demo_history_binding"
	ErrorDigest      ErrorCode = "demo_history_digest"
)

// Error is safe to log because it contains only a stable code.
type Error struct {
	Code ErrorCode
}

func (e *Error) Error() string {
	if e == nil || e.Code == "" {
		return "demo-history dataset rejected"
	}
	return "demo-history dataset rejected: " + string(e.Code)
}

func reject(code ErrorCode) error {
	return &Error{Code: code}
}
