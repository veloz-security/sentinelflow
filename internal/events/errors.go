package events

import "fmt"

// ErrorCode is a stable machine-readable validation failure category.
type ErrorCode string

const (
	ErrorInvalidJSON      ErrorCode = "invalid_json"
	ErrorExpectedObject   ErrorCode = "expected_object"
	ErrorTrailingJSON     ErrorCode = "trailing_json"
	ErrorDuplicateField   ErrorCode = "duplicate_field"
	ErrorUnknownField     ErrorCode = "unknown_field"
	ErrorPrivacyForbidden ErrorCode = "privacy_forbidden"
	ErrorRequired         ErrorCode = "required"
	ErrorInvalidType      ErrorCode = "invalid_type"
	ErrorInvalidConstant  ErrorCode = "invalid_constant"
	ErrorInvalidFormat    ErrorCode = "invalid_format"
	ErrorInvalidEnum      ErrorCode = "invalid_enum"
	ErrorOutOfRange       ErrorCode = "out_of_range"
	ErrorCardinality      ErrorCode = "invalid_cardinality"
	ErrorInvariant        ErrorCode = "invariant_violation"
	ErrorTooLarge         ErrorCode = "too_large"
)

// FieldError identifies a failed field and a stable error code. Problem is a
// fixed diagnostic and never contains the rejected value, raw JSON, an unknown
// property name, or secret-bearing request data.
type FieldError struct {
	Field   string
	Code    ErrorCode
	Problem string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("event field %s: %s (%s)", e.Field, e.Problem, e.Code)
}

func fieldError(field string, code ErrorCode, problem string) error {
	return &FieldError{Field: field, Code: code, Problem: problem}
}

func prefixError(prefix string, err error) error {
	fieldErr, ok := err.(*FieldError)
	if !ok {
		return fieldError(prefix, ErrorInvalidJSON, "value is invalid")
	}

	field := prefix
	if fieldErr.Field != "" && fieldErr.Field != "$" {
		field += "." + fieldErr.Field
	}
	return &FieldError{Field: field, Code: fieldErr.Code, Problem: fieldErr.Problem}
}
