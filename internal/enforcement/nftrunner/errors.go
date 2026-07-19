package nftrunner

// ErrorCode is a stable, content-free failure classification. Error values do
// not wrap process errors or contain command bytes, target addresses, nft JSON,
// paths, arguments, environment values, or process output.
type ErrorCode string

const (
	ErrorInvalidInput        ErrorCode = "invalid_input"
	ErrorUnsupportedPlatform ErrorCode = "unsupported_platform"
	ErrorProcessUnavailable  ErrorCode = "nft_process_unavailable"
	ErrorProcessNonzero      ErrorCode = "nft_process_nonzero"
	ErrorProcessSignaled     ErrorCode = "nft_process_signaled"
	ErrorOutputLimit         ErrorCode = "nft_output_limit_exceeded"
	ErrorCancelled           ErrorCode = "nft_operation_cancelled"
	ErrorTimeout             ErrorCode = "nft_operation_timeout"
	ErrorReadbackInvalid     ErrorCode = "nft_readback_invalid"
)

// Error intentionally exposes no wrapped cause. Callers may retain Code as
// bounded audit evidence but must not reflect lower-trust process details.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "nft runner rejected"
	}
	return "nft runner rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }
