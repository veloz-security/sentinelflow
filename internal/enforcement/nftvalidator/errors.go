package nftvalidator

// ErrorCode is a stable, data-free classification for the private validator
// boundary. Error values never include candidate bytes, socket paths, process
// output, or operating-system diagnostics.
type ErrorCode string

const (
	ErrorInvalidConfiguration ErrorCode = "invalid_configuration"
	ErrorRequestInvalid       ErrorCode = "request_invalid"
	ErrorResponseInvalid      ErrorCode = "response_invalid"
	ErrorRequestReplayed      ErrorCode = "request_replayed"
	ErrorReplayCacheFull      ErrorCode = "replay_cache_full"
	ErrorNonceUnavailable     ErrorCode = "nonce_unavailable"
	ErrorSocketBoundary       ErrorCode = "socket_boundary_invalid"
	ErrorTransport            ErrorCode = "transport_failed"
	ErrorCancelled            ErrorCode = "request_cancelled"
	ErrorServerBoundary       ErrorCode = "server_boundary_invalid"
)

type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "nft validator request failed"
	}
	return "nft validator request failed: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }
