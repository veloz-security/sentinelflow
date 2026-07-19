// Package capability implements the signed, exact-artifact boundary between
// SentinelFlow's restricted dispatcher and isolated nftables executor.
package capability

// ErrorCode is a stable, content-free rejection classification. Errors from
// this package never include identifiers, artifacts, signatures, or command
// output and are safe to expose to structured audit code.
type ErrorCode string

const (
	ErrorEncoding       ErrorCode = "encoding_invalid"
	ErrorCanonical      ErrorCode = "canonical_encoding_required"
	ErrorSchema         ErrorCode = "schema_invalid"
	ErrorIdentity       ErrorCode = "identity_invalid"
	ErrorOperation      ErrorCode = "operation_invalid"
	ErrorDigest         ErrorCode = "digest_invalid"
	ErrorArtifact       ErrorCode = "artifact_invalid"
	ErrorAuthorization  ErrorCode = "authorization_invalid"
	ErrorTime           ErrorCode = "time_invalid"
	ErrorNotYetValid    ErrorCode = "not_yet_valid"
	ErrorExpired        ErrorCode = "expired"
	ErrorKey            ErrorCode = "key_invalid"
	ErrorKeyRole        ErrorCode = "key_role_invalid"
	ErrorSignature      ErrorCode = "signature_invalid"
	ErrorResult         ErrorCode = "result_invalid"
	ErrorResultBinding  ErrorCode = "result_binding_invalid"
	ErrorReplayConflict ErrorCode = "replay_conflict"
	ErrorNotExecutable  ErrorCode = "not_executable"
	ErrorUnchecked      ErrorCode = "unchecked_value"
)

// Error reports only a stable code so malformed untrusted input cannot be
// reflected into logs.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "execution contract rejected"
	}
	return "execution contract rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }
