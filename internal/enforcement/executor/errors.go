package executor

// ErrorCode is a stable, content-free service failure classification. Error
// values never contain capability bytes, signatures, command bytes, process
// output, paths, identifiers, or runner errors.
type ErrorCode string

const (
	ErrorConfiguration    ErrorCode = "configuration_invalid"
	ErrorRequest          ErrorCode = "request_invalid"
	ErrorCapability       ErrorCode = "capability_invalid"
	ErrorArtifact         ErrorCode = "artifact_mismatch"
	ErrorSchema           ErrorCode = "owned_schema_mismatch"
	ErrorReplay           ErrorCode = "replay_conflict"
	ErrorFreshness        ErrorCode = "capability_not_fresh"
	ErrorTargetState      ErrorCode = "target_state_invalid"
	ErrorJournal          ErrorCode = "journal_failed"
	ErrorRunner           ErrorCode = "nft_runner_failed"
	ErrorDeadline         ErrorCode = "deadline_exceeded"
	ErrorResult           ErrorCode = "result_invalid"
	ErrorResultSigning    ErrorCode = "result_signing_failed"
	ErrorResultDurability ErrorCode = "result_durability_failed"
)

// Error intentionally exposes no wrapped cause. Callers may audit Code but
// must not reflect details from lower trust boundaries.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "executor service rejected"
	}
	return "executor service rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }
