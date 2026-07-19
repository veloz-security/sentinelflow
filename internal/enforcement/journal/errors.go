package journal

// ErrorCode is a stable, content-free failure classification. Journal errors
// never reflect paths, command bytes, signatures, or malformed payloads.
type ErrorCode string

const (
	ErrorPath              ErrorCode = "path_invalid"
	ErrorUnsafeDirectory   ErrorCode = "directory_unsafe"
	ErrorUnsafeFile        ErrorCode = "file_unsafe"
	ErrorLocked            ErrorCode = "journal_locked"
	ErrorTooLarge          ErrorCode = "journal_too_large"
	ErrorCorrupt           ErrorCode = "journal_corrupt"
	ErrorVersion           ErrorCode = "journal_version_unsupported"
	ErrorSequence          ErrorCode = "journal_sequence_invalid"
	ErrorVerification      ErrorCode = "contract_verification_failed"
	ErrorTime              ErrorCode = "time_invalid"
	ErrorConflict          ErrorCode = "replay_conflict"
	ErrorMissingStart      ErrorCode = "started_record_missing"
	ErrorDuplicateTerminal ErrorCode = "terminal_record_conflict"
	ErrorOperation         ErrorCode = "operation_invalid"
	ErrorFreshness         ErrorCode = "capability_not_fresh"
	ErrorPermitUsed        ErrorCode = "execution_permit_used"
	ErrorSync              ErrorCode = "durability_sync_failed"
	ErrorIO                ErrorCode = "journal_io_failed"
	ErrorUnhealthy         ErrorCode = "journal_not_ready"
)

// Error is safe for structured logs because it contains only a stable code.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "executor journal rejected"
	}
	return "executor journal rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }
