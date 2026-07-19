package demohistoryimport

// ErrorCode is a stable, content-free importer failure category.
type ErrorCode string

const (
	ErrorConfiguration ErrorCode = "demo_history_import_configuration"
	ErrorSource        ErrorCode = "demo_history_import_source"
	ErrorDataset       ErrorCode = "demo_history_import_dataset"
	ErrorManifest      ErrorCode = "demo_history_import_manifest"
	ErrorBinding       ErrorCode = "demo_history_import_binding"
	ErrorConflict      ErrorCode = "demo_history_import_conflict"
	ErrorStorage       ErrorCode = "demo_history_import_storage"
	ErrorCanceled      ErrorCode = "demo_history_import_canceled"
	ErrorFaultInjected ErrorCode = "demo_history_import_fault_injected"
)

// Error contains no raw dataset, signed envelope, database diagnostic, key,
// signature, or other attacker-controlled text.
type Error struct {
	Code ErrorCode
}

func (e *Error) Error() string {
	if e == nil || e.Code == "" {
		return "demo history import failed"
	}
	return "demo history import failed: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }
