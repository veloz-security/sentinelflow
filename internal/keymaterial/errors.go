package keymaterial

// ErrorCode is a stable, path-free key-loading failure classification.
type ErrorCode string

const (
	CodePath       ErrorCode = "invalid_path"
	CodeFilesystem ErrorCode = "unsafe_file"
	CodeEncoding   ErrorCode = "invalid_encoding"
	CodeKeyRole    ErrorCode = "invalid_key_role"
)

// Error deliberately carries no path, operating-system detail, PEM bytes, or
// parser error that could disclose deployment layout or key material.
type Error struct{ code ErrorCode }

func (e *Error) Error() string { return "Ed25519 key material rejected" }

func (e *Error) Code() ErrorCode {
	if e == nil {
		return CodeFilesystem
	}
	return e.code
}

func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && other != nil && e.code == other.code
}

var (
	ErrPath       = &Error{code: CodePath}
	ErrFilesystem = &Error{code: CodeFilesystem}
	ErrEncoding   = &Error{code: CodeEncoding}
	ErrKeyRole    = &Error{code: CodeKeyRole}
)
