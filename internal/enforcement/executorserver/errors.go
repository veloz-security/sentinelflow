package executorserver

// ErrorCode is a stable, path-free listener failure classification.
type ErrorCode string

const (
	ErrorConfiguration ErrorCode = "configuration_invalid"
	ErrorSocketPath    ErrorCode = "socket_path_unsafe"
	ErrorSocketParent  ErrorCode = "socket_parent_unsafe"
	ErrorSocketExists  ErrorCode = "socket_already_exists"
	ErrorSocketCreate  ErrorCode = "socket_create_failed"
	ErrorSocketMode    ErrorCode = "socket_permissions_unsafe"
	ErrorServe         ErrorCode = "socket_serve_failed"
)

// Error omits filesystem paths and operating-system errors so deployment
// layout and permission details cannot be reflected into logs.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "executor socket boundary rejected"
	}
	return "executor socket boundary rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }
