// Package adminauth implements the pure administrator credential, session,
// browser-request, and in-memory rate-limit boundary. HTTP and database
// adapters intentionally live outside this package.
package adminauth

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrInvalidCredentials deliberately does not distinguish an unknown
	// administrator from an incorrect password.
	ErrInvalidCredentials   = errors.New("administrator credentials are invalid")
	ErrInvalidPasswordHash  = errors.New("administrator password hash is invalid")
	ErrInvalidConfiguration = errors.New("administrator authentication configuration is invalid")
	ErrSessionInvalid       = errors.New("administrator session is invalid")
	ErrStepUpRequired       = errors.New("administrator password step-up is required")
	ErrBrowserRequest       = errors.New("administrator browser request is invalid")
)

// RateLimitScope identifies a safe, non-secret limiter dimension.
type RateLimitScope string

const (
	RateLimitLoginSource RateLimitScope = "login_source"
	RateLimitLoginGlobal RateLimitScope = "login_global"
	RateLimitDecision    RateLimitScope = "decision_session"
	RateLimitCapacity    RateLimitScope = "limiter_capacity"
)

// RateLimitError carries the value required for an HTTP Retry-After response.
// It never includes a source address, session identifier, username, password,
// or token.
type RateLimitError struct {
	Scope      RateLimitScope
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("administrator request rate limited (%s); retry later", e.Scope)
}

// RetryAfterSeconds returns a positive, ceiling-rounded Retry-After value.
func (e *RateLimitError) RetryAfterSeconds() int {
	if e == nil {
		return 0
	}
	seconds := int((e.RetryAfter + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
