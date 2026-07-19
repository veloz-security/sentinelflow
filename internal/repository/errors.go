// Package repository implements SentinelFlow persistence boundaries.
package repository

import "fmt"

// PreconditionCode identifies a cross-layer contract that must be satisfied
// before a batch can be represented without weakening its authenticated
// provenance or sequence semantics.
type PreconditionCode string

const (
	PreconditionExactRawBodySize PreconditionCode = "exact_raw_body_size_required"
)

// PreconditionError deliberately carries no batch, nonce, sender, signature,
// or event data. Callers may safely classify it without logging secrets.
type PreconditionError struct {
	Code PreconditionCode
}

func (e *PreconditionError) Error() string {
	return fmt.Sprintf("repository precondition failed: %s", e.Code)
}

func (e *PreconditionError) Is(target error) bool {
	other, ok := target.(*PreconditionError)
	return ok && e.Code == other.Code
}

var ErrExactRawBodySizeRequired = &PreconditionError{Code: PreconditionExactRawBodySize}
