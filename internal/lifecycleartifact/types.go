package lifecycleartifact

import (
	"errors"
	"time"
)

const (
	InspectSchemaVersion       = "nft-inspect-v1"
	InspectionOperation        = "inspect"
	AuthorizationSchemaVersion = "inspection-authorization-v1"
	RevokeSchemaVersion        = "nft-revoke-v1"

	MaxInspectArtifactBytes  = 4 * 1024
	MaxAuthorizationBytes    = 8 * 1024
	MaxRevokeArtifactBytes   = 257
	MaxAuthorizationValidity = 5 * time.Minute
)

// Purpose is intentionally closed so read-only authority cannot be repurposed
// into a generic executor operation.
type Purpose string

const (
	PurposeReconciliation     Purpose = "reconciliation"
	PurposeExpiryConfirmation Purpose = "expiry_confirmation"
	PurposeOperatorStatus     Purpose = "operator_status"
)

// ErrorCode is a stable, content-free rejection classification. Error values
// never reflect untrusted artifacts, identifiers, or command bytes.
type ErrorCode string

const (
	ErrorEncoding  ErrorCode = "encoding_invalid"
	ErrorCanonical ErrorCode = "canonical_encoding_required"
	ErrorSchema    ErrorCode = "schema_invalid"
	ErrorIdentity  ErrorCode = "identity_invalid"
	ErrorDigest    ErrorCode = "digest_invalid"
	ErrorArtifact  ErrorCode = "artifact_invalid"
	ErrorBinding   ErrorCode = "artifact_binding_invalid"
	ErrorTime      ErrorCode = "time_invalid"
	ErrorUnchecked ErrorCode = "unchecked_artifact"
)

// Error reports only its stable code.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "lifecycle artifact rejected"
	}
	return "lifecycle artifact rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }

// IsCode reports whether err is a lifecycle artifact rejection with code.
func IsCode(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.Code == code
}

// InspectInput contains untrusted inputs for a fixed read-only inspection.
type InspectInput struct {
	ActionID          string
	TargetIPv4        string
	OriginalAddDigest string
	OwnedSchemaDigest string
	Purpose           Purpose
}

// InspectValue is an immutable copy of nft-inspect-v1.
type InspectValue struct {
	SchemaVersion     string
	Operation         string
	ActionID          string
	TargetIPv4        string
	OriginalAddDigest string
	OwnedSchemaDigest string
	Purpose           Purpose
}

// CheckedInspectArtifact is a byte-exact, read-only nft-inspect-v1 artifact.
// Its zero value is intentionally invalid.
type CheckedInspectArtifact struct {
	value     InspectValue
	canonical string
	digest    string
}

func (CheckedInspectArtifact) String() string {
	return "lifecycleartifact.CheckedInspectArtifact{artifact:[REDACTED]}"
}

func (a CheckedInspectArtifact) GoString() string { return a.String() }

func (a CheckedInspectArtifact) Value() InspectValue { return a.value }

// CanonicalBytes returns a new allocation on every call.
func (a CheckedInspectArtifact) CanonicalBytes() []byte { return []byte(a.canonical) }

func (a CheckedInspectArtifact) Digest() string { return a.digest }

// InspectionAuthorizationInput contains only fields not derived from the
// checked inspect artifact. Action, target, original add digest, live schema
// digest, purpose, and artifact digest are always taken from Inspect.
type InspectionAuthorizationInput struct {
	AuthorizationID             string
	PolicyID                    string
	PolicyVersion               uint32
	OriginalAuthorizationDigest string
	EvidenceSnapshotDigest      string
	ValidationSnapshotDigest    string
	SchedulerID                 string
	RequestedAt                 time.Time
	ValidUntil                  time.Time
	IdempotencyKeyDigest        string
	Inspect                     CheckedInspectArtifact
}

// InspectionAuthorizationValue is an immutable copy of every field in the
// inspection-authorization-v1 schema.
type InspectionAuthorizationValue struct {
	SchemaVersion               string
	AuthorizationID             string
	Purpose                     Purpose
	ActionID                    string
	PolicyID                    string
	PolicyVersion               uint32
	TargetIPv4                  string
	OriginalAddDigest           string
	OriginalAuthorizationDigest string
	EvidenceSnapshotDigest      string
	ValidationSnapshotDigest    string
	ArtifactDigest              string
	OwnedSchemaDigest           string
	SchedulerID                 string
	RequestedAt                 time.Time
	ValidUntil                  time.Time
	IdempotencyKeyDigest        string
}

// CheckedInspectionAuthorization is an exact JCS authorization bound to one
// checked read-only inspect artifact. Its zero value is invalid.
type CheckedInspectionAuthorization struct {
	value     InspectionAuthorizationValue
	canonical string
	digest    string
	inspect   CheckedInspectArtifact
}

func (CheckedInspectionAuthorization) String() string {
	return "lifecycleartifact.CheckedInspectionAuthorization{artifact:[REDACTED]}"
}

func (a CheckedInspectionAuthorization) GoString() string { return a.String() }

func (a CheckedInspectionAuthorization) Value() InspectionAuthorizationValue { return a.value }

// CanonicalBytes returns a new allocation on every call.
func (a CheckedInspectionAuthorization) CanonicalBytes() []byte { return []byte(a.canonical) }

func (a CheckedInspectionAuthorization) Digest() string { return a.digest }

// InspectArtifact returns an immutable checked value. Its byte accessor still
// returns a fresh allocation.
func (a CheckedInspectionAuthorization) InspectArtifact() CheckedInspectArtifact { return a.inspect }

// RevokeValue is the typed meaning of the only supported nft-revoke-v1 bytes.
type RevokeValue struct {
	SchemaVersion string
	TargetIPv4    string
}

// CheckedRevokeArtifact contains one deterministic nftables delete statement.
// It cannot represent a table, chain, set, or multi-statement mutation.
type CheckedRevokeArtifact struct {
	value     RevokeValue
	canonical string
	digest    string
}

func (CheckedRevokeArtifact) String() string {
	return "lifecycleartifact.CheckedRevokeArtifact{artifact:[REDACTED]}"
}

func (a CheckedRevokeArtifact) GoString() string { return a.String() }

func (a CheckedRevokeArtifact) Value() RevokeValue { return a.value }

// CanonicalBytes returns a new allocation on every call.
func (a CheckedRevokeArtifact) CanonicalBytes() []byte { return []byte(a.canonical) }

func (a CheckedRevokeArtifact) Digest() string { return a.digest }
