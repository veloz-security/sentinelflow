package capability

import "time"

const (
	CapabilitySchemaVersion = "execution-capability-v1"
	ResultSchemaVersion     = "execution-result-v1"
	ResultV2SchemaVersion   = "execution-result-v2"
	InspectSchemaVersion    = "nft-inspect-v1"

	CapabilitySigningDomain = "sentinelflow execution-capability-v1"
	ResultSigningDomain     = "sentinelflow execution-result-v1"
	ResultV2SigningDomain   = "sentinelflow execution-result-v2"

	MaxCapabilityBytes = 8 * 1024
	MaxArtifactBytes   = 4 * 1024
	MaxResultBytes     = 8 * 1024
	MaxValidity        = 60 * time.Second

	canonicalTimeLayout = "2006-01-02T15:04:05.000Z"
)

// Operation is intentionally closed. There is no generic mutation operation.
type Operation string

const (
	OperationAdd     Operation = "add"
	OperationRevoke  Operation = "revoke"
	OperationInspect Operation = "inspect"
)

// Common contains fields shared by each operation-specific capability input.
// These values are untrusted until a constructor returns CheckedCapability.
type Common struct {
	CapabilityID             string
	JobID                    string
	ActionID                 string
	PolicyID                 string
	PolicyVersion            uint32
	TargetIPv4               string
	EvidenceSnapshotDigest   string
	ValidationSnapshotDigest string
	AuthorizationDigest      string
	ActorID                  string
	ReasonDigest             string
	OwnedSchemaDigest        string
	IssuedAt                 time.Time
	NotBefore                time.Time
	ExpiresAt                time.Time
	Nonce                    string
}

// Add binds the exact canonical add bytes. The TTL is parsed from those bytes
// and frozen into ExecutableAdd; callers cannot provide a second TTL value.
// AuthorizationDigest transitively binds the checked policy, generated and
// canonical artifact digests, validation snapshot, and exact HIL decision.
type Add struct {
	Common
	CanonicalCommand []byte
}

// Revoke binds a separately authorized exact delete artifact and the original
// add digest. It cannot be constructed from an add authorization alone.
type Revoke struct {
	Common
	OriginalAddDigest string
	CanonicalDelete   []byte
}

// Inspect binds a checked read-only inspection artifact. It deliberately has
// no command byte field.
type Inspect struct {
	Common
	OriginalAddDigest string
	Artifact          InspectArtifact
}

// InspectArtifact is data for the executor's fixed read-back implementation,
// not nftables input or a shell command.
type InspectArtifact struct {
	SchemaVersion     string
	ActionID          string
	TargetIPv4        string
	OriginalAddDigest string
	OwnedSchemaDigest string
	Purpose           string
}

// Value is an immutable copy of the signed capability payload.
type Value struct {
	SchemaVersion            string
	CapabilityID             string
	Operation                Operation
	JobID                    string
	ActionID                 string
	PolicyID                 string
	PolicyVersion            uint32
	TargetIPv4               string
	ArtifactDigest           string
	OriginalAddDigest        string
	EvidenceSnapshotDigest   string
	ValidationSnapshotDigest string
	AuthorizationDigest      string
	ActorID                  string
	ReasonDigest             string
	OwnedSchemaDigest        string
	IssuedAt                 time.Time
	NotBefore                time.Time
	ExpiresAt                time.Time
	Nonce                    string
}

// CheckedCapability may be signed by the dispatcher but cannot be executed.
// Only CapabilityVerifier can produce VerifiedCapability.
type CheckedCapability struct {
	value      Value
	canonical  []byte
	digest     string
	artifact   []byte
	addTTL     uint32
	inspection InspectArtifact
}

func (c CheckedCapability) Value() Value           { return c.value }
func (c CheckedCapability) CanonicalBytes() []byte { return clone(c.canonical) }
func (c CheckedCapability) Digest() string         { return c.digest }
func (c CheckedCapability) ArtifactBytes() []byte  { return clone(c.artifact) }

// SignedCapability is safe to transport but remains untrusted. KeyID is an
// explicit local key-selection identity; the frozen v1 UDS schema transports
// one configured key and therefore does not serialize it inside the payload.
type SignedCapability struct {
	keyID     string
	canonical []byte
	signature []byte
	artifact  []byte
}

func (s SignedCapability) KeyID() string          { return s.keyID }
func (s SignedCapability) CanonicalBytes() []byte { return clone(s.canonical) }
func (s SignedCapability) Signature() []byte      { return clone(s.signature) }
func (s SignedCapability) ArtifactBytes() []byte  { return clone(s.artifact) }

// VerifiedCapability has a valid dispatcher signature, canonical payload, and
// operation-specific exact artifact. It is still not executable until the
// unseen-capability freshness check is made after durable replay lookup.
type VerifiedCapability struct {
	value      Value
	canonical  []byte
	digest     string
	artifact   []byte
	keyID      string
	executorID string
	addTTL     uint32
	inspection InspectArtifact
}

func (v VerifiedCapability) Value() Value           { return v.value }
func (v VerifiedCapability) CanonicalBytes() []byte { return clone(v.canonical) }
func (v VerifiedCapability) Digest() string         { return v.digest }
func (v VerifiedCapability) KeyID() string          { return v.keyID }
func (v VerifiedCapability) ExecutorID() string     { return v.executorID }

// ExpectedAddTTLSeconds exposes only the already verified read-back bound. It
// does not release artifact bytes or create add authority.
func (v VerifiedCapability) ExpectedAddTTLSeconds() (uint32, bool) {
	if v.value.Operation != OperationAdd || v.addTTL == 0 {
		return 0, false
	}
	return v.addTTL, true
}

// ExecutableAdd is the only type that releases add command bytes.
type ExecutableAdd struct {
	verified VerifiedCapability
}

func (e ExecutableAdd) Capability() VerifiedCapability { return e.verified }
func (e ExecutableAdd) CanonicalCommand() []byte       { return clone(e.verified.artifact) }
func (e ExecutableAdd) TTLSeconds() uint32             { return e.verified.addTTL }

// ExecutableRevoke is the only type that releases delete command bytes.
type ExecutableRevoke struct {
	verified VerifiedCapability
}

func (e ExecutableRevoke) Capability() VerifiedCapability { return e.verified }
func (e ExecutableRevoke) CanonicalDelete() []byte        { return clone(e.verified.artifact) }

// ExecutableInspect exposes only a typed read-back request. It has no method
// returning mutation bytes.
type ExecutableInspect struct {
	verified VerifiedCapability
}

func (e ExecutableInspect) Capability() VerifiedCapability { return e.verified }
func (e ExecutableInspect) Request() InspectArtifact       { return e.verified.inspection }

type Classification string

const (
	ClassificationApplied         Classification = "applied"
	ClassificationRecoveredActive Classification = "recovered_active"
	ClassificationRevoked         Classification = "revoked"
	ClassificationInspectActive   Classification = "inspect_active"
	ClassificationInspectAbsent   Classification = "inspect_absent"
	ClassificationInspectMismatch Classification = "inspect_mismatch"
	ClassificationFailed          Classification = "failed"
	ClassificationIndeterminate   Classification = "indeterminate"
)

type NFTExitClass string

const (
	NFTExitSuccess    NFTExitClass = "success"
	NFTExitNotInvoked NFTExitClass = "not_invoked"
	NFTExitNonzero    NFTExitClass = "nonzero"
	NFTExitTimeout    NFTExitClass = "timeout"
	NFTExitSignaled   NFTExitClass = "signaled"
)

type ReadbackState string

const (
	ReadbackActive      ReadbackState = "active"
	ReadbackAbsent      ReadbackState = "absent"
	ReadbackMismatch    ReadbackState = "mismatch"
	ReadbackUnavailable ReadbackState = "unavailable"
)

type ResultErrorCode string

const (
	ResultErrorNone              ResultErrorCode = "none"
	ResultErrorCapabilityInvalid ResultErrorCode = "capability_invalid"
	ResultErrorArtifactMismatch  ResultErrorCode = "artifact_mismatch"
	ResultErrorSchemaMismatch    ResultErrorCode = "schema_mismatch"
	ResultErrorTargetExists      ResultErrorCode = "target_exists"
	ResultErrorTargetAbsent      ResultErrorCode = "target_absent"
	ResultErrorNFTFailed         ResultErrorCode = "nft_failed"
	ResultErrorReadbackFailed    ResultErrorCode = "readback_failed"
	ResultErrorReadbackMismatch  ResultErrorCode = "readback_mismatch"
	ResultErrorJournalFailed     ResultErrorCode = "journal_failed"
	ResultErrorDeadlineExceeded  ResultErrorCode = "deadline_exceeded"
	ResultErrorReplayConflict    ResultErrorCode = "replay_conflict"
	ResultErrorIndeterminate     ResultErrorCode = "indeterminate"
)

// Result is an untrusted executor attestation input. It contains enumerated
// error classifications only; stdout, stderr, command text, and secrets have
// no representable field.
type Result struct {
	// SchemaVersion is v1 when omitted for backwards-compatible historical
	// fixtures. New executor output MUST be execution-result-v2.
	SchemaVersion       string
	ResultID            string
	CapabilityID        string
	CapabilityDigest    string
	Operation           Operation
	ActionID            string
	ArtifactDigest      string
	TargetIPv4          string
	Classification      Classification
	NFTExitClass        *NFTExitClass
	ReadbackState       ReadbackState
	ElementHandle       *uint64
	RemainingTTLSeconds *uint64
	OwnedSchemaDigest   string
	StartedAt           time.Time
	// ReadbackStartedAt and ReadbackCompletedAt bracket the executor's fixed
	// nft list-set call. They are executor-signed observations, not
	// dispatcher-provided lifecycle timestamps.
	ReadbackStartedAt   *time.Time
	ReadbackCompletedAt *time.Time
	CompletedAt         time.Time
	JournalSequence     uint64
	ErrorCode           ResultErrorCode
}

// ResultValue is an immutable copy of a versioned executor result.
type ResultValue = Result

type CheckedResult struct {
	value     ResultValue
	canonical []byte
	digest    string
}

func (r CheckedResult) Value() ResultValue     { return cloneResultValue(r.value) }
func (r CheckedResult) CanonicalBytes() []byte { return clone(r.canonical) }
func (r CheckedResult) Digest() string         { return r.digest }

type SignedResult struct {
	keyID      string
	executorID string
	canonical  []byte
	signature  []byte
}

func (s SignedResult) KeyID() string          { return s.keyID }
func (s SignedResult) ExecutorID() string     { return s.executorID }
func (s SignedResult) CanonicalBytes() []byte { return clone(s.canonical) }
func (s SignedResult) Signature() []byte      { return clone(s.signature) }

type VerifiedResult struct {
	value      ResultValue
	canonical  []byte
	digest     string
	keyID      string
	executorID string
}

func (r VerifiedResult) Value() ResultValue     { return cloneResultValue(r.value) }
func (r VerifiedResult) CanonicalBytes() []byte { return clone(r.canonical) }
func (r VerifiedResult) Digest() string         { return r.digest }
func (r VerifiedResult) KeyID() string          { return r.keyID }
func (r VerifiedResult) ExecutorID() string     { return r.executorID }

// BoundResult can only be produced after the dispatcher verifies both the
// executor signature and the exact capability/artifact linkage.
type BoundResult struct {
	result     VerifiedResult
	capability VerifiedCapability
}

func (b BoundResult) Result() VerifiedResult         { return b.result }
func (b BoundResult) Capability() VerifiedCapability { return b.capability }

func clone(value []byte) []byte { return append([]byte(nil), value...) }

func cloneResultValue(value ResultValue) ResultValue {
	result := value
	if value.NFTExitClass != nil {
		copyValue := *value.NFTExitClass
		result.NFTExitClass = &copyValue
	}
	if value.ElementHandle != nil {
		copyValue := *value.ElementHandle
		result.ElementHandle = &copyValue
	}
	if value.RemainingTTLSeconds != nil {
		copyValue := *value.RemainingTTLSeconds
		result.RemainingTTLSeconds = &copyValue
	}
	if value.ReadbackStartedAt != nil {
		copyValue := *value.ReadbackStartedAt
		result.ReadbackStartedAt = &copyValue
	}
	if value.ReadbackCompletedAt != nil {
		copyValue := *value.ReadbackCompletedAt
		result.ReadbackCompletedAt = &copyValue
	}
	return result
}
