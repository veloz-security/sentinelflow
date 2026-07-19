package correlation

import (
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

const (
	CorrelationVersion      = "correlation-v1"
	EvidenceSnapshotVersion = "correlation-evidence-v1"
	MaximumSignalGap        = 5 * time.Minute
	IncidentIdleTimeout     = 15 * time.Minute
	IncidentReopenWindow    = 30 * time.Minute
	MaximumAnalysisAttempts = 2
)

type IdentityReason string

const IdentitySameCanonicalSource IdentityReason = "same_canonical_source"

type TemporalReason string

const (
	TemporalWindowOverlap               TemporalReason = "window_overlap"
	TemporalWithinFiveMinutes           TemporalReason = "gap_within_five_minutes"
	TemporalReopenedWithinThirtyMinutes TemporalReason = "reopened_within_thirty_minutes"
)

// SupportingReason is descriptive context only. None of these values can
// establish identity or merge signals without the canonical-source and
// temporal relation.
type SupportingReason string

const (
	SupportingSameService              SupportingReason = "same_service"
	SupportingDifferentService         SupportingReason = "different_service"
	SupportingSameRule                 SupportingReason = "same_rule"
	SupportingDifferentRule            SupportingReason = "different_rule"
	SupportingAccountIdentityMinimized SupportingReason = "account_identity_minimized"
	SupportingPathIdentityMinimized    SupportingReason = "path_identity_minimized"
)

type Relation struct {
	LeftSignalID      string
	RightSignalID     string
	IdentityReason    IdentityReason
	TemporalReason    TemporalReason
	SupportingReasons []SupportingReason
}

// SignalRef is the complete minimized signal projection retained in an
// immutable evidence snapshot. It contains counts and digests, never account
// hashes, path values, request content, or arbitrary text.
type SignalRef struct {
	SignalID                    string
	RuleID                      detection.RuleID
	Classification              detection.Classification
	ConfigurationVersion        string
	ConfigurationDigest         string
	WindowStart                 time.Time
	WindowEnd                   time.Time
	EventCount                  int
	DistinctAccountCount        int
	DistinctSuspiciousPathCount int
	EvidenceDigest              string
	SignalDigest                string
}

// EvidenceSnapshot keeps slices and canonical bytes private. Every accessor
// returns a defensive copy, so callers cannot mutate a snapshot after its
// digest has been calculated.
type EvidenceSnapshot struct {
	schemaVersion      string
	sourceIP           string
	windowStart        time.Time
	windowEnd          time.Time
	sourceHealthStatus detection.SourceHealthStatus
	serviceLabels      []string
	signalIDs          []string
	evidenceEventIDs   []string
	signalRefs         []SignalRef
	canonicalBytes     []byte
	digest             string
}

func (s EvidenceSnapshot) SchemaVersion() string  { return s.schemaVersion }
func (s EvidenceSnapshot) SourceIP() string       { return s.sourceIP }
func (s EvidenceSnapshot) WindowStart() time.Time { return s.windowStart }
func (s EvidenceSnapshot) WindowEnd() time.Time   { return s.windowEnd }
func (s EvidenceSnapshot) SourceHealthStatus() detection.SourceHealthStatus {
	return s.sourceHealthStatus
}
func (s EvidenceSnapshot) Digest() string { return s.digest }

func (s EvidenceSnapshot) ServiceLabels() []string {
	return append([]string(nil), s.serviceLabels...)
}

func (s EvidenceSnapshot) SignalIDs() []string {
	return append([]string(nil), s.signalIDs...)
}

func (s EvidenceSnapshot) EvidenceEventIDs() []string {
	return append([]string(nil), s.evidenceEventIDs...)
}

func (s EvidenceSnapshot) SignalRefs() []SignalRef {
	return append([]SignalRef(nil), s.signalRefs...)
}

func (s EvidenceSnapshot) CanonicalBytes() []byte {
	return append([]byte(nil), s.canonicalBytes...)
}

// Group is one deterministic same-source temporal component.
type Group struct {
	SourceIP    string
	WindowStart time.Time
	WindowEnd   time.Time
	Snapshot    EvidenceSnapshot
	signals     []detection.Signal
	relations   []Relation
}

func (g Group) Signals() []detection.Signal {
	return cloneSignals(g.signals)
}

func (g Group) Relations() []Relation {
	return cloneRelations(g.relations)
}

type ErrorCode string

const (
	ErrorInvalidInput           ErrorCode = "invalid_input"
	ErrorConflictingSignal      ErrorCode = "conflicting_signal"
	ErrorStaleRevision          ErrorCode = "stale_revision"
	ErrorIdempotencyConflict    ErrorCode = "idempotency_conflict"
	ErrorInvalidTransition      ErrorCode = "invalid_transition"
	ErrorRetryNotAllowed        ErrorCode = "retry_not_allowed"
	ErrorIdleDeadlineNotReached ErrorCode = "idle_deadline_not_reached"
	ErrorTimeRegression         ErrorCode = "time_regression"
)

type Error struct {
	Code  ErrorCode
	Field string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return "correlation: " + string(e.Code)
	}
	return "correlation: " + string(e.Code) + ": " + e.Field
}

func correlationError(code ErrorCode, field string) error {
	return &Error{Code: code, Field: field}
}
