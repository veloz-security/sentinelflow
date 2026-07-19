package correlation

import (
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

type IncidentState string

const (
	IncidentOpen           IncidentState = "open"
	IncidentAnalyzing      IncidentState = "analyzing"
	IncidentReviewReady    IncidentState = "review_ready"
	IncidentAnalysisFailed IncidentState = "analysis_failed"
	IncidentClosed         IncidentState = "closed"
)

type AnalysisFailureReason string

const (
	FailureBudgetExhausted    AnalysisFailureReason = "budget_exhausted"
	FailureInputTooLarge      AnalysisFailureReason = "input_too_large"
	FailureNetworkError       AnalysisFailureReason = "network_error"
	FailureHTTP408            AnalysisFailureReason = "http_408"
	FailureHTTP409            AnalysisFailureReason = "http_409"
	FailureRateLimited        AnalysisFailureReason = "rate_limited"
	FailureServerError        AnalysisFailureReason = "server_error"
	FailureTimeout            AnalysisFailureReason = "timeout"
	FailureRefused            AnalysisFailureReason = "refused"
	FailureIncomplete         AnalysisFailureReason = "incomplete"
	FailureSchemaInvalid      AnalysisFailureReason = "schema_invalid"
	FailureEvidenceInvalid    AnalysisFailureReason = "evidence_invalid"
	FailureUnsupportedAction  AnalysisFailureReason = "unsupported_action"
	FailureCancelled          AnalysisFailureReason = "cancelled"
	FailureConfigurationError AnalysisFailureReason = "configuration_error"
)

type RetryClassification string

const (
	RetryOnceWithBoundedJitter RetryClassification = "retry_once_with_bounded_jitter"
	RetryTerminal              RetryClassification = "terminal"
)

// ClassifyAnalysisFailure mirrors the frozen TDD retry allowlist. timeout is
// terminal: only transport network errors and HTTP 408/409/429/5xx classes may
// consume the one additional attempt.
func ClassifyAnalysisFailure(reason AnalysisFailureReason) (RetryClassification, error) {
	switch reason {
	case FailureNetworkError, FailureHTTP408, FailureHTTP409, FailureRateLimited, FailureServerError:
		return RetryOnceWithBoundedJitter, nil
	case FailureBudgetExhausted, FailureInputTooLarge, FailureTimeout, FailureRefused,
		FailureIncomplete, FailureSchemaInvalid, FailureEvidenceInvalid,
		FailureUnsupportedAction, FailureCancelled, FailureConfigurationError:
		return RetryTerminal, nil
	default:
		return "", correlationError(ErrorInvalidInput, "analysis_failure_reason")
	}
}

type Command struct {
	ID               string
	ExpectedRevision uint64
	At               time.Time
}

type TransitionDisposition string

const (
	TransitionApplied             TransitionDisposition = "applied"
	TransitionIdempotentDuplicate TransitionDisposition = "idempotent_duplicate"
)

type TransitionResult struct {
	Disposition     TransitionDisposition
	AppliedRevision uint64
	CurrentRevision uint64
}

type RouteDisposition string

const (
	RouteAppended        RouteDisposition = "appended"
	RouteReopened        RouteDisposition = "reopened"
	RouteNewIncident     RouteDisposition = "new_incident"
	RouteDuplicateSignal RouteDisposition = "duplicate_signal"
)

type RouteResult struct {
	Disposition RouteDisposition
	Current     Incident
	NewIncident *Incident
}

type commandRecord struct {
	id              string
	fingerprint     string
	appliedRevision uint64
}

// Incident is an immutable aggregate value. Every operation returns a new
// aggregate and leaves the receiver unchanged. Internal slices are cloned on
// writes and exposed only through defensive-copy accessors.
type Incident struct {
	id               string
	version          uint64
	revision         uint64
	state            IncidentState
	createdAt        time.Time
	updatedAt        time.Time
	lastSignalAt     time.Time
	closedAt         time.Time
	failureReason    AnalysisFailureReason
	analysisAttempts int
	snapshot         EvidenceSnapshot
	signals          []detection.Signal
	relations        []Relation
	commands         []commandRecord
}

func (i Incident) ID() string                           { return i.id }
func (i Incident) Version() uint64                      { return i.version }
func (i Incident) Revision() uint64                     { return i.revision }
func (i Incident) State() IncidentState                 { return i.state }
func (i Incident) CreatedAt() time.Time                 { return i.createdAt }
func (i Incident) UpdatedAt() time.Time                 { return i.updatedAt }
func (i Incident) LastSignalAt() time.Time              { return i.lastSignalAt }
func (i Incident) AnalysisAttempts() int                { return i.analysisAttempts }
func (i Incident) Snapshot() EvidenceSnapshot           { return i.snapshot }
func (i Incident) FailureReason() AnalysisFailureReason { return i.failureReason }

func (i Incident) ClosedAt() (time.Time, bool) {
	return i.closedAt, !i.closedAt.IsZero()
}

func (i Incident) Signals() []detection.Signal { return cloneSignals(i.signals) }
func (i Incident) Relations() []Relation       { return cloneRelations(i.relations) }

func (i Incident) IsAnalysisFailureNonEnforcing() bool {
	return i.state == IncidentAnalysisFailed
}

func (i Incident) CanRetryAnalysis() bool {
	if i.state != IncidentAnalysisFailed || i.analysisAttempts >= MaximumAnalysisAttempts {
		return false
	}
	classification, err := ClassifyAnalysisFailure(i.failureReason)
	return err == nil && classification == RetryOnceWithBoundedJitter
}

func cloneIncident(value Incident) Incident {
	value.signals = cloneSignals(value.signals)
	value.relations = cloneRelations(value.relations)
	value.commands = append([]commandRecord(nil), value.commands...)
	return value
}
