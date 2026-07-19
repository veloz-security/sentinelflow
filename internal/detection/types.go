package detection

import (
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
)

// RuleID is a stable, versioned deterministic detector identifier.
type RuleID string

const (
	RulePathScan           RuleID = "path_scan.v1"
	RuleRequestBurst       RuleID = "request_burst.v1"
	RuleLoginBruteForce    RuleID = "login_bruteforce.v1"
	RuleCredentialStuffing RuleID = "credential_stuffing.v1"
)

// Classification is the stable unversioned value emitted to downstream
// correlation and AI contracts. RuleID separately retains detector version.
type Classification string

const (
	ClassificationPathScan           Classification = "path_scan"
	ClassificationRequestBurst       Classification = "request_burst"
	ClassificationLoginBruteForce    Classification = "brute_force"
	ClassificationCredentialStuffing Classification = "credential_stuffing"
)

// TimestampTrust is assigned by the authenticated ingestion boundary. The
// detector cannot upgrade an untrusted event to trusted.
type TimestampTrust string

const (
	TimestampTrusted   TimestampTrust = "trusted"
	TimestampUntrusted TimestampTrust = "untrusted"
)

// BindingState records whether an application event or Gateway authentication
// response was exactly bound to the trusted Gateway identity tuple.
type BindingState string

const (
	BindingVerified      BindingState = "verified"
	BindingPending       BindingState = "pending"
	BindingUntrusted     BindingState = "untrusted"
	BindingNotApplicable BindingState = "not_applicable"
)

// SuspiciousPathID and AuthOutcome reuse the versioned minimized-event enums.
// Detection inputs still expose only the fields required by deterministic
// rules; they cannot carry paths, queries, bodies, headers, or free-form text.
type SuspiciousPathID = events.SuspiciousPathID

const (
	SuspiciousPathNone          = events.SuspiciousPathNone
	SuspiciousPathAdminConsole  = events.SuspiciousPathAdminConsole
	SuspiciousPathEnvFile       = events.SuspiciousPathEnvFile
	SuspiciousPathGitConfig     = events.SuspiciousPathGitConfig
	SuspiciousPathWPAdmin       = events.SuspiciousPathWPAdmin
	SuspiciousPathPHPMyAdmin    = events.SuspiciousPathPHPMyAdmin
	SuspiciousPathServerStatus  = events.SuspiciousPathServerStatus
	SuspiciousPathActuatorEnv   = events.SuspiciousPathActuatorEnv
	SuspiciousPathBackupArchive = events.SuspiciousPathBackupArchive
)

type AuthOutcome = events.AuthOutcome

const (
	AuthOutcomeFailed    = events.AuthOutcomeFailed
	AuthOutcomeSucceeded = events.AuthOutcomeSucceeded
)

// GatewayEvent is the detector's minimized projection of gateway-http-v1.
// OccurredAt is the trusted completed_at instant supplied by ingestion.
type GatewayEvent struct {
	EventID             string
	OccurredAt          time.Time
	SourceIP            string
	ServiceLabel        string
	RouteLabel          string
	PathCatalogVersion  string
	SuspiciousPathID    SuspiciousPathID
	StatusCode          int
	TimestampTrust      TimestampTrust
	AuthenticationMatch BindingState
}

// AuthEvent is the detector's minimized projection of auth-event-v1 plus the
// ingestion-owned trust and exact-binding decisions.
type AuthEvent struct {
	EventID        string
	OccurredAt     time.Time
	SourceIP       string
	ServiceLabel   string
	RouteLabel     string
	AccountHash    string
	Outcome        AuthOutcome
	TimestampTrust TimestampTrust
	GatewayBinding BindingState
}

// SourceKind identifies the independently checkpointed producer whose health
// must cover a rule window.
type SourceKind string

const (
	SourceGateway SourceKind = "gateway"
	SourceAuth    SourceKind = "auth"
)

// HealthIntervalState is intentionally closed. A recovered interval remains
// evidence that its covered historical window was incomplete.
type HealthIntervalState string

const (
	HealthDegraded    HealthIntervalState = "degraded"
	HealthLost        HealthIntervalState = "lost"
	HealthGapped      HealthIntervalState = "gapped"
	HealthUnknownLoss HealthIntervalState = "unknown_loss"
	HealthRecovered   HealthIntervalState = "recovered"
)

// HealthInterval describes a closed or still-open interval that cannot support
// an enforcement-eligible signal. A zero End means the interval remains open.
type HealthInterval struct {
	State        HealthIntervalState
	Start        time.Time
	End          time.Time
	DroppedCount uint64
}

// SourceHealth proves the bounded observation coverage supplied to one
// evaluation. Complete alone is insufficient: the coverage bounds must enclose
// the exact rule window and no unhealthy interval may overlap it.
type SourceHealth struct {
	Source        SourceKind
	Complete      bool
	CoverageStart time.Time
	CoverageEnd   time.Time
	Intervals     []HealthInterval
}

type SourceHealthStatus string

const (
	SourceHealthStatusComplete   SourceHealthStatus = "complete"
	SourceHealthStatusIncomplete SourceHealthStatus = "incomplete"
)

// EvaluationInput is immutable from the detector's perspective. Now is the
// application-owned clock instant; every rule uses an inclusive [Now-window,
// Now] event-time window.
type EvaluationInput struct {
	Now           time.Time
	GatewayEvents []GatewayEvent
	AuthEvents    []AuthEvent
	GatewayHealth SourceHealth
	AuthHealth    SourceHealth
}

type GroupKey struct {
	SourceIP     string
	ServiceLabel string
}

type Decision string

const (
	DecisionMatched    Decision = "matched"
	DecisionNoMatch    Decision = "no_match"
	DecisionIncomplete Decision = "incomplete"
)

type DecisionReason string

const (
	ReasonThresholdMet           DecisionReason = "threshold_met"
	ReasonBelowThreshold         DecisionReason = "below_threshold"
	ReasonSourceHealthIncomplete DecisionReason = "source_health_incomplete"
	ReasonTimestampUntrusted     DecisionReason = "timestamp_untrusted"
	ReasonBindingNotVerified     DecisionReason = "binding_not_verified"
)

// Metrics are sufficient to reproduce each frozen threshold without carrying
// request content, account hashes, or arbitrary metadata downstream.
type Metrics struct {
	EventCount                  int
	DistinctSuspiciousPathCount int
	DistinctAccountCount        int
}

// Signal is a deterministic, enforcement-supporting fact. EvidenceIDs are
// lexicographically sorted and unique. SignalID, EvidenceDigest, and Digest are
// stable for identical normalized inputs and application clock.
type Signal struct {
	SignalID             string
	RuleID               RuleID
	Classification       Classification
	ConfigurationVersion string
	ConfigurationDigest  string
	SourceIP             string
	ServiceLabel         string
	WindowStart          time.Time
	WindowEnd            time.Time
	Metrics              Metrics
	EvidenceIDs          []string
	EvidenceDigest       string
	Digest               string
	SourceHealthStatus   SourceHealthStatus
}

type RuleEvaluation struct {
	RuleID                RuleID
	Group                 GroupKey
	WindowStart           time.Time
	WindowEnd             time.Time
	Threshold             Metrics
	Observed              Metrics
	Decision              Decision
	Reason                DecisionReason
	SourceHealthStatus    SourceHealthStatus
	EnforcementSupporting bool
	Signal                *Signal
}

// Output uses slices, rather than maps, so serialized or compared output has a
// stable rule and group order.
type Output struct {
	ConfigurationVersion string
	ConfigurationDigest  string
	PathScan             []RuleEvaluation
	RequestBurst         []RuleEvaluation
	LoginBruteForce      []RuleEvaluation
	CredentialStuffing   []RuleEvaluation
}
