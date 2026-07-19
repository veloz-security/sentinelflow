package investigationstore

import "time"

const (
	DefaultPageLimit = 25
	MaxPageLimit     = 100
	DetailItemLimit  = 100
)

type IncidentQuery struct {
	State        string
	Kind         string
	SourceIP     string
	ServiceLabel string
	From         *time.Time
	Until        *time.Time
	Cursor       IncidentCursor
	Limit        int
}

type IncidentSummary struct {
	IncidentID          string     `json:"incident_id"`
	Kind                string     `json:"kind"`
	State               string     `json:"state"`
	SourceIP            string     `json:"source_ip"`
	ServiceLabel        string     `json:"service_label"`
	FirstSeen           time.Time  `json:"first_seen"`
	LastSeen            time.Time  `json:"last_seen"`
	ClosedAt            *time.Time `json:"closed_at,omitempty"`
	DeterministicScore  string     `json:"deterministic_score"`
	Version             int32      `json:"version"`
	AnalysisFailureCode *string    `json:"analysis_failure_code,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type IncidentPage struct {
	Items      []IncidentSummary `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type SignalSummary struct {
	SignalID          string    `json:"signal_id"`
	RuleID            string    `json:"rule_id"`
	RuleVersion       int32     `json:"rule_version"`
	Kind              string    `json:"kind"`
	WindowStart       time.Time `json:"window_start"`
	WindowEnd         time.Time `json:"window_end"`
	ObservedCount     int32     `json:"observed_count"`
	DistinctCount     *int32    `json:"distinct_count,omitempty"`
	ThresholdCount    int32     `json:"threshold_count"`
	ThresholdDistinct *int32    `json:"threshold_distinct,omitempty"`
	SourceHealth      string    `json:"source_health_status"`
	EvidenceDigest    string    `json:"evidence_digest"`
}

type AnalysisSummary struct {
	AnalysisID      string     `json:"analysis_id"`
	IncidentVersion int32      `json:"incident_version"`
	ProviderKind    string     `json:"provider_kind"`
	AdapterID       string     `json:"adapter_id"`
	Model           *string    `json:"model"`
	ReasoningEffort *string    `json:"reasoning_effort"`
	RateCardVersion *string    `json:"rate_card_version"`
	ResultState     string     `json:"result_state"`
	FailureCode     *string    `json:"failure_code,omitempty"`
	OutputDigest    *string    `json:"output_digest,omitempty"`
	Summary         *string    `json:"summary,omitempty"`
	Classification  *string    `json:"classification,omitempty"`
	Confidence      *string    `json:"confidence,omitempty"`
	Uncertainty     *string    `json:"uncertainty,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	FalsePositives  []string   `json:"false_positive_factors"`
}

type PolicySummary struct {
	PolicyID               string    `json:"policy_id"`
	Version                int32     `json:"version"`
	IncidentVersion        int32     `json:"incident_version"`
	State                  string    `json:"state"`
	StateRevision          int64     `json:"state_revision"`
	TargetIPv4             string    `json:"target_ipv4"`
	TTLSeconds             int32     `json:"ttl_seconds"`
	PolicyDigest           string    `json:"policy_digest"`
	EvidenceSnapshotDigest string    `json:"evidence_snapshot_digest"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type IncidentDetail struct {
	Incident          IncidentSummary  `json:"incident"`
	Signals           []SignalSummary  `json:"signals"`
	SignalsTruncated  bool             `json:"signals_truncated"`
	Analysis          *AnalysisSummary `json:"latest_analysis,omitempty"`
	Policies          []PolicySummary  `json:"policies"`
	PoliciesTruncated bool             `json:"policies_truncated"`
}

type IncidentEventQuery struct {
	IncidentID string
	Cursor     EventCursor
	Limit      int
}

// IncidentEvent is deliberately allowlisted. It has no exact path, query,
// request/response body, cookie, Authorization value, account hash, raw
// header map, sender credential, or idempotency material.
type IncidentEvent struct {
	IncidentEventID  string    `json:"incident_event_id"`
	EventID          string    `json:"event_id"`
	IncidentVersion  int32     `json:"incident_version"`
	Kind             string    `json:"kind"`
	OccurredAt       time.Time `json:"occurred_at"`
	TraceID          *string   `json:"trace_id,omitempty"`
	SourceIP         *string   `json:"source_ip,omitempty"`
	ServiceLabel     *string   `json:"service_label,omitempty"`
	RouteLabel       *string   `json:"route_label,omitempty"`
	Method           *string   `json:"method,omitempty"`
	StatusCode       *int16    `json:"status_code,omitempty"`
	SuspiciousPathID *string   `json:"suspicious_path_id,omitempty"`
	AuthOutcome      *string   `json:"auth_outcome,omitempty"`
	BindingState     *string   `json:"binding_state,omitempty"`
	HealthState      *string   `json:"health_state,omitempty"`
	HealthCause      *string   `json:"health_cause,omitempty"`
	DroppedCount     *int64    `json:"dropped_count,omitempty"`
	TrustState       string    `json:"trust_state"`
	TrustReason      string    `json:"trust_reason"`
	RelationReason   string    `json:"relation_reason"`
}

type IncidentEventPage struct {
	Items      []IncidentEvent `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type ValidationGate struct {
	Order        int16     `json:"order"`
	Name         string    `json:"name"`
	Passed       bool      `json:"passed"`
	ResultCode   string    `json:"result_code"`
	InputDigest  string    `json:"input_digest"`
	ResultDigest string    `json:"result_digest"`
	CheckedAt    time.Time `json:"checked_at"`
}

type ValidationSummary struct {
	ValidationSnapshotID     string           `json:"validation_snapshot_id"`
	SnapshotDigest           string           `json:"snapshot_digest"`
	State                    string           `json:"state"`
	FailureCode              *string          `json:"failure_code,omitempty"`
	SourceHealthStatus       string           `json:"source_health_status"`
	BaseChainRawDigest       string           `json:"base_chain_contract_raw_digest"`
	LiveOwnedSchemaDigest    string           `json:"live_owned_schema_digest"`
	ProtectedStaticDigest    string           `json:"protected_ipv4_static_digest"`
	ProtectedEffectiveDigest string           `json:"protected_ipv4_effective_config_digest"`
	HistoricalImpactDigest   string           `json:"historical_impact_digest"`
	HistoryDatasetDigest     *string          `json:"history_dataset_digest,omitempty"`
	HistoryManifestDigest    *string          `json:"history_manifest_digest,omitempty"`
	CreatedAt                time.Time        `json:"created_at"`
	ValidUntil               time.Time        `json:"valid_until"`
	Gates                    []ValidationGate `json:"gates"`
}

// ValidationAttemptSummary exposes the immutable terminal evidence for the
// latest completed validation attempt. Unlike ValidationSummary, it exists for
// fail-closed attempts that never publish a HIL-authorizing snapshot.
type ValidationAttemptSummary struct {
	ValidationAttemptID    string                  `json:"validation_attempt_id"`
	PolicyID               string                  `json:"policy_id"`
	AnalysisID             string                  `json:"analysis_id"`
	IncidentID             string                  `json:"incident_id"`
	IncidentVersion        int32                   `json:"incident_version"`
	State                  string                  `json:"state"`
	FailureCode            *string                 `json:"failure_code,omitempty"`
	FailedGate             *string                 `json:"failed_gate,omitempty"`
	PreparedSnapshotDigest string                  `json:"prepared_snapshot_digest"`
	TerminalMutationDigest *string                 `json:"terminal_mutation_digest,omitempty"`
	CompletedAt            time.Time               `json:"completed_at"`
	Gates                  []ValidationAttemptGate `json:"gates"`
}

type ValidationAttemptGate struct {
	Order          int16  `json:"order"`
	Name           string `json:"name"`
	State          string `json:"state"`
	ResultCode     string `json:"result_code"`
	ArtifactDigest string `json:"artifact_digest"`
}

type DecisionSummary struct {
	DecisionID   string    `json:"decision_id"`
	Decision     string    `json:"decision"`
	ActorID      string    `json:"actor_id"`
	ReasonDigest string    `json:"reason_digest"`
	DecidedAt    time.Time `json:"decided_at"`
}

type PolicyDetail struct {
	PolicyID               string                    `json:"policy_id"`
	Version                int32                     `json:"version"`
	IncidentID             string                    `json:"incident_id"`
	IncidentVersion        int32                     `json:"incident_version"`
	AnalysisID             string                    `json:"analysis_id"`
	CommandCandidateID     string                    `json:"command_candidate_id"`
	State                  string                    `json:"state"`
	StateRevision          int64                     `json:"state_revision"`
	TargetIPv4             string                    `json:"target_ipv4"`
	Action                 string                    `json:"action"`
	TTLSeconds             int32                     `json:"ttl_seconds"`
	TimeoutToken           string                    `json:"timeout_token"`
	Rationale              string                    `json:"rationale"`
	PolicyDigest           string                    `json:"policy_digest"`
	EvidenceSnapshotDigest string                    `json:"evidence_snapshot_digest"`
	GeneratedCommand       string                    `json:"generated_command"`
	GeneratedDigest        string                    `json:"generated_artifact_digest"`
	CanonicalCommand       string                    `json:"canonical_command"`
	CanonicalDigest        string                    `json:"canonical_artifact_digest"`
	ParseState             string                    `json:"parse_state"`
	ParseErrorCode         *string                   `json:"parse_error_code,omitempty"`
	CreatedAt              time.Time                 `json:"created_at"`
	UpdatedAt              time.Time                 `json:"updated_at"`
	Validation             *ValidationSummary        `json:"latest_validation,omitempty"`
	ValidationAttempt      *ValidationAttemptSummary `json:"latest_validation_attempt,omitempty"`
	Decision               *DecisionSummary          `json:"decision,omitempty"`
}

type ExecutionResultSummary struct {
	ResultID            string    `json:"result_id"`
	Operation           string    `json:"operation"`
	Classification      string    `json:"classification"`
	ReadbackState       string    `json:"readback_state"`
	RemainingTTLSeconds *int32    `json:"remaining_ttl_seconds,omitempty"`
	JournalSequence     int64     `json:"journal_sequence"`
	ErrorCode           string    `json:"error_code"`
	ResultDigest        string    `json:"result_digest"`
	PersistedAt         time.Time `json:"persisted_at"`
}

type EnforcementActionDetail struct {
	ActionID               string                  `json:"action_id"`
	PolicyID               string                  `json:"policy_id"`
	PolicyVersion          int32                   `json:"policy_version"`
	ValidationSnapshotID   string                  `json:"validation_snapshot_id"`
	EvidenceSnapshotDigest string                  `json:"evidence_snapshot_digest"`
	TargetIPv4             string                  `json:"target_ipv4"`
	CanonicalDigest        string                  `json:"canonical_artifact_digest"`
	TTLSeconds             int32                   `json:"ttl_seconds"`
	State                  string                  `json:"state"`
	ApprovedAt             time.Time               `json:"approved_at"`
	QueuedAt               *time.Time              `json:"queued_at,omitempty"`
	AppliedAt              *time.Time              `json:"applied_at,omitempty"`
	ExpectedExpiresAt      *time.Time              `json:"expected_expires_at,omitempty"`
	FinishedAt             *time.Time              `json:"finished_at,omitempty"`
	Version                int32                   `json:"version"`
	CreatedAt              time.Time               `json:"created_at"`
	UpdatedAt              time.Time               `json:"updated_at"`
	LatestResult           *ExecutionResultSummary `json:"latest_result,omitempty"`
}

type AuditQuery struct {
	IncidentID string
	PolicyID   string
	ActionID   string
	ActorType  string
	ActorID    string
	ObjectType string
	ObjectID   string
	TraceID    string
	From       *time.Time
	Until      *time.Time
	Cursor     AuditCursor
	Limit      int
}

// AuditEvent omits session/token/challenge/capability bytes, signatures,
// executable artifacts, and free-form HIL reasons. Digests are inert evidence
// references, not authority.
type AuditEvent struct {
	Sequence            int64     `json:"sequence"`
	EventID             string    `json:"event_id"`
	ActorType           string    `json:"actor_type"`
	ActorID             string    `json:"actor_id"`
	Action              string    `json:"action"`
	ObjectType          string    `json:"object_type"`
	ObjectID            *string   `json:"object_id,omitempty"`
	IncidentID          *string   `json:"incident_id,omitempty"`
	PolicyID            *string   `json:"policy_id,omitempty"`
	PolicyVersion       *int32    `json:"policy_version,omitempty"`
	EnforcementActionID *string   `json:"enforcement_action_id,omitempty"`
	TraceID             *string   `json:"trace_id,omitempty"`
	PrimaryDigest       *string   `json:"primary_digest,omitempty"`
	SecondaryDigest     *string   `json:"secondary_digest,omitempty"`
	Outcome             string    `json:"outcome"`
	OccurredAt          time.Time `json:"occurred_at"`
	RecordedAt          time.Time `json:"recorded_at"`
}

type AuditPage struct {
	Items      []AuditEvent `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}
