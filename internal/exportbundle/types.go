// Package exportbundle creates bounded, privacy-preserving incident and audit
// exports from the sentinelflow_read database role. Exported audit records keep
// their original sequence and evidence digests, while a separate domain-bound
// chain makes deletion, insertion, reordering, and mutation detectable.
package exportbundle

import (
	"context"
	"errors"
	"regexp"
	"time"
)

const (
	BundleSchemaVersion   = "sentinelflow-export-bundle-v1"
	ManifestSchemaVersion = "sentinelflow-export-manifest-v1"
	IncidentSchemaVersion = "sentinelflow-export-incident-v1"
	AuditSchemaVersion    = "sentinelflow-export-audit-v1"
	PseudonymAlgorithm    = "HMAC-SHA-256"
	GenesisDigest         = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	MinimumPseudonymKeyBytes = 32
	MaximumPseudonymKeyBytes = 64
	MaximumExportWindow      = 31 * 24 * time.Hour
	MaximumIncidentRecords   = 10_000
	MaximumAuditRecords      = 50_000
	MaximumBundleBytes       = 64 << 20
	MaximumAuditSequence     = int64(1<<53 - 1)
)

var (
	ErrInvalidRequest = errors.New("export request rejected")
	ErrInvalidData    = errors.New("export data rejected")
	ErrLimitExceeded  = errors.New("export bound exceeded")
	ErrIntegrity      = errors.New("export integrity verification failed")
	ErrUnsafeFile     = errors.New("export file rejected")

	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	labelPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// Query bounds one repeatable-read database snapshot. The constructor is the
// only supported way to create it so callers cannot bypass row or time limits.
type Query struct {
	since          time.Time
	until          time.Time
	incidentID     string
	maxIncidents   int
	maxAuditEvents int
}

func NewQuery(since, until time.Time, incidentID string, maxIncidents, maxAuditEvents int) (Query, error) {
	since = since.UTC()
	until = until.UTC()
	if since.IsZero() || until.IsZero() || !until.After(since) || until.Sub(since) > MaximumExportWindow ||
		(incidentID != "" && !uuidPattern.MatchString(incidentID)) ||
		maxIncidents < 1 || maxIncidents > MaximumIncidentRecords ||
		maxAuditEvents < 1 || maxAuditEvents > MaximumAuditRecords {
		return Query{}, ErrInvalidRequest
	}
	return Query{since: since, until: until, incidentID: incidentID,
		maxIncidents: maxIncidents, maxAuditEvents: maxAuditEvents}, nil
}

func (q Query) Since() time.Time    { return q.since }
func (q Query) Until() time.Time    { return q.until }
func (q Query) IncidentID() string  { return q.incidentID }
func (q Query) MaxIncidents() int   { return q.maxIncidents }
func (q Query) MaxAuditEvents() int { return q.maxAuditEvents }
func (q Query) Valid() bool {
	_, err := NewQuery(q.since, q.until, q.incidentID, q.maxIncidents, q.maxAuditEvents)
	return err == nil
}

type RawIncident struct {
	IncidentID            string
	Kind                  string
	State                 string
	SourceIPv4            string
	ServiceLabel          string
	FirstSeen             time.Time
	LastSeen              time.Time
	ClosedAt              *time.Time
	ReopenUntil           *time.Time
	DeterministicScore    string
	Version               int32
	AnalysisFailureReason *string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type RawAuditEvent struct {
	Sequence            int64
	EventID             string
	ActorType           string
	ActorID             string
	Action              string
	ObjectType          string
	ObjectID            *string
	IncidentID          *string
	PolicyID            *string
	PolicyVersion       *int32
	EnforcementActionID *string
	TraceID             *string
	PrimaryDigest       *string
	SecondaryDigest     *string
	Outcome             string
	OccurredAt          time.Time
	RecordedAt          time.Time
}

type Snapshot struct {
	SnapshotAt time.Time
	Incidents  []RawIncident
	Audit      []RawAuditEvent
}

// Store must return one internally consistent, read-only snapshot. It must
// return ErrLimitExceeded rather than truncate either result set.
type Store interface {
	Snapshot(context.Context, Query) (Snapshot, error)
}

type Window struct {
	Since string `json:"since"`
	Until string `json:"until"`
}

type Filters struct {
	IncidentID *string `json:"incident_id"`
}

type Pseudonymization struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
}

type IncidentRecord struct {
	SchemaVersion         string  `json:"schema_version"`
	IncidentID            string  `json:"incident_id"`
	Kind                  string  `json:"kind"`
	State                 string  `json:"state"`
	SourcePseudonym       string  `json:"source_pseudonym"`
	ServiceLabel          string  `json:"service_label"`
	FirstSeen             string  `json:"first_seen"`
	LastSeen              string  `json:"last_seen"`
	ClosedAt              *string `json:"closed_at"`
	ReopenUntil           *string `json:"reopen_until"`
	DeterministicScore    string  `json:"deterministic_score"`
	Version               int32   `json:"version"`
	AnalysisFailureReason *string `json:"analysis_failure_reason"`
	CreatedAt             string  `json:"created_at"`
	UpdatedAt             string  `json:"updated_at"`
	RecordDigest          string  `json:"record_digest"`
}

type AuditRecord struct {
	SchemaVersion        string  `json:"schema_version"`
	Sequence             int64   `json:"sequence"`
	EventID              string  `json:"event_id"`
	ActorType            string  `json:"actor_type"`
	ActorPseudonym       string  `json:"actor_pseudonym"`
	Action               string  `json:"action"`
	ObjectType           string  `json:"object_type"`
	ObjectID             *string `json:"object_id"`
	IncidentID           *string `json:"incident_id"`
	PolicyID             *string `json:"policy_id"`
	PolicyVersion        *int32  `json:"policy_version"`
	EnforcementActionID  *string `json:"enforcement_action_id"`
	TracePseudonym       *string `json:"trace_pseudonym"`
	PrimaryDigest        *string `json:"primary_digest"`
	SecondaryDigest      *string `json:"secondary_digest"`
	Outcome              string  `json:"outcome"`
	OccurredAt           string  `json:"occurred_at"`
	RecordedAt           string  `json:"recorded_at"`
	PreviousRecordDigest string  `json:"previous_record_digest"`
	RecordDigest         string  `json:"record_digest"`
}

type Manifest struct {
	SchemaVersion         string           `json:"schema_version"`
	ExportID              string           `json:"export_id"`
	CreatedAt             string           `json:"created_at"`
	DatabaseSnapshotAt    string           `json:"database_snapshot_at"`
	Window                Window           `json:"window"`
	Filters               Filters          `json:"filters"`
	Pseudonymization      Pseudonymization `json:"pseudonymization"`
	IncidentCount         int              `json:"incident_count"`
	AuditEventCount       int              `json:"audit_event_count"`
	IncidentRecordsDigest string           `json:"incident_records_digest"`
	AuditChainGenesis     string           `json:"audit_chain_genesis"`
	AuditChainRoot        string           `json:"audit_chain_root"`
	ManifestDigest        string           `json:"manifest_digest"`
}

type Bundle struct {
	SchemaVersion string           `json:"schema_version"`
	Manifest      Manifest         `json:"manifest"`
	Incidents     []IncidentRecord `json:"incidents"`
	AuditEvents   []AuditRecord    `json:"audit_events"`
}

type Result struct {
	ExportID        string `json:"export_id"`
	ManifestDigest  string `json:"manifest_digest"`
	BundleDigest    string `json:"bundle_digest"`
	IncidentCount   int    `json:"incident_count"`
	AuditEventCount int    `json:"audit_event_count"`
	OutputPath      string `json:"output_path,omitempty"`
}
