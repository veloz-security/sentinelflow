package events

const (
	GatewayHTTPV1Schema    = "gateway-http-v1"
	AuthEventV1Schema      = "auth-event-v1"
	SourceHealthV1Schema   = "source-health-v1"
	SourceCoverageV1Schema = "source-coverage-v1"
	EventBatchV1Schema     = "event-batch-v1"

	PathCatalogV1 = "path-catalog-v1"

	MaxSafeInteger         = uint64(9007199254740991)
	MaxEventBatchRecords   = 100
	MaxEventBatchBodyBytes = 256 * 1024
)

// EnqueueResult is the bounded, non-blocking observation outcome returned to
// the Gateway request path. It deliberately carries no persistence or
// analysis result.
type EnqueueResult string

const (
	EnqueueAccepted EnqueueResult = "accepted"
	EnqueueDegraded EnqueueResult = "degraded"
	EnqueueDropped  EnqueueResult = "dropped"
)

type SuspiciousPathID string

const (
	SuspiciousPathNone          SuspiciousPathID = "none"
	SuspiciousPathAdminConsole  SuspiciousPathID = "admin_console"
	SuspiciousPathEnvFile       SuspiciousPathID = "env_file"
	SuspiciousPathGitConfig     SuspiciousPathID = "git_config"
	SuspiciousPathWPAdmin       SuspiciousPathID = "wp_admin"
	SuspiciousPathPHPMyAdmin    SuspiciousPathID = "phpmyadmin"
	SuspiciousPathServerStatus  SuspiciousPathID = "server_status"
	SuspiciousPathActuatorEnv   SuspiciousPathID = "actuator_env"
	SuspiciousPathBackupArchive SuspiciousPathID = "backup_archive"
)

type AuthOutcome string

const (
	AuthOutcomeFailed    AuthOutcome = "failed"
	AuthOutcomeSucceeded AuthOutcome = "succeeded"
)

type SourceHealthCause string

const (
	SourceHealthQueueOverflow  SourceHealthCause = "queue_overflow"
	SourceHealthDeliveryOutage SourceHealthCause = "delivery_outage"
	SourceHealthRejectedBatch  SourceHealthCause = "rejected_batch"
	SourceHealthSequenceGap    SourceHealthCause = "sequence_gap"
	SourceHealthPermanentLoss  SourceHealthCause = "permanent_loss"
	SourceHealthUncleanRestart SourceHealthCause = "unclean_restart"
	SourceHealthUnknownLoss    SourceHealthCause = "unknown_loss"
	SourceHealthRecovered      SourceHealthCause = "recovered"
)

type SourceHealthState string

const (
	SourceHealthStateDegraded  SourceHealthState = "degraded"
	SourceHealthStateLost      SourceHealthState = "lost"
	SourceHealthStateRecovered SourceHealthState = "recovered"
)

type SourceHealthDetailCode string

const (
	SourceHealthDetailNone             SourceHealthDetailCode = "none"
	SourceHealthDetailKnownRange       SourceHealthDetailCode = "known_range"
	SourceHealthDetailUnknownRange     SourceHealthDetailCode = "unknown_range"
	SourceHealthDetailReceiverRejected SourceHealthDetailCode = "receiver_rejected"
	SourceHealthDetailSenderRestart    SourceHealthDetailCode = "sender_restart"
	SourceHealthDetailDeliveryRestored SourceHealthDetailCode = "delivery_restored"
)

// GatewayHTTPV1 is the complete gateway-http-v1 persistence allowlist.
type GatewayHTTPV1 struct {
	SchemaVersion      string           `json:"schema_version"`
	EventID            string           `json:"event_id"`
	RequestID          string           `json:"request_id"`
	TraceID            string           `json:"trace_id"`
	IdempotencyKey     string           `json:"idempotency_key"`
	StartedAt          Timestamp        `json:"started_at"`
	CompletedAt        Timestamp        `json:"completed_at"`
	SourceIP           string           `json:"source_ip"`
	Method             string           `json:"method"`
	Protocol           string           `json:"protocol"`
	RouteLabel         string           `json:"route_label"`
	PathCatalogVersion string           `json:"path_catalog_version"`
	SuspiciousPathID   SuspiciousPathID `json:"suspicious_path_id"`
	Host               string           `json:"host"`
	ServiceLabel       string           `json:"service_label"`
	StatusCode         int              `json:"status_code"`
	RequestBytes       uint64           `json:"request_bytes"`
	ResponseBytes      uint64           `json:"response_bytes"`
	LatencyMS          uint64           `json:"latency_ms"`
}

// GatewayEvent keeps the component-facing TDD name while preserving the exact
// gateway-http-v1 wire type.
type GatewayEvent = GatewayHTTPV1

type AuthEventV1 struct {
	SchemaVersion    string      `json:"schema_version"`
	EventID          string      `json:"event_id"`
	GatewayRequestID string      `json:"gateway_request_id"`
	TraceID          string      `json:"trace_id"`
	IdempotencyKey   string      `json:"idempotency_key"`
	OccurredAt       Timestamp   `json:"occurred_at"`
	SourceIP         string      `json:"source_ip"`
	ServiceLabel     string      `json:"service_label"`
	RouteLabel       string      `json:"route_label"`
	AccountHash      string      `json:"account_hash"`
	Outcome          AuthOutcome `json:"outcome"`
}

type SourceHealthV1 struct {
	SchemaVersion       string                 `json:"schema_version"`
	EventID             string                 `json:"event_id"`
	IdempotencyKey      string                 `json:"idempotency_key"`
	OccurredAt          Timestamp              `json:"occurred_at"`
	SourceID            string                 `json:"source_id"`
	Cause               SourceHealthCause      `json:"cause"`
	State               SourceHealthState      `json:"state"`
	AffectedSenderEpoch string                 `json:"affected_sender_epoch"`
	SequenceStart       *uint64                `json:"sequence_start"`
	SequenceEnd         *uint64                `json:"sequence_end"`
	IntervalStart       *Timestamp             `json:"interval_start"`
	IntervalEnd         *Timestamp             `json:"interval_end"`
	DroppedCount        uint64                 `json:"dropped_count"`
	DetailCode          SourceHealthDetailCode `json:"detail_code"`
}

// SourceCoverageV1 is a positive producer assertion made at one serialized
// queue cut. It is valid only as the final record of the containing,
// endpoint-authenticated batch. The receiver binds the record to that exact
// batch's raw-body digest and database receipt time.
type SourceCoverageV1 struct {
	SchemaVersion          string    `json:"schema_version"`
	EventID                string    `json:"event_id"`
	IdempotencyKey         string    `json:"idempotency_key"`
	SourceID               string    `json:"source_id"`
	AffectedSenderEpoch    string    `json:"affected_sender_epoch"`
	SegmentID              string    `json:"segment_id"`
	PreviousCoverageDigest *string   `json:"previous_coverage_digest"`
	CoverageStart          Timestamp `json:"coverage_start"`
	CoverageEnd            Timestamp `json:"coverage_end"`
	CoveredThroughBatchID  string    `json:"covered_through_batch_id"`
	CoveredThroughSequence uint64    `json:"covered_through_sequence"`
	State                  string    `json:"state"`
}

// EventRecordV1 contains exactly one event variant. It intentionally stores no
// raw JSON, arbitrary properties, or catch-all metadata map.
type EventRecordV1 struct {
	GatewayHTTP    *GatewayHTTPV1
	AuthEvent      *AuthEventV1
	SourceHealth   *SourceHealthV1
	SourceCoverage *SourceCoverageV1
}

func GatewayHTTPRecord(event GatewayHTTPV1) EventRecordV1 {
	return EventRecordV1{GatewayHTTP: &event}
}

func AuthEventRecord(event AuthEventV1) EventRecordV1 {
	return EventRecordV1{AuthEvent: &event}
}

func SourceHealthRecord(event SourceHealthV1) EventRecordV1 {
	return EventRecordV1{SourceHealth: &event}
}

func SourceCoverageRecord(event SourceCoverageV1) EventRecordV1 {
	return EventRecordV1{SourceCoverage: &event}
}

func (r EventRecordV1) SchemaVersion() string {
	switch {
	case r.GatewayHTTP != nil && r.AuthEvent == nil && r.SourceHealth == nil && r.SourceCoverage == nil:
		return r.GatewayHTTP.SchemaVersion
	case r.GatewayHTTP == nil && r.AuthEvent != nil && r.SourceHealth == nil && r.SourceCoverage == nil:
		return r.AuthEvent.SchemaVersion
	case r.GatewayHTTP == nil && r.AuthEvent == nil && r.SourceHealth != nil && r.SourceCoverage == nil:
		return r.SourceHealth.SchemaVersion
	case r.GatewayHTTP == nil && r.AuthEvent == nil && r.SourceHealth == nil && r.SourceCoverage != nil:
		return r.SourceCoverage.SchemaVersion
	default:
		return ""
	}
}

type EventBatchV1 struct {
	SchemaVersion string          `json:"schema_version"`
	SenderID      string          `json:"sender_id"`
	SenderEpoch   string          `json:"sender_epoch"`
	BatchID       string          `json:"batch_id"`
	Sequence      uint64          `json:"sequence"`
	SentAt        Timestamp       `json:"sent_at"`
	Records       []EventRecordV1 `json:"records"`
}
