package events

import (
	"encoding/base64"
	"net/netip"
	"regexp"
	"time"
)

var (
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	accountHashPattern = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
	labelPattern       = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	senderIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	senderEpochPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	methodPattern      = regexp.MustCompile(`^[A-Z]{1,16}$`)
	hostPattern        = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[1-9][0-9]{0,4})?$`)
)

func (e GatewayHTTPV1) Validate() error {
	if e.SchemaVersion != GatewayHTTPV1Schema {
		return fieldError("schema_version", ErrorInvalidConstant, "must identify gateway-http-v1")
	}
	if err := validateUUID("event_id", e.EventID); err != nil {
		return err
	}
	if err := validateUUID("request_id", e.RequestID); err != nil {
		return err
	}
	if err := validateUUID("trace_id", e.TraceID); err != nil {
		return err
	}
	if err := validateDigest("idempotency_key", e.IdempotencyKey); err != nil {
		return err
	}
	if err := validateTimestamp("started_at", e.StartedAt); err != nil {
		return err
	}
	if err := validateTimestamp("completed_at", e.CompletedAt); err != nil {
		return err
	}
	if e.CompletedAt.Time().Before(e.StartedAt.Time()) {
		return fieldError("completed_at", ErrorInvariant, "must not precede started_at")
	}
	if err := validateIPv4("source_ip", e.SourceIP); err != nil {
		return err
	}
	if !methodPattern.MatchString(e.Method) {
		return fieldError("method", ErrorInvalidFormat, "must be 1 to 16 uppercase ASCII letters")
	}
	if e.Protocol != "HTTP/1.1" {
		return fieldError("protocol", ErrorInvalidConstant, "must be HTTP/1.1")
	}
	if err := validateLabel("route_label", e.RouteLabel); err != nil {
		return err
	}
	if e.PathCatalogVersion != PathCatalogV1 {
		return fieldError("path_catalog_version", ErrorInvalidConstant, "must be path-catalog-v1")
	}
	if !e.SuspiciousPathID.valid() {
		return fieldError("suspicious_path_id", ErrorInvalidEnum, "must be a supported suspicious path identifier")
	}
	if len(e.Host) > 255 || !hostPattern.MatchString(e.Host) {
		return fieldError("host", ErrorInvalidFormat, "must be a normalized lowercase ASCII host")
	}
	if err := validateLabel("service_label", e.ServiceLabel); err != nil {
		return err
	}
	if e.StatusCode < 100 || e.StatusCode > 599 {
		return fieldError("status_code", ErrorOutOfRange, "must be between 100 and 599")
	}
	if e.RequestBytes > 10485760 {
		return fieldError("request_bytes", ErrorOutOfRange, "must be at most 10485760")
	}
	if e.ResponseBytes > MaxSafeInteger {
		return fieldError("response_bytes", ErrorOutOfRange, "must be a JSON safe integer")
	}
	if e.LatencyMS > 30000 {
		return fieldError("latency_ms", ErrorOutOfRange, "must be at most 30000")
	}
	return nil
}

func (e AuthEventV1) Validate() error {
	if e.SchemaVersion != AuthEventV1Schema {
		return fieldError("schema_version", ErrorInvalidConstant, "must identify auth-event-v1")
	}
	if err := validateUUID("event_id", e.EventID); err != nil {
		return err
	}
	if err := validateUUID("gateway_request_id", e.GatewayRequestID); err != nil {
		return err
	}
	if err := validateUUID("trace_id", e.TraceID); err != nil {
		return err
	}
	if err := validateDigest("idempotency_key", e.IdempotencyKey); err != nil {
		return err
	}
	if err := validateTimestamp("occurred_at", e.OccurredAt); err != nil {
		return err
	}
	if err := validateIPv4("source_ip", e.SourceIP); err != nil {
		return err
	}
	if err := validateLabel("service_label", e.ServiceLabel); err != nil {
		return err
	}
	if err := validateLabel("route_label", e.RouteLabel); err != nil {
		return err
	}
	if !accountHashPattern.MatchString(e.AccountHash) {
		return fieldError("account_hash", ErrorInvalidFormat, "must be a lowercase hmac-sha256 digest")
	}
	if e.Outcome != AuthOutcomeFailed && e.Outcome != AuthOutcomeSucceeded {
		return fieldError("outcome", ErrorInvalidEnum, "must be failed or succeeded")
	}
	return nil
}

func (e SourceHealthV1) Validate() error {
	if e.SchemaVersion != SourceHealthV1Schema {
		return fieldError("schema_version", ErrorInvalidConstant, "must identify source-health-v1")
	}
	if err := validateUUID("event_id", e.EventID); err != nil {
		return err
	}
	if err := validateDigest("idempotency_key", e.IdempotencyKey); err != nil {
		return err
	}
	if err := validateTimestamp("occurred_at", e.OccurredAt); err != nil {
		return err
	}
	if !senderIDPattern.MatchString(e.SourceID) {
		return fieldError("source_id", ErrorInvalidFormat, "must be a lowercase ASCII source identifier")
	}
	if !e.Cause.valid() {
		return fieldError("cause", ErrorInvalidEnum, "must be a supported source health cause")
	}
	if !e.State.valid() {
		return fieldError("state", ErrorInvalidEnum, "must be degraded, lost, or recovered")
	}
	if err := validateSenderEpoch("affected_sender_epoch", e.AffectedSenderEpoch); err != nil {
		return err
	}
	if e.SequenceStart != nil && (*e.SequenceStart < 1 || *e.SequenceStart > MaxSafeInteger) {
		return fieldError("sequence_start", ErrorOutOfRange, "must be null or a JSON safe positive integer")
	}
	if e.SequenceEnd != nil && (*e.SequenceEnd < 1 || *e.SequenceEnd > MaxSafeInteger) {
		return fieldError("sequence_end", ErrorOutOfRange, "must be null or a JSON safe positive integer")
	}
	if e.SequenceStart != nil && e.SequenceEnd != nil && *e.SequenceEnd < *e.SequenceStart {
		return fieldError("sequence_end", ErrorInvariant, "must not precede sequence_start")
	}
	if e.IntervalStart != nil {
		if err := validateTimestamp("interval_start", *e.IntervalStart); err != nil {
			return err
		}
	}
	if e.IntervalEnd != nil {
		if err := validateTimestamp("interval_end", *e.IntervalEnd); err != nil {
			return err
		}
	}
	if e.IntervalStart != nil && e.IntervalEnd != nil && e.IntervalEnd.Time().Before(e.IntervalStart.Time()) {
		return fieldError("interval_end", ErrorInvariant, "must not precede interval_start")
	}
	if e.DroppedCount > MaxSafeInteger {
		return fieldError("dropped_count", ErrorOutOfRange, "must be a JSON safe integer")
	}
	if !e.DetailCode.valid() {
		return fieldError("detail_code", ErrorInvalidEnum, "must be a supported source health detail code")
	}
	return nil
}

func (e SourceCoverageV1) Validate() error {
	if e.SchemaVersion != SourceCoverageV1Schema {
		return fieldError("schema_version", ErrorInvalidConstant, "must identify source-coverage-v1")
	}
	if err := validateUUID("event_id", e.EventID); err != nil {
		return err
	}
	if err := validateDigest("idempotency_key", e.IdempotencyKey); err != nil {
		return err
	}
	if !senderIDPattern.MatchString(e.SourceID) {
		return fieldError("source_id", ErrorInvalidFormat, "must be a lowercase ASCII source identifier")
	}
	if err := validateSenderEpoch("affected_sender_epoch", e.AffectedSenderEpoch); err != nil {
		return err
	}
	if err := validateUUID("segment_id", e.SegmentID); err != nil {
		return err
	}
	if e.PreviousCoverageDigest != nil {
		if err := validateDigest("previous_coverage_digest", *e.PreviousCoverageDigest); err != nil {
			return err
		}
	}
	if err := validateMillisecondTimestamp("coverage_start", e.CoverageStart); err != nil {
		return err
	}
	if err := validateMillisecondTimestamp("coverage_end", e.CoverageEnd); err != nil {
		return err
	}
	if e.CoverageEnd.Time().Before(e.CoverageStart.Time()) {
		return fieldError("coverage_end", ErrorInvariant, "must not precede coverage_start")
	}
	if err := validateUUID("covered_through_batch_id", e.CoveredThroughBatchID); err != nil {
		return err
	}
	if e.CoveredThroughSequence < 1 || e.CoveredThroughSequence > MaxSafeInteger {
		return fieldError("covered_through_sequence", ErrorOutOfRange, "must be a JSON safe positive integer")
	}
	if e.State != "complete" {
		return fieldError("state", ErrorInvalidConstant, "must be complete")
	}
	return nil
}

func (r EventRecordV1) Validate() error {
	variants := 0
	if r.GatewayHTTP != nil {
		variants++
	}
	if r.AuthEvent != nil {
		variants++
	}
	if r.SourceHealth != nil {
		variants++
	}
	if r.SourceCoverage != nil {
		variants++
	}
	if variants != 1 {
		return fieldError("$", ErrorCardinality, "record must contain exactly one typed event")
	}

	switch {
	case r.GatewayHTTP != nil:
		return r.GatewayHTTP.Validate()
	case r.AuthEvent != nil:
		return r.AuthEvent.Validate()
	case r.SourceHealth != nil:
		return r.SourceHealth.Validate()
	default:
		return r.SourceCoverage.Validate()
	}
}

func (b EventBatchV1) Validate() error {
	if b.SchemaVersion != EventBatchV1Schema {
		return fieldError("schema_version", ErrorInvalidConstant, "must identify event-batch-v1")
	}
	if !senderIDPattern.MatchString(b.SenderID) {
		return fieldError("sender_id", ErrorInvalidFormat, "must be a lowercase ASCII sender identifier")
	}
	if err := validateSenderEpoch("sender_epoch", b.SenderEpoch); err != nil {
		return err
	}
	if err := validateUUID("batch_id", b.BatchID); err != nil {
		return err
	}
	if b.Sequence < 1 || b.Sequence > MaxSafeInteger {
		return fieldError("sequence", ErrorOutOfRange, "must be a JSON safe positive integer")
	}
	if err := validateTimestamp("sent_at", b.SentAt); err != nil {
		return err
	}
	if len(b.Records) < 1 || len(b.Records) > MaxEventBatchRecords {
		return fieldError("records", ErrorCardinality, "must contain between 1 and 100 records")
	}
	for index := range b.Records {
		if err := b.Records[index].Validate(); err != nil {
			return prefixError(recordField(index), err)
		}
	}
	coverageIndex := -1
	for index := range b.Records {
		coverage := b.Records[index].SourceCoverage
		if coverage == nil {
			continue
		}
		if coverageIndex != -1 || index != len(b.Records)-1 {
			return fieldError("records", ErrorInvariant, "source coverage must be the single final record")
		}
		coverageIndex = index
		if coverage.SourceID != b.SenderID || coverage.AffectedSenderEpoch != b.SenderEpoch ||
			coverage.CoveredThroughBatchID != b.BatchID || coverage.CoveredThroughSequence != b.Sequence {
			return fieldError(recordField(index), ErrorInvariant, "source coverage must bind the containing batch")
		}
	}
	return nil
}

func validateUUID(field, value string) error {
	if !uuidPattern.MatchString(value) {
		return fieldError(field, ErrorInvalidFormat, "must be a lowercase UUID string")
	}
	return nil
}

func validateDigest(field, value string) error {
	if !digestPattern.MatchString(value) {
		return fieldError(field, ErrorInvalidFormat, "must be a lowercase sha256 digest")
	}
	return nil
}

func validateLabel(field, value string) error {
	if !labelPattern.MatchString(value) {
		return fieldError(field, ErrorInvalidFormat, "must be a lowercase ASCII label")
	}
	return nil
}

func validateTimestamp(field string, value Timestamp) error {
	if !value.Valid() {
		return fieldError(field, ErrorRequired, "must be a UTC RFC3339 timestamp")
	}
	return nil
}

func validateMillisecondTimestamp(field string, value Timestamp) error {
	if err := validateTimestamp(field, value); err != nil {
		return err
	}
	if value.Time().Nanosecond()%int(time.Millisecond) != 0 {
		return fieldError(field, ErrorInvalidFormat, "must use at most millisecond precision")
	}
	return nil
}

func validateIPv4(field, value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value {
		return fieldError(field, ErrorInvalidFormat, "must be a canonical IPv4 address")
	}
	return nil
}

func validateSenderEpoch(field, value string) error {
	if !senderEpochPattern.MatchString(value) {
		return fieldError(field, ErrorInvalidFormat, "must be a 128-bit unpadded base64url value")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return fieldError(field, ErrorInvalidFormat, "must be a 128-bit unpadded base64url value")
	}
	return nil
}

func (v SuspiciousPathID) valid() bool {
	switch v {
	case SuspiciousPathNone, SuspiciousPathAdminConsole, SuspiciousPathEnvFile,
		SuspiciousPathGitConfig, SuspiciousPathWPAdmin, SuspiciousPathPHPMyAdmin,
		SuspiciousPathServerStatus, SuspiciousPathActuatorEnv, SuspiciousPathBackupArchive:
		return true
	default:
		return false
	}
}

func (v SourceHealthCause) valid() bool {
	switch v {
	case SourceHealthQueueOverflow, SourceHealthDeliveryOutage, SourceHealthRejectedBatch,
		SourceHealthSequenceGap, SourceHealthPermanentLoss, SourceHealthUncleanRestart,
		SourceHealthUnknownLoss, SourceHealthRecovered:
		return true
	default:
		return false
	}
}

func (v SourceHealthState) valid() bool {
	return v == SourceHealthStateDegraded || v == SourceHealthStateLost || v == SourceHealthStateRecovered
}

func (v SourceHealthDetailCode) valid() bool {
	switch v {
	case SourceHealthDetailNone, SourceHealthDetailKnownRange, SourceHealthDetailUnknownRange,
		SourceHealthDetailReceiverRejected, SourceHealthDetailSenderRestart, SourceHealthDetailDeliveryRestored:
		return true
	default:
		return false
	}
}

func recordField(index int) string {
	const digits = "0123456789"
	if index < 10 {
		return "records[" + string(digits[index]) + "]"
	}

	// Batch size is at most 100, so this fixed conversion avoids formatting
	// arbitrary input in validation errors.
	if index < 100 {
		return "records[" + string(digits[index/10]) + string(digits[index%10]) + "]"
	}
	return "records"
}
