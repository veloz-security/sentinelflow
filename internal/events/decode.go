package events

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
)

var (
	gatewayHTTPFields = fieldSet(
		"schema_version", "event_id", "request_id", "trace_id", "idempotency_key",
		"started_at", "completed_at", "source_ip", "method", "protocol", "route_label",
		"path_catalog_version", "suspicious_path_id", "host", "service_label", "status_code",
		"request_bytes", "response_bytes", "latency_ms",
	)
	authEventFields = fieldSet(
		"schema_version", "event_id", "gateway_request_id", "trace_id", "idempotency_key",
		"occurred_at", "source_ip", "service_label", "route_label", "account_hash", "outcome",
	)
	sourceHealthFields = fieldSet(
		"schema_version", "event_id", "idempotency_key", "occurred_at", "source_id", "cause",
		"state", "affected_sender_epoch", "sequence_start", "sequence_end", "interval_start",
		"interval_end", "dropped_count", "detail_code",
	)
	sourceCoverageFields = fieldSet(
		"schema_version", "event_id", "idempotency_key", "source_id",
		"affected_sender_epoch", "segment_id", "previous_coverage_digest",
		"coverage_start", "coverage_end", "covered_through_batch_id",
		"covered_through_sequence", "state",
	)
	eventBatchFields = fieldSet(
		"schema_version", "sender_id", "sender_epoch", "batch_id", "sequence", "sent_at", "records",
	)
)

// DecodeGatewayHTTPV1 strictly decodes one gateway-http-v1 object.
func DecodeGatewayHTTPV1(data []byte) (GatewayHTTPV1, error) {
	fields, err := decodeObject(data)
	if err != nil {
		return GatewayHTTPV1{}, err
	}
	return decodeGatewayHTTPObject(fields)
}

// DecodeAuthEventV1 strictly decodes one auth-event-v1 object.
func DecodeAuthEventV1(data []byte) (AuthEventV1, error) {
	fields, err := decodeObject(data)
	if err != nil {
		return AuthEventV1{}, err
	}
	return decodeAuthEventObject(fields)
}

// DecodeSourceHealthV1 strictly decodes one source-health-v1 object.
func DecodeSourceHealthV1(data []byte) (SourceHealthV1, error) {
	fields, err := decodeObject(data)
	if err != nil {
		return SourceHealthV1{}, err
	}
	return decodeSourceHealthObject(fields)
}

// DecodeSourceCoverageV1 strictly decodes one source-coverage-v1 object.
func DecodeSourceCoverageV1(data []byte) (SourceCoverageV1, error) {
	fields, err := decodeObject(data)
	if err != nil {
		return SourceCoverageV1{}, err
	}
	return decodeSourceCoverageObject(fields)
}

// DecodeEventRecordV1 strictly decodes one of the four allowed event record
// schemas using schema_version as its discriminator.
func DecodeEventRecordV1(data []byte) (EventRecordV1, error) {
	fields, err := decodeObject(data)
	if err != nil {
		return EventRecordV1{}, err
	}
	return decodeEventRecordObject(fields)
}

// DecodeEventBatchV1 strictly decodes one bounded event-batch-v1 body.
func DecodeEventBatchV1(data []byte) (EventBatchV1, error) {
	if len(data) > MaxEventBatchBodyBytes {
		return EventBatchV1{}, fieldError("$", ErrorTooLarge, "batch body exceeds 256 KiB")
	}
	fields, err := decodeObject(data)
	if err != nil {
		return EventBatchV1{}, err
	}
	return decodeEventBatchObject(fields)
}

func decodeGatewayHTTPObject(fields map[string]json.RawMessage) (GatewayHTTPV1, error) {
	if err := validateObjectFields(fields, gatewayHTTPFields); err != nil {
		return GatewayHTTPV1{}, err
	}

	var event GatewayHTTPV1
	var err error
	if event.SchemaVersion, err = readString(fields, "schema_version"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.EventID, err = readString(fields, "event_id"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.RequestID, err = readString(fields, "request_id"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.TraceID, err = readString(fields, "trace_id"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.IdempotencyKey, err = readString(fields, "idempotency_key"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.StartedAt, err = readTimestamp(fields, "started_at"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.CompletedAt, err = readTimestamp(fields, "completed_at"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.SourceIP, err = readString(fields, "source_ip"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.Method, err = readString(fields, "method"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.Protocol, err = readString(fields, "protocol"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.RouteLabel, err = readString(fields, "route_label"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.PathCatalogVersion, err = readString(fields, "path_catalog_version"); err != nil {
		return GatewayHTTPV1{}, err
	}
	suspiciousPathID, err := readString(fields, "suspicious_path_id")
	if err != nil {
		return GatewayHTTPV1{}, err
	}
	event.SuspiciousPathID = SuspiciousPathID(suspiciousPathID)
	if event.Host, err = readString(fields, "host"); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.ServiceLabel, err = readString(fields, "service_label"); err != nil {
		return GatewayHTTPV1{}, err
	}
	statusCode, err := readUint(fields, "status_code", 100, 599)
	if err != nil {
		return GatewayHTTPV1{}, err
	}
	event.StatusCode = int(statusCode)
	if event.RequestBytes, err = readUint(fields, "request_bytes", 0, 10485760); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.ResponseBytes, err = readUint(fields, "response_bytes", 0, MaxSafeInteger); err != nil {
		return GatewayHTTPV1{}, err
	}
	if event.LatencyMS, err = readUint(fields, "latency_ms", 0, 30000); err != nil {
		return GatewayHTTPV1{}, err
	}
	if err := event.Validate(); err != nil {
		return GatewayHTTPV1{}, err
	}
	return event, nil
}

func decodeAuthEventObject(fields map[string]json.RawMessage) (AuthEventV1, error) {
	if err := validateObjectFields(fields, authEventFields); err != nil {
		return AuthEventV1{}, err
	}

	var event AuthEventV1
	var err error
	if event.SchemaVersion, err = readString(fields, "schema_version"); err != nil {
		return AuthEventV1{}, err
	}
	if event.EventID, err = readString(fields, "event_id"); err != nil {
		return AuthEventV1{}, err
	}
	if event.GatewayRequestID, err = readString(fields, "gateway_request_id"); err != nil {
		return AuthEventV1{}, err
	}
	if event.TraceID, err = readString(fields, "trace_id"); err != nil {
		return AuthEventV1{}, err
	}
	if event.IdempotencyKey, err = readString(fields, "idempotency_key"); err != nil {
		return AuthEventV1{}, err
	}
	if event.OccurredAt, err = readTimestamp(fields, "occurred_at"); err != nil {
		return AuthEventV1{}, err
	}
	if event.SourceIP, err = readString(fields, "source_ip"); err != nil {
		return AuthEventV1{}, err
	}
	if event.ServiceLabel, err = readString(fields, "service_label"); err != nil {
		return AuthEventV1{}, err
	}
	if event.RouteLabel, err = readString(fields, "route_label"); err != nil {
		return AuthEventV1{}, err
	}
	if event.AccountHash, err = readString(fields, "account_hash"); err != nil {
		return AuthEventV1{}, err
	}
	outcome, err := readString(fields, "outcome")
	if err != nil {
		return AuthEventV1{}, err
	}
	event.Outcome = AuthOutcome(outcome)
	if err := event.Validate(); err != nil {
		return AuthEventV1{}, err
	}
	return event, nil
}

func decodeSourceHealthObject(fields map[string]json.RawMessage) (SourceHealthV1, error) {
	if err := validateObjectFields(fields, sourceHealthFields); err != nil {
		return SourceHealthV1{}, err
	}

	var event SourceHealthV1
	var err error
	if event.SchemaVersion, err = readString(fields, "schema_version"); err != nil {
		return SourceHealthV1{}, err
	}
	if event.EventID, err = readString(fields, "event_id"); err != nil {
		return SourceHealthV1{}, err
	}
	if event.IdempotencyKey, err = readString(fields, "idempotency_key"); err != nil {
		return SourceHealthV1{}, err
	}
	if event.OccurredAt, err = readTimestamp(fields, "occurred_at"); err != nil {
		return SourceHealthV1{}, err
	}
	if event.SourceID, err = readString(fields, "source_id"); err != nil {
		return SourceHealthV1{}, err
	}
	cause, err := readString(fields, "cause")
	if err != nil {
		return SourceHealthV1{}, err
	}
	event.Cause = SourceHealthCause(cause)
	state, err := readString(fields, "state")
	if err != nil {
		return SourceHealthV1{}, err
	}
	event.State = SourceHealthState(state)
	if event.AffectedSenderEpoch, err = readString(fields, "affected_sender_epoch"); err != nil {
		return SourceHealthV1{}, err
	}
	if event.SequenceStart, err = readNullableUint(fields, "sequence_start", 1, MaxSafeInteger); err != nil {
		return SourceHealthV1{}, err
	}
	if event.SequenceEnd, err = readNullableUint(fields, "sequence_end", 1, MaxSafeInteger); err != nil {
		return SourceHealthV1{}, err
	}
	if event.IntervalStart, err = readNullableTimestamp(fields, "interval_start"); err != nil {
		return SourceHealthV1{}, err
	}
	if event.IntervalEnd, err = readNullableTimestamp(fields, "interval_end"); err != nil {
		return SourceHealthV1{}, err
	}
	if event.DroppedCount, err = readUint(fields, "dropped_count", 0, MaxSafeInteger); err != nil {
		return SourceHealthV1{}, err
	}
	detailCode, err := readString(fields, "detail_code")
	if err != nil {
		return SourceHealthV1{}, err
	}
	event.DetailCode = SourceHealthDetailCode(detailCode)
	if err := event.Validate(); err != nil {
		return SourceHealthV1{}, err
	}
	return event, nil
}

func decodeSourceCoverageObject(fields map[string]json.RawMessage) (SourceCoverageV1, error) {
	if err := validateObjectFields(fields, sourceCoverageFields); err != nil {
		return SourceCoverageV1{}, err
	}

	var event SourceCoverageV1
	var err error
	if event.SchemaVersion, err = readString(fields, "schema_version"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.EventID, err = readString(fields, "event_id"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.IdempotencyKey, err = readString(fields, "idempotency_key"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.SourceID, err = readString(fields, "source_id"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.AffectedSenderEpoch, err = readString(fields, "affected_sender_epoch"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.SegmentID, err = readString(fields, "segment_id"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.PreviousCoverageDigest, err = readNullableString(fields, "previous_coverage_digest"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.CoverageStart, err = readMillisecondTimestamp(fields, "coverage_start"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.CoverageEnd, err = readMillisecondTimestamp(fields, "coverage_end"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.CoveredThroughBatchID, err = readString(fields, "covered_through_batch_id"); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.CoveredThroughSequence, err = readUint(fields, "covered_through_sequence", 1, MaxSafeInteger); err != nil {
		return SourceCoverageV1{}, err
	}
	if event.State, err = readString(fields, "state"); err != nil {
		return SourceCoverageV1{}, err
	}
	if err := event.Validate(); err != nil {
		return SourceCoverageV1{}, err
	}
	return event, nil
}

func decodeEventRecordObject(fields map[string]json.RawMessage) (EventRecordV1, error) {
	schemaVersion, err := readString(fields, "schema_version")
	if err != nil {
		return EventRecordV1{}, err
	}
	switch schemaVersion {
	case GatewayHTTPV1Schema:
		event, err := decodeGatewayHTTPObject(fields)
		if err != nil {
			return EventRecordV1{}, err
		}
		return GatewayHTTPRecord(event), nil
	case AuthEventV1Schema:
		event, err := decodeAuthEventObject(fields)
		if err != nil {
			return EventRecordV1{}, err
		}
		return AuthEventRecord(event), nil
	case SourceHealthV1Schema:
		event, err := decodeSourceHealthObject(fields)
		if err != nil {
			return EventRecordV1{}, err
		}
		return SourceHealthRecord(event), nil
	case SourceCoverageV1Schema:
		event, err := decodeSourceCoverageObject(fields)
		if err != nil {
			return EventRecordV1{}, err
		}
		return SourceCoverageRecord(event), nil
	default:
		return EventRecordV1{}, fieldError("schema_version", ErrorInvalidEnum, "must identify an allowed event record schema")
	}
}

func decodeEventBatchObject(fields map[string]json.RawMessage) (EventBatchV1, error) {
	if err := validateObjectFields(fields, eventBatchFields); err != nil {
		return EventBatchV1{}, err
	}

	var batch EventBatchV1
	var err error
	if batch.SchemaVersion, err = readString(fields, "schema_version"); err != nil {
		return EventBatchV1{}, err
	}
	if batch.SenderID, err = readString(fields, "sender_id"); err != nil {
		return EventBatchV1{}, err
	}
	if batch.SenderEpoch, err = readString(fields, "sender_epoch"); err != nil {
		return EventBatchV1{}, err
	}
	if batch.BatchID, err = readString(fields, "batch_id"); err != nil {
		return EventBatchV1{}, err
	}
	if batch.Sequence, err = readUint(fields, "sequence", 1, MaxSafeInteger); err != nil {
		return EventBatchV1{}, err
	}
	if batch.SentAt, err = readTimestamp(fields, "sent_at"); err != nil {
		return EventBatchV1{}, err
	}
	records, err := readRawArray(fields, "records")
	if err != nil {
		return EventBatchV1{}, err
	}
	if len(records) < 1 || len(records) > MaxEventBatchRecords {
		return EventBatchV1{}, fieldError("records", ErrorCardinality, "must contain between 1 and 100 records")
	}
	batch.Records = make([]EventRecordV1, len(records))
	for index := range records {
		record, err := DecodeEventRecordV1(records[index])
		if err != nil {
			return EventBatchV1{}, prefixError(recordField(index), err)
		}
		batch.Records[index] = record
	}
	if err := batch.Validate(); err != nil {
		return EventBatchV1{}, err
	}
	return batch, nil
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, fieldError("$", ErrorInvalidJSON, "must be valid JSON")
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return nil, fieldError("$", ErrorExpectedObject, "must be a JSON object")
	}

	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fieldError("$", ErrorInvalidJSON, "must be valid JSON")
		}
		name, ok := token.(string)
		if !ok {
			return nil, fieldError("$", ErrorInvalidJSON, "must contain string property names")
		}
		if _, exists := fields[name]; exists {
			return nil, fieldError("$", ErrorDuplicateField, "must not contain duplicate properties")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fieldError("$", ErrorInvalidJSON, "must be valid JSON")
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fieldError("$", ErrorInvalidJSON, "must be valid JSON")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fieldError("$", ErrorTrailingJSON, "must contain exactly one JSON value")
	}
	return fields, nil
}

func validateObjectFields(fields map[string]json.RawMessage, allowed map[string]struct{}) error {
	unknown := false
	privacyForbidden := false
	for name := range fields {
		if _, ok := allowed[name]; ok {
			continue
		}
		if isPrivacyFieldName(name) {
			privacyForbidden = true
			continue
		}
		unknown = true
	}
	if privacyForbidden {
		return fieldError("$", ErrorPrivacyForbidden, "payload contains a forbidden sensitive property")
	}
	if unknown {
		return fieldError("$", ErrorUnknownField, "payload contains an unknown property")
	}

	required := make([]string, 0, len(allowed))
	for name := range allowed {
		required = append(required, name)
	}
	sort.Strings(required)
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return fieldError(name, ErrorRequired, "field is required")
		}
	}
	return nil
}

func fieldSet(names ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(names))
	for _, name := range names {
		result[name] = struct{}{}
	}
	return result
}

func readString(fields map[string]json.RawMessage, name string) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", fieldError(name, ErrorRequired, "field is required")
	}
	value, err := decodeJSONString(raw)
	if err != nil {
		return "", prefixError(name, err)
	}
	return value, nil
}

func readNullableString(fields map[string]json.RawMessage, name string) (*string, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, fieldError(name, ErrorRequired, "field is required")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	value, err := decodeJSONString(raw)
	if err != nil {
		return nil, prefixError(name, err)
	}
	return &value, nil
}

func decodeJSONString(data []byte) (string, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return "", fieldError("$", ErrorInvalidType, "must be a JSON string")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return "", fieldError("$", ErrorInvalidType, "must be a JSON string")
	}
	return value, nil
}

func readTimestamp(fields map[string]json.RawMessage, name string) (Timestamp, error) {
	value, err := readString(fields, name)
	if err != nil {
		return Timestamp{}, err
	}
	timestamp, err := ParseTimestamp(value)
	if err != nil {
		return Timestamp{}, prefixError(name, err)
	}
	return timestamp, nil
}

func readMillisecondTimestamp(fields map[string]json.RawMessage, name string) (Timestamp, error) {
	value, err := readString(fields, name)
	if err != nil {
		return Timestamp{}, err
	}
	timestamp, err := ParseTimestamp(value)
	if err != nil {
		return Timestamp{}, prefixError(name, err)
	}
	if timestamp.Time().Format(coverageTimestampLayout) != value {
		return Timestamp{}, fieldError(name, ErrorInvalidFormat, "must be canonical UTC with exactly three fractional digits")
	}
	return timestamp, nil
}

func readNullableTimestamp(fields map[string]json.RawMessage, name string) (*Timestamp, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, fieldError(name, ErrorRequired, "field is required")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	value, err := decodeJSONString(raw)
	if err != nil {
		return nil, prefixError(name, err)
	}
	timestamp, err := ParseTimestamp(value)
	if err != nil {
		return nil, prefixError(name, err)
	}
	return &timestamp, nil
}

func readUint(fields map[string]json.RawMessage, name string, minimum, maximum uint64) (uint64, error) {
	raw, ok := fields[name]
	if !ok {
		return 0, fieldError(name, ErrorRequired, "field is required")
	}
	return decodeUint(raw, name, minimum, maximum)
}

func readNullableUint(fields map[string]json.RawMessage, name string, minimum, maximum uint64) (*uint64, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, fieldError(name, ErrorRequired, "field is required")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	value, err := decodeUint(raw, name, minimum, maximum)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func decodeUint(data []byte, name string, minimum, maximum uint64) (uint64, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return 0, fieldError(name, ErrorInvalidType, "must be an integer")
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return 0, fieldError(name, ErrorInvalidType, "must be an integer")
	}
	text := number.String()
	if strings.ContainsAny(text, ".eE") {
		return 0, fieldError(name, ErrorInvalidType, "must be an integer")
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, fieldError(name, ErrorOutOfRange, "must be an integer in the allowed range")
	}
	if value < minimum || value > maximum {
		return 0, fieldError(name, ErrorOutOfRange, "must be an integer in the allowed range")
	}
	return value, nil
}

func readRawArray(fields map[string]json.RawMessage, name string) ([]json.RawMessage, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, fieldError(name, ErrorRequired, "field is required")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fieldError(name, ErrorInvalidType, "must be an array")
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fieldError(name, ErrorInvalidType, "must be an array")
	}
	return values, nil
}

func isPrivacyFieldName(name string) bool {
	normalized := strings.ToLower(name)
	normalized = strings.NewReplacer("-", "", "_", "", ".", "").Replace(normalized)
	for _, marker := range []string{
		"path", "query", "body", "cookie", "authorization", "credential", "password",
		"username", "email", "token", "session", "headers", "requesttarget", "rawtarget",
		"useragent", "referrer", "referer", "forwarded", "url", "uri",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
