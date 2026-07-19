package events

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const validGatewayJSON = `{
  "schema_version":"gateway-http-v1",
  "event_id":"019b0000-0000-7000-8000-000000000101",
  "request_id":"019b0000-0000-7000-8000-000000000102",
  "trace_id":"019b0000-0000-7000-8000-000000000103",
  "idempotency_key":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "started_at":"2026-07-17T03:00:00.000Z",
  "completed_at":"2026-07-17T03:00:00.007Z",
  "source_ip":"203.0.113.20",
  "method":"POST",
  "protocol":"HTTP/1.1",
  "route_label":"login",
  "path_catalog_version":"path-catalog-v1",
  "suspicious_path_id":"none",
  "host":"app.example.test",
  "service_label":"demo-app",
  "status_code":401,
  "request_bytes":128,
  "response_bytes":431,
  "latency_ms":7
}`

const validAuthJSON = `{
  "schema_version":"auth-event-v1",
  "event_id":"019b0000-0000-7000-8000-000000000104",
  "gateway_request_id":"019b0000-0000-7000-8000-000000000102",
  "trace_id":"019b0000-0000-7000-8000-000000000103",
  "idempotency_key":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "occurred_at":"2026-07-17T03:00:00.006Z",
  "source_ip":"203.0.113.20",
  "service_label":"demo-app",
  "route_label":"login",
  "account_hash":"hmac-sha256:3333333333333333333333333333333333333333333333333333333333333333",
  "outcome":"failed"
}`

const validSourceHealthJSON = `{
  "schema_version":"source-health-v1",
  "event_id":"019b0000-0000-7000-8000-000000000120",
  "idempotency_key":"sha256:4444444444444444444444444444444444444444444444444444444444444444",
  "occurred_at":"2026-07-17T03:01:00.000Z",
  "source_id":"gateway-demo",
  "cause":"permanent_loss",
  "state":"lost",
  "affected_sender_epoch":"IiIiIiIiIiIiIiIiIiIiIg",
  "sequence_start":2,
  "sequence_end":4,
  "interval_start":"2026-07-17T03:00:00.000Z",
  "interval_end":"2026-07-17T03:01:00.000Z",
  "dropped_count":3,
  "detail_code":"known_range"
}`

const validSourceCoverageJSON = `{
  "schema_version":"source-coverage-v1",
  "event_id":"019b0000-0000-7000-8000-000000000130",
  "idempotency_key":"sha256:5555555555555555555555555555555555555555555555555555555555555555",
  "source_id":"gateway-demo",
  "affected_sender_epoch":"IiIiIiIiIiIiIiIiIiIiIg",
  "segment_id":"019b0000-0000-7000-8000-000000000131",
  "previous_coverage_digest":null,
  "coverage_start":"2026-07-17T03:00:00.000Z",
  "coverage_end":"2026-07-17T03:00:00.010Z",
  "covered_through_batch_id":"019b0000-0000-7000-8000-000000000400",
  "covered_through_sequence":1,
  "state":"complete"
}`

func TestCheckedSchemaPropertiesMatchWireTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		file     string
		expected map[string]struct{}
		wireType any
	}{
		{"gateway_http_v1.schema.json", gatewayHTTPFields, GatewayHTTPV1{}},
		{"auth_event_v1.schema.json", authEventFields, AuthEventV1{}},
		{"source_health_v1.schema.json", sourceHealthFields, SourceHealthV1{}},
		{"source_coverage_v1.schema.json", sourceCoverageFields, SourceCoverageV1{}},
		{"event_batch_v1.schema.json", eventBatchFields, EventBatchV1{}},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.file, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "contracts", "events", testCase.file))
			if err != nil {
				t.Fatal(err)
			}
			var schema struct {
				AdditionalProperties bool                       `json:"additionalProperties"`
				Properties           map[string]json.RawMessage `json:"properties"`
				Required             []string                   `json:"required"`
			}
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatal(err)
			}
			if schema.AdditionalProperties {
				t.Fatal("event schema must reject additional properties")
			}
			actualProperties := make(map[string]struct{}, len(schema.Properties))
			for name := range schema.Properties {
				actualProperties[name] = struct{}{}
			}
			if !reflect.DeepEqual(actualProperties, testCase.expected) {
				t.Fatalf("property set mismatch: got %v want %v", sortedKeys(actualProperties), sortedKeys(testCase.expected))
			}
			wireProperties := jsonTags(reflect.TypeOf(testCase.wireType))
			if !reflect.DeepEqual(wireProperties, testCase.expected) {
				t.Fatalf("wire field mismatch: got %v want %v", sortedKeys(wireProperties), sortedKeys(testCase.expected))
			}
			required := make(map[string]struct{}, len(schema.Required))
			for _, name := range schema.Required {
				required[name] = struct{}{}
			}
			if !reflect.DeepEqual(required, testCase.expected) {
				t.Fatalf("required set mismatch: got %v want %v", sortedKeys(required), sortedKeys(testCase.expected))
			}
		})
	}
}

func TestCheckedSchemaEnumsMatchWireConstants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		file     string
		property string
		expected []string
	}{
		{"gateway_http_v1.schema.json", "suspicious_path_id", []string{"none", "admin_console", "env_file", "git_config", "wp_admin", "phpmyadmin", "server_status", "actuator_env", "backup_archive"}},
		{"auth_event_v1.schema.json", "outcome", []string{"failed", "succeeded"}},
		{"source_health_v1.schema.json", "cause", []string{"queue_overflow", "delivery_outage", "rejected_batch", "sequence_gap", "permanent_loss", "unclean_restart", "unknown_loss", "recovered"}},
		{"source_health_v1.schema.json", "state", []string{"degraded", "lost", "recovered"}},
		{"source_health_v1.schema.json", "detail_code", []string{"none", "known_range", "unknown_range", "receiver_rejected", "sender_restart", "delivery_restored"}},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.file+"/"+testCase.property, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "contracts", "events", testCase.file))
			if err != nil {
				t.Fatal(err)
			}
			var schema struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			}
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatal(err)
			}
			actual := append([]string(nil), schema.Properties[testCase.property].Enum...)
			expected := append([]string(nil), testCase.expected...)
			sort.Strings(actual)
			sort.Strings(expected)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("enum mismatch: got %v want %v", actual, expected)
			}
		})
	}
}

func TestFixtureRecordsDecodeAndRoundTrip(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "contracts", "fixtures", "demo_history_dataset_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Records) != 4 {
		t.Fatalf("unexpected fixture record count: %d", len(fixture.Records))
	}

	for index, raw := range fixture.Records {
		record, err := DecodeEventRecordV1(raw)
		if err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("record %d marshal: %v", index, err)
		}
		roundTripped, err := DecodeEventRecordV1(encoded)
		if err != nil {
			t.Fatalf("record %d round trip: %v", index, err)
		}
		if !reflect.DeepEqual(record, roundTripped) {
			t.Fatalf("record %d changed after round trip", index)
		}
	}
}

func TestPublicEventBatchVectorsDecodeAndRoundTrip(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "contracts", "vectors", "contract_vectors_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Vectors struct {
			EventBatch struct {
				PositiveCases []struct {
					CaseID        string `json:"case_id"`
					RawBodyB64URL string `json:"raw_body_b64url"`
				} `json:"positive_cases"`
			} `json:"event_batch_hmac_v1"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if len(bundle.Vectors.EventBatch.PositiveCases) != 2 {
		t.Fatalf("unexpected vector count: %d", len(bundle.Vectors.EventBatch.PositiveCases))
	}
	for _, vector := range bundle.Vectors.EventBatch.PositiveCases {
		vector := vector
		t.Run(vector.CaseID, func(t *testing.T) {
			t.Parallel()
			raw, err := base64.RawURLEncoding.Strict().DecodeString(vector.RawBodyB64URL)
			if err != nil {
				t.Fatal(err)
			}
			batch, err := DecodeEventBatchV1(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(batch.Records) != 1 || batch.Records[0].SchemaVersion() == "" {
				t.Fatal("vector did not produce one typed event")
			}
			encoded, err := json.Marshal(batch)
			if err != nil {
				t.Fatal(err)
			}
			roundTripped, err := DecodeEventBatchV1(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(batch, roundTripped) {
				t.Fatal("batch changed after round trip")
			}
		})
	}
}

func TestStandaloneExamplesRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		raw    string
		decode func([]byte) (any, error)
	}{
		{"gateway", validGatewayJSON, func(data []byte) (any, error) { return DecodeGatewayHTTPV1(data) }},
		{"auth", validAuthJSON, func(data []byte) (any, error) { return DecodeAuthEventV1(data) }},
		{"source-health", validSourceHealthJSON, func(data []byte) (any, error) { return DecodeSourceHealthV1(data) }},
		{"source-coverage", validSourceCoverageJSON, func(data []byte) (any, error) { return DecodeSourceCoverageV1(data) }},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			decoded, err := testCase.decode([]byte(testCase.raw))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			roundTripped, err := testCase.decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, roundTripped) {
				t.Fatal("value changed after round trip")
			}
		})
	}
}

func TestBatchAcceptsEverySchemaRecordVariant(t *testing.T) {
	t.Parallel()

	raw := makeBatch(strings.Join([]string{validGatewayJSON, validAuthJSON, validSourceHealthJSON, validSourceCoverageJSON}, ","))
	batch, err := DecodeEventBatchV1([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(batch.Records))
	for index := range batch.Records {
		got[index] = batch.Records[index].SchemaVersion()
	}
	want := []string{GatewayHTTPV1Schema, AuthEventV1Schema, SourceHealthV1Schema, SourceCoverageV1Schema}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("record variants: got %v want %v", got, want)
	}
}

func TestSourceCoverageCanonicalDigestAndBatchBinding(t *testing.T) {
	t.Parallel()
	event, err := DecodeSourceCoverageV1([]byte(validSourceCoverageJSON))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := event.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"affected_sender_epoch":"IiIiIiIiIiIiIiIiIiIiIg","coverage_end":"2026-07-17T03:00:00.010Z","coverage_start":"2026-07-17T03:00:00.000Z","covered_through_batch_id":"019b0000-0000-7000-8000-000000000400","covered_through_sequence":1,"event_id":"019b0000-0000-7000-8000-000000000130","idempotency_key":"sha256:5555555555555555555555555555555555555555555555555555555555555555","previous_coverage_digest":null,"schema_version":"source-coverage-v1","segment_id":"019b0000-0000-7000-8000-000000000131","source_id":"gateway-demo","state":"complete"}`
	if string(canonical) != want {
		t.Fatalf("canonical = %s", canonical)
	}
	digest, err := event.Digest()
	if err != nil || digest != "sha256:25907cec9fcc59ffdd4a587f627bac9ba95900d7bf9f13fd8de1dea3bb98ab14" {
		t.Fatalf("digest=%q err=%v", digest, err)
	}

	notFinal := makeBatch(validSourceCoverageJSON + "," + validGatewayJSON)
	_, err = DecodeEventBatchV1([]byte(notFinal))
	assertFieldError(t, err, "records", ErrorInvariant)
	mismatched := replace(makeBatch(validSourceCoverageJSON), `"covered_through_sequence":1`, `"covered_through_sequence":2`)
	_, err = DecodeEventBatchV1([]byte(mismatched))
	assertFieldError(t, err, "records[0]", ErrorInvariant)
}

func TestNewSourceCoverageRejectsSilentTimestampRepair(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 7, 18, 1, 2, 3, 1, time.UTC)
	_, err := NewSourceCoverageV1(
		"gateway-demo", "IiIiIiIiIiIiIiIiIiIiIg",
		CoverageSegmentID("gateway-demo", "IiIiIiIiIiIiIiIiIiIiIg", "test"), nil,
		start, start.Add(time.Millisecond),
		"019b0000-0000-7000-8000-000000000400", 1,
	)
	if err == nil {
		t.Fatal("sub-millisecond input was silently repaired")
	}
}

func TestSourceCoverageStrictNegativeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, raw, field string
		code             ErrorCode
	}{
		{"missing-milliseconds", replace(validSourceCoverageJSON, ".010Z", "Z"), "coverage_end", ErrorInvalidFormat},
		{"short-milliseconds", replace(validSourceCoverageJSON, ".010Z", ".01Z"), "coverage_end", ErrorInvalidFormat},
		{"sub-millisecond", replace(validSourceCoverageJSON, ".010Z", ".010001Z"), "coverage_end", ErrorInvalidFormat},
		{"time-order", replace(validSourceCoverageJSON, "03:00:00.010Z", "02:59:59.000Z"), "coverage_end", ErrorInvariant},
		{"state", replace(validSourceCoverageJSON, `"state":"complete"`, `"state":"healthy"`), "state", ErrorInvalidConstant},
		{"previous-digest", replace(validSourceCoverageJSON, `"previous_coverage_digest":null`, `"previous_coverage_digest":"bad"`), "previous_coverage_digest", ErrorInvalidFormat},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeSourceCoverageV1([]byte(test.raw))
			assertFieldError(t, err, test.field, test.code)
		})
	}
}

func TestGatewayStrictNegativeCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		raw   string
		field string
		code  ErrorCode
	}{
		{"invalid-json", `{`, "$", ErrorInvalidJSON},
		{"not-object", `[]`, "$", ErrorExpectedObject},
		{"trailing-json", validGatewayJSON + `{}`, "$", ErrorTrailingJSON},
		{"duplicate-field", replace(validGatewayJSON, `"method":"POST"`, `"method":"POST","method":"GET"`), "$", ErrorDuplicateField},
		{"missing-field", replace(validGatewayJSON, `  "method":"POST",`+"\n", ""), "method", ErrorRequired},
		{"unknown-field", appendProperty(validGatewayJSON, `"future_field":true`), "$", ErrorUnknownField},
		{"privacy-path", appendProperty(validGatewayJSON, `"exact_path":"/private/reset"`), "$", ErrorPrivacyForbidden},
		{"null-method", replace(validGatewayJSON, `"method":"POST"`, `"method":null`), "method", ErrorInvalidType},
		{"schema", replace(validGatewayJSON, GatewayHTTPV1Schema, "gateway-http-v2"), "schema_version", ErrorInvalidConstant},
		{"uuid", replace(validGatewayJSON, "019b0000-0000-7000-8000-000000000101", "019B0000-0000-7000-8000-000000000101"), "event_id", ErrorInvalidFormat},
		{"non-utc", replace(validGatewayJSON, "2026-07-17T03:00:00.000Z", "2026-07-17T03:00:00.000+00:00"), "started_at", ErrorInvalidFormat},
		{"time-order", replace(validGatewayJSON, "2026-07-17T03:00:00.007Z", "2026-07-17T02:59:59.000Z"), "completed_at", ErrorInvariant},
		{"ipv6", replace(validGatewayJSON, "203.0.113.20", "2001:db8::1"), "source_ip", ErrorInvalidFormat},
		{"method", replace(validGatewayJSON, `"method":"POST"`, `"method":"post"`), "method", ErrorInvalidFormat},
		{"protocol", replace(validGatewayJSON, "HTTP/1.1", "HTTP/2"), "protocol", ErrorInvalidConstant},
		{"suspicious-path", replace(validGatewayJSON, `"suspicious_path_id":"none"`, `"suspicious_path_id":"/admin"`), "suspicious_path_id", ErrorInvalidEnum},
		{"host", replace(validGatewayJSON, "app.example.test", "App.Example.Test"), "host", ErrorInvalidFormat},
		{"status", replace(validGatewayJSON, `"status_code":401`, `"status_code":99`), "status_code", ErrorOutOfRange},
		{"request-bytes", replace(validGatewayJSON, `"request_bytes":128`, `"request_bytes":10485761`), "request_bytes", ErrorOutOfRange},
		{"response-bytes", replace(validGatewayJSON, `"response_bytes":431`, `"response_bytes":9007199254740992`), "response_bytes", ErrorOutOfRange},
		{"latency", replace(validGatewayJSON, `"latency_ms":7`, `"latency_ms":30001`), "latency_ms", ErrorOutOfRange},
		{"fractional-integer", replace(validGatewayJSON, `"status_code":401`, `"status_code":401.0`), "status_code", ErrorInvalidType},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeGatewayHTTPV1([]byte(testCase.raw))
			assertFieldError(t, err, testCase.field, testCase.code)
		})
	}
}

func TestAuthStrictNegativeCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		raw   string
		field string
		code  ErrorCode
	}{
		{"account-hash", replace(validAuthJSON, "hmac-sha256:3333333333333333333333333333333333333333333333333333333333333333", "sha256:3333333333333333333333333333333333333333333333333333333333333333"), "account_hash", ErrorInvalidFormat},
		{"outcome", replace(validAuthJSON, `"outcome":"failed"`, `"outcome":"locked"`), "outcome", ErrorInvalidEnum},
		{"source-ip", replace(validAuthJSON, "203.0.113.20", "203.0.113.020"), "source_ip", ErrorInvalidFormat},
		{"route-label", replace(validAuthJSON, `"route_label":"login"`, `"route_label":"/login"`), "route_label", ErrorInvalidFormat},
		{"privacy-credential", appendProperty(validAuthJSON, `"password":"do-not-retain"`), "$", ErrorPrivacyForbidden},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeAuthEventV1([]byte(testCase.raw))
			assertFieldError(t, err, testCase.field, testCase.code)
		})
	}
}

func TestSourceHealthStrictNegativeCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		raw   string
		field string
		code  ErrorCode
	}{
		{"source-id-ascii", replace(validSourceHealthJSON, "gateway-demo", "Gateway-démo"), "source_id", ErrorInvalidFormat},
		{"old-cause-name", replace(validSourceHealthJSON, "permanent_loss", "clean_shutdown_loss"), "cause", ErrorInvalidEnum},
		{"state", replace(validSourceHealthJSON, `"state":"lost"`, `"state":"closed"`), "state", ErrorInvalidEnum},
		{"epoch", replace(validSourceHealthJSON, "IiIiIiIiIiIiIiIiIiIiIg", "invalid"), "affected_sender_epoch", ErrorInvalidFormat},
		{"sequence-zero", replace(validSourceHealthJSON, `"sequence_start":2`, `"sequence_start":0`), "sequence_start", ErrorOutOfRange},
		{"sequence-order", replace(validSourceHealthJSON, `"sequence_end":4`, `"sequence_end":1`), "sequence_end", ErrorInvariant},
		{"interval-order", replace(validSourceHealthJSON, `"interval_end":"2026-07-17T03:01:00.000Z"`, `"interval_end":"2026-07-17T02:59:00.000Z"`), "interval_end", ErrorInvariant},
		{"detail", replace(validSourceHealthJSON, "known_range", "raw_details"), "detail_code", ErrorInvalidEnum},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeSourceHealthV1([]byte(testCase.raw))
			assertFieldError(t, err, testCase.field, testCase.code)
		})
	}
}

func TestSourceHealthNullableFields(t *testing.T) {
	t.Parallel()

	raw := replace(validSourceHealthJSON,
		`"sequence_start":2,`+"\n"+`  "sequence_end":4,`+"\n"+`  "interval_start":"2026-07-17T03:00:00.000Z",`+"\n"+`  "interval_end":"2026-07-17T03:01:00.000Z",`,
		`"sequence_start":null,`+"\n"+`  "sequence_end":null,`+"\n"+`  "interval_start":null,`+"\n"+`  "interval_end":null,`)
	event, err := DecodeSourceHealthV1([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if event.SequenceStart != nil || event.SequenceEnd != nil || event.IntervalStart != nil || event.IntervalEnd != nil {
		t.Fatal("nullable source-health fields were not preserved")
	}
}

func TestEventBatchStrictNegativeCases(t *testing.T) {
	t.Parallel()

	validBatch := makeBatch(validGatewayJSON)
	cases := []struct {
		name  string
		raw   string
		field string
		code  ErrorCode
	}{
		{"sender-ascii", replace(validBatch, "gateway-demo", "Gateway-demo"), "sender_id", ErrorInvalidFormat},
		{"epoch", replace(validBatch, "IiIiIiIiIiIiIiIiIiIiIg", "short"), "sender_epoch", ErrorInvalidFormat},
		{"sequence-zero", replace(validBatch, `"sequence":1`, `"sequence":0`), "sequence", ErrorOutOfRange},
		{"sequence-too-large", replace(validBatch, `"sequence":1`, `"sequence":9007199254740992`), "sequence", ErrorOutOfRange},
		{"records-empty", replace(validBatch, `"records":[`+validGatewayJSON+`]`, `"records":[]`), "records", ErrorCardinality},
		{"record-schema", replace(validBatch, GatewayHTTPV1Schema, "future-event-v1"), "records[0].schema_version", ErrorInvalidEnum},
		{"record-null", replace(validBatch, `"records":[`+validGatewayJSON+`]`, `"records":[null]`), "records[0]", ErrorExpectedObject},
		{"record-privacy", replace(validBatch, validGatewayJSON, appendProperty(validGatewayJSON, `"query":"secret=true"`)), "records[0]", ErrorPrivacyForbidden},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeEventBatchV1([]byte(testCase.raw))
			assertFieldError(t, err, testCase.field, testCase.code)
		})
	}

	tooMany := make([]string, MaxEventBatchRecords+1)
	for index := range tooMany {
		tooMany[index] = validGatewayJSON
	}
	_, err := DecodeEventBatchV1([]byte(makeBatch(strings.Join(tooMany, ","))))
	assertFieldError(t, err, "records", ErrorCardinality)

	oversized := append([]byte(validBatch), bytes.Repeat([]byte(" "), MaxEventBatchBodyBytes)...)
	_, err = DecodeEventBatchV1(oversized)
	assertFieldError(t, err, "$", ErrorTooLarge)
}

func TestJSONUnmarshalUsesStrictDecoder(t *testing.T) {
	t.Parallel()

	var event GatewayHTTPV1
	err := json.Unmarshal([]byte(appendProperty(validGatewayJSON, `"body":"sensitive"`)), &event)
	assertFieldError(t, err, "$", ErrorPrivacyForbidden)
}

func TestErrorsDoNotRetainSensitiveFieldsOrValues(t *testing.T) {
	t.Parallel()

	const sensitiveField = "authorization_header"
	const sensitiveValue = "Bearer should-never-appear"
	raw := appendProperty(validGatewayJSON, fmt.Sprintf("%q:%q", sensitiveField, sensitiveValue))
	_, err := DecodeGatewayHTTPV1([]byte(raw))
	assertFieldError(t, err, "$", ErrorPrivacyForbidden)
	for _, rendered := range []string{err.Error(), fmt.Sprintf("%#v", err)} {
		if strings.Contains(rendered, sensitiveField) || strings.Contains(rendered, sensitiveValue) {
			t.Fatalf("error retained sensitive input: %s", rendered)
		}
	}

	const unknownField = "customer_supplied_arbitrary_name"
	_, err = DecodeGatewayHTTPV1([]byte(appendProperty(validGatewayJSON, `"`+unknownField+`":true`)))
	assertFieldError(t, err, "$", ErrorUnknownField)
	if strings.Contains(err.Error(), unknownField) || strings.Contains(fmt.Sprintf("%#v", err), unknownField) {
		t.Fatal("error retained an unknown property name")
	}
}

func TestMarshalRejectsInvalidConstructedValues(t *testing.T) {
	t.Parallel()

	gateway, err := DecodeGatewayHTTPV1([]byte(validGatewayJSON))
	if err != nil {
		t.Fatal(err)
	}
	gateway.Method = "get"
	if _, err := json.Marshal(gateway); err == nil {
		t.Fatal("invalid gateway event marshaled successfully")
	}

	auth, err := DecodeAuthEventV1([]byte(validAuthJSON))
	if err != nil {
		t.Fatal(err)
	}
	record := EventRecordV1{GatewayHTTP: &gateway, AuthEvent: &auth}
	if _, err := json.Marshal(record); err == nil {
		t.Fatal("multi-variant record marshaled successfully")
	}
}

func assertFieldError(t *testing.T, err error, field string, code ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error for %s", code, field)
	}
	var fieldErr *FieldError
	if !errors.As(err, &fieldErr) {
		t.Fatalf("expected FieldError, got %T: %v", err, err)
	}
	if fieldErr.Field != field || fieldErr.Code != code {
		t.Fatalf("got field=%q code=%q, want field=%q code=%q", fieldErr.Field, fieldErr.Code, field, code)
	}
}

func appendProperty(object, property string) string {
	return strings.TrimSuffix(object, "}") + "," + property + "}"
}

func replace(input, old, replacement string) string {
	if !strings.Contains(input, old) {
		panic("test mutation target not found")
	}
	return strings.Replace(input, old, replacement, 1)
}

func makeBatch(records string) string {
	return `{
  "schema_version":"event-batch-v1",
  "sender_id":"gateway-demo",
  "sender_epoch":"IiIiIiIiIiIiIiIiIiIiIg",
  "batch_id":"019b0000-0000-7000-8000-000000000400",
  "sequence":1,
  "sent_at":"2026-07-17T03:00:00.010Z",
  "records":[` + records + `]
}`
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func jsonTags(wireType reflect.Type) map[string]struct{} {
	result := make(map[string]struct{}, wireType.NumField())
	for index := 0; index < wireType.NumField(); index++ {
		tag := strings.Split(wireType.Field(index).Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			result[tag] = struct{}{}
		}
	}
	return result
}
