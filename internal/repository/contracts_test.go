package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/api"
	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
)

func TestPrepareBatchRequiresExactAuthenticatedRawBodySize(t *testing.T) {
	now := time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC)
	authenticated := validAuthenticatedBatch(t, now)
	authenticated.RawBodySize = 0

	_, err := prepareBatch(ingestion.GatewayEventsPath, authenticated, now)
	if !errors.Is(err, api.ErrBatchRejected) {
		t.Fatalf("prepareBatch() error = %v, want ErrBatchRejected", err)
	}
	if !errors.Is(err, ErrExactRawBodySizeRequired) {
		t.Fatalf("prepareBatch() error = %v, want ErrExactRawBodySizeRequired", err)
	}
}

func TestPrepareBatchRejectsEndpointRecordMismatch(t *testing.T) {
	now := time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC)
	authenticated := validAuthenticatedBatch(t, now)

	_, err := prepareBatch(ingestion.AuthEventsPath, authenticated, now)
	if !errors.Is(err, api.ErrBatchRejected) {
		t.Fatalf("prepareBatch() error = %v, want ErrBatchRejected", err)
	}
}

func TestPrepareBatchRejectsInvalidAuthenticatedKeyIdentity(t *testing.T) {
	now := time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC)
	authenticated := validAuthenticatedBatch(t, now)
	authenticated.KeyID = "INVALID KEY"
	_, err := prepareBatch(ingestion.GatewayEventsPath, authenticated, now)
	if !errors.Is(err, api.ErrBatchRejected) {
		t.Fatalf("prepareBatch() error = %v, want ErrBatchRejected", err)
	}
}

func TestRecordTrustUsesInclusiveSkewBoundaries(t *testing.T) {
	receivedAt := time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC)
	tests := []struct {
		name  string
		start time.Time
		end   time.Time
		state string
	}{
		{name: "past boundary", start: receivedAt.Add(-recordPastSkew), end: receivedAt, state: "trusted"},
		{name: "future boundary", start: receivedAt, end: receivedAt.Add(recordFutureSkew), state: "trusted"},
		{name: "before past boundary", start: receivedAt.Add(-recordPastSkew - time.Nanosecond), end: receivedAt, state: "untrusted"},
		{name: "after future boundary", start: receivedAt, end: receivedAt.Add(recordFutureSkew + time.Nanosecond), state: "untrusted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			start := mustTimestamp(t, test.start)
			end := mustTimestamp(t, test.end)
			record := events.GatewayHTTPRecord(events.GatewayHTTPV1{StartedAt: start, CompletedAt: end})
			state, reason := recordTrust(record, receivedAt)
			if state != test.state {
				t.Fatalf("recordTrust() state = %q, want %q", state, test.state)
			}
			if test.state == "trusted" && reason != "none" {
				t.Fatalf("recordTrust() reason = %q, want none", reason)
			}
			if test.state == "untrusted" && reason != "timestamp_skew" {
				t.Fatalf("recordTrust() reason = %q, want timestamp_skew", reason)
			}
		})
	}
}

func TestRecordTrustDoesNotApplyTransportSkewToHistoricalHealthInterval(t *testing.T) {
	receivedAt := time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC)
	occurredAt := mustTimestamp(t, receivedAt)
	intervalStart := mustTimestamp(t, receivedAt.Add(-24*time.Hour))
	intervalEnd := mustTimestamp(t, receivedAt.Add(-23*time.Hour))
	record := events.SourceHealthRecord(events.SourceHealthV1{
		OccurredAt:    occurredAt,
		IntervalStart: &intervalStart,
		IntervalEnd:   &intervalEnd,
	})

	state, reason := recordTrust(record, receivedAt)
	if state != "trusted" || reason != "none" {
		t.Fatalf("recordTrust() = (%q, %q), want (trusted, none)", state, reason)
	}
}

func TestSourceCoverageEndpointAndTimestampTrust(t *testing.T) {
	receivedAt := time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC)
	batch := validAuthenticatedBatch(t, receivedAt).Batch
	coverage, err := events.NewSourceCoverageV1(
		batch.SenderID, batch.SenderEpoch,
		events.CoverageSegmentID(batch.SenderID, batch.SenderEpoch, "test"), nil,
		receivedAt.Add(-recordPastSkew), receivedAt.Add(recordFutureSkew),
		batch.BatchID, batch.Sequence,
	)
	if err != nil {
		t.Fatal(err)
	}
	batch.Records = append(batch.Records, events.SourceCoverageRecord(coverage))
	if !recordsMatchEndpoint(ingestion.GatewayEventsPath, batch) {
		t.Fatal("Gateway endpoint rejected its source coverage marker")
	}
	if recordsMatchEndpoint(ingestion.AuthEventsPath, batch) {
		t.Fatal("auth endpoint accepted a Gateway domain record")
	}
	state, reason := recordTrust(batch.Records[len(batch.Records)-1], receivedAt)
	if state != "trusted" || reason != "none" {
		t.Fatalf("coverage boundary trust = (%q, %q)", state, reason)
	}
	coverage.CoverageEnd = mustTimestamp(t, receivedAt.Add(recordFutureSkew+time.Millisecond))
	state, reason = recordTrust(events.SourceCoverageRecord(coverage), receivedAt)
	if state != "untrusted" || reason != "timestamp_skew" {
		t.Fatalf("coverage skew trust = (%q, %q)", state, reason)
	}
}

func TestBatchOutboxIdentityIsStableAndBatchBound(t *testing.T) {
	batch := validAuthenticatedBatch(t, time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC)).Batch
	first := batchOutboxIdentity(batch)
	second := batchOutboxIdentity(batch)
	if first != second {
		t.Fatalf("batchOutboxIdentity() changed: %#v != %#v", first, second)
	}
	if len(first.jobID) != 36 || first.jobID[14] != '8' {
		t.Fatalf("job ID %q is not a UUIDv8-shaped identifier", first.jobID)
	}
	if !strings.HasPrefix(first.idempotencyKey, "sha256:") || len(first.idempotencyKey) != 71 {
		t.Fatalf("idempotency key %q is not a sha256 digest", first.idempotencyKey)
	}

	batch.Sequence++
	if changed := batchOutboxIdentity(batch); changed != first {
		t.Fatalf("identity unexpectedly depends on mutable sequence: %#v != %#v", changed, first)
	}
	batch.BatchID = "00000000-0000-4000-8000-000000000099"
	if changed := batchOutboxIdentity(batch); changed == first {
		t.Fatal("identity did not change with batch identity")
	}
}

func TestClassifyWriteErrorDoesNotExposeDatabaseDetails(t *testing.T) {
	tests := []struct {
		name          string
		pgError       *pgconn.PgError
		batchIdentity bool
		want          error
	}{
		{
			name:    "replay",
			pgError: &pgconn.PgError{Code: "23505", ConstraintName: "ingest_replay_nonces_pkey", Message: "secret nonce"},
			want:    api.ErrBatchRejected,
		},
		{
			name:          "batch identity",
			pgError:       &pgconn.PgError{Code: "23505", ConstraintName: "unexpected_name", Message: "private batch"},
			batchIdentity: true,
			want:          api.ErrBatchConflict,
		},
		{
			name:    "typed check",
			pgError: &pgconn.PgError{Code: "23514", ConstraintName: "gateway_event_time_order", Message: "private event"},
			want:    api.ErrBatchRejected,
		},
		{
			name:    "database unavailable",
			pgError: &pgconn.PgError{Code: "08006", Message: "internal address"},
			want:    api.ErrStoreUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := classifyWriteError(context.Background(), test.pgError, test.batchIdentity)
			if err != test.want {
				t.Fatalf("classifyWriteError() = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), test.pgError.Message) {
				t.Fatalf("classified error leaked database detail: %v", err)
			}
		})
	}
}

func validAuthenticatedBatch(t *testing.T, now time.Time) ingestion.AuthenticatedBatch {
	t.Helper()
	startedAt := mustTimestamp(t, now.Add(-time.Second))
	completedAt := mustTimestamp(t, now)
	sentAt := mustTimestamp(t, now)
	return ingestion.AuthenticatedBatch{
		Batch: events.EventBatchV1{
			SchemaVersion: events.EventBatchV1Schema,
			SenderID:      "gateway.unit",
			SenderEpoch:   "AAAAAAAAAAAAAAAAAAAAAA",
			BatchID:       "00000000-0000-4000-8000-000000000001",
			Sequence:      1,
			SentAt:        sentAt,
			Records: []events.EventRecordV1{events.GatewayHTTPRecord(events.GatewayHTTPV1{
				SchemaVersion:      events.GatewayHTTPV1Schema,
				EventID:            "00000000-0000-4000-8000-000000000002",
				RequestID:          "00000000-0000-4000-8000-000000000003",
				TraceID:            "00000000-0000-4000-8000-000000000004",
				IdempotencyKey:     digestForTest(1),
				StartedAt:          startedAt,
				CompletedAt:        completedAt,
				SourceIP:           "192.0.2.10",
				Method:             "GET",
				Protocol:           "HTTP/1.1",
				RouteLabel:         "unknown",
				PathCatalogVersion: events.PathCatalogV1,
				SuspiciousPathID:   events.SuspiciousPathNone,
				Host:               "example.test",
				ServiceLabel:       "demo",
				StatusCode:         200,
				RequestBytes:       0,
				ResponseBytes:      10,
				LatencyMS:          1,
			})},
		},
		BodyDigest:      digestForTest(2),
		RawBodySize:     100,
		AuthenticatedAt: now,
	}
}

func mustTimestamp(t *testing.T, value time.Time) events.Timestamp {
	t.Helper()
	timestamp, err := events.NewTimestamp(value.UTC())
	if err != nil {
		t.Fatalf("events.NewTimestamp() error = %v", err)
	}
	return timestamp
}

func digestForTest(value int) string {
	return "sha256:" + strings.Repeat("0", 63) + string(rune('0'+value))
}
