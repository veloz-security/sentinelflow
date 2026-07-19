package eventsender

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
	"github.com/devwooops/sentinelflow/internal/observability"
)

func renderSenderMetrics(t *testing.T, metrics *observability.Metrics) string {
	t.Helper()
	var output strings.Builder
	if _, err := metrics.WriteOpenMetrics(&output); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func acknowledgeEventBatch(t *testing.T, writer http.ResponseWriter, request *http.Request) {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Errorf("read event batch: %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	var envelope events.EventBatchV1
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Validate() != nil {
		t.Errorf("invalid event batch: %v", err)
		writer.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	digest := sha256.Sum256(body)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(writer).Encode(acknowledgement{
		Status:      "accepted",
		SenderID:    envelope.SenderID,
		SenderEpoch: envelope.SenderEpoch,
		BatchID:     envelope.BatchID,
		Sequence:    envelope.Sequence,
		BodyDigest:  "sha256:" + hex.EncodeToString(digest[:]),
	})
}

func TestSenderMetricsTrackRetryRecoveryBacklogAndCheckpoint(t *testing.T) {
	metrics := observability.New(observability.Config{})
	var attempts atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if attempts.Add(1) == 1 {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		acknowledgeEventBatch(t, writer, request)
	}))
	defer server.Close()

	key := bytes.Repeat([]byte{0x61}, 32)
	config := baseConfig(server.URL+ingestion.GatewayEventsPath, filepath.Join(t.TempDir(), "sender.json"), key)
	config.BatchSize = 1
	config.FlushInterval = time.Second
	config.Metrics = metrics
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if result := sender.TryEnqueue(testEvent(t, 301)); result != events.EnqueueAccepted {
		t.Fatalf("enqueue = %s", result)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := sender.Close(ctx); err != nil {
		t.Fatal(err)
	}

	output := renderSenderMetrics(t, metrics)
	for _, expected := range []string{
		`sentinelflow_event_queue_depth 0`,
		`sentinelflow_event_queue_capacity 4`,
		`sentinelflow_event_enqueue_total{outcome="accepted"} 1`,
		`sentinelflow_event_enqueue_total{outcome="degraded"} 0`,
		`sentinelflow_event_enqueue_total{outcome="dropped"} 0`,
		`sentinelflow_event_batch_attempts_total{outcome="accepted"} 2`,
		`sentinelflow_event_batch_attempts_total{outcome="retryable_error"} 1`,
		`sentinelflow_event_batch_errors_total{reason="response"} 1`,
		`sentinelflow_event_batch_retries_total 1`,
		`sentinelflow_event_sender_degraded 0`,
		`sentinelflow_event_checkpoint_operations_total{operation="load",outcome="missing"} 1`,
		`sentinelflow_event_checkpoint_operations_total{operation="store",outcome="success"} 4`,
		`sentinelflow_event_last_acknowledged_sequence 2`,
	} {
		if !strings.Contains(output, expected+"\n") {
			t.Fatalf("missing exact sender metric %q in:\n%s", expected, output)
		}
	}
	for _, prohibited := range []string{"203.0.113.20", "app.example.test", ingestion.GatewayEventsPath, "gateway-01"} {
		if strings.Contains(output, prohibited) {
			t.Fatalf("sender metrics exposed value %q", prohibited)
		}
	}
}

func TestSenderMetricsExposeQueueOverflowWithoutBlocking(t *testing.T) {
	metrics := observability.New(observability.Config{})
	sender := &Sender{
		config: Config{QueueCapacity: 1, Metrics: metrics},
		queue:  make(chan events.EventRecordV1, 1),
	}
	if result := sender.TryEnqueue(testEvent(t, 401)); result != events.EnqueueAccepted {
		t.Fatalf("first enqueue = %s", result)
	}
	startedAt := time.Now()
	if result := sender.TryEnqueue(testEvent(t, 402)); result != events.EnqueueDropped {
		t.Fatalf("overflow enqueue = %s", result)
	}
	if elapsed := time.Since(startedAt); elapsed > 50*time.Millisecond {
		t.Fatalf("bounded enqueue blocked for %s", elapsed)
	}

	output := renderSenderMetrics(t, metrics)
	for _, expected := range []string{
		`sentinelflow_event_queue_depth 1`,
		`sentinelflow_event_queue_capacity 1`,
		`sentinelflow_event_enqueue_total{outcome="accepted"} 1`,
		`sentinelflow_event_enqueue_total{outcome="dropped"} 1`,
		`sentinelflow_event_dropped_total 1`,
		`sentinelflow_event_sender_degraded 1`,
		`sentinelflow_event_sequence_gaps_total{cause="queue_overflow"} 1`,
		`sentinelflow_event_gap_records_total{cause="queue_overflow"} 1`,
	} {
		if !strings.Contains(output, expected+"\n") {
			t.Fatalf("missing exact overflow metric %q", expected)
		}
	}
}

func TestSenderMetricsExposeUncleanRestartGap(t *testing.T) {
	metrics := observability.New(observability.Config{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		acknowledgeEventBatch(t, writer, request)
	}))
	defer server.Close()

	checkpointPath := filepath.Join(t.TempDir(), "sender.json")
	state := checkpoint{
		SenderID:                   "gateway-01",
		EndpointPath:               ingestion.GatewayEventsPath,
		SenderEpoch:                "AAAAAAAAAAAAAAAAAAAAAA",
		LastAcknowledgedSequence:   7,
		LastAcknowledgedBodyDigest: "sha256:" + strings.Repeat("a", 64),
		CleanShutdown:              false,
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteCheckpoint(checkpointPath, append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}

	config := baseConfig(server.URL+ingestion.GatewayEventsPath, checkpointPath, bytes.Repeat([]byte{0x62}, 32))
	config.Metrics = metrics
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := sender.Close(ctx); err != nil {
		t.Fatal(err)
	}

	output := renderSenderMetrics(t, metrics)
	for _, expected := range []string{
		`sentinelflow_event_checkpoint_operations_total{operation="load",outcome="success"} 1`,
		`sentinelflow_event_sequence_gaps_total{cause="unclean_restart"} 1`,
		`sentinelflow_event_gap_records_total{cause="unclean_restart"} 0`,
		`sentinelflow_event_sender_degraded 0`,
		`sentinelflow_event_queue_depth 0`,
	} {
		if !strings.Contains(output, expected+"\n") {
			t.Fatalf("missing exact restart metric %q", expected)
		}
	}
}
