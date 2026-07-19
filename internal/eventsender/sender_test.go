package eventsender

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
)

func testEvent(t *testing.T, suffix int) events.GatewayEvent {
	t.Helper()
	timestamp, err := events.NewTimestamp(time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	id := func(offset int) string { return fmt.Sprintf("019b0000-0000-7000-8000-%012d", suffix*10+offset) }
	digest := sha256.Sum256([]byte(id(0)))
	return events.GatewayEvent{
		SchemaVersion:      events.GatewayHTTPV1Schema,
		EventID:            id(1),
		RequestID:          id(2),
		TraceID:            id(3),
		IdempotencyKey:     "sha256:" + hex.EncodeToString(digest[:]),
		StartedAt:          timestamp,
		CompletedAt:        timestamp,
		SourceIP:           "203.0.113.20",
		Method:             http.MethodGet,
		Protocol:           "HTTP/1.1",
		RouteLabel:         "other",
		PathCatalogVersion: events.PathCatalogV1,
		SuspiciousPathID:   events.SuspiciousPathNone,
		Host:               "app.example.test",
		ServiceLabel:       "demo-app",
		StatusCode:         http.StatusOK,
	}
}

func sequenceIDs() func() (string, error) {
	var next atomic.Uint64
	return func() (string, error) {
		value := next.Add(1)
		return fmt.Sprintf("019b0000-0000-7000-8000-%012d", value), nil
	}
}

func baseConfig(endpoint, checkpoint string, key []byte) Config {
	return Config{
		SenderID:       "gateway-01",
		EndpointURL:    endpoint,
		HMACKey:        key,
		CheckpointFile: checkpoint,
		QueueCapacity:  4,
		BatchSize:      2,
		MaxBatchBytes:  events.MaxEventBatchBodyBytes,
		FlushInterval:  5 * time.Millisecond,
		RequestTimeout: 500 * time.Millisecond,
		Clock:          func() time.Time { return time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC) },
		NewID:          sequenceIDs(),
	}
}

type observedRequest struct {
	body      []byte
	nonce     string
	signature string
	batch     events.EventBatchV1
}

func TestSenderRetriesExactBodyWithFreshAuthenticationAndCleanCheckpoint(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	registry, err := ingestion.NewRegistry([]ingestion.Binding{{
		SenderID: "gateway-01", EndpointPath: ingestion.GatewayEventsPath, Key: key,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var observed []observedRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		headers := ingestion.Headers{
			SenderID:  request.Header.Get("X-Sentinel-Sender-ID"),
			Timestamp: request.Header.Get("X-Sentinel-Timestamp"),
			Nonce:     request.Header.Get("X-Sentinel-Nonce"),
			Signature: request.Header.Get("X-Sentinel-Signature"),
		}
		authenticated, authErr := registry.Authenticate(ingestion.GatewayEventsPath, headers, body,
			time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC))
		if authErr != nil {
			t.Errorf("authenticate: %v", authErr)
			writer.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		mu.Lock()
		observed = append(observed, observedRequest{
			body: bytes.Clone(body), nonce: headers.Nonce, signature: headers.Signature, batch: authenticated.Batch,
		})
		attempt := len(observed)
		mu.Unlock()
		if attempt == 1 {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(acknowledgement{
			Status: "accepted", SenderID: authenticated.Batch.SenderID, SenderEpoch: authenticated.Batch.SenderEpoch,
			BatchID: authenticated.Batch.BatchID, Sequence: authenticated.Batch.Sequence, BodyDigest: authenticated.BodyDigest,
		})
	}))
	defer server.Close()

	checkpointPath := filepath.Join(t.TempDir(), "sender.json")
	config := baseConfig(server.URL+ingestion.GatewayEventsPath, checkpointPath, key)
	// This test verifies retry bytes and authentication, not ticker scheduling.
	// Close drains synchronously; keep the real ticker outside the batching race.
	config.FlushInterval = time.Second
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	firstEvent := testEvent(t, 1)
	secondEvent := testEvent(t, 2)
	if got := sender.TryEnqueue(firstEvent); got != events.EnqueueAccepted {
		t.Fatalf("first enqueue = %s", got)
	}
	if got := sender.TryEnqueue(secondEvent); got != events.EnqueueAccepted {
		t.Fatalf("second enqueue = %s", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := sender.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sender.Close(ctx); err != nil {
		t.Fatalf("second Close must be idempotent: %v", err)
	}

	mu.Lock()
	requests := append([]observedRequest(nil), observed...)
	mu.Unlock()
	if len(requests) < 3 {
		t.Fatalf("requests = %d, want retry plus recovered-health delivery", len(requests))
	}
	if !bytes.Equal(requests[0].body, requests[1].body) || requests[0].batch.BatchID != requests[1].batch.BatchID ||
		requests[0].batch.Sequence != requests[1].batch.Sequence {
		t.Fatal("retry changed body, batch ID, or sequence")
	}
	if requests[0].nonce == requests[1].nonce || requests[0].signature == requests[1].signature {
		t.Fatal("retry reused authentication nonce or signature")
	}
	if len(requests[0].batch.Records) == 0 || requests[0].batch.Sequence != 1 {
		t.Fatalf("first batch = %#v", requests[0].batch)
	}
	foundRecovery := false
	deliveredEvents := map[string]bool{}
	for _, request := range requests[1:] {
		for _, record := range request.batch.Records {
			if record.GatewayHTTP != nil {
				deliveredEvents[record.GatewayHTTP.EventID] = true
			}
			if record.SourceHealth != nil && record.SourceHealth.State == events.SourceHealthStateRecovered {
				foundRecovery = true
			}
		}
	}
	for _, eventID := range []string{firstEvent.EventID, secondEvent.EventID} {
		if !deliveredEvents[eventID] {
			t.Fatalf("accepted event %s was not delivered after recovery", eventID)
		}
	}
	if !foundRecovery {
		t.Fatal("delivery outage recovery was not reported")
	}

	info, err := os.Stat(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode = %o", info.Mode().Perm())
	}
	state, exists, err := loadCheckpoint(checkpointPath)
	if err != nil || !exists || !state.CleanShutdown || state.LastAcknowledgedSequence < 2 || state.LastAcknowledgedBodyDigest == "" {
		t.Fatalf("checkpoint = %#v, exists=%v err=%v", state, exists, err)
	}
	checkpointBytes, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"app.example.test", "203.0.113.20", "gateway-http-v1"} {
		if strings.Contains(string(checkpointBytes), prohibited) {
			t.Fatalf("checkpoint retained event data %q", prohibited)
		}
	}
}

func TestCoverageMarkerBindsCompleteCutAndChainsOnlyAfterAcknowledgement(t *testing.T) {
	now := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	sender := &Sender{
		config: Config{
			SenderID: "gateway-01", BatchSize: 100, MaxBatchBytes: events.MaxEventBatchBodyBytes,
			Clock: func() time.Time { return now }, NewID: sequenceIDs(),
		},
		epoch:             "AAAAAAAAAAAAAAAAAAAAAA",
		sequence:          1,
		coverageStart:     now,
		coverageSegmentID: events.CoverageSegmentID("gateway-01", "AAAAAAAAAAAAAAAAAAAAAA", "epoch-start"),
	}
	pending := []events.EventRecordV1{events.GatewayHTTPRecord(testEvent(t, 50))}
	first, count, err := sender.buildBatchWithCoverage(pending, true)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || !first.hasCoverage || len(first.records) != 2 || first.records[1].SourceCoverage == nil {
		t.Fatalf("first coverage batch = %#v count=%d", first, count)
	}
	marker := first.records[1].SourceCoverage
	if marker.SourceID != sender.config.SenderID || marker.AffectedSenderEpoch != sender.epoch ||
		marker.CoveredThroughBatchID != first.id || marker.CoveredThroughSequence != first.sequence ||
		marker.PreviousCoverageDigest != nil {
		t.Fatalf("first marker = %#v", marker)
	}
	if digest, err := marker.Digest(); err != nil || digest != first.coverageDigest {
		t.Fatalf("marker digest = %q err=%v", digest, err)
	}

	// Merely constructing a retryable body cannot advance the chain.
	if sender.coverageCommitted {
		t.Fatal("unacknowledged marker advanced coverage")
	}
	sender.commitCoverage(first)
	sender.sequence++
	now = now.Add(time.Second)
	second, _, err := sender.buildBatchWithCoverage(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	secondMarker := second.records[0].SourceCoverage
	if secondMarker == nil || secondMarker.PreviousCoverageDigest == nil ||
		*secondMarker.PreviousCoverageDigest != first.coverageDigest ||
		!secondMarker.CoverageStart.Time().Equal(marker.CoverageEnd.Time()) {
		t.Fatalf("second marker = %#v", secondMarker)
	}

	backlog := make([]events.EventRecordV1, 100)
	for index := range backlog {
		backlog[index] = events.GatewayHTTPRecord(testEvent(t, 60+index))
	}
	if sender.canAttachCoverage(backlog) {
		t.Fatal("coverage attached before the complete backlog could fit")
	}
}

func TestIdleSenderEmitsAtMostOneBoundMarkerPerHeartbeat(t *testing.T) {
	key := bytes.Repeat([]byte{0x49}, 32)
	registry, err := ingestion.NewRegistry([]ingestion.Binding{{
		SenderID: "gateway-01", EndpointPath: ingestion.GatewayEventsPath, Key: key,
	}})
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan events.EventBatchV1, 8)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Error(readErr)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		authenticated, authErr := registry.Authenticate(ingestion.GatewayEventsPath, ingestion.Headers{
			SenderID:  request.Header.Get("X-Sentinel-Sender-ID"),
			Timestamp: request.Header.Get("X-Sentinel-Timestamp"),
			Nonce:     request.Header.Get("X-Sentinel-Nonce"),
			Signature: request.Header.Get("X-Sentinel-Signature"),
		}, body, time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC))
		if authErr != nil {
			t.Errorf("authenticate request: %v", authErr)
			writer.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		select {
		case observed <- authenticated.Batch:
		default:
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(acknowledgement{
			Status: "accepted", SenderID: authenticated.Batch.SenderID,
			SenderEpoch: authenticated.Batch.SenderEpoch, BatchID: authenticated.Batch.BatchID,
			Sequence: authenticated.Batch.Sequence, BodyDigest: authenticated.BodyDigest,
		})
	}))
	defer server.Close()

	base := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	var clockNanos atomic.Int64
	clockNanos.Store(base.UnixNano())
	config := baseConfig(server.URL+ingestion.GatewayEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), key)
	config.FlushInterval = 5 * time.Millisecond
	config.Clock = func() time.Time { return time.Unix(0, clockNanos.Load()).UTC() }
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}

	var first events.EventBatchV1
	select {
	case first = <-observed:
		if len(first.Records) != 1 || first.Records[0].SourceCoverage == nil {
			t.Fatalf("idle batch = %#v", first)
		}
	case <-time.After(time.Second):
		t.Fatal("idle coverage heartbeat was not emitted")
	}
	select {
	case duplicate := <-observed:
		t.Fatalf("idle coverage ignored the one-second rate fence: %#v", duplicate)
	case <-time.After(40 * time.Millisecond):
	}
	clockNanos.Store(base.Add(coverageHeartbeat).UnixNano())
	select {
	case second := <-observed:
		marker := second.Records[0].SourceCoverage
		if marker == nil || marker.PreviousCoverageDigest == nil ||
			!marker.CoverageStart.Time().Equal(first.Records[0].SourceCoverage.CoverageEnd.Time()) {
			t.Fatalf("second idle marker did not extend the acknowledged chain: %#v", marker)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("idle coverage heartbeat did not resume at the one-second fence")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sender.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestTryEnqueueRemainsBoundedWhenControlPlaneIsUnavailable(t *testing.T) {
	t.Parallel()
	started := make(chan struct{}, 1)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	config := baseConfig("http://control.internal"+ingestion.GatewayEventsPath, filepath.Join(t.TempDir(), "sender.json"), bytes.Repeat([]byte{1}, 32))
	config.HTTPClient = client
	config.QueueCapacity = 1
	config.BatchSize = 1
	config.RequestTimeout = 30 * time.Millisecond
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := sender.TryEnqueue(testEvent(t, 3)); got != events.EnqueueAccepted {
		t.Fatalf("enqueue = %s", got)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sender did not start delivery")
	}
	_ = sender.TryEnqueue(testEvent(t, 4))
	begin := time.Now()
	if got := sender.TryEnqueue(testEvent(t, 5)); got != events.EnqueueDropped {
		t.Fatalf("full queue result = %s", got)
	}
	if time.Since(begin) > 20*time.Millisecond {
		t.Fatal("TryEnqueue blocked on control-plane I/O")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := sender.Close(ctx); err == nil {
		t.Fatal("unacknowledged outage shutdown unexpectedly became clean")
	}
}

func TestUncleanCheckpointProducesRestartLossBeforeNewEvents(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	checkpointPath := filepath.Join(directory, "sender.json")
	previousEpoch := "AQEBAQEBAQEBAQEBAQEBAQ"
	previousBytes, err := json.Marshal(checkpoint{
		SenderID: "gateway-01", EndpointPath: ingestion.GatewayEventsPath, SenderEpoch: previousEpoch,
		LastAcknowledgedSequence: 7, LastAcknowledgedBodyDigest: "sha256:" + strings.Repeat("a", 64), CleanShutdown: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteCheckpoint(checkpointPath, append(previousBytes, '\n')); err != nil {
		t.Fatal(err)
	}

	captured := make(chan events.EventBatchV1, 4)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Error(readErr)
			return
		}
		batch, decodeErr := events.DecodeEventBatchV1(body)
		if decodeErr != nil {
			t.Error(decodeErr)
			writer.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		captured <- batch
		sum := sha256.Sum256(body)
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(acknowledgement{
			Status: "accepted", SenderID: batch.SenderID, SenderEpoch: batch.SenderEpoch, BatchID: batch.BatchID,
			Sequence: batch.Sequence, BodyDigest: "sha256:" + hex.EncodeToString(sum[:]),
		})
	}))
	defer server.Close()
	sender, err := New(baseConfig(server.URL+ingestion.GatewayEventsPath, checkpointPath, bytes.Repeat([]byte{2}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case batch := <-captured:
		if len(batch.Records) != 1 || batch.Records[0].SourceHealth == nil ||
			batch.Records[0].SourceHealth.Cause != events.SourceHealthUncleanRestart ||
			batch.Records[0].SourceHealth.AffectedSenderEpoch != previousEpoch {
			t.Fatalf("restart batch = %#v", batch)
		}
	case <-time.After(time.Second):
		t.Fatal("unclean-restart loss record was not delivered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sender.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSenderConfigurationAndAcknowledgementFailClosed(t *testing.T) {
	t.Parallel()
	valid := baseConfig("http://control.internal"+ingestion.GatewayEventsPath, filepath.Join(t.TempDir(), "sender.json"), bytes.Repeat([]byte{3}, 32))
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"short key", func(c *Config) { c.HMACKey = []byte("short") }},
		{"wrong path", func(c *Config) { c.EndpointURL = "http://control.internal/wrong" }},
		{"credentials", func(c *Config) { c.EndpointURL = "http://user:secret@control.internal" + ingestion.GatewayEventsPath }},
		{"batch over queue", func(c *Config) { c.BatchSize = c.QueueCapacity + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := New(config); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	validAck := []byte(`{"status":"accepted","sender_id":"gateway-01","sender_epoch":"AQEBAQEBAQEBAQEBAQEBAQ","batch_id":"019b0000-0000-7000-8000-000000000001","sequence":1,"body_digest":"sha256:` + strings.Repeat("a", 64) + `"}`)
	if _, err := decodeAcknowledgement(validAck); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		bytes.Replace(validAck, []byte(`"status":"accepted"`), []byte(`"status":"accepted","status":"duplicate"`), 1),
		append(bytes.Clone(validAck), []byte(` {}`)...),
		bytes.Replace(validAck, []byte(`"sequence":1`), []byte(`"sequence":0`), 1),
	} {
		if _, err := decodeAcknowledgement(invalid); err == nil {
			t.Fatalf("invalid acknowledgement accepted: %s", invalid)
		}
	}

	badCheckpoint := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badCheckpoint, []byte(`{"sender_id":"gateway-01"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	valid.CheckpointFile = badCheckpoint
	if _, err := New(valid); err == nil || !errors.Is(err, os.ErrPermission) && !strings.Contains(err.Error(), "unsafe checkpoint") {
		if err == nil {
			t.Fatal("unsafe checkpoint accepted")
		}
	}
}
