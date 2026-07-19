package authsender

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
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
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

var fixedNow = time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)

func testAuthEvent(t *testing.T, suffix int) events.AuthEventV1 {
	t.Helper()
	timestamp, err := events.NewTimestamp(fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	id := func(offset int) string { return fmt.Sprintf("019b0000-0000-7000-8000-%012d", suffix*10+offset) }
	digest := sha256.Sum256([]byte(id(0)))
	account := sha256.Sum256([]byte(id(1)))
	return events.AuthEventV1{
		SchemaVersion:    events.AuthEventV1Schema,
		EventID:          id(1),
		GatewayRequestID: id(2),
		TraceID:          id(3),
		IdempotencyKey:   "sha256:" + hex.EncodeToString(digest[:]),
		OccurredAt:       timestamp,
		SourceIP:         "203.0.113.20",
		ServiceLabel:     "demo-app",
		RouteLabel:       "login",
		AccountHash:      "hmac-sha256:" + hex.EncodeToString(account[:]),
		Outcome:          events.AuthOutcomeFailed,
	}
}

func sequenceIDs() func() (string, error) {
	var next atomic.Uint64
	return func() (string, error) {
		value := next.Add(1)
		return fmt.Sprintf("019b0000-0000-7000-8000-%012d", value), nil
	}
}

type incrementingReader struct {
	mu   sync.Mutex
	next byte
}

func (r *incrementingReader) Read(destination []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range destination {
		r.next++
		destination[index] = r.next
	}
	return len(destination), nil
}

func baseConfig(endpoint, checkpoint string, key []byte) Config {
	return Config{
		SenderID:       "auth-app",
		EndpointURL:    endpoint,
		HMACKey:        key,
		CheckpointFile: checkpoint,
		QueueCapacity:  8,
		BatchSize:      2,
		MaxBatchBytes:  events.MaxEventBatchBodyBytes,
		FlushInterval:  2 * time.Millisecond,
		RequestTimeout: 250 * time.Millisecond,
		Clock:          func() time.Time { return fixedNow },
		Random:         &incrementingReader{},
		NewID:          sequenceIDs(),
	}
}

type observedRequest struct {
	body      []byte
	nonce     string
	signature string
	batch     events.EventBatchV1
}

func authenticateRequest(t *testing.T, registry *ingestion.Registry, request *http.Request, body []byte) ingestion.AuthenticatedBatch {
	t.Helper()
	authenticated, err := registry.Authenticate(ingestion.AuthEventsPath, ingestion.Headers{
		SenderID:  request.Header.Get("X-Sentinel-Sender-ID"),
		Timestamp: request.Header.Get("X-Sentinel-Timestamp"),
		Nonce:     request.Header.Get("X-Sentinel-Nonce"),
		Signature: request.Header.Get("X-Sentinel-Signature"),
	}, body, fixedNow)
	if err != nil {
		t.Errorf("authenticate request: %v", err)
		return ingestion.AuthenticatedBatch{}
	}
	return authenticated
}

func writeAcknowledgement(writer http.ResponseWriter, authenticated ingestion.AuthenticatedBatch, status string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(writer).Encode(acknowledgement{
		Status:      status,
		SenderID:    authenticated.Batch.SenderID,
		SenderEpoch: authenticated.Batch.SenderEpoch,
		BatchID:     authenticated.Batch.BatchID,
		Sequence:    authenticated.Batch.Sequence,
		BodyDigest:  authenticated.BodyDigest,
	})
}

func closeSender(t *testing.T, sender *Sender, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return sender.Close(ctx)
}

func nilCloseContext() context.Context { return nil }

func TestSenderRetriesExactAuthBodyAndReportsOutageRecovery(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	registry, err := ingestion.NewRegistry([]ingestion.Binding{{
		SenderID: "auth-app", EndpointPath: ingestion.AuthEventsPath, Key: key,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var observed []observedRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != ingestion.AuthEventsPath || request.Method != http.MethodPost {
			t.Errorf("request target = %s %s", request.Method, request.URL.Path)
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Error(readErr)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		authenticated := authenticateRequest(t, registry, request, body)
		mu.Lock()
		observed = append(observed, observedRequest{
			body: bytes.Clone(body), nonce: request.Header.Get("X-Sentinel-Nonce"),
			signature: request.Header.Get("X-Sentinel-Signature"), batch: authenticated.Batch,
		})
		attempt := len(observed)
		mu.Unlock()
		if attempt == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeAcknowledgement(writer, authenticated, "accepted")
	}))
	defer server.Close()

	checkpointPath := filepath.Join(t.TempDir(), "auth-sender.json")
	sender, err := New(baseConfig(server.URL+ingestion.AuthEventsPath, checkpointPath, key))
	if err != nil {
		t.Fatal(err)
	}
	if got := sender.TryEnqueue(testAuthEvent(t, 1)); got != events.EnqueueAccepted {
		t.Fatalf("enqueue = %s", got)
	}
	if err := closeSender(t, sender, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := closeSender(t, sender, time.Second); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}

	mu.Lock()
	requests := append([]observedRequest(nil), observed...)
	mu.Unlock()
	if len(requests) < 3 {
		t.Fatalf("request count = %d, want retry and health batch", len(requests))
	}
	if !bytes.Equal(requests[0].body, requests[1].body) || requests[0].batch.BatchID != requests[1].batch.BatchID ||
		requests[0].batch.SenderEpoch != requests[1].batch.SenderEpoch || requests[0].batch.Sequence != requests[1].batch.Sequence {
		t.Fatal("retry changed exact body or persistent batch identity")
	}
	if requests[0].nonce == requests[1].nonce || requests[0].signature == requests[1].signature {
		t.Fatal("retry reused nonce or signature")
	}
	if len(requests[0].batch.Records) != 2 || requests[0].batch.Records[0].AuthEvent == nil ||
		requests[0].batch.Records[0].GatewayHTTP != nil ||
		requests[0].batch.Records[1].SourceCoverage == nil {
		t.Fatalf("auth batch records = %#v", requests[0].batch.Records)
	}
	var outage, recovery bool
	for _, request := range requests[2:] {
		for _, record := range request.batch.Records {
			if record.SourceHealth == nil {
				continue
			}
			outage = outage || record.SourceHealth.Cause == events.SourceHealthDeliveryOutage
			recovery = recovery || record.SourceHealth.Cause == events.SourceHealthRecovered
		}
	}
	if !outage || !recovery {
		t.Fatalf("outage=%v recovery=%v", outage, recovery)
	}

	info, err := os.Stat(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode = %o", info.Mode().Perm())
	}
	state, exists, err := loadCheckpoint(checkpointPath)
	if err != nil || !exists || !state.CleanShutdown || state.LastAcknowledgedSequence < 2 || state.EndpointPath != ingestion.AuthEventsPath {
		t.Fatalf("checkpoint=%#v exists=%v err=%v", state, exists, err)
	}
	checkpointBytes, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"203.0.113.20", "auth-event-v1", "hmac-sha256", hex.EncodeToString(key)} {
		if strings.Contains(string(checkpointBytes), prohibited) {
			t.Fatalf("checkpoint retained prohibited data %q", prohibited)
		}
	}
	formatted := fmt.Sprintf("%v %#v", sender, sender)
	if strings.Contains(formatted, server.URL) || strings.Contains(formatted, hex.EncodeToString(key)) {
		t.Fatalf("sender formatting exposed configuration: %q", formatted)
	}
}

func TestIdleSenderEmitsAtMostOneBoundMarkerPerHeartbeat(t *testing.T) {
	key := bytes.Repeat([]byte{0x49}, 32)
	registry, err := ingestion.NewRegistry([]ingestion.Binding{{
		SenderID: "auth-app", EndpointPath: ingestion.AuthEventsPath, Key: key,
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
		authenticated := authenticateRequest(t, registry, request, body)
		select {
		case observed <- authenticated.Batch:
		default:
		}
		writeAcknowledgement(writer, authenticated, "accepted")
	}))
	defer server.Close()
	config := baseConfig(server.URL+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), key)
	config.FlushInterval = 5 * time.Millisecond
	var clockNanos atomic.Int64
	clockNanos.Store(fixedNow.UnixNano())
	config.Clock = func() time.Time { return time.Unix(0, clockNanos.Load()).UTC() }
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	var first events.EventBatchV1
	select {
	case first = <-observed:
		batch := first
		if len(batch.Records) != 1 || batch.Records[0].SourceCoverage == nil {
			t.Fatalf("idle batch = %#v", batch)
		}
		coverage := batch.Records[0].SourceCoverage
		if coverage.CoveredThroughBatchID != batch.BatchID ||
			coverage.CoveredThroughSequence != batch.Sequence || coverage.SourceID != batch.SenderID {
			t.Fatalf("idle marker = %#v", coverage)
		}
	case <-time.After(time.Second):
		t.Fatal("idle coverage heartbeat was not emitted")
	}
	select {
	case duplicate := <-observed:
		t.Fatalf("idle coverage ignored the one-second rate fence: %#v", duplicate)
	case <-time.After(40 * time.Millisecond):
	}
	clockNanos.Store(fixedNow.Add(coverageHeartbeat).UnixNano())
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
	if err := closeSender(t, sender, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestQueueOverflowIsNonBlockingAndReportedBeforeRecovery(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x33}, 32)
	registry, err := ingestion.NewRegistry([]ingestion.Binding{{
		SenderID: "auth-app", EndpointPath: ingestion.AuthEventsPath, Key: key,
	}})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var requestNumber atomic.Int32
	var mu sync.Mutex
	var batches []events.EventBatchV1
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		authenticated := authenticateRequest(t, registry, request, body)
		if requestNumber.Add(1) == 1 {
			started <- struct{}{}
			<-release
		}
		mu.Lock()
		batches = append(batches, authenticated.Batch)
		mu.Unlock()
		writeAcknowledgement(writer, authenticated, "accepted")
	}))
	defer server.Close()
	config := baseConfig(server.URL+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), key)
	config.QueueCapacity = 1
	config.BatchSize = 1
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := sender.TryEnqueue(testAuthEvent(t, 2)); got != events.EnqueueAccepted {
		t.Fatalf("first enqueue = %s", got)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("delivery did not start")
	}
	if got := sender.TryEnqueue(testAuthEvent(t, 3)); got != events.EnqueueAccepted {
		t.Fatalf("queued enqueue = %s", got)
	}
	begin := time.Now()
	if got := sender.TryEnqueue(testAuthEvent(t, 4)); got != events.EnqueueDropped {
		t.Fatalf("overflow enqueue = %s", got)
	}
	if elapsed := time.Since(begin); elapsed > 25*time.Millisecond {
		t.Fatalf("TryEnqueue blocked for %s", elapsed)
	}
	if got := sender.TryEnqueue(testAuthEvent(t, 5)); got != events.EnqueueDropped {
		t.Fatalf("second overflow enqueue = %s", got)
	}
	close(release)
	if err := closeSender(t, sender, 3*time.Second); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	captured := append([]events.EventBatchV1(nil), batches...)
	mu.Unlock()
	var overflow, recovery bool
	var dropped uint64
	for _, batch := range captured {
		for _, record := range batch.Records {
			if record.SourceHealth == nil {
				continue
			}
			if record.SourceHealth.Cause == events.SourceHealthQueueOverflow {
				overflow = true
				dropped += record.SourceHealth.DroppedCount
			}
			recovery = recovery || record.SourceHealth.Cause == events.SourceHealthRecovered
		}
	}
	if !overflow || !recovery || dropped != 2 {
		t.Fatalf("overflow=%v recovery=%v dropped=%d batches=%#v", overflow, recovery, dropped, captured)
	}
}

func TestReceiverRejectionEmitsExactLostBatchHealth(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x24}, 32)
	registry, err := ingestion.NewRegistry([]ingestion.Binding{{
		SenderID: "auth-app", EndpointPath: ingestion.AuthEventsPath, Key: key,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int32
	captured := make(chan events.EventBatchV1, 8)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		authenticated := authenticateRequest(t, registry, request, body)
		captured <- authenticated.Batch
		if count.Add(1) == 1 {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		writeAcknowledgement(writer, authenticated, "accepted")
	}))
	defer server.Close()
	config := baseConfig(server.URL+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), key)
	config.BatchSize = 1
	// Keep the initial idle-coverage tick out of this test. The receiver must
	// reject the queued auth-event batch, not a scheduler-dependent coverage-only
	// batch that happens to win a short test timer under -race.
	config.FlushInterval = 5 * time.Second
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := sender.TryEnqueue(testAuthEvent(t, 6)); got != events.EnqueueAccepted {
		t.Fatalf("enqueue = %s", got)
	}
	if err := closeSender(t, sender, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	close(captured)
	var rejected bool
	for batch := range captured {
		for _, record := range batch.Records {
			health := record.SourceHealth
			if health == nil || health.Cause != events.SourceHealthRejectedBatch {
				continue
			}
			rejected = health.State == events.SourceHealthStateLost && health.SequenceStart != nil &&
				health.SequenceEnd != nil && *health.SequenceStart == 1 && *health.SequenceEnd == 1 && health.DroppedCount == 1
		}
	}
	if !rejected {
		t.Fatal("missing exact rejected-batch source health")
	}
}

func TestUncleanRestartUsesIndependentEpochAndHealthOnlyCheckpoint(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x17}, 32)
	checkpointPath := filepath.Join(t.TempDir(), "checkpoint.json")
	previousEpoch := "AQEBAQEBAQEBAQEBAQEBAQ"
	previousBytes, err := json.Marshal(checkpoint{
		SenderID: "auth-app", EndpointPath: ingestion.AuthEventsPath, SenderEpoch: previousEpoch,
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
		body, _ := io.ReadAll(request.Body)
		batch, decodeErr := events.DecodeEventBatchV1(body)
		if decodeErr != nil {
			t.Error(decodeErr)
			writer.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		captured <- batch
		sum := sha256.Sum256(body)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(acknowledgement{
			Status: "duplicate", SenderID: batch.SenderID, SenderEpoch: batch.SenderEpoch,
			BatchID: batch.BatchID, Sequence: batch.Sequence, BodyDigest: "sha256:" + hex.EncodeToString(sum[:]),
		})
	}))
	defer server.Close()
	sender, err := New(baseConfig(server.URL+ingestion.AuthEventsPath, checkpointPath, key))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case batch := <-captured:
		if batch.Sequence != 1 || batch.SenderEpoch == previousEpoch || len(batch.Records) != 1 || batch.Records[0].SourceHealth == nil {
			t.Fatalf("restart batch = %#v", batch)
		}
		health := batch.Records[0].SourceHealth
		if health.Cause != events.SourceHealthUncleanRestart || health.State != events.SourceHealthStateLost ||
			health.AffectedSenderEpoch != previousEpoch || health.DetailCode != events.SourceHealthDetailSenderRestart {
			t.Fatalf("restart health = %#v", health)
		}
	case <-time.After(time.Second):
		t.Fatal("restart health was not delivered")
	}
	if err := closeSender(t, sender, time.Second); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestCloseCancellationStopsUnavailableDeliveryAndClosesAcceptance(t *testing.T) {
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
	config := baseConfig("http://control.internal"+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), bytes.Repeat([]byte{8}, 32))
	config.HTTPClient = client
	config.BatchSize = 1
	config.RequestTimeout = 30 * time.Second
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := sender.TryEnqueue(testAuthEvent(t, 7)); got != events.EnqueueAccepted {
		t.Fatalf("enqueue = %s", got)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("delivery did not start")
	}
	if err := sender.Close(nilCloseContext()); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := sender.Close(ctx); err == nil {
		t.Fatal("unavailable delivery closed cleanly")
	}
	if got := sender.TryEnqueue(testAuthEvent(t, 8)); got != events.EnqueueDropped {
		t.Fatalf("enqueue after Close = %s", got)
	}
	if err := closeSender(t, sender, time.Second); err == nil {
		t.Fatal("second Close lost the unclean result")
	}
}

func TestSenderConfigurationCheckpointAndRecordTypeFailClosed(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x51}, 32)
	valid := baseConfig("http://control.internal"+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), key)
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"short key", func(c *Config) { c.HMACKey = []byte("short") }},
		{"oversized key", func(c *Config) { c.HMACKey = make([]byte, maximumKeyBytes+1) }},
		{"wrong path", func(c *Config) { c.EndpointURL = "http://control.internal/wrong" }},
		{"query", func(c *Config) { c.EndpointURL += "?debug=1" }},
		{"empty query", func(c *Config) { c.EndpointURL += "?" }},
		{"fragment", func(c *Config) { c.EndpointURL += "#fragment" }},
		{"credentials", func(c *Config) { c.EndpointURL = "http://user:secret@control.internal" + ingestion.AuthEventsPath }},
		{"wrong scheme", func(c *Config) { c.EndpointURL = "ftp://control.internal" + ingestion.AuthEventsPath }},
		{"empty checkpoint", func(c *Config) { c.CheckpointFile = "" }},
		{"queue negative", func(c *Config) { c.QueueCapacity = -1 }},
		{"queue huge", func(c *Config) { c.QueueCapacity = 1000001 }},
		{"batch over queue", func(c *Config) { c.BatchSize = c.QueueCapacity + 1 }},
		{"batch huge", func(c *Config) { c.BatchSize = events.MaxEventBatchRecords + 1 }},
		{"body small", func(c *Config) { c.MaxBatchBytes = 1 }},
		{"body huge", func(c *Config) { c.MaxBatchBytes = events.MaxEventBatchBodyBytes + 1 }},
		{"flush short", func(c *Config) { c.FlushInterval = time.Nanosecond }},
		{"flush long", func(c *Config) { c.FlushInterval = 6 * time.Second }},
		{"timeout negative", func(c *Config) { c.RequestTimeout = -time.Second }},
		{"timeout long", func(c *Config) { c.RequestTimeout = 31 * time.Second }},
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name   string
		mutate func(*Config)
	}{"cookie jar", func(c *Config) { c.HTTPClient = &http.Client{Jar: jar} }})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			config.CheckpointFile = filepath.Join(t.TempDir(), "checkpoint.json")
			test.mutate(&config)
			if _, err := New(config); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}

	badMode := filepath.Join(t.TempDir(), "bad-mode.json")
	if err := os.WriteFile(badMode, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	valid.CheckpointFile = badMode
	if _, err := New(valid); err == nil || !strings.Contains(err.Error(), "unsafe checkpoint") {
		t.Fatalf("unsafe checkpoint error = %v", err)
	}

	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	valid.CheckpointFile = symlink
	if _, err := New(valid); err == nil {
		t.Fatal("symlink checkpoint accepted")
	}

	invalidEvent := testAuthEvent(t, 9)
	invalidEvent.ServiceLabel = "other-app"
	config := baseConfig("http://control.invalid"+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "valid.json"), key)
	// This subcase verifies local record rejection only; keep the independent
	// idle coverage heartbeat outside its immediate shutdown window.
	config.FlushInterval = 5 * time.Second
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := sender.TryEnqueue(invalidEvent); got != events.EnqueueDropped {
		t.Fatalf("foreign service result = %s", got)
	}
	invalidEvent = testAuthEvent(t, 10)
	invalidEvent.AccountHash = "raw-account"
	if got := sender.TryEnqueue(invalidEvent); got != events.EnqueueDropped {
		t.Fatalf("invalid auth event result = %s", got)
	}
	if err := closeSender(t, sender, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestAcknowledgementAmbiguityRetriesExactBody(t *testing.T) {
	key := bytes.Repeat([]byte{0x62}, 32)
	tests := []struct {
		name   string
		write  func(http.ResponseWriter, ingestion.AuthenticatedBatch)
		status string
	}{
		{"wrong sender", func(w http.ResponseWriter, a ingestion.AuthenticatedBatch) {
			a.Batch.SenderID = "wrong"
			writeAcknowledgement(w, a, "accepted")
		}, "accepted"},
		{"wrong epoch", func(w http.ResponseWriter, a ingestion.AuthenticatedBatch) {
			a.Batch.SenderEpoch = "AQEBAQEBAQEBAQEBAQEBAQ"
			writeAcknowledgement(w, a, "accepted")
		}, "accepted"},
		{"wrong sequence", func(w http.ResponseWriter, a ingestion.AuthenticatedBatch) {
			a.Batch.Sequence++
			writeAcknowledgement(w, a, "accepted")
		}, "accepted"},
		{"wrong digest", func(w http.ResponseWriter, a ingestion.AuthenticatedBatch) {
			a.BodyDigest = "sha256:" + strings.Repeat("0", 64)
			writeAcknowledgement(w, a, "accepted")
		}, "accepted"},
		{"invalid status", func(w http.ResponseWriter, a ingestion.AuthenticatedBatch) { writeAcknowledgement(w, a, "partial") }, "accepted"},
		{"unknown field", func(w http.ResponseWriter, _ ingestion.AuthenticatedBatch) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"status":"accepted","unknown":true}`)
		}, "accepted"},
		{"duplicate key", func(w http.ResponseWriter, a ingestion.AuthenticatedBatch) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprintf(w, `{"status":"accepted","status":"duplicate","sender_id":%q,"sender_epoch":%q,"batch_id":%q,"sequence":%d,"body_digest":%q}`,
				a.Batch.SenderID, a.Batch.SenderEpoch, a.Batch.BatchID, a.Batch.Sequence, a.BodyDigest)
		}, "accepted"},
		{"wrong content type", func(w http.ResponseWriter, a ingestion.AuthenticatedBatch) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(acknowledgement{Status: "accepted", SenderID: a.Batch.SenderID, SenderEpoch: a.Batch.SenderEpoch,
				BatchID: a.Batch.BatchID, Sequence: a.Batch.Sequence, BodyDigest: a.BodyDigest})
		}, "accepted"},
		{"duplicate acknowledgement", func(w http.ResponseWriter, a ingestion.AuthenticatedBatch) { writeAcknowledgement(w, a, "duplicate") }, "duplicate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry, err := ingestion.NewRegistry([]ingestion.Binding{{
				SenderID: "auth-app", EndpointPath: ingestion.AuthEventsPath, Key: key,
			}})
			if err != nil {
				t.Fatal(err)
			}
			var attempts atomic.Int32
			var firstBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body, _ := io.ReadAll(request.Body)
				authenticated := authenticateRequest(t, registry, request, body)
				attempt := attempts.Add(1)
				if attempt == 1 {
					firstBody = bytes.Clone(body)
					test.write(writer, authenticated)
					return
				}
				if attempt == 2 && !bytes.Equal(firstBody, body) {
					t.Error("ambiguous acknowledgement retry changed body")
				}
				writeAcknowledgement(writer, authenticated, "accepted")
			}))
			defer server.Close()
			sender, err := New(baseConfig(server.URL+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), key))
			if err != nil {
				t.Fatal(err)
			}
			if sender.TryEnqueue(testAuthEvent(t, 11)) != events.EnqueueAccepted {
				t.Fatal("enqueue failed")
			}
			if err := closeSender(t, sender, 3*time.Second); err != nil {
				t.Fatal(err)
			}
			if test.status == "duplicate" && attempts.Load() != 1 {
				t.Fatalf("valid duplicate ACK retried %d times", attempts.Load())
			}
			if test.status != "duplicate" && attempts.Load() < 2 {
				t.Fatal("ambiguous ACK was accepted")
			}
		})
	}
}

func TestRedirectAndAmbientDefaultProxyAreNotUsed(t *testing.T) {
	redirected := atomic.Int32{}
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL+ingestion.AuthEventsPath, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	config := baseConfig(redirector.URL+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), bytes.Repeat([]byte{3}, 32))
	config.HTTPClient = &http.Client{}
	config.BatchSize = 1
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if sender.TryEnqueue(testAuthEvent(t, 12)) != events.EnqueueAccepted {
		t.Fatal("enqueue failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := sender.Close(ctx); err == nil {
		t.Fatal("redirect outage closed cleanly")
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect target was reached")
	}

	client := hardenHTTPClient(&http.Client{})
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.ProxyConnectHeader != nil || !transport.DisableCompression || transport.ForceAttemptHTTP2 {
		t.Fatalf("default transport was not hardened: %#v", transport)
	}
}

func TestConcurrentEnqueueAndCloseIsRaceSafe(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x71}, 32)
	registry, err := ingestion.NewRegistry([]ingestion.Binding{{
		SenderID: "auth-app", EndpointPath: ingestion.AuthEventsPath, Key: key,
	}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		authenticated := authenticateRequest(t, registry, request, body)
		writeAcknowledgement(writer, authenticated, "accepted")
	}))
	defer server.Close()
	config := baseConfig(server.URL+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), key)
	config.QueueCapacity = 128
	config.BatchSize = 32
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for worker := range 8 {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for index := range 30 {
				_ = sender.TryEnqueue(testAuthEvent(t, 100+worker*30+index))
			}
		}(worker)
	}
	wait.Wait()
	if err := closeSender(t, sender, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestLocalDependencyFailuresRemainUncleanAndRedacted(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x81}, 32)
	config := baseConfig("http://control.internal"+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), key)
	config.Random = bytes.NewReader(make([]byte, 15))
	if _, err := New(config); err == nil || strings.Contains(err.Error(), hex.EncodeToString(key)) {
		t.Fatalf("epoch entropy error = %v", err)
	}

	config = baseConfig("http://control.internal"+ingestion.AuthEventsPath, filepath.Join(t.TempDir(), "checkpoint.json"), key)
	config.NewID = func() (string, error) { return "", errors.New("secret generator detail") }
	// Force the failing ID dependency to be exercised by the shutdown flush
	// after the event is accepted. A 2ms idle tick would otherwise make the
	// ordering scheduler-dependent and could halt the sender before enqueue.
	config.FlushInterval = 5 * time.Second
	sender, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if sender.TryEnqueue(testAuthEvent(t, 13)) != events.EnqueueAccepted {
		t.Fatal("enqueue failed")
	}
	if err := closeSender(t, sender, time.Second); err == nil || strings.Contains(err.Error(), "secret generator") {
		t.Fatalf("halt error = %v", err)
	}
}

func TestDefaultsHelpersAndHealthRestoration(t *testing.T) {
	t.Parallel()
	config := Config{}
	config.setDefaults()
	if config.QueueCapacity != defaultQueueCapacity || config.BatchSize != defaultBatchSize ||
		config.MaxBatchBytes != defaultMaxBatchBytes || config.FlushInterval != defaultFlushInterval ||
		config.RequestTimeout != defaultRequestTimeout || config.HTTPClient == nil || config.Clock == nil ||
		config.Random == nil || config.NewID == nil {
		t.Fatalf("defaults = %#v", config)
	}
	if identifier, err := newUUID(); err != nil || !uuidPattern.MatchString(identifier) {
		t.Fatalf("UUID = %q err=%v", identifier, err)
	}
	earlier := fixedNow.Add(-time.Minute)
	later := fixedNow
	if got := earliestTime(time.Time{}, later); !got.Equal(later) {
		t.Fatalf("earliest zero = %s", got)
	}
	if got := earliestTime(later, earlier); !got.Equal(earlier) {
		t.Fatalf("earliest = %s", got)
	}
	if got := saturatingAdd(2, 3); got != 5 {
		t.Fatalf("sum = %d", got)
	}
	if got := saturatingAdd(events.MaxSafeInteger-1, 2); got != events.MaxSafeInteger {
		t.Fatalf("saturated sum = %d", got)
	}

	sender := &Sender{}
	sender.restoreHealth(healthAccumulator{overflowCount: 2, overflowStart: later, outageStart: later})
	sender.restoreHealth(healthAccumulator{overflowCount: events.MaxSafeInteger, overflowStart: earlier, outageStart: earlier})
	sender.healthMu.Lock()
	health := sender.health
	sender.healthMu.Unlock()
	if health.overflowCount != events.MaxSafeInteger || !health.overflowStart.Equal(earlier) ||
		!health.outageStart.Equal(earlier) || !sender.degraded.Load() {
		t.Fatalf("restored health = %#v", health)
	}
}

func TestBuildBatchAndHealthGenerationRejectLocalInvariantFailures(t *testing.T) {
	t.Parallel()
	timestamp, err := events.NewTimestamp(fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	sender := &Sender{
		config: Config{
			SenderID: "auth-app", BatchSize: 2, MaxBatchBytes: events.MaxEventBatchBodyBytes,
			Clock: func() time.Time { return fixedNow }, NewID: sequenceIDs(),
		},
		epoch:    "AQEBAQEBAQEBAQEBAQEBAQ",
		sequence: 1,
	}
	gateway := events.GatewayHTTPV1{
		SchemaVersion: events.GatewayHTTPV1Schema, EventID: "019b0000-0000-7000-8000-000000000001",
		RequestID: "019b0000-0000-7000-8000-000000000002", TraceID: "019b0000-0000-7000-8000-000000000003",
		IdempotencyKey: "sha256:" + strings.Repeat("a", 64), StartedAt: timestamp, CompletedAt: timestamp,
		SourceIP: "203.0.113.20", Method: http.MethodGet, Protocol: "HTTP/1.1", RouteLabel: "other",
		PathCatalogVersion: events.PathCatalogV1, SuspiciousPathID: events.SuspiciousPathNone,
		Host: "app.example.test", ServiceLabel: "demo-app", StatusCode: http.StatusOK,
	}
	if _, _, err := sender.buildBatch([]events.EventRecordV1{events.GatewayHTTPRecord(gateway)}); err == nil {
		t.Fatal("Gateway record accepted by auth sender")
	}
	foreign, err := sender.sourceHealth(events.SourceHealthRecovered, events.SourceHealthStateRecovered,
		events.SourceHealthDetailDeliveryRestored, sender.epoch, nil, nil, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	foreign.SourceID = "other"
	if _, _, err := sender.buildBatch([]events.EventRecordV1{events.SourceHealthRecord(foreign)}); err == nil {
		t.Fatal("foreign source health accepted")
	}
	sender.sequence = 0
	if _, _, err := sender.buildBatch([]events.EventRecordV1{events.AuthEventRecord(testAuthEvent(t, 14))}); err == nil {
		t.Fatal("zero sequence accepted")
	}
	sender.sequence = events.MaxSafeInteger + 1
	if _, _, err := sender.buildBatch([]events.EventRecordV1{events.AuthEventRecord(testAuthEvent(t, 15))}); err == nil {
		t.Fatal("exhausted sequence accepted")
	}

	sender.config.NewID = func() (string, error) { return "not-a-uuid", nil }
	if _, err := sender.sourceHealth(events.SourceHealthRecovered, events.SourceHealthStateRecovered,
		events.SourceHealthDetailDeliveryRestored, sender.epoch, nil, nil, nil, nil, 0); err == nil {
		t.Fatal("invalid health ID accepted")
	}
}

func TestOversizedLocalBodyIsFatalWithoutNetwork(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("must not be reached")
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender := &Sender{
		config: Config{
			SenderID: "auth-app", HMACKey: bytes.Repeat([]byte{1}, 32), HTTPClient: client,
			Clock: func() time.Time { return fixedNow }, Random: &incrementingReader{}, RequestTimeout: time.Second,
		},
		endpoint:     &url.URL{Scheme: "http", Host: "control.internal", Path: ingestion.AuthEventsPath},
		lifecycleCtx: ctx,
		epoch:        "AQEBAQEBAQEBAQEBAQEBAQ",
	}
	outcome := sender.deliver(outboundBatch{body: bytes.Repeat([]byte{'x'}, events.MaxEventBatchBodyBytes+1)})
	if outcome != deliveryFatal || calls.Load() != 0 {
		t.Fatalf("outcome=%d calls=%d", outcome, calls.Load())
	}
}
