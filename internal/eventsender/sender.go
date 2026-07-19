// Package eventsender provides the Gateway's bounded, non-blocking event
// delivery adapter. It stores only sender health checkpoint data, never events.
package eventsender

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
	"github.com/devwooops/sentinelflow/internal/observability"
)

const (
	defaultQueueCapacity  = 10000
	defaultBatchSize      = 100
	defaultMaxBatchBytes  = 256 * 1024
	defaultFlushInterval  = 100 * time.Millisecond
	defaultRequestTimeout = 5 * time.Second
	coverageHeartbeat     = time.Second
	maxBackoff            = 5 * time.Second
	maxAckBytes           = 4096
)

var (
	senderPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Config struct {
	SenderID       string
	EndpointURL    string
	HMACKey        []byte
	CheckpointFile string
	QueueCapacity  int
	BatchSize      int
	MaxBatchBytes  int
	FlushInterval  time.Duration
	RequestTimeout time.Duration
	HTTPClient     *http.Client
	Clock          func() time.Time
	Random         io.Reader
	NewID          func() (string, error)
	Metrics        *observability.Metrics
}

type Sender struct {
	config   Config
	endpoint *url.URL
	epoch    string
	queue    chan events.EventRecordV1
	stop     chan struct{}
	done     chan struct{}

	enqueueMu        sync.Mutex
	closed           bool
	sequence         uint64
	lastAckSequence  uint64
	lastAckDigest    string
	closeResultMu    sync.Mutex
	closeResult      error
	degraded         atomic.Bool
	dropped          atomic.Uint64
	backlog          atomic.Int64
	healthGeneration atomic.Uint64
	healthMu         sync.Mutex
	outageStart      time.Time
	shutdownDeadline atomic.Int64

	coverageSegmentID      string
	coverageStart          time.Time
	coveragePreviousDigest string
	coverageCommitted      bool
}

type batch struct {
	body             []byte
	id               string
	sequence         uint64
	records          []events.EventRecordV1
	hasHealth        bool
	healthGeneration uint64
	hasCoverage      bool
	coverageDigest   string
	coverageEnd      time.Time
}

type acknowledgement struct {
	Status      string `json:"status"`
	SenderID    string `json:"sender_id"`
	SenderEpoch string `json:"sender_epoch"`
	BatchID     string `json:"batch_id"`
	Sequence    uint64 `json:"sequence"`
	BodyDigest  string `json:"body_digest"`
}

func New(input Config) (*Sender, error) {
	input.setDefaults()
	endpoint, err := validateConfig(input)
	if err != nil {
		return nil, err
	}
	previous, exists, err := loadCheckpoint(input.CheckpointFile)
	if err != nil {
		input.Metrics.ObserveCheckpoint(observability.CheckpointLoad, observability.CheckpointError)
		return nil, err
	}
	if exists {
		input.Metrics.ObserveCheckpoint(observability.CheckpointLoad, observability.CheckpointSuccess)
	} else {
		input.Metrics.ObserveCheckpoint(observability.CheckpointLoad, observability.CheckpointMissing)
	}
	epochBytes := make([]byte, 16)
	if _, err := io.ReadFull(input.Random, epochBytes); err != nil {
		return nil, errors.New("eventsender: generate sender epoch")
	}
	epoch := base64.RawURLEncoding.EncodeToString(epochBytes)
	input.HMACKey = bytes.Clone(input.HMACKey)
	clientCopy := *input.HTTPClient
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("eventsender: redirects are forbidden")
	}
	input.HTTPClient = &clientCopy
	sender := &Sender{
		config:            input,
		endpoint:          endpoint,
		epoch:             epoch,
		queue:             make(chan events.EventRecordV1, input.QueueCapacity),
		stop:              make(chan struct{}),
		done:              make(chan struct{}),
		sequence:          1,
		coverageSegmentID: events.CoverageSegmentID(input.SenderID, epoch, "epoch-start"),
		coverageStart:     coverageStartTime(input.Clock()),
	}
	sender.config.Metrics.SetEventQueue(0, input.QueueCapacity)
	if exists && (previous.SenderID != input.SenderID || previous.EndpointPath != ingestion.GatewayEventsPath) {
		return nil, errors.New("eventsender: checkpoint belongs to another sender or endpoint")
	}
	var previousLoss *events.SourceHealthV1
	if exists && !previous.CleanShutdown {
		health, healthErr := sender.uncleanRestartEvent(previous.SenderEpoch)
		if healthErr != nil {
			return nil, healthErr
		}
		previousLoss = &health
	}
	if err := sender.storeCheckpoint(false); err != nil {
		return nil, err
	}
	if previousLoss != nil {
		sender.setDegraded(true)
		sender.healthGeneration.Add(1)
		sender.queue <- events.SourceHealthRecord(*previousLoss)
		sender.addBacklog(1)
		sender.config.Metrics.ObserveSequenceGap(observability.GapUncleanRestart, 0)
	}
	go sender.run()
	return sender, nil
}

func (c *Config) setDefaults() {
	if c.QueueCapacity == 0 {
		c.QueueCapacity = defaultQueueCapacity
	}
	if c.BatchSize == 0 {
		c.BatchSize = defaultBatchSize
	}
	if c.MaxBatchBytes == 0 {
		c.MaxBatchBytes = defaultMaxBatchBytes
	}
	if c.FlushInterval == 0 {
		c.FlushInterval = defaultFlushInterval
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = defaultRequestTimeout
	}
	if c.Clock == nil {
		c.Clock = func() time.Time { return time.Now().UTC() }
	}
	if c.Random == nil {
		c.Random = rand.Reader
	}
	if c.NewID == nil {
		c.NewID = newUUID
	}
	if c.HTTPClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.ForceAttemptHTTP2 = false
		transport.DisableCompression = true
		c.HTTPClient = &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("eventsender: redirects are forbidden")
			},
		}
	}
	if c.Metrics == nil {
		c.Metrics = observability.New(observability.Config{})
	}
}

func validateConfig(config Config) (*url.URL, error) {
	if !senderPattern.MatchString(config.SenderID) || len(config.HMACKey) < 32 {
		return nil, errors.New("eventsender: invalid sender or HMAC key")
	}
	endpoint, err := url.Parse(config.EndpointURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Path != ingestion.GatewayEventsPath || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("eventsender: endpoint must be the fixed Gateway ingestion URL")
	}
	if config.CheckpointFile == "" || config.QueueCapacity < 1 || config.QueueCapacity > 1000000 ||
		config.BatchSize < 1 || config.BatchSize > events.MaxEventBatchRecords || config.BatchSize > config.QueueCapacity ||
		config.MaxBatchBytes < 1024 || config.MaxBatchBytes > events.MaxEventBatchBodyBytes ||
		config.FlushInterval < time.Millisecond || config.FlushInterval > 5*time.Second ||
		config.RequestTimeout <= 0 || config.RequestTimeout > 30*time.Second {
		return nil, errors.New("eventsender: invalid bounded delivery configuration")
	}
	if config.HTTPClient == nil || config.Clock == nil || config.Random == nil || config.NewID == nil {
		return nil, errors.New("eventsender: incomplete dependencies")
	}
	return endpoint, nil
}

// TryEnqueue is bounded and never performs I/O. It implements gateway.EventSink.
func (s *Sender) TryEnqueue(event events.GatewayEvent) events.EnqueueResult {
	if event.Validate() != nil {
		s.config.Metrics.ObserveEnqueue(observability.EnqueueDropped)
		return events.EnqueueDropped
	}
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	if s.closed {
		s.config.Metrics.ObserveEnqueue(observability.EnqueueDropped)
		return events.EnqueueDropped
	}
	select {
	case s.queue <- events.GatewayHTTPRecord(event):
		s.addBacklog(1)
		if s.degraded.Load() {
			s.config.Metrics.ObserveEnqueue(observability.EnqueueDegraded)
			return events.EnqueueDegraded
		}
		s.config.Metrics.ObserveEnqueue(observability.EnqueueAccepted)
		return events.EnqueueAccepted
	default:
		s.dropped.Add(1)
		s.config.Metrics.ObserveEnqueue(observability.EnqueueDropped)
		s.config.Metrics.ObserveSequenceGap(observability.GapQueueOverflow, 1)
		s.markDegraded()
		return events.EnqueueDropped
	}
}

func (s *Sender) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("eventsender: nil close context")
	}
	s.enqueueMu.Lock()
	if !s.closed {
		s.closed = true
		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(5 * time.Second)
		}
		s.shutdownDeadline.Store(deadline.UnixNano())
		close(s.stop)
	}
	s.enqueueMu.Unlock()
	select {
	case <-s.done:
		s.closeResultMu.Lock()
		defer s.closeResultMu.Unlock()
		return s.closeResult
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Sender) run() {
	defer close(s.done)
	ticker := time.NewTicker(minDuration(s.config.FlushInterval, coverageHeartbeat))
	defer ticker.Stop()
	pending := make([]events.EventRecordV1, 0, s.config.BatchSize)
	for {
		select {
		case record := <-s.queue:
			pending = append(pending, record)
			if len(pending) >= s.config.BatchSize {
				pending = s.flush(pending)
			}
		case <-ticker.C:
			pending = s.flush(pending)
		case <-s.stop:
			for {
				select {
				case record := <-s.queue:
					pending = append(pending, record)
				default:
					goto drained
				}
			}
		drained:
			for len(pending) > 0 && !s.shutdownExpired() {
				pending = s.flush(pending)
			}
			var closeErr error
			if len(pending) == 0 && !s.degraded.Load() {
				closeErr = s.storeCheckpoint(true)
			} else {
				closeErr = errors.New("eventsender: shutdown left an unacknowledged loss interval")
			}
			s.closeResultMu.Lock()
			s.closeResult = closeErr
			s.closeResultMu.Unlock()
			return
		}
	}
}

func (s *Sender) flush(pending []events.EventRecordV1) []events.EventRecordV1 {
	// TryEnqueue uses the same mutex. Draining while it is held establishes a
	// serialized queue cut without holding the request path across network I/O.
	s.enqueueMu.Lock()
	for {
		select {
		case record := <-s.queue:
			pending = append(pending, record)
		default:
			goto cut
		}
	}
cut:
	wantCoverage := s.canAttachCoverage(pending)
	current, count, err := s.buildBatchWithCoverage(pending, wantCoverage)
	s.enqueueMu.Unlock()
	if errors.Is(err, errNoSendableBatch) {
		return pending
	}
	if err != nil {
		s.markDegraded()
		return pending
	}
	permanent, delivered := s.deliver(current)
	if delivered {
		s.sequence++
		pending = pending[count:]
		s.addBacklog(-int64(count))
		s.commitCoverage(current)
		if current.hasHealth && current.healthGeneration == s.healthGeneration.Load() {
			s.setDegraded(false)
			s.resetCoverageAfterHealth(current)
		}
		if health, ok := s.takeHealthEvent(); ok {
			pending = append([]events.EventRecordV1{events.SourceHealthRecord(health)}, pending...)
			s.addBacklog(1)
		}
		return pending
	}
	if permanent {
		s.sequence++
		pending = pending[count:]
		s.addBacklog(-int64(count))
		s.markDegraded()
		if !current.hasHealth {
			health, healthErr := s.rejectedBatchEvent(current.sequence, uint64(count))
			if healthErr == nil {
				pending = append([]events.EventRecordV1{events.SourceHealthRecord(health)}, pending...)
				s.addBacklog(1)
				s.config.Metrics.ObserveSequenceGap(observability.GapRejectedBatch, uint64(count))
			}
		}
	}
	return pending
}

var errNoSendableBatch = errors.New("eventsender: no sendable batch")

func (s *Sender) buildBatchWithCoverage(pending []events.EventRecordV1, wantCoverage bool) (batch, int, error) {
	if s.sequence < 1 || s.sequence > events.MaxSafeInteger {
		return batch{}, 0, errors.New("eventsender: sequence exhausted")
	}
	if len(pending) == 0 && !wantCoverage {
		return batch{}, 0, errNoSendableBatch
	}
	if wantCoverage {
		current, err := s.buildEnvelope(pending, len(pending), true)
		if err != nil {
			return batch{}, 0, err
		}
		if len(current.body) <= s.config.MaxBatchBytes {
			return current, len(pending), nil
		}
		// A marker never causes an observation to be silently omitted. If the
		// complete cut does not fit, send observations without positive coverage.
		if len(pending) == 0 {
			return batch{}, 0, errors.New("eventsender: coverage marker exceeds the batch contract")
		}
	}
	count := minInt(len(pending), s.config.BatchSize)
	for count > 0 {
		current, err := s.buildEnvelope(pending, count, false)
		if err != nil {
			return batch{}, 0, err
		}
		if len(current.body) <= s.config.MaxBatchBytes {
			return current, count, nil
		}
		count--
	}
	return batch{}, 0, errors.New("eventsender: one record exceeds the batch contract")
}

func (s *Sender) buildEnvelope(pending []events.EventRecordV1, count int, withCoverage bool) (batch, error) {
	batchID, err := s.config.NewID()
	if err != nil || !uuidPattern.MatchString(batchID) {
		return batch{}, errors.New("eventsender: invalid generated batch ID")
	}
	now := coverageCutTime(s.config.Clock())
	sentAt, err := events.NewTimestamp(now)
	if err != nil {
		return batch{}, errors.New("eventsender: invalid clock")
	}
	records := append([]events.EventRecordV1(nil), pending[:count]...)
	for _, record := range records {
		if record.GatewayHTTP == nil && record.SourceHealth == nil {
			return batch{}, errors.New("eventsender: forbidden record type")
		}
		if record.SourceHealth != nil && record.SourceHealth.SourceID != s.config.SenderID {
			return batch{}, errors.New("eventsender: foreign source-health record")
		}
	}
	coverageDigest := ""
	if withCoverage {
		var previous *string
		if s.coverageCommitted {
			value := s.coveragePreviousDigest
			previous = &value
		}
		coverage, coverageErr := events.NewSourceCoverageV1(
			s.config.SenderID, s.epoch, s.coverageSegmentID, previous,
			s.coverageStart, now, batchID, s.sequence,
		)
		if coverageErr != nil {
			return batch{}, errors.New("eventsender: invalid coverage marker")
		}
		coverageDigest, coverageErr = coverage.Digest()
		if coverageErr != nil {
			return batch{}, errors.New("eventsender: invalid coverage digest")
		}
		records = append(records, events.SourceCoverageRecord(coverage))
	}
	envelope := events.EventBatchV1{
		SchemaVersion: events.EventBatchV1Schema,
		SenderID:      s.config.SenderID,
		SenderEpoch:   s.epoch,
		BatchID:       batchID,
		Sequence:      s.sequence,
		SentAt:        sentAt,
		Records:       records,
	}
	if err := envelope.Validate(); err != nil {
		return batch{}, errors.New("eventsender: invalid generated batch")
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return batch{}, err
	}
	hasHealth := containsSourceHealth(records)
	return batch{
		body: body, id: batchID, sequence: s.sequence, records: records,
		hasHealth: hasHealth, healthGeneration: s.healthGeneration.Load(),
		hasCoverage: withCoverage, coverageDigest: coverageDigest, coverageEnd: now,
	}, nil
}

func (s *Sender) canAttachCoverage(pending []events.EventRecordV1) bool {
	if s.degraded.Load() || containsSourceHealth(pending) {
		return false
	}
	limit := minInt(s.config.BatchSize-1, events.MaxEventBatchRecords-1)
	if len(pending) > limit {
		return false
	}
	now := coverageCutTime(s.config.Clock())
	if now.Before(s.coverageStart) {
		return false
	}
	// Observation-bearing batches attest their complete cut immediately. Empty
	// flushes are heartbeat-only and must not inherit a faster flush cadence.
	// coverageStart advances only after the receiver acknowledges a marker, so
	// it is also the exact idle heartbeat rate fence.
	if !s.coverageCommitted {
		return true
	}
	if !now.After(s.coverageStart) {
		return false
	}
	if len(pending) > 0 {
		return true
	}
	return !now.Before(s.coverageStart.Add(coverageHeartbeat))
}

func (s *Sender) commitCoverage(current batch) {
	if !current.hasCoverage {
		return
	}
	s.coveragePreviousDigest = current.coverageDigest
	s.coverageStart = current.coverageEnd
	s.coverageCommitted = true
}

func (s *Sender) resetCoverageAfterHealth(current batch) {
	start, found := healthRecoveryBoundary(current.records, s.epoch)
	if !found {
		return
	}
	s.coverageSegmentID = events.CoverageSegmentID(s.config.SenderID, s.epoch, current.id)
	s.coverageStart = coverageStartTime(start)
	s.coveragePreviousDigest = ""
	s.coverageCommitted = false
}

func healthRecoveryBoundary(records []events.EventRecordV1, epoch string) (time.Time, bool) {
	var boundary time.Time
	for _, record := range records {
		health := record.SourceHealth
		if health == nil || health.AffectedSenderEpoch != epoch {
			continue
		}
		candidate := health.OccurredAt.Time()
		if health.IntervalEnd != nil {
			candidate = health.IntervalEnd.Time()
		}
		if boundary.IsZero() || candidate.After(boundary) {
			boundary = candidate
		}
	}
	return boundary, !boundary.IsZero()
}

func containsSourceHealth(records []events.EventRecordV1) bool {
	for _, record := range records {
		if record.SourceHealth != nil {
			return true
		}
	}
	return false
}

func coverageCutTime(now time.Time) time.Time {
	return now.UTC().Truncate(time.Millisecond)
}

func coverageStartTime(now time.Time) time.Time {
	now = now.UTC()
	start := now.Truncate(time.Millisecond)
	if start.Before(now) {
		start = start.Add(time.Millisecond)
	}
	return start
}

func (s *Sender) deliver(current batch) (permanent, delivered bool) {
	bodySum := sha256.Sum256(current.body)
	bodyDigest := "sha256:" + hex.EncodeToString(bodySum[:])
	backoff := 100 * time.Millisecond
	attempt := uint64(0)
	for !s.shutdownExpired() {
		if attempt > 0 {
			s.config.Metrics.ObserveBatchRetry()
		}
		attempt++
		attemptStartedAt := time.Now()
		nonce := make([]byte, 16)
		if _, err := io.ReadFull(s.config.Random, nonce); err != nil {
			s.config.Metrics.ObserveBatchAttempt(observability.BatchPermanentError, observability.BatchErrorInternal, time.Since(attemptStartedAt))
			s.markOutage()
			return true, false
		}
		headers, err := ingestion.Sign(ingestion.GatewayEventsPath, s.config.SenderID, s.config.HMACKey, current.body, nonce, s.config.Clock().UTC())
		if err != nil {
			s.config.Metrics.ObserveBatchAttempt(observability.BatchPermanentError, observability.BatchErrorAuthentication, time.Since(attemptStartedAt))
			s.markOutage()
			return true, false
		}
		ctx, cancel := s.attemptContext()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(current.body))
		if err != nil {
			cancel()
			s.config.Metrics.ObserveBatchAttempt(observability.BatchPermanentError, observability.BatchErrorInternal, time.Since(attemptStartedAt))
			s.markOutage()
			return true, false
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("X-Sentinel-Sender-ID", headers.SenderID)
		request.Header.Set("X-Sentinel-Timestamp", headers.Timestamp)
		request.Header.Set("X-Sentinel-Nonce", headers.Nonce)
		request.Header.Set("X-Sentinel-Signature", headers.Signature)
		response, requestErr := s.config.HTTPClient.Do(request)
		if requestErr != nil {
			cancel()
			s.config.Metrics.ObserveBatchAttempt(observability.BatchRetryableError, observability.BatchErrorNetwork, time.Since(attemptStartedAt))
			s.markOutage()
			if !s.waitBackoff(backoff) {
				return false, false
			}
			backoff = minDuration(backoff*2, maxBackoff)
			continue
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxAckBytes+1))
		_ = response.Body.Close()
		cancel()
		if response.StatusCode == http.StatusAccepted && readErr == nil && len(responseBody) <= maxAckBytes {
			ack, ackErr := decodeAcknowledgement(responseBody)
			if ackErr == nil && (ack.Status == "accepted" || ack.Status == "duplicate") &&
				ack.SenderID == s.config.SenderID && ack.SenderEpoch == s.epoch && ack.BatchID == current.id &&
				ack.Sequence == current.sequence && ack.BodyDigest == bodyDigest {
				s.lastAckSequence = current.sequence
				s.lastAckDigest = bodyDigest
				if err := s.storeCheckpoint(false); err == nil {
					s.config.Metrics.SetLastAcknowledgedSequence(current.sequence)
					s.config.Metrics.ObserveBatchAttempt(observability.BatchAccepted, observability.BatchErrorNone, time.Since(attemptStartedAt))
					return false, true
				}
				s.config.Metrics.ObserveBatchAttempt(observability.BatchRetryableError, observability.BatchErrorCheckpoint, time.Since(attemptStartedAt))
			} else {
				s.config.Metrics.ObserveBatchAttempt(observability.BatchRetryableError, observability.BatchErrorAcknowledgement, time.Since(attemptStartedAt))
			}
			s.markOutage()
		} else if response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusUnprocessableEntity ||
			(response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusRequestTimeout && response.StatusCode != http.StatusTooManyRequests) {
			s.config.Metrics.ObserveBatchAttempt(observability.BatchPermanentError, observability.BatchErrorResponse, time.Since(attemptStartedAt))
			s.markOutage()
			return true, false
		} else {
			s.config.Metrics.ObserveBatchAttempt(observability.BatchRetryableError, observability.BatchErrorResponse, time.Since(attemptStartedAt))
			s.markOutage()
		}
		if !s.waitBackoff(backoff) {
			return false, false
		}
		backoff = minDuration(backoff*2, maxBackoff)
	}
	return false, false
}

func (s *Sender) attemptContext() (context.Context, context.CancelFunc) {
	if deadlineNanos := s.shutdownDeadline.Load(); deadlineNanos != 0 {
		deadline := time.Unix(0, deadlineNanos)
		if requestDeadline := time.Now().Add(s.config.RequestTimeout); requestDeadline.Before(deadline) {
			deadline = requestDeadline
		}
		return context.WithDeadline(context.Background(), deadline)
	}
	return context.WithTimeout(context.Background(), s.config.RequestTimeout)
}

func (s *Sender) waitBackoff(duration time.Duration) bool {
	if s.shutdownDeadline.Load() != 0 {
		return !s.shutdownExpired()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.stop:
		return !s.shutdownExpired()
	}
}

func (s *Sender) shutdownExpired() bool {
	deadline := s.shutdownDeadline.Load()
	return deadline != 0 && !time.Now().Before(time.Unix(0, deadline))
}

func (s *Sender) markDegraded() {
	s.setDegraded(true)
	s.healthGeneration.Add(1)
}

func (s *Sender) setDegraded(value bool) {
	s.degraded.Store(value)
	s.config.Metrics.SetSenderDegraded(value)
}

func (s *Sender) addBacklog(delta int64) {
	depth := s.backlog.Add(delta)
	if depth < 0 {
		s.backlog.Store(0)
		depth = 0
	}
	s.config.Metrics.SetEventQueue(int(depth), s.config.QueueCapacity)
}

func (s *Sender) markOutage() {
	s.healthMu.Lock()
	if s.outageStart.IsZero() {
		s.outageStart = s.config.Clock().UTC()
	}
	s.healthMu.Unlock()
	s.markDegraded()
}

func (s *Sender) takeHealthEvent() (events.SourceHealthV1, bool) {
	dropped := s.dropped.Swap(0)
	s.healthMu.Lock()
	started := s.outageStart
	s.outageStart = time.Time{}
	s.healthMu.Unlock()
	if dropped == 0 && started.IsZero() {
		return events.SourceHealthV1{}, false
	}
	now := s.config.Clock().UTC()
	cause := events.SourceHealthRecovered
	state := events.SourceHealthStateRecovered
	detail := events.SourceHealthDetailDeliveryRestored
	if dropped > 0 {
		cause = events.SourceHealthQueueOverflow
		state = events.SourceHealthStateLost
		detail = events.SourceHealthDetailUnknownRange
	}
	if started.IsZero() {
		started = now
	}
	health, err := s.sourceHealth(cause, state, detail, s.epoch, nil, nil, &started, &now, dropped)
	return health, err == nil
}

func (s *Sender) uncleanRestartEvent(previousEpoch string) (events.SourceHealthV1, error) {
	return s.sourceHealth(events.SourceHealthUncleanRestart, events.SourceHealthStateLost, events.SourceHealthDetailSenderRestart,
		previousEpoch, nil, nil, nil, nil, 0)
}

func (s *Sender) rejectedBatchEvent(sequence, count uint64) (events.SourceHealthV1, error) {
	return s.sourceHealth(events.SourceHealthRejectedBatch, events.SourceHealthStateLost, events.SourceHealthDetailReceiverRejected,
		s.epoch, &sequence, &sequence, nil, nil, count)
}

func (s *Sender) sourceHealth(cause events.SourceHealthCause, state events.SourceHealthState, detail events.SourceHealthDetailCode,
	affectedEpoch string, sequenceStart, sequenceEnd *uint64, intervalStart, intervalEnd *time.Time, dropped uint64,
) (events.SourceHealthV1, error) {
	eventID, err := s.config.NewID()
	if err != nil || !uuidPattern.MatchString(eventID) {
		return events.SourceHealthV1{}, errors.New("eventsender: invalid generated health event ID")
	}
	now := s.config.Clock().UTC()
	occurredAt, err := events.NewTimestamp(now)
	if err != nil {
		return events.SourceHealthV1{}, err
	}
	var startTimestamp, endTimestamp *events.Timestamp
	if intervalStart != nil {
		value, timestampErr := events.NewTimestamp(intervalStart.UTC())
		if timestampErr != nil {
			return events.SourceHealthV1{}, timestampErr
		}
		startTimestamp = &value
	}
	if intervalEnd != nil {
		value, timestampErr := events.NewTimestamp(intervalEnd.UTC())
		if timestampErr != nil {
			return events.SourceHealthV1{}, timestampErr
		}
		endTimestamp = &value
	}
	digestBytes := sha256.Sum256([]byte(events.SourceHealthV1Schema + "\n" + s.config.SenderID + "\n" + affectedEpoch + "\n" + eventID))
	event := events.SourceHealthV1{
		SchemaVersion:       events.SourceHealthV1Schema,
		EventID:             eventID,
		IdempotencyKey:      "sha256:" + hex.EncodeToString(digestBytes[:]),
		OccurredAt:          occurredAt,
		SourceID:            s.config.SenderID,
		Cause:               cause,
		State:               state,
		AffectedSenderEpoch: affectedEpoch,
		SequenceStart:       sequenceStart,
		SequenceEnd:         sequenceEnd,
		IntervalStart:       startTimestamp,
		IntervalEnd:         endTimestamp,
		DroppedCount:        dropped,
		DetailCode:          detail,
	}
	if err := event.Validate(); err != nil {
		return events.SourceHealthV1{}, err
	}
	return event, nil
}

func decodeAcknowledgement(data []byte) (acknowledgement, error) {
	if err := validateStrictJSON(data); err != nil {
		return acknowledgement{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var ack acknowledgement
	if err := decoder.Decode(&ack); err != nil || (ack.Status != "accepted" && ack.Status != "duplicate") ||
		!senderPattern.MatchString(ack.SenderID) || len(ack.SenderEpoch) != 22 || !uuidPattern.MatchString(ack.BatchID) ||
		ack.Sequence < 1 || ack.Sequence > events.MaxSafeInteger || !digestPattern.MatchString(ack.BodyDigest) {
		return acknowledgement{}, errors.New("eventsender: invalid acknowledgement")
	}
	return ack, nil
}

func validateStrictJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("eventsender: invalid JSON")
	}
	if err := consumeValue(decoder, first); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("eventsender: trailing JSON")
	}
	return nil
}

func consumeValue(decoder *json.Decoder, token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("eventsender: invalid object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("eventsender: duplicate object key")
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("eventsender: invalid object")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("eventsender: invalid array")
		}
	default:
		return errors.New("eventsender: invalid JSON delimiter")
	}
	return nil
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func (s *Sender) String() string { return "eventsender(" + s.config.SenderID + ")" }

func (s *Sender) GoString() string { return s.String() }

// Ensure no credential-shaped configuration is exposed through formatting.
var _ fmt.Stringer = (*Sender)(nil)
