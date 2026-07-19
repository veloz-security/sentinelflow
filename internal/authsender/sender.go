// Package authsender provides the demo application's bounded, non-blocking
// auth-event delivery adapter. It persists sender health checkpoints only;
// auth events and transport credentials are never written to disk.
package authsender

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
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
)

const (
	defaultQueueCapacity  = 10000
	defaultBatchSize      = 100
	defaultMaxBatchBytes  = 256 * 1024
	defaultFlushInterval  = 100 * time.Millisecond
	defaultRequestTimeout = 5 * time.Second
	defaultCloseTimeout   = 5 * time.Second
	coverageHeartbeat     = time.Second
	initialBackoff        = 100 * time.Millisecond
	maximumBackoff        = 5 * time.Second
	maximumAckBytes       = 4096
	maximumKeyBytes       = 4096
)

var (
	senderPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Config contains the application sender's fixed endpoint and bounded runtime
// dependencies. HMACKey is copied on construction and is never formatted or
// persisted. A supplied HTTP client is treated as an explicitly trusted test
// or deployment dependency; redirects, cookie jars, and environment proxies on
// a standard *http.Transport are still disabled by New.
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
}

// Sender owns one independent auth producer epoch and sequence.
type Sender struct {
	config   Config
	endpoint *url.URL
	epoch    string
	queue    chan events.EventRecordV1
	stop     chan struct{}
	done     chan struct{}

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	enqueueMu sync.Mutex
	closed    bool

	sequence        uint64
	lastAckSequence uint64
	lastAckDigest   string

	resultMu   sync.Mutex
	closeErr   error
	haltErr    error
	closeTimer *time.Timer

	degraded atomic.Bool
	halted   atomic.Bool

	healthMu sync.Mutex
	health   healthAccumulator

	coverageSegmentID      string
	coverageStart          time.Time
	coveragePreviousDigest string
	coverageCommitted      bool
}

type healthAccumulator struct {
	overflowCount uint64
	overflowStart time.Time
	outageStart   time.Time
}

type outboundBatch struct {
	body           []byte
	id             string
	sequence       uint64
	records        []events.EventRecordV1
	hasHealth      bool
	hasCoverage    bool
	coverageDigest string
	coverageEnd    time.Time
}

type acknowledgement struct {
	Status      string `json:"status"`
	SenderID    string `json:"sender_id"`
	SenderEpoch string `json:"sender_epoch"`
	BatchID     string `json:"batch_id"`
	Sequence    uint64 `json:"sequence"`
	BodyDigest  string `json:"body_digest"`
}

type deliveryOutcome uint8

const (
	deliveryPending deliveryOutcome = iota
	deliveryAccepted
	deliveryRejected
	deliveryFatal
)

// New validates all fixed authority before creating a per-boot epoch. It marks
// the health-only checkpoint unclean before starting the delivery goroutine.
func New(input Config) (*Sender, error) {
	input.setDefaults()
	endpoint, err := validateConfig(input)
	if err != nil {
		return nil, err
	}
	previous, exists, err := loadCheckpoint(input.CheckpointFile)
	if err != nil {
		return nil, err
	}
	if exists && (previous.SenderID != input.SenderID || previous.EndpointPath != ingestion.AuthEventsPath) {
		return nil, errors.New("authsender: checkpoint belongs to another sender or endpoint")
	}

	epochBytes := make([]byte, 16)
	if _, err := io.ReadFull(input.Random, epochBytes); err != nil {
		return nil, errors.New("authsender: generate sender epoch")
	}

	input.HMACKey = bytes.Clone(input.HMACKey)
	input.HTTPClient = hardenHTTPClient(input.HTTPClient)
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	sender := &Sender{
		config:          input,
		endpoint:        endpoint,
		epoch:           base64.RawURLEncoding.EncodeToString(epochBytes),
		queue:           make(chan events.EventRecordV1, input.QueueCapacity),
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		sequence:        1,
		coverageSegmentID: events.CoverageSegmentID(input.SenderID,
			base64.RawURLEncoding.EncodeToString(epochBytes), "epoch-start"),
		coverageStart: coverageStartTime(input.Clock()),
	}

	var restartHealth *events.SourceHealthV1
	if exists && !previous.CleanShutdown {
		health, healthErr := sender.uncleanRestartEvent(previous.SenderEpoch)
		if healthErr != nil {
			lifecycleCancel()
			return nil, healthErr
		}
		restartHealth = &health
	}
	if err := sender.storeCheckpoint(false); err != nil {
		lifecycleCancel()
		return nil, err
	}
	if restartHealth != nil {
		sender.degraded.Store(true)
		sender.queue <- events.SourceHealthRecord(*restartHealth)
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
		transport.ProxyConnectHeader = nil
		transport.DisableCompression = true
		transport.ForceAttemptHTTP2 = false
		c.HTTPClient = &http.Client{Transport: transport}
	}
}

func validateConfig(config Config) (*url.URL, error) {
	if !senderPattern.MatchString(config.SenderID) || len(config.HMACKey) < 32 || len(config.HMACKey) > maximumKeyBytes {
		return nil, errors.New("authsender: invalid sender or HMAC key")
	}
	endpoint, err := url.Parse(config.EndpointURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Opaque != "" || endpoint.Path != ingestion.AuthEventsPath || endpoint.RawPath != "" || endpoint.RawQuery != "" ||
		endpoint.ForceQuery || endpoint.Fragment != "" {
		return nil, errors.New("authsender: endpoint must be the fixed auth ingestion URL")
	}
	if config.CheckpointFile == "" || config.QueueCapacity < 1 || config.QueueCapacity > 1000000 ||
		config.BatchSize < 1 || config.BatchSize > events.MaxEventBatchRecords || config.BatchSize > config.QueueCapacity ||
		config.MaxBatchBytes < 1024 || config.MaxBatchBytes > events.MaxEventBatchBodyBytes ||
		config.FlushInterval < time.Millisecond || config.FlushInterval > 5*time.Second ||
		config.RequestTimeout <= 0 || config.RequestTimeout > 30*time.Second {
		return nil, errors.New("authsender: invalid bounded delivery configuration")
	}
	if config.HTTPClient == nil || config.HTTPClient.Jar != nil || config.Clock == nil || config.Random == nil || config.NewID == nil {
		return nil, errors.New("authsender: incomplete or ambient HTTP dependencies")
	}
	return endpoint, nil
}

func hardenHTTPClient(input *http.Client) *http.Client {
	client := *input
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("authsender: redirects are forbidden")
	}
	if client.Transport == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.ProxyConnectHeader = nil
		transport.DisableCompression = true
		transport.ForceAttemptHTTP2 = false
		client.Transport = transport
	} else if transport, ok := client.Transport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.Proxy = nil
		clone.ProxyConnectHeader = nil
		clone.DisableCompression = true
		clone.ForceAttemptHTTP2 = false
		client.Transport = clone
	}
	client.Jar = nil
	return &client
}

// TryEnqueue validates and offers one auth-event-v1 without disk, network, or
// channel waiting. Invalid, closed, halted, or full senders fail closed.
func (s *Sender) TryEnqueue(event events.AuthEventV1) events.EnqueueResult {
	if event.Validate() != nil || event.ServiceLabel != "demo-app" {
		return events.EnqueueDropped
	}
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	if s.closed || s.halted.Load() {
		return events.EnqueueDropped
	}
	select {
	case s.queue <- events.AuthEventRecord(event):
		if s.degraded.Load() {
			return events.EnqueueDegraded
		}
		return events.EnqueueAccepted
	default:
		s.recordOverflow()
		return events.EnqueueDropped
	}
}

// Close stops acceptance, drains the bounded queue, and tries to acknowledge
// all events or explicit loss markers before marking the checkpoint clean.
// The first Close context controls graceful shutdown; later calls only wait.
func (s *Sender) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("authsender: nil close context")
	}
	s.enqueueMu.Lock()
	if !s.closed {
		s.closed = true
		s.beginShutdown(ctx)
		close(s.stop)
	}
	s.enqueueMu.Unlock()

	select {
	case <-s.done:
		s.resultMu.Lock()
		defer s.resultMu.Unlock()
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Sender) beginShutdown(ctx context.Context) {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(defaultCloseTimeout)
	}
	delay := time.Until(deadline)
	if delay <= 0 {
		s.lifecycleCancel()
	} else {
		s.resultMu.Lock()
		s.closeTimer = time.AfterFunc(delay, s.lifecycleCancel)
		s.resultMu.Unlock()
	}
	go func() {
		select {
		case <-ctx.Done():
			s.lifecycleCancel()
		case <-s.done:
		}
	}()
}

func (s *Sender) run() {
	defer func() {
		s.lifecycleCancel()
		s.resultMu.Lock()
		if s.closeTimer != nil {
			s.closeTimer.Stop()
		}
		s.resultMu.Unlock()
		close(s.done)
	}()
	ticker := time.NewTicker(minDuration(s.config.FlushInterval, coverageHeartbeat))
	defer ticker.Stop()
	pending := make([]events.EventRecordV1, 0, s.config.BatchSize)
	for {
		if s.halted.Load() {
			select {
			case <-s.stop:
				s.finish(errors.New("authsender: delivery halted before clean shutdown"))
				return
			case <-s.lifecycleCtx.Done():
				s.finish(errors.New("authsender: delivery halted before clean shutdown"))
				return
			case <-ticker.C:
				continue
			}
		}

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
			for len(pending) > 0 && s.lifecycleCtx.Err() == nil && !s.halted.Load() {
				pending = s.flush(pending)
			}
			if len(pending) == 0 && !s.degraded.Load() && !s.halted.Load() && s.lifecycleCtx.Err() == nil {
				s.finish(s.storeCheckpoint(true))
			} else {
				s.finish(errors.New("authsender: shutdown left unacknowledged events or health state"))
			}
			return
		}
	}
}

func (s *Sender) finish(err error) {
	s.resultMu.Lock()
	if err == nil && s.haltErr != nil {
		err = s.haltErr
	}
	s.closeErr = err
	s.resultMu.Unlock()
}

func (s *Sender) halt(err error) {
	if err == nil {
		err = errors.New("authsender: delivery halted")
	}
	s.resultMu.Lock()
	if s.haltErr == nil {
		s.haltErr = err
	}
	s.resultMu.Unlock()
	s.degraded.Store(true)
	s.halted.Store(true)
}

func (s *Sender) flush(pending []events.EventRecordV1) []events.EventRecordV1 {
	// TryEnqueue takes the same mutex. This bounded drain establishes the exact
	// producer cut before a marker is created, then releases the request path
	// before delivery can block or retry.
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
	current, count, err := s.buildBatchWithCoverage(pending, s.canAttachCoverage(pending))
	s.enqueueMu.Unlock()
	if errors.Is(err, errNoSendableBatch) {
		return pending
	}
	if err != nil {
		s.halt(err)
		return pending
	}

	switch s.deliver(current) {
	case deliveryAccepted:
		s.sequence++
		pending = pending[count:]
		s.commitCoverage(current)
		if current.hasHealth {
			s.resetCoverageAfterHealth(current)
		}
		healthRecords, healthErr := s.takeHealthRecords()
		if healthErr != nil {
			s.halt(healthErr)
			return pending
		}
		if len(healthRecords) > 0 {
			pending = append(healthRecords, pending...)
		} else if current.hasHealth && !containsHealth(pending) {
			s.degraded.Store(false)
		}
	case deliveryRejected:
		s.sequence++
		pending = pending[count:]
		s.degraded.Store(true)
		if current.hasHealth {
			s.halt(errors.New("authsender: receiver rejected a source-health batch"))
			return pending
		}
		health, healthErr := s.rejectedBatchEvent(current.sequence, uint64(count))
		if healthErr != nil {
			s.halt(healthErr)
			return pending
		}
		pending = append([]events.EventRecordV1{events.SourceHealthRecord(health)}, pending...)
	case deliveryFatal:
		s.halt(errors.New("authsender: local delivery invariant failed"))
	}
	return pending
}

func containsHealth(records []events.EventRecordV1) bool {
	for _, record := range records {
		if record.SourceHealth != nil {
			return true
		}
	}
	return false
}

func (s *Sender) buildBatch(pending []events.EventRecordV1) (outboundBatch, int, error) {
	return s.buildBatchWithCoverage(pending, false)
}

var errNoSendableBatch = errors.New("authsender: no sendable batch")

func (s *Sender) buildBatchWithCoverage(pending []events.EventRecordV1, wantCoverage bool) (outboundBatch, int, error) {
	if s.sequence < 1 || s.sequence > events.MaxSafeInteger {
		return outboundBatch{}, 0, errors.New("authsender: sequence exhausted")
	}
	if len(pending) == 0 && !wantCoverage {
		return outboundBatch{}, 0, errNoSendableBatch
	}
	if wantCoverage {
		current, err := s.buildEnvelope(pending, len(pending), true)
		if err != nil {
			return outboundBatch{}, 0, err
		}
		if len(current.body) <= s.config.MaxBatchBytes {
			return current, len(pending), nil
		}
		if len(pending) == 0 {
			return outboundBatch{}, 0, errors.New("authsender: coverage marker exceeds the batch contract")
		}
	}
	count := minInt(len(pending), s.config.BatchSize)
	for count > 0 {
		current, err := s.buildEnvelope(pending, count, false)
		if err != nil {
			return outboundBatch{}, 0, err
		}
		if len(current.body) <= s.config.MaxBatchBytes {
			return current, count, nil
		}
		count--
	}
	return outboundBatch{}, 0, errors.New("authsender: one record exceeds the batch contract")
}

func (s *Sender) buildEnvelope(pending []events.EventRecordV1, count int, withCoverage bool) (outboundBatch, error) {
	batchID, err := s.config.NewID()
	if err != nil || !uuidPattern.MatchString(batchID) {
		return outboundBatch{}, errors.New("authsender: invalid generated batch ID")
	}
	now := coverageCutTime(s.config.Clock())
	sentAt, err := events.NewTimestamp(now)
	if err != nil {
		return outboundBatch{}, errors.New("authsender: invalid clock")
	}
	records := append([]events.EventRecordV1(nil), pending[:count]...)
	for _, record := range records {
		if record.AuthEvent == nil && record.SourceHealth == nil {
			return outboundBatch{}, errors.New("authsender: forbidden record type")
		}
		if record.SourceHealth != nil && record.SourceHealth.SourceID != s.config.SenderID {
			return outboundBatch{}, errors.New("authsender: foreign source-health record")
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
			return outboundBatch{}, errors.New("authsender: invalid coverage marker")
		}
		coverageDigest, coverageErr = coverage.Digest()
		if coverageErr != nil {
			return outboundBatch{}, errors.New("authsender: invalid coverage digest")
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
		return outboundBatch{}, errors.New("authsender: invalid generated batch")
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return outboundBatch{}, err
	}
	return outboundBatch{
		body: body, id: batchID, sequence: s.sequence, records: records,
		hasHealth: containsHealth(records), hasCoverage: withCoverage,
		coverageDigest: coverageDigest, coverageEnd: now,
	}, nil
}

func (s *Sender) canAttachCoverage(pending []events.EventRecordV1) bool {
	if s.degraded.Load() || containsHealth(pending) {
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
	// A real observation batch should attest its complete serialized cut
	// immediately. Once the queue is idle, however, coverageStart is the last
	// acknowledged marker's end and also acts as the heartbeat rate fence. Do
	// not let a shorter flush interval turn positive coverage into write load.
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

func (s *Sender) commitCoverage(current outboundBatch) {
	if !current.hasCoverage {
		return
	}
	s.coveragePreviousDigest = current.coverageDigest
	s.coverageStart = current.coverageEnd
	s.coverageCommitted = true
}

func (s *Sender) resetCoverageAfterHealth(current outboundBatch) {
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

func (s *Sender) deliver(current outboundBatch) deliveryOutcome {
	bodySum := sha256.Sum256(current.body)
	bodyDigest := "sha256:" + hex.EncodeToString(bodySum[:])
	backoff := initialBackoff
	for s.lifecycleCtx.Err() == nil {
		nonce := make([]byte, 16)
		if _, err := io.ReadFull(s.config.Random, nonce); err != nil {
			s.markOutage()
			if !s.waitBackoff(backoff) {
				return deliveryPending
			}
			backoff = minDuration(backoff*2, maximumBackoff)
			continue
		}
		headers, err := ingestion.Sign(ingestion.AuthEventsPath, s.config.SenderID, s.config.HMACKey, current.body, nonce, s.config.Clock().UTC())
		if err != nil {
			return deliveryFatal
		}
		ctx, cancel := context.WithTimeout(s.lifecycleCtx, s.config.RequestTimeout)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(current.body))
		if err != nil {
			cancel()
			return deliveryFatal
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
			s.markOutage()
			if !s.waitBackoff(backoff) {
				return deliveryPending
			}
			backoff = minDuration(backoff*2, maximumBackoff)
			continue
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maximumAckBytes+1))
		closeErr := response.Body.Close()
		cancel()

		if response.StatusCode == http.StatusAccepted && readErr == nil && closeErr == nil && len(responseBody) <= maximumAckBytes &&
			validJSONContentType(response.Header.Get("Content-Type")) && response.Header.Get("Content-Encoding") == "" {
			ack, ackErr := decodeAcknowledgement(responseBody)
			if ackErr == nil && ack.SenderID == s.config.SenderID && ack.SenderEpoch == s.epoch && ack.BatchID == current.id &&
				ack.Sequence == current.sequence && ack.BodyDigest == bodyDigest {
				s.lastAckSequence = current.sequence
				s.lastAckDigest = bodyDigest
				if err := s.storeCheckpoint(false); err == nil {
					return deliveryAccepted
				}
			}
			s.markOutage()
		} else if response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusUnprocessableEntity {
			s.markOutage()
			return deliveryRejected
		} else {
			s.markOutage()
		}

		if !s.waitBackoff(backoff) {
			return deliveryPending
		}
		backoff = minDuration(backoff*2, maximumBackoff)
	}
	return deliveryPending
}

func validJSONContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json" && len(parameters) == 0
}

func (s *Sender) waitBackoff(duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.lifecycleCtx.Done():
		return false
	}
}

func (s *Sender) recordOverflow() {
	now := s.config.Clock().UTC()
	s.healthMu.Lock()
	if s.health.overflowCount < events.MaxSafeInteger {
		s.health.overflowCount++
	}
	if s.health.overflowStart.IsZero() {
		s.health.overflowStart = now
	}
	s.healthMu.Unlock()
	s.degraded.Store(true)
}

func (s *Sender) markOutage() {
	now := s.config.Clock().UTC()
	s.healthMu.Lock()
	if s.health.outageStart.IsZero() {
		s.health.outageStart = now
	}
	s.healthMu.Unlock()
	s.degraded.Store(true)
}

func (s *Sender) takeHealthRecords() ([]events.EventRecordV1, error) {
	s.healthMu.Lock()
	snapshot := s.health
	s.health = healthAccumulator{}
	s.healthMu.Unlock()
	if snapshot.overflowCount == 0 && snapshot.outageStart.IsZero() {
		return nil, nil
	}

	ended := s.config.Clock().UTC()
	records := make([]events.EventRecordV1, 0, 3)
	earliest := ended
	if snapshot.overflowCount > 0 {
		started := snapshot.overflowStart
		if started.IsZero() {
			started = ended
		}
		if started.Before(earliest) {
			earliest = started
		}
		health, err := s.sourceHealth(events.SourceHealthQueueOverflow, events.SourceHealthStateLost,
			events.SourceHealthDetailUnknownRange, s.epoch, nil, nil, &started, &ended, snapshot.overflowCount)
		if err != nil {
			s.restoreHealth(snapshot)
			return nil, err
		}
		records = append(records, events.SourceHealthRecord(health))
	}
	if !snapshot.outageStart.IsZero() {
		if snapshot.outageStart.Before(earliest) {
			earliest = snapshot.outageStart
		}
		health, err := s.sourceHealth(events.SourceHealthDeliveryOutage, events.SourceHealthStateDegraded,
			events.SourceHealthDetailNone, s.epoch, nil, nil, &snapshot.outageStart, &ended, 0)
		if err != nil {
			s.restoreHealth(snapshot)
			return nil, err
		}
		records = append(records, events.SourceHealthRecord(health))
	}
	recovered, err := s.sourceHealth(events.SourceHealthRecovered, events.SourceHealthStateRecovered,
		events.SourceHealthDetailDeliveryRestored, s.epoch, nil, nil, &earliest, &ended, 0)
	if err != nil {
		s.restoreHealth(snapshot)
		return nil, err
	}
	records = append(records, events.SourceHealthRecord(recovered))
	return records, nil
}

func (s *Sender) restoreHealth(snapshot healthAccumulator) {
	s.healthMu.Lock()
	s.health.overflowCount = saturatingAdd(s.health.overflowCount, snapshot.overflowCount)
	s.health.overflowStart = earliestTime(s.health.overflowStart, snapshot.overflowStart)
	s.health.outageStart = earliestTime(s.health.outageStart, snapshot.outageStart)
	s.healthMu.Unlock()
	s.degraded.Store(true)
}

func (s *Sender) uncleanRestartEvent(previousEpoch string) (events.SourceHealthV1, error) {
	return s.sourceHealth(events.SourceHealthUncleanRestart, events.SourceHealthStateLost,
		events.SourceHealthDetailSenderRestart, previousEpoch, nil, nil, nil, nil, 0)
}

func (s *Sender) rejectedBatchEvent(sequence, count uint64) (events.SourceHealthV1, error) {
	return s.sourceHealth(events.SourceHealthRejectedBatch, events.SourceHealthStateLost,
		events.SourceHealthDetailReceiverRejected, s.epoch, &sequence, &sequence, nil, nil, count)
}

func (s *Sender) sourceHealth(cause events.SourceHealthCause, state events.SourceHealthState, detail events.SourceHealthDetailCode,
	affectedEpoch string, sequenceStart, sequenceEnd *uint64, intervalStart, intervalEnd *time.Time, dropped uint64,
) (events.SourceHealthV1, error) {
	eventID, err := s.config.NewID()
	if err != nil || !uuidPattern.MatchString(eventID) {
		return events.SourceHealthV1{}, errors.New("authsender: invalid generated health event ID")
	}
	occurredAt, err := events.NewTimestamp(s.config.Clock().UTC())
	if err != nil {
		return events.SourceHealthV1{}, errors.New("authsender: invalid clock")
	}
	startTimestamp, err := optionalTimestamp(intervalStart)
	if err != nil {
		return events.SourceHealthV1{}, err
	}
	endTimestamp, err := optionalTimestamp(intervalEnd)
	if err != nil {
		return events.SourceHealthV1{}, err
	}
	digest := sha256.Sum256([]byte(events.SourceHealthV1Schema + "\n" + s.config.SenderID + "\n" + affectedEpoch + "\n" + eventID))
	health := events.SourceHealthV1{
		SchemaVersion:       events.SourceHealthV1Schema,
		EventID:             eventID,
		IdempotencyKey:      "sha256:" + hex.EncodeToString(digest[:]),
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
	if err := health.Validate(); err != nil {
		return events.SourceHealthV1{}, errors.New("authsender: invalid generated source health")
	}
	return health, nil
}

func optionalTimestamp(value *time.Time) (*events.Timestamp, error) {
	if value == nil {
		return nil, nil
	}
	timestamp, err := events.NewTimestamp(value.UTC())
	if err != nil {
		return nil, errors.New("authsender: invalid health interval")
	}
	return &timestamp, nil
}

func decodeAcknowledgement(data []byte) (acknowledgement, error) {
	if err := validateStrictJSONObject(data); err != nil {
		return acknowledgement{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var ack acknowledgement
	if err := decoder.Decode(&ack); err != nil || (ack.Status != "accepted" && ack.Status != "duplicate") ||
		!senderPattern.MatchString(ack.SenderID) || !validEpoch(ack.SenderEpoch) || !uuidPattern.MatchString(ack.BatchID) ||
		ack.Sequence < 1 || ack.Sequence > events.MaxSafeInteger || !digestPattern.MatchString(ack.BodyDigest) {
		return acknowledgement{}, errors.New("authsender: invalid acknowledgement")
	}
	return ack, nil
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

func validEpoch(value string) bool {
	if len(value) != 22 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 16
}

func earliestTime(left, right time.Time) time.Time {
	if left.IsZero() || (!right.IsZero() && right.Before(left)) {
		return right
	}
	return left
}

func saturatingAdd(left, right uint64) uint64 {
	if left >= events.MaxSafeInteger || right >= events.MaxSafeInteger-left {
		return events.MaxSafeInteger
	}
	return left + right
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

func (s *Sender) String() string { return "authsender(" + s.config.SenderID + ")" }

func (s *Sender) GoString() string { return s.String() }

// Ensure formatting never exposes credential-shaped configuration.
var _ fmt.Stringer = (*Sender)(nil)
