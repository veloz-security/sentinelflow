// Package observability provides bounded, dependency-free operational metrics.
//
// Metric labels are closed enums derived from process state. Request-derived
// values such as paths, hosts, addresses, request IDs, and account data are
// never accepted by this package.
package observability

import (
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// GatewayRejectionReason is a closed, low-cardinality rejection label.
type GatewayRejectionReason uint8

const (
	RejectProtocol GatewayRejectionReason = iota
	RejectTargetForm
	RejectIdentityGeneration
	RejectPeerAddress
	RejectHostSyntax
	RejectHostNotAllowed
	RejectTrailer
	RejectTransferEncoding
	RejectExpectation
	RejectUpgrade
	RejectConnectionHeader
	RejectRequestTarget
	RejectBodyLimit
	rejectionReasonCount
)

var gatewayRejectionLabels = [...]string{
	"protocol",
	"target_form",
	"identity_generation",
	"peer_address",
	"host_syntax",
	"host_not_allowed",
	"trailer",
	"transfer_encoding",
	"expectation",
	"upgrade",
	"connection_header",
	"request_target",
	"body_limit",
}

// GatewayProxyErrorReason is a closed, low-cardinality proxy failure label.
type GatewayProxyErrorReason uint8

const (
	ProxyErrorUpstream GatewayProxyErrorReason = iota
	ProxyErrorTimeout
	ProxyErrorResponse
	ProxyErrorBodyLimit
	proxyErrorReasonCount
)

var gatewayProxyErrorLabels = [...]string{
	"upstream",
	"timeout",
	"response",
	"body_limit",
}

// EnqueueOutcome is the bounded event-queue outcome.
type EnqueueOutcome uint8

const (
	EnqueueAccepted EnqueueOutcome = iota
	EnqueueDegraded
	EnqueueDropped
	enqueueOutcomeCount
)

var enqueueOutcomeLabels = [...]string{"accepted", "degraded", "dropped"}

// BatchOutcome is the bounded result of one HTTP delivery attempt.
type BatchOutcome uint8

const (
	BatchAccepted BatchOutcome = iota
	BatchRetryableError
	BatchPermanentError
	batchOutcomeCount
)

var batchOutcomeLabels = [...]string{"accepted", "retryable_error", "permanent_error"}

// BatchErrorReason is a closed delivery failure label.
type BatchErrorReason uint8

const (
	BatchErrorNone BatchErrorReason = iota
	BatchErrorNetwork
	BatchErrorAuthentication
	BatchErrorResponse
	BatchErrorAcknowledgement
	BatchErrorCheckpoint
	BatchErrorInternal
	batchErrorReasonCount
)

var batchErrorLabels = [...]string{
	"none",
	"network",
	"authentication",
	"response",
	"acknowledgement",
	"checkpoint",
	"internal",
}

// CheckpointOperation and CheckpointOutcome form a fixed status matrix.
type CheckpointOperation uint8

const (
	CheckpointLoad CheckpointOperation = iota
	CheckpointStore
	checkpointOperationCount
)

var checkpointOperationLabels = [...]string{"load", "store"}

type CheckpointOutcome uint8

const (
	CheckpointSuccess CheckpointOutcome = iota
	CheckpointMissing
	CheckpointError
	checkpointOutcomeCount
)

var checkpointOutcomeLabels = [...]string{"success", "missing", "error"}

// SequenceGapCause identifies only loss that this sender can observe itself.
type SequenceGapCause uint8

const (
	GapUncleanRestart SequenceGapCause = iota
	GapQueueOverflow
	GapRejectedBatch
	sequenceGapCauseCount
)

var sequenceGapLabels = [...]string{"unclean_restart", "queue_overflow", "rejected_batch"}

var requestDurationBounds = [...]time.Duration{
	time.Millisecond,
	2 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2500 * time.Millisecond,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

var batchDurationBounds = [...]time.Duration{
	time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2500 * time.Millisecond,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

type histogram struct {
	mu      sync.Mutex
	bounds  []time.Duration
	buckets []uint64
	count   uint64
	sumNS   int64
}

type histogramSnapshot struct {
	bounds  []time.Duration
	buckets []uint64
	count   uint64
	sumNS   int64
}

// atomicHistogram is used for observations made inside the forwarding data
// path. Updates never wait for a scrape or another observation. The bounds are
// immutable after construction and each sample is fully reflected once
// observe returns.
type atomicHistogram struct {
	bounds  []time.Duration
	buckets []atomic.Uint64
	count   atomic.Uint64
	sumNS   atomic.Int64
}

func newHistogram(bounds []time.Duration) histogram {
	return histogram{bounds: bounds, buckets: make([]uint64, len(bounds))}
}

func (h *histogram) observe(value time.Duration) {
	if value < 0 {
		value = 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++
	h.sumNS += int64(value)
	for index, bound := range h.bounds {
		if value <= bound {
			h.buckets[index]++
		}
	}
}

func (h *histogram) snapshot() histogramSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return histogramSnapshot{
		bounds:  append([]time.Duration(nil), h.bounds...),
		buckets: append([]uint64(nil), h.buckets...),
		count:   h.count,
		sumNS:   h.sumNS,
	}
}

func newAtomicHistogram(bounds []time.Duration) atomicHistogram {
	return atomicHistogram{
		bounds:  append([]time.Duration(nil), bounds...),
		buckets: make([]atomic.Uint64, len(bounds)),
	}
}

func (h *atomicHistogram) observe(value time.Duration) {
	if value < 0 {
		value = 0
	}
	h.sumNS.Add(int64(value))
	for index, bound := range h.bounds {
		if value <= bound {
			h.buckets[index].Add(1)
		}
	}
	h.count.Add(1)
}

func (h *atomicHistogram) snapshot() histogramSnapshot {
	buckets := make([]uint64, len(h.buckets))
	for index := range h.buckets {
		buckets[index] = h.buckets[index].Load()
	}
	return histogramSnapshot{
		bounds:  append([]time.Duration(nil), h.bounds...),
		buckets: buckets,
		count:   h.count.Load(),
		sumNS:   h.sumNS.Load(),
	}
}

// Config contains only testable process-local dependencies.
type Config struct {
	Clock func() time.Time
}

// Metrics is safe for concurrent use. A nil receiver is deliberately a no-op,
// so instrumentation cannot break the Gateway forwarding path.
type Metrics struct {
	clock func() time.Time

	requestStatus   [6]atomic.Uint64
	requestLatency  histogram
	upstreamLatency atomicHistogram
	proxyErrors     [proxyErrorReasonCount]atomic.Uint64
	rejections      [rejectionReasonCount]atomic.Uint64

	connectionMu      sync.Mutex
	connectionStates  map[uintptr]http.ConnState
	activeConnections atomic.Int64

	queueDepth    atomic.Int64
	queueCapacity atomic.Int64
	enqueues      [enqueueOutcomeCount]atomic.Uint64
	droppedEvents atomic.Uint64

	batchAttempts [batchOutcomeCount]atomic.Uint64
	batchErrors   [batchErrorReasonCount]atomic.Uint64
	batchRetries  atomic.Uint64
	batchLatency  histogram

	degradedMu      sync.Mutex
	degraded        bool
	degradedSince   time.Time
	degradedAccumNS int64
	degradedShownNS int64

	checkpoint [checkpointOperationCount][checkpointOutcomeCount]atomic.Uint64
	lastAck    atomic.Uint64
	gaps       [sequenceGapCauseCount]atomic.Uint64
	gapRecords [sequenceGapCauseCount]atomic.Uint64
}

func New(config Config) *Metrics {
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Metrics{
		clock:            config.Clock,
		requestLatency:   newHistogram(requestDurationBounds[:]),
		upstreamLatency:  newAtomicHistogram(requestDurationBounds[:]),
		batchLatency:     newHistogram(batchDurationBounds[:]),
		connectionStates: make(map[uintptr]http.ConnState),
	}
}

// ObserveGatewayUpstreamRoundTrip records only the origin RoundTripper call.
// It deliberately accepts no request-derived dimensions and never waits on a
// scrape or another observation.
func (m *Metrics) ObserveGatewayUpstreamRoundTrip(duration time.Duration) {
	if m != nil {
		m.upstreamLatency.observe(duration)
	}
}

func (m *Metrics) ObserveGatewayRequest(statusCode int, duration time.Duration) {
	if m == nil {
		return
	}
	index := 5
	if statusCode >= 100 && statusCode <= 599 {
		index = statusCode/100 - 1
	}
	m.requestStatus[index].Add(1)
	m.requestLatency.observe(duration)
}

func (m *Metrics) ObserveGatewayRejection(reason GatewayRejectionReason) {
	if m == nil || reason >= rejectionReasonCount {
		return
	}
	m.rejections[reason].Add(1)
}

func (m *Metrics) ObserveGatewayProxyError(reason GatewayProxyErrorReason) {
	if m == nil || reason >= proxyErrorReasonCount {
		return
	}
	m.proxyErrors[reason].Add(1)
}

// ObserveConnectionState is intended for http.Server.ConnState. It tracks only
// currently active request connections and removes terminal connection keys.
func (m *Metrics) ObserveConnectionState(connection net.Conn, state http.ConnState) {
	if m == nil || connection == nil {
		return
	}
	key, ok := connectionPointer(connection)
	if !ok {
		return
	}
	m.connectionMu.Lock()
	previous, exists := m.connectionStates[key]
	wasActive := exists && previous == http.StateActive
	isActive := state == http.StateActive
	if !wasActive && isActive {
		m.activeConnections.Add(1)
	} else if wasActive && !isActive {
		m.activeConnections.Add(-1)
	}
	if state == http.StateClosed || state == http.StateHijacked {
		delete(m.connectionStates, key)
	} else {
		m.connectionStates[key] = state
	}
	m.connectionMu.Unlock()
}

func connectionPointer(connection net.Conn) (uintptr, bool) {
	value := reflect.ValueOf(connection)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() {
		return 0, false
	}
	return value.Pointer(), true
}

func (m *Metrics) SetEventQueue(depth, capacity int) {
	if m == nil {
		return
	}
	if depth < 0 {
		depth = 0
	}
	if capacity < 0 {
		capacity = 0
	}
	m.queueDepth.Store(int64(depth))
	m.queueCapacity.Store(int64(capacity))
}

func (m *Metrics) ObserveEnqueue(outcome EnqueueOutcome) {
	if m == nil || outcome >= enqueueOutcomeCount {
		return
	}
	m.enqueues[outcome].Add(1)
	if outcome == EnqueueDropped {
		m.droppedEvents.Add(1)
	}
}

func (m *Metrics) ObserveBatchAttempt(outcome BatchOutcome, reason BatchErrorReason, duration time.Duration) {
	if m == nil || outcome >= batchOutcomeCount || reason >= batchErrorReasonCount {
		return
	}
	m.batchAttempts[outcome].Add(1)
	if reason != BatchErrorNone {
		m.batchErrors[reason].Add(1)
	}
	m.batchLatency.observe(duration)
}

func (m *Metrics) ObserveBatchRetry() {
	if m != nil {
		m.batchRetries.Add(1)
	}
}

func (m *Metrics) SetSenderDegraded(degraded bool) {
	if m == nil {
		return
	}
	now := m.clock()
	m.degradedMu.Lock()
	defer m.degradedMu.Unlock()
	if degraded == m.degraded {
		return
	}
	if degraded {
		m.degraded = true
		m.degradedSince = now
		return
	}
	if !m.degradedSince.IsZero() && now.After(m.degradedSince) {
		m.degradedAccumNS += int64(now.Sub(m.degradedSince))
	}
	if m.degradedAccumNS < m.degradedShownNS {
		m.degradedAccumNS = m.degradedShownNS
	}
	m.degraded = false
	m.degradedSince = time.Time{}
}

func (m *Metrics) ObserveCheckpoint(operation CheckpointOperation, outcome CheckpointOutcome) {
	if m == nil || operation >= checkpointOperationCount || outcome >= checkpointOutcomeCount {
		return
	}
	m.checkpoint[operation][outcome].Add(1)
}

func (m *Metrics) SetLastAcknowledgedSequence(sequence uint64) {
	if m != nil {
		m.lastAck.Store(sequence)
	}
}

func (m *Metrics) ObserveSequenceGap(cause SequenceGapCause, knownLostRecords uint64) {
	if m == nil || cause >= sequenceGapCauseCount {
		return
	}
	m.gaps[cause].Add(1)
	if knownLostRecords > 0 {
		m.gapRecords[cause].Add(knownLostRecords)
	}
}
