package observability

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const openMetricsContentType = "application/openmetrics-text; version=1.0.0; charset=utf-8"

var statusClassLabels = [...]string{"1xx", "2xx", "3xx", "4xx", "5xx", "invalid"}

// Handler returns an exact-path, read-only OpenMetrics endpoint. Callers must
// mount it only on an internal or loopback listener; the package intentionally
// does not open a listener or modify the public Gateway router.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writeMetricError(writer, http.StatusMethodNotAllowed)
			return
		}
		if request.URL == nil || request.URL.Path != "/metrics" || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" ||
			request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
			writeMetricError(writer, http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", openMetricsContentType)
		writer.WriteHeader(http.StatusOK)
		_, _ = m.WriteOpenMetrics(writer)
	})
}

func writeMetricError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, strings.ToLower(http.StatusText(status))+"\n")
}

// WriteOpenMetrics writes a deterministic snapshot. It contains no secret- or
// request-derived labels and is bounded by the package's fixed metric matrix.
func (m *Metrics) WriteOpenMetrics(writer io.Writer) (int64, error) {
	if m == nil {
		return 0, nil
	}
	var output bytes.Buffer
	writeHelpType(&output, "sentinelflow_gateway_requests_total", "Gateway requests by bounded status class.", "counter")
	for index, label := range statusClassLabels {
		fmt.Fprintf(&output, "sentinelflow_gateway_requests_total{status_class=%q} %d\n", label, m.requestStatus[index].Load())
	}
	writeHistogram(&output, "sentinelflow_gateway_request_duration_seconds", "Gateway request duration in seconds.", &m.requestLatency)
	writeHistogram(&output, "sentinelflow_gateway_upstream_round_trip_duration_seconds", "Gateway origin round-trip duration from transport call to response headers or transport error in seconds; response-body streaming time is excluded.", &m.upstreamLatency)

	writeHelpType(&output, "sentinelflow_gateway_proxy_errors_total", "Gateway proxy failures by bounded reason.", "counter")
	for index, label := range gatewayProxyErrorLabels {
		fmt.Fprintf(&output, "sentinelflow_gateway_proxy_errors_total{reason=%q} %d\n", label, m.proxyErrors[index].Load())
	}
	writeHelpType(&output, "sentinelflow_gateway_rejections_total", "Deterministic Gateway rejections by bounded reason.", "counter")
	for index, label := range gatewayRejectionLabels {
		fmt.Fprintf(&output, "sentinelflow_gateway_rejections_total{reason=%q} %d\n", label, m.rejections[index].Load())
	}
	writeHelpType(&output, "sentinelflow_gateway_active_connections", "Gateway connections currently serving a request.", "gauge")
	fmt.Fprintf(&output, "sentinelflow_gateway_active_connections %d\n", maxInt64(m.activeConnections.Load(), 0))

	writeHelpType(&output, "sentinelflow_event_queue_depth", "Unacknowledged Gateway event records in the bounded sender backlog.", "gauge")
	fmt.Fprintf(&output, "sentinelflow_event_queue_depth %d\n", maxInt64(m.queueDepth.Load(), 0))
	writeHelpType(&output, "sentinelflow_event_queue_capacity", "Configured Gateway event input queue capacity.", "gauge")
	fmt.Fprintf(&output, "sentinelflow_event_queue_capacity %d\n", maxInt64(m.queueCapacity.Load(), 0))
	writeHelpType(&output, "sentinelflow_event_enqueue_total", "Gateway event enqueue outcomes.", "counter")
	for index, label := range enqueueOutcomeLabels {
		fmt.Fprintf(&output, "sentinelflow_event_enqueue_total{outcome=%q} %d\n", label, m.enqueues[index].Load())
	}
	writeHelpType(&output, "sentinelflow_event_dropped_total", "Gateway event enqueue drops.", "counter")
	fmt.Fprintf(&output, "sentinelflow_event_dropped_total %d\n", m.droppedEvents.Load())

	writeHelpType(&output, "sentinelflow_event_batch_attempts_total", "Event batch delivery attempts by bounded outcome.", "counter")
	for index, label := range batchOutcomeLabels {
		fmt.Fprintf(&output, "sentinelflow_event_batch_attempts_total{outcome=%q} %d\n", label, m.batchAttempts[index].Load())
	}
	writeHelpType(&output, "sentinelflow_event_batch_errors_total", "Event batch delivery errors by bounded reason.", "counter")
	for index := BatchErrorNetwork; index < batchErrorReasonCount; index++ {
		fmt.Fprintf(&output, "sentinelflow_event_batch_errors_total{reason=%q} %d\n", batchErrorLabels[index], m.batchErrors[index].Load())
	}
	writeHelpType(&output, "sentinelflow_event_batch_retries_total", "Event batch delivery retries.", "counter")
	fmt.Fprintf(&output, "sentinelflow_event_batch_retries_total %d\n", m.batchRetries.Load())
	writeHistogram(&output, "sentinelflow_event_batch_duration_seconds", "Event batch HTTP attempt duration in seconds.", &m.batchLatency)

	m.degradedMu.Lock()
	degraded := m.degraded
	degradedNS := m.degradedAccumNS
	if degraded && !m.degradedSince.IsZero() {
		now := m.clock()
		if now.After(m.degradedSince) {
			degradedNS += int64(now.Sub(m.degradedSince))
		}
	}
	if degradedNS < m.degradedShownNS {
		degradedNS = m.degradedShownNS
	} else {
		m.degradedShownNS = degradedNS
	}
	m.degradedMu.Unlock()
	writeHelpType(&output, "sentinelflow_event_sender_degraded", "Whether Gateway event coverage is currently degraded.", "gauge")
	fmt.Fprintf(&output, "sentinelflow_event_sender_degraded %d\n", boolNumber(degraded))
	writeHelpType(&output, "sentinelflow_event_sender_degraded_seconds_total", "Accumulated sender degraded duration in seconds.", "counter")
	fmt.Fprintf(&output, "sentinelflow_event_sender_degraded_seconds_total %s\n", formatSeconds(degradedNS))

	writeHelpType(&output, "sentinelflow_event_checkpoint_operations_total", "Sender checkpoint operations by bounded outcome.", "counter")
	for operation, operationLabel := range checkpointOperationLabels {
		for outcome, outcomeLabel := range checkpointOutcomeLabels {
			fmt.Fprintf(&output, "sentinelflow_event_checkpoint_operations_total{operation=%q,outcome=%q} %d\n",
				operationLabel, outcomeLabel, m.checkpoint[operation][outcome].Load())
		}
	}
	writeHelpType(&output, "sentinelflow_event_last_acknowledged_sequence", "Last event batch sequence durably checkpointed by this sender process.", "gauge")
	fmt.Fprintf(&output, "sentinelflow_event_last_acknowledged_sequence %d\n", m.lastAck.Load())
	writeHelpType(&output, "sentinelflow_event_sequence_gaps_total", "Sender-observed loss or sequence-gap occurrences by bounded cause.", "counter")
	for index, label := range sequenceGapLabels {
		fmt.Fprintf(&output, "sentinelflow_event_sequence_gaps_total{cause=%q} %d\n", label, m.gaps[index].Load())
	}
	writeHelpType(&output, "sentinelflow_event_gap_records_total", "Known event records affected by sender-observed gaps; unknown restart ranges remain zero.", "counter")
	for index, label := range sequenceGapLabels {
		fmt.Fprintf(&output, "sentinelflow_event_gap_records_total{cause=%q} %d\n", label, m.gapRecords[index].Load())
	}
	output.WriteString("# EOF\n")

	return output.WriteTo(writer)
}

func writeHelpType(output *bytes.Buffer, name, help, metricType string) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

type histogramSnapshotter interface {
	snapshot() histogramSnapshot
}

func writeHistogram(output *bytes.Buffer, name, help string, value histogramSnapshotter) {
	writeHelpType(output, name, help, "histogram")
	snapshot := value.snapshot()
	for index, bound := range snapshot.bounds {
		fmt.Fprintf(output, "%s_bucket{le=%q} %d\n", name, formatSeconds(int64(bound)), snapshot.buckets[index])
	}
	fmt.Fprintf(output, "%s_bucket{le=%q} %d\n", name, "+Inf", snapshot.count)
	fmt.Fprintf(output, "%s_sum %s\n", name, formatSeconds(snapshot.sumNS))
	fmt.Fprintf(output, "%s_count %d\n", name, snapshot.count)
}

func formatSeconds(nanoseconds int64) string {
	return strconv.FormatFloat(float64(nanoseconds)/float64(time.Second), 'f', 9, 64)
}

func maxInt64(value, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

func boolNumber(value bool) int {
	if value {
		return 1
	}
	return 0
}
