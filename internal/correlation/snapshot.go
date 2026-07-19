package correlation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

func buildEvidenceSnapshot(signals []detection.Signal) (EvidenceSnapshot, error) {
	if len(signals) == 0 {
		return EvidenceSnapshot{}, correlationError(ErrorInvalidInput, "signals")
	}
	values, err := normalizeSignals(signals)
	if err != nil {
		return EvidenceSnapshot{}, err
	}
	sourceIP := values[0].SourceIP
	windowStart := values[0].WindowStart
	windowEnd := values[0].WindowEnd
	serviceLabels := make([]string, 0, len(values))
	signalIDs := make([]string, 0, len(values))
	evidenceIDs := make([]string, 0)
	refs := make([]SignalRef, 0, len(values))
	for _, signal := range values {
		if signal.SourceIP != sourceIP {
			return EvidenceSnapshot{}, correlationError(ErrorInvalidInput, "signals.source_ip")
		}
		if signal.WindowStart.Before(windowStart) {
			windowStart = signal.WindowStart
		}
		if signal.WindowEnd.After(windowEnd) {
			windowEnd = signal.WindowEnd
		}
		serviceLabels = append(serviceLabels, signal.ServiceLabel)
		signalIDs = append(signalIDs, signal.SignalID)
		evidenceIDs = append(evidenceIDs, signal.EvidenceIDs...)
		refs = append(refs, SignalRef{
			SignalID:                    signal.SignalID,
			RuleID:                      signal.RuleID,
			Classification:              signal.Classification,
			ConfigurationVersion:        signal.ConfigurationVersion,
			ConfigurationDigest:         signal.ConfigurationDigest,
			WindowStart:                 signal.WindowStart,
			WindowEnd:                   signal.WindowEnd,
			EventCount:                  signal.Metrics.EventCount,
			DistinctAccountCount:        signal.Metrics.DistinctAccountCount,
			DistinctSuspiciousPathCount: signal.Metrics.DistinctSuspiciousPathCount,
			EvidenceDigest:              signal.EvidenceDigest,
			SignalDigest:                signal.Digest,
		})
	}
	serviceLabels = sortedUnique(serviceLabels)
	signalIDs = sortedUnique(signalIDs)
	evidenceIDs = sortedUnique(evidenceIDs)
	sort.Slice(refs, func(i, j int) bool { return refs[i].SignalID < refs[j].SignalID })

	canonical := marshalSnapshotJCS(sourceIP, windowStart, windowEnd, serviceLabels, signalIDs, evidenceIDs, refs)
	digest := sha256Digest(canonical)
	return EvidenceSnapshot{
		schemaVersion:      EvidenceSnapshotVersion,
		sourceIP:           sourceIP,
		windowStart:        canonicalTime(windowStart),
		windowEnd:          canonicalTime(windowEnd),
		sourceHealthStatus: detection.SourceHealthStatusComplete,
		serviceLabels:      serviceLabels,
		signalIDs:          signalIDs,
		evidenceEventIDs:   evidenceIDs,
		signalRefs:         refs,
		canonicalBytes:     canonical,
		digest:             digest,
	}, nil
}

func marshalSnapshotJCS(
	sourceIP string,
	windowStart time.Time,
	windowEnd time.Time,
	serviceLabels []string,
	signalIDs []string,
	evidenceIDs []string,
	refs []SignalRef,
) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	writeJSONKey(&buffer, "evidence_event_ids")
	writeStringArray(&buffer, evidenceIDs)
	buffer.WriteByte(',')
	writeJSONKey(&buffer, "schema_version")
	writeJSONString(&buffer, EvidenceSnapshotVersion)
	buffer.WriteByte(',')
	writeJSONKey(&buffer, "service_labels")
	writeStringArray(&buffer, serviceLabels)
	buffer.WriteByte(',')
	writeJSONKey(&buffer, "signal_ids")
	writeStringArray(&buffer, signalIDs)
	buffer.WriteByte(',')
	writeJSONKey(&buffer, "signal_refs")
	buffer.WriteByte('[')
	for index, ref := range refs {
		if index > 0 {
			buffer.WriteByte(',')
		}
		writeSignalRefJCS(&buffer, ref)
	}
	buffer.WriteByte(']')
	buffer.WriteByte(',')
	writeJSONKey(&buffer, "source_health_status")
	writeJSONString(&buffer, string(detection.SourceHealthStatusComplete))
	buffer.WriteByte(',')
	writeJSONKey(&buffer, "source_ip")
	writeJSONString(&buffer, sourceIP)
	buffer.WriteByte(',')
	writeJSONKey(&buffer, "window_end")
	writeJSONString(&buffer, formatTime(windowEnd))
	buffer.WriteByte(',')
	writeJSONKey(&buffer, "window_start")
	writeJSONString(&buffer, formatTime(windowStart))
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func writeSignalRefJCS(buffer *bytes.Buffer, ref SignalRef) {
	buffer.WriteByte('{')
	writeJSONKey(buffer, "classification")
	writeJSONString(buffer, string(ref.Classification))
	buffer.WriteByte(',')
	writeJSONKey(buffer, "configuration_digest")
	writeJSONString(buffer, ref.ConfigurationDigest)
	buffer.WriteByte(',')
	writeJSONKey(buffer, "configuration_version")
	writeJSONString(buffer, ref.ConfigurationVersion)
	buffer.WriteByte(',')
	writeJSONKey(buffer, "distinct_account_count")
	buffer.WriteString(strconv.Itoa(ref.DistinctAccountCount))
	buffer.WriteByte(',')
	writeJSONKey(buffer, "distinct_suspicious_path_count")
	buffer.WriteString(strconv.Itoa(ref.DistinctSuspiciousPathCount))
	buffer.WriteByte(',')
	writeJSONKey(buffer, "event_count")
	buffer.WriteString(strconv.Itoa(ref.EventCount))
	buffer.WriteByte(',')
	writeJSONKey(buffer, "evidence_digest")
	writeJSONString(buffer, ref.EvidenceDigest)
	buffer.WriteByte(',')
	writeJSONKey(buffer, "rule_id")
	writeJSONString(buffer, string(ref.RuleID))
	buffer.WriteByte(',')
	writeJSONKey(buffer, "signal_digest")
	writeJSONString(buffer, ref.SignalDigest)
	buffer.WriteByte(',')
	writeJSONKey(buffer, "signal_id")
	writeJSONString(buffer, ref.SignalID)
	buffer.WriteByte(',')
	writeJSONKey(buffer, "window_end")
	writeJSONString(buffer, formatTime(ref.WindowEnd))
	buffer.WriteByte(',')
	writeJSONKey(buffer, "window_start")
	writeJSONString(buffer, formatTime(ref.WindowStart))
	buffer.WriteByte('}')
}

func writeJSONKey(buffer *bytes.Buffer, key string) {
	writeJSONString(buffer, key)
	buffer.WriteByte(':')
}

func writeJSONString(buffer *bytes.Buffer, value string) {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("correlation: JSON string encoding failed")
	}
	buffer.Write(encoded)
}

func writeStringArray(buffer *bytes.Buffer, values []string) {
	buffer.WriteByte('[')
	for index, value := range values {
		if index > 0 {
			buffer.WriteByte(',')
		}
		writeJSONString(buffer, value)
	}
	buffer.WriteByte(']')
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if write > 0 && result[write-1] == value {
			continue
		}
		result[write] = value
		write++
	}
	return result[:write]
}

func sha256Digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func formatTime(value time.Time) string {
	return canonicalTime(value).Format(time.RFC3339Nano)
}
