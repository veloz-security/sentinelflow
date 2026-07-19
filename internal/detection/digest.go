package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

func digestConfig(config Config) string {
	var builder strings.Builder
	writeCanonicalLine(&builder, "sentinelflow-detector-config-v1")
	writeCanonicalLine(&builder, config.Version)
	writeCanonicalLine(&builder, config.PathCatalogVersion)
	writeCanonicalLine(&builder, config.LoginRouteLabel)
	writeCanonicalLine(&builder, strconv.Itoa(config.PathScanThreshold))
	writeCanonicalLine(&builder, strconv.FormatInt(int64(config.PathScanWindow), 10))
	writeCanonicalLine(&builder, strconv.Itoa(config.RequestBurstThreshold))
	writeCanonicalLine(&builder, strconv.FormatInt(int64(config.RequestBurstWindow), 10))
	writeCanonicalLine(&builder, strconv.Itoa(config.LoginBruteForceThreshold))
	writeCanonicalLine(&builder, strconv.FormatInt(int64(config.LoginBruteForceWindow), 10))
	writeCanonicalLine(&builder, strconv.Itoa(config.CredentialStuffingEventThreshold))
	writeCanonicalLine(&builder, strconv.Itoa(config.CredentialStuffingAccountThreshold))
	writeCanonicalLine(&builder, strconv.FormatInt(int64(config.CredentialStuffingWindow), 10))
	for _, identifier := range config.SuspiciousPathIDs {
		writeCanonicalLine(&builder, string(identifier))
	}
	return sha256Digest([]byte(builder.String()))
}

func buildSignal(
	detector *Detector,
	ruleID RuleID,
	classification Classification,
	group GroupKey,
	windowStart time.Time,
	windowEnd time.Time,
	metrics Metrics,
	evidenceIDs []string,
) Signal {
	evidenceIDs = sortedUniqueStrings(evidenceIDs)
	evidenceDigest := digestEvidenceIDs(evidenceIDs)

	var builder strings.Builder
	writeCanonicalLine(&builder, "sentinelflow-deterministic-signal-v1")
	writeCanonicalLine(&builder, detector.config.Version)
	writeCanonicalLine(&builder, detector.configDigest)
	writeCanonicalLine(&builder, string(ruleID))
	writeCanonicalLine(&builder, string(classification))
	writeCanonicalLine(&builder, group.SourceIP)
	writeCanonicalLine(&builder, group.ServiceLabel)
	writeCanonicalLine(&builder, formatTime(windowStart))
	writeCanonicalLine(&builder, formatTime(windowEnd))
	writeCanonicalLine(&builder, strconv.Itoa(metrics.EventCount))
	writeCanonicalLine(&builder, strconv.Itoa(metrics.DistinctSuspiciousPathCount))
	writeCanonicalLine(&builder, strconv.Itoa(metrics.DistinctAccountCount))
	writeCanonicalLine(&builder, evidenceDigest)
	for _, eventID := range evidenceIDs {
		writeCanonicalLine(&builder, eventID)
	}
	canonical := []byte(builder.String())
	sum := sha256.Sum256(canonical)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	return Signal{
		SignalID:             uuidV8FromDigest(sum),
		RuleID:               ruleID,
		Classification:       classification,
		ConfigurationVersion: detector.config.Version,
		ConfigurationDigest:  detector.configDigest,
		SourceIP:             group.SourceIP,
		ServiceLabel:         group.ServiceLabel,
		WindowStart:          canonicalTime(windowStart),
		WindowEnd:            canonicalTime(windowEnd),
		Metrics:              metrics,
		EvidenceIDs:          evidenceIDs,
		EvidenceDigest:       evidenceDigest,
		Digest:               digest,
		SourceHealthStatus:   SourceHealthStatusComplete,
	}
}

func digestEvidenceIDs(values []string) string {
	var builder strings.Builder
	writeCanonicalLine(&builder, "sentinelflow-evidence-ids-v1")
	for _, value := range sortedUniqueStrings(values) {
		writeCanonicalLine(&builder, value)
	}
	return sha256Digest([]byte(builder.String()))
}

func sortedUniqueStrings(values []string) []string {
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

func uuidV8FromDigest(sum [sha256.Size]byte) string {
	bytes := [16]byte{}
	copy(bytes[:], sum[:16])
	bytes[6] = (bytes[6] & 0x0f) | 0x80
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

func writeCanonicalLine(builder *strings.Builder, value string) {
	builder.WriteString(strconv.Itoa(len(value)))
	builder.WriteByte(':')
	builder.WriteString(value)
	builder.WriteByte('\n')
}

func formatTime(value time.Time) string {
	return canonicalTime(value).Format(time.RFC3339Nano)
}
