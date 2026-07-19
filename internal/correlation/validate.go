package correlation

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	labelPattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

func normalizeSignals(values []detection.Signal) ([]detection.Signal, error) {
	byID := make(map[string]detection.Signal, len(values))
	for index, value := range values {
		value = cloneSignal(value)
		if err := validateSignal(value, fmt.Sprintf("signals[%d]", index)); err != nil {
			return nil, err
		}
		if previous, exists := byID[value.SignalID]; exists {
			if !equalSignal(previous, value) {
				return nil, correlationError(ErrorConflictingSignal, value.SignalID)
			}
			continue
		}
		byID[value.SignalID] = value
	}
	result := make([]detection.Signal, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	sortSignals(result)
	return result, nil
}

func validateSignal(signal detection.Signal, field string) error {
	if !uuidPattern.MatchString(signal.SignalID) {
		return correlationError(ErrorInvalidInput, field+".signal_id")
	}
	if !validRuleClassification(signal.RuleID, signal.Classification) {
		return correlationError(ErrorInvalidInput, field+".rule_classification")
	}
	if !versionPattern.MatchString(signal.ConfigurationVersion) {
		return correlationError(ErrorInvalidInput, field+".configuration_version")
	}
	if !digestPattern.MatchString(signal.ConfigurationDigest) {
		return correlationError(ErrorInvalidInput, field+".configuration_digest")
	}
	if err := validateCanonicalIPv4(signal.SourceIP); err != nil {
		return correlationError(ErrorInvalidInput, field+".source_ip")
	}
	if !labelPattern.MatchString(signal.ServiceLabel) {
		return correlationError(ErrorInvalidInput, field+".service_label")
	}
	if signal.WindowStart.IsZero() || signal.WindowEnd.IsZero() || signal.WindowEnd.Before(signal.WindowStart) {
		return correlationError(ErrorInvalidInput, field+".window")
	}
	if signal.Metrics.EventCount < 1 || signal.Metrics.EventCount > 1_000_000 ||
		signal.Metrics.DistinctAccountCount < 0 || signal.Metrics.DistinctAccountCount > 1_000_000 ||
		signal.Metrics.DistinctSuspiciousPathCount < 0 || signal.Metrics.DistinctSuspiciousPathCount > 8 {
		return correlationError(ErrorInvalidInput, field+".metrics")
	}
	if !metricsReproduceRule(signal.RuleID, signal.Metrics) {
		return correlationError(ErrorInvalidInput, field+".rule_metrics")
	}
	if signal.SourceHealthStatus != detection.SourceHealthStatusComplete {
		return correlationError(ErrorInvalidInput, field+".source_health_status")
	}
	if len(signal.EvidenceIDs) != signal.Metrics.EventCount || len(signal.EvidenceIDs) == 0 {
		return correlationError(ErrorInvalidInput, field+".evidence_ids")
	}
	for index, eventID := range signal.EvidenceIDs {
		if !uuidPattern.MatchString(eventID) {
			return correlationError(ErrorInvalidInput, field+".evidence_ids")
		}
		if index > 0 && signal.EvidenceIDs[index-1] >= eventID {
			return correlationError(ErrorInvalidInput, field+".evidence_ids_order")
		}
	}
	if !digestPattern.MatchString(signal.EvidenceDigest) || !digestPattern.MatchString(signal.Digest) {
		return correlationError(ErrorInvalidInput, field+".digest")
	}
	return nil
}

func metricsReproduceRule(rule detection.RuleID, metrics detection.Metrics) bool {
	switch rule {
	case detection.RulePathScan:
		return metrics.EventCount >= detection.PathScanThreshold &&
			metrics.DistinctSuspiciousPathCount == detection.PathScanThreshold &&
			metrics.DistinctAccountCount == 0
	case detection.RuleRequestBurst:
		return metrics.EventCount >= detection.RequestBurstThreshold &&
			metrics.DistinctAccountCount == 0 && metrics.DistinctSuspiciousPathCount == 0
	case detection.RuleLoginBruteForce:
		return metrics.EventCount >= detection.LoginBruteForceThreshold &&
			metrics.DistinctAccountCount == 0 && metrics.DistinctSuspiciousPathCount == 0
	case detection.RuleCredentialStuffing:
		return metrics.EventCount >= detection.CredentialStuffingEventThreshold &&
			metrics.DistinctAccountCount >= detection.CredentialStuffingAccountThreshold &&
			metrics.DistinctSuspiciousPathCount == 0
	default:
		return false
	}
}

func validRuleClassification(rule detection.RuleID, classification detection.Classification) bool {
	switch rule {
	case detection.RulePathScan:
		return classification == detection.ClassificationPathScan
	case detection.RuleRequestBurst:
		return classification == detection.ClassificationRequestBurst
	case detection.RuleLoginBruteForce:
		return classification == detection.ClassificationLoginBruteForce
	case detection.RuleCredentialStuffing:
		return classification == detection.ClassificationCredentialStuffing
	default:
		return false
	}
}

func validateCanonicalIPv4(value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value {
		return fmt.Errorf("invalid canonical IPv4")
	}
	return nil
}

func canonicalTime(value time.Time) time.Time {
	return value.Round(0).UTC()
}

func cloneSignal(value detection.Signal) detection.Signal {
	value.WindowStart = canonicalTime(value.WindowStart)
	value.WindowEnd = canonicalTime(value.WindowEnd)
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	return value
}

func cloneSignals(values []detection.Signal) []detection.Signal {
	result := make([]detection.Signal, len(values))
	for index, value := range values {
		result[index] = cloneSignal(value)
	}
	return result
}

func cloneRelations(values []Relation) []Relation {
	result := make([]Relation, len(values))
	for index, value := range values {
		value.SupportingReasons = append([]SupportingReason(nil), value.SupportingReasons...)
		result[index] = value
	}
	return result
}

func equalSignal(left, right detection.Signal) bool {
	if left.SignalID != right.SignalID || left.RuleID != right.RuleID || left.Classification != right.Classification ||
		left.ConfigurationVersion != right.ConfigurationVersion || left.ConfigurationDigest != right.ConfigurationDigest ||
		left.SourceIP != right.SourceIP || left.ServiceLabel != right.ServiceLabel ||
		!left.WindowStart.Equal(right.WindowStart) || !left.WindowEnd.Equal(right.WindowEnd) ||
		left.Metrics != right.Metrics || left.EvidenceDigest != right.EvidenceDigest || left.Digest != right.Digest ||
		left.SourceHealthStatus != right.SourceHealthStatus || len(left.EvidenceIDs) != len(right.EvidenceIDs) {
		return false
	}
	for index := range left.EvidenceIDs {
		if left.EvidenceIDs[index] != right.EvidenceIDs[index] {
			return false
		}
	}
	return true
}

func sortSignals(values []detection.Signal) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].SourceIP != values[j].SourceIP {
			return values[i].SourceIP < values[j].SourceIP
		}
		if !values[i].WindowStart.Equal(values[j].WindowStart) {
			return values[i].WindowStart.Before(values[j].WindowStart)
		}
		if !values[i].WindowEnd.Equal(values[j].WindowEnd) {
			return values[i].WindowEnd.Before(values[j].WindowEnd)
		}
		return values[i].SignalID < values[j].SignalID
	})
}
