package detection

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"time"
)

var (
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	labelPattern       = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	accountHashPattern = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
)

type InputError struct {
	Field string
	Code  string
}

func (e *InputError) Error() string {
	return fmt.Sprintf("detection input %s: %s", e.Field, e.Code)
}

func inputError(field, code string) error {
	return &InputError{Field: field, Code: code}
}

func normalizeInput(input EvaluationInput, config Config) (EvaluationInput, error) {
	if input.Now.IsZero() {
		return EvaluationInput{}, inputError("now", "required")
	}
	input.Now = canonicalTime(input.Now)

	var err error
	input.GatewayEvents, err = normalizeGatewayEvents(input.GatewayEvents, config)
	if err != nil {
		return EvaluationInput{}, err
	}
	input.AuthEvents, err = normalizeAuthEvents(input.AuthEvents)
	if err != nil {
		return EvaluationInput{}, err
	}
	input.GatewayHealth, err = normalizeHealth("gateway_health", input.GatewayHealth, SourceGateway)
	if err != nil {
		return EvaluationInput{}, err
	}
	input.AuthHealth, err = normalizeHealth("auth_health", input.AuthHealth, SourceAuth)
	if err != nil {
		return EvaluationInput{}, err
	}
	return input, nil
}

func normalizeGatewayEvents(values []GatewayEvent, config Config) ([]GatewayEvent, error) {
	byID := make(map[string]GatewayEvent, len(values))
	for index, value := range values {
		field := fmt.Sprintf("gateway_events[%d]", index)
		if !uuidPattern.MatchString(value.EventID) {
			return nil, inputError(field+".event_id", "invalid_uuid")
		}
		if value.OccurredAt.IsZero() {
			return nil, inputError(field+".occurred_at", "required")
		}
		if err := validateCanonicalIPv4(value.SourceIP); err != nil {
			return nil, inputError(field+".source_ip", "invalid_canonical_ipv4")
		}
		if !labelPattern.MatchString(value.ServiceLabel) {
			return nil, inputError(field+".service_label", "invalid_label")
		}
		if !labelPattern.MatchString(value.RouteLabel) {
			return nil, inputError(field+".route_label", "invalid_label")
		}
		if value.PathCatalogVersion != config.PathCatalogVersion {
			return nil, inputError(field+".path_catalog_version", "unsupported_version")
		}
		if !validSuspiciousPathID(value.SuspiciousPathID) {
			return nil, inputError(field+".suspicious_path_id", "invalid_enum")
		}
		if value.StatusCode < 100 || value.StatusCode > 599 {
			return nil, inputError(field+".status_code", "out_of_range")
		}
		if value.TimestampTrust != TimestampTrusted && value.TimestampTrust != TimestampUntrusted {
			return nil, inputError(field+".timestamp_trust", "invalid_enum")
		}
		if !validGatewayBinding(value.AuthenticationMatch) {
			return nil, inputError(field+".authentication_match", "invalid_enum")
		}
		value.OccurredAt = canonicalTime(value.OccurredAt)
		if previous, exists := byID[value.EventID]; exists {
			if !equalGatewayEvent(previous, value) {
				return nil, inputError(field+".event_id", "conflicting_duplicate")
			}
			continue
		}
		byID[value.EventID] = value
	}

	result := make([]GatewayEvent, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].OccurredAt.Equal(result[j].OccurredAt) {
			return result[i].EventID < result[j].EventID
		}
		return result[i].OccurredAt.Before(result[j].OccurredAt)
	})
	return result, nil
}

func normalizeAuthEvents(values []AuthEvent) ([]AuthEvent, error) {
	byID := make(map[string]AuthEvent, len(values))
	for index, value := range values {
		field := fmt.Sprintf("auth_events[%d]", index)
		if !uuidPattern.MatchString(value.EventID) {
			return nil, inputError(field+".event_id", "invalid_uuid")
		}
		if value.OccurredAt.IsZero() {
			return nil, inputError(field+".occurred_at", "required")
		}
		if err := validateCanonicalIPv4(value.SourceIP); err != nil {
			return nil, inputError(field+".source_ip", "invalid_canonical_ipv4")
		}
		if !labelPattern.MatchString(value.ServiceLabel) {
			return nil, inputError(field+".service_label", "invalid_label")
		}
		if !labelPattern.MatchString(value.RouteLabel) {
			return nil, inputError(field+".route_label", "invalid_label")
		}
		if !accountHashPattern.MatchString(value.AccountHash) {
			return nil, inputError(field+".account_hash", "invalid_digest")
		}
		if value.Outcome != AuthOutcomeFailed && value.Outcome != AuthOutcomeSucceeded {
			return nil, inputError(field+".outcome", "invalid_enum")
		}
		if value.TimestampTrust != TimestampTrusted && value.TimestampTrust != TimestampUntrusted {
			return nil, inputError(field+".timestamp_trust", "invalid_enum")
		}
		if value.GatewayBinding != BindingVerified && value.GatewayBinding != BindingPending && value.GatewayBinding != BindingUntrusted {
			return nil, inputError(field+".gateway_binding", "invalid_enum")
		}
		value.OccurredAt = canonicalTime(value.OccurredAt)
		if previous, exists := byID[value.EventID]; exists {
			if !equalAuthEvent(previous, value) {
				return nil, inputError(field+".event_id", "conflicting_duplicate")
			}
			continue
		}
		byID[value.EventID] = value
	}

	result := make([]AuthEvent, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].OccurredAt.Equal(result[j].OccurredAt) {
			return result[i].EventID < result[j].EventID
		}
		return result[i].OccurredAt.Before(result[j].OccurredAt)
	})
	return result, nil
}

func normalizeHealth(field string, value SourceHealth, expected SourceKind) (SourceHealth, error) {
	if value.Source != expected {
		return SourceHealth{}, inputError(field+".source", "invalid_constant")
	}
	if value.CoverageStart.IsZero() || value.CoverageEnd.IsZero() {
		return SourceHealth{}, inputError(field+".coverage", "required")
	}
	value.CoverageStart = canonicalTime(value.CoverageStart)
	value.CoverageEnd = canonicalTime(value.CoverageEnd)
	if value.CoverageEnd.Before(value.CoverageStart) {
		return SourceHealth{}, inputError(field+".coverage_end", "precedes_start")
	}
	value.Intervals = append([]HealthInterval(nil), value.Intervals...)
	for index := range value.Intervals {
		interval := &value.Intervals[index]
		intervalField := fmt.Sprintf("%s.intervals[%d]", field, index)
		if !validHealthState(interval.State) {
			return SourceHealth{}, inputError(intervalField+".state", "invalid_enum")
		}
		if interval.Start.IsZero() {
			return SourceHealth{}, inputError(intervalField+".start", "required")
		}
		interval.Start = canonicalTime(interval.Start)
		if !interval.End.IsZero() {
			interval.End = canonicalTime(interval.End)
			if interval.End.Before(interval.Start) {
				return SourceHealth{}, inputError(intervalField+".end", "precedes_start")
			}
		}
	}
	sort.Slice(value.Intervals, func(i, j int) bool {
		if value.Intervals[i].Start.Equal(value.Intervals[j].Start) {
			if value.Intervals[i].End.Equal(value.Intervals[j].End) {
				return value.Intervals[i].State < value.Intervals[j].State
			}
			if value.Intervals[i].End.IsZero() {
				return false
			}
			if value.Intervals[j].End.IsZero() {
				return true
			}
			return value.Intervals[i].End.Before(value.Intervals[j].End)
		}
		return value.Intervals[i].Start.Before(value.Intervals[j].Start)
	})
	return value, nil
}

func canonicalTime(value time.Time) time.Time {
	return value.Round(0).UTC()
}

func validateCanonicalIPv4(value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value {
		return fmt.Errorf("invalid canonical IPv4")
	}
	return nil
}

func validSuspiciousPathID(value SuspiciousPathID) bool {
	switch value {
	case SuspiciousPathNone,
		SuspiciousPathAdminConsole,
		SuspiciousPathEnvFile,
		SuspiciousPathGitConfig,
		SuspiciousPathWPAdmin,
		SuspiciousPathPHPMyAdmin,
		SuspiciousPathServerStatus,
		SuspiciousPathActuatorEnv,
		SuspiciousPathBackupArchive:
		return true
	default:
		return false
	}
}

func validGatewayBinding(value BindingState) bool {
	return value == BindingVerified || value == BindingPending || value == BindingUntrusted || value == BindingNotApplicable
}

func validHealthState(value HealthIntervalState) bool {
	return value == HealthDegraded || value == HealthLost || value == HealthGapped || value == HealthUnknownLoss || value == HealthRecovered
}

func equalGatewayEvent(left, right GatewayEvent) bool {
	return left.EventID == right.EventID &&
		left.OccurredAt.Equal(right.OccurredAt) &&
		left.SourceIP == right.SourceIP &&
		left.ServiceLabel == right.ServiceLabel &&
		left.RouteLabel == right.RouteLabel &&
		left.PathCatalogVersion == right.PathCatalogVersion &&
		left.SuspiciousPathID == right.SuspiciousPathID &&
		left.StatusCode == right.StatusCode &&
		left.TimestampTrust == right.TimestampTrust &&
		left.AuthenticationMatch == right.AuthenticationMatch
}

func equalAuthEvent(left, right AuthEvent) bool {
	return left.EventID == right.EventID &&
		left.OccurredAt.Equal(right.OccurredAt) &&
		left.SourceIP == right.SourceIP &&
		left.ServiceLabel == right.ServiceLabel &&
		left.RouteLabel == right.RouteLabel &&
		left.AccountHash == right.AccountHash &&
		left.Outcome == right.Outcome &&
		left.TimestampTrust == right.TimestampTrust &&
		left.GatewayBinding == right.GatewayBinding
}
