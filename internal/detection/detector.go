package detection

import (
	"sort"
	"time"
)

type gatewayGroup struct {
	key    GroupKey
	events []GatewayEvent
}

type authGroup struct {
	key    GroupKey
	events []AuthEvent
}

// Evaluate applies all frozen rules without I/O, wall-clock reads, mutable
// global state, or AI involvement.
func (d *Detector) Evaluate(input EvaluationInput) (Output, error) {
	input, err := normalizeInput(input, d.config)
	if err != nil {
		return Output{}, err
	}

	return Output{
		ConfigurationVersion: d.config.Version,
		ConfigurationDigest:  d.configDigest,
		PathScan:             d.evaluatePathScan(input),
		RequestBurst:         d.evaluateRequestBurst(input),
		LoginBruteForce:      d.evaluateLoginBruteForce(input),
		CredentialStuffing:   d.evaluateCredentialStuffing(input),
	}, nil
}

func (d *Detector) evaluatePathScan(input EvaluationInput) []RuleEvaluation {
	start := input.Now.Add(-d.config.PathScanWindow)
	groups := groupGatewayEvents(input.GatewayEvents, start, input.Now)
	result := make([]RuleEvaluation, 0, len(groups))
	for _, group := range groups {
		evaluation := baseEvaluation(RulePathScan, group.key, start, input.Now, Metrics{
			DistinctSuspiciousPathCount: d.config.PathScanThreshold,
		})
		evidence := make([]string, 0, len(group.events))
		distinct := make(map[SuspiciousPathID]struct{}, d.config.PathScanThreshold)
		untrusted := false
		for _, event := range group.events {
			if event.SuspiciousPathID == SuspiciousPathNone {
				continue
			}
			if event.TimestampTrust != TimestampTrusted {
				untrusted = true
				continue
			}
			evidence = append(evidence, event.EventID)
			distinct[event.SuspiciousPathID] = struct{}{}
		}
		evaluation.Observed = Metrics{
			EventCount:                  len(evidence),
			DistinctSuspiciousPathCount: len(distinct),
		}
		complete := healthComplete(input.GatewayHealth, start, input.Now)
		finalizeEvaluation(d, &evaluation, complete, untrusted, false,
			len(distinct) >= d.config.PathScanThreshold,
			ClassificationPathScan, evidence)
		result = append(result, evaluation)
	}
	return result
}

func (d *Detector) evaluateRequestBurst(input EvaluationInput) []RuleEvaluation {
	start := input.Now.Add(-d.config.RequestBurstWindow)
	groups := groupGatewayEvents(input.GatewayEvents, start, input.Now)
	result := make([]RuleEvaluation, 0, len(groups))
	for _, group := range groups {
		evaluation := baseEvaluation(RuleRequestBurst, group.key, start, input.Now, Metrics{
			EventCount: d.config.RequestBurstThreshold,
		})
		evidence := make([]string, 0, len(group.events))
		untrusted := false
		for _, event := range group.events {
			if event.TimestampTrust != TimestampTrusted {
				untrusted = true
				continue
			}
			evidence = append(evidence, event.EventID)
		}
		evaluation.Observed = Metrics{EventCount: len(evidence)}
		complete := healthComplete(input.GatewayHealth, start, input.Now)
		finalizeEvaluation(d, &evaluation, complete, untrusted, false,
			len(evidence) >= d.config.RequestBurstThreshold,
			ClassificationRequestBurst, evidence)
		result = append(result, evaluation)
	}
	return result
}

func (d *Detector) evaluateLoginBruteForce(input EvaluationInput) []RuleEvaluation {
	start := input.Now.Add(-d.config.LoginBruteForceWindow)
	groups := groupGatewayEvents(input.GatewayEvents, start, input.Now)
	result := make([]RuleEvaluation, 0, len(groups))
	for _, group := range groups {
		evaluation := baseEvaluation(RuleLoginBruteForce, group.key, start, input.Now, Metrics{
			EventCount: d.config.LoginBruteForceThreshold,
		})
		evidence := make([]string, 0, len(group.events))
		untrusted := false
		unverified := false
		for _, event := range group.events {
			if event.RouteLabel != d.config.LoginRouteLabel || (event.StatusCode != 401 && event.StatusCode != 403) {
				continue
			}
			if event.TimestampTrust != TimestampTrusted {
				untrusted = true
				continue
			}
			if event.AuthenticationMatch != BindingVerified {
				unverified = true
				continue
			}
			evidence = append(evidence, event.EventID)
		}
		evaluation.Observed = Metrics{EventCount: len(evidence)}
		// A verified login response is a cross-producer fact. Gateway coverage
		// alone cannot prove that missing application-auth evidence was not lost,
		// so both independently checkpointed sources must cover the full rule
		// window before the result may support enforcement.
		complete := healthComplete(input.GatewayHealth, start, input.Now) &&
			healthComplete(input.AuthHealth, start, input.Now)
		finalizeEvaluation(d, &evaluation, complete, untrusted, unverified,
			len(evidence) >= d.config.LoginBruteForceThreshold,
			ClassificationLoginBruteForce, evidence)
		result = append(result, evaluation)
	}
	return result
}

func (d *Detector) evaluateCredentialStuffing(input EvaluationInput) []RuleEvaluation {
	start := input.Now.Add(-d.config.CredentialStuffingWindow)
	groups := groupAuthEvents(input.AuthEvents, start, input.Now)
	result := make([]RuleEvaluation, 0, len(groups))
	for _, group := range groups {
		evaluation := baseEvaluation(RuleCredentialStuffing, group.key, start, input.Now, Metrics{
			EventCount:           d.config.CredentialStuffingEventThreshold,
			DistinctAccountCount: d.config.CredentialStuffingAccountThreshold,
		})
		evidence := make([]string, 0, len(group.events))
		accounts := make(map[string]struct{}, d.config.CredentialStuffingAccountThreshold)
		untrusted := false
		unverified := false
		for _, event := range group.events {
			if event.Outcome != AuthOutcomeFailed {
				continue
			}
			if event.TimestampTrust != TimestampTrusted {
				untrusted = true
				continue
			}
			if event.GatewayBinding != BindingVerified {
				unverified = true
				continue
			}
			evidence = append(evidence, event.EventID)
			accounts[event.AccountHash] = struct{}{}
		}
		evaluation.Observed = Metrics{
			EventCount:           len(evidence),
			DistinctAccountCount: len(accounts),
		}
		complete := healthComplete(input.AuthHealth, start, input.Now)
		matched := len(evidence) >= d.config.CredentialStuffingEventThreshold &&
			len(accounts) >= d.config.CredentialStuffingAccountThreshold
		finalizeEvaluation(d, &evaluation, complete, untrusted, unverified,
			matched, ClassificationCredentialStuffing, evidence)
		result = append(result, evaluation)
	}
	return result
}

func baseEvaluation(ruleID RuleID, group GroupKey, start, end time.Time, threshold Metrics) RuleEvaluation {
	return RuleEvaluation{
		RuleID:      ruleID,
		Group:       group,
		WindowStart: canonicalTime(start),
		WindowEnd:   canonicalTime(end),
		Threshold:   threshold,
	}
}

func finalizeEvaluation(
	detector *Detector,
	evaluation *RuleEvaluation,
	healthIsComplete bool,
	hasUntrustedTimestamp bool,
	hasUnverifiedBinding bool,
	thresholdMet bool,
	classification Classification,
	evidenceIDs []string,
) {
	evaluation.SourceHealthStatus = SourceHealthStatusComplete
	if !healthIsComplete {
		evaluation.SourceHealthStatus = SourceHealthStatusIncomplete
	}
	switch {
	case !healthIsComplete:
		evaluation.Decision = DecisionIncomplete
		evaluation.Reason = ReasonSourceHealthIncomplete
	case hasUntrustedTimestamp:
		evaluation.Decision = DecisionIncomplete
		evaluation.Reason = ReasonTimestampUntrusted
	case hasUnverifiedBinding:
		evaluation.Decision = DecisionIncomplete
		evaluation.Reason = ReasonBindingNotVerified
	case !thresholdMet:
		evaluation.Decision = DecisionNoMatch
		evaluation.Reason = ReasonBelowThreshold
	default:
		evaluation.Decision = DecisionMatched
		evaluation.Reason = ReasonThresholdMet
		evaluation.EnforcementSupporting = true
		signal := buildSignal(detector, evaluation.RuleID, classification, evaluation.Group,
			evaluation.WindowStart, evaluation.WindowEnd, evaluation.Observed, evidenceIDs)
		evaluation.Signal = &signal
	}
}

func groupGatewayEvents(values []GatewayEvent, start, end time.Time) []gatewayGroup {
	groups := make(map[GroupKey][]GatewayEvent)
	for _, value := range values {
		if value.OccurredAt.Before(start) || value.OccurredAt.After(end) {
			continue
		}
		key := GroupKey{SourceIP: value.SourceIP, ServiceLabel: value.ServiceLabel}
		groups[key] = append(groups[key], value)
	}
	keys := sortedGroupKeys(groups)
	result := make([]gatewayGroup, 0, len(keys))
	for _, key := range keys {
		result = append(result, gatewayGroup{key: key, events: groups[key]})
	}
	return result
}

func groupAuthEvents(values []AuthEvent, start, end time.Time) []authGroup {
	groups := make(map[GroupKey][]AuthEvent)
	for _, value := range values {
		if value.OccurredAt.Before(start) || value.OccurredAt.After(end) {
			continue
		}
		key := GroupKey{SourceIP: value.SourceIP, ServiceLabel: value.ServiceLabel}
		groups[key] = append(groups[key], value)
	}
	keys := sortedGroupKeys(groups)
	result := make([]authGroup, 0, len(keys))
	for _, key := range keys {
		result = append(result, authGroup{key: key, events: groups[key]})
	}
	return result
}

func sortedGroupKeys[T any](groups map[GroupKey][]T) []GroupKey {
	keys := make([]GroupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].SourceIP == keys[j].SourceIP {
			return keys[i].ServiceLabel < keys[j].ServiceLabel
		}
		return keys[i].SourceIP < keys[j].SourceIP
	})
	return keys
}

func healthComplete(health SourceHealth, start, end time.Time) bool {
	if !health.Complete || health.CoverageStart.After(start) || health.CoverageEnd.Before(end) {
		return false
	}
	for _, interval := range health.Intervals {
		if intervalsOverlap(interval.Start, interval.End, start, end) {
			return false
		}
	}
	return true
}

func intervalsOverlap(intervalStart, intervalEnd, windowStart, windowEnd time.Time) bool {
	if intervalStart.After(windowEnd) {
		return false
	}
	return intervalEnd.IsZero() || !intervalEnd.Before(windowStart)
}
