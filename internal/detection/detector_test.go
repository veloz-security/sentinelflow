package detection

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"testing"
	"time"
)

var testNow = time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC)

func TestDefaultConfigIsFrozenVersionedAndDefensive(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	detector, err := New(config)
	if err != nil {
		t.Fatalf("New(DefaultConfig()) error = %v", err)
	}
	if detector.ConfigurationDigest() == "" {
		t.Fatal("configuration digest is empty")
	}

	config.SuspiciousPathIDs[0] = SuspiciousPathNone
	got := detector.Config()
	if slices.Contains(got.SuspiciousPathIDs, SuspiciousPathNone) {
		t.Fatal("constructor retained caller-owned suspicious path slice")
	}
	got.SuspiciousPathIDs[0] = SuspiciousPathNone
	if slices.Contains(detector.Config().SuspiciousPathIDs, SuspiciousPathNone) {
		t.Fatal("Config returned mutable detector state")
	}

	invalid := DefaultConfig()
	invalid.RequestBurstThreshold--
	if _, err := New(invalid); err == nil {
		t.Fatal("New accepted drift from the frozen request-burst threshold")
	}
	invalid = DefaultConfig()
	invalid.SuspiciousPathIDs = append(invalid.SuspiciousPathIDs, SuspiciousPathAdminConsole)
	if _, err := New(invalid); err == nil {
		t.Fatal("New accepted a duplicate path-catalog identifier")
	}
}

func TestPathScanThresholdsAndEvidence(t *testing.T) {
	t.Parallel()

	pathIDs := defaultSuspiciousPathIDs()
	tests := []struct {
		name     string
		count    int
		matched  bool
		evidence int
	}{
		{name: "below", count: 7, matched: false, evidence: 7},
		{name: "at", count: 8, matched: true, evidence: 8},
		{name: "above with repeated classification", count: 9, matched: true, evidence: 9},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validInput()
			for index := 0; index < test.count; index++ {
				event := gatewayEvent(index + 1)
				event.SuspiciousPathID = pathIDs[index%len(pathIDs)]
				input.GatewayEvents = append(input.GatewayEvents, event)
			}
			output := evaluateOK(t, input)
			evaluation := onlyEvaluation(t, output.PathScan)
			assertMatched(t, evaluation, test.matched)
			if evaluation.Observed.EventCount != test.evidence {
				t.Fatalf("event count = %d, want %d", evaluation.Observed.EventCount, test.evidence)
			}
			wantDistinct := min(test.count, len(pathIDs))
			if evaluation.Observed.DistinctSuspiciousPathCount != wantDistinct {
				t.Fatalf("distinct path count = %d, want %d", evaluation.Observed.DistinctSuspiciousPathCount, wantDistinct)
			}
			if test.matched {
				assertCanonicalSignal(t, evaluation.Signal, test.evidence)
				if evaluation.Signal.RuleID != RulePathScan || evaluation.Signal.Classification != ClassificationPathScan {
					t.Fatalf("path signal identity = %s/%s", evaluation.Signal.RuleID, evaluation.Signal.Classification)
				}
			}
		})
	}
}

func TestRequestBurstInclusiveThresholds(t *testing.T) {
	t.Parallel()

	for _, count := range []int{119, 120, 121} {
		count := count
		t.Run(fmt.Sprintf("count_%d", count), func(t *testing.T) {
			t.Parallel()
			input := validInput()
			for index := 0; index < count; index++ {
				input.GatewayEvents = append(input.GatewayEvents, gatewayEvent(index+1))
			}
			evaluation := onlyEvaluation(t, evaluateOK(t, input).RequestBurst)
			assertMatched(t, evaluation, count >= RequestBurstThreshold)
			if evaluation.Observed.EventCount != count {
				t.Fatalf("observed event count = %d, want %d", evaluation.Observed.EventCount, count)
			}
			if count >= RequestBurstThreshold && (evaluation.Signal.RuleID != RuleRequestBurst || evaluation.Signal.Classification != ClassificationRequestBurst) {
				t.Fatalf("request-burst signal identity = %s/%s", evaluation.Signal.RuleID, evaluation.Signal.Classification)
			}
		})
	}
}

func TestLoginBruteForceRequiresVerifiedLoginFailures(t *testing.T) {
	t.Parallel()

	for _, count := range []int{9, 10, 11} {
		count := count
		t.Run(fmt.Sprintf("count_%d", count), func(t *testing.T) {
			t.Parallel()
			input := validInput()
			for index := 0; index < count; index++ {
				event := gatewayEvent(index + 1)
				event.RouteLabel = DefaultLoginRouteLabel
				event.StatusCode = 401
				if index%2 == 1 {
					event.StatusCode = 403
				}
				event.AuthenticationMatch = BindingVerified
				input.GatewayEvents = append(input.GatewayEvents, event)
			}
			// These trusted events are deliberately non-qualifying.
			nonLogin := gatewayEvent(1000)
			nonLogin.StatusCode = 401
			nonLogin.AuthenticationMatch = BindingVerified
			input.GatewayEvents = append(input.GatewayEvents, nonLogin)
			success := gatewayEvent(1001)
			success.RouteLabel = DefaultLoginRouteLabel
			success.StatusCode = 200
			success.AuthenticationMatch = BindingVerified
			input.GatewayEvents = append(input.GatewayEvents, success)

			evaluation := onlyEvaluation(t, evaluateOK(t, input).LoginBruteForce)
			assertMatched(t, evaluation, count >= LoginBruteForceThreshold)
			if evaluation.Observed.EventCount != count {
				t.Fatalf("observed event count = %d, want %d", evaluation.Observed.EventCount, count)
			}
			if count >= LoginBruteForceThreshold && (evaluation.Signal.RuleID != RuleLoginBruteForce || evaluation.Signal.Classification != ClassificationLoginBruteForce) {
				t.Fatalf("brute-force signal identity = %s/%s", evaluation.Signal.RuleID, evaluation.Signal.Classification)
			}
		})
	}
}

func TestLoginBruteForceRequiresCompleteAuthSourceCoverage(t *testing.T) {
	t.Parallel()
	input := validInput()
	for index := 0; index < LoginBruteForceThreshold; index++ {
		input.GatewayEvents = append(input.GatewayEvents, loginFailure(index+1))
	}
	input.AuthHealth.Complete = false
	evaluation := onlyEvaluation(t, evaluateOK(t, input).LoginBruteForce)
	assertIncomplete(t, evaluation, ReasonSourceHealthIncomplete)
	if evaluation.Signal != nil || evaluation.EnforcementSupporting {
		t.Fatal("brute-force signal survived incomplete auth-source coverage")
	}
}

func TestCredentialStuffingRequiresBothThresholds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		events   int
		accounts int
		matched  bool
	}{
		{name: "below event threshold", events: 19, accounts: 8, matched: false},
		{name: "below account threshold", events: 20, accounts: 7, matched: false},
		{name: "at both thresholds", events: 20, accounts: 8, matched: true},
		{name: "above both thresholds", events: 21, accounts: 9, matched: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validInput()
			for index := 0; index < test.events; index++ {
				event := authEvent(index + 1)
				event.AccountHash = accountHash((index % test.accounts) + 1)
				input.AuthEvents = append(input.AuthEvents, event)
			}
			// A verified success must never inflate either threshold.
			success := authEvent(1000)
			success.Outcome = AuthOutcomeSucceeded
			success.AccountHash = accountHash(1000)
			input.AuthEvents = append(input.AuthEvents, success)

			evaluation := onlyEvaluation(t, evaluateOK(t, input).CredentialStuffing)
			assertMatched(t, evaluation, test.matched)
			if evaluation.Observed.EventCount != test.events {
				t.Fatalf("event count = %d, want %d", evaluation.Observed.EventCount, test.events)
			}
			if evaluation.Observed.DistinctAccountCount != test.accounts {
				t.Fatalf("account count = %d, want %d", evaluation.Observed.DistinctAccountCount, test.accounts)
			}
			if test.matched && (evaluation.Signal.RuleID != RuleCredentialStuffing || evaluation.Signal.Classification != ClassificationCredentialStuffing) {
				t.Fatalf("credential-stuffing signal identity = %s/%s", evaluation.Signal.RuleID, evaluation.Signal.Classification)
			}
		})
	}
}

func TestInclusiveWindowBoundariesAndFutureEvents(t *testing.T) {
	t.Parallel()

	input := validInput()
	for index := 0; index < RequestBurstThreshold-1; index++ {
		input.GatewayEvents = append(input.GatewayEvents, gatewayEvent(index+1))
	}
	atBoundary := gatewayEvent(500)
	atBoundary.OccurredAt = testNow.Add(-RequestBurstWindow)
	input.GatewayEvents = append(input.GatewayEvents, atBoundary)
	tooOld := gatewayEvent(501)
	tooOld.OccurredAt = testNow.Add(-RequestBurstWindow - time.Nanosecond)
	input.GatewayEvents = append(input.GatewayEvents, tooOld)
	future := gatewayEvent(502)
	future.OccurredAt = testNow.Add(time.Nanosecond)
	input.GatewayEvents = append(input.GatewayEvents, future)

	evaluation := onlyEvaluation(t, evaluateOK(t, input).RequestBurst)
	assertMatched(t, evaluation, true)
	if evaluation.Observed.EventCount != RequestBurstThreshold {
		t.Fatalf("observed event count = %d, want %d", evaluation.Observed.EventCount, RequestBurstThreshold)
	}
	if slices.Contains(evaluation.Signal.EvidenceIDs, tooOld.EventID) || slices.Contains(evaluation.Signal.EvidenceIDs, future.EventID) {
		t.Fatal("out-of-window event entered evidence")
	}
}

func TestGroupingPreventsCrossSourceAndServiceLeakage(t *testing.T) {
	t.Parallel()

	input := validInput()
	for index := 0; index < RequestBurstThreshold; index++ {
		event := gatewayEvent(index + 1)
		if index >= RequestBurstThreshold/2 {
			event.SourceIP = "198.51.100.10"
		}
		if index%2 == 1 {
			event.ServiceLabel = "other"
		}
		input.GatewayEvents = append(input.GatewayEvents, event)
	}
	for _, evaluation := range evaluateOK(t, input).RequestBurst {
		if evaluation.Decision == DecisionMatched {
			t.Fatalf("cross-group events produced a signal for %+v", evaluation.Group)
		}
	}
}

func TestDuplicateAndInputOrderAreIdempotent(t *testing.T) {
	t.Parallel()

	input := validInput()
	for index := 0; index < RequestBurstThreshold; index++ {
		event := gatewayEvent(index + 1)
		event.OccurredAt = testNow.Add(-time.Second)
		input.GatewayEvents = append(input.GatewayEvents, event)
	}
	input.GatewayEvents = append(input.GatewayEvents, input.GatewayEvents[0])
	first := evaluateOK(t, input)
	slices.Reverse(input.GatewayEvents)
	second := evaluateOK(t, input)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("input order changed deterministic output\nfirst: %#v\nsecond: %#v", first, second)
	}
	evaluation := onlyEvaluation(t, first.RequestBurst)
	if evaluation.Observed.EventCount != RequestBurstThreshold {
		t.Fatalf("duplicate inflated count to %d", evaluation.Observed.EventCount)
	}
	assertCanonicalSignal(t, evaluation.Signal, RequestBurstThreshold)

	conflict := input
	conflict.GatewayEvents = append([]GatewayEvent(nil), input.GatewayEvents...)
	duplicate := conflict.GatewayEvents[0]
	duplicate.StatusCode = 500
	conflict.GatewayEvents = append(conflict.GatewayEvents, duplicate)
	_, err := NewDefault().Evaluate(conflict)
	var inputErr *InputError
	if !errors.As(err, &inputErr) || inputErr.Code != "conflicting_duplicate" {
		t.Fatalf("conflicting duplicate error = %v, want InputError/conflicting_duplicate", err)
	}
}

func TestTrustAndBindingFailuresFailClosed(t *testing.T) {
	t.Parallel()

	t.Run("request timestamp", func(t *testing.T) {
		input := validInput()
		for index := 0; index < RequestBurstThreshold; index++ {
			input.GatewayEvents = append(input.GatewayEvents, gatewayEvent(index+1))
		}
		untrusted := gatewayEvent(1000)
		untrusted.TimestampTrust = TimestampUntrusted
		input.GatewayEvents = append(input.GatewayEvents, untrusted)
		assertIncomplete(t, onlyEvaluation(t, evaluateOK(t, input).RequestBurst), ReasonTimestampUntrusted)
	})

	t.Run("login pending binding", func(t *testing.T) {
		input := validInput()
		for index := 0; index < LoginBruteForceThreshold; index++ {
			event := loginFailure(index + 1)
			input.GatewayEvents = append(input.GatewayEvents, event)
		}
		pending := loginFailure(1000)
		pending.AuthenticationMatch = BindingPending
		input.GatewayEvents = append(input.GatewayEvents, pending)
		assertIncomplete(t, onlyEvaluation(t, evaluateOK(t, input).LoginBruteForce), ReasonBindingNotVerified)
	})

	t.Run("credential untrusted timestamp", func(t *testing.T) {
		input := credentialInput(CredentialStuffingEventThreshold, CredentialStuffingAccountThreshold)
		untrusted := authEvent(1000)
		untrusted.TimestampTrust = TimestampUntrusted
		input.AuthEvents = append(input.AuthEvents, untrusted)
		assertIncomplete(t, onlyEvaluation(t, evaluateOK(t, input).CredentialStuffing), ReasonTimestampUntrusted)
	})

	t.Run("credential pending binding", func(t *testing.T) {
		input := credentialInput(CredentialStuffingEventThreshold, CredentialStuffingAccountThreshold)
		pending := authEvent(1000)
		pending.GatewayBinding = BindingPending
		input.AuthEvents = append(input.AuthEvents, pending)
		assertIncomplete(t, onlyEvaluation(t, evaluateOK(t, input).CredentialStuffing), ReasonBindingNotVerified)
	})
}

func TestSourceHealthCoverageAndIntervalsFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*SourceHealth)
	}{
		{name: "declared incomplete", mutate: func(health *SourceHealth) { health.Complete = false }},
		{name: "coverage starts late", mutate: func(health *SourceHealth) { health.CoverageStart = testNow.Add(-5 * time.Second) }},
		{name: "coverage ends early", mutate: func(health *SourceHealth) { health.CoverageEnd = testNow.Add(-time.Nanosecond) }},
		{name: "degraded overlap", mutate: func(health *SourceHealth) {
			health.Intervals = []HealthInterval{{State: HealthDegraded, Start: testNow.Add(-5 * time.Second), End: testNow}}
		}},
		{name: "open loss", mutate: func(health *SourceHealth) {
			health.Intervals = []HealthInterval{{State: HealthLost, Start: testNow.Add(-5 * time.Second)}}
		}},
		{name: "gap overlap", mutate: func(health *SourceHealth) {
			health.Intervals = []HealthInterval{{State: HealthGapped, Start: testNow.Add(-5 * time.Second), End: testNow.Add(-4 * time.Second)}}
		}},
		{name: "unknown loss overlap", mutate: func(health *SourceHealth) {
			health.Intervals = []HealthInterval{{State: HealthUnknownLoss, Start: testNow.Add(-5 * time.Second), End: testNow.Add(-4 * time.Second)}}
		}},
		{name: "recovered overlap", mutate: func(health *SourceHealth) {
			health.Intervals = []HealthInterval{{State: HealthRecovered, Start: testNow.Add(-10 * time.Second), End: testNow.Add(-10 * time.Second)}}
		}},
		{name: "inclusive edge overlap", mutate: func(health *SourceHealth) {
			health.Intervals = []HealthInterval{{State: HealthRecovered, Start: testNow.Add(-20 * time.Second), End: testNow.Add(-RequestBurstWindow)}}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validInput()
			for index := 0; index < RequestBurstThreshold; index++ {
				input.GatewayEvents = append(input.GatewayEvents, gatewayEvent(index+1))
			}
			test.mutate(&input.GatewayHealth)
			assertIncomplete(t, onlyEvaluation(t, evaluateOK(t, input).RequestBurst), ReasonSourceHealthIncomplete)
		})
	}

	t.Run("recovered interval outside window does not poison current coverage", func(t *testing.T) {
		input := validInput()
		for index := 0; index < RequestBurstThreshold; index++ {
			input.GatewayEvents = append(input.GatewayEvents, gatewayEvent(index+1))
		}
		input.GatewayHealth.Intervals = []HealthInterval{{
			State: HealthRecovered,
			Start: testNow.Add(-time.Minute),
			End:   testNow.Add(-time.Minute + time.Second),
		}}
		assertMatched(t, onlyEvaluation(t, evaluateOK(t, input).RequestBurst), true)
	})
}

func TestMinimizedInputTypesHaveClosedFieldSets(t *testing.T) {
	t.Parallel()

	assertFields(t, reflect.TypeFor[GatewayEvent](), []string{
		"EventID", "OccurredAt", "SourceIP", "ServiceLabel", "RouteLabel",
		"PathCatalogVersion", "SuspiciousPathID", "StatusCode", "TimestampTrust", "AuthenticationMatch",
	})
	assertFields(t, reflect.TypeFor[AuthEvent](), []string{
		"EventID", "OccurredAt", "SourceIP", "ServiceLabel", "RouteLabel",
		"AccountHash", "Outcome", "TimestampTrust", "GatewayBinding",
	})
}

func TestInvalidInputReturnsTypedErrorAndNoOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*EvaluationInput)
	}{
		{name: "noncanonical IPv4", mutate: func(input *EvaluationInput) {
			event := gatewayEvent(1)
			event.SourceIP = "198.051.100.9"
			input.GatewayEvents = []GatewayEvent{event}
		}},
		{name: "missing trust", mutate: func(input *EvaluationInput) {
			event := gatewayEvent(1)
			event.TimestampTrust = ""
			input.GatewayEvents = []GatewayEvent{event}
		}},
		{name: "wrong health source", mutate: func(input *EvaluationInput) {
			input.GatewayHealth.Source = SourceAuth
		}},
		{name: "invalid health interval", mutate: func(input *EvaluationInput) {
			input.GatewayHealth.Intervals = []HealthInterval{{State: HealthLost, Start: testNow, End: testNow.Add(-time.Second)}}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validInput()
			test.mutate(&input)
			output, err := NewDefault().Evaluate(input)
			var inputErr *InputError
			if !errors.As(err, &inputErr) {
				t.Fatalf("error = %v, want *InputError", err)
			}
			if !reflect.DeepEqual(output, Output{}) {
				t.Fatalf("invalid input returned partial output: %#v", output)
			}
		})
	}
}

func validInput() EvaluationInput {
	return EvaluationInput{
		Now: testNow,
		GatewayHealth: SourceHealth{
			Source:        SourceGateway,
			Complete:      true,
			CoverageStart: testNow.Add(-10 * time.Minute),
			CoverageEnd:   testNow,
		},
		AuthHealth: SourceHealth{
			Source:        SourceAuth,
			Complete:      true,
			CoverageStart: testNow.Add(-10 * time.Minute),
			CoverageEnd:   testNow,
		},
	}
}

func gatewayEvent(index int) GatewayEvent {
	return GatewayEvent{
		EventID:             uuidFor(index),
		OccurredAt:          testNow.Add(-time.Second),
		SourceIP:            "198.51.100.9",
		ServiceLabel:        "app",
		RouteLabel:          "home",
		PathCatalogVersion:  DefaultPathCatalogVersion,
		SuspiciousPathID:    SuspiciousPathNone,
		StatusCode:          200,
		TimestampTrust:      TimestampTrusted,
		AuthenticationMatch: BindingNotApplicable,
	}
}

func loginFailure(index int) GatewayEvent {
	event := gatewayEvent(index)
	event.RouteLabel = DefaultLoginRouteLabel
	event.StatusCode = 401
	event.AuthenticationMatch = BindingVerified
	return event
}

func authEvent(index int) AuthEvent {
	return AuthEvent{
		EventID:        uuidFor(index),
		OccurredAt:     testNow.Add(-time.Second),
		SourceIP:       "198.51.100.9",
		ServiceLabel:   "app",
		RouteLabel:     DefaultLoginRouteLabel,
		AccountHash:    accountHash(index),
		Outcome:        AuthOutcomeFailed,
		TimestampTrust: TimestampTrusted,
		GatewayBinding: BindingVerified,
	}
}

func credentialInput(eventCount, accountCount int) EvaluationInput {
	input := validInput()
	for index := 0; index < eventCount; index++ {
		event := authEvent(index + 1)
		event.AccountHash = accountHash((index % accountCount) + 1)
		input.AuthEvents = append(input.AuthEvents, event)
	}
	return input
}

func uuidFor(index int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", index)
}

func accountHash(index int) string {
	return "hmac-sha256:" + fmt.Sprintf("%064x", index)
}

func evaluateOK(t *testing.T, input EvaluationInput) Output {
	t.Helper()
	output, err := NewDefault().Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate error = %v", err)
	}
	return output
}

func onlyEvaluation(t *testing.T, values []RuleEvaluation) RuleEvaluation {
	t.Helper()
	if len(values) != 1 {
		t.Fatalf("evaluation count = %d, want 1", len(values))
	}
	return values[0]
}

func assertMatched(t *testing.T, evaluation RuleEvaluation, want bool) {
	t.Helper()
	if want {
		if evaluation.Decision != DecisionMatched || !evaluation.EnforcementSupporting || evaluation.Signal == nil ||
			evaluation.SourceHealthStatus != SourceHealthStatusComplete || evaluation.Signal.SourceHealthStatus != SourceHealthStatusComplete {
			t.Fatalf("evaluation = %#v, want enforcement-supporting match", evaluation)
		}
		return
	}
	if evaluation.Decision != DecisionNoMatch || evaluation.EnforcementSupporting || evaluation.Signal != nil {
		t.Fatalf("evaluation = %#v, want no match", evaluation)
	}
}

func assertIncomplete(t *testing.T, evaluation RuleEvaluation, reason DecisionReason) {
	t.Helper()
	if evaluation.Decision != DecisionIncomplete || evaluation.Reason != reason || evaluation.EnforcementSupporting || evaluation.Signal != nil ||
		(reason == ReasonSourceHealthIncomplete && evaluation.SourceHealthStatus != SourceHealthStatusIncomplete) {
		t.Fatalf("evaluation = %#v, want incomplete/%s with no signal", evaluation, reason)
	}
}

func assertCanonicalSignal(t *testing.T, signal *Signal, evidenceCount int) {
	t.Helper()
	if signal == nil {
		t.Fatal("signal is nil")
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(signal.SignalID) {
		t.Fatalf("signal ID = %q, want deterministic UUIDv8", signal.SignalID)
	}
	for name, value := range map[string]string{
		"configuration": signal.ConfigurationDigest,
		"evidence":      signal.EvidenceDigest,
		"signal":        signal.Digest,
	} {
		if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(value) {
			t.Fatalf("%s digest = %q", name, value)
		}
	}
	if len(signal.EvidenceIDs) != evidenceCount {
		t.Fatalf("evidence count = %d, want %d", len(signal.EvidenceIDs), evidenceCount)
	}
	if !slices.IsSorted(signal.EvidenceIDs) {
		t.Fatalf("evidence IDs are not sorted: %v", signal.EvidenceIDs)
	}
	for index := 1; index < len(signal.EvidenceIDs); index++ {
		if signal.EvidenceIDs[index-1] == signal.EvidenceIDs[index] {
			t.Fatalf("duplicate evidence ID %q", signal.EvidenceIDs[index])
		}
	}
}

func assertFields(t *testing.T, value reflect.Type, expected []string) {
	t.Helper()
	actual := make([]string, 0, value.NumField())
	for index := 0; index < value.NumField(); index++ {
		actual = append(actual, value.Field(index).Name)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("%s fields = %v, want exact minimized field set %v", value.Name(), actual, expected)
	}
}
