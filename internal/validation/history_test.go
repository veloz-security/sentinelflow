package validation

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/events"
)

var historyTestAt = time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)

func TestSealDatabaseHistoryCutoff(t *testing.T) {
	at := historyTestAt.In(time.FixedZone("database", 9*60*60)).Add(123 * time.Nanosecond)
	cutoff, err := SealDatabaseHistoryCutoff(at)
	if err != nil {
		t.Fatal(err)
	}
	if !cutoff.sealed || cutoff.authority != HistoryClockRealtime || !cutoff.At().Equal(at.Round(0).UTC()) || cutoff.At().Location() != time.UTC {
		t.Fatalf("unexpected database cutoff: %#v", cutoff)
	}
	for _, invalid := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		candidate, sealErr := SealDatabaseHistoryCutoff(invalid)
		if !errors.Is(sealErr, ErrInvalidDatabaseHistoryCutoff) || !candidate.At().IsZero() {
			t.Fatalf("invalid database cutoff accepted: cutoff=%#v err=%v", candidate, sealErr)
		}
	}
}

func TestHistoricalImpactAllowsCompleteInclusiveHistory(t *testing.T) {
	input := validHistoricalImpactInput()
	input.GatewayRecords = []HistoricalGatewayRecord{
		historyGateway("019b0000-0000-7000-8000-000000000001", historyTestAt.Add(-HistoricalImpactLookback), 200),
		historyGateway("019b0000-0000-7000-8000-000000000002", historyTestAt, 404),
	}
	input.AuthRecords = []HistoricalAuthRecord{
		historyAuth("019b0000-0000-7000-8000-000000000003", historyTestAt.Add(-time.Hour), events.AuthOutcomeFailed, detection.BindingVerified),
	}

	checked := EvaluateHistoricalImpact(input)
	if !checked.Allowed() {
		t.Fatalf("expected complete history to pass, got %+v", checked.Value())
	}
	value := checked.Value()
	if value.LookbackSeconds != 86_400 || value.GatewayRecordCount != 2 || value.Gateway2xxCount != 1 ||
		value.Gateway4xxCount != 1 || value.AuthRecordCount != 1 || value.VerifiedFailedAuthCount != 1 ||
		value.SucceededAuthCount != 0 {
		t.Fatalf("unexpected safe impact counts: %+v", value)
	}
	if !json.Valid(checked.CanonicalBytes()) || !validDigest(checked.Digest()) ||
		!bytes.Equal(checked.DigestInput(), checked.CanonicalBytes()) {
		t.Fatal("report must expose stable canonical JCS and a lowercase sha256 digest")
	}

	// Freeze the compact report representation. Input/category digests bind all
	// raw rows while the report itself remains content-free.
	const wantDigest = "sha256:300010a63e2c76b292d1d09902041036355072e758935544d70470439355c7e2"
	if checked.Digest() != wantDigest {
		t.Fatalf("historical-impact-v1 golden digest changed: got %s", checked.Digest())
	}

	first := checked.CanonicalBytes()
	first[0] = 'x'
	if !json.Valid(checked.CanonicalBytes()) {
		t.Fatal("canonical accessor must return a defensive copy")
	}
}

func TestHistoricalImpactWindowIsExactAndInclusive(t *testing.T) {
	for _, test := range []struct {
		name    string
		at      time.Time
		allowed bool
	}{
		{"start inclusive", historyTestAt.Add(-HistoricalImpactLookback), true},
		{"end inclusive", historyTestAt, true},
		{"before start", historyTestAt.Add(-HistoricalImpactLookback - time.Nanosecond), false},
		{"after end", historyTestAt.Add(time.Nanosecond), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validHistoricalImpactInput()
			input.GatewayRecords = []HistoricalGatewayRecord{historyGateway("019b0000-0000-7000-8000-000000000010", test.at, 204)}
			result := EvaluateHistoricalImpact(input)
			if result.Allowed() != test.allowed {
				t.Fatalf("allowed=%v reason=%s", result.Allowed(), result.Value().ReasonCode)
			}
			if !test.allowed && result.Value().ReasonCode != HistoryReasonInputInvalid {
				t.Fatalf("out-of-window query row must fail closed as malformed input, got %s", result.Value().ReasonCode)
			}
		})
	}
}

func TestHistoricalImpactCoverageFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HistoricalImpactInput)
		want   HistoricalImpactReason
	}{
		{"gateway unavailable", func(i *HistoricalImpactInput) { i.Coverage.GatewayStatus = HistoryQueryUnavailable }, HistoryReasonInputUnavailable},
		{"auth unavailable", func(i *HistoricalImpactInput) { i.Coverage.AuthStatus = HistoryQueryUnavailable }, HistoryReasonInputUnavailable},
		{"health unavailable", func(i *HistoricalImpactInput) { i.Coverage.SourceHealthStatus = HistoryQueryUnavailable }, HistoryReasonInputUnavailable},
		{"gap unavailable", func(i *HistoricalImpactInput) { i.Coverage.ReceiverGapStatus = HistoryQueryUnavailable }, HistoryReasonInputUnavailable},
		{"query incomplete", func(i *HistoricalImpactInput) { i.Coverage.AuthStatus = HistoryQueryIncomplete }, HistoryReasonCoverageIncomplete},
		{"missing retention start", func(i *HistoricalImpactInput) { i.Coverage.RetainedFrom = time.Time{} }, HistoryReasonRetentionMissing},
		{"late retention start", func(i *HistoricalImpactInput) {
			i.Coverage.RetainedFrom = historyTestAt.Add(-HistoricalImpactLookback + time.Nanosecond)
		}, HistoryReasonRetentionMissing},
		{"early retention end", func(i *HistoricalImpactInput) { i.Coverage.RetainedThrough = historyTestAt.Add(-time.Nanosecond) }, HistoryReasonCoverageIncomplete},
		{"gateway health incomplete", func(i *HistoricalImpactInput) { i.GatewayHealth.Complete = false }, HistoryReasonCoverageIncomplete},
		{"auth health starts late", func(i *HistoricalImpactInput) {
			i.AuthHealth.CoverageStart = historyTestAt.Add(-HistoricalImpactLookback + time.Nanosecond)
		}, HistoryReasonCoverageIncomplete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validHistoricalImpactInput()
			test.mutate(&input)
			assertHistoryBlocked(t, EvaluateHistoricalImpact(input), test.want)
		})
	}
}

func TestHistoricalImpactAuthBindingAndSuccessRules(t *testing.T) {
	for _, binding := range []detection.BindingState{detection.BindingVerified, detection.BindingPending, detection.BindingUntrusted} {
		t.Run("success "+string(binding), func(t *testing.T) {
			input := validHistoricalImpactInput()
			input.AuthRecords = []HistoricalAuthRecord{
				historyAuth("019b0000-0000-7000-8000-000000000020", historyTestAt.Add(-time.Minute), events.AuthOutcomeSucceeded, binding),
			}
			result := EvaluateHistoricalImpact(input)
			assertHistoryBlocked(t, result, HistoryReasonAuthSucceeded)
			if result.Value().SucceededAuthCount != 1 || result.Value().VerifiedFailedAuthCount != 0 {
				t.Fatalf("success counts must be conservative: %+v", result.Value())
			}
		})
	}

	tests := []struct {
		name    string
		binding detection.BindingState
		trust   detection.TimestampTrust
		want    HistoricalImpactReason
	}{
		{"pending failure", detection.BindingPending, detection.TimestampTrusted, HistoryReasonAuthBindingPending},
		{"untrusted failure", detection.BindingUntrusted, detection.TimestampTrusted, HistoryReasonAuthBindingUntrusted},
		{"untrusted timestamp", detection.BindingVerified, detection.TimestampUntrusted, HistoryReasonTimestampUntrusted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validHistoricalImpactInput()
			event := historyAuth("019b0000-0000-7000-8000-000000000021", historyTestAt.Add(-time.Minute), events.AuthOutcomeFailed, test.binding)
			event.TimestampTrust = test.trust
			input.AuthRecords = []HistoricalAuthRecord{event}
			result := EvaluateHistoricalImpact(input)
			assertHistoryBlocked(t, result, test.want)
			if result.Value().VerifiedFailedAuthCount != 0 {
				t.Fatal("only trusted binding-verified failures may support attack evidence")
			}
		})
	}
}

func TestHistoricalImpactHealthAndReceiverGapsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name    string
		state   detection.HealthIntervalState
		dropped uint64
		want    HistoricalImpactReason
	}{
		{"degraded", detection.HealthDegraded, 0, HistoryReasonSourceDegraded},
		{"lost", detection.HealthLost, 1, HistoryReasonSourceDegraded},
		{"gapped", detection.HealthGapped, 0, HistoryReasonSourceDegraded},
		{"recovered still incomplete", detection.HealthRecovered, 0, HistoryReasonSourceDegraded},
		{"unknown loss", detection.HealthUnknownLoss, 0, HistoryReasonSourceUnknownLoss},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validHistoricalImpactInput()
			input.GatewayHealth.Intervals = []detection.HealthInterval{{
				State: test.state, Start: historyTestAt.Add(-time.Hour), DroppedCount: test.dropped,
			}}
			assertHistoryBlocked(t, EvaluateHistoricalImpact(input), test.want)
		})
	}

	for _, test := range []struct {
		name       string
		resolution ReceiverGapResolution
		end        time.Time
		want       HistoricalImpactReason
		allowed    bool
	}{
		{"unresolved", ReceiverGapUnresolved, time.Time{}, HistoryReasonGapUnresolved, false},
		{"permanent", ReceiverGapPermanentLoss, historyTestAt.Add(-30 * time.Minute), HistoryReasonGapPermanentLoss, false},
		{"resolved exact", ReceiverGapResolvedExact, historyTestAt.Add(-30 * time.Minute), HistoryReasonOK, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validHistoricalImpactInput()
			input.ReceiverGaps = []HistoricalReceiverGap{{
				GapID: "019b0000-0000-7000-8000-000000000030", Source: detection.SourceGateway,
				SequenceStart: 3, SequenceEnd: 5, ImpactStart: historyTestAt.Add(-time.Hour), ImpactEnd: test.end,
				Resolution: test.resolution,
			}}
			result := EvaluateHistoricalImpact(input)
			if result.Allowed() != test.allowed || result.Value().ReasonCode != test.want {
				t.Fatalf("allowed=%v reason=%s", result.Allowed(), result.Value().ReasonCode)
			}
		})
	}

	input := validHistoricalImpactInput()
	input.ReceiverGaps = []HistoricalReceiverGap{{
		GapID: "019b0000-0000-7000-8000-000000000031", Source: detection.SourceAuth,
		SequenceStart: 1, SequenceEnd: 1, ImpactStart: historyTestAt.Add(-HistoricalImpactLookback - 2*time.Hour),
		ImpactEnd: historyTestAt.Add(-HistoricalImpactLookback - time.Nanosecond), Resolution: ReceiverGapPermanentLoss,
	}}
	if !EvaluateHistoricalImpact(input).Allowed() {
		t.Fatal("a fully bounded gap ending before the inclusive lookback must not affect the gate")
	}
}

func TestHistoricalImpactPermutationStabilityAndMutationBinding(t *testing.T) {
	input := validHistoricalImpactInput()
	input.GatewayRecords = []HistoricalGatewayRecord{
		historyGateway("019b0000-0000-7000-8000-000000000043", historyTestAt.Add(-3*time.Hour), 200),
		historyGateway("019b0000-0000-7000-8000-000000000041", historyTestAt.Add(-time.Hour), 404),
		historyGateway("019b0000-0000-7000-8000-000000000042", historyTestAt.Add(-2*time.Hour), 503),
	}
	input.AuthRecords = []HistoricalAuthRecord{
		historyAuth("019b0000-0000-7000-8000-000000000045", historyTestAt.Add(-90*time.Minute), events.AuthOutcomeFailed, detection.BindingVerified),
		historyAuth("019b0000-0000-7000-8000-000000000044", historyTestAt.Add(-2*time.Hour), events.AuthOutcomeFailed, detection.BindingVerified),
	}
	original := cloneHistoryInput(input)
	first := EvaluateHistoricalImpact(input)
	if !reflect.DeepEqual(input, original) {
		t.Fatal("gate must not mutate caller-owned input")
	}
	slices.Reverse(input.GatewayRecords)
	slices.Reverse(input.AuthRecords)
	second := EvaluateHistoricalImpact(input)
	if first.Digest() != second.Digest() || !bytes.Equal(first.CanonicalBytes(), second.CanonicalBytes()) {
		t.Fatal("permutation of typed rows must not change normalized JCS or digest")
	}
	if !reflect.DeepEqual(input.GatewayRecords[0], original.GatewayRecords[2]) {
		t.Fatal("gate must not mutate caller-owned row slices")
	}

	mutated := original
	mutated.GatewayRecords = append([]HistoricalGatewayRecord(nil), original.GatewayRecords...)
	mutated.GatewayRecords[0].StatusCode = 201
	third := EvaluateHistoricalImpact(mutated)
	if !third.Allowed() || third.Digest() == first.Digest() || third.Value().GatewayDigest == first.Value().GatewayDigest {
		t.Fatal("a retained-row mutation must change bound input/report digests")
	}
}

func TestHistoricalImpactRejectsAmbiguousRecordsAndLeaksNoContent(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HistoricalImpactInput)
	}{
		{"invalid target", func(i *HistoricalImpactInput) { i.TargetIPv4 = "not-an-ip" }},
		{"different row target", func(i *HistoricalImpactInput) { i.GatewayRecords[0].SourceIPv4 = "1.1.1.1" }},
		{"duplicate gateway ID", func(i *HistoricalImpactInput) { i.GatewayRecords = append(i.GatewayRecords, i.GatewayRecords[0]) }},
		{"duplicate auth ID", func(i *HistoricalImpactInput) { i.AuthRecords = append(i.AuthRecords, i.AuthRecords[0]) }},
		{"invalid auth binding", func(i *HistoricalImpactInput) { i.AuthRecords[0].Binding = detection.BindingNotApplicable }},
		{"invalid status", func(i *HistoricalImpactInput) { i.GatewayRecords[0].StatusCode = 99 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validHistoricalImpactInput()
			test.mutate(&input)
			assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonInputInvalid)
		})
	}

	input := validHistoricalImpactInput()
	input.GatewayRecords[0].EventID = "019b0000-0000-7000-8000-deadbeefdead"
	input.AuthRecords[0].EventID = "019b0000-0000-7000-8000-cafebabecafe"
	result := EvaluateHistoricalImpact(input)
	canonical := string(result.CanonicalBytes())
	for _, forbidden := range []string{input.TargetIPv4, "deadbeefdead", "cafebabecafe"} {
		if strings.Contains(canonical, forbidden) {
			t.Fatalf("content-free report leaked %q: %s", forbidden, canonical)
		}
	}
}

func TestHistoricalImpactDemoBindingIsSealedAndProductionRejectsFakeClock(t *testing.T) {
	input := validHistoricalImpactInput()
	input.Environment = EnvironmentTest
	input.Mode = HistoryModeVerifiedDemo
	input.Clock = testHistoryCutoff(historyTestAt, HistoryClockVerifiedDemo)
	input.DemoHistory = nil
	assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonDemoVerificationMissing)

	zero := VerifiedDemoHistoryBinding{}
	input.DemoHistory = &zero
	assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonDemoVerificationMissing)

	input.DemoHistory = sealedDemoBinding(input)
	input.Clock = input.DemoHistory.HistoryCutoff()
	result := EvaluateHistoricalImpact(input)
	if !result.Allowed() || !validDigest(result.Value().DemoBindingDigest) {
		t.Fatalf("sealed test binding should pass the pure gate: %+v", result.Value())
	}

	mutated := *input.DemoHistory
	mutated.datasetDigest = digestBytes([]byte("different dataset"))
	input.DemoHistory = &mutated
	assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonDemoBindingMismatch)

	input.DemoHistory = sealedDemoBinding(input)
	input.Clock = input.DemoHistory.HistoryCutoff()
	input.Environment = EnvironmentProduction
	assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonClockNotAllowed)

	input = validHistoricalImpactInput()
	input.Clock = testHistoryCutoff(historyTestAt, HistoryClockVerifiedDemo)
	assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonClockNotAllowed)

	input = validHistoricalImpactInput()
	input.Clock = HistoryCutoff{}
	assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonInputInvalid)
}

func TestHistoricalImpactReasonPriorityIsStable(t *testing.T) {
	input := validHistoricalImpactInput()
	input.GatewayHealth.Intervals = []detection.HealthInterval{{
		State: detection.HealthUnknownLoss, Start: historyTestAt.Add(-time.Hour),
	}}
	input.ReceiverGaps = []HistoricalReceiverGap{{
		GapID: "019b0000-0000-7000-8000-000000000060", Source: detection.SourceGateway,
		SequenceStart: 1, SequenceEnd: 2, ImpactStart: historyTestAt.Add(-time.Hour), Resolution: ReceiverGapPermanentLoss,
	}}
	input.AuthRecords[0].Outcome = events.AuthOutcomeSucceeded
	input.GatewayRecords[0].TimestampTrust = detection.TimestampUntrusted
	assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonSourceUnknownLoss)
}

func validHistoricalImpactInput() HistoricalImpactInput {
	start := historyTestAt.Add(-HistoricalImpactLookback)
	return HistoricalImpactInput{
		Environment: EnvironmentProduction,
		Mode:        HistoryModeRetained,
		Clock:       testHistoryCutoff(historyTestAt, HistoryClockRealtime),
		TargetIPv4:  "8.8.8.8",
		Coverage: HistoryCoverage{
			GatewayStatus: HistoryQueryComplete, AuthStatus: HistoryQueryComplete,
			SourceHealthStatus: HistoryQueryComplete, ReceiverGapStatus: HistoryQueryComplete,
			RetainedFrom: start, RetainedThrough: historyTestAt,
		},
		GatewayRecords: []HistoricalGatewayRecord{
			historyGateway("019b0000-0000-7000-8000-000000000070", historyTestAt.Add(-time.Hour), 200),
		},
		AuthRecords: []HistoricalAuthRecord{
			historyAuth("019b0000-0000-7000-8000-000000000071", historyTestAt.Add(-30*time.Minute), events.AuthOutcomeFailed, detection.BindingVerified),
		},
		GatewayHealth: detection.SourceHealth{
			Source: detection.SourceGateway, Complete: true, CoverageStart: start, CoverageEnd: historyTestAt,
		},
		AuthHealth: detection.SourceHealth{
			Source: detection.SourceAuth, Complete: true, CoverageStart: start, CoverageEnd: historyTestAt,
		},
	}
}

func historyGateway(id string, at time.Time, status int) HistoricalGatewayRecord {
	return HistoricalGatewayRecord{
		EventID: id, OccurredAt: at, SourceIPv4: "8.8.8.8", StatusCode: status, TimestampTrust: detection.TimestampTrusted,
	}
}

func historyAuth(id string, at time.Time, outcome events.AuthOutcome, binding detection.BindingState) HistoricalAuthRecord {
	return HistoricalAuthRecord{
		EventID: id, OccurredAt: at, SourceIPv4: "8.8.8.8", Outcome: outcome,
		TimestampTrust: detection.TimestampTrusted, Binding: binding,
	}
}

func sealedDemoBinding(input HistoricalImpactInput) *VerifiedDemoHistoryBinding {
	at := input.Clock.At()
	health, reason := normalizeHistoryHealth(input.GatewayHealth, input.AuthHealth, at.Add(-HistoricalImpactLookback), at)
	if reason != HistoryReasonOK {
		panic("invalid test health")
	}
	return &VerifiedDemoHistoryBinding{
		verified: true, verificationEnvironment: EnvironmentTest, fixtureOnly: true,
		schemaVersion: "demo-history-v1", profile: "isolated-demo",
		manifestID: "019b0000-0000-7000-8000-000000000500",
		datasetID:  "019b0000-0000-7000-8000-000000000100", datasetSchemaVersion: "demo-history-dataset-v1",
		datasetLocator: DemoHistoryDatasetLocator, importID: "019b0000-0000-7000-8000-000000000501",
		clockAt: at, coverageStart: at.Add(-HistoricalImpactLookback), coverageEnd: at, issuedAt: at,
		pathCatalogVersion: events.PathCatalogV1, datasetRecordCount: uint64(len(input.GatewayRecords) + len(input.AuthRecords)),
		rawFileDigest: PinnedDemoHistoryRawFileDigest,
		datasetDigest: PinnedDemoHistoryDatasetDigest, manifestDigest: digestBytes([]byte("signed manifest")),
		importedRowsDigest: digestBytes([]byte("imported rows")), manifestSourceHealthDigest: digestBytes([]byte("manifest source health")),
		impactSourceHealthDigest: digestHistoryValue(health), runScopeDigest: digestBytes([]byte("run scope")),
		publicKeyDigest: digestBytes([]byte("public key")), signatureVerificationDigest: digestBytes([]byte("verified signature result")),
	}
}

func testHistoryCutoff(at time.Time, authority HistoryClockAuthority) HistoryCutoff {
	return HistoryCutoff{at: at.Round(0).UTC(), authority: authority, sealed: true}
}

func cloneHistoryInput(input HistoricalImpactInput) HistoricalImpactInput {
	clone := input
	clone.GatewayRecords = append([]HistoricalGatewayRecord(nil), input.GatewayRecords...)
	clone.AuthRecords = append([]HistoricalAuthRecord(nil), input.AuthRecords...)
	clone.GatewayHealth.Intervals = append([]detection.HealthInterval(nil), input.GatewayHealth.Intervals...)
	clone.AuthHealth.Intervals = append([]detection.HealthInterval(nil), input.AuthHealth.Intervals...)
	clone.ReceiverGaps = append([]HistoricalReceiverGap(nil), input.ReceiverGaps...)
	if input.DemoHistory != nil {
		binding := *input.DemoHistory
		clone.DemoHistory = &binding
	}
	return clone
}

func assertHistoryBlocked(t *testing.T, result CheckedHistoricalImpact, want HistoricalImpactReason) {
	t.Helper()
	if result.Allowed() || result.Value().Decision != HistoricalImpactBlocked || result.Value().ReasonCode != want {
		t.Fatalf("expected blocked/%s, got %+v", want, result.Value())
	}
	if len(result.CanonicalBytes()) == 0 || !validDigest(result.Digest()) {
		t.Fatal("blocked decisions must remain typed and digestible")
	}
}
