package correlation

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

var correlationNow = time.Date(2026, 7, 18, 4, 0, 0, 0, time.UTC)

func TestCorrelateTemporalBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		leftStart  time.Time
		leftEnd    time.Time
		rightStart time.Time
		rightEnd   time.Time
		groupCount int
		reason     TemporalReason
	}{
		{
			name: "overlap", leftStart: correlationNow.Add(-time.Minute), leftEnd: correlationNow,
			rightStart: correlationNow.Add(-30 * time.Second), rightEnd: correlationNow.Add(time.Second),
			groupCount: 1, reason: TemporalWindowOverlap,
		},
		{
			name: "touching windows are overlap", leftStart: correlationNow.Add(-time.Minute), leftEnd: correlationNow,
			rightStart: correlationNow, rightEnd: correlationNow.Add(time.Second),
			groupCount: 1, reason: TemporalWindowOverlap,
		},
		{
			name: "below five minute gap", leftStart: correlationNow.Add(-time.Minute), leftEnd: correlationNow,
			rightStart: correlationNow.Add(MaximumSignalGap - time.Nanosecond), rightEnd: correlationNow.Add(MaximumSignalGap),
			groupCount: 1, reason: TemporalWithinFiveMinutes,
		},
		{
			name: "exact five minute gap", leftStart: correlationNow.Add(-time.Minute), leftEnd: correlationNow,
			rightStart: correlationNow.Add(MaximumSignalGap), rightEnd: correlationNow.Add(MaximumSignalGap + time.Second),
			groupCount: 1, reason: TemporalWithinFiveMinutes,
		},
		{
			name: "above five minute gap", leftStart: correlationNow.Add(-time.Minute), leftEnd: correlationNow,
			rightStart: correlationNow.Add(MaximumSignalGap + time.Nanosecond), rightEnd: correlationNow.Add(MaximumSignalGap + time.Second),
			groupCount: 2,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			left := testSignal(1, detection.RulePathScan, test.leftStart, test.leftEnd)
			right := testSignal(2, detection.RuleLoginBruteForce, test.rightStart, test.rightEnd)
			groups, err := Correlate([]detection.Signal{right, left})
			if err != nil {
				t.Fatalf("Correlate error = %v", err)
			}
			if len(groups) != test.groupCount {
				t.Fatalf("group count = %d, want %d", len(groups), test.groupCount)
			}
			if test.groupCount == 1 {
				relations := groups[0].Relations()
				if len(relations) != 1 || relations[0].TemporalReason != test.reason || relations[0].IdentityReason != IdentitySameCanonicalSource {
					t.Fatalf("relations = %#v, want temporal reason %s", relations, test.reason)
				}
			}
		})
	}
}

func TestCorrelationUsesCanonicalSourceOnlyAndServiceIsSupporting(t *testing.T) {
	t.Parallel()

	base := testSignal(1, detection.RuleRequestBurst, correlationNow.Add(-time.Second), correlationNow)
	differentService := testSignal(2, detection.RuleCredentialStuffing, correlationNow, correlationNow.Add(time.Second))
	differentService.ServiceLabel = "other"
	differentSource := testSignal(3, detection.RuleLoginBruteForce, correlationNow, correlationNow.Add(time.Second))
	differentSource.SourceIP = "198.51.100.10"

	groups, err := Correlate([]detection.Signal{differentSource, differentService, base})
	if err != nil {
		t.Fatalf("Correlate error = %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("group count = %d, want 2", len(groups))
	}
	var sameSource Group
	for _, group := range groups {
		if group.SourceIP == base.SourceIP {
			sameSource = group
		}
	}
	if got := sameSource.Snapshot.ServiceLabels(); !reflect.DeepEqual(got, []string{"app", "other"}) {
		t.Fatalf("service labels = %v", got)
	}
	relations := sameSource.Relations()
	if len(relations) != 1 || !slices.Contains(relations[0].SupportingReasons, SupportingDifferentService) ||
		!slices.Contains(relations[0].SupportingReasons, SupportingAccountIdentityMinimized) ||
		!slices.Contains(relations[0].SupportingReasons, SupportingPathIdentityMinimized) {
		t.Fatalf("supporting reasons = %#v", relations)
	}
}

func TestCorrelationIsTransitiveButRecordsOnlyDirectRelations(t *testing.T) {
	t.Parallel()

	a := testSignal(1, detection.RulePathScan, correlationNow, correlationNow.Add(time.Second))
	b := testSignal(2, detection.RuleRequestBurst, correlationNow.Add(MaximumSignalGap), correlationNow.Add(MaximumSignalGap+time.Second))
	c := testSignal(3, detection.RuleLoginBruteForce, correlationNow.Add(2*MaximumSignalGap), correlationNow.Add(2*MaximumSignalGap+time.Second))
	groups, err := Correlate([]detection.Signal{c, a, b})
	if err != nil {
		t.Fatalf("Correlate error = %v", err)
	}
	if len(groups) != 1 || len(groups[0].Signals()) != 3 {
		t.Fatalf("groups = %#v, want one three-signal component", groups)
	}
	if got := len(groups[0].Relations()); got != 2 {
		t.Fatalf("direct relation count = %d, want 2", got)
	}
}

func TestCorrelationPermutationDuplicateAndSnapshotStability(t *testing.T) {
	t.Parallel()

	firstSignal := testSignal(1, detection.RulePathScan, correlationNow.Add(-time.Minute), correlationNow)
	secondSignal := testSignal(2, detection.RuleCredentialStuffing, correlationNow, correlationNow.Add(time.Second))
	input := []detection.Signal{secondSignal, firstSignal, firstSignal}
	first, err := Correlate(input)
	if err != nil {
		t.Fatalf("Correlate error = %v", err)
	}
	slices.Reverse(input)
	second, err := Correlate(input)
	if err != nil {
		t.Fatalf("Correlate reversed error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("permutation changed output\nfirst=%#v\nsecond=%#v", first, second)
	}
	if got := len(first[0].Snapshot.SignalIDs()); got != 2 {
		t.Fatalf("signal count = %d, want duplicate removed", got)
	}
	assertSnapshot(t, first[0].Snapshot)

	originalDigest := first[0].Snapshot.Digest()
	input[0].EvidenceIDs[0] = testUUID(999, 999)
	ids := first[0].Snapshot.EvidenceEventIDs()
	ids[0] = testUUID(998, 998)
	canonical := first[0].Snapshot.CanonicalBytes()
	canonical[0] = '['
	refs := first[0].Snapshot.SignalRefs()
	refs[0].SignalDigest = digestText("mutated")
	if first[0].Snapshot.Digest() != originalDigest || first[0].Snapshot.CanonicalBytes()[0] != '{' {
		t.Fatal("snapshot changed through caller-owned or accessor-owned memory")
	}
}

func TestConflictingAndInvalidSignalsFailClosed(t *testing.T) {
	t.Parallel()

	base := testSignal(1, detection.RuleRequestBurst, correlationNow.Add(-time.Second), correlationNow)
	tests := []struct {
		name   string
		values func() []detection.Signal
		code   ErrorCode
	}{
		{
			name: "conflicting duplicate",
			values: func() []detection.Signal {
				conflict := cloneSignal(base)
				conflict.Digest = digestText("conflict")
				return []detection.Signal{base, conflict}
			},
			code: ErrorConflictingSignal,
		},
		{
			name: "different rule classification",
			values: func() []detection.Signal {
				invalid := cloneSignal(base)
				invalid.Classification = detection.ClassificationPathScan
				return []detection.Signal{invalid}
			},
			code: ErrorInvalidInput,
		},
		{
			name: "incomplete source health",
			values: func() []detection.Signal {
				invalid := cloneSignal(base)
				invalid.SourceHealthStatus = detection.SourceHealthStatusIncomplete
				return []detection.Signal{invalid}
			},
			code: ErrorInvalidInput,
		},
		{
			name: "unsorted evidence",
			values: func() []detection.Signal {
				invalid := cloneSignal(base)
				invalid.EvidenceIDs[0], invalid.EvidenceIDs[1] = invalid.EvidenceIDs[1], invalid.EvidenceIDs[0]
				return []detection.Signal{invalid}
			},
			code: ErrorInvalidInput,
		},
		{
			name: "threshold cannot be reproduced",
			values: func() []detection.Signal {
				invalid := cloneSignal(base)
				invalid.Metrics.EventCount--
				invalid.EvidenceIDs = invalid.EvidenceIDs[:len(invalid.EvidenceIDs)-1]
				return []detection.Signal{invalid}
			},
			code: ErrorInvalidInput,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			groups, err := Correlate(test.values())
			var correlationErr *Error
			if !errors.As(err, &correlationErr) || correlationErr.Code != test.code {
				t.Fatalf("error = %v, want code %s", err, test.code)
			}
			if groups != nil {
				t.Fatalf("invalid input returned groups: %#v", groups)
			}
		})
	}
}

func TestEmptyCorrelationIsDeterministicEmptySlice(t *testing.T) {
	t.Parallel()
	groups, err := Correlate(nil)
	if err != nil {
		t.Fatalf("Correlate(nil) error = %v", err)
	}
	if groups == nil || len(groups) != 0 {
		t.Fatalf("groups = %#v, want non-nil empty slice", groups)
	}
}

func assertSnapshot(t *testing.T, snapshot EvidenceSnapshot) {
	t.Helper()
	if snapshot.SchemaVersion() != EvidenceSnapshotVersion || snapshot.SourceHealthStatus() != detection.SourceHealthStatusComplete {
		t.Fatalf("snapshot version/health = %s/%s", snapshot.SchemaVersion(), snapshot.SourceHealthStatus())
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(snapshot.Digest()) {
		t.Fatalf("snapshot digest = %q", snapshot.Digest())
	}
	if snapshot.Digest() != sha256Digest(snapshot.CanonicalBytes()) {
		t.Fatal("snapshot digest does not bind canonical bytes")
	}
	if !slices.IsSorted(snapshot.SignalIDs()) || !slices.IsSorted(snapshot.EvidenceEventIDs()) {
		t.Fatal("snapshot IDs are not sorted")
	}
	for _, values := range [][]string{snapshot.SignalIDs(), snapshot.EvidenceEventIDs()} {
		for index := 1; index < len(values); index++ {
			if values[index-1] == values[index] {
				t.Fatalf("snapshot contains duplicate ID %q", values[index])
			}
		}
	}
	orderedKeys := []string{
		"evidence_event_ids", "schema_version", "service_labels", "signal_ids",
		"signal_refs", "source_health_status", "source_ip", "window_end", "window_start",
	}
	if got := topLevelJSONKeys(t, snapshot.CanonicalBytes()); !reflect.DeepEqual(got, orderedKeys) {
		t.Fatalf("top-level JCS keys = %v, want %v", got, orderedKeys)
	}
	var decoded struct {
		SignalRefs []json.RawMessage `json:"signal_refs"`
	}
	if err := json.Unmarshal(snapshot.CanonicalBytes(), &decoded); err != nil || len(decoded.SignalRefs) == 0 {
		t.Fatalf("decode signal refs = %d, %v", len(decoded.SignalRefs), err)
	}
	refKeys := []string{
		"classification", "configuration_digest", "configuration_version", "distinct_account_count",
		"distinct_suspicious_path_count", "event_count", "evidence_digest", "rule_id",
		"signal_digest", "signal_id", "window_end", "window_start",
	}
	if got := topLevelJSONKeys(t, decoded.SignalRefs[0]); !reflect.DeepEqual(got, refKeys) {
		t.Fatalf("signal-ref JCS keys = %v, want %v", got, refKeys)
	}
}

func topLevelJSONKeys(t *testing.T, value []byte) []string {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(value))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		t.Fatalf("canonical snapshot opening token = %v, %v", opening, err)
	}
	keys := make([]string, 0)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			t.Fatalf("canonical snapshot key error = %v", err)
		}
		key, ok := token.(string)
		if !ok {
			t.Fatalf("canonical snapshot key token = %#v", token)
		}
		keys = append(keys, key)
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			t.Fatalf("canonical snapshot value error = %v", err)
		}
	}
	return keys
}

func testSignal(index int, rule detection.RuleID, start, end time.Time) detection.Signal {
	metrics := detection.Metrics{}
	classification := detection.Classification("")
	switch rule {
	case detection.RulePathScan:
		metrics.EventCount = detection.PathScanThreshold
		metrics.DistinctSuspiciousPathCount = detection.PathScanThreshold
		classification = detection.ClassificationPathScan
	case detection.RuleRequestBurst:
		metrics.EventCount = detection.RequestBurstThreshold
		classification = detection.ClassificationRequestBurst
	case detection.RuleLoginBruteForce:
		metrics.EventCount = detection.LoginBruteForceThreshold
		classification = detection.ClassificationLoginBruteForce
	case detection.RuleCredentialStuffing:
		metrics.EventCount = detection.CredentialStuffingEventThreshold
		metrics.DistinctAccountCount = detection.CredentialStuffingAccountThreshold
		classification = detection.ClassificationCredentialStuffing
	default:
		panic("unknown test rule")
	}
	evidence := make([]string, metrics.EventCount)
	for eventIndex := range evidence {
		evidence[eventIndex] = testUUID(index+1000, eventIndex+1)
	}
	slices.Sort(evidence)
	return detection.Signal{
		SignalID:             testUUID(index, index),
		RuleID:               rule,
		Classification:       classification,
		ConfigurationVersion: detection.DefaultConfigurationVersion,
		ConfigurationDigest:  digestText("configuration"),
		SourceIP:             "198.51.100.9",
		ServiceLabel:         "app",
		WindowStart:          start,
		WindowEnd:            end,
		Metrics:              metrics,
		EvidenceIDs:          evidence,
		EvidenceDigest:       digestText(fmt.Sprintf("evidence-%d", index)),
		Digest:               digestText(fmt.Sprintf("signal-%d", index)),
		SourceHealthStatus:   detection.SourceHealthStatusComplete,
	}
}

func testUUID(high, low int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", high, low)
}

func digestText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", sum)
}
