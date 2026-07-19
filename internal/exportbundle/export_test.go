package exportbundle

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testIncidentID  = "019b0000-0000-4000-8000-000000000101"
	testIncidentID2 = "019b0000-0000-4000-8000-000000000102"
	testEventID     = "019b0000-0000-4000-8000-000000000201"
	testEventID2    = "019b0000-0000-4000-8000-000000000202"
	testPolicyID    = "019b0000-0000-4000-8000-000000000301"
	testTraceID     = "019b0000-0000-4000-8000-000000000401"
	testDigest      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigest2     = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var testNow = time.Date(2026, 7, 18, 3, 4, 5, 123456789, time.UTC)

type fixedStore struct {
	snapshot Snapshot
	err      error
	query    Query
}

func (s *fixedStore) Snapshot(_ context.Context, query Query) (Snapshot, error) {
	s.query = query
	return s.snapshot, s.err
}

func TestBuildRedactsSensitiveValuesAndPreservesVerifiableEvidence(t *testing.T) {
	store := &fixedStore{snapshot: testSnapshot()}
	exporter, err := NewExporter(store, []byte("0123456789abcdef0123456789abcdef"), "ops-export-v1")
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	exporter.now = func() time.Time { return testNow.Add(time.Minute) }
	query, err := NewQuery(testNow.Add(-time.Hour), testNow.Add(time.Hour), "", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := exporter.Build(t.Context(), query)
	if err != nil {
		t.Fatal(err)
	}
	encoded, result, err := Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"198.51.100.42", "admin.alice", testTraceID} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("export leaked %q", forbidden)
		}
	}
	for _, required := range []string{testIncidentID, testEventID, testPolicyID, testDigest, testDigest2} {
		if !strings.Contains(text, required) {
			t.Fatalf("export omitted traceability value %q", required)
		}
	}
	if len(bundle.Incidents) != 2 ||
		bundle.Incidents[0].SourcePseudonym != bundle.Incidents[1].SourcePseudonym ||
		bundle.AuditEvents[0].PreviousRecordDigest != GenesisDigest ||
		bundle.AuditEvents[1].PreviousRecordDigest != bundle.AuditEvents[0].RecordDigest ||
		bundle.Manifest.AuditChainRoot != bundle.AuditEvents[1].RecordDigest ||
		result.BundleDigest == "" || result.ManifestDigest != bundle.Manifest.ManifestDigest {
		t.Fatalf("bundle linkage/result mismatch: %+v %+v", bundle.Manifest, result)
	}
	decoded, decodedResult, err := DecodeAndVerify(encoded)
	if err != nil || decoded.Manifest.ManifestDigest != bundle.Manifest.ManifestDigest ||
		decodedResult.BundleDigest != result.BundleDigest {
		t.Fatalf("round trip failed: result=%+v err=%v", decodedResult, err)
	}
}

func TestVerifyRejectsMutationDeletionInsertionReorderAndUnknownFields(t *testing.T) {
	bundle := buildTestBundle(t)
	cases := map[string]func(Bundle) Bundle{
		"incident mutation": func(value Bundle) Bundle {
			value.Incidents[0].Kind = "request_burst"
			return value
		},
		"audit mutation": func(value Bundle) Bundle {
			value.AuditEvents[0].Outcome = "failed"
			return value
		},
		"audit deletion": func(value Bundle) Bundle {
			value.AuditEvents = value.AuditEvents[1:]
			value.Manifest.AuditEventCount--
			return value
		},
		"audit reorder": func(value Bundle) Bundle {
			value.AuditEvents[0], value.AuditEvents[1] = value.AuditEvents[1], value.AuditEvents[0]
			return value
		},
		"manifest mutation": func(value Bundle) Bundle {
			value.Manifest.Pseudonymization.KeyID = "different-key"
			return value
		},
		"invalid pseudonym": func(value Bundle) Bundle {
			value.AuditEvents[0].ActorPseudonym = "actor:raw"
			return value
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Verify(mutate(cloneBundle(t, bundle))); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	encoded, _, err := Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	document["unexpected"] = true
	encoded, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = DecodeAndVerify(encoded); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unknown field err=%v", err)
	}
}

func cloneBundle(t *testing.T, value Bundle) Bundle {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result Bundle
	if err = json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestBuildRejectsInvalidOrOverBoundStoreData(t *testing.T) {
	query, err := NewQuery(testNow.Add(-time.Hour), testNow.Add(time.Hour), "", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Snapshot{
		"too many incidents": testSnapshot(),
		"invalid source": {
			SnapshotAt: testNow,
			Incidents: []RawIncident{func() RawIncident {
				value := testSnapshot().Incidents[0]
				value.SourceIPv4 = "198.051.100.42"
				return value
			}()},
		},
		"duplicate audit sequence": {
			SnapshotAt: testNow,
			Audit: []RawAuditEvent{testSnapshot().Audit[0], func() RawAuditEvent {
				value := testSnapshot().Audit[1]
				value.Sequence = 1
				return value
			}()},
		},
		"audit sequence outside checked JSON range": {
			SnapshotAt: testNow,
			Audit: []RawAuditEvent{func() RawAuditEvent {
				value := testSnapshot().Audit[0]
				value.Sequence = MaximumAuditSequence + 1
				return value
			}()},
		},
	}
	for name, snapshot := range cases {
		t.Run(name, func(t *testing.T) {
			store := &fixedStore{snapshot: snapshot}
			exporter, newErr := NewExporter(store, []byte("0123456789abcdef0123456789abcdef"), "ops-export-v1")
			if newErr != nil {
				t.Fatal(newErr)
			}
			defer exporter.Close()
			if _, buildErr := exporter.Build(t.Context(), query); buildErr == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestBuildAndVerifyRejectRecordsOutsideTheDeclaredQueryScope(t *testing.T) {
	filteredQuery, err := NewQuery(testNow.Add(-time.Hour), testNow.Add(time.Hour), testIncidentID, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	exporter, err := NewExporter(&fixedStore{snapshot: testSnapshot()},
		[]byte("0123456789abcdef0123456789abcdef"), "ops-export-v1")
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	if _, err = exporter.Build(t.Context(), filteredQuery); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("store escaped exact incident filter: %v", err)
	}

	base := buildTestBundle(t)
	tests := map[string]func(Bundle) Bundle{
		"filter mismatch": func(value Bundle) Bundle {
			value.Manifest.Filters.IncidentID = stringPointer(testIncidentID2)
			return recomputeBundleDigests(t, value)
		},
		"audit outside window": func(value Bundle) Bundle {
			value.AuditEvents[0].OccurredAt = canonicalTime(testNow.Add(2 * time.Hour))
			return recomputeBundleDigests(t, value)
		},
		"audit sequence outside checked JSON range": func(value Bundle) Bundle {
			value.AuditEvents[0].Sequence = MaximumAuditSequence + 1
			return recomputeBundleDigests(t, value)
		},
		"incident outside window without audit": func(value Bundle) Bundle {
			value.Incidents[1].CreatedAt = canonicalTime(testNow.Add(-3 * time.Hour))
			value.Incidents[1].UpdatedAt = canonicalTime(testNow.Add(-2 * time.Hour))
			return recomputeBundleDigests(t, value)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if verifyErr := Verify(mutate(cloneBundle(t, base))); !errors.Is(verifyErr, ErrIntegrity) {
				t.Fatalf("scope mismatch err=%v", verifyErr)
			}
		})
	}
}

func recomputeBundleDigests(t *testing.T, value Bundle) Bundle {
	t.Helper()
	for index := range value.Incidents {
		value.Incidents[index].RecordDigest = ""
		digest, err := digestJSON("sentinelflow export incident record v1", value.Incidents[index])
		if err != nil {
			t.Fatal(err)
		}
		value.Incidents[index].RecordDigest = digest
	}
	previous := GenesisDigest
	for index := range value.AuditEvents {
		value.AuditEvents[index].PreviousRecordDigest = previous
		value.AuditEvents[index].RecordDigest = ""
		digest, err := digestJSON("sentinelflow export audit record v1", value.AuditEvents[index])
		if err != nil {
			t.Fatal(err)
		}
		value.AuditEvents[index].RecordDigest = digest
		previous = digest
	}
	value.Manifest.IncidentCount = len(value.Incidents)
	value.Manifest.AuditEventCount = len(value.AuditEvents)
	value.Manifest.IncidentRecordsDigest = digestList(
		"sentinelflow export incident set v1", incidentDigests(value.Incidents),
	)
	value.Manifest.AuditChainRoot = previous
	value.Manifest.ExportID = exportID(value.Manifest)
	value.Manifest.ManifestDigest = ""
	digest, err := digestJSON("sentinelflow export manifest v1", value.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	value.Manifest.ManifestDigest = digest
	return value
}

func TestQueryRequiresCanonicalBoundsAndCaps(t *testing.T) {
	if _, err := NewQuery(testNow, testNow, "", 1, 1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("equal bound err=%v", err)
	}
	if _, err := NewQuery(testNow, testNow.Add(MaximumExportWindow+time.Second), "", 1, 1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("long window err=%v", err)
	}
	if _, err := NewQuery(testNow, testNow.Add(time.Hour), "not-uuid", 1, 1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad UUID err=%v", err)
	}
	if _, err := NewQuery(testNow, testNow.Add(time.Hour), "", 0, MaximumAuditRecords+1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("caps err=%v", err)
	}
}

func buildTestBundle(t *testing.T) Bundle {
	t.Helper()
	store := &fixedStore{snapshot: testSnapshot()}
	exporter, err := NewExporter(store, []byte("0123456789abcdef0123456789abcdef"), "ops-export-v1")
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	exporter.now = func() time.Time { return testNow.Add(time.Minute) }
	query, err := NewQuery(testNow.Add(-time.Hour), testNow.Add(time.Hour), "", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := exporter.Build(t.Context(), query)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func testSnapshot() Snapshot {
	policyVersion := int32(1)
	return Snapshot{
		SnapshotAt: testNow,
		Incidents: []RawIncident{
			{
				IncidentID: testIncidentID2, Kind: "path_scan", State: "open",
				SourceIPv4: "198.51.100.42", ServiceLabel: "demo_app",
				FirstSeen: testNow.Add(-10 * time.Minute), LastSeen: testNow.Add(-time.Minute),
				DeterministicScore: "0.90000", Version: 1,
				CreatedAt: testNow.Add(-10 * time.Minute), UpdatedAt: testNow.Add(-time.Minute),
			},
			{
				IncidentID: testIncidentID, Kind: "path_scan", State: "open",
				SourceIPv4: "198.51.100.42", ServiceLabel: "demo_app",
				FirstSeen: testNow.Add(-20 * time.Minute), LastSeen: testNow.Add(-2 * time.Minute),
				DeterministicScore: "0.80000", Version: 2,
				CreatedAt: testNow.Add(-20 * time.Minute), UpdatedAt: testNow.Add(-2 * time.Minute),
			},
		},
		Audit: []RawAuditEvent{
			{
				Sequence: 2, EventID: testEventID2, ActorType: "system", ActorID: "dispatcher.one",
				Action: "policy_validated", ObjectType: "policy", ObjectID: stringPointer(testPolicyID),
				IncidentID: stringPointer(testIncidentID), PolicyID: stringPointer(testPolicyID),
				PolicyVersion: &policyVersion, TraceID: stringPointer(testTraceID),
				PrimaryDigest: stringPointer(testDigest2), Outcome: "succeeded",
				OccurredAt: testNow.Add(-time.Minute), RecordedAt: testNow.Add(-time.Minute),
			},
			{
				Sequence: 1, EventID: testEventID, ActorType: "administrator", ActorID: "admin.alice",
				Action: "incident_reviewed", ObjectType: "incident", ObjectID: stringPointer(testIncidentID),
				IncidentID: stringPointer(testIncidentID), TraceID: stringPointer(testTraceID),
				PrimaryDigest: stringPointer(testDigest), SecondaryDigest: stringPointer(testDigest2),
				Outcome: "accepted", OccurredAt: testNow.Add(-2 * time.Minute),
				RecordedAt: testNow.Add(-2 * time.Minute),
			},
		},
	}
}

func stringPointer(value string) *string { return &value }
