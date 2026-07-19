package validationstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/validationworker"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	testJobID        = "019b0000-0000-7000-8000-000000009001"
	testAnalysisID   = "019b0000-0000-7000-8000-000000009002"
	testIncidentID   = "019b0000-0000-7000-8000-000000009003"
	testAttemptID    = "019b0000-0000-7000-8000-000000009004"
	testPolicyID     = "019b0000-0000-7000-8000-000000009005"
	testCandidateID  = "019b0000-0000-7000-8000-000000009006"
	testValidationID = "019b0000-0000-7000-8000-000000009007"
	testEvidenceID   = "019b0000-0000-7000-8000-000000009008"
	testSignalID     = "019b0000-0000-7000-8000-000000009009"
	testEventID      = "019b0000-0000-7000-8000-000000009010"
	testGatewayID    = "019b0000-0000-7000-8000-000000009011"
	testAuthID       = "019b0000-0000-7000-8000-000000009012"
	testLeaseToken   = "00000000-0000-4000-8000-000000009013"
	testDigest       = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var storeTestNow = time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)

func TestStoreUsesOnlyFencedValidationFunctions(t *testing.T) {
	t.Parallel()
	db := &queryStub{rows: []pgx.Row{
		rowFunc(func(dest ...any) error {
			setLeaseRow(dest)
			return nil
		}),
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = "prepared"
			*dest[1].(*[]byte) = snapshotJSON(t)
			*dest[2].(*[]byte) = testEvidenceCanonical(t)
			return nil
		}),
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = testJobID
			*dest[1].(*string) = "completed"
			return nil
		}),
	}}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	job, found, err := store.Lease(context.Background(), leaseRequest())
	if err != nil || !found || job.JobID != testJobID {
		t.Fatalf("lease=%+v found=%v err=%v", job, found, err)
	}
	snapshot, prepared, err := store.Prepare(context.Background(), prepareRequest())
	if err != nil || !prepared || snapshot.ValidationAttemptID != testAttemptID ||
		len(snapshot.History.GatewayRecords) != 1 {
		t.Fatalf("snapshot=%+v prepared=%v err=%v", snapshot, prepared, err)
	}
	finished, err := store.Finalize(context.Background(), invalidFinalize())
	if err != nil || !finished {
		t.Fatalf("finished=%v err=%v", finished, err)
	}
	queries := db.queriesSnapshot()
	if len(queries) != 3 || !strings.Contains(queries[0], "lease_validation_outbox_job") ||
		!strings.Contains(queries[1], "prepare_validation_attempt") ||
		!strings.Contains(queries[2], "finalize_validation_attempt") {
		t.Fatalf("queries=%q", queries)
	}
	for _, query := range queries {
		if strings.Contains(query, "INSERT INTO") || strings.Contains(query, "UPDATE sentinelflow") {
			t.Fatalf("direct mutation query=%q", query)
		}
	}
}

func TestActivatedDemoStoreRequiresOpaqueReceiptAndUsesExactPrepare(t *testing.T) {
	t.Parallel()
	document := demoSnapshotJSON(t)
	db := &queryStub{rows: []pgx.Row{
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = "00000000-0000-4000-8000-000000009099"
			*dest[1].(*string) = "00000000-0000-4000-8000-000000009098"
			*dest[2].(*time.Time) = storeTestNow
			*dest[3].(*time.Time) = storeTestNow.Add(time.Hour)
			return nil
		}),
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = "prepared"
			*dest[1].(*[]byte) = document
			*dest[2].(*[]byte) = testEvidenceCanonical(t)
			return nil
		}),
	}}
	activation := fixtureDemoActivation(t, db, validation.DemoHistoryConsumerValidation)
	binding, ok := activation.Binding()
	if !ok {
		t.Fatal("activated binding unavailable")
	}
	store, err := NewPostgreSQLActivatedDemoStore(db, activation)
	if err != nil {
		t.Fatal(err)
	}
	if returned, ok := store.VerifiedDemoHistoryBinding(); !ok || returned.HistoryCutoff().At().IsZero() {
		t.Fatal("verified binding was not retained after the DB gate")
	}
	snapshot, prepared, err := store.Prepare(context.Background(), prepareRequest())
	if err != nil || !prepared || snapshot.History.Cutoff.Equal(snapshot.GeneratedAt) ||
		!snapshot.History.Cutoff.Equal(binding.HistoryCutoff().At()) {
		t.Fatalf("snapshot=%+v prepared=%v err=%v", snapshot, prepared, err)
	}
	queries := db.queriesSnapshot()
	if len(queries) != 2 || !strings.Contains(queries[0], "create_demo_history_runtime_activation_pair_and_fence_000030") ||
		!strings.Contains(queries[1], "prepare_validation_attempt_verified_demo_000030") {
		t.Fatalf("queries=%q", queries)
	}
	_, arguments := db.lastCall()
	if len(arguments) != 21 || arguments[3] != "019b0000-0000-7000-8000-000000000501" ||
		arguments[19] != validation.PinnedDemoHistoryImpactSourceHealthDigest ||
		!strings.HasPrefix(arguments[20].(string), "sha256:") {
		t.Fatal("unexpected exact demo prepare argument shape")
	}

	if rejected, rejectErr := NewPostgreSQLActivatedDemoStore(db, validation.ActivatedDemoHistoryBinding{}); rejected != nil || rejectErr == nil {
		t.Fatalf("zero receipt store=%v err=%v", rejected, rejectErr)
	}
}

func TestActivatedDemoStoreRunOncePublishesSixGateValidation(t *testing.T) {
	now := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	document, evidenceCanonical := validDemoRuntimeSnapshotJSON(t, now)
	db := &queryStub{rows: []pgx.Row{
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = "00000000-0000-4000-8000-000000009099"
			*dest[1].(*string) = "00000000-0000-4000-8000-000000009098"
			*dest[2].(*time.Time) = storeTestNow
			*dest[3].(*time.Time) = storeTestNow.Add(time.Hour)
			return nil
		}),
		rowFunc(func(dest ...any) error {
			setLeaseRowAt(dest, now)
			return nil
		}),
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = "prepared"
			*dest[1].(*[]byte) = document
			*dest[2].(*[]byte) = evidenceCanonical
			return nil
		}),
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = testJobID
			*dest[1].(*string) = "completed"
			return nil
		}),
	}}
	activation := fixtureDemoActivation(t, db, validation.DemoHistoryConsumerValidation)
	store, err := NewPostgreSQLActivatedDemoStore(db, activation)
	if err != nil {
		t.Fatal(err)
	}
	protectedContract, err := validation.LoadProtectedContractFile(filepath.Join(
		"..", "..", "contracts", "enforcement", "protected_ipv4_v1.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	protectedGate, err := validation.NewProtectedGate(protectedContract, validation.ProtectedConfig{
		Environment: validation.EnvironmentDemo,
		Demo: validation.DemoExceptionConfig{
			Profile: validation.DemoExceptionIsolatedRFC5737, AllowRFC5737: true,
			IsolationVerified: true, HostRulesetUnchanged: true,
			ClientCIDR: "203.0.113.0/24", AttackSourceIPv4: "203.0.113.20",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	baseContract, err := os.ReadFile(filepath.Join(
		"..", "..", "contracts", "enforcement", "nft_base_chain_v1.nft",
	))
	if err != nil {
		t.Fatal(err)
	}
	liveSchema, err := os.ReadFile(filepath.Join(
		"..", "..", "contracts", "enforcement", "nft_base_chain_v1.live.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	config := validationworker.DefaultConfig(
		"validation-worker", testDigest, "nftables v1.0.9", testDigest, testDigest,
	)
	config.Environment = validation.EnvironmentDemo
	config.LeaseDuration = 30 * time.Second
	runtime, err := validationworker.New(store, config, validationworker.Dependencies{
		Clock: runtimeTestClock{now: now}, Tokens: runtimeTestTokenSource{},
		Jitter: runtimeTestJitter{}, ProtectedGate: protectedGate,
		SyntaxChecker: runtimeTestSyntaxChecker{}, BaseContract: baseContract, LiveSchema: liveSchema,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.RunOnce(context.Background())
	if err != nil || result.Outcome != worker.OutcomeCompleted ||
		result.State != validationworker.StateValid {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	queries := db.queriesSnapshot()
	if len(queries) != 4 ||
		!strings.Contains(queries[1], "lease_validation_outbox_job") ||
		!strings.Contains(queries[2], "prepare_validation_attempt_verified_demo_000030") ||
		!strings.Contains(queries[3], "finalize_validation_attempt_exact") {
		t.Fatalf("queries=%q", queries)
	}
	_, arguments := db.lastCall()
	var mutation struct {
		State string `json:"state"`
		Gates []struct {
			Order  uint8  `json:"order"`
			Name   string `json:"name"`
			Passed bool   `json:"passed"`
		} `json:"gates"`
	}
	if len(arguments) != 9 || json.Unmarshal(arguments[7].([]byte), &mutation) != nil ||
		mutation.State != string(validationworker.StateValid) || len(mutation.Gates) != 6 {
		t.Fatalf("terminal mutation=%+v", mutation)
	}
	for index, gate := range mutation.Gates {
		if gate.Order != uint8(index+1) || !gate.Passed {
			t.Fatalf("gate %d=%+v", index, gate)
		}
	}
}

func TestStoreSanitizesPersistenceErrorsAndFencing(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name  string
		row   pgx.Row
		want  error
		found bool
	}{
		{name: "empty", row: rowFunc(func(...any) error { return pgx.ErrNoRows })},
		{name: "database", row: rowFunc(func(...any) error { return errors.New("password=secret") }), want: ErrPersistence},
		{name: "invalid", row: rowFunc(func(dest ...any) error {
			setLeaseRow(dest)
			*dest[1].(*string) = "analyze"
			return nil
		}), want: ErrInvalidRow},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store, _ := NewPostgreSQLStore(&queryStub{rows: []pgx.Row{testCase.row}})
			_, found, err := store.Lease(context.Background(), leaseRequest())
			if found != testCase.found || !errors.Is(err, testCase.want) || strings.Contains(errorText(err), "secret") {
				t.Fatalf("found=%v err=%v", found, err)
			}
		})
	}
	store, _ := NewPostgreSQLStore(&queryStub{rows: []pgx.Row{rowFunc(func(...any) error { return pgx.ErrNoRows })}})
	if finished, err := store.Finalize(context.Background(), invalidFinalize()); err != nil || finished {
		t.Fatalf("fenced finalize finished=%v err=%v", finished, err)
	}
}

func TestPrepareRejectsAmbiguousOrUnsafeSnapshots(t *testing.T) {
	t.Parallel()
	valid := snapshotJSON(t)
	variants := [][]byte{
		[]byte(`{"validation_attempt_id":"x"}`),
		append(valid[:len(valid)-1], []byte(`,"unknown":true}`)...),
		[]byte(`{"validation_attempt_id":"a","validation_attempt_id":"b"}`),
		{0xff, 0xfe},
	}
	for index, document := range variants {
		store, _ := NewPostgreSQLStore(&queryStub{rows: []pgx.Row{rowFunc(func(dest ...any) error {
			*dest[0].(*string) = "prepared"
			*dest[1].(*[]byte) = append([]byte(nil), document...)
			*dest[2].(*[]byte) = testEvidenceCanonical(t)
			return nil
		})}})
		if _, prepared, err := store.Prepare(context.Background(), prepareRequest()); prepared || !errors.Is(err, ErrInvalidRow) {
			t.Fatalf("variant %d prepared=%v err=%v", index, prepared, err)
		}
	}
}

func TestStoreClassifiesEvidenceStalenessWithoutDatabaseDetail(t *testing.T) {
	t.Parallel()
	stale := &pgconn.PgError{Code: "SF005", Message: "observed secret evidence"}
	prepareStore, _ := NewPostgreSQLStore(&queryStub{rows: []pgx.Row{
		rowFunc(func(...any) error { return stale }),
	}})
	if _, prepared, err := prepareStore.Prepare(context.Background(), prepareRequest()); prepared || !errors.Is(err, ErrEvidenceStale) || strings.Contains(errorText(err), "secret") {
		t.Fatalf("prepared=%v err=%v", prepared, err)
	}

	finalizeStore, _ := NewPostgreSQLStore(&queryStub{rows: []pgx.Row{
		rowFunc(func(...any) error { return stale }),
	}})
	if finished, err := finalizeStore.Finalize(context.Background(), validFinalize()); finished || !errors.Is(err, ErrEvidenceStale) || strings.Contains(errorText(err), "secret") {
		t.Fatalf("finished=%v err=%v", finished, err)
	}

	deadStore, _ := NewPostgreSQLStore(&queryStub{rows: []pgx.Row{
		rowFunc(func(dest ...any) error {
			*dest[0].(*string) = testJobID
			*dest[1].(*string) = "dead"
			return nil
		}),
	}})
	if finished, err := deadStore.Finalize(context.Background(), validFinalize()); finished || !errors.Is(err, ErrEvidenceStale) {
		t.Fatalf("stale terminal finished=%v err=%v", finished, err)
	}
}

func TestPersistenceConflictClassificationIsExactAndRedacted(t *testing.T) {
	t.Parallel()
	for _, code := range []string{"40001", "40P01", "55P03"} {
		classified := classifyPersistenceError(&pgconn.PgError{Code: code, Message: "secret row"})
		if !errors.Is(classified, validationworker.ErrRetryablePersistence) ||
			strings.Contains(classified.Error(), "secret") {
			t.Fatalf("code=%s classified=%v", code, classified)
		}
	}
	for _, err := range []error{
		&pgconn.PgError{Code: "23505", Message: "secret row"},
		&pgconn.PgError{Code: "57014", Message: "secret cancellation"},
		errors.New("secret transport"),
	} {
		classified := classifyPersistenceError(err)
		if !errors.Is(classified, ErrPersistence) ||
			errors.Is(classified, validationworker.ErrRetryablePersistence) ||
			strings.Contains(classified.Error(), "secret") {
			t.Fatalf("classified=%v", classified)
		}
	}
}

func TestFinalizeWireIsBoundedAndRejectsAmbiguityBeforeQuery(t *testing.T) {
	t.Parallel()
	db := &queryStub{rows: []pgx.Row{rowFunc(func(dest ...any) error {
		*dest[0].(*string) = testJobID
		*dest[1].(*string) = "completed"
		return nil
	})}}
	store, _ := NewPostgreSQLStore(db)
	request := validFinalize()
	if finished, err := store.Finalize(context.Background(), request); err != nil || !finished {
		t.Fatalf("finished=%v err=%v", finished, err)
	}
	_, args := db.lastCall()
	payload := string(args[7].([]byte))
	if !strings.Contains(payload, `"validation_attempt_id":"`+testAttemptID+`"`) ||
		!strings.Contains(payload, `"canonical_hex":"7b7d"`) || strings.Contains(payload, "CanonicalBytes") {
		t.Fatalf("payload=%s", payload)
	}

	badDB := &queryStub{rows: []pgx.Row{rowFunc(func(...any) error {
		t.Fatal("invalid mutation reached database")
		return nil
	})}}
	badStore, _ := NewPostgreSQLStore(badDB)
	bad := validFinalize()
	bad.Mutation.Gates[4].Passed = false
	if _, err := badStore.Finalize(context.Background(), bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error=%v", err)
	}
	if len(badDB.queriesSnapshot()) != 0 {
		t.Fatal("invalid mutation issued query")
	}
}

func snapshotJSON(t *testing.T) []byte {
	t.Helper()
	structured := []byte(`{}`)
	evidenceCanonical := testEvidenceCanonical(t)
	value := snapshotDocument{
		ValidationAttemptID: testAttemptID, PolicyID: testPolicyID,
		ValidationID: testValidationID, CommandCandidateID: testCandidateID,
		AnalysisID: testAnalysisID, IncidentID: testIncidentID, IncidentVersion: 1,
		GeneratedAt: storeTestNow.Format(time.RFC3339Nano), EvidenceSnapshotID: testEvidenceID,
		EvidenceSnapshotDigest: digest(evidenceCanonical), AnalysisInputDigest: testDigest,
		OutputSchemaDigest: testDigest, PromptDigest: testDigest,
		AnalysisOutputDigest: digest(structured), GeneratedCommandDigest: testDigest,
		StructuredOutputHex: hex.EncodeToString(structured), PolicyOutputHex: "7b7d", CandidateOutputHex: "7b7d",
	}
	value.Evidence.SourceIPv4 = "8.8.8.8"
	value.Evidence.ServiceLabel = "gateway"
	value.Evidence.SourceHealthDigest = testDigest
	value.Evidence.SourceHealthStatus = validation.SourceHealthComplete
	value.Evidence.SignalIDs = []string{testSignalID}
	value.Evidence.EventIDs = []string{testEventID}
	value.Evidence.Signals = []signalDocument{{
		SignalID: testSignalID, SignalDigest: testDigest, SourceIPv4: "8.8.8.8",
		EventIDs: []string{testEventID}, ThresholdReproduced: true,
		SourceHealthStatus: validation.SourceHealthComplete,
	}}
	value.History.Cutoff = storeTestNow.Format(time.RFC3339Nano)
	value.History.WindowStart = storeTestNow.Add(-24 * time.Hour).Format(time.RFC3339Nano)
	value.History.CoverageComplete = true
	value.History.GatewayRecords = []gatewayDocument{{
		EventID: testGatewayID, OccurredAt: storeTestNow.Add(-time.Hour).Format(time.RFC3339Nano),
		SourceIPv4: "8.8.8.8", StatusCode: 404, TimestampTrust: "trusted",
	}}
	value.History.AuthRecords = []authDocument{{
		EventID: testAuthID, OccurredAt: storeTestNow.Add(-time.Minute).Format(time.RFC3339Nano),
		SourceIPv4: "8.8.8.8", Outcome: "failed", TimestampTrust: "trusted", Binding: "verified",
	}}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func demoSnapshotJSON(t *testing.T) []byte {
	t.Helper()
	var document snapshotDocument
	if err := json.Unmarshal(snapshotJSON(t), &document); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	document.History.Cutoff = cutoff.Format(time.RFC3339Nano)
	document.History.WindowStart = cutoff.Add(-validation.HistoricalImpactLookback).Format(time.RFC3339Nano)
	document.History.GatewayRecords[0].OccurredAt = cutoff.Add(-time.Hour).Format(time.RFC3339Nano)
	document.History.AuthRecords[0].OccurredAt = cutoff.Add(-time.Minute).Format(time.RFC3339Nano)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func validDemoRuntimeSnapshotJSON(t *testing.T, generatedAt time.Time) ([]byte, []byte) {
	t.Helper()
	checkedEvidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:    testEvidenceID, IncidentID: testIncidentID, IncidentVersion: 1,
		SourceIPv4: "203.0.113.20", ServiceLabel: "gateway",
		WindowStart: generatedAt.Add(-time.Minute), WindowEnd: generatedAt,
		SourceHealthDigest: testDigest, EventIDs: []string{testEventID},
		SignalIDs: []string{testSignalID}, CreatedAt: generatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	command := "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }"
	policyValue := map[string]any{
		"schema_version": policy.PolicySchemaVersion, "action": policy.ActionBlockIP,
		"target_ip": "203.0.113.20", "ttl_seconds": 1800,
		"evidence_ids": []string{testSignalID},
		"rationale":    "Complete deterministic evidence supports a temporary block.",
	}
	candidateValue := map[string]any{
		"schema_version": policy.CandidateSchemaVersion, "target_ip": "203.0.113.20",
		"timeout": "30m", "evidence_ids": []string{testSignalID}, "command": command,
	}
	policyJSON, err := json.Marshal(policyValue)
	if err != nil {
		t.Fatal(err)
	}
	candidateJSON, err := json.Marshal(candidateValue)
	if err != nil {
		t.Fatal(err)
	}
	structured, err := json.Marshal(map[string]any{
		"schema_version":   "sentinelflow_analysis_v1",
		"incident_summary": "Synthetic test incident.", "classification": "path_scan",
		"confidence": 0.9, "uncertainty": "", "false_positive_factors": []string{},
		"evidence_ids": []string{testSignalID}, "policy": policyValue,
		"nftables_command_candidate": candidateValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	cutoff := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	document := snapshotDocument{
		ValidationAttemptID: testAttemptID, PolicyID: testPolicyID,
		ValidationID: testValidationID, CommandCandidateID: testCandidateID,
		AnalysisID: testAnalysisID, IncidentID: testIncidentID, IncidentVersion: 1,
		GeneratedAt: generatedAt.Format(time.RFC3339Nano), EvidenceSnapshotID: testEvidenceID,
		EvidenceSnapshotDigest: checkedEvidence.Digest(), AnalysisInputDigest: testDigest,
		OutputSchemaDigest: testDigest, PromptDigest: testDigest,
		AnalysisOutputDigest: digest(structured), GeneratedCommandDigest: digest([]byte(command)),
		StructuredOutputHex: hex.EncodeToString(structured), PolicyOutputHex: hex.EncodeToString(policyJSON),
		CandidateOutputHex: hex.EncodeToString(candidateJSON),
	}
	document.Evidence.SourceIPv4 = "203.0.113.20"
	document.Evidence.ServiceLabel = "gateway"
	document.Evidence.SourceHealthDigest = testDigest
	document.Evidence.SourceHealthStatus = validation.SourceHealthComplete
	document.Evidence.SignalIDs = []string{testSignalID}
	document.Evidence.EventIDs = []string{testEventID}
	document.Evidence.Signals = []signalDocument{{
		SignalID: testSignalID, SignalDigest: testDigest, SourceIPv4: "203.0.113.20",
		EventIDs: []string{testEventID}, ThresholdReproduced: true,
		SourceHealthStatus: validation.SourceHealthComplete,
	}}
	document.History.Cutoff = cutoff.Format(time.RFC3339Nano)
	document.History.WindowStart = cutoff.Add(-validation.HistoricalImpactLookback).Format(time.RFC3339Nano)
	document.History.CoverageComplete = true
	document.History.GatewayRecords = []gatewayDocument{
		{EventID: "019b0000-0000-7000-8000-000000000101", OccurredAt: cutoff.Add(-23 * time.Hour).Format(time.RFC3339Nano), SourceIPv4: "203.0.113.20", StatusCode: 401, TimestampTrust: "trusted"},
		{EventID: "019b0000-0000-7000-8000-000000000105", OccurredAt: cutoff.Add(-12 * time.Hour).Format(time.RFC3339Nano), SourceIPv4: "203.0.113.20", StatusCode: 200, TimestampTrust: "trusted"},
		{EventID: "019b0000-0000-7000-8000-000000000108", OccurredAt: cutoff.Add(-time.Minute).Format(time.RFC3339Nano), SourceIPv4: "203.0.113.20", StatusCode: 204, TimestampTrust: "trusted"},
	}
	document.History.AuthRecords = []authDocument{{
		EventID: "019b0000-0000-7000-8000-000000000104", OccurredAt: cutoff.Add(-23*time.Hour + 6*time.Millisecond).Format(time.RFC3339Nano),
		SourceIPv4: "203.0.113.20", Outcome: "failed", TimestampTrust: "trusted", Binding: "verified",
	}}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, checkedEvidence.CanonicalBytes()
}

func fixtureDemoActivation(
	t *testing.T,
	db queryRower,
	consumer validation.DemoHistoryActivationConsumer,
) validation.ActivatedDemoHistoryBinding {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clockAt := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	issuedAt := time.Now().UTC().Truncate(time.Millisecond)
	runScope := "sentinelflow-demo-run:019b0000-0000-7000-8000-000000000901"
	manifest := map[string]any{
		"clock_at":               clockAt.Format("2006-01-02T15:04:05.000Z"),
		"coverage_end":           clockAt.Format("2006-01-02T15:04:05.000Z"),
		"coverage_start":         clockAt.Add(-validation.HistoricalImpactLookback).Format("2006-01-02T15:04:05.000Z"),
		"dataset_digest":         validation.PinnedDemoHistoryDatasetDigest,
		"dataset_id":             validation.PinnedDemoHistoryDatasetID,
		"dataset_record_count":   validation.PinnedDemoHistoryDatasetRecordCount,
		"dataset_schema_version": validation.DemoHistoryDatasetSchemaVersion,
		"import_id":              "019b0000-0000-7000-8000-000000000501",
		"issued_at":              issuedAt.Format("2006-01-02T15:04:05.000Z"),
		"manifest_id":            "019b0000-0000-7000-8000-000000000500",
		"path_catalog_version":   "path-catalog-v1",
		"profile":                validation.DemoHistoryProfile,
		"schema_version":         validation.DemoHistoryManifestSchemaVersion,
		"source_health_digest":   validation.PinnedDemoHistorySourceHealthDigest,
	}
	manifestJCS, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest(manifestJCS)
	digestBytes, err := hex.DecodeString(strings.TrimPrefix(manifestDigest, "sha256:"))
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey,
		append([]byte(validation.DemoHistorySignatureDomain+"\n"), digestBytes...))
	envelope, err := json.Marshal(map[string]any{
		"fixture_only":        false,
		"key_scope":           runScope,
		"manifest":            manifest,
		"manifest_digest":     manifestDigest,
		"manifest_jcs_b64url": base64.RawURLEncoding.EncodeToString(manifestJCS),
		"public_key_b64url":   base64.RawURLEncoding.EncodeToString(publicKey),
		"schema_version":      validation.DemoHistorySignedManifestSchemaVersion,
		"signature_b64url":    base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := validation.NewStrictDemoHistoryManifestVerifier(validation.DemoHistoryManifestVerifierConfig{
		Environment:                      validation.EnvironmentDemo,
		ExpectedPublicKey:                publicKey,
		ExpectedRunScope:                 runScope,
		ExpectedImportID:                 "019b0000-0000-7000-8000-000000000501",
		ExpectedClockAt:                  clockAt,
		ExpectedImpactSourceHealthDigest: validation.PinnedDemoHistoryImpactSourceHealthDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := validation.CreateDemoHistoryRuntimeActivationPair(
		context.Background(), db, []byte(strings.Repeat("a", 32)),
		[]byte(strings.Repeat("v", 32)), verifier,
		validation.DemoHistoryVerificationInput{
			SignedManifestEnvelope: envelope,
			ImportedRowsDigest:     validation.PinnedDemoHistoryImportedRowsDigest,
			ImportedRecordCount:    validation.PinnedDemoHistoryDatasetRecordCount,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if consumer == validation.DemoHistoryConsumerAnalysis {
		activation, ok := pair.Analysis()
		if !ok {
			t.Fatal("analysis activation unavailable")
		}
		return activation
	}
	activation, ok := pair.Validation()
	if !ok {
		t.Fatal("validation activation unavailable")
	}
	return activation
}

func validFinalize() validationworker.FinalizeRequest {
	generated := []byte("add element inet sentinelflow blacklist_ipv4 { 8.8.8.8 timeout 30m }")
	canonical := append(append([]byte(nil), generated...), '\n')
	policyBytes := []byte(`{}`)
	validationBytes := []byte(`{}`)
	evidenceCanonical := testEvidenceCanonical(nil)
	evidenceDigest := digest(evidenceCanonical)
	checks := []validation.ValidationCheckID{
		validation.CheckStructuredOutput, validation.CheckCommandGrammar,
		validation.CheckPolicyEvidenceCommandConsistency, validation.CheckProtectedNetwork,
		validation.CheckOwnedSchemaSyntax, validation.CheckHistoricalImpact,
	}
	gates := make([]validationworker.GateRecord, len(checks))
	for index, check := range checks {
		gates[index] = validationworker.GateRecord{
			Order: uint8(index + 1), Name: check, Passed: true, ResultCode: "ok",
			InputDigest: testDigest, ResultDigest: testDigest,
		}
	}
	return validationworker.FinalizeRequest{
		Finish: worker.FinishRequest{State: worker.FinishCompleted, Now: storeTestNow, JobID: testJobID, LeaseToken: testLeaseToken},
		Mutation: &validationworker.Mutation{
			ValidationAttemptID: testAttemptID, AnalysisID: testAnalysisID,
			IncidentID: testIncidentID, IncidentVersion: 1, State: validationworker.StateValid,
			FailureCode: validationworker.ValidationFailureNone,
			AuditAction: validationworker.ValidationAuditSucceeded, Gates: gates,
			EvidenceCanonicalBytes: evidenceCanonical,
			Candidate: &validationworker.CandidateRecord{
				SchemaVersion: policy.CandidateSchemaVersion, TargetIPv4: "8.8.8.8",
				TimeoutToken: "30m", TTLSeconds: 1800, GeneratedBytes: generated,
				GeneratedDigest: digest(generated), CanonicalBytes: canonical, CanonicalDigest: digest(canonical),
			},
			Policy: &validationworker.PolicyRecord{
				SchemaVersion: policy.PolicySchemaVersion, PolicyID: testPolicyID, PolicyVersion: 1,
				CanonicalBytes: policyBytes, PolicyDigest: digest(policyBytes), TargetIPv4: "8.8.8.8",
				TTLSeconds: 1800, Rationale: "Synthetic evidence supports a temporary block.",
			},
			Validation: &validationworker.ValidationRecord{
				CanonicalBytes: validationBytes, SnapshotDigest: digest(validationBytes),
				PolicyDigest: digest(policyBytes), EvidenceSnapshotDigest: evidenceDigest,
				AnalysisInputDigest: testDigest, AnalysisOutputSchemaDigest: testDigest,
				PromptDigest: testDigest, GeneratedCandidateDigest: digest(generated),
				CanonicalArtifactDigest: digest(canonical), GrammarVersion: policy.CandidateSchemaVersion,
				ParserVersion:              validationworker.ValidationParserVersion,
				ValidatorVersion:           validationworker.ValidationValidatorVersion,
				BaseChainContractRawDigest: testDigest, LiveOwnedSchemaDigest: testDigest,
				ProtectedIPv4StaticDigest: testDigest, ProtectedIPv4EffectiveConfigDigest: testDigest,
				NFTBinaryDigest: testDigest, NFTVersion: "1.0.9", HistoricalImpactDigest: testDigest,
				TargetIPv4: "8.8.8.8", TTLSeconds: 1800, SourceHealthStatus: validation.SourceHealthComplete,
				CreatedAt: storeTestNow, ValidUntil: storeTestNow.Add(validation.ValidationSnapshotLifetime),
			},
		},
	}
}

func testEvidenceCanonical(t *testing.T) []byte {
	checked, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:    testEvidenceID, IncidentID: testIncidentID, IncidentVersion: 1,
		SourceIPv4: "8.8.8.8", ServiceLabel: "gateway",
		WindowStart: storeTestNow.Add(-time.Minute), WindowEnd: storeTestNow,
		SourceHealthDigest: testDigest, EventIDs: []string{testEventID},
		SignalIDs: []string{testSignalID}, CreatedAt: storeTestNow,
	})
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return checked.CanonicalBytes()
}

func invalidFinalize() validationworker.FinalizeRequest {
	request := validFinalize()
	request.Mutation.State = validationworker.StateInvalid
	request.Mutation.FailureCode = "structured_output_invalid"
	request.Mutation.AuditAction = validationworker.ValidationAuditRejected
	request.Mutation.Gates = []validationworker.GateRecord{{
		Order: 1, Name: validation.CheckStructuredOutput, Passed: false,
		ResultCode: "structured_output_invalid", InputDigest: testDigest, ResultDigest: testDigest,
	}}
	request.Mutation.Candidate = nil
	request.Mutation.Policy = nil
	request.Mutation.Validation = nil
	return request
}

func leaseRequest() worker.LeaseRequest {
	return worker.LeaseRequest{
		Now: storeTestNow, LeaseToken: testLeaseToken, LeaseOwner: "validation-worker",
		LeaseExpiresAt: storeTestNow.Add(30 * time.Second),
	}
}

func prepareRequest() validationworker.PrepareRequest {
	return validationworker.PrepareRequest{Job: worker.Job{
		JobID: testJobID, Kind: worker.JobValidate,
		AggregateType: validationworker.ValidationAggregateType,
		AggregateID:   testAnalysisID, AggregateVersion: 1, Attempt: 1, MaxAttempts: 3,
	}, LeaseToken: testLeaseToken}
}

func setLeaseRow(dest []any) {
	setLeaseRowAt(dest, storeTestNow)
}

func setLeaseRowAt(dest []any, now time.Time) {
	*dest[0].(*string) = testJobID
	*dest[1].(*string) = "validate"
	*dest[2].(*string) = validationworker.ValidationAggregateType
	*dest[3].(*string) = testAnalysisID
	*dest[4].(*int32) = 1
	*dest[5].(*string) = "leased"
	*dest[6].(*time.Time) = now
	*dest[7].(*string) = testLeaseToken
	*dest[8].(*string) = "validation-worker"
	*dest[9].(*time.Time) = now
	*dest[10].(*time.Time) = now.Add(30 * time.Second)
	*dest[11].(*int32) = 1
	*dest[12].(*int32) = 3
}

type runtimeTestClock struct{ now time.Time }

func (clock runtimeTestClock) Now() time.Time                       { return clock.now }
func (runtimeTestClock) Sleep(context.Context, time.Duration) error { return nil }

type runtimeTestTokenSource struct{}

func (runtimeTestTokenSource) NewLeaseToken() (string, error) { return testLeaseToken, nil }

type runtimeTestJitter struct{}

func (runtimeTestJitter) Uint64() (uint64, error) { return 0, nil }

type runtimeTestSyntaxChecker struct{}

func (runtimeTestSyntaxChecker) Check(context.Context, nftcheck.Input) (nftcheck.Evidence, error) {
	return nftcheck.Evidence{NFTVersion: "nftables v1.0.9"}, nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type rowFunc func(...any) error

func (row rowFunc) Scan(dest ...any) error { return row(dest...) }

type queryStub struct {
	queries []string
	args    [][]any
	rows    []pgx.Row
}

func (stub *queryStub) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	stub.queries = append(stub.queries, query)
	stub.args = append(stub.args, append([]any(nil), args...))
	index := len(stub.queries) - 1
	if index >= len(stub.rows) {
		return rowFunc(func(...any) error { return pgx.ErrNoRows })
	}
	return stub.rows[index]
}

func (stub *queryStub) queriesSnapshot() []string {
	return append([]string(nil), stub.queries...)
}

func (stub *queryStub) lastCall() (string, []any) {
	index := len(stub.queries) - 1
	return stub.queries[index], append([]any(nil), stub.args[index]...)
}
