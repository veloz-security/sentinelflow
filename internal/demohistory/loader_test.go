package demohistory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/validation"
)

func TestLoadPinnedFixtureGolden(t *testing.T) {
	raw := readFixture(t)
	dataset, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}

	if dataset.SchemaVersion() != DatasetSchemaVersion || dataset.DatasetID() != PinnedDatasetID ||
		dataset.PathCatalogVersion() != events.PathCatalogV1 {
		t.Fatal("dataset identity projection mismatch")
	}
	if dataset.RecordCount() != PinnedImportedRecordCount || len(dataset.Records()) != 4 ||
		len(dataset.GatewayHTTPRecords()) != 3 || len(dataset.AuthEventRecords()) != 1 {
		t.Fatal("record projection count mismatch")
	}
	if dataset.ManifestDatasetJCSDigest() != validation.PinnedDemoHistoryDatasetDigest ||
		dataset.ImportedRowsJCSDigest() != validation.PinnedDemoHistoryImportedRowsDigest ||
		dataset.SourceHealthJCSDigest() != validation.PinnedDemoHistorySourceHealthDigest ||
		dataset.RecordCount() != validation.PinnedDemoHistoryDatasetRecordCount {
		t.Fatal("loader digest domains drifted from validation manifest pins")
	}
	if DatasetSchemaVersion != validation.DemoHistoryDatasetSchemaVersion || PinnedDatasetID != validation.PinnedDemoHistoryDatasetID {
		t.Fatal("loader identity constants drifted from validation manifest contract")
	}

	expectedRawDigest := independentSHA256(raw)
	if dataset.RawFileByteSHA256() != expectedRawDigest || !dataset.MatchesRawFileBytes(raw) {
		t.Fatal("raw-file byte provenance mismatch")
	}
	if dataset.RawFileByteSHA256() == dataset.ManifestDatasetJCSDigest() {
		t.Fatal("formatted raw-file digest was confused with canonical manifest digest")
	}

	start := mustTime(t, "2026-07-17T02:00:00.000Z")
	end := mustTime(t, "2026-07-18T02:00:00.000Z")
	if !dataset.CoverageStart().Equal(start) || !dataset.CoverageEnd().Equal(end) {
		t.Fatal("coverage projection mismatch")
	}
	records := dataset.Records()
	wantKinds := []RecordKind{RecordGatewayHTTP, RecordAuthEvent, RecordGatewayHTTP, RecordGatewayHTTP}
	for index := range wantKinds {
		if records[index].Kind() != wantKinds[index] {
			t.Fatalf("record %d kind=%q", index, records[index].Kind())
		}
	}
	firstGateway, ok := records[0].GatewayHTTP()
	if !ok || firstGateway.RequestID != "019b0000-0000-7000-8000-000000000102" || firstGateway.RouteLabel != "login" {
		t.Fatal("gateway projection mismatch")
	}
	auth, ok := records[1].AuthEvent()
	if !ok || auth.GatewayRequestID != firstGateway.RequestID || auth.TraceID != firstGateway.TraceID ||
		auth.SourceIP != firstGateway.SourceIP || auth.Outcome != events.AuthOutcomeFailed {
		t.Fatal("auth request binding projection mismatch")
	}
	coverage := dataset.SourceCoverage()
	if len(coverage) != 2 || coverage[0].SenderID() != "auth-demo" || coverage[1].SenderID() != "gateway-demo" ||
		coverage[0].CoverageStatus() != "complete" || coverage[0].UnresolvedIntervalCount() != 0 ||
		coverage[0].FirstSequence() != 1 || coverage[0].LastSequence() != 1 ||
		coverage[1].FirstSequence() != 1 || coverage[1].LastSequence() != 3 {
		t.Fatal("source coverage projection mismatch")
	}
}

func TestRawFileDigestIsObservationalNotManifestAuthority(t *testing.T) {
	raw := readFixture(t)
	original, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	reformatted, err := Load(compact.Bytes())
	if err != nil {
		t.Fatalf("semantically identical formatting must preserve JCS authority: %v", err)
	}
	if original.RawFileByteSHA256() == reformatted.RawFileByteSHA256() {
		t.Fatal("different formatted bytes unexpectedly had the same raw digest")
	}
	if original.ManifestDatasetJCSDigest() != reformatted.ManifestDatasetJCSDigest() ||
		original.ImportedRowsJCSDigest() != reformatted.ImportedRowsJCSDigest() ||
		original.SourceHealthJCSDigest() != reformatted.SourceHealthJCSDigest() {
		t.Fatal("format-only change altered a canonical/JCS digest")
	}
	if original.RawFileByteSHA256() == validation.PinnedDemoHistoryDatasetDigest ||
		reformatted.RawFileByteSHA256() == validation.PinnedDemoHistoryDatasetDigest {
		t.Fatal("manifest JCS pin must never be treated as the raw-file byte digest")
	}
	if original.MatchesRawFileBytes(compact.Bytes()) || !reformatted.MatchesRawFileBytes(compact.Bytes()) {
		t.Fatal("raw-file provenance check crossed dataset instances")
	}
}

func TestLoadRejectsCanonicalDigestMutation(t *testing.T) {
	mutated := mutateDataset(t, func(root map[string]any) {
		record(root, 2)["host"] = "changed.example.test"
	})
	if _, err := parseDataset(mutated); err != nil {
		t.Fatalf("well-shaped unpinned mutation should reach the pin gate: %v", err)
	}
	assertCode(t, loadError(mutated), ErrorDigest)
}

func TestStrictStructuralMutations(t *testing.T) {
	raw := readFixture(t)
	tests := []struct {
		name string
		raw  func() []byte
		code ErrorCode
	}{
		{"empty", func() []byte { return nil }, ErrorInputBounds},
		{"invalid utf8", func() []byte { return append(append([]byte(nil), raw...), 0xff) }, ErrorEncoding},
		{"trailing bytes", func() []byte { return append(append([]byte(nil), raw...), []byte(" true")...) }, ErrorJSON},
		{"root array", func() []byte { return []byte(`[]`) }, ErrorJSON},
		{"duplicate top field", func() []byte {
			return replaceOnce(t, raw, `"schema_version": "demo-history-dataset-v1",`, `"schema_version": "demo-history-dataset-v1", "schema_version": "demo-history-dataset-v1",`)
		}, ErrorShape},
		{"duplicate record field", func() []byte {
			return replaceFirst(t, raw, `"schema_version": "gateway-http-v1",`, `"schema_version": "gateway-http-v1", "schema_version": "gateway-http-v1",`)
		}, ErrorShape},
		{"duplicate source field", func() []byte {
			return replaceOnce(t, raw, `"sender_id": "auth-demo",`, `"sender_id": "auth-demo", "sender_id": "auth-demo",`)
		}, ErrorShape},
		{"unknown top field", func() []byte {
			return mutateDataset(t, func(root map[string]any) { root["unknown"] = "x" })
		}, ErrorShape},
		{"unknown record field", func() []byte {
			return mutateDataset(t, func(root map[string]any) { record(root, 0)["request_path"] = "/forbidden" })
		}, ErrorContract},
		{"unknown source field", func() []byte {
			return mutateDataset(t, func(root map[string]any) { source(root, 0)["unknown"] = "x" })
		}, ErrorShape},
		{"fractional integer", func() []byte {
			return replaceFirst(t, raw, `"first_sequence": 1,`, `"first_sequence": 1.0,`)
		}, ErrorContract},
		{"exponent integer", func() []byte {
			return replaceFirst(t, raw, `"first_sequence": 1,`, `"first_sequence": 1e0,`)
		}, ErrorContract},
		{"unsafe integer", func() []byte {
			return replaceOnce(t, raw, `"last_sequence": 3,`, `"last_sequence": 9007199254740992,`)
		}, ErrorContract},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseDataset(test.raw())
			assertCode(t, err, test.code)
		})
	}
}

func TestContractCoverageOrderingAndBindingMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		code   ErrorCode
	}{
		{"schema", func(root map[string]any) { root["schema_version"] = "demo-history-dataset-v2" }, ErrorContract},
		{"dataset id", func(root map[string]any) { root["dataset_id"] = "019b0000-0000-7000-8000-000000000999" }, ErrorContract},
		{"path catalog", func(root map[string]any) { root["path_catalog_version"] = "path-catalog-v2" }, ErrorContract},
		{"coverage precision", func(root map[string]any) { root["coverage_start"] = "2026-07-17T02:00:00Z" }, ErrorCoverage},
		{"coverage duration", func(root map[string]any) { root["coverage_end"] = "2026-07-18T01:59:59.999Z" }, ErrorCoverage},
		{"empty records", func(root map[string]any) { root["records"] = []any{} }, ErrorShape},
		{"one source", func(root map[string]any) { root["source_health"] = root["source_health"].([]any)[:1] }, ErrorShape},
		{"unsupported record", func(root map[string]any) { record(root, 0)["schema_version"] = "source-health-v1" }, ErrorContract},
		{"record catalog mismatch", func(root map[string]any) { record(root, 0)["path_catalog_version"] = "path-catalog-v2" }, ErrorContract},
		{"record outside coverage", func(root map[string]any) { record(root, 3)["completed_at"] = "2026-07-18T02:00:00.001Z" }, ErrorCoverage},
		{"record nanosecond precision", func(root map[string]any) { record(root, 3)["completed_at"] = "2026-07-18T01:59:00.000001Z" }, ErrorContract},
		{"record ordering", func(root map[string]any) {
			records := root["records"].([]any)
			records[1], records[2] = records[2], records[1]
		}, ErrorOrdering},
		{"duplicate event id", func(root map[string]any) { record(root, 1)["event_id"] = record(root, 0)["event_id"] }, ErrorDuplicate},
		{"cross-kind id collision", func(root map[string]any) { record(root, 1)["event_id"] = record(root, 0)["request_id"] }, ErrorDuplicate},
		{"duplicate idempotency", func(root map[string]any) { record(root, 2)["idempotency_key"] = record(root, 0)["idempotency_key"] }, ErrorDuplicate},
		{"duplicate gateway request", func(root map[string]any) { record(root, 2)["request_id"] = record(root, 0)["request_id"] }, ErrorDuplicate},
		{"duplicate auth request binding", func(root map[string]any) {
			records := root["records"].([]any)
			duplicate := make(map[string]any, len(record(root, 1)))
			for key, value := range record(root, 1) {
				duplicate[key] = value
			}
			duplicate["event_id"] = "019b0000-0000-7000-8000-00000000010b"
			duplicate["idempotency_key"] = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
			root["records"] = append(records[:2], append([]any{duplicate}, records[2:]...)...)
		}, ErrorDuplicate},
		{"missing request binding", func(root map[string]any) {
			record(root, 1)["gateway_request_id"] = "019b0000-0000-7000-8000-000000000999"
		}, ErrorBinding},
		{"trace binding mismatch", func(root map[string]any) { record(root, 1)["trace_id"] = "019b0000-0000-7000-8000-000000000999" }, ErrorBinding},
		{"source binding mismatch", func(root map[string]any) { record(root, 1)["source_ip"] = "203.0.113.21" }, ErrorBinding},
		{"service binding mismatch", func(root map[string]any) { record(root, 1)["service_label"] = "other-app" }, ErrorBinding},
		{"route binding mismatch", func(root map[string]any) { record(root, 1)["route_label"] = "other" }, ErrorBinding},
		{"time binding mismatch", func(root map[string]any) { record(root, 1)["occurred_at"] = "2026-07-17T03:00:00.008Z" }, ErrorBinding},
		{"source ordering", func(root map[string]any) {
			health := root["source_health"].([]any)
			health[0], health[1] = health[1], health[0]
		}, ErrorOrdering},
		{"duplicate sender", func(root map[string]any) { source(root, 1)["sender_id"] = source(root, 0)["sender_id"] }, ErrorDuplicate},
		{"duplicate epoch", func(root map[string]any) { source(root, 1)["sender_epoch"] = source(root, 0)["sender_epoch"] }, ErrorDuplicate},
		{"bad epoch", func(root map[string]any) { source(root, 0)["sender_epoch"] = "not-base64url-epoch___" }, ErrorContract},
		{"source coverage mismatch", func(root map[string]any) { source(root, 0)["coverage_start"] = "2026-07-17T02:00:00.001Z" }, ErrorCoverage},
		{"source incomplete", func(root map[string]any) { source(root, 0)["coverage_status"] = "incomplete" }, ErrorCoverage},
		{"source sequence reverse", func(root map[string]any) { source(root, 1)["first_sequence"] = json.Number("4") }, ErrorCoverage},
		{"source unresolved", func(root map[string]any) { source(root, 0)["unresolved_intervals"] = []any{json.Number("1")} }, ErrorCoverage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseDataset(mutateDataset(t, test.mutate))
			assertCode(t, err, test.code)
		})
	}
}

func TestInputBounds(t *testing.T) {
	if MaxDatasetBytes <= 0 || MaxDatasetRecords != 100_000 || MinSourceHealthRecords != 2 || MaxSourceHealthRecords != 16 {
		t.Fatal("schema bounds drifted")
	}
	oversized := make([]byte, MaxDatasetBytes+1)
	_, err := parseDataset(oversized)
	assertCode(t, err, ErrorInputBounds)
}

func TestPrivacyMinimizedProjection(t *testing.T) {
	dataset, err := Load(readFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, gateway := range dataset.GatewayHTTPRecords() {
		assertNoForbiddenJSONFields(t, gateway)
	}
	for _, auth := range dataset.AuthEventRecords() {
		assertNoForbiddenJSONFields(t, auth)
	}
	assertNoExportedStorageFields(t, reflect.TypeOf(Dataset{}))
	assertNoExportedStorageFields(t, reflect.TypeOf(Record{}))
	assertNoExportedStorageFields(t, reflect.TypeOf(SourceCoverage{}))
}

func TestDatasetAccessorsAreDefensiveAndConcurrent(t *testing.T) {
	raw := readFixture(t)
	dataset, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	originalDigest := dataset.RawFileByteSHA256()
	originalRecordID := dataset.GatewayHTTPRecords()[0].EventID
	originalSender := dataset.SourceCoverage()[0].SenderID()

	records := dataset.Records()
	records[0] = records[1]
	gateways := dataset.GatewayHTTPRecords()
	gateways[0].EventID = "mutated"
	auth := dataset.AuthEventRecords()
	auth[0].AccountHash = "mutated"
	coverage := dataset.SourceCoverage()
	coverage[0] = coverage[1]
	for index := range raw {
		raw[index] = 0
	}
	if dataset.Records()[0].Kind() != RecordGatewayHTTP || dataset.GatewayHTTPRecords()[0].EventID != originalRecordID ||
		dataset.SourceCoverage()[0].SenderID() != originalSender || dataset.RawFileByteSHA256() != originalDigest {
		t.Fatal("caller mutation changed immutable dataset projection")
	}

	var wait sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				rows := dataset.Records()
				rows[0] = rows[len(rows)-1]
				gws := dataset.GatewayHTTPRecords()
				gws[0].RouteLabel = "mutated"
				health := dataset.SourceCoverage()
				health[0] = health[len(health)-1]
				_ = dataset.ManifestDatasetJCSDigest()
			}
		}()
	}
	wait.Wait()
	if dataset.GatewayHTTPRecords()[0].RouteLabel != "login" {
		t.Fatal("concurrent access changed immutable dataset")
	}
}

func FuzzLoadNeverPanics(f *testing.F) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "contracts", "fixtures", "demo_history_dataset_v1.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(fixture)
	f.Add([]byte(`{}`))
	f.Add([]byte{0xff, 0xfe, 0xfd})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		dataset, err := parseDataset(raw)
		if err == nil {
			if dataset.SchemaVersion() != DatasetSchemaVersion || dataset.DatasetID() != PinnedDatasetID ||
				dataset.PathCatalogVersion() != events.PathCatalogV1 || dataset.RecordCount() == 0 ||
				len(dataset.SourceCoverage()) < MinSourceHealthRecords || dataset.RawFileByteSHA256() == "" {
				t.Fatal("accepted dataset violated loader invariants")
			}
		}
		_, _ = Load(raw)
	})
}

func readFixture(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "fixtures", "demo_history_dataset_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutateDataset(t testing.TB, mutate func(map[string]any)) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(readFixture(t)))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatal(err)
	}
	mutate(root)
	result, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func record(root map[string]any, index int) map[string]any {
	return root["records"].([]any)[index].(map[string]any)
}

func source(root map[string]any, index int) map[string]any {
	return root["source_health"].([]any)[index].(map[string]any)
}

func replaceOnce(t testing.TB, raw []byte, old, replacement string) []byte {
	t.Helper()
	if bytes.Count(raw, []byte(old)) != 1 {
		t.Fatalf("mutation target count for %q was not one", old)
	}
	return bytes.Replace(raw, []byte(old), []byte(replacement), 1)
}

func replaceFirst(t testing.TB, raw []byte, old, replacement string) []byte {
	t.Helper()
	if !bytes.Contains(raw, []byte(old)) {
		t.Fatalf("mutation target %q was missing", old)
	}
	return bytes.Replace(raw, []byte(old), []byte(replacement), 1)
}

func assertCode(t testing.TB, err error, expected ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s rejection", expected)
	}
	var datasetError *Error
	if !errors.As(err, &datasetError) || datasetError.Code != expected {
		t.Fatalf("error=%v code=%v want=%v", err, datasetError, expected)
	}
	if strings.Contains(err.Error(), "203.0.113") || strings.Contains(err.Error(), "hmac-sha256") {
		t.Fatal("error leaked rejected payload content")
	}
}

func loadError(raw []byte) error {
	_, err := Load(raw)
	return err
}

func independentSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func mustTime(t testing.TB, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.UTC()
}

func assertNoForbiddenJSONFields(t testing.TB, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"path", "exact_path", "query", "body", "cookie", "authorization", "headers",
		"request_target", "raw_target", "account", "username", "email", "session", "token",
	} {
		if _, exists := fields[forbidden]; exists {
			t.Fatalf("projection retained forbidden field %q", forbidden)
		}
	}
}

func assertNoExportedStorageFields(t testing.TB, value reflect.Type) {
	t.Helper()
	for _, field := range reflect.VisibleFields(value) {
		if field.PkgPath == "" {
			t.Fatalf("%s exposes mutable storage field %s", value, field.Name)
		}
	}
}
