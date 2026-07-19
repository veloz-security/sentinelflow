package demohistoryimport

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/demohistory"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const (
	fixtureImportID = "019b0000-0000-7000-8000-000000000501"
	fixtureClock    = "2026-07-18T02:00:00Z"
)

type failingBeginner struct {
	calls atomic.Int32
}

func (f *failingBeginner) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	f.calls.Add(1)
	return nil, errors.New("database must not be reached")
}

type staticReader struct {
	raw []byte
	err error
}

func (r staticReader) ReadPinnedDataset(context.Context) ([]byte, error) {
	return append([]byte(nil), r.raw...), r.err
}

type zeroBindingVerifier struct {
	calls          atomic.Int32
	immutableCalls atomic.Int32
}

func (v *zeroBindingVerifier) VerifyDemoHistory(context.Context, validation.DemoHistoryVerificationInput) (validation.VerifiedDemoHistoryBinding, error) {
	v.calls.Add(1)
	return validation.VerifiedDemoHistoryBinding{}, nil
}

// VerifyDemoHistoryImmutable intentionally mimics the strict verifier's
// exported method. Recovery must still reject this externally implementable
// shape rather than trusting method-name compatibility as authority.
func (v *zeroBindingVerifier) VerifyDemoHistoryImmutable(context.Context, validation.DemoHistoryVerificationInput) error {
	v.immutableCalls.Add(1)
	return nil
}

func TestImmutableRecoveryRejectsForgeableVerifierBeforeDatabase(t *testing.T) {
	db := &failingBeginner{}
	verifier := &zeroBindingVerifier{}
	importer, err := New(db, staticReader{raw: readFixture(t, validation.DemoHistoryDatasetLocator)}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	_, err = importer.ImportOrAttachExisting(context.Background(),
		readFixture(t, "contracts/fixtures/demo_history_manifest_v1.json"))
	assertCode(t, err, ErrorConfiguration)
	if db.calls.Load() != 0 || verifier.calls.Load() != 0 || verifier.immutableCalls.Load() != 0 {
		t.Fatalf("forgeable verifier reached authority boundary: db=%d fresh=%d immutable=%d",
			db.calls.Load(), verifier.calls.Load(), verifier.immutableCalls.Load())
	}
}

func TestVerifyManifestPersistsDistinctProofDomains(t *testing.T) {
	rawDataset := readFixture(t, validation.DemoHistoryDatasetLocator)
	dataset, err := demohistory.Load(rawDataset)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifyManifest(context.Background(), fixtureVerifier(t),
		readFixture(t, "contracts/fixtures/demo_history_manifest_v1.json"), dataset)
	if err != nil {
		t.Fatal(err)
	}
	wantClock := mustTime(t, fixtureClock)
	if claims.importID != fixtureImportID || claims.manifestID != "019b0000-0000-7000-8000-000000000500" ||
		claims.manifestDigest != "sha256:da25f169a263cd9e15bf3edb4617762d0a3c49a66478837a878a81b75d32bd7e" ||
		claims.runScopeDigest != "sha256:5b144bdd482baa1fc9cc336d673c84372dfcb70e3be1380feacde8c266faa279" ||
		claims.publicKeyDigest != "sha256:dac073e0123bdea59dd9b3bda9cf6037f63aca82627d7abcd5c4ac29dd74003e" ||
		claims.signatureVerificationDigest != "sha256:c28c85ff73806cdd449af9a018eb580c5839490711a94bf75d947f5529ffa8f0" ||
		!claims.clockAt.Equal(wantClock) || !claims.issuedAt.Equal(wantClock) ||
		claims.verifiedBinding.HistoryCutoff().At().IsZero() {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if dataset.RawFileByteSHA256() == dataset.ManifestDatasetJCSDigest() {
		t.Fatal("formatted-file provenance was confused with signed JCS authority")
	}
}

func TestUnverifiedBindingNeverReachesDatabase(t *testing.T) {
	db := &failingBeginner{}
	verifier := &zeroBindingVerifier{}
	importer, err := New(db, staticReader{raw: readFixture(t, validation.DemoHistoryDatasetLocator)}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	_, err = importer.Import(context.Background(), readFixture(t, "contracts/fixtures/demo_history_manifest_v1.json"))
	assertCode(t, err, ErrorBinding)
	if db.calls.Load() != 0 || verifier.calls.Load() != 1 {
		t.Fatalf("database calls=%d verifier calls=%d", db.calls.Load(), verifier.calls.Load())
	}
}

func TestInvalidInputFailsBeforeDatabase(t *testing.T) {
	tests := []struct {
		name     string
		dataset  []byte
		manifest []byte
		code     ErrorCode
	}{
		{name: "dataset", dataset: []byte(`{"schema_version":"wrong"}`), manifest: []byte(`{}`), code: ErrorDataset},
		{name: "manifest", dataset: readFixture(t, validation.DemoHistoryDatasetLocator), manifest: []byte(`{}`), code: ErrorManifest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := &failingBeginner{}
			importer, err := New(db, staticReader{raw: test.dataset}, fixtureVerifier(t))
			if err != nil {
				t.Fatal(err)
			}
			_, err = importer.Import(context.Background(), test.manifest)
			assertCode(t, err, test.code)
			if db.calls.Load() != 0 {
				t.Fatal("invalid authority reached PostgreSQL")
			}
		})
	}
}

func TestSyntheticBatchIsDeterministicAndContentFree(t *testing.T) {
	dataset, err := demohistory.Load(readFixture(t, validation.DemoHistoryDatasetLocator))
	if err != nil {
		t.Fatal(err)
	}
	record := dataset.Records()[0]
	event, ok := record.GatewayHTTP()
	if !ok {
		t.Fatal("first fixture record is not gateway-http-v1")
	}
	first, err := syntheticBatch("gateway-demo", "IiIiIiIiIiIiIiIiIiIiIg", gatewayBatchIDs[0], 1,
		event.CompletedAt.Time(), event)
	if err != nil {
		t.Fatal(err)
	}
	second, err := syntheticBatch("gateway-demo", "IiIiIiIiIiIiIiIiIiIiIg", gatewayBatchIDs[0], 1,
		event.CompletedAt.Time(), event)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.size < 2 || !strings.HasPrefix(first.digest, "sha256:") {
		t.Fatalf("non-deterministic synthetic batch: %#v %#v", first, second)
	}
	value := reflect.ValueOf(first)
	for index := 0; index < value.NumField(); index++ {
		if value.Type().Field(index).Name == "raw" || value.Type().Field(index).Type == reflect.TypeOf([]byte(nil)) {
			t.Fatal("synthetic batch retained raw content")
		}
	}
}

func TestResultHasNoExportedMutableFields(t *testing.T) {
	typ := reflect.TypeOf(Result{})
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath == "" {
			t.Fatalf("Result field %q is exported", field.Name)
		}
		if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Map || field.Type.Kind() == reflect.Pointer {
			t.Fatalf("Result field %q is mutable", field.Name)
		}
	}
	secret := "raw-secret-value"
	err := classify(context.Background(), errors.New(secret))
	if strings.Contains(err.Error(), secret) {
		t.Fatal("error leaked attacker-controlled content")
	}
}

func TestFixedDatasetFileBoundsAndContainment(t *testing.T) {
	if _, err := NewFixedDatasetFile("relative"); err == nil {
		t.Fatal("relative repository root accepted")
	}
	root := t.TempDir()
	fixturePath := filepath.Join(root, validation.DemoHistoryDatasetLocator)
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := readFixture(t, validation.DemoHistoryDatasetLocator)
	if err := os.WriteFile(fixturePath, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := NewFixedDatasetFile(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadPinnedDataset(context.Background())
	if err != nil || string(got) != string(fixture) {
		t.Fatalf("read fixed dataset: bytes=%d err=%v", len(got), err)
	}

	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixturePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, fixturePath); err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadPinnedDataset(context.Background())
	assertCode(t, err, ErrorSource)

	if err := os.Remove(fixturePath); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(fixturePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(demohistory.MaxDatasetBytes) + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadPinnedDataset(context.Background())
	assertCode(t, err, ErrorSource)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = reader.ReadPinnedDataset(canceled)
	assertCode(t, err, ErrorCanceled)
}

func fixtureVerifier(t testing.TB) *validation.StrictDemoHistoryManifestVerifier {
	return fixtureVerifierAt(t, mustTime(t, fixtureClock))
}

func fixtureVerifierAt(t testing.TB, securityNow time.Time) *validation.StrictDemoHistoryManifestVerifier {
	t.Helper()
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(validation.PinnedDemoHistoryFixturePublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("invalid checked-in public fixture key")
	}
	clockAt := mustTime(t, fixtureClock)
	verifier, err := validation.NewStrictDemoHistoryManifestVerifier(validation.DemoHistoryManifestVerifierConfig{
		Environment:                      validation.EnvironmentTest,
		ExpectedPublicKey:                publicKey,
		ExpectedRunScope:                 validation.DemoHistoryFixtureKeyScope,
		ExpectedImportID:                 fixtureImportID,
		ExpectedClockAt:                  clockAt,
		ExpectedImpactSourceHealthDigest: validation.PinnedDemoHistoryImpactSourceHealthDigest,
		AllowPublicTestFixture:           true,
		TestSecurityNow:                  securityNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func readFixture(t testing.TB, relative string) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustTime(t testing.TB, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Round(0).UTC()
}

func assertCode(t testing.TB, err error, want ErrorCode) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != want {
		t.Fatalf("error=%v code=%v want=%v", err, typed, want)
	}
}
