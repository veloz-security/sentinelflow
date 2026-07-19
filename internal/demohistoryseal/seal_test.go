package demohistoryseal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/demohistory"
	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/validation"
)

func TestSealCreatesFreshRunScopedPublicAuthority(t *testing.T) {
	raw := fixtureDataset(t)
	first, err := Seal(context.Background(), raw, bytes.NewReader(randomMaterial(1)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal(context.Background(), raw, bytes.NewReader(randomMaterial(101)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.SignedEnvelope(), second.SignedEnvelope()) || bytes.Equal(first.PublicAssertions(), second.PublicAssertions()) {
		t.Fatal("two demo runs reused authority material")
	}
	verifier, assertions, err := VerifyBundle(context.Background(), raw, first.SignedEnvelope(), first.PublicAssertions())
	if err != nil || verifier == nil {
		t.Fatal(err)
	}
	if assertions.PublicKeyB64URL() == validation.PinnedDemoHistoryFixturePublicKey ||
		!strings.HasPrefix(assertions.RunScope(), "sentinelflow-demo-run:") ||
		assertions.ImportID() == assertions.ManifestID() || assertions.IssuedAt().Before(assertions.ClockAt()) ||
		assertions.ImpactSourceHealthDigest() != "sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3" {
		t.Fatalf("invalid assertions: %+v", assertions)
	}
	dataset, err := demohistory.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := verifier.VerifyDemoHistory(context.Background(), validation.DemoHistoryVerificationInput{
		SignedManifestEnvelope: first.SignedEnvelope(), ImportedRowsDigest: dataset.ImportedRowsJCSDigest(),
		ImportedRecordCount: dataset.RecordCount(),
	})
	if err != nil || !binding.HistoryCutoff().At().Equal(dataset.CoverageEnd()) {
		t.Fatalf("fresh strict binding failed: %v", err)
	}
}

func TestImpactSourceHealthDigestMatchesValidationProjection(t *testing.T) {
	raw := fixtureDataset(t)
	dataset, err := demohistory.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ImpactSourceHealthDigest(dataset)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Seal(context.Background(), raw, bytes.NewReader(randomMaterial(7)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, _, err := VerifyBundle(context.Background(), raw, bundle.SignedEnvelope(), bundle.PublicAssertions())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := verifier.VerifyDemoHistory(context.Background(), validation.DemoHistoryVerificationInput{
		SignedManifestEnvelope: bundle.SignedEnvelope(), ImportedRowsDigest: dataset.ImportedRowsJCSDigest(),
		ImportedRecordCount: dataset.RecordCount(),
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := make([]validation.HistoricalGatewayRecord, 0, 3)
	for _, event := range dataset.GatewayHTTPRecords() {
		gateway = append(gateway, validation.HistoricalGatewayRecord{
			EventID: event.EventID, OccurredAt: event.StartedAt.Time(), SourceIPv4: event.SourceIP,
			StatusCode: event.StatusCode, TimestampTrust: detection.TimestampTrusted,
		})
	}
	auth := make([]validation.HistoricalAuthRecord, 0, 1)
	for _, event := range dataset.AuthEventRecords() {
		auth = append(auth, validation.HistoricalAuthRecord{
			EventID: event.EventID, OccurredAt: event.OccurredAt.Time(), SourceIPv4: event.SourceIP,
			Outcome: event.Outcome, TimestampTrust: detection.TimestampTrusted, Binding: detection.BindingVerified,
		})
	}
	health := func(source detection.SourceKind) detection.SourceHealth {
		return detection.SourceHealth{Source: source, Complete: true,
			CoverageStart: dataset.CoverageStart(), CoverageEnd: dataset.CoverageEnd()}
	}
	report := validation.EvaluateHistoricalImpact(validation.HistoricalImpactInput{
		Environment: validation.EnvironmentDemo, Mode: validation.HistoryModeVerifiedDemo,
		Clock: binding.HistoryCutoff(), TargetIPv4: "203.0.113.20",
		Coverage: validation.HistoryCoverage{
			GatewayStatus: validation.HistoryQueryComplete, AuthStatus: validation.HistoryQueryComplete,
			SourceHealthStatus: validation.HistoryQueryComplete, ReceiverGapStatus: validation.HistoryQueryComplete,
			RetainedFrom: dataset.CoverageStart(), RetainedThrough: dataset.CoverageEnd(),
		},
		GatewayRecords: gateway, AuthRecords: auth,
		GatewayHealth: health(detection.SourceGateway), AuthHealth: health(detection.SourceAuth),
		DemoHistory: &binding,
	}).Value()
	if report.SourceHealthDigest != want {
		t.Fatalf("impact digest=%s want=%s", report.SourceHealthDigest, want)
	}
}

func TestSealRejectsStaleAndTamperedAuthority(t *testing.T) {
	raw := fixtureDataset(t)
	if _, err := sealAt(context.Background(), raw, bytes.NewReader(randomMaterial(1)),
		time.Now().UTC().Add(-validation.DemoHistoryManifestMaximumAge-time.Minute)); err == nil {
		t.Fatal("stale security issued_at was accepted")
	}
	bundle, err := Seal(context.Background(), raw, bytes.NewReader(randomMaterial(2)))
	if err != nil {
		t.Fatal(err)
	}
	var base assertionsWire
	if err := json.Unmarshal(bundle.PublicAssertions(), &base); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*assertionsWire)
	}{
		{"wrong run", func(value *assertionsWire) {
			value.RunScope = "sentinelflow-demo-run:019b0000-0000-4000-8000-000000000999"
		}},
		{"wrong import", func(value *assertionsWire) { value.ImportID = "019b0000-0000-4000-8000-000000000999" }},
		{"wrong manifest", func(value *assertionsWire) { value.ManifestDigest = "sha256:" + strings.Repeat("a", 64) }},
		{"missing proof", func(value *assertionsWire) { value.SignatureVerificationDigest = "" }},
		{"public fixture", func(value *assertionsWire) { value.PublicKeyB64URL = validation.PinnedDemoHistoryFixturePublicKey }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			rawAssertions, marshalErr := json.Marshal(candidate)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, _, verifyErr := VerifyBundle(context.Background(), raw, bundle.SignedEnvelope(), rawAssertions); verifyErr == nil {
				t.Fatal("tampered public assertion was accepted")
			}
		})
	}
	tamperedEnvelope := bundle.SignedEnvelope()
	tamperedEnvelope[len(tamperedEnvelope)-2] ^= 1
	if _, _, err := VerifyBundle(context.Background(), raw, tamperedEnvelope, bundle.PublicAssertions()); err == nil {
		t.Fatal("tampered signed envelope was accepted")
	}
	noncanonicalEnvelope := append([]byte{' '}, bundle.SignedEnvelope()...)
	if _, _, err := VerifyBundle(context.Background(), raw, noncanonicalEnvelope, bundle.PublicAssertions()); err == nil {
		t.Fatal("noncanonical signed envelope was accepted")
	}
	duplicate := append([]byte(`{"clock_at":"x",`), bundle.PublicAssertions()[1:]...)
	if _, err := ParseAssertions(duplicate); err == nil {
		t.Fatal("noncanonical duplicate assertion was accepted")
	}
}

func TestSealNeverSerializesPrivateKeyMaterial(t *testing.T) {
	random := randomMaterial(31)
	seed := append([]byte(nil), random[:32]...)
	bundle, err := Seal(context.Background(), fixtureDataset(t), bytes.NewReader(random))
	if err != nil {
		t.Fatal(err)
	}
	combined := append(bundle.SignedEnvelope(), bundle.PublicAssertions()...)
	for _, forbidden := range [][]byte{
		seed,
		[]byte(base64.RawURLEncoding.EncodeToString(seed)),
		[]byte(base64.StdEncoding.EncodeToString(seed)),
		[]byte(hex.EncodeToString(seed)),
		[]byte("PRIVATE KEY"), []byte("private_key"), []byte("OPENAI_API_KEY"),
	} {
		if bytes.Contains(combined, forbidden) {
			t.Fatal("public bundle contains private or unrelated secret material")
		}
	}
}

func TestReadBundleRejectsSymlinkMissingOversizeAndTraversal(t *testing.T) {
	bundle, err := Seal(context.Background(), fixtureDataset(t), bytes.NewReader(randomMaterial(4)))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write := func() {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, EnvelopeFileName), bundle.SignedEnvelope(), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, AssertionsFileName), bundle.PublicAssertions(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, _, err := ReadBundle(root); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadBundle("relative"); err == nil {
		t.Fatal("relative bundle root accepted")
	}
	if err := os.Remove(filepath.Join(root, AssertionsFileName)); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "assertions.json")
	if err := os.WriteFile(outside, bundle.PublicAssertions(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, AssertionsFileName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadBundle(root); err == nil {
		t.Fatal("symlinked public assertion accepted")
	}
	if err := os.Remove(filepath.Join(root, AssertionsFileName)); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(root, AssertionsFileName), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxAssertionsBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	_ = file.Close()
	if _, _, err := ReadBundle(root); err == nil {
		t.Fatal("oversize public assertion accepted")
	}
}

func fixtureDataset(t testing.TB) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", validation.DemoHistoryDatasetLocator)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func randomMaterial(offset byte) []byte {
	result := make([]byte, 128)
	for index := range result {
		result[index] = byte(index) + offset
	}
	return result
}
