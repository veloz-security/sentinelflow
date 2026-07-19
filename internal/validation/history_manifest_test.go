package validation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/events"
)

const testDemoImpactSourceHealthDigest = "sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3"

func TestDemoHistoryFixtureVectorVerifiesOnlyInExplicitTestMode(t *testing.T) {
	verifier := newFixtureDemoHistoryVerifier(t)
	envelope := readDemoHistoryFixture(t)
	input := validDemoHistoryVerificationInput(envelope)

	binding, err := verifier.VerifyDemoHistory(context.Background(), input)
	if err != nil {
		t.Fatalf("verify fixture: %v", err)
	}
	if !binding.verified || binding.schemaVersion != DemoHistoryManifestSchemaVersion || binding.profile != DemoHistoryProfile ||
		binding.manifestID != "019b0000-0000-7000-8000-000000000500" || binding.datasetID != PinnedDemoHistoryDatasetID ||
		binding.datasetSchemaVersion != DemoHistoryDatasetSchemaVersion || binding.datasetLocator != DemoHistoryDatasetLocator ||
		binding.importID != "019b0000-0000-7000-8000-000000000501" || !binding.clockAt.Equal(historyTestAt) ||
		!binding.coverageStart.Equal(historyTestAt.Add(-HistoricalImpactLookback)) || !binding.coverageEnd.Equal(historyTestAt) ||
		!binding.issuedAt.Equal(historyTestAt) || binding.pathCatalogVersion != events.PathCatalogV1 ||
		binding.datasetRecordCount != PinnedDemoHistoryDatasetRecordCount || binding.datasetDigest != PinnedDemoHistoryDatasetDigest ||
		binding.manifestDigest != "sha256:da25f169a263cd9e15bf3edb4617762d0a3c49a66478837a878a81b75d32bd7e" ||
		binding.importedRowsDigest != PinnedDemoHistoryImportedRowsDigest ||
		binding.manifestSourceHealthDigest != PinnedDemoHistorySourceHealthDigest ||
		binding.impactSourceHealthDigest != testDemoImpactSourceHealthDigest ||
		!validDigest(binding.signatureVerificationDigest) {
		t.Fatalf("unexpected sealed fixture binding: %+v", binding)
	}
	if binding.manifestSourceHealthDigest == binding.impactSourceHealthDigest {
		t.Fatal("signed source-health digest substituted for trusted impact projection digest")
	}
	if cutoff := binding.HistoryCutoff(); !cutoff.sealed || cutoff.authority != HistoryClockVerifiedDemo || !cutoff.At().Equal(historyTestAt) {
		t.Fatalf("invalid sealed history cutoff: %+v", cutoff)
	}

	for index := range envelope {
		envelope[index] ^= 0xff
	}
	if !binding.HistoryCutoff().At().Equal(historyTestAt) {
		t.Fatal("returned binding retained caller-owned envelope bytes")
	}
}

func TestDemoHistoryFixtureBindingPassesExactImpactProjection(t *testing.T) {
	verifier := newFixtureDemoHistoryVerifier(t)
	binding, err := verifier.VerifyDemoHistory(context.Background(), validDemoHistoryVerificationInput(readDemoHistoryFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	input := demoHistoricalImpactInput(binding)
	checked := EvaluateHistoricalImpact(input)
	if !checked.Allowed() {
		t.Fatalf("verified fixture binding did not pass exact history projection: %+v", checked.Value())
	}
	if checked.Value().SourceHealthDigest != testDemoImpactSourceHealthDigest {
		t.Fatalf("impact projection digest = %q", checked.Value().SourceHealthDigest)
	}

	wrongConfig := fixtureDemoHistoryVerifierConfig(t)
	wrongConfig.ExpectedImpactSourceHealthDigest = PinnedDemoHistorySourceHealthDigest
	if _, err := NewStrictDemoHistoryManifestVerifier(wrongConfig); manifestErrorCode(err) != DemoHistoryManifestErrorConfiguration {
		t.Fatalf("signed source-health digest was accepted as impact projection: %v", err)
	}

	mutated := binding
	mutated.impactSourceHealthDigest = digestBytes([]byte("different trusted projection"))
	input.DemoHistory = &mutated
	assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonDemoBindingMismatch)
}

func TestVerifiedDemoHistoryProjectionFailsClosedForUnsafeRowsAndCoverage(t *testing.T) {
	verifier := newFixtureDemoHistoryVerifier(t)
	binding, err := verifier.VerifyDemoHistory(context.Background(), validDemoHistoryVerificationInput(readDemoHistoryFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*HistoricalImpactInput)
		want   HistoricalImpactReason
	}{
		{"successful auth", func(input *HistoricalImpactInput) {
			input.AuthRecords[0].Outcome = events.AuthOutcomeSucceeded
		}, HistoryReasonAuthSucceeded},
		{"pending auth binding", func(input *HistoricalImpactInput) {
			input.AuthRecords[0].Binding = detection.BindingPending
		}, HistoryReasonAuthBindingPending},
		{"untrusted auth binding", func(input *HistoricalImpactInput) {
			input.AuthRecords[0].Binding = detection.BindingUntrusted
		}, HistoryReasonAuthBindingUntrusted},
		{"untrusted event time", func(input *HistoricalImpactInput) {
			input.GatewayRecords[0].TimestampTrust = detection.TimestampUntrusted
		}, HistoryReasonTimestampUntrusted},
		{"incomplete query coverage", func(input *HistoricalImpactInput) {
			input.Coverage.AuthStatus = HistoryQueryIncomplete
		}, HistoryReasonCoverageIncomplete},
		{"unknown source loss", func(input *HistoricalImpactInput) {
			input.GatewayHealth.Intervals = []detection.HealthInterval{{
				State: detection.HealthUnknownLoss, Start: historyTestAt.Add(-time.Minute),
			}}
		}, HistoryReasonDemoBindingMismatch},
		{"receiver gap", func(input *HistoricalImpactInput) {
			input.ReceiverGaps = []HistoricalReceiverGap{{
				GapID: "019b0000-0000-7000-8000-000000000700", Source: detection.SourceGateway,
				SequenceStart: 1, SequenceEnd: 1, ImpactStart: historyTestAt.Add(-time.Minute),
				Resolution: ReceiverGapUnresolved,
			}}
		}, HistoryReasonGapUnresolved},
		{"unmapped extra record", func(input *HistoricalImpactInput) {
			input.GatewayRecords = append(input.GatewayRecords, HistoricalGatewayRecord{
				EventID:    "019b0000-0000-7000-8000-000000000701",
				OccurredAt: historyTestAt.Add(-time.Second), SourceIPv4: "203.0.113.20",
				StatusCode: 200, TimestampTrust: detection.TimestampTrusted,
			})
		}, HistoryReasonDemoBindingMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := demoHistoricalImpactInput(binding)
			test.mutate(&input)
			assertHistoryBlocked(t, EvaluateHistoricalImpact(input), test.want)
		})
	}

	input := demoHistoricalImpactInput(binding)
	input.Environment = EnvironmentDemo
	assertHistoryBlocked(t, EvaluateHistoricalImpact(input), HistoryReasonDemoBindingMismatch)
}

func TestDemoHistoryPinnedDatasetProjectionDigests(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", DemoHistoryDatasetLocator))
	if err != nil {
		t.Fatal(err)
	}
	if strictJSON(raw) != nil {
		t.Fatal("pinned dataset is not strict JSON")
	}
	if canonical, err := canonicalJSON(raw); err != nil || sha256Digest(canonical) != PinnedDemoHistoryDatasetDigest {
		t.Fatalf("dataset digest mismatch: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	records, err := canonicalJSON(object["records"])
	if err != nil || sha256Digest(records) != PinnedDemoHistoryImportedRowsDigest {
		t.Fatalf("imported rows digest mismatch: %v", err)
	}
	health, err := canonicalJSON(object["source_health"])
	if err != nil || sha256Digest(health) != PinnedDemoHistorySourceHealthDigest {
		t.Fatalf("source health digest mismatch: %v", err)
	}
	var recordValues []json.RawMessage
	if err := json.Unmarshal(object["records"], &recordValues); err != nil || uint64(len(recordValues)) != PinnedDemoHistoryDatasetRecordCount {
		t.Fatalf("record count mismatch: %d, %v", len(recordValues), err)
	}
}

func TestDemoHistoryFreshRunScopedKeyVerifiesInDemoMode(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runScope := "sentinelflow-demo-run:019b0000-0000-7000-8000-000000009001"
	now := time.Now().UTC().Truncate(time.Millisecond)
	manifest := validDemoHistoryManifest(now)
	envelope := signDemoHistoryEnvelope(t, privateKey, publicKey, runScope, false, manifest)
	config := demoHistoryVerifierConfig(publicKey, runScope)

	verifier, err := NewStrictDemoHistoryManifestVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	for index := range publicKey {
		publicKey[index] ^= 0xff
	}
	binding, err := verifier.VerifyDemoHistory(context.Background(), validDemoHistoryVerificationInput(envelope))
	if err != nil {
		t.Fatalf("verify fresh run-scoped manifest: %v", err)
	}
	if !binding.verified || binding.impactSourceHealthDigest != testDemoImpactSourceHealthDigest || !binding.issuedAt.Equal(now) {
		t.Fatalf("unexpected demo binding: %+v", binding)
	}
	if !binding.issuedAt.After(binding.clockAt) {
		t.Fatalf("security issued_at must be independent of fixed history clock: issued=%s clock=%s", binding.issuedAt, binding.clockAt)
	}
	if checked := EvaluateHistoricalImpact(demoHistoricalImpactInput(binding)); !checked.Allowed() {
		t.Fatalf("real issued_at after fixed clock was rejected: %+v", checked.Value())
	}
	claims, ok := binding.Claims()
	if !ok || claims.RawFileDigest != PinnedDemoHistoryRawFileDigest ||
		claims.ImpactSourceHealthDigest != PinnedDemoHistoryImpactSourceHealthDigest ||
		!claims.IssuedAt.Equal(now) || claims.RunScopeDigest == "" || claims.PublicKeyDigest == "" {
		t.Fatalf("unexpected public binding claims: ok=%v claims=%+v", ok, claims)
	}

	fixtureEnvelope := readDemoHistoryFixture(t)
	assertDemoHistoryError(t, verifier, validDemoHistoryVerificationInput(fixtureEnvelope), DemoHistoryManifestErrorScope)
}

func TestDemoHistoryVerifierRejectsInvalidConfiguration(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := demoHistoryVerifierConfig(publicKey, "sentinelflow-demo-run:019b0000-0000-7000-8000-000000009002")
	fixtureKey, err := decodeExactBase64URL(PinnedDemoHistoryFixturePublicKey, ed25519.PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*DemoHistoryManifestVerifierConfig)
	}{
		{"development environment", func(c *DemoHistoryManifestVerifierConfig) { c.Environment = EnvironmentDevelopment }},
		{"production environment", func(c *DemoHistoryManifestVerifierConfig) { c.Environment = EnvironmentProduction }},
		{"unknown environment", func(c *DemoHistoryManifestVerifierConfig) { c.Environment = "staging" }},
		{"empty public key", func(c *DemoHistoryManifestVerifierConfig) { c.ExpectedPublicKey = nil }},
		{"short public key", func(c *DemoHistoryManifestVerifierConfig) { c.ExpectedPublicKey = c.ExpectedPublicKey[:31] }},
		{"fixture key in demo", func(c *DemoHistoryManifestVerifierConfig) { c.ExpectedPublicKey = fixtureKey }},
		{"fixture permission in demo", func(c *DemoHistoryManifestVerifierConfig) { c.AllowPublicTestFixture = true }},
		{"test clock in demo", func(c *DemoHistoryManifestVerifierConfig) { c.TestSecurityNow = historyTestAt }},
		{"empty run scope", func(c *DemoHistoryManifestVerifierConfig) { c.ExpectedRunScope = "" }},
		{"unscoped run", func(c *DemoHistoryManifestVerifierConfig) { c.ExpectedRunScope = "demo" }},
		{"uppercase run id", func(c *DemoHistoryManifestVerifierConfig) {
			c.ExpectedRunScope = "sentinelflow-demo-run:019B0000-0000-7000-8000-000000009002"
		}},
		{"bad import id", func(c *DemoHistoryManifestVerifierConfig) { c.ExpectedImportID = "import" }},
		{"zero clock", func(c *DemoHistoryManifestVerifierConfig) { c.ExpectedClockAt = time.Time{} }},
		{"bad impact digest", func(c *DemoHistoryManifestVerifierConfig) {
			c.ExpectedImpactSourceHealthDigest = "SHA256:" + strings.Repeat("0", 64)
		}},
		{"signed digest substituted", func(c *DemoHistoryManifestVerifierConfig) {
			c.ExpectedImpactSourceHealthDigest = PinnedDemoHistorySourceHealthDigest
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.ExpectedPublicKey = append([]byte(nil), base.ExpectedPublicKey...)
			test.mutate(&config)
			verifier, err := NewStrictDemoHistoryManifestVerifier(config)
			if verifier != nil || manifestErrorCode(err) != DemoHistoryManifestErrorConfiguration {
				t.Fatalf("expected configuration rejection, got verifier=%v err=%v", verifier, err)
			}
		})
	}

	fixture := fixtureDemoHistoryVerifierConfig(t)
	fixture.AllowPublicTestFixture = false
	if _, err := NewStrictDemoHistoryManifestVerifier(fixture); manifestErrorCode(err) != DemoHistoryManifestErrorConfiguration {
		t.Fatalf("implicit fixture mode accepted: %v", err)
	}
	fixture = fixtureDemoHistoryVerifierConfig(t)
	fixture.ExpectedRunScope = "sentinelflow-demo-run:019b0000-0000-7000-8000-000000009002"
	if _, err := NewStrictDemoHistoryManifestVerifier(fixture); manifestErrorCode(err) != DemoHistoryManifestErrorConfiguration {
		t.Fatalf("run scope accepted with fixture key: %v", err)
	}
}

func TestDemoHistoryVerifierRejectsStructuralAndEnvelopeMutations(t *testing.T) {
	verifier := newFixtureDemoHistoryVerifier(t)
	valid := readDemoHistoryFixture(t)
	baseInput := validDemoHistoryVerificationInput(valid)

	rootUnknown := mutateDemoHistoryJSON(t, valid, func(root map[string]any) { root["unknown"] = true })
	rootMissing := mutateDemoHistoryJSON(t, valid, func(root map[string]any) { delete(root, "signature_b64url") })
	nestedUnknown := mutateDemoHistoryJSON(t, valid, func(root map[string]any) { root["manifest"].(map[string]any)["unknown"] = true })
	nestedMissing := mutateDemoHistoryJSON(t, valid, func(root map[string]any) { delete(root["manifest"].(map[string]any), "profile") })
	typeMismatch := mutateDemoHistoryJSON(t, valid, func(root map[string]any) { root["key_scope"] = 7 })
	nullManifest := mutateDemoHistoryJSON(t, valid, func(root map[string]any) { root["manifest"] = nil })

	tests := []struct {
		name string
		raw  []byte
		code DemoHistoryManifestErrorCode
	}{
		{"empty", nil, DemoHistoryManifestErrorInput},
		{"root array", []byte(`[]`), DemoHistoryManifestErrorInput},
		{"invalid utf8", []byte{'{', '"', 0xff, '"', ':', '1', '}'}, DemoHistoryManifestErrorInput},
		{"trailing json", append(append([]byte(nil), valid...), []byte(`{}`)...), DemoHistoryManifestErrorInput},
		{"duplicate root", []byte(`{"schema_version":"a","schema_version":"b"}`), DemoHistoryManifestErrorInput},
		{"duplicate nested", []byte(`{"manifest":{"schema_version":"a","schema_version":"b"}}`), DemoHistoryManifestErrorInput},
		{"unknown root", rootUnknown, DemoHistoryManifestErrorContract},
		{"missing root", rootMissing, DemoHistoryManifestErrorContract},
		{"unknown nested", nestedUnknown, DemoHistoryManifestErrorContract},
		{"missing nested", nestedMissing, DemoHistoryManifestErrorContract},
		{"type mismatch", typeMismatch, DemoHistoryManifestErrorEncoding},
		{"null manifest", nullManifest, DemoHistoryManifestErrorContract},
		{"oversized", bytes.Repeat([]byte{' '}, MaxDemoHistorySignedEnvelopeBytes+1), DemoHistoryManifestErrorInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := baseInput
			input.SignedManifestEnvelope = test.raw
			assertDemoHistoryError(t, verifier, input, test.code)
		})
	}

	inputMutations := []struct {
		name   string
		mutate func(*DemoHistoryVerificationInput)
	}{
		{"empty imported digest", func(i *DemoHistoryVerificationInput) { i.ImportedRowsDigest = "" }},
		{"uppercase imported digest", func(i *DemoHistoryVerificationInput) { i.ImportedRowsDigest = "sha256:" + strings.Repeat("A", 64) }},
		{"different imported digest", func(i *DemoHistoryVerificationInput) { i.ImportedRowsDigest = digestBytes([]byte("other rows")) }},
		{"zero count", func(i *DemoHistoryVerificationInput) { i.ImportedRecordCount = 0 }},
		{"different count", func(i *DemoHistoryVerificationInput) { i.ImportedRecordCount++ }},
	}
	for _, test := range inputMutations {
		t.Run(test.name, func(t *testing.T) {
			input := baseInput
			test.mutate(&input)
			assertDemoHistoryError(t, verifier, input, DemoHistoryManifestErrorInput)
		})
	}

	var nilVerifier *StrictDemoHistoryManifestVerifier
	if binding, err := nilVerifier.VerifyDemoHistory(context.Background(), baseInput); binding.verified || manifestErrorCode(err) != DemoHistoryManifestErrorInput {
		t.Fatalf("nil verifier returned binding=%+v err=%v", binding, err)
	}
	//lint:ignore SA1012 This negative test proves the verifier rejects a nil context without panicking.
	if binding, err := verifier.VerifyDemoHistory(nil, baseInput); binding.verified || manifestErrorCode(err) != DemoHistoryManifestErrorInput {
		t.Fatalf("nil context returned binding=%+v err=%v", binding, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assertDemoHistoryErrorWithContext(t, verifier, ctx, baseInput, DemoHistoryManifestErrorCanceled)
}

func TestDemoHistoryVerifierRejectsCryptographicEnvelopeMutations(t *testing.T) {
	verifier := newFixtureDemoHistoryVerifier(t)
	valid := readDemoHistoryFixture(t)
	decode := func(t *testing.T) demoHistorySignedEnvelopeWire {
		t.Helper()
		var envelope demoHistorySignedEnvelopeWire
		if err := json.Unmarshal(valid, &envelope); err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	tests := []struct {
		name   string
		code   DemoHistoryManifestErrorCode
		mutate func(*demoHistorySignedEnvelopeWire)
	}{
		{"wrong envelope schema", DemoHistoryManifestErrorContract, func(e *demoHistorySignedEnvelopeWire) { e.SchemaVersion = "demo-history-signed-manifest-v2" }},
		{"fixture flag false", DemoHistoryManifestErrorScope, func(e *demoHistorySignedEnvelopeWire) { value := false; e.FixtureOnly = &value }},
		{"wrong scope", DemoHistoryManifestErrorScope, func(e *demoHistorySignedEnvelopeWire) { e.KeyScope += "!" }},
		{"wrong public key", DemoHistoryManifestErrorScope, func(e *demoHistorySignedEnvelopeWire) {
			e.PublicKeyB64URL = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		}},
		{"padded public key", DemoHistoryManifestErrorScope, func(e *demoHistorySignedEnvelopeWire) { e.PublicKeyB64URL += "=" }},
		{"empty manifest jcs", DemoHistoryManifestErrorEncoding, func(e *demoHistorySignedEnvelopeWire) { e.ManifestJCSB64URL = "" }},
		{"padded manifest jcs", DemoHistoryManifestErrorEncoding, func(e *demoHistorySignedEnvelopeWire) { e.ManifestJCSB64URL += "=" }},
		{"noncanonical manifest jcs", DemoHistoryManifestErrorContract, func(e *demoHistorySignedEnvelopeWire) {
			raw, _ := json.MarshalIndent(e.Manifest, "", "  ")
			e.ManifestJCSB64URL = base64.RawURLEncoding.EncodeToString(raw)
		}},
		{"wrong manifest jcs", DemoHistoryManifestErrorContract, func(e *demoHistorySignedEnvelopeWire) {
			e.ManifestJCSB64URL = base64.RawURLEncoding.EncodeToString([]byte(`{"schema_version":"demo-history-v1"}`))
		}},
		{"uppercase digest", DemoHistoryManifestErrorDigest, func(e *demoHistorySignedEnvelopeWire) { e.ManifestDigest = "sha256:" + strings.Repeat("A", 64) }},
		{"wrong digest", DemoHistoryManifestErrorDigest, func(e *demoHistorySignedEnvelopeWire) { e.ManifestDigest = digestBytes([]byte("different manifest")) }},
		{"short signature", DemoHistoryManifestErrorEncoding, func(e *demoHistorySignedEnvelopeWire) { e.SignatureB64URL = "AA" }},
		{"padded signature", DemoHistoryManifestErrorEncoding, func(e *demoHistorySignedEnvelopeWire) { e.SignatureB64URL += "=" }},
		{"mutated signature", DemoHistoryManifestErrorSignature, func(e *demoHistorySignedEnvelopeWire) {
			signature, _ := base64.RawURLEncoding.DecodeString(e.SignatureB64URL)
			signature[len(signature)-1] ^= 1
			e.SignatureB64URL = base64.RawURLEncoding.EncodeToString(signature)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := decode(t)
			test.mutate(&envelope)
			raw, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			assertDemoHistoryError(t, verifier, validDemoHistoryVerificationInput(raw), test.code)
		})
	}
}

func TestDemoHistoryVerifierRejectsResignedManifestMutations(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runScope := "sentinelflow-demo-run:019b0000-0000-7000-8000-000000009003"
	config := demoHistoryVerifierConfig(publicKey, runScope)
	verifier, err := NewStrictDemoHistoryManifestVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	base := validDemoHistoryManifest(now)
	tests := []struct {
		name   string
		code   DemoHistoryManifestErrorCode
		mutate func(*demoHistoryManifestWire)
	}{
		{"schema", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.SchemaVersion = "demo-history-v2" }},
		{"manifest id", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.ManifestID = "not-a-uuid" }},
		{"profile", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.Profile = "production" }},
		{"dataset id", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.DatasetID = "019b0000-0000-7000-8000-000000000999" }},
		{"dataset schema", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.DatasetSchema = "demo-history-dataset-v2" }},
		{"dataset digest", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.DatasetDigest = digestBytes([]byte("other dataset")) }},
		{"record count zero", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.DatasetRecordCount = 0 }},
		{"record count mismatch", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.DatasetRecordCount++ }},
		{"import id", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.ImportID = "019b0000-0000-7000-8000-000000000999" }},
		{"path catalog", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.PathCatalogVersion = "path-catalog-v2" }},
		{"source health signed digest", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.SourceHealthDigest = testDemoImpactSourceHealthDigest }},
		{"clock offset", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.ClockAt = "2026-07-18T02:00:00+00:00" }},
		{"clock mismatch", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.ClockAt = historyTestAt.Add(time.Second).Format(time.RFC3339Nano) }},
		{"coverage start", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) {
			m.CoverageStart = historyTestAt.Add(-HistoricalImpactLookback + time.Second).Format(time.RFC3339Nano)
		}},
		{"coverage end", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) {
			m.CoverageEnd = historyTestAt.Add(-time.Second).Format(time.RFC3339Nano)
		}},
		{"issued before coverage", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) {
			m.IssuedAt = historyTestAt.Add(-time.Second).Format(time.RFC3339Nano)
		}},
		{"issued offset", DemoHistoryManifestErrorContract, func(m *demoHistoryManifestWire) { m.IssuedAt = now.Format("2006-01-02T15:04:05+00:00") }},
		{"stale issued", DemoHistoryManifestErrorFreshness, func(m *demoHistoryManifestWire) {
			m.IssuedAt = now.Add(-DemoHistoryManifestMaximumAge - time.Second).Format(time.RFC3339Nano)
		}},
		{"future issued", DemoHistoryManifestErrorFreshness, func(m *demoHistoryManifestWire) {
			m.IssuedAt = now.Add(DemoHistoryManifestMaximumFutureSkew + time.Minute).Format(time.RFC3339Nano)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := base
			test.mutate(&manifest)
			envelope := signDemoHistoryEnvelope(t, privateKey, publicKey, runScope, false, manifest)
			assertDemoHistoryError(t, verifier, validDemoHistoryVerificationInput(envelope), test.code)
		})
	}
}

func newFixtureDemoHistoryVerifier(t testing.TB) *StrictDemoHistoryManifestVerifier {
	t.Helper()
	verifier, err := NewStrictDemoHistoryManifestVerifier(fixtureDemoHistoryVerifierConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func fixtureDemoHistoryVerifierConfig(t testing.TB) DemoHistoryManifestVerifierConfig {
	t.Helper()
	publicKey, err := decodeExactBase64URL(PinnedDemoHistoryFixturePublicKey, ed25519.PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	return DemoHistoryManifestVerifierConfig{
		Environment:                      EnvironmentTest,
		ExpectedPublicKey:                append([]byte(nil), publicKey...),
		ExpectedRunScope:                 DemoHistoryFixtureKeyScope,
		ExpectedImportID:                 "019b0000-0000-7000-8000-000000000501",
		ExpectedClockAt:                  historyTestAt,
		ExpectedImpactSourceHealthDigest: testDemoImpactSourceHealthDigest,
		AllowPublicTestFixture:           true,
		TestSecurityNow:                  historyTestAt,
	}
}

func demoHistoryVerifierConfig(publicKey []byte, runScope string) DemoHistoryManifestVerifierConfig {
	return DemoHistoryManifestVerifierConfig{
		Environment:                      EnvironmentDemo,
		ExpectedPublicKey:                append([]byte(nil), publicKey...),
		ExpectedRunScope:                 runScope,
		ExpectedImportID:                 "019b0000-0000-7000-8000-000000000501",
		ExpectedClockAt:                  historyTestAt,
		ExpectedImpactSourceHealthDigest: testDemoImpactSourceHealthDigest,
	}
}

func validDemoHistoryManifest(issuedAt time.Time) demoHistoryManifestWire {
	return demoHistoryManifestWire{
		SchemaVersion:      DemoHistoryManifestSchemaVersion,
		ManifestID:         "019b0000-0000-7000-8000-000000000500",
		Profile:            DemoHistoryProfile,
		ClockAt:            historyTestAt.Format(time.RFC3339Nano),
		DatasetID:          PinnedDemoHistoryDatasetID,
		DatasetSchema:      DemoHistoryDatasetSchemaVersion,
		DatasetDigest:      PinnedDemoHistoryDatasetDigest,
		DatasetRecordCount: PinnedDemoHistoryDatasetRecordCount,
		ImportID:           "019b0000-0000-7000-8000-000000000501",
		CoverageStart:      historyTestAt.Add(-HistoricalImpactLookback).Format(time.RFC3339Nano),
		CoverageEnd:        historyTestAt.Format(time.RFC3339Nano),
		PathCatalogVersion: events.PathCatalogV1,
		SourceHealthDigest: PinnedDemoHistorySourceHealthDigest,
		IssuedAt:           issuedAt.Format(time.RFC3339Nano),
	}
}

func signDemoHistoryEnvelope(t *testing.T, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, runScope string, fixtureOnly bool, manifest demoHistoryManifestWire) []byte {
	t.Helper()
	canonical, err := marshalSnapshotJCS(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Digest(canonical)
	signingInput, err := demoHistorySigningInput(digest)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, signingInput)
	envelope := demoHistorySignedEnvelopeWire{
		SchemaVersion:     DemoHistorySignedManifestSchemaVersion,
		FixtureOnly:       &fixtureOnly,
		KeyScope:          runScope,
		Manifest:          &manifest,
		ManifestJCSB64URL: base64.RawURLEncoding.EncodeToString(canonical),
		ManifestDigest:    digest,
		SignatureB64URL:   base64.RawURLEncoding.EncodeToString(signature),
		PublicKeyB64URL:   base64.RawURLEncoding.EncodeToString(publicKey),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validDemoHistoryVerificationInput(envelope []byte) DemoHistoryVerificationInput {
	return DemoHistoryVerificationInput{
		SignedManifestEnvelope: append([]byte(nil), envelope...),
		ImportedRowsDigest:     PinnedDemoHistoryImportedRowsDigest,
		ImportedRecordCount:    PinnedDemoHistoryDatasetRecordCount,
	}
}

func readDemoHistoryFixture(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "fixtures", "demo_history_manifest_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutateDemoHistoryJSON(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	mutate(object)
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func demoHistoricalImpactInput(binding VerifiedDemoHistoryBinding) HistoricalImpactInput {
	start := historyTestAt.Add(-HistoricalImpactLookback)
	return HistoricalImpactInput{
		Environment: EnvironmentTest,
		Mode:        HistoryModeVerifiedDemo,
		Clock:       binding.HistoryCutoff(),
		TargetIPv4:  "203.0.113.20",
		Coverage: HistoryCoverage{
			GatewayStatus: HistoryQueryComplete, AuthStatus: HistoryQueryComplete,
			SourceHealthStatus: HistoryQueryComplete, ReceiverGapStatus: HistoryQueryComplete,
			RetainedFrom: start, RetainedThrough: historyTestAt,
		},
		GatewayRecords: []HistoricalGatewayRecord{
			{EventID: "019b0000-0000-7000-8000-000000000101", OccurredAt: historyTestAt.Add(-23 * time.Hour), SourceIPv4: "203.0.113.20", StatusCode: 401, TimestampTrust: detection.TimestampTrusted},
			{EventID: "019b0000-0000-7000-8000-000000000105", OccurredAt: historyTestAt.Add(-12 * time.Hour), SourceIPv4: "203.0.113.20", StatusCode: 200, TimestampTrust: detection.TimestampTrusted},
			{EventID: "019b0000-0000-7000-8000-000000000108", OccurredAt: historyTestAt.Add(-time.Minute), SourceIPv4: "203.0.113.20", StatusCode: 204, TimestampTrust: detection.TimestampTrusted},
		},
		AuthRecords: []HistoricalAuthRecord{
			{EventID: "019b0000-0000-7000-8000-000000000104", OccurredAt: historyTestAt.Add(-23*time.Hour + 6*time.Millisecond), SourceIPv4: "203.0.113.20", Outcome: events.AuthOutcomeFailed, TimestampTrust: detection.TimestampTrusted, Binding: detection.BindingVerified},
		},
		GatewayHealth: detection.SourceHealth{Source: detection.SourceGateway, Complete: true, CoverageStart: start, CoverageEnd: historyTestAt},
		AuthHealth:    detection.SourceHealth{Source: detection.SourceAuth, Complete: true, CoverageStart: start, CoverageEnd: historyTestAt},
		DemoHistory:   &binding,
	}
}

func assertDemoHistoryError(t *testing.T, verifier *StrictDemoHistoryManifestVerifier, input DemoHistoryVerificationInput, code DemoHistoryManifestErrorCode) {
	t.Helper()
	assertDemoHistoryErrorWithContext(t, verifier, context.Background(), input, code)
}

func assertDemoHistoryErrorWithContext(t *testing.T, verifier *StrictDemoHistoryManifestVerifier, ctx context.Context, input DemoHistoryVerificationInput, code DemoHistoryManifestErrorCode) {
	t.Helper()
	binding, err := verifier.VerifyDemoHistory(ctx, input)
	if binding.verified || !binding.HistoryCutoff().At().IsZero() {
		t.Fatalf("rejection returned a sealed binding: %+v", binding)
	}
	if got := manifestErrorCode(err); got != code {
		t.Fatalf("error code = %q, want %q (err=%v)", got, code, err)
	}
}

func manifestErrorCode(err error) DemoHistoryManifestErrorCode {
	var manifestError *DemoHistoryManifestError
	if !errors.As(err, &manifestError) {
		return ""
	}
	return manifestError.Code
}
