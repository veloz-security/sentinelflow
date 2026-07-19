package demohistoryproof

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/validation"
)

func TestVerifyAcceptsFreshRunScopedPublicProof(t *testing.T) {
	config, envelope := signedProof(t, time.Now().UTC().Truncate(time.Millisecond))
	config.SignedEnvelopeFile = writeEnvelope(t, envelope)
	binding, err := Verify(t.Context(), config)
	claims, ok := binding.Claims()
	if err != nil || !ok || claims.ImportID != config.ImportID ||
		!claims.ClockAt.Equal(config.ClockAt) || claims.FixtureOnly {
		t.Fatalf("binding claims=%+v ok=%v err=%v", claims, ok, err)
	}
}

func TestVerifyRejectsSignatureClaimsFreshnessAndSourceDrift(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	for name, testCase := range map[string]struct {
		issuedAt time.Time
		mutate   func(*Config, []byte) []byte
		want     error
	}{
		"signature": {issuedAt: now, want: ErrVerification, mutate: func(_ *Config, envelope []byte) []byte {
			var wire map[string]any
			if err := json.Unmarshal(envelope, &wire); err != nil {
				t.Fatal(err)
			}
			signature := wire["signature_b64url"].(string)
			if signature[0] == 'A' {
				signature = "B" + signature[1:]
			} else {
				signature = "A" + signature[1:]
			}
			wire["signature_b64url"] = signature
			result, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			return result
		}},
		"claims": {issuedAt: now, want: ErrVerification, mutate: func(config *Config, envelope []byte) []byte {
			config.ImportID = "019b0000-0000-4000-8000-000000000999"
			return envelope
		}},
		"stale at start":  {issuedAt: now.Add(-validation.DemoHistoryManifestMaximumAge - time.Second), want: ErrVerification},
		"future at start": {issuedAt: now.Add(validation.DemoHistoryManifestMaximumFutureSkew + time.Second), want: ErrVerification},
		"impact digest": {issuedAt: now, want: ErrInvalidConfiguration, mutate: func(config *Config, envelope []byte) []byte {
			config.ImpactSourceHealthDigest = "sha256:" + strings.Repeat("9", 64)
			return envelope
		}},
	} {
		t.Run(name, func(t *testing.T) {
			config, envelope := signedProof(t, testCase.issuedAt)
			if testCase.mutate != nil {
				envelope = testCase.mutate(&config, envelope)
			}
			config.SignedEnvelopeFile = writeEnvelope(t, envelope)
			if _, err := Verify(context.Background(), config); !errors.Is(err, testCase.want) {
				t.Fatalf("error=%v want=%v", err, testCase.want)
			}
		})
	}

	config, envelope := signedProof(t, now)
	regular := writeEnvelope(t, envelope)
	link := filepath.Join(t.TempDir(), "signed-manifest.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	config.SignedEnvelopeFile = link
	if _, err := Verify(t.Context(), config); !errors.Is(err, ErrSource) {
		t.Fatalf("symlink error=%v", err)
	}
}

type manifestWire struct {
	ClockAt            string `json:"clock_at"`
	CoverageEnd        string `json:"coverage_end"`
	CoverageStart      string `json:"coverage_start"`
	DatasetDigest      string `json:"dataset_digest"`
	DatasetID          string `json:"dataset_id"`
	DatasetRecordCount uint64 `json:"dataset_record_count"`
	DatasetSchema      string `json:"dataset_schema_version"`
	ImportID           string `json:"import_id"`
	IssuedAt           string `json:"issued_at"`
	ManifestID         string `json:"manifest_id"`
	PathCatalogVersion string `json:"path_catalog_version"`
	Profile            string `json:"profile"`
	SchemaVersion      string `json:"schema_version"`
	SourceHealthDigest string `json:"source_health_digest"`
}

type envelopeWire struct {
	FixtureOnly       bool         `json:"fixture_only"`
	KeyScope          string       `json:"key_scope"`
	Manifest          manifestWire `json:"manifest"`
	ManifestDigest    string       `json:"manifest_digest"`
	ManifestJCSB64URL string       `json:"manifest_jcs_b64url"`
	PublicKeyB64URL   string       `json:"public_key_b64url"`
	SchemaVersion     string       `json:"schema_version"`
	SignatureB64URL   string       `json:"signature_b64url"`
}

func signedProof(t *testing.T, issuedAt time.Time) (Config, []byte) {
	t.Helper()
	clockAt := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	issuedAt = issuedAt.Truncate(time.Millisecond).UTC()
	seed := sha256.Sum256([]byte(t.Name() + issuedAt.Format(time.RFC3339Nano)))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	importID := "019b0000-0000-4000-8000-000000000901"
	runScope := "sentinelflow-demo-run:019b0000-0000-4000-8000-000000000902"
	manifest := manifestWire{
		ClockAt:            clockAt.Format("2006-01-02T15:04:05.000Z"),
		CoverageEnd:        clockAt.Format("2006-01-02T15:04:05.000Z"),
		CoverageStart:      clockAt.Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000Z"),
		DatasetDigest:      validation.PinnedDemoHistoryDatasetDigest,
		DatasetID:          validation.PinnedDemoHistoryDatasetID,
		DatasetRecordCount: validation.PinnedDemoHistoryDatasetRecordCount,
		DatasetSchema:      validation.DemoHistoryDatasetSchemaVersion,
		ImportID:           importID,
		IssuedAt:           issuedAt.Format("2006-01-02T15:04:05.000Z"),
		ManifestID:         "019b0000-0000-4000-8000-000000000903",
		PathCatalogVersion: "path-catalog-v1",
		Profile:            validation.DemoHistoryProfile,
		SchemaVersion:      validation.DemoHistoryManifestSchemaVersion,
		SourceHealthDigest: validation.PinnedDemoHistorySourceHealthDigest,
	}
	manifestJCS, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifestJCS)
	manifestDigest := "sha256:" + hex.EncodeToString(digest[:])
	signingInput := append([]byte(validation.DemoHistorySignatureDomain+"\n"), digest[:]...)
	signature := ed25519.Sign(privateKey, signingInput)
	envelope, err := json.Marshal(envelopeWire{
		FixtureOnly: false, KeyScope: runScope, Manifest: manifest,
		ManifestDigest:    manifestDigest,
		ManifestJCSB64URL: base64.RawURLEncoding.EncodeToString(manifestJCS),
		PublicKeyB64URL:   base64.RawURLEncoding.EncodeToString(publicKey),
		SchemaVersion:     validation.DemoHistorySignedManifestSchemaVersion,
		SignatureB64URL:   base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		PublicKeyB64URL: base64.RawURLEncoding.EncodeToString(publicKey),
		RunScope:        runScope, ImportID: importID, ClockAt: clockAt,
		ImpactSourceHealthDigest: validation.PinnedDemoHistoryImpactSourceHealthDigest,
	}, envelope
}

func writeEnvelope(t *testing.T, envelope []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signed-manifest.json")
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
