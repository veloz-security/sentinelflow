package demohistoryseal

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/demohistory"
	"github.com/devwooops/sentinelflow/internal/validation"
)

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

type assertionsWire struct {
	ClockAt                     string `json:"clock_at"`
	ImpactSourceHealthDigest    string `json:"impact_source_health_digest"`
	ImportID                    string `json:"import_id"`
	IssuedAt                    string `json:"issued_at"`
	ManifestDigest              string `json:"manifest_digest"`
	ManifestID                  string `json:"manifest_id"`
	PublicKeyB64URL             string `json:"public_key_b64url"`
	RunScope                    string `json:"run_scope"`
	SchemaVersion               string `json:"schema_version"`
	SignatureVerificationDigest string `json:"signature_verification_digest"`
}

// Seal generates a fresh run key and real-security-time manifest, verifies it
// immediately through StrictDemoHistoryManifestVerifier, clears the private
// bytes, and returns public material only.
func Seal(ctx context.Context, rawDataset []byte, random io.Reader) (Bundle, error) {
	return sealAt(ctx, rawDataset, random, time.Now().UTC().Truncate(time.Millisecond))
}

func sealAt(ctx context.Context, rawDataset []byte, random io.Reader, securityNow time.Time) (Bundle, error) {
	if ctx == nil || random == nil || securityNow.IsZero() {
		return Bundle{}, reject(ErrorInput)
	}
	if err := contextError(ctx); err != nil {
		return Bundle{}, err
	}
	dataset, err := demohistory.Load(rawDataset)
	if err != nil {
		return Bundle{}, reject(ErrorDataset)
	}
	securityNow = securityNow.Round(0).UTC()
	if securityNow.Before(dataset.CoverageEnd()) {
		return Bundle{}, reject(ErrorInput)
	}
	impactDigest, err := ImpactSourceHealthDigest(dataset)
	if err != nil {
		return Bundle{}, err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return Bundle{}, reject(ErrorRandom)
	}
	defer clear(privateKey)
	fixtureKey, err := base64.RawURLEncoding.Strict().DecodeString(validation.PinnedDemoHistoryFixturePublicKey)
	if err != nil || subtle.ConstantTimeCompare(publicKey, fixtureKey) == 1 {
		return Bundle{}, reject(ErrorRandom)
	}
	manifestID, err := randomUUID(random)
	if err != nil {
		return Bundle{}, err
	}
	importID, err := randomUUID(random)
	if err != nil {
		return Bundle{}, err
	}
	runID, err := randomUUID(random)
	if err != nil || manifestID == importID || manifestID == runID || importID == runID {
		return Bundle{}, reject(ErrorRandom)
	}
	runScope := "sentinelflow-demo-run:" + runID
	manifest := manifestWire{
		ClockAt:            formatMilliseconds(dataset.CoverageEnd()),
		CoverageEnd:        formatMilliseconds(dataset.CoverageEnd()),
		CoverageStart:      formatMilliseconds(dataset.CoverageStart()),
		DatasetDigest:      dataset.ManifestDatasetJCSDigest(),
		DatasetID:          dataset.DatasetID(),
		DatasetRecordCount: dataset.RecordCount(),
		DatasetSchema:      dataset.SchemaVersion(),
		ImportID:           importID,
		IssuedAt:           formatMilliseconds(securityNow),
		ManifestID:         manifestID,
		PathCatalogVersion: dataset.PathCatalogVersion(),
		Profile:            validation.DemoHistoryProfile,
		SchemaVersion:      validation.DemoHistoryManifestSchemaVersion,
		SourceHealthDigest: dataset.SourceHealthJCSDigest(),
	}
	manifestJCS, err := json.Marshal(manifest)
	if err != nil || len(manifestJCS) == 0 || len(manifestJCS) > validation.MaxDemoHistoryManifestJCSBytes {
		return Bundle{}, reject(ErrorCanonical)
	}
	manifestDigest := digest(manifestJCS)
	signingDigest, err := hex.DecodeString(strings.TrimPrefix(manifestDigest, "sha256:"))
	if err != nil || len(signingDigest) != sha256.Size {
		return Bundle{}, reject(ErrorCanonical)
	}
	signingInput := make([]byte, 0, len(validation.DemoHistorySignatureDomain)+1+len(signingDigest))
	signingInput = append(signingInput, validation.DemoHistorySignatureDomain...)
	signingInput = append(signingInput, '\n')
	signingInput = append(signingInput, signingDigest...)
	signature := ed25519.Sign(privateKey, signingInput)
	defer clear(signingInput)
	envelope := envelopeWire{
		FixtureOnly:       false,
		KeyScope:          runScope,
		Manifest:          manifest,
		ManifestDigest:    manifestDigest,
		ManifestJCSB64URL: base64.RawURLEncoding.EncodeToString(manifestJCS),
		PublicKeyB64URL:   base64.RawURLEncoding.EncodeToString(publicKey),
		SchemaVersion:     validation.DemoHistorySignedManifestSchemaVersion,
		SignatureB64URL:   base64.RawURLEncoding.EncodeToString(signature),
	}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil || len(envelopeBytes) == 0 || len(envelopeBytes) > validation.MaxDemoHistorySignedEnvelopeBytes {
		return Bundle{}, reject(ErrorCanonical)
	}
	verificationDigest, err := signatureVerificationDigest(runScope, publicKey, manifestDigest, signature)
	if err != nil {
		return Bundle{}, err
	}
	assertionDocument := assertionsWire{
		ClockAt:                     manifest.ClockAt,
		ImpactSourceHealthDigest:    impactDigest,
		ImportID:                    importID,
		IssuedAt:                    manifest.IssuedAt,
		ManifestDigest:              manifestDigest,
		ManifestID:                  manifestID,
		PublicKeyB64URL:             envelope.PublicKeyB64URL,
		RunScope:                    runScope,
		SchemaVersion:               AssertionsSchemaVersion,
		SignatureVerificationDigest: verificationDigest,
	}
	assertionBytes, err := json.Marshal(assertionDocument)
	if err != nil || len(assertionBytes) == 0 || len(assertionBytes) > MaxAssertionsBytes {
		return Bundle{}, reject(ErrorCanonical)
	}
	bundle := Bundle{envelope: envelopeBytes, assertions: assertionBytes}
	if _, assertions, verifyErr := VerifyBundle(ctx, rawDataset, bundle.SignedEnvelope(), bundle.PublicAssertions()); verifyErr != nil ||
		assertions.signatureVerificationDigest != verificationDigest {
		return Bundle{}, reject(ErrorVerification)
	}
	return bundle, nil
}

// ImpactSourceHealthDigest computes the exact validation historical-impact
// normalized source-health digest for the pinned complete-coverage dataset.
func ImpactSourceHealthDigest(dataset demohistory.Dataset) (string, error) {
	coverage := dataset.SourceCoverage()
	if len(coverage) != 2 {
		return "", reject(ErrorDataset)
	}
	bySender := make(map[string]demohistory.SourceCoverage, len(coverage))
	for _, item := range coverage {
		bySender[item.SenderID()] = item
	}
	gateway, gatewayOK := bySender["gateway-demo"]
	auth, authOK := bySender["auth-demo"]
	if !gatewayOK || !authOK || gateway.CoverageStatus() != "complete" || auth.CoverageStatus() != "complete" ||
		gateway.UnresolvedIntervalCount() != 0 || auth.UnresolvedIntervalCount() != 0 ||
		!gateway.CoverageStart().Equal(dataset.CoverageStart()) || !gateway.CoverageEnd().Equal(dataset.CoverageEnd()) ||
		!auth.CoverageStart().Equal(dataset.CoverageStart()) || !auth.CoverageEnd().Equal(dataset.CoverageEnd()) {
		return "", reject(ErrorDataset)
	}
	start := dataset.CoverageStart().Format(time.RFC3339Nano)
	end := dataset.CoverageEnd().Format(time.RFC3339Nano)
	canonical := `[{"complete":true,"coverage_end":"` + end + `","coverage_start":"` + start +
		`","intervals":[],"source":"gateway"},{"complete":true,"coverage_end":"` + end +
		`","coverage_start":"` + start + `","intervals":[],"source":"auth"}]`
	result := digest([]byte(canonical))
	if result != validation.PinnedDemoHistoryImpactSourceHealthDigest {
		return "", reject(ErrorDataset)
	}
	return result, nil
}

func randomUUID(random io.Reader) (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(random, raw); err != nil {
		clear(raw)
		return "", reject(ErrorRandom)
	}
	defer clear(raw)
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	value := hex.EncodeToString(raw)
	return value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:], nil
}

func signatureVerificationDigest(runScope string, publicKey []byte, manifestDigest string, signature []byte) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return "", reject(ErrorCanonical)
	}
	proof := struct {
		Domain          string `json:"domain"`
		ManifestDigest  string `json:"manifest_digest"`
		PublicKeyDigest string `json:"public_key_digest"`
		RunScopeDigest  string `json:"run_scope_digest"`
		SchemaVersion   string `json:"schema_version"`
		SignatureDigest string `json:"signature_digest"`
	}{
		Domain:          validation.DemoHistorySignatureDomain,
		ManifestDigest:  manifestDigest,
		PublicKeyDigest: digest(publicKey),
		RunScopeDigest:  digest([]byte(runScope)),
		SchemaVersion:   "demo-history-signature-verification-v1",
		SignatureDigest: digest(signature),
	}
	canonical, err := json.Marshal(proof)
	if err != nil {
		return "", reject(ErrorCanonical)
	}
	return digest(canonical), nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func formatMilliseconds(value time.Time) string {
	return value.Round(0).UTC().Format("2006-01-02T15:04:05.000Z")
}
