package validation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/events"
)

const (
	DemoHistorySignedManifestSchemaVersion = "demo-history-signed-manifest-v1"
	DemoHistoryManifestSchemaVersion       = "demo-history-v1"
	DemoHistoryDatasetSchemaVersion        = "demo-history-dataset-v1"
	DemoHistoryProfile                     = "isolated-demo"
	DemoHistorySignatureDomain             = "sentinelflow demo-history-v1"
	DemoHistoryFixtureKeyScope             = "public-test-only; actual demo runs must generate a run-scoped key and manifest"

	PinnedDemoHistoryDatasetID           = "019b0000-0000-7000-8000-000000000100"
	PinnedDemoHistoryDatasetRecordCount  = uint64(4)
	PinnedDemoHistoryImportedRowsDigest  = "sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807"
	PinnedDemoHistorySourceHealthDigest  = "sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe"
	PinnedDemoHistoryFixturePublicKey    = "_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU"
	MaxDemoHistorySignedEnvelopeBytes    = 32 << 10
	MaxDemoHistoryManifestJCSBytes       = 16 << 10
	DemoHistoryManifestMaximumAge        = 5 * time.Minute
	DemoHistoryManifestMaximumFutureSkew = 30 * time.Second
)

var demoHistoryRunScopePattern = regexp.MustCompile(`^sentinelflow-demo-run:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type DemoHistoryManifestErrorCode string

const (
	DemoHistoryManifestErrorConfiguration DemoHistoryManifestErrorCode = "demo_history_manifest_configuration_invalid"
	DemoHistoryManifestErrorInput         DemoHistoryManifestErrorCode = "demo_history_manifest_input_invalid"
	DemoHistoryManifestErrorEncoding      DemoHistoryManifestErrorCode = "demo_history_manifest_encoding_invalid"
	DemoHistoryManifestErrorContract      DemoHistoryManifestErrorCode = "demo_history_manifest_contract_invalid"
	DemoHistoryManifestErrorScope         DemoHistoryManifestErrorCode = "demo_history_manifest_scope_mismatch"
	DemoHistoryManifestErrorDigest        DemoHistoryManifestErrorCode = "demo_history_manifest_digest_mismatch"
	DemoHistoryManifestErrorSignature     DemoHistoryManifestErrorCode = "demo_history_manifest_signature_invalid"
	DemoHistoryManifestErrorFreshness     DemoHistoryManifestErrorCode = "demo_history_manifest_freshness_invalid"
	DemoHistoryManifestErrorCanceled      DemoHistoryManifestErrorCode = "demo_history_manifest_canceled"
)

// DemoHistoryManifestError deliberately carries only a stable code. It never
// includes an envelope, a dataset row, a signature, or key material.
type DemoHistoryManifestError struct {
	Code DemoHistoryManifestErrorCode
}

func (e *DemoHistoryManifestError) Error() string {
	if e == nil {
		return "demo history manifest verification failed"
	}
	return "demo history manifest verification failed: " + string(e.Code)
}

// DemoHistoryManifestVerifierConfig is a fail-closed startup assertion. The
// impact digest is intentionally separate from the source-health digest in the
// signed manifest: it belongs to the normalized retained-history query
// projection and must be supplied by that trusted import/query boundary.
type DemoHistoryManifestVerifierConfig struct {
	Environment                      Environment
	ExpectedPublicKey                []byte
	ExpectedRunScope                 string
	ExpectedImportID                 string
	ExpectedClockAt                  time.Time
	ExpectedImpactSourceHealthDigest string
	AllowPublicTestFixture           bool
	TestSecurityNow                  time.Time
}

// StrictDemoHistoryManifestVerifier holds only public verification material
// and immutable run assertions. There is no constructor accepting a private
// key and no path that returns a successful fake binding.
type StrictDemoHistoryManifestVerifier struct {
	environment                      Environment
	expectedPublicKey                [ed25519.PublicKeySize]byte
	expectedRunScope                 string
	expectedImportID                 string
	expectedClockAt                  time.Time
	expectedImpactSourceHealthDigest string
	allowPublicTestFixture           bool
	testSecurityNow                  time.Time
}

// NewStrictDemoHistoryManifestVerifier creates either a production-shaped
// isolated-demo verifier or an explicit test-only fixture verifier. Production
// and development environments can never opt in to deterministic demo time.
func NewStrictDemoHistoryManifestVerifier(config DemoHistoryManifestVerifierConfig) (*StrictDemoHistoryManifestVerifier, error) {
	if len(config.ExpectedPublicKey) != ed25519.PublicKeySize ||
		!consistencyUUIDPattern.MatchString(config.ExpectedImportID) ||
		!validSnapshotTime(config.ExpectedClockAt) ||
		config.ExpectedImpactSourceHealthDigest != PinnedDemoHistoryImpactSourceHealthDigest {
		return nil, rejectDemoHistoryManifest(DemoHistoryManifestErrorConfiguration)
	}

	fixturePublicKey, err := decodeExactBase64URL(PinnedDemoHistoryFixturePublicKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, rejectDemoHistoryManifest(DemoHistoryManifestErrorConfiguration)
	}

	switch config.Environment {
	case EnvironmentTest:
		if !config.AllowPublicTestFixture || config.ExpectedRunScope != DemoHistoryFixtureKeyScope ||
			!bytes.Equal(config.ExpectedPublicKey, fixturePublicKey) || !validSnapshotTime(config.TestSecurityNow) {
			return nil, rejectDemoHistoryManifest(DemoHistoryManifestErrorConfiguration)
		}
	case EnvironmentDemo:
		if config.AllowPublicTestFixture || !config.TestSecurityNow.IsZero() ||
			!demoHistoryRunScopePattern.MatchString(config.ExpectedRunScope) ||
			bytes.Equal(config.ExpectedPublicKey, fixturePublicKey) {
			return nil, rejectDemoHistoryManifest(DemoHistoryManifestErrorConfiguration)
		}
	default:
		return nil, rejectDemoHistoryManifest(DemoHistoryManifestErrorConfiguration)
	}

	verifier := &StrictDemoHistoryManifestVerifier{
		environment:                      config.Environment,
		expectedRunScope:                 config.ExpectedRunScope,
		expectedImportID:                 config.ExpectedImportID,
		expectedClockAt:                  config.ExpectedClockAt.Round(0).UTC(),
		expectedImpactSourceHealthDigest: config.ExpectedImpactSourceHealthDigest,
		allowPublicTestFixture:           config.AllowPublicTestFixture,
		testSecurityNow:                  config.TestSecurityNow.Round(0).UTC(),
	}
	copy(verifier.expectedPublicKey[:], config.ExpectedPublicKey)
	return verifier, nil
}

type demoHistorySignedEnvelopeWire struct {
	SchemaVersion     string                   `json:"schema_version"`
	FixtureOnly       *bool                    `json:"fixture_only"`
	KeyScope          string                   `json:"key_scope"`
	Manifest          *demoHistoryManifestWire `json:"manifest"`
	ManifestJCSB64URL string                   `json:"manifest_jcs_b64url"`
	ManifestDigest    string                   `json:"manifest_digest"`
	SignatureB64URL   string                   `json:"signature_b64url"`
	PublicKeyB64URL   string                   `json:"public_key_b64url"`
}

type demoHistoryManifestWire struct {
	SchemaVersion      string `json:"schema_version"`
	ManifestID         string `json:"manifest_id"`
	Profile            string `json:"profile"`
	ClockAt            string `json:"clock_at"`
	DatasetID          string `json:"dataset_id"`
	DatasetSchema      string `json:"dataset_schema_version"`
	DatasetDigest      string `json:"dataset_digest"`
	DatasetRecordCount uint64 `json:"dataset_record_count"`
	ImportID           string `json:"import_id"`
	CoverageStart      string `json:"coverage_start"`
	CoverageEnd        string `json:"coverage_end"`
	PathCatalogVersion string `json:"path_catalog_version"`
	SourceHealthDigest string `json:"source_health_digest"`
	IssuedAt           string `json:"issued_at"`
}

var demoHistoryEnvelopeKeys = map[string]struct{}{
	"schema_version": {}, "fixture_only": {}, "key_scope": {}, "manifest": {},
	"manifest_jcs_b64url": {}, "manifest_digest": {}, "signature_b64url": {}, "public_key_b64url": {},
}

var demoHistoryManifestKeys = map[string]struct{}{
	"schema_version": {}, "manifest_id": {}, "profile": {}, "clock_at": {}, "dataset_id": {},
	"dataset_schema_version": {}, "dataset_digest": {}, "dataset_record_count": {}, "import_id": {},
	"coverage_start": {}, "coverage_end": {}, "path_catalog_version": {}, "source_health_digest": {}, "issued_at": {},
}

// VerifyDemoHistory verifies strict envelope shape, byte-exact manifest JCS,
// pinned dataset/import assertions, freshness, and the run-scoped Ed25519
// signature before minting the package-private sealed binding.
func (v *StrictDemoHistoryManifestVerifier) VerifyDemoHistory(ctx context.Context, input DemoHistoryVerificationInput) (VerifiedDemoHistoryBinding, error) {
	return v.verifyDemoHistory(ctx, input, true)
}

// VerifyDemoHistoryImmutable validates the complete signature, shape and
// immutable claim contract while deliberately discarding the sealed binding.
// It can support an exact append-only import read on restart, but cannot
// authorize runtime history use or a first stale import.
func (v *StrictDemoHistoryManifestVerifier) VerifyDemoHistoryImmutable(
	ctx context.Context,
	input DemoHistoryVerificationInput,
) error {
	_, err := v.verifyDemoHistory(ctx, input, false)
	return err
}

// verifyDemoHistory always verifies the complete cryptographic and immutable
// claim contract. Only the package-owned runtime activation path may defer the
// five-minute issuance check to a consumer-bound database activation receipt.
// The resulting binding never leaves this package before that receipt is
// verified.
func (v *StrictDemoHistoryManifestVerifier) verifyDemoHistory(
	ctx context.Context,
	input DemoHistoryVerificationInput,
	requireFreshIssuance bool,
) (VerifiedDemoHistoryBinding, error) {
	if v == nil || ctx == nil {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorInput)
	}
	if err := demoHistoryContextError(ctx); err != nil {
		return VerifiedDemoHistoryBinding{}, err
	}
	// Freeze caller-owned bytes once so the strict-shape, canonicalization, and
	// signature passes all evaluate the same immutable envelope.
	rawEnvelope := append([]byte(nil), input.SignedManifestEnvelope...)
	if len(rawEnvelope) == 0 || len(rawEnvelope) > MaxDemoHistorySignedEnvelopeBytes ||
		!utf8.Valid(rawEnvelope) || strictJSON(rawEnvelope) != nil ||
		!validDigest(input.ImportedRowsDigest) || input.ImportedRowsDigest != PinnedDemoHistoryImportedRowsDigest ||
		input.ImportedRecordCount != PinnedDemoHistoryDatasetRecordCount {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorInput)
	}

	root, err := requireDemoHistoryObjectKeys(rawEnvelope, demoHistoryEnvelopeKeys)
	if err != nil {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorContract)
	}
	if _, err := requireDemoHistoryObjectKeys(root["manifest"], demoHistoryManifestKeys); err != nil {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorContract)
	}

	decoder := json.NewDecoder(bytes.NewReader(rawEnvelope))
	decoder.DisallowUnknownFields()
	var envelope demoHistorySignedEnvelopeWire
	if err := decoder.Decode(&envelope); err != nil || requireSnapshotEOF(decoder) != nil ||
		envelope.FixtureOnly == nil || envelope.Manifest == nil {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorEncoding)
	}
	if envelope.SchemaVersion != DemoHistorySignedManifestSchemaVersion {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorContract)
	}
	if envelope.KeyScope != v.expectedRunScope ||
		(v.allowPublicTestFixture && !*envelope.FixtureOnly) || (!v.allowPublicTestFixture && *envelope.FixtureOnly) {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorScope)
	}

	publicKey, err := decodeExactBase64URL(envelope.PublicKeyB64URL, ed25519.PublicKeySize)
	if err != nil || !bytes.Equal(publicKey, v.expectedPublicKey[:]) {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorScope)
	}
	if v.environment == EnvironmentDemo && envelope.PublicKeyB64URL == PinnedDemoHistoryFixturePublicKey {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorScope)
	}

	manifestJCS, err := decodeBoundedBase64URL(envelope.ManifestJCSB64URL, MaxDemoHistoryManifestJCSBytes)
	if err != nil || !utf8.Valid(manifestJCS) || strictJSON(manifestJCS) != nil {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorEncoding)
	}
	canonicalManifest, err := marshalSnapshotJCS(envelope.Manifest)
	if err != nil || !bytes.Equal(manifestJCS, canonicalManifest) {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorContract)
	}
	if !validDigest(envelope.ManifestDigest) || sha256Digest(canonicalManifest) != envelope.ManifestDigest {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorDigest)
	}

	signature, err := decodeExactBase64URL(envelope.SignatureB64URL, ed25519.SignatureSize)
	if err != nil {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorEncoding)
	}
	signingInput, err := demoHistorySigningInput(envelope.ManifestDigest)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(v.expectedPublicKey[:]), signingInput, signature) {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorSignature)
	}
	if err := demoHistoryContextError(ctx); err != nil {
		return VerifiedDemoHistoryBinding{}, err
	}

	manifest := envelope.Manifest
	clockAt, coverageStart, coverageEnd, issuedAt, err := v.validateManifest(manifest, requireFreshIssuance)
	if err != nil {
		return VerifiedDemoHistoryBinding{}, err
	}

	verificationDigest, err := demoHistorySignatureVerificationDigest(
		v.expectedRunScope,
		v.expectedPublicKey[:],
		envelope.ManifestDigest,
		signature,
	)
	if err != nil {
		return VerifiedDemoHistoryBinding{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorContract)
	}

	return VerifiedDemoHistoryBinding{
		verified:                    true,
		verificationEnvironment:     v.environment,
		fixtureOnly:                 v.allowPublicTestFixture,
		schemaVersion:               manifest.SchemaVersion,
		profile:                     manifest.Profile,
		manifestID:                  manifest.ManifestID,
		datasetID:                   manifest.DatasetID,
		datasetSchemaVersion:        manifest.DatasetSchema,
		datasetLocator:              DemoHistoryDatasetLocator,
		importID:                    manifest.ImportID,
		clockAt:                     clockAt,
		coverageStart:               coverageStart,
		coverageEnd:                 coverageEnd,
		issuedAt:                    issuedAt,
		pathCatalogVersion:          manifest.PathCatalogVersion,
		datasetRecordCount:          manifest.DatasetRecordCount,
		rawFileDigest:               PinnedDemoHistoryRawFileDigest,
		datasetDigest:               manifest.DatasetDigest,
		manifestDigest:              envelope.ManifestDigest,
		importedRowsDigest:          input.ImportedRowsDigest,
		manifestSourceHealthDigest:  manifest.SourceHealthDigest,
		impactSourceHealthDigest:    v.expectedImpactSourceHealthDigest,
		runScopeDigest:              sha256Digest([]byte(v.expectedRunScope)),
		publicKeyDigest:             sha256Digest(v.expectedPublicKey[:]),
		signatureVerificationDigest: verificationDigest,
	}, nil
}

func (v *StrictDemoHistoryManifestVerifier) validateManifest(
	manifest *demoHistoryManifestWire,
	requireFreshIssuance bool,
) (time.Time, time.Time, time.Time, time.Time, error) {
	if manifest.SchemaVersion != DemoHistoryManifestSchemaVersion || manifest.Profile != DemoHistoryProfile ||
		!consistencyUUIDPattern.MatchString(manifest.ManifestID) || manifest.DatasetID != PinnedDemoHistoryDatasetID ||
		manifest.DatasetSchema != DemoHistoryDatasetSchemaVersion || manifest.DatasetDigest != PinnedDemoHistoryDatasetDigest ||
		manifest.DatasetRecordCount != PinnedDemoHistoryDatasetRecordCount || manifest.ImportID != v.expectedImportID ||
		manifest.PathCatalogVersion != events.PathCatalogV1 || manifest.SourceHealthDigest != PinnedDemoHistorySourceHealthDigest {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorContract)
	}

	clockAt, err := parseDemoHistoryTime(manifest.ClockAt)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, err
	}
	coverageStart, err := parseDemoHistoryTime(manifest.CoverageStart)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, err
	}
	coverageEnd, err := parseDemoHistoryTime(manifest.CoverageEnd)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, err
	}
	issuedAt, err := parseDemoHistoryTime(manifest.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, err
	}

	if !clockAt.Equal(v.expectedClockAt) || !coverageEnd.Equal(clockAt) ||
		!coverageStart.Equal(clockAt.Add(-HistoricalImpactLookback)) || issuedAt.Before(coverageEnd) {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorContract)
	}

	now := time.Now().Round(0).UTC()
	if v.allowPublicTestFixture {
		now = v.testSecurityNow
	}
	if requireFreshIssuance &&
		(issuedAt.Before(now.Add(-DemoHistoryManifestMaximumAge)) || issuedAt.After(now.Add(DemoHistoryManifestMaximumFutureSkew))) {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorFreshness)
	}
	return clockAt, coverageStart, coverageEnd, issuedAt, nil
}

func requireDemoHistoryObjectKeys(raw []byte, expected map[string]struct{}) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&object); err != nil || requireSnapshotEOF(decoder) != nil || object == nil || len(object) != len(expected) {
		return nil, errors.New("invalid object")
	}
	for key := range object {
		if _, ok := expected[key]; !ok {
			return nil, errors.New("invalid object key")
		}
	}
	return object, nil
}

func decodeExactBase64URL(value string, expectedBytes int) ([]byte, error) {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(expectedBytes) {
		return nil, errors.New("invalid base64url length")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != expectedBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid base64url")
	}
	return decoded, nil
}

func decodeBoundedBase64URL(value string, maximumBytes int) ([]byte, error) {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(maximumBytes) {
		return nil, errors.New("invalid base64url length")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximumBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid base64url")
	}
	return decoded, nil
}

func demoHistorySigningInput(manifestDigest string) ([]byte, error) {
	if !validDigest(manifestDigest) {
		return nil, errors.New("invalid digest")
	}
	digestBytes, err := hex.DecodeString(manifestDigest[len("sha256:"):])
	if err != nil || len(digestBytes) != sha256.Size {
		return nil, errors.New("invalid digest")
	}
	result := make([]byte, 0, len(DemoHistorySignatureDomain)+1+sha256.Size)
	result = append(result, DemoHistorySignatureDomain...)
	result = append(result, '\n')
	result = append(result, digestBytes...)
	return result, nil
}

func demoHistorySignatureVerificationDigest(runScope string, publicKey []byte, manifestDigest string, signature []byte) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !validDigest(manifestDigest) {
		return "", errors.New("invalid signature proof")
	}
	proof := struct {
		SchemaVersion   string `json:"schema_version"`
		Domain          string `json:"domain"`
		RunScopeDigest  string `json:"run_scope_digest"`
		PublicKeyDigest string `json:"public_key_digest"`
		ManifestDigest  string `json:"manifest_digest"`
		SignatureDigest string `json:"signature_digest"`
	}{
		SchemaVersion:   "demo-history-signature-verification-v1",
		Domain:          DemoHistorySignatureDomain,
		RunScopeDigest:  sha256Digest([]byte(runScope)),
		PublicKeyDigest: sha256Digest(publicKey),
		ManifestDigest:  manifestDigest,
		SignatureDigest: sha256Digest(signature),
	}
	canonical, err := marshalSnapshotJCS(proof)
	if err != nil {
		return "", err
	}
	return sha256Digest(canonical), nil
}

func parseDemoHistoryTime(value string) (time.Time, error) {
	timestamp, err := events.ParseTimestamp(value)
	if err != nil || !timestamp.Valid() || !validSnapshotTime(timestamp.Time()) {
		return time.Time{}, rejectDemoHistoryManifest(DemoHistoryManifestErrorContract)
	}
	return timestamp.Time().Round(0).UTC(), nil
}

func demoHistoryContextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return rejectDemoHistoryManifest(DemoHistoryManifestErrorCanceled)
	default:
		return nil
	}
}

func rejectDemoHistoryManifest(code DemoHistoryManifestErrorCode) error {
	return &DemoHistoryManifestError{Code: code}
}
