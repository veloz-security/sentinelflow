package demohistoryseal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/devwooops/sentinelflow/internal/demohistory"
	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/validation"
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	runPattern    = regexp.MustCompile(`^sentinelflow-demo-run:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func ParseAssertions(raw []byte) (Assertions, error) {
	if len(raw) == 0 || len(raw) > MaxAssertionsBytes {
		return Assertions{}, reject(ErrorBundle)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire assertionsWire
	if err := decoder.Decode(&wire); err != nil {
		return Assertions{}, reject(ErrorBundle)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Assertions{}, reject(ErrorBundle)
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Assertions{}, reject(ErrorBundle)
	}
	clockAt, err := parseTime(wire.ClockAt)
	if err != nil {
		return Assertions{}, err
	}
	issuedAt, err := parseTime(wire.IssuedAt)
	if err != nil {
		return Assertions{}, err
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(wire.PublicKeyB64URL)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKey) != wire.PublicKeyB64URL ||
		wire.PublicKeyB64URL == validation.PinnedDemoHistoryFixturePublicKey ||
		wire.SchemaVersion != AssertionsSchemaVersion || !uuidPattern.MatchString(wire.ImportID) ||
		!uuidPattern.MatchString(wire.ManifestID) || !runPattern.MatchString(wire.RunScope) ||
		wire.ImpactSourceHealthDigest != validation.PinnedDemoHistoryImpactSourceHealthDigest ||
		!digestPattern.MatchString(wire.ManifestDigest) ||
		!digestPattern.MatchString(wire.SignatureVerificationDigest) || issuedAt.Before(clockAt) {
		return Assertions{}, reject(ErrorBundle)
	}
	return Assertions{
		clockAt:                     clockAt,
		impactSourceHealthDigest:    wire.ImpactSourceHealthDigest,
		importID:                    wire.ImportID,
		issuedAt:                    issuedAt,
		manifestDigest:              wire.ManifestDigest,
		manifestID:                  wire.ManifestID,
		publicKeyB64URL:             wire.PublicKeyB64URL,
		runScope:                    wire.RunScope,
		signatureVerificationDigest: wire.SignatureVerificationDigest,
	}, nil
}

// VerifyBundle reconstructs the strict verifier solely from public assertions,
// recomputes the dataset-owned impact proof, and verifies the envelope.
func VerifyBundle(
	ctx context.Context,
	rawDataset, signedEnvelope, publicAssertions []byte,
) (*validation.StrictDemoHistoryManifestVerifier, Assertions, error) {
	return verifyBundle(ctx, rawDataset, signedEnvelope, publicAssertions, true)
}

// VerifyBundleImmutable preserves all shape, JCS, signature, assertion and
// dataset checks without minting a runtime binding or consuming freshness.
func VerifyBundleImmutable(
	ctx context.Context,
	rawDataset, signedEnvelope, publicAssertions []byte,
) (*validation.StrictDemoHistoryManifestVerifier, Assertions, error) {
	return verifyBundle(ctx, rawDataset, signedEnvelope, publicAssertions, false)
}

func verifyBundle(
	ctx context.Context,
	rawDataset, signedEnvelope, publicAssertions []byte,
	requireFresh bool,
) (*validation.StrictDemoHistoryManifestVerifier, Assertions, error) {
	if ctx == nil {
		return nil, Assertions{}, reject(ErrorInput)
	}
	if err := contextError(ctx); err != nil {
		return nil, Assertions{}, err
	}
	dataset, err := demohistory.Load(rawDataset)
	if err != nil {
		return nil, Assertions{}, reject(ErrorDataset)
	}
	assertions, err := ParseAssertions(publicAssertions)
	if err != nil {
		return nil, Assertions{}, err
	}
	impactDigest, err := ImpactSourceHealthDigest(dataset)
	if err != nil || impactDigest != validation.PinnedDemoHistoryImpactSourceHealthDigest ||
		impactDigest != assertions.impactSourceHealthDigest {
		return nil, Assertions{}, reject(ErrorVerification)
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(assertions.publicKeyB64URL)
	if err != nil {
		return nil, Assertions{}, reject(ErrorBundle)
	}
	verifier, err := validation.NewStrictDemoHistoryManifestVerifier(validation.DemoHistoryManifestVerifierConfig{
		Environment:                      validation.EnvironmentDemo,
		ExpectedPublicKey:                publicKey,
		ExpectedRunScope:                 assertions.runScope,
		ExpectedImportID:                 assertions.importID,
		ExpectedClockAt:                  assertions.clockAt,
		ExpectedImpactSourceHealthDigest: assertions.impactSourceHealthDigest,
	})
	if err != nil {
		return nil, Assertions{}, reject(ErrorVerification)
	}
	input := validation.DemoHistoryVerificationInput{
		SignedManifestEnvelope: append([]byte(nil), signedEnvelope...),
		ImportedRowsDigest:     dataset.ImportedRowsJCSDigest(),
		ImportedRecordCount:    dataset.RecordCount(),
	}
	if requireFresh {
		binding, verifyErr := verifier.VerifyDemoHistory(ctx, input)
		if verifyErr != nil || !binding.HistoryCutoff().At().Equal(assertions.clockAt) {
			return nil, Assertions{}, reject(ErrorVerification)
		}
	} else if verifier.VerifyDemoHistoryImmutable(ctx, input) != nil {
		return nil, Assertions{}, reject(ErrorVerification)
	}
	var envelope envelopeWire
	decoder := json.NewDecoder(bytes.NewReader(signedEnvelope))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, Assertions{}, reject(ErrorVerification)
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonicalEnvelope, signedEnvelope) {
		return nil, Assertions{}, reject(ErrorVerification)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureB64URL)
	if err != nil {
		return nil, Assertions{}, reject(ErrorVerification)
	}
	proof, err := signatureVerificationDigest(assertions.runScope, publicKey, assertions.manifestDigest, signature)
	if err != nil || proof != assertions.signatureVerificationDigest || envelope.FixtureOnly ||
		envelope.KeyScope != assertions.runScope || envelope.PublicKeyB64URL != assertions.publicKeyB64URL ||
		envelope.ManifestDigest != assertions.manifestDigest || envelope.Manifest.ImportID != assertions.importID ||
		envelope.Manifest.ManifestID != assertions.manifestID || envelope.Manifest.ClockAt != formatMilliseconds(assertions.clockAt) ||
		envelope.Manifest.IssuedAt != formatMilliseconds(assertions.issuedAt) {
		return nil, Assertions{}, reject(ErrorVerification)
	}
	return verifier, assertions, nil
}

// ReadBundle reads exactly the two fixed public files beneath an absolute
// directory. Symlinks, non-regular files, replacement races, and oversize
// inputs fail closed.
func ReadBundle(directory string) ([]byte, []byte, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, nil, reject(ErrorSource)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, reject(ErrorSource)
	}
	defer root.Close()
	envelope, err := readRegular(root, EnvelopeFileName, validation.MaxDemoHistorySignedEnvelopeBytes)
	if err != nil {
		return nil, nil, err
	}
	assertions, err := readRegular(root, AssertionsFileName, MaxAssertionsBytes)
	if err != nil {
		return nil, nil, err
	}
	return envelope, assertions, nil
}

func readRegular(root *os.Root, name string, maximum int) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > int64(maximum) {
		return nil, reject(ErrorSource)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, reject(ErrorSource)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, reject(ErrorSource)
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(raw) < 1 || len(raw) > maximum {
		return nil, reject(ErrorSource)
	}
	return raw, nil
}

func parseTime(value string) (time.Time, error) {
	parsed, err := events.ParseTimestamp(value)
	if err != nil || !parsed.Valid() {
		return time.Time{}, reject(ErrorBundle)
	}
	result := parsed.Time().Round(0).UTC()
	if formatMilliseconds(result) != value {
		return time.Time{}, reject(ErrorBundle)
	}
	return result, nil
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return reject(ErrorCanceled)
	}
	return nil
}
