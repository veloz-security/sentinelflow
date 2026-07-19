// Package demohistoryproof loads and verifies the public, run-scoped proof
// material used by demo-only workers. It never accepts or reads a private key.
package demohistoryproof

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/validation"
)

var (
	ErrInvalidConfiguration = errors.New("demo history public proof configuration rejected")
	ErrSource               = errors.New("demo history public proof source rejected")
	ErrVerification         = errors.New("demo history public proof verification rejected")
)

// Config contains public proof assertions only. The signed envelope is
// untrusted input until Verify returns an opaque VerifiedDemoHistoryBinding.
type Config struct {
	SignedEnvelopeFile       string
	PublicKeyB64URL          string
	RunScope                 string
	ImportID                 string
	ClockAt                  time.Time
	ImpactSourceHealthDigest string
}

// Verify freezes one bounded regular file, reconstructs the strict demo
// verifier from separately supplied public assertions, and verifies the
// run-scoped Ed25519 signature before returning a sealed binding.
func Verify(ctx context.Context, config Config) (validation.VerifiedDemoHistoryBinding, error) {
	verifier, envelope, err := load(ctx, config)
	if err != nil {
		return validation.VerifiedDemoHistoryBinding{}, err
	}
	binding, err := verifier.VerifyDemoHistory(ctx, verificationInput(envelope))
	if err != nil {
		return validation.VerifiedDemoHistoryBinding{}, ErrVerification
	}
	return binding, nil
}

// CreatePair is restricted to the one-shot demo activator. It requires the
// full strict proof and promotes both consumer capabilities atomically.
func CreatePair(
	ctx context.Context,
	config Config,
	db validation.DemoHistoryActivationDB,
	analysisSecret demohistoryactivation.Secret,
	validationSecret demohistoryactivation.Secret,
) (validation.CreatedDemoHistoryActivationPair, error) {
	verifier, envelope, err := load(ctx, config)
	if err != nil {
		return validation.CreatedDemoHistoryActivationPair{}, err
	}
	analysisBytes, analysisOK := analysisSecret.Bytes()
	validationBytes, validationOK := validationSecret.Bytes()
	if !analysisOK || !validationOK {
		clear(analysisBytes)
		clear(validationBytes)
		return validation.CreatedDemoHistoryActivationPair{}, ErrInvalidConfiguration
	}
	activated, err := validation.CreateDemoHistoryRuntimeActivationPair(
		ctx, db, analysisBytes, validationBytes, verifier, verificationInput(envelope),
	)
	clear(analysisBytes)
	clear(validationBytes)
	if err != nil {
		return validation.CreatedDemoHistoryActivationPair{}, ErrVerification
	}
	return activated, nil
}

// Attach verifies the signature and immutable claims, then asks the database
// to attach to an exact pre-created, unexpired activation. It cannot create a
// new activation and does not expose an intermediate stale binding.
func Attach(
	ctx context.Context,
	config Config,
	db validation.DemoHistoryActivationDB,
	consumer validation.DemoHistoryActivationConsumer,
	secret demohistoryactivation.Secret,
) (validation.ActivatedDemoHistoryBinding, error) {
	verifier, envelope, err := load(ctx, config)
	if err != nil {
		return validation.ActivatedDemoHistoryBinding{}, err
	}
	secretBytes, ok := secret.Bytes()
	if !ok {
		return validation.ActivatedDemoHistoryBinding{}, ErrInvalidConfiguration
	}
	activated, err := validation.AttachDemoHistoryRuntimeActivation(
		ctx, db, consumer, secretBytes, verifier, verificationInput(envelope),
	)
	clear(secretBytes)
	if err != nil {
		return validation.ActivatedDemoHistoryBinding{}, ErrVerification
	}
	return activated, nil
}

func load(
	ctx context.Context,
	config Config,
) (*validation.StrictDemoHistoryManifestVerifier, []byte, error) {
	if ctx == nil || !validConfig(config) {
		return nil, nil, ErrInvalidConfiguration
	}
	envelope, err := readRegular(config.SignedEnvelopeFile, validation.MaxDemoHistorySignedEnvelopeBytes)
	if err != nil {
		return nil, nil, ErrSource
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(config.PublicKeyB64URL)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKey) != config.PublicKeyB64URL {
		return nil, nil, ErrInvalidConfiguration
	}
	verifier, err := validation.NewStrictDemoHistoryManifestVerifier(validation.DemoHistoryManifestVerifierConfig{
		Environment:                      validation.EnvironmentDemo,
		ExpectedPublicKey:                publicKey,
		ExpectedRunScope:                 config.RunScope,
		ExpectedImportID:                 config.ImportID,
		ExpectedClockAt:                  config.ClockAt,
		ExpectedImpactSourceHealthDigest: config.ImpactSourceHealthDigest,
	})
	if err != nil {
		return nil, nil, ErrInvalidConfiguration
	}
	return verifier, envelope, nil
}

func verificationInput(envelope []byte) validation.DemoHistoryVerificationInput {
	return validation.DemoHistoryVerificationInput{
		SignedManifestEnvelope: envelope,
		ImportedRowsDigest:     validation.PinnedDemoHistoryImportedRowsDigest,
		ImportedRecordCount:    validation.PinnedDemoHistoryDatasetRecordCount,
	}
}

func validConfig(config Config) bool {
	path := config.SignedEnvelopeFile
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		config.PublicKeyB64URL != "" && config.RunScope != "" && config.ImportID != "" &&
		!config.ClockAt.IsZero() && config.ClockAt.Equal(config.ClockAt.Round(0).UTC()) &&
		config.ImpactSourceHealthDigest == validation.PinnedDemoHistoryImpactSourceHealthDigest
}

func readRegular(path string, maximum int) ([]byte, error) {
	if maximum < 1 || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrSource
	}
	directory, name := filepath.Split(path)
	if name == "" {
		return nil, ErrSource
	}
	root, err := os.OpenRoot(filepath.Clean(directory))
	if err != nil {
		return nil, ErrSource
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > int64(maximum) {
		return nil, ErrSource
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, ErrSource
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, ErrSource
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(raw) < 1 || len(raw) > maximum {
		return nil, ErrSource
	}
	return raw, nil
}
