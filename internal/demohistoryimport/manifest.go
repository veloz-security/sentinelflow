package demohistoryimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/devwooops/sentinelflow/internal/demohistory"
	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/validation"
)

type manifestEnvelopeWire struct {
	SchemaVersion     string       `json:"schema_version"`
	FixtureOnly       bool         `json:"fixture_only"`
	KeyScope          string       `json:"key_scope"`
	Manifest          manifestWire `json:"manifest"`
	ManifestJCSB64URL string       `json:"manifest_jcs_b64url"`
	ManifestDigest    string       `json:"manifest_digest"`
	SignatureB64URL   string       `json:"signature_b64url"`
	PublicKeyB64URL   string       `json:"public_key_b64url"`
}

type manifestWire struct {
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

func verifyManifest(
	ctx context.Context,
	verifier validation.DemoHistoryManifestVerifier,
	envelope []byte,
	dataset demohistory.Dataset,
) (manifestClaims, error) {
	return verifyManifestMode(ctx, verifier, envelope, dataset, true)
}

func verifyManifestImmutable(
	ctx context.Context,
	verifier validation.DemoHistoryManifestVerifier,
	envelope []byte,
	dataset demohistory.Dataset,
) (manifestClaims, error) {
	return verifyManifestMode(ctx, verifier, envelope, dataset, false)
}

func verifyManifestMode(
	ctx context.Context,
	verifier validation.DemoHistoryManifestVerifier,
	envelope []byte,
	dataset demohistory.Dataset,
	requireFresh bool,
) (manifestClaims, error) {
	if verifier == nil || len(envelope) == 0 || len(envelope) > validation.MaxDemoHistorySignedEnvelopeBytes {
		return manifestClaims{}, reject(ErrorManifest)
	}
	frozen := append([]byte(nil), envelope...)
	input := validation.DemoHistoryVerificationInput{
		SignedManifestEnvelope: frozen,
		ImportedRowsDigest:     dataset.ImportedRowsJCSDigest(),
		ImportedRecordCount:    dataset.RecordCount(),
	}
	var binding validation.VerifiedDemoHistoryBinding
	var err error
	if requireFresh {
		binding, err = verifier.VerifyDemoHistory(ctx, input)
	} else {
		// Recovery authority is deliberately limited to the validation package's
		// concrete strict verifier. An exported-method interface here would let an
		// arbitrary implementation claim that stale bytes were verified.
		immutable, ok := verifier.(*validation.StrictDemoHistoryManifestVerifier)
		if !ok {
			return manifestClaims{}, reject(ErrorConfiguration)
		}
		err = immutable.VerifyDemoHistoryImmutable(ctx, input)
	}
	if err != nil {
		if contextError(ctx) != nil {
			return manifestClaims{}, reject(ErrorCanceled)
		}
		return manifestClaims{}, reject(ErrorManifest)
	}

	decoder := json.NewDecoder(bytes.NewReader(frozen))
	decoder.DisallowUnknownFields()
	var wire manifestEnvelopeWire
	if err := decoder.Decode(&wire); err != nil {
		return manifestClaims{}, reject(ErrorManifest)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return manifestClaims{}, reject(ErrorManifest)
	}
	clockAt, err := parseTime(wire.Manifest.ClockAt)
	if err != nil {
		return manifestClaims{}, err
	}
	issuedAt, err := parseTime(wire.Manifest.IssuedAt)
	if err != nil {
		return manifestClaims{}, err
	}
	coverageStart, err := parseTime(wire.Manifest.CoverageStart)
	if err != nil {
		return manifestClaims{}, err
	}
	coverageEnd, err := parseTime(wire.Manifest.CoverageEnd)
	if err != nil {
		return manifestClaims{}, err
	}
	sealedCutoff := binding.HistoryCutoff().At()
	runScopeDigest, publicKeyDigest, signatureVerificationDigest, err := verificationProof(wire)
	if err != nil {
		return manifestClaims{}, err
	}
	if (requireFresh && (sealedCutoff.IsZero() || !sealedCutoff.Equal(clockAt))) ||
		wire.SchemaVersion != validation.DemoHistorySignedManifestSchemaVersion ||
		wire.Manifest.SchemaVersion != validation.DemoHistoryManifestSchemaVersion ||
		wire.Manifest.Profile != validation.DemoHistoryProfile ||
		wire.Manifest.DatasetID != dataset.DatasetID() ||
		wire.Manifest.DatasetSchema != dataset.SchemaVersion() ||
		wire.Manifest.DatasetDigest != dataset.ManifestDatasetJCSDigest() ||
		wire.Manifest.DatasetRecordCount != dataset.RecordCount() ||
		wire.Manifest.PathCatalogVersion != dataset.PathCatalogVersion() ||
		wire.Manifest.SourceHealthDigest != dataset.SourceHealthJCSDigest() ||
		!coverageStart.Equal(dataset.CoverageStart()) ||
		!coverageEnd.Equal(dataset.CoverageEnd()) || !clockAt.Equal(coverageEnd) ||
		issuedAt.Before(coverageEnd) {
		return manifestClaims{}, reject(ErrorBinding)
	}
	return manifestClaims{
		manifestID: wire.Manifest.ManifestID, importID: wire.Manifest.ImportID,
		manifestDigest: wire.ManifestDigest, runScopeDigest: runScopeDigest,
		publicKeyDigest:             publicKeyDigest,
		signatureVerificationDigest: signatureVerificationDigest,
		clockAt:                     clockAt, issuedAt: issuedAt,
		coverageStart: coverageStart, coverageEnd: coverageEnd,
		verifiedBinding: binding,
	}, nil
}

func parseTime(value string) (time.Time, error) {
	timestamp, err := events.ParseTimestamp(value)
	if err != nil || !timestamp.Valid() {
		return time.Time{}, reject(ErrorManifest)
	}
	return timestamp.Time().Round(0).UTC(), nil
}

func verificationProof(wire manifestEnvelopeWire) (string, string, string, error) {
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(wire.PublicKeyB64URL)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", "", "", reject(ErrorManifest)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(wire.SignatureB64URL)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return "", "", "", reject(ErrorManifest)
	}
	runScopeDigest := digest([]byte(wire.KeyScope))
	publicKeyDigest := digest(publicKey)
	proof := struct {
		Domain          string `json:"domain"`
		ManifestDigest  string `json:"manifest_digest"`
		PublicKeyDigest string `json:"public_key_digest"`
		RunScopeDigest  string `json:"run_scope_digest"`
		SchemaVersion   string `json:"schema_version"`
		SignatureDigest string `json:"signature_digest"`
	}{
		Domain:         validation.DemoHistorySignatureDomain,
		ManifestDigest: wire.ManifestDigest, PublicKeyDigest: publicKeyDigest,
		RunScopeDigest:  runScopeDigest,
		SchemaVersion:   "demo-history-signature-verification-v1",
		SignatureDigest: digest(signature),
	}
	canonical, err := json.Marshal(proof)
	if err != nil {
		return "", "", "", reject(ErrorManifest)
	}
	return runScopeDigest, publicKeyDigest, digest(canonical), nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
