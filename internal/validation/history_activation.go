package validation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

const DemoHistoryRuntimeActivationLifetime = time.Hour

type DemoHistoryActivationConsumer string

const (
	DemoHistoryConsumerAnalysis   DemoHistoryActivationConsumer = "analysis"
	DemoHistoryConsumerValidation DemoHistoryActivationConsumer = "validation"
)

var (
	ErrDemoHistoryActivationInvalid  = errors.New("demo history runtime activation invalid")
	ErrDemoHistoryActivationRejected = errors.New("demo history runtime activation rejected")
	activationUUIDPattern            = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

const createDemoHistoryRuntimePairSQL = `
SELECT analysis_activation_id::text, validation_activation_id::text,
    activated_at, expires_at
FROM sentinelflow.create_demo_history_runtime_activation_pair_and_fence_000030(
    $1::bytea, $2::bytea, $3::uuid, $4::uuid, $5::uuid,
    $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15::timestamptz, $16::timestamptz, $17::timestamptz, $18::timestamptz,
    $19, $20
)`

const attachDemoHistoryRuntimeSQL = `
SELECT activation_id::text, activated_at, expires_at
FROM sentinelflow.attach_demo_history_runtime_activation_000030(
    $1::bytea, $2, $3::uuid, $4::uuid, $5::uuid,
    $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15::timestamptz, $16::timestamptz, $17::timestamptz, $18::timestamptz,
    $19, $20
)`

type DemoHistoryActivationDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ActivatedDemoHistoryBinding is a consumer-separated, process-local runtime
// capability. Its proof, plaintext secret, and HMAC receipt are private. A
// zero value or a value copied across consumers cannot expose a usable binding.
type ActivatedDemoHistoryBinding struct {
	activated    bool
	consumer     DemoHistoryActivationConsumer
	binding      VerifiedDemoHistoryBinding
	claims       DemoHistoryBindingClaims
	secret       [32]byte
	activationID string
	activatedAt  time.Time
	expiresAt    time.Time
	claimsDigest string
	receiptMAC   [sha256.Size]byte
}

// CreatedDemoHistoryActivationPair is emitted only after both consumer
// activations are created or exactly reattached in one database statement.
// It has no public constructor and does not expose either secret.
type CreatedDemoHistoryActivationPair struct {
	analysis   ActivatedDemoHistoryBinding
	validation ActivatedDemoHistoryBinding
}

func (p CreatedDemoHistoryActivationPair) String() string {
	if _, ok := p.Analysis(); !ok {
		return "demo-history-runtime-activation-pair[INVALID]"
	}
	return "demo-history-runtime-activation-pair[REDACTED]"
}

func (p CreatedDemoHistoryActivationPair) GoString() string { return p.String() }
func (p CreatedDemoHistoryActivationPair) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(p.String()))
}

func (p CreatedDemoHistoryActivationPair) Analysis() (ActivatedDemoHistoryBinding, bool) {
	if p.analysis.Consumer() != DemoHistoryConsumerAnalysis ||
		p.validation.Consumer() != DemoHistoryConsumerValidation {
		return ActivatedDemoHistoryBinding{}, false
	}
	return p.analysis, true
}

func (p CreatedDemoHistoryActivationPair) Validation() (ActivatedDemoHistoryBinding, bool) {
	if p.analysis.Consumer() != DemoHistoryConsumerAnalysis ||
		p.validation.Consumer() != DemoHistoryConsumerValidation {
		return ActivatedDemoHistoryBinding{}, false
	}
	return p.validation, true
}

// CreateDemoHistoryRuntimeActivationPair is for the one-shot demo activator
// role. Go always verifies the immutable signed proof, while the atomic DB
// wrapper derives issuance freshness through the owner-only 000022 verifier
// only when neither activation exists, then atomically commits phase-one
// NOLOGIN, password removal, and credential expiry for both bootstrap roles.
// The caller must execute the separate session finalizer and close immediately
// before this local receipt can make the one-shot command successful. If the
// immutable pair already exists, the database may return that exact pair while
// it remains unexpired, but only to a caller that still holds the separately
// bounded activator login stage; this function cannot reopen or renew it.
func CreateDemoHistoryRuntimeActivationPair(
	ctx context.Context,
	db DemoHistoryActivationDB,
	analysisSecret []byte,
	validationSecret []byte,
	verifier *StrictDemoHistoryManifestVerifier,
	input DemoHistoryVerificationInput,
) (CreatedDemoHistoryActivationPair, error) {
	if ctx == nil || db == nil || verifier == nil ||
		len(analysisSecret) != sha256.Size || len(validationSecret) != sha256.Size ||
		allZero(analysisSecret) || allZero(validationSecret) ||
		hmac.Equal(analysisSecret, validationSecret) {
		return CreatedDemoHistoryActivationPair{}, ErrDemoHistoryActivationInvalid
	}
	binding, err := verifier.verifyDemoHistory(ctx, input, false)
	if err != nil {
		return CreatedDemoHistoryActivationPair{}, ErrDemoHistoryActivationRejected
	}
	claims, ok := binding.Claims()
	if !ok {
		return CreatedDemoHistoryActivationPair{}, ErrDemoHistoryActivationRejected
	}
	claimsDigest, err := demoHistoryActivationClaimsDigest(claims)
	if err != nil {
		return CreatedDemoHistoryActivationPair{}, ErrDemoHistoryActivationRejected
	}
	arguments := demoHistoryActivationPairArguments(
		analysisSecret, validationSecret, claims, claimsDigest,
	)
	var analysisID, validationID string
	var activatedAt, expiresAt time.Time
	if err := db.QueryRow(ctx, createDemoHistoryRuntimePairSQL, arguments...).Scan(
		&analysisID, &validationID, &activatedAt, &expiresAt,
	); err != nil {
		return CreatedDemoHistoryActivationPair{}, ErrDemoHistoryActivationRejected
	}
	analysis, err := newActivatedDemoHistoryBinding(
		DemoHistoryConsumerAnalysis, analysisSecret, binding, claims, claimsDigest,
		analysisID, activatedAt, expiresAt,
	)
	if err != nil {
		return CreatedDemoHistoryActivationPair{}, err
	}
	validationBinding, err := newActivatedDemoHistoryBinding(
		DemoHistoryConsumerValidation, validationSecret, binding, claims, claimsDigest,
		validationID, activatedAt, expiresAt,
	)
	if err != nil {
		return CreatedDemoHistoryActivationPair{}, err
	}
	return CreatedDemoHistoryActivationPair{analysis: analysis, validation: validationBinding}, nil
}

// AttachDemoHistoryRuntimeActivation is for ordinary long-running workers.
// It can attach only the exact secret, consumer and claims to a pre-existing,
// unexpired activation. The attach role cannot create activation evidence.
func AttachDemoHistoryRuntimeActivation(
	ctx context.Context,
	db DemoHistoryActivationDB,
	consumer DemoHistoryActivationConsumer,
	secret []byte,
	verifier *StrictDemoHistoryManifestVerifier,
	input DemoHistoryVerificationInput,
) (ActivatedDemoHistoryBinding, error) {
	return promoteDemoHistoryRuntime(
		ctx, db, consumer, secret, verifier, input,
	)
}

func promoteDemoHistoryRuntime(
	ctx context.Context,
	db DemoHistoryActivationDB,
	consumer DemoHistoryActivationConsumer,
	secret []byte,
	verifier *StrictDemoHistoryManifestVerifier,
	input DemoHistoryVerificationInput,
) (ActivatedDemoHistoryBinding, error) {
	if ctx == nil || db == nil || verifier == nil || !validActivationConsumer(consumer) ||
		len(secret) != sha256.Size || allZero(secret) {
		return ActivatedDemoHistoryBinding{}, ErrDemoHistoryActivationInvalid
	}
	// The binding remains package-local until the database activation receipt is
	// scanned, checked, HMAC-bound, and reverified below.
	binding, err := verifier.verifyDemoHistory(ctx, input, false)
	if err != nil {
		return ActivatedDemoHistoryBinding{}, ErrDemoHistoryActivationRejected
	}
	claims, ok := binding.Claims()
	if !ok {
		return ActivatedDemoHistoryBinding{}, ErrDemoHistoryActivationRejected
	}
	claimsDigest, err := demoHistoryActivationClaimsDigest(claims)
	if err != nil {
		return ActivatedDemoHistoryBinding{}, ErrDemoHistoryActivationRejected
	}
	arguments := demoHistoryActivationArguments(secret, consumer, claims, claimsDigest)
	var activationID string
	var activatedAt, expiresAt time.Time
	if err := db.QueryRow(ctx, attachDemoHistoryRuntimeSQL, arguments...).Scan(
		&activationID, &activatedAt, &expiresAt,
	); err != nil {
		return ActivatedDemoHistoryBinding{}, ErrDemoHistoryActivationRejected
	}
	return newActivatedDemoHistoryBinding(
		consumer, secret, binding, claims, claimsDigest, activationID, activatedAt, expiresAt,
	)
}

func newActivatedDemoHistoryBinding(
	consumer DemoHistoryActivationConsumer,
	secret []byte,
	binding VerifiedDemoHistoryBinding,
	claims DemoHistoryBindingClaims,
	claimsDigest string,
	activationID string,
	activatedAt time.Time,
	expiresAt time.Time,
) (ActivatedDemoHistoryBinding, error) {
	activatedAt = activatedAt.Round(0).UTC()
	expiresAt = expiresAt.Round(0).UTC()
	if !validActivationConsumer(consumer) || len(secret) != sha256.Size || allZero(secret) ||
		!activationUUIDPattern.MatchString(activationID) || !validSnapshotTime(activatedAt) ||
		!validSnapshotTime(expiresAt) || !expiresAt.Equal(activatedAt.Add(DemoHistoryRuntimeActivationLifetime)) {
		return ActivatedDemoHistoryBinding{}, ErrDemoHistoryActivationRejected
	}
	result := ActivatedDemoHistoryBinding{
		activated: true, consumer: consumer, binding: binding, claims: claims,
		activationID: activationID, activatedAt: activatedAt, expiresAt: expiresAt,
		claimsDigest: claimsDigest,
	}
	copy(result.secret[:], secret)
	payload, err := result.receiptPayload()
	if err != nil {
		return ActivatedDemoHistoryBinding{}, ErrDemoHistoryActivationRejected
	}
	result.receiptMAC = hmacSHA256(result.secret[:], payload)
	if !result.valid() {
		return ActivatedDemoHistoryBinding{}, ErrDemoHistoryActivationRejected
	}
	return result, nil
}

func (a ActivatedDemoHistoryBinding) Binding() (VerifiedDemoHistoryBinding, bool) {
	if !a.valid() {
		return VerifiedDemoHistoryBinding{}, false
	}
	return a.binding, true
}

func (a ActivatedDemoHistoryBinding) Claims() (DemoHistoryBindingClaims, bool) {
	if !a.valid() {
		return DemoHistoryBindingClaims{}, false
	}
	return a.claims, true
}

func (a ActivatedDemoHistoryBinding) Consumer() DemoHistoryActivationConsumer {
	if !a.valid() {
		return ""
	}
	return a.consumer
}

// ClaimsDigest exposes only the versioned public-claims digest after the
// private receipt has been revalidated. It never exposes capability bytes.
func (a ActivatedDemoHistoryBinding) ClaimsDigest() (string, bool) {
	if !a.valid() {
		return "", false
	}
	return a.claimsDigest, true
}

// ActivationSecret returns a defensive in-memory copy for the narrow prepare
// function call. Formatting methods never reveal it and the database stores
// only its SHA-256 digest.
func (a ActivatedDemoHistoryBinding) ActivationSecret() ([]byte, bool) {
	if !a.valid() {
		return nil, false
	}
	return append([]byte(nil), a.secret[:]...), true
}

func (a ActivatedDemoHistoryBinding) String() string {
	if !a.valid() {
		return "demo-history-runtime-activation[INVALID]"
	}
	return "demo-history-runtime-activation[REDACTED]"
}

func (a ActivatedDemoHistoryBinding) GoString() string { return a.String() }
func (a ActivatedDemoHistoryBinding) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(a.String()))
}

func (a ActivatedDemoHistoryBinding) valid() bool {
	if !a.activated || !validActivationConsumer(a.consumer) ||
		!activationUUIDPattern.MatchString(a.activationID) || allZero(a.secret[:]) ||
		!validSnapshotTime(a.activatedAt) || !validSnapshotTime(a.expiresAt) ||
		!a.expiresAt.Equal(a.activatedAt.Add(DemoHistoryRuntimeActivationLifetime)) {
		return false
	}
	currentClaims, ok := a.binding.Claims()
	if !ok || currentClaims != a.claims {
		return false
	}
	claimsDigest, err := demoHistoryActivationClaimsDigest(a.claims)
	if err != nil || claimsDigest != a.claimsDigest {
		return false
	}
	payload, err := a.receiptPayload()
	if err != nil {
		return false
	}
	want := hmacSHA256(a.secret[:], payload)
	return hmac.Equal(a.receiptMAC[:], want[:])
}

func (a ActivatedDemoHistoryBinding) receiptPayload() ([]byte, error) {
	secretDigest := sha256.Sum256(a.secret[:])
	return marshalSnapshotJCS(struct {
		ActivationID  string `json:"activation_id"`
		ActivatedAt   string `json:"activated_at"`
		ClaimsDigest  string `json:"claims_digest"`
		Consumer      string `json:"consumer"`
		ExpiresAt     string `json:"expires_at"`
		SchemaVersion string `json:"schema_version"`
		SecretDigest  string `json:"secret_digest"`
	}{
		ActivationID:  a.activationID,
		ActivatedAt:   historyTime(a.activatedAt),
		ClaimsDigest:  a.claimsDigest,
		Consumer:      string(a.consumer),
		ExpiresAt:     historyTime(a.expiresAt),
		SchemaVersion: "demo-history-runtime-activation-receipt-v1",
		SecretDigest:  "sha256:" + hex.EncodeToString(secretDigest[:]),
	})
}

func demoHistoryActivationClaimsDigest(value DemoHistoryBindingClaims) (string, error) {
	canonical, err := marshalSnapshotJCS(struct {
		ClockAt                     string `json:"clock_at"`
		CoverageEnd                 string `json:"coverage_end"`
		CoverageStart               string `json:"coverage_start"`
		DatasetID                   string `json:"dataset_id"`
		DatasetLocator              string `json:"dataset_locator"`
		DatasetRecordCount          uint64 `json:"dataset_record_count"`
		DatasetSchemaVersion        string `json:"dataset_schema_version"`
		DatasetDigest               string `json:"dataset_digest"`
		FixtureOnly                 bool   `json:"fixture_only"`
		ImpactSourceHealthDigest    string `json:"impact_source_health_digest"`
		ImportedRowsDigest          string `json:"imported_rows_digest"`
		ImportID                    string `json:"import_id"`
		IssuedAt                    string `json:"issued_at"`
		ManifestDigest              string `json:"manifest_digest"`
		ManifestID                  string `json:"manifest_id"`
		ManifestSourceHealthDigest  string `json:"manifest_source_health_digest"`
		PathCatalogVersion          string `json:"path_catalog_version"`
		Profile                     string `json:"profile"`
		PublicKeyDigest             string `json:"public_key_digest"`
		RawFileDigest               string `json:"raw_file_digest"`
		RunScopeDigest              string `json:"run_scope_digest"`
		SchemaVersion               string `json:"schema_version"`
		SignatureVerificationDigest string `json:"signature_verification_digest"`
		VerificationEnvironment     string `json:"verification_environment"`
	}{
		ClockAt: historyTime(value.ClockAt), CoverageEnd: historyTime(value.CoverageEnd),
		CoverageStart: historyTime(value.CoverageStart), DatasetID: value.DatasetID,
		DatasetLocator: value.DatasetLocator, DatasetRecordCount: value.DatasetRecordCount,
		DatasetSchemaVersion: value.DatasetSchemaVersion, DatasetDigest: value.DatasetDigest,
		FixtureOnly: value.FixtureOnly, ImpactSourceHealthDigest: value.ImpactSourceHealthDigest,
		ImportedRowsDigest: value.ImportedRowsDigest, ImportID: value.ImportID,
		IssuedAt: historyTime(value.IssuedAt), ManifestDigest: value.ManifestDigest,
		ManifestID: value.ManifestID, ManifestSourceHealthDigest: value.ManifestSourceHealthDigest,
		PathCatalogVersion: value.PathCatalogVersion, Profile: value.Profile,
		PublicKeyDigest: value.PublicKeyDigest, RawFileDigest: value.RawFileDigest,
		RunScopeDigest: value.RunScopeDigest, SchemaVersion: value.SchemaVersion,
		SignatureVerificationDigest: value.SignatureVerificationDigest,
		VerificationEnvironment:     string(value.VerificationEnvironment),
	})
	if err != nil {
		return "", err
	}
	return sha256Digest(canonical), nil
}

func demoHistoryActivationArguments(
	secret []byte,
	consumer DemoHistoryActivationConsumer,
	value DemoHistoryBindingClaims,
	claimsDigest string,
) []any {
	return []any{
		append([]byte(nil), secret...), string(consumer),
		value.ImportID, value.ManifestID, value.DatasetID,
		value.RawFileDigest, value.DatasetDigest, value.ImportedRowsDigest,
		value.DatasetRecordCount, value.ManifestSourceHealthDigest, value.ManifestDigest,
		value.RunScopeDigest, value.PublicKeyDigest, value.SignatureVerificationDigest,
		value.ClockAt.Round(0).UTC(), value.IssuedAt.Round(0).UTC(),
		value.CoverageStart.Round(0).UTC(), value.CoverageEnd.Round(0).UTC(),
		value.ImpactSourceHealthDigest, claimsDigest,
	}
}

func demoHistoryActivationPairArguments(
	analysisSecret []byte,
	validationSecret []byte,
	value DemoHistoryBindingClaims,
	claimsDigest string,
) []any {
	arguments := demoHistoryActivationArguments(
		analysisSecret, DemoHistoryConsumerAnalysis, value, claimsDigest,
	)
	// The pair SQL has no consumer parameter and takes both capabilities first.
	return append(
		[]any{append([]byte(nil), analysisSecret...), append([]byte(nil), validationSecret...)},
		arguments[2:]...,
	)
}

func validActivationConsumer(value DemoHistoryActivationConsumer) bool {
	return value == DemoHistoryConsumerAnalysis || value == DemoHistoryConsumerValidation
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

func hmacSHA256(key, payload []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}
