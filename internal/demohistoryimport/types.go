package demohistoryimport

import (
	"time"

	"github.com/devwooops/sentinelflow/internal/validation"
)

type Disposition string

const (
	DispositionApplied    Disposition = "applied"
	DispositionHistorical Disposition = "historical"
)

// Result is the immutable, secret-free durable ledger projection. Application
// clock_at and real-security issued_at remain distinct.
type Result struct {
	disposition                 Disposition
	importID                    string
	manifestID                  string
	datasetID                   string
	rawFileByteSHA256           string
	manifestDatasetJCSDigest    string
	importedRowsJCSDigest       string
	importedRecordCount         uint64
	sourceHealthJCSDigest       string
	manifestDigest              string
	runScopeDigest              string
	publicKeyDigest             string
	signatureVerificationDigest string
	clockAt                     time.Time
	issuedAt                    time.Time
	coverageStart               time.Time
	coverageEnd                 time.Time
	status                      string
	failureCode                 string
	attemptCount                int
	gatewayRecordCount          int
	authRecordCount             int
	sourceCoverageCount         int
	completedAt                 time.Time
	verifiedBinding             validation.VerifiedDemoHistoryBinding
	recoveryRowsValid           bool
	recoveryGatewayRows         int
	recoveryAuthRows            int
	recoveryCoverageRows        int
}

func (r Result) Disposition() Disposition            { return r.disposition }
func (r Result) ImportID() string                    { return r.importID }
func (r Result) ManifestID() string                  { return r.manifestID }
func (r Result) DatasetID() string                   { return r.datasetID }
func (r Result) RawFileByteSHA256() string           { return r.rawFileByteSHA256 }
func (r Result) ManifestDatasetJCSDigest() string    { return r.manifestDatasetJCSDigest }
func (r Result) ImportedRowsJCSDigest() string       { return r.importedRowsJCSDigest }
func (r Result) ImportedRecordCount() uint64         { return r.importedRecordCount }
func (r Result) SourceHealthJCSDigest() string       { return r.sourceHealthJCSDigest }
func (r Result) ManifestDigest() string              { return r.manifestDigest }
func (r Result) RunScopeDigest() string              { return r.runScopeDigest }
func (r Result) PublicKeyDigest() string             { return r.publicKeyDigest }
func (r Result) SignatureVerificationDigest() string { return r.signatureVerificationDigest }
func (r Result) ClockAt() time.Time                  { return r.clockAt }
func (r Result) IssuedAt() time.Time                 { return r.issuedAt }
func (r Result) CoverageStart() time.Time            { return r.coverageStart }
func (r Result) CoverageEnd() time.Time              { return r.coverageEnd }
func (r Result) Status() string                      { return r.status }
func (r Result) FailureCode() string                 { return r.failureCode }
func (r Result) AttemptCount() int                   { return r.attemptCount }
func (r Result) GatewayRecordCount() int             { return r.gatewayRecordCount }
func (r Result) AuthRecordCount() int                { return r.authRecordCount }
func (r Result) SourceCoverageCount() int            { return r.sourceCoverageCount }
func (r Result) CompletedAt() time.Time              { return r.completedAt }

// VerifiedBinding returns the fresh opaque binding minted by the injected
// StrictDemoHistoryManifestVerifier for this import call. The durable ledger
// is never a substitute for this sealed value.
func (r Result) VerifiedBinding() validation.VerifiedDemoHistoryBinding {
	return r.verifiedBinding
}

type manifestClaims struct {
	manifestID                  string
	importID                    string
	manifestDigest              string
	runScopeDigest              string
	publicKeyDigest             string
	signatureVerificationDigest string
	clockAt                     time.Time
	issuedAt                    time.Time
	coverageStart               time.Time
	coverageEnd                 time.Time
	verifiedBinding             validation.VerifiedDemoHistoryBinding
}
