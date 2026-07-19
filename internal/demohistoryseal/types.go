// Package demohistoryseal creates and verifies one run-scoped, public
// demo-history authority bundle. The Ed25519 private key exists only in the
// sealing call's memory and is never returned or serialized.
package demohistoryseal

import (
	"bytes"
	"time"
)

const (
	AssertionsSchemaVersion = "demo-history-public-assertions-v1"
	EnvelopeFileName        = "signed-manifest.json"
	AssertionsFileName      = "public-assertions.json"
	MaxAssertionsBytes      = 8 << 10
)

type ErrorCode string

const (
	ErrorInput        ErrorCode = "demo_history_seal_input"
	ErrorDataset      ErrorCode = "demo_history_seal_dataset"
	ErrorRandom       ErrorCode = "demo_history_seal_random"
	ErrorCanonical    ErrorCode = "demo_history_seal_canonical"
	ErrorVerification ErrorCode = "demo_history_seal_verification"
	ErrorBundle       ErrorCode = "demo_history_seal_bundle"
	ErrorSource       ErrorCode = "demo_history_seal_source"
	ErrorCanceled     ErrorCode = "demo_history_seal_canceled"
)

type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil || e.Code == "" {
		return "demo history authority failed"
	}
	return "demo history authority failed: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }

// Bundle contains public material only: a signed envelope and the exact
// assertions required to reconstruct the strict verifier.
type Bundle struct {
	envelope   []byte
	assertions []byte
}

func (b Bundle) SignedEnvelope() []byte   { return bytes.Clone(b.envelope) }
func (b Bundle) PublicAssertions() []byte { return bytes.Clone(b.assertions) }

// Assertions is an immutable projection of the public run authority. It
// deliberately has no private-key, database, OpenAI, administrator, dispatcher,
// or executor field.
type Assertions struct {
	clockAt                     time.Time
	impactSourceHealthDigest    string
	importID                    string
	issuedAt                    time.Time
	manifestDigest              string
	manifestID                  string
	publicKeyB64URL             string
	runScope                    string
	signatureVerificationDigest string
}

func (a Assertions) ClockAt() time.Time                  { return a.clockAt }
func (a Assertions) ImpactSourceHealthDigest() string    { return a.impactSourceHealthDigest }
func (a Assertions) ImportID() string                    { return a.importID }
func (a Assertions) IssuedAt() time.Time                 { return a.issuedAt }
func (a Assertions) ManifestDigest() string              { return a.manifestDigest }
func (a Assertions) ManifestID() string                  { return a.manifestID }
func (a Assertions) PublicKeyB64URL() string             { return a.publicKeyB64URL }
func (a Assertions) RunScope() string                    { return a.runScope }
func (a Assertions) SignatureVerificationDigest() string { return a.signatureVerificationDigest }
