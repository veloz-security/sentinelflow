package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
)

type fixture struct {
	issuer         capability.CapabilityIssuer
	capVerifier    capability.CapabilityVerifier
	resultSigner   capability.ResultSigner
	resultVerifier capability.ResultVerifier
	signed         capability.SignedCapability
	verified       capability.VerifiedCapability
	received       time.Time
	deadline       time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dispatchKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	resultKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	issuer, err := capability.NewCapabilityIssuer("dispatch-test-v1", dispatchKey)
	if err != nil {
		t.Fatal(err)
	}
	capVerifier, err := capability.NewCapabilityVerifier("dispatch-test-v1", "executor-demo", dispatchKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	resultSigner, err := capability.NewResultSigner("result-test-v1", "executor-demo", resultKey)
	if err != nil {
		t.Fatal(err)
	}
	resultVerifier, err := capability.NewResultVerifier("result-test-v1", "executor-demo", resultKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 7, 18, 6, 0, 0, 0, time.UTC)
	common := capability.Common{
		CapabilityID:             "019b0000-0000-7000-8000-000000000101",
		JobID:                    "019b0000-0000-7000-8000-000000000102",
		ActionID:                 "019b0000-0000-7000-8000-000000000103",
		PolicyID:                 "019b0000-0000-7000-8000-000000000104",
		PolicyVersion:            1,
		TargetIPv4:               "203.0.113.20",
		EvidenceSnapshotDigest:   testDigest("evidence"),
		ValidationSnapshotDigest: testDigest("validation"),
		AuthorizationDigest:      testDigest("authorization"),
		ActorID:                  "dispatcher",
		ReasonDigest:             testDigest("reason"),
		OwnedSchemaDigest:        testDigest("owned-schema"),
		IssuedAt:                 issued,
		NotBefore:                issued,
		ExpiresAt:                issued.Add(time.Minute),
		Nonce:                    base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 16)),
	}
	checked, err := capability.CheckAdd(capability.Add{
		Common:           common,
		CanonicalCommand: []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := issuer.Sign(checked)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := capVerifier.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{
		issuer: issuer, capVerifier: capVerifier, resultSigner: resultSigner, resultVerifier: resultVerifier,
		signed: signed, verified: verified, received: issued.Add(time.Second), deadline: issued.Add(2 * time.Second),
	}
}

func (f fixture) options(path string) Options {
	return Options{Path: path, CapabilityVerifier: f.capVerifier, ResultVerifier: f.resultVerifier}
}

func (f fixture) alternate(t *testing.T) capability.SignedCapability {
	t.Helper()
	value := f.verified.Value()
	common := capability.Common{
		CapabilityID: value.CapabilityID, JobID: value.JobID, ActionID: value.ActionID,
		PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion, TargetIPv4: value.TargetIPv4,
		EvidenceSnapshotDigest: value.EvidenceSnapshotDigest, ValidationSnapshotDigest: value.ValidationSnapshotDigest,
		AuthorizationDigest: value.AuthorizationDigest, ActorID: value.ActorID, ReasonDigest: value.ReasonDigest,
		OwnedSchemaDigest: value.OwnedSchemaDigest, IssuedAt: value.IssuedAt, NotBefore: value.NotBefore,
		ExpiresAt: value.ExpiresAt, Nonce: value.Nonce,
	}
	checked, err := capability.CheckAdd(capability.Add{Common: common, CanonicalCommand: []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 20m }\n")})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.issuer.Sign(checked)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (f fixture) signedResult(t *testing.T, sequence uint64, class capability.Classification, started time.Time, signer func(capability.CheckedResult) (capability.SignedResult, error)) capability.SignedResult {
	t.Helper()
	exit := capability.NFTExitSuccess
	errorCode := capability.ResultErrorNone
	ttl := uint64(1700)
	if class == capability.ClassificationRecoveredActive {
		exit = capability.NFTExitNotInvoked
	}
	checked, err := capability.CheckResult(capability.Result{
		ResultID:            "019b0000-0000-7000-8000-000000000105",
		CapabilityID:        f.verified.Value().CapabilityID,
		CapabilityDigest:    f.verified.Digest(),
		Operation:           capability.OperationAdd,
		ActionID:            f.verified.Value().ActionID,
		ArtifactDigest:      f.verified.Value().ArtifactDigest,
		TargetIPv4:          f.verified.Value().TargetIPv4,
		Classification:      class,
		NFTExitClass:        &exit,
		ReadbackState:       capability.ReadbackActive,
		ElementHandle:       nil,
		RemainingTTLSeconds: &ttl,
		OwnedSchemaDigest:   f.verified.Value().OwnedSchemaDigest,
		StartedAt:           started, CompletedAt: started.Add(100 * time.Millisecond),
		JournalSequence: sequence, ErrorCode: errorCode,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer(checked)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func journalPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "executor.journal")
}

func assertCode(t *testing.T, err error, expected ErrorCode) {
	t.Helper()
	var journalError *Error
	if !errors.As(err, &journalError) || journalError.Code != expected {
		t.Fatalf("unexpected error: got %v want %s", err, expected)
	}
}

func writeJournal(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readJournal(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
