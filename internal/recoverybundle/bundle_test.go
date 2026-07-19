package recoverybundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
	"golang.org/x/sys/unix"
)

func TestSealVerifyAndJournalRestoreAreByteExact(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	journalBytes := []byte("SFJNLv1\n\x01\x01\x00\x00opaque-started-record-with-signature-bytes\x00\xff")
	fixture := newBundleFixture(t, privateKey, journalBytes)

	verified, err := Verify(fixture.bundle, publicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Manifest.SchemaVersion != SchemaVersion ||
		verified.Manifest.LatestMigration != 23 || verified.Manifest.MigrationCount != 3 {
		t.Fatalf("unexpected manifest: %#v", verified.Manifest)
	}
	bundledJournal, err := os.ReadFile(filepath.Join(fixture.bundle, filepath.FromSlash(JournalPath)))
	if err != nil || !bytes.Equal(bundledJournal, journalBytes) {
		t.Fatalf("bundle changed opaque journal bytes: %v", err)
	}

	destinationDirectory := privateDirectory(t)
	destination := filepath.Join(destinationDirectory, "replay.json")
	staged, err := StageJournal(fixture.bundle, publicKey, destination)
	if err != nil {
		t.Fatalf("stage journal: %v", err)
	}
	if staged != stagedJournalPath(destination) {
		t.Fatalf("unexpected staged path: %q", staged)
	}
	stagedBytes, err := os.ReadFile(staged)
	if err != nil || !bytes.Equal(stagedBytes, journalBytes) {
		t.Fatalf("staging changed opaque journal bytes: %v", err)
	}
	if info, statErr := os.Stat(staged); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("staged mode changed: %v %#o", statErr, info.Mode().Perm())
	}
	if err := CommitJournal(fixture.bundle, publicKey, destination); err != nil {
		t.Fatalf("commit journal: %v", err)
	}
	restored, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(restored, journalBytes) {
		t.Fatalf("restore changed opaque journal bytes: %v", err)
	}
	if info, statErr := os.Stat(destination); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored mode changed: %v %#o", statErr, info.Mode().Perm())
	}
	if _, err := StageJournal(fixture.bundle, publicKey, destination); !errors.Is(err, &Error{code: CodeExists}) {
		t.Fatalf("existing journal was not rejected: %v", err)
	}
}

func TestEmptyJournalIsPreserved(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	fixture := newBundleFixture(t, privateKey, nil)
	verified, err := Verify(fixture.bundle, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	entry := verified.Manifest.Files[indexOfPath(JournalPath)]
	if entry.Size != 0 || entry.SHA256 != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty journal identity changed: %#v", entry)
	}
	destination := filepath.Join(privateDirectory(t), "replay.json")
	if _, err := PrepareRestore(fixture.bundle, publicKey, destination, "pg17:1:2:empty_journal"); err != nil {
		t.Fatal(err)
	}
	if _, err := MarkDatabaseRestored(fixture.bundle, publicKey, destination, "pg17:1:2:empty_journal"); err != nil {
		t.Fatal(err)
	}
	if _, err := CommitPreparedJournal(fixture.bundle, publicKey, destination, "pg17:1:2:empty_journal"); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(destination); err != nil || len(contents) != 0 {
		t.Fatalf("empty journal restore changed bytes: %v %x", err, contents)
	}
}

func TestSealRejectsJournalLockedByRunningExecutor(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	parent := privateDirectory(t)
	staging := filepath.Join(parent, "stage")
	prepareStaging(t, staging)
	journalPath := filepath.Join(parent, "replay.json")
	writeFile(t, journalPath, []byte("journal"), 0o600)
	locked, err := os.Open(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	if err := unix.Flock(int(locked.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	err = Seal(SealOptions{
		StagingDir: staging, OutputDir: filepath.Join(parent, "bundle"), Journal: journalPath,
		PrivateKey: privateKey, Now: time.Now(),
	})
	if !errors.Is(err, &Error{code: CodeFilesystem}) {
		t.Fatalf("locked executor journal was copied: %v", err)
	}
}

func TestSealCopiesFromInheritedSessionJournalDescriptor(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	parent := privateDirectory(t)
	staging := filepath.Join(parent, "stage")
	prepareStaging(t, staging)
	journalPath := filepath.Join(parent, "replay.json")
	want := []byte("opaque-session-journal")
	writeFile(t, journalPath, want, 0o600)
	locked, err := os.Open(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	if err := unix.Flock(int(locked.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(parent, "bundle")
	if err := Seal(SealOptions{
		StagingDir: staging, OutputDir: bundle, Journal: journalPath,
		JournalFD: int(locked.Fd()), PrivateKey: privateKey, Now: time.Now(),
	}); err != nil {
		t.Fatalf("seal with inherited journal descriptor: %v", err)
	}
	if _, err := Verify(bundle, publicKey); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(bundle, filepath.FromSlash(JournalPath)))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("journal copy = %q err=%v", got, err)
	}
}

func TestBundleTamperMissingExtraAndLinksFailClosed(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture bundleFixture)
		code   ErrorCode
	}{
		{
			name: "tampered journal",
			mutate: func(t *testing.T, fixture bundleFixture) {
				t.Helper()
				path := filepath.Join(fixture.bundle, filepath.FromSlash(JournalPath))
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write([]byte("tamper")); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeIntegrity,
		},
		{
			name: "torn journal",
			mutate: func(t *testing.T, fixture bundleFixture) {
				t.Helper()
				path := filepath.Join(fixture.bundle, filepath.FromSlash(JournalPath))
				if err := os.Truncate(path, 3); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeIntegrity,
		},
		{
			name: "missing metadata",
			mutate: func(t *testing.T, fixture bundleFixture) {
				t.Helper()
				if err := os.Remove(filepath.Join(fixture.bundle, filepath.FromSlash(MigrationsPath))); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeContents,
		},
		{
			name: "extra private key",
			mutate: func(t *testing.T, fixture bundleFixture) {
				t.Helper()
				writeFile(t, filepath.Join(fixture.bundle, "executor", "executor-result-private.pem"), []byte("PRIVATE KEY MUST NEVER BE BUNDLED\n"), 0o600)
			},
			code: CodeContents,
		},
		{
			name: "payload symlink",
			mutate: func(t *testing.T, fixture bundleFixture) {
				t.Helper()
				path := filepath.Join(fixture.bundle, filepath.FromSlash(SchemaPath))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(fixture.bundle, filepath.FromSlash(MigrationsPath)), path); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeFilesystem,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBundleFixture(t, privateKey, []byte("complete-started-frame-and-terminal-frame"))
			test.mutate(t, fixture)
			if _, err := Verify(fixture.bundle, publicKey); !errors.Is(err, &Error{code: test.code}) {
				t.Fatalf("error=%v want code=%s", err, test.code)
			}
		})
	}
}

func TestSealRejectsUnlistedKeyMaterialAndExistingOutput(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	parent := privateDirectory(t)
	staging := filepath.Join(parent, "stage")
	prepareStaging(t, staging)
	writeFile(t, filepath.Join(staging, "signing-private.pem"), []byte("PRIVATE KEY\n"), 0o600)
	journal := filepath.Join(parent, "replay.json")
	writeFile(t, journal, []byte("journal"), 0o600)
	err := Seal(SealOptions{
		StagingDir: staging, OutputDir: filepath.Join(parent, "bundle"), Journal: journal,
		PrivateKey: privateKey, Now: time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, &Error{code: CodeContents}) {
		t.Fatalf("unlisted private key accepted: %v", err)
	}

	staging = filepath.Join(parent, "stage-two")
	prepareStaging(t, staging)
	output := filepath.Join(parent, "existing")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	err = Seal(SealOptions{StagingDir: staging, OutputDir: output, Journal: journal, PrivateKey: privateKey, Now: time.Now()})
	if !errors.Is(err, &Error{code: CodeExists}) {
		t.Fatalf("existing output accepted: %v", err)
	}
}

func TestWrongKeyManifestTraversalAndStageSwapFailClosed(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	fixture := newBundleFixture(t, privateKey, []byte("journal"))
	if _, err := Verify(fixture.bundle, wrongPublic); !errors.Is(err, &Error{code: CodeSignature}) {
		t.Fatalf("wrong verification key accepted: %v", err)
	}

	manifest := fixture.manifest
	manifest.Files[0].Path = "../executor/private.pem"
	if err := validateManifest(manifest); !errors.Is(err, &Error{code: CodeContents}) {
		t.Fatalf("manifest traversal accepted: %v", err)
	}

	destinationDirectory := privateDirectory(t)
	destination := filepath.Join(destinationDirectory, "replay.json")
	staged, err := StageJournal(fixture.bundle, publicKey, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("swapped"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CommitJournal(fixture.bundle, publicKey, destination); !errors.Is(err, &Error{code: CodeIntegrity}) {
		t.Fatalf("swapped stage accepted: %v", err)
	}
}

func TestRestoreMarkerResumesOnlyExactDatabaseAndBundle(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	fixture := newBundleFixture(t, privateKey, []byte("opaque-started-without-terminal"))
	destinationDirectory := privateDirectory(t)
	destination := filepath.Join(destinationDirectory, "replay.json")
	databaseIdentity := "pg17:123456789:4242:sentinelflow_restore"

	prepared, err := PrepareRestore(fixture.bundle, publicKey, destination, databaseIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Phase != RestorePhasePrepared || prepared.JournalState != "staged" ||
		!validDigest(prepared.ReceiptDigest) {
		t.Fatalf("unexpected prepared state: %#v", prepared)
	}
	marker, _ := RestoreStatePath(destination)
	if info, err := os.Stat(marker); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("marker was not durable and private: %v", err)
	}

	repeated, err := PrepareRestore(fixture.bundle, publicKey, destination, databaseIdentity)
	if err != nil || repeated != prepared {
		t.Fatalf("exact prepared retry drifted: %#v %v", repeated, err)
	}
	if _, err := PrepareRestore(fixture.bundle, publicKey, destination, "pg17:123456789:4243:other"); !errors.Is(err, &Error{code: CodeIntegrity}) {
		t.Fatalf("different database resumed marker: %v", err)
	}

	databaseRestored, err := MarkDatabaseRestored(fixture.bundle, publicKey, destination, databaseIdentity)
	if err != nil || databaseRestored.Phase != RestorePhaseDatabase || databaseRestored.JournalState != "staged" {
		t.Fatalf("database phase failed: %#v %v", databaseRestored, err)
	}
	resumed, err := PrepareRestore(fixture.bundle, publicKey, destination, databaseIdentity)
	if err != nil || resumed.Phase != RestorePhaseDatabase || resumed.ReceiptDigest != prepared.ReceiptDigest {
		t.Fatalf("database-restored retry drifted: %#v %v", resumed, err)
	}
	installed, err := CommitPreparedJournal(fixture.bundle, publicKey, destination, databaseIdentity)
	if err != nil || installed.Phase != RestorePhaseJournal || installed.JournalState != "installed" {
		t.Fatalf("journal commit failed: %#v %v", installed, err)
	}
	installedAgain, err := CommitPreparedJournal(fixture.bundle, publicKey, destination, databaseIdentity)
	if err != nil || installedAgain.JournalState != "installed" {
		t.Fatalf("installed retry failed: %#v %v", installedAgain, err)
	}
	finalized, err := FinalizeRestore(fixture.bundle, publicKey, destination, databaseIdentity)
	if err != nil || finalized.Phase != RestorePhaseFinalized || finalized.JournalState != "installed" {
		t.Fatalf("finalize failed: %#v %v", finalized, err)
	}
	if info, err := os.Stat(marker); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("permanent final marker missing: %v", err)
	}
	retried, err := PrepareRestore(fixture.bundle, publicKey, destination, databaseIdentity)
	if err != nil || retried != finalized {
		t.Fatalf("finalized retry did not converge: %#v %v", retried, err)
	}
}

func TestRestoreMarkerTamperFailsClosed(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	fixture := newBundleFixture(t, privateKey, []byte("journal"))
	destination := filepath.Join(privateDirectory(t), "replay.json")
	identity := "pg17:987654321:5252:sentinelflow_restore"
	if _, err := PrepareRestore(fixture.bundle, publicKey, destination, identity); err != nil {
		t.Fatal(err)
	}
	marker, _ := RestoreStatePath(destination)
	contents, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	contents[bytes.Index(contents, []byte(RestorePhasePrepared))] ^= 1
	if err := os.WriteFile(marker, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareRestore(fixture.bundle, publicKey, destination, identity); !errors.Is(err, &Error{code: CodeContents}) && !errors.Is(err, &Error{code: CodeIntegrity}) {
		t.Fatalf("tampered marker accepted: %v", err)
	}
}

func TestRestoreNextCrashWindowsConvergeAndConflictsFailClosed(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	fixture := newBundleFixture(t, privateKey, []byte("journal"))
	identity := "pg17:123456789:6262:next_recovery"

	t.Run("missing marker adopts only exact initial prepared next", func(t *testing.T) {
		destination := filepath.Join(privateDirectory(t), "replay.json")
		if _, err := PrepareRestore(fixture.bundle, publicKey, destination, identity); err != nil {
			t.Fatal(err)
		}
		marker, _ := RestoreStatePath(destination)
		if err := os.Remove(stagedJournalPath(destination)); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(marker, restoreNextPath(marker)); err != nil {
			t.Fatal(err)
		}
		status, err := PrepareRestore(fixture.bundle, publicKey, destination, identity)
		if err != nil || status.Phase != RestorePhasePrepared || status.JournalState != "staged" {
			t.Fatalf("initial next was not adopted: %#v %v", status, err)
		}
	})

	t.Run("exact successor next advances monotonically", func(t *testing.T) {
		destination := filepath.Join(privateDirectory(t), "replay.json")
		if _, err := PrepareRestore(fixture.bundle, publicKey, destination, identity); err != nil {
			t.Fatal(err)
		}
		marker, _ := RestoreStatePath(destination)
		current, err := readRestoreState(marker)
		if err != nil {
			t.Fatal(err)
		}
		writeRestoreNextForTest(t, marker, current, RestorePhaseDatabase)
		status, err := PrepareRestore(fixture.bundle, publicKey, destination, identity)
		if err != nil || status.Phase != RestorePhaseDatabase {
			t.Fatalf("database successor was not adopted: %#v %v", status, err)
		}
		status, err = CommitPreparedJournal(fixture.bundle, publicKey, destination, identity)
		if err != nil || status.Phase != RestorePhaseJournal {
			t.Fatalf("journal phase failed: %#v %v", status, err)
		}
		current, err = readRestoreState(marker)
		if err != nil {
			t.Fatal(err)
		}
		writeRestoreNextForTest(t, marker, current, RestorePhaseFinalized)
		status, err = PrepareRestore(fixture.bundle, publicKey, destination, identity)
		if err != nil || status.Phase != RestorePhaseFinalized || status.JournalState != "installed" {
			t.Fatalf("final successor was not adopted: %#v %v", status, err)
		}
	})

	t.Run("torn and conflicting next never override current", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			write func(t *testing.T, marker string, current restoreState)
		}{
			{
				name: "torn",
				write: func(t *testing.T, marker string, _ restoreState) {
					t.Helper()
					writeFile(t, restoreNextPath(marker), []byte("{\n"), 0o600)
				},
			},
			{
				name: "conflicting",
				write: func(t *testing.T, marker string, current restoreState) {
					t.Helper()
					current.Phase = RestorePhaseDatabase
					current.RestoreNonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 32))
					current.StateChecksum = ""
					encoded, err := marshalRestoreState(current)
					if err != nil {
						t.Fatal(err)
					}
					writeFile(t, restoreNextPath(marker), encoded, 0o600)
				},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				destination := filepath.Join(privateDirectory(t), "replay.json")
				if _, err := PrepareRestore(fixture.bundle, publicKey, destination, identity); err != nil {
					t.Fatal(err)
				}
				marker, _ := RestoreStatePath(destination)
				current, err := readRestoreState(marker)
				if err != nil {
					t.Fatal(err)
				}
				test.write(t, marker, current)
				if _, err := PrepareRestore(fixture.bundle, publicKey, destination, identity); err == nil {
					t.Fatal("unsafe next state was adopted")
				}
				persisted, err := readRestoreState(marker)
				if err != nil || persisted != current {
					t.Fatalf("current marker changed after rejection: %v", err)
				}
			})
		}
	})
}

func writeRestoreNextForTest(t *testing.T, marker string, current restoreState, phase string) {
	t.Helper()
	current.Phase = phase
	current.StateChecksum = ""
	encoded, err := marshalRestoreState(current)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, restoreNextPath(marker), encoded, 0o600)
}

func TestRestoreDatabaseIdentityGrammarFailsClosed(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	fixture := newBundleFixture(t, privateKey, []byte("journal"))
	invalid := []string{
		"pg16:123:456:database",
		"pg17::456:database",
		"pg17:123::database",
		"pg17:123:456:",
		"pg17:123:456:database;DROP_TABLE",
		"pg17:123:456:database/name",
		"pg17:123:456:database\nextra",
		"pg17:123:456:database:extra",
		"pg17:123:456:" + strings.Repeat("a", 64),
	}
	for _, identity := range invalid {
		destination := filepath.Join(privateDirectory(t), "replay.json")
		if _, err := PrepareRestore(fixture.bundle, publicKey, destination, identity); !errors.Is(err, &Error{code: CodeArgument}) {
			t.Fatalf("invalid database identity accepted: %q: %v", identity, err)
		}
	}
}

func TestStartedOnlyExecutorJournalRemainsInspectOnlyAfterRestore(t *testing.T) {
	dispatchPublic, dispatchPrivate, _ := ed25519.GenerateKey(rand.Reader)
	resultPublic, resultPrivate, _ := ed25519.GenerateKey(rand.Reader)
	issuer, err := capability.NewCapabilityIssuer("dispatch-recovery-test", dispatchPrivate)
	if err != nil {
		t.Fatal(err)
	}
	capabilityVerifier, err := capability.NewCapabilityVerifier("dispatch-recovery-test", "executor-recovery-test", dispatchPublic)
	if err != nil {
		t.Fatal(err)
	}
	resultVerifier, err := capability.NewResultVerifier("result-recovery-test", "executor-recovery-test", resultPublic)
	if err != nil {
		t.Fatal(err)
	}
	resultSigner, err := capability.NewResultSigner("result-recovery-test", "executor-recovery-test", resultPrivate)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	common := capability.Common{
		CapabilityID:  "019b0000-0000-7000-8000-00000000c001",
		JobID:         "019b0000-0000-7000-8000-00000000c002",
		ActionID:      "019b0000-0000-7000-8000-00000000c003",
		PolicyID:      "019b0000-0000-7000-8000-00000000c004",
		PolicyVersion: 1, TargetIPv4: "203.0.113.20",
		EvidenceSnapshotDigest:   digestBytes([]byte("evidence")),
		ValidationSnapshotDigest: digestBytes([]byte("validation")),
		AuthorizationDigest:      digestBytes([]byte("authorization")),
		ActorID:                  "dispatcher", ReasonDigest: digestBytes([]byte("reason")),
		OwnedSchemaDigest: digestBytes([]byte("owned-schema")),
		IssuedAt:          issued, NotBefore: issued, ExpiresAt: issued.Add(time.Minute),
		Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16)),
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
	journalDirectory := privateDirectory(t)
	sourceJournal := filepath.Join(journalDirectory, "replay.json")
	opened, err := journal.Open(journal.Options{
		Path: sourceJournal, CapabilityVerifier: capabilityVerifier, ResultVerifier: resultVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := opened.Begin(signed, issued.Add(time.Second), issued.Add(2*time.Second))
	if err != nil || outcome.State() != journal.StateNewStarted {
		t.Fatalf("durable start failed: %v %s", err, outcome.State())
	}
	terminalCommon := common
	terminalCommon.CapabilityID = "019b0000-0000-7000-8000-00000000c011"
	terminalCommon.JobID = "019b0000-0000-7000-8000-00000000c012"
	terminalCommon.ActionID = "019b0000-0000-7000-8000-00000000c013"
	terminalCommon.PolicyID = "019b0000-0000-7000-8000-00000000c014"
	terminalCommon.Nonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 16))
	terminalChecked, err := capability.CheckAdd(capability.Add{
		Common:           terminalCommon,
		CanonicalCommand: []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	terminalCapability, err := issuer.Sign(terminalChecked)
	if err != nil {
		t.Fatal(err)
	}
	terminalVerified, err := capabilityVerifier.Verify(terminalCapability)
	if err != nil {
		t.Fatal(err)
	}
	terminalOutcome, err := opened.Begin(terminalCapability, issued.Add(time.Second), issued.Add(2*time.Second))
	if err != nil || terminalOutcome.State() != journal.StateNewStarted {
		t.Fatalf("terminal start failed: %v %s", err, terminalOutcome.State())
	}
	exitClass := capability.NFTExitSuccess
	remainingTTL := uint64(1700)
	terminalResultChecked, err := capability.CheckResult(capability.Result{
		ResultID:     "019b0000-0000-7000-8000-00000000c015",
		CapabilityID: terminalVerified.Value().CapabilityID, CapabilityDigest: terminalVerified.Digest(),
		Operation: capability.OperationAdd, ActionID: terminalVerified.Value().ActionID,
		ArtifactDigest: terminalVerified.Value().ArtifactDigest, TargetIPv4: terminalVerified.Value().TargetIPv4,
		Classification: capability.ClassificationApplied, NFTExitClass: &exitClass,
		ReadbackState: capability.ReadbackActive, RemainingTTLSeconds: &remainingTTL,
		OwnedSchemaDigest: terminalVerified.Value().OwnedSchemaDigest,
		StartedAt:         issued.Add(1100 * time.Millisecond), CompletedAt: issued.Add(1200 * time.Millisecond),
		JournalSequence: terminalOutcome.Started().Sequence, ErrorCode: capability.ResultErrorNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminalResult, err := resultSigner.SignFor(terminalVerified, terminalResultChecked)
	if err != nil {
		t.Fatal(err)
	}
	if _, appended, err := opened.Complete(terminalResult); err != nil || !appended {
		t.Fatalf("terminal record was not committed: %v %v", appended, err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	sourceBytes, err := os.ReadFile(sourceJournal)
	if err != nil || len(sourceBytes) == 0 {
		t.Fatalf("started journal was not written: %v", err)
	}

	backupPublic, backupPrivate, _ := ed25519.GenerateKey(rand.Reader)
	parent := privateDirectory(t)
	staging := filepath.Join(parent, "stage")
	prepareStaging(t, staging)
	bundle := filepath.Join(parent, "bundle")
	if err := Seal(SealOptions{
		StagingDir: staging, OutputDir: bundle, Journal: sourceJournal,
		PrivateKey: backupPrivate, Now: issued,
	}); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(privateDirectory(t), "replay.json")
	identity := "pg17:777:888:started_only_restore"
	if _, err := PrepareRestore(bundle, backupPublic, destination, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := MarkDatabaseRestored(bundle, backupPublic, destination, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := CommitPreparedJournal(bundle, backupPublic, destination, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeRestore(bundle, backupPublic, destination, identity); err != nil {
		t.Fatal(err)
	}
	restoredBytes, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(restoredBytes, sourceBytes) {
		t.Fatalf("actual executor journal changed: %v", err)
	}

	reopened, err := journal.Open(journal.Options{
		Path: destination, CapabilityVerifier: capabilityVerifier, ResultVerifier: resultVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.Lookup(signed)
	if err != nil || recovered.State() != journal.StateStartedOnly {
		t.Fatalf("started-only classification changed: %v %s", err, recovered.State())
	}
	if _, ok := recovered.Permit(); ok {
		t.Fatal("restored started-only record released mutation authority")
	}
	recovery, ok := recovered.Recovery()
	if !ok {
		t.Fatal("restored started-only record lost read-only recovery handle")
	}
	if ttl, ok := recovery.ExpectedAddTTLSeconds(); !ok || ttl != 1800 {
		t.Fatalf("restored recovery expectation changed: %d %v", ttl, ok)
	}
	terminalRecovered, err := reopened.Lookup(terminalCapability)
	if err != nil || terminalRecovered.State() != journal.StateTerminal {
		t.Fatalf("terminal classification changed: %v %s", err, terminalRecovered.State())
	}
	if _, ok := terminalRecovered.Permit(); ok {
		t.Fatal("restored terminal record released mutation authority")
	}
	if _, ok := terminalRecovered.Recovery(); ok {
		t.Fatal("restored terminal record exposed started-only recovery")
	}
	terminalSnapshot, ok := terminalRecovered.Terminal()
	if !ok || terminalSnapshot.ResultDigest() != terminalResultChecked.Digest() ||
		!bytes.Equal(terminalSnapshot.SignedResult().CanonicalBytes(), terminalResult.CanonicalBytes()) ||
		!bytes.Equal(terminalSnapshot.SignedResult().Signature(), terminalResult.Signature()) {
		t.Fatal("restored terminal result changed")
	}
}

func TestPublishKeepsCandidateHiddenUntilNoClobberRename(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("complete candidate publishes once", func(t *testing.T) {
		fixture := newBundleFixture(t, privateKey, []byte("journal"))
		parent := filepath.Dir(fixture.bundle)
		candidate := filepath.Join(parent, ".sentinelflow-recovery-v1.candidate.complete")
		output := filepath.Join(parent, "public-bundle")
		if err := os.Rename(fixture.bundle, candidate); err != nil {
			t.Fatal(err)
		}
		if err := Publish(candidate, output); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("candidate remains after publish: %v", err)
		}
		if info, err := os.Stat(output); err != nil || !info.IsDir() {
			t.Fatalf("public output missing: %v", err)
		}
	})

	t.Run("post-seal scratch fails with no public output", func(t *testing.T) {
		fixture := newBundleFixture(t, privateKey, []byte("journal"))
		parent := filepath.Dir(fixture.bundle)
		candidate := filepath.Join(parent, ".sentinelflow-recovery-v1.candidate.scratch")
		output := filepath.Join(parent, "must-not-appear")
		if err := os.Rename(fixture.bundle, candidate); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(candidate, "metadata", "sequences.current.tsv"), []byte("scratch\n"), 0o600)
		if err := Publish(candidate, output); !errors.Is(err, &Error{code: CodeContents}) {
			t.Fatalf("candidate scratch accepted: %v", err)
		}
		if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed publish exposed public output: %v", err)
		}
	})

	t.Run("existing output is never replaced", func(t *testing.T) {
		fixture := newBundleFixture(t, privateKey, []byte("journal"))
		parent := filepath.Dir(fixture.bundle)
		candidate := filepath.Join(parent, ".sentinelflow-recovery-v1.candidate.clobber")
		output := filepath.Join(parent, "existing-output")
		if err := os.Rename(fixture.bundle, candidate); err != nil {
			t.Fatal(err)
		}
		writeFile(t, output, []byte("owner-data"), 0o600)
		if err := Publish(candidate, output); !errors.Is(err, &Error{code: CodeExists}) {
			t.Fatalf("existing output accepted: %v", err)
		}
		contents, err := os.ReadFile(output)
		if err != nil || string(contents) != "owner-data" {
			t.Fatalf("existing output changed: %q %v", contents, err)
		}
	})
}

type bundleFixture struct {
	bundle   string
	manifest Manifest
}

func newBundleFixture(t *testing.T, privateKey ed25519.PrivateKey, journalBytes []byte) bundleFixture {
	t.Helper()
	parent := privateDirectory(t)
	staging := filepath.Join(parent, "stage")
	prepareStaging(t, staging)
	journal := filepath.Join(parent, "source-replay.json")
	writeFile(t, journal, journalBytes, 0o600)
	bundle := filepath.Join(parent, "bundle")
	if err := Seal(SealOptions{
		StagingDir: staging, OutputDir: bundle, Journal: journal, PrivateKey: privateKey,
		Now: time.Date(2026, 7, 18, 12, 34, 56, 0, time.UTC),
	}); err != nil {
		t.Fatalf("seal fixture: %v", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	verified, err := Verify(bundle, publicKey)
	if err != nil {
		t.Fatalf("verify fixture: %v", err)
	}
	return bundleFixture{bundle: bundle, manifest: verified.Manifest}
}

func prepareStaging(t *testing.T, staging string) {
	t.Helper()
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"metadata", "postgres"} {
		if err := os.Mkdir(filepath.Join(staging, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(staging, filepath.FromSlash(PostgresMajorPath)), []byte("17\n"), 0o600)
	writeFile(t, filepath.Join(staging, filepath.FromSlash(MigrationsPath)), []byte("1\tbootstrap_roles\n2\tcore_schema\n23\tretention_runtime\n"), 0o600)
	writeFile(t, filepath.Join(staging, filepath.FromSlash(RelationsPath)), []byte(PostgreSQLRelationContractRows()), 0o600)
	writeFile(t, filepath.Join(staging, filepath.FromSlash(SchemaPath)), []byte("CREATE SCHEMA sentinelflow;\nCREATE TABLE sentinelflow.schema_migrations(version bigint);\n"), 0o600)
	writeFile(t, filepath.Join(staging, filepath.FromSlash(SequencesPath)), []byte("sentinelflow.audit_events_sequence_seq\t1\tfalse\nsentinelflow.sse_notification_cursor_seq\t1\tfalse\n"), 0o600)
	writeFile(t, filepath.Join(staging, filepath.FromSlash(PostgresDumpPath)), []byte("PGDMP synthetic data-only fixture"), 0o600)
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
