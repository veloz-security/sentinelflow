package recoverybundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
	"github.com/devwooops/sentinelflow/internal/enforcement/keyidentity"
)

type executionArtifactFixture struct {
	row                executionArtifactRow
	dispatchPublic     ed25519.PublicKey
	dispatchPrivate    ed25519.PrivateKey
	resultPublic       ed25519.PublicKey
	resultPrivate      ed25519.PrivateKey
	capabilityVerifier capability.CapabilityVerifier
	resultVerifier     capability.ResultVerifier
	signedCapability   capability.SignedCapability
	signedResult       capability.SignedResult
	receivedAt         time.Time
	deadlineAt         time.Time
}

func TestRecoveryStartedMarkerGoldenVector(t *testing.T) {
	job := executionArtifactJob{
		JobID:                 "019b0000-0000-7000-8000-00000000d002",
		DeadLetterFailureCode: stringPointer("fixture_crash"),
		DeadLetterFailureDigest: stringPointer(
			"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		),
	}
	const capabilityDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const expected = "sha256:7a1b1022e371c08750c48330a4c9f3b05570216f67e673551ae64296b54cf316"
	if actual := recoveryStartedDigest(job, capabilityDigest); actual != expected {
		t.Fatalf("recovery marker drifted: got %s want %s", actual, expected)
	}
}

func TestValidateExecutionArtifactRowsAuthenticatesExactPersistedBytes(t *testing.T) {
	fixture := newExecutionArtifactFixture(t)
	if err := validateExecutionArtifactFixture(fixture); err != nil {
		t.Fatalf("valid execution artifact rejected: %v", err)
	}
	started := newExecutionArtifactFixture(t)
	started.row.Job.State = "dead"
	started.row.Job.LastErrorCode = stringPointer("fixture_crash")
	started.row.Job.LastErrorDigest = stringPointer(digestBytes([]byte("fixture_crash")))
	setFixtureDeadLetter(&started.row.Job, started.row.Capability.Digest, "unresolved")
	started.row.Capability.ConsumedAt = nil
	started.row.Result = nil
	started.row.LifecycleApplication = nil
	if err := validateExecutionArtifactFixture(started); err != nil {
		t.Fatalf("valid retained started capability rejected: %v", err)
	}
	retry := started
	retry.row.Job.State = "retry"
	retry.row.Job.AvailableAt = retry.row.Capability.ExpiresAt
	retry.row.Job.LastErrorCode = stringPointer("recovery_started")
	setFixtureDeadLetter(&retry.row.Job, retry.row.Capability.Digest, "requeued")
	retry.row.Job.LastErrorDigest = stringPointer(recoveryStartedDigest(retry.row.Job, retry.row.Capability.Digest))
	if err := validateExecutionArtifactFixture(retry); err != nil {
		t.Fatalf("valid recovery-only retry rejected: %v", err)
	}
	terminalRecovered := newExecutionArtifactFixture(t)
	setFixtureDeadLetter(
		&terminalRecovered.row.Job,
		terminalRecovered.row.Capability.Digest,
		"resolved",
	)
	if err := validateExecutionArtifactFixture(terminalRecovered); err != nil {
		t.Fatalf("valid recovered terminal rejected: %v", err)
	}

	provenanceTests := []struct {
		name   string
		mutate func(*executionArtifactFixture)
	}{
		{
			name: "forged recovery actor",
			mutate: func(f *executionArtifactFixture) {
				f.row.Job.DeadLetterResolutionActor = stringPointer("worker")
			},
		},
		{
			name: "forged recovery digest",
			mutate: func(f *executionArtifactFixture) {
				f.row.Job.DeadLetterResolutionDigest = stringPointer(digestBytes([]byte("forged")))
			},
		},
		{
			name: "noncanonical recovery time binding",
			mutate: func(f *executionArtifactFixture) {
				f.row.Job.DeadLetterResolvedAt = stringPointer("2026-07-19T01:02:03.000000Z")
			},
		},
		{
			name: "forged original failure",
			mutate: func(f *executionArtifactFixture) {
				f.row.Job.DeadLetterFailureCode = stringPointer("different_failure")
			},
		},
		{
			name: "forged dead letter identity",
			mutate: func(f *executionArtifactFixture) {
				f.row.Job.DeadLetterJobID = stringPointer("019b0000-0000-7000-8000-00000000ffff")
			},
		},
	}
	for _, test := range provenanceTests {
		t.Run(test.name, func(t *testing.T) {
			mutated := retry
			test.mutate(&mutated)
			if err := validateExecutionArtifactFixture(mutated); err == nil {
				t.Fatal("forged recovery provenance accepted")
			}
		})
	}

	tests := []struct {
		name   string
		mutate func(*executionArtifactFixture)
	}{
		{
			name: "capability missing key plus unknown key at same count",
			mutate: func(f *executionArtifactFixture) {
				raw := decodeFixtureHex(t, f.row.Capability.JCSHex)
				raw = bytes.Replace(raw, []byte(`"actor_id":"dispatcher"`), []byte(`"unknown":"dispatcher"`), 1)
				resignCapabilityFixture(t, f, raw)
			},
		},
		{
			name: "capability duplicate last key",
			mutate: func(f *executionArtifactFixture) {
				raw := decodeFixtureHex(t, f.row.Capability.JCSHex)
				raw = append(append([]byte(nil), raw[:len(raw)-1]...), `,"actor_id":"dispatcher"}`...)
				resignCapabilityFixture(t, f, raw)
			},
		},
		{
			name: "capability noncanonical whitespace",
			mutate: func(f *executionArtifactFixture) {
				raw := append([]byte{' '}, decodeFixtureHex(t, f.row.Capability.JCSHex)...)
				resignCapabilityFixture(t, f, raw)
			},
		},
		{
			name: "result duplicate last key",
			mutate: func(f *executionArtifactFixture) {
				raw := decodeFixtureHex(t, f.row.Result.JCSHex)
				raw = append(append([]byte(nil), raw[:len(raw)-1]...), `,"result_id":"019b0000-0000-7000-8000-00000000d005"}`...)
				resignResultFixture(t, f, raw)
			},
		},
		{
			name: "result noncanonical reencoding",
			mutate: func(f *executionArtifactFixture) {
				raw := decodeFixtureHex(t, f.row.Result.JCSHex)
				raw = bytes.Replace(raw, []byte(`"journal_sequence":1`), []byte(`"journal_sequence":1.0`), 1)
				resignResultFixture(t, f, raw)
			},
		},
		{
			name: "nonce digest mismatch",
			mutate: func(f *executionArtifactFixture) {
				f.row.Capability.NonceDigest = digestBytes([]byte("different-nonce"))
			},
		},
		{
			name: "forged capability signature",
			mutate: func(f *executionArtifactFixture) {
				signature := decodeFixtureHex(t, f.row.Capability.SignatureHex)
				signature[0] ^= 0x80
				f.row.Capability.SignatureHex = hex.EncodeToString(signature)
			},
		},
		{
			name: "forged result signature",
			mutate: func(f *executionArtifactFixture) {
				signature := decodeFixtureHex(t, f.row.Result.SignatureHex)
				signature[len(signature)-1] ^= 0x01
				f.row.Result.SignatureHex = hex.EncodeToString(signature)
			},
		},
		{
			name: "missing dispatch operation",
			mutate: func(f *executionArtifactFixture) {
				f.row.Operation = executionArtifactOperation{}
			},
		},
		{
			name: "operation artifact uppercase hex",
			mutate: func(f *executionArtifactFixture) {
				f.row.Operation.ArtifactHex = strings.ToUpper(f.row.Operation.ArtifactHex)
			},
		},
		{
			name: "missing result on runnable job",
			mutate: func(f *executionArtifactFixture) {
				f.row.Job.State = "retry"
				f.row.Job.LastErrorCode = stringPointer("other_retry")
				f.row.Job.LastErrorDigest = stringPointer(digestBytes([]byte("other_retry")))
				setFixtureDeadLetter(&f.row.Job, f.row.Capability.Digest, "requeued")
				f.row.Capability.ConsumedAt = nil
				f.row.Result = nil
				f.row.LifecycleApplication = nil
			},
		},
		{
			name: "dead capability falsely consumed without result",
			mutate: func(f *executionArtifactFixture) {
				f.row.Job.State = "dead"
				f.row.Job.LastErrorCode = stringPointer("fixture_crash")
				f.row.Job.LastErrorDigest = stringPointer(digestBytes([]byte("fixture_crash")))
				setFixtureDeadLetter(&f.row.Job, f.row.Capability.Digest, "unresolved")
				f.row.Result = nil
				f.row.LifecycleApplication = nil
			},
		},
		{
			name: "recovery retry available before capability expiry",
			mutate: func(f *executionArtifactFixture) {
				f.row.Job.State = "retry"
				f.row.Job.AvailableAt = f.row.Capability.NotBefore
				f.row.Job.LastErrorCode = stringPointer("recovery_started")
				setFixtureDeadLetter(&f.row.Job, f.row.Capability.Digest, "requeued")
				f.row.Job.LastErrorDigest = stringPointer(recoveryStartedDigest(f.row.Job, f.row.Capability.Digest))
				f.row.Capability.ConsumedAt = nil
				f.row.Result = nil
				f.row.LifecycleApplication = nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := newExecutionArtifactFixture(t)
			test.mutate(&mutated)
			if err := validateExecutionArtifactFixture(mutated); err == nil {
				t.Fatal("invalid execution artifact accepted")
			}
		})
	}
}

func TestValidateExecutionArtifactRowsVersionsLifecycleApplication(t *testing.T) {
	v1 := newExecutionArtifactFixture(t)
	v1.row.SchemaVersion = executionArtifactRowVersionV1
	v1.row.LifecycleApplication = nil
	setFixtureDeadLetter(&v1.row.Job, v1.row.Capability.Digest, "resolved")
	if err := validateExecutionArtifactFixture(v1); err != nil {
		t.Fatalf("v1 equal-version terminal artifact rejected: %v", err)
	}

	v1Advanced := newExecutionArtifactFixture(t)
	v1Advanced.row.SchemaVersion = executionArtifactRowVersionV1
	v1Advanced.row.LifecycleApplication = nil
	setFixtureDeadLetter(&v1Advanced.row.Job, v1Advanced.row.Capability.Digest, "resolved")
	v1Advanced.row.Job.AggregateVersion++
	if err := validateExecutionArtifactFixture(v1Advanced); err == nil {
		t.Fatal("v1 artifact reinterpreted as authorizing a lifecycle version advance")
	}

	v1WithApplication := newExecutionArtifactFixture(t)
	v1WithApplication.row.SchemaVersion = executionArtifactRowVersionV1
	if err := validateExecutionArtifactFixture(v1WithApplication); err == nil {
		t.Fatal("v1 artifact accepted a v2 lifecycle application")
	}

	v2MissingApplication := newExecutionArtifactFixture(t)
	v2MissingApplication.row.LifecycleApplication = nil
	if err := validateExecutionArtifactFixture(v2MissingApplication); err == nil {
		t.Fatal("v2 terminal artifact accepted a missing lifecycle application")
	}

	v2Advanced := newExecutionArtifactFixture(t)
	setFixtureDeadLetter(&v2Advanced.row.Job, v2Advanced.row.Capability.Digest, "resolved")
	v2Advanced.row.Job.AggregateVersion++
	v2Advanced.row.LifecycleApplication.ResultingActionVersion = v2Advanced.row.Job.AggregateVersion
	if err := validateExecutionArtifactFixture(v2Advanced); err != nil {
		t.Fatalf("v2 exact one-version lifecycle advance rejected: %v", err)
	}

	v2AdvancedTwo := newExecutionArtifactFixture(t)
	setFixtureDeadLetter(&v2AdvancedTwo.row.Job, v2AdvancedTwo.row.Capability.Digest, "resolved")
	v2AdvancedTwo.row.Job.AggregateVersion += 2
	v2AdvancedTwo.row.LifecycleApplication.ResultingActionVersion = v2AdvancedTwo.row.Job.AggregateVersion
	if err := validateExecutionArtifactFixture(v2AdvancedTwo); err == nil {
		t.Fatal("v2 artifact accepted a two-version lifecycle advance")
	}

	tests := []struct {
		name   string
		mutate func(*executionArtifactLifecycleApplication)
	}{
		{
			name: "schema version",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.SchemaVersion = "lifecycle-result-application-v2"
			},
		},
		{
			name: "job id",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.JobID = "019b0000-0000-7000-8000-00000000ffff"
			},
		},
		{
			name: "capability id",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.CapabilityID = "019b0000-0000-7000-8000-00000000ffff"
			},
		},
		{
			name: "result id",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.ResultID = "019b0000-0000-7000-8000-00000000ffff"
			},
		},
		{
			name: "result digest",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.ResultDigest = digestBytes([]byte("other-result"))
			},
		},
		{
			name: "action id",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.ActionID = "019b0000-0000-7000-8000-00000000ffff"
			},
		},
		{
			name: "operation",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.Operation = "revoke"
			},
		},
		{
			name: "classification",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.Classification = "failed"
			},
		},
		{
			name: "resulting state",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.ResultingState = "failed"
			},
		},
		{
			name: "resulting action version",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.ResultingActionVersion++
			},
		},
		{
			name: "processed at",
			mutate: func(application *executionArtifactLifecycleApplication) {
				application.ProcessedAt = "2026-07-19T01:02:04.000000Z"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newExecutionArtifactFixture(t)
			test.mutate(fixture.row.LifecycleApplication)
			if err := validateExecutionArtifactFixture(fixture); err == nil {
				t.Fatal("mutated lifecycle application accepted")
			}
		})
	}
}

func TestValidateExecutionArtifactRowsRetainsHistoricalLifecycleResults(t *testing.T) {
	add := newExecutionArtifactFixture(t)
	inspect := newExecutionArtifactFollowupFixture(
		t, add, capability.OperationInspect,
		"019b0000-0000-7000-8000-00000000d006",
		"019b0000-0000-7000-8000-00000000d007",
		"019b0000-0000-7000-8000-00000000d008",
		2,
	)
	revoke := newExecutionArtifactFollowupFixture(
		t, add, capability.OperationRevoke,
		"019b0000-0000-7000-8000-00000000d009",
		"019b0000-0000-7000-8000-00000000d00a",
		"019b0000-0000-7000-8000-00000000d00b",
		3,
	)

	rows := append(executionArtifactFixtureBytes(t, add), executionArtifactFixtureBytes(t, inspect)...)
	rows = append(rows, executionArtifactFixtureBytes(t, revoke)...)
	if err := ValidateExecutionArtifactRows(
		bytes.NewReader(rows), add.dispatchPublic, add.resultPublic,
	); err != nil {
		t.Fatalf("retained add/inspect/revoke lifecycle history rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*executionArtifactFixture)
	}{
		{
			name: "application result binding",
			mutate: func(fixture *executionArtifactFixture) {
				fixture.row.LifecycleApplication.ResultDigest = digestBytes([]byte("forged"))
			},
		},
		{
			name: "signed result binding",
			mutate: func(fixture *executionArtifactFixture) {
				fixture.row.Result.Classification = string(capability.ClassificationInspectActive)
			},
		},
		{
			name: "job version binding",
			mutate: func(fixture *executionArtifactFixture) {
				fixture.row.Job.AggregateVersion++
			},
		},
		{
			name: "dead letter two versions behind",
			mutate: func(fixture *executionArtifactFixture) {
				setFixtureDeadLetter(&fixture.row.Job, fixture.row.Capability.Digest, "resolved")
				*fixture.row.Job.DeadLetterAggregateVersion = fixture.row.Job.AggregateVersion - 2
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			freshInspect := newExecutionArtifactFollowupFixture(
				t, add, capability.OperationInspect,
				"019b0000-0000-7000-8000-00000000d006",
				"019b0000-0000-7000-8000-00000000d007",
				"019b0000-0000-7000-8000-00000000d008",
				2,
			)
			test.mutate(&freshInspect)
			mutatedRows := append(
				executionArtifactFixtureBytes(t, add),
				executionArtifactFixtureBytes(t, freshInspect)...,
			)
			mutatedRows = append(mutatedRows, executionArtifactFixtureBytes(t, revoke)...)
			if err := ValidateExecutionArtifactRows(
				bytes.NewReader(mutatedRows), add.dispatchPublic, add.resultPublic,
			); err == nil {
				t.Fatal("mutated historical lifecycle binding accepted")
			}
		})
	}
}

func TestValidateJournalExecutionArtifactRowsReconcilesRetainedSubset(t *testing.T) {
	fixture := newExecutionArtifactFixture(t)
	terminalJournal := terminalJournalBytes(t, fixture, true)
	row := executionArtifactFixtureBytes(t, fixture)
	if err := ValidateJournalExecutionArtifactRows(
		terminalJournal, bytes.NewReader(row), fixture.dispatchPublic, fixture.resultPublic,
	); err != nil {
		t.Fatalf("matching terminal journal rejected: %v", err)
	}

	// The append-only journal may retain authenticated terminal history after
	// the corresponding database rows have expired under retention.
	if err := ValidateJournalExecutionArtifactRows(
		terminalJournal, bytes.NewReader(nil), fixture.dispatchPublic, fixture.resultPublic,
	); err != nil {
		t.Fatalf("authenticated retained terminal history rejected: %v", err)
	}

	started := fixture
	started.row.Job.State = "dead"
	started.row.Job.LastErrorCode = stringPointer("fixture_crash")
	started.row.Job.LastErrorDigest = stringPointer(digestBytes([]byte("fixture_crash")))
	setFixtureDeadLetter(&started.row.Job, started.row.Capability.Digest, "unresolved")
	started.row.Capability.ConsumedAt = nil
	started.row.Result = nil
	started.row.LifecycleApplication = nil
	startedRow := executionArtifactFixtureBytes(t, started)
	startedJournal := terminalJournalBytes(t, fixture, false)
	if err := ValidateJournalExecutionArtifactRows(
		startedJournal, bytes.NewReader(startedRow), fixture.dispatchPublic, fixture.resultPublic,
	); err != nil {
		t.Fatalf("matching inert started lifecycle rejected: %v", err)
	}
	if err := ValidateJournalExecutionArtifactRows(
		terminalJournal, bytes.NewReader(startedRow), fixture.dispatchPublic, fixture.resultPublic,
	); err != nil {
		t.Fatalf("terminal-journal-ahead recovery lifecycle rejected: %v", err)
	}

	tests := []struct {
		name    string
		journal []byte
		rows    []byte
	}{
		{name: "empty journal with database terminal", rows: row},
		{name: "orphan started only journal", journal: startedJournal},
		{name: "started journal with terminal database row", journal: startedJournal, rows: row},
		{name: "fake opaque journal", journal: []byte("SFJNLv1\nopaque-invalid-frame"), rows: row},
		{name: "torn terminal journal", journal: terminalJournal[:len(terminalJournal)-1], rows: row},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateJournalExecutionArtifactRows(
				test.journal, bytes.NewReader(test.rows), fixture.dispatchPublic, fixture.resultPublic,
			); err == nil {
				t.Fatal("journal/database mismatch accepted")
			}
		})
	}

	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateJournalExecutionArtifactRows(
		terminalJournal, bytes.NewReader(row), wrongPublic, fixture.resultPublic,
	); err == nil {
		t.Fatal("wrong dispatcher key accepted")
	}
}

func TestValidateExecutionArtifactRowsV2ReadbackBounds(t *testing.T) {
	fixture := newExecutionArtifactFixture(t)
	upgradeExecutionArtifactFixtureToV2(t, &fixture)
	if err := validateExecutionArtifactFixture(fixture); err != nil {
		t.Fatalf("valid v2 execution artifact rejected: %v", err)
	}
	if err := ValidateJournalExecutionArtifactRows(
		terminalJournalBytes(t, fixture, true),
		bytes.NewReader(executionArtifactFixtureBytes(t, fixture)),
		fixture.dispatchPublic,
		fixture.resultPublic,
	); err != nil {
		t.Fatalf("valid v2 journal/database artifacts rejected: %v", err)
	}

	tampered := newExecutionArtifactFixture(t)
	upgradeExecutionArtifactFixtureToV2(t, &tampered)
	*tampered.row.Result.ReadbackCompletedAt = databaseTime(
		mustFixtureDatabaseTime(t, tampered.row.Result.CompletedAt).Add(time.Millisecond),
	)
	if err := validateExecutionArtifactFixture(tampered); err == nil {
		t.Fatal("database readback bound detached from signed v2 result")
	}
}

func newExecutionArtifactFixture(t *testing.T) executionArtifactFixture {
	t.Helper()
	dispatchPublic, dispatchPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resultPublic, resultPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := keyidentity.Derive(dispatchPublic, resultPublic)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := capability.NewCapabilityIssuer(identities.DispatchKeyID, dispatchPrivate)
	if err != nil {
		t.Fatal(err)
	}
	capabilityVerifier, err := capability.NewCapabilityVerifier(identities.DispatchKeyID, identities.ExecutorID, dispatchPublic)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 7, 19, 1, 2, 3, 456_000_000, time.UTC)
	artifact := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1m }\n")
	common := capability.Common{
		CapabilityID:  "019b0000-0000-7000-8000-00000000d001",
		JobID:         "019b0000-0000-7000-8000-00000000d002",
		ActionID:      "019b0000-0000-7000-8000-00000000d003",
		PolicyID:      "019b0000-0000-7000-8000-00000000d004",
		PolicyVersion: 1, TargetIPv4: "203.0.113.20",
		EvidenceSnapshotDigest:   digestBytes([]byte("evidence")),
		ValidationSnapshotDigest: digestBytes([]byte("validation")),
		AuthorizationDigest:      digestBytes([]byte("authorization")),
		ActorID:                  "dispatcher", ReasonDigest: digestBytes([]byte("reason")),
		OwnedSchemaDigest: digestBytes([]byte("owned-schema")),
		IssuedAt:          issuedAt, NotBefore: issuedAt, ExpiresAt: issuedAt.Add(time.Minute),
		Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 16)),
	}
	checked, err := capability.CheckAdd(capability.Add{Common: common, CanonicalCommand: artifact})
	if err != nil {
		t.Fatal(err)
	}
	signedCapability, err := issuer.Sign(checked)
	if err != nil {
		t.Fatal(err)
	}
	verifiedCapability, err := capabilityVerifier.Verify(signedCapability)
	if err != nil {
		t.Fatal(err)
	}
	exitClass := capability.NFTExitSuccess
	remainingTTL := uint64(50)
	startedAt := issuedAt.Add(time.Second)
	completedAt := issuedAt.Add(2 * time.Second)
	checkedResult, err := capability.CheckResult(capability.Result{
		ResultID:     "019b0000-0000-7000-8000-00000000d005",
		CapabilityID: common.CapabilityID, CapabilityDigest: verifiedCapability.Digest(),
		Operation: capability.OperationAdd, ActionID: common.ActionID,
		ArtifactDigest: checked.Value().ArtifactDigest, TargetIPv4: common.TargetIPv4,
		Classification: capability.ClassificationApplied, NFTExitClass: &exitClass,
		ReadbackState: capability.ReadbackActive, RemainingTTLSeconds: &remainingTTL,
		OwnedSchemaDigest: common.OwnedSchemaDigest, StartedAt: startedAt, CompletedAt: completedAt,
		JournalSequence: 1, ErrorCode: capability.ResultErrorNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	resultSigner, err := capability.NewResultSigner(identities.ResultKeyID, identities.ExecutorID, resultPrivate)
	if err != nil {
		t.Fatal(err)
	}
	signedResult, err := resultSigner.SignFor(verifiedCapability, checkedResult)
	if err != nil {
		t.Fatal(err)
	}
	nonceDigest, ok := executionNonceDigest(common.Nonce)
	if !ok {
		t.Fatal("fixture nonce rejected")
	}
	artifactHex := hex.EncodeToString(artifact)
	capabilityJCS := signedCapability.CanonicalBytes()
	resultJCS := signedResult.CanonicalBytes()
	row := executionArtifactRow{
		SchemaVersion: executionArtifactRowVersion,
		Job: executionArtifactJob{
			JobID: common.JobID, Kind: "dispatch_add", Operation: "add", State: "completed",
			AggregateType: "enforcement_action", AggregateID: common.ActionID, AggregateVersion: 1,
			AvailableAt: databaseTime(issuedAt), Attempts: 1, MaxAttempts: 8,
			UpdatedAt: databaseTime(completedAt.Add(time.Second)),
		},
		Operation: executionArtifactOperation{
			JobID: common.JobID, Operation: "add", ActionID: common.ActionID,
			PolicyID: common.PolicyID, PolicyVersion: common.PolicyVersion, TargetIPv4: common.TargetIPv4,
			ArtifactHex: artifactHex, ArtifactDigest: checked.Value().ArtifactDigest,
			EvidenceSnapshotDigest:   common.EvidenceSnapshotDigest,
			ValidationSnapshotDigest: common.ValidationSnapshotDigest,
			AuthorizationDigest:      common.AuthorizationDigest, ActorID: common.ActorID,
			ReasonDigest: common.ReasonDigest, OwnedSchemaDigest: common.OwnedSchemaDigest,
			NotBefore: databaseTime(common.NotBefore), ValidUntil: databaseTime(common.ExpiresAt),
		},
		Capability: executionArtifactCapability{
			CapabilityID: common.CapabilityID, SchemaVersion: capability.CapabilitySchemaVersion,
			JobID: common.JobID, Operation: "add", ActionID: common.ActionID,
			PolicyID: common.PolicyID, PolicyVersion: common.PolicyVersion, TargetIPv4: common.TargetIPv4,
			ArtifactHex: artifactHex, ArtifactDigest: checked.Value().ArtifactDigest,
			EvidenceSnapshotDigest:   common.EvidenceSnapshotDigest,
			ValidationSnapshotDigest: common.ValidationSnapshotDigest,
			AuthorizationDigest:      common.AuthorizationDigest, ActorID: common.ActorID,
			ReasonDigest: common.ReasonDigest, OwnedSchemaDigest: common.OwnedSchemaDigest,
			JCSHex: hex.EncodeToString(capabilityJCS), Digest: verifiedCapability.Digest(),
			SignatureHex: hex.EncodeToString(signedCapability.Signature()), NonceDigest: nonceDigest,
			IssuedAt: databaseTime(common.IssuedAt), NotBefore: databaseTime(common.NotBefore),
			ExpiresAt: databaseTime(common.ExpiresAt), ConsumedAt: stringPointer(databaseTime(completedAt)),
		},
		Result: &executionArtifactResult{
			ResultID: checkedResult.Value().ResultID, SchemaVersion: capability.ResultSchemaVersion,
			CapabilityID: common.CapabilityID, CapabilityDigest: verifiedCapability.Digest(),
			Operation: "add", ActionID: common.ActionID, ArtifactDigest: checked.Value().ArtifactDigest,
			TargetIPv4: common.TargetIPv4, Classification: string(capability.ClassificationApplied),
			NFTExitClass: stringPointer(string(exitClass)), ReadbackState: string(capability.ReadbackActive),
			RemainingTTLSeconds: &remainingTTL, OwnedSchemaDigest: common.OwnedSchemaDigest,
			StartedAt: databaseTime(startedAt), CompletedAt: databaseTime(completedAt),
			JournalSequence: 1, ErrorCode: string(capability.ResultErrorNone),
			JCSHex: hex.EncodeToString(resultJCS), Digest: checkedResult.Digest(),
			SignatureHex: hex.EncodeToString(signedResult.Signature()), PersistedAt: databaseTime(completedAt.Add(time.Second)),
		},
		LifecycleApplication: &executionArtifactLifecycleApplication{
			SchemaVersion: lifecycleApplicationVersion,
			JobID:         common.JobID, CapabilityID: common.CapabilityID,
			ResultID: checkedResult.Value().ResultID, ResultDigest: checkedResult.Digest(),
			ActionID: common.ActionID, Operation: string(capability.OperationAdd),
			Classification: string(capability.ClassificationApplied), ResultingState: "active",
			ResultingActionVersion: 1,
			ProcessedAt:            databaseTime(completedAt.Add(time.Second)),
		},
	}
	return executionArtifactFixture{
		row: row, dispatchPublic: dispatchPublic, dispatchPrivate: dispatchPrivate,
		resultPublic: resultPublic, resultPrivate: resultPrivate,
		capabilityVerifier: capabilityVerifier, resultVerifier: mustResultVerifier(t, identities, resultPublic),
		signedCapability: signedCapability, signedResult: signedResult,
		receivedAt: issuedAt, deadlineAt: issuedAt.Add(2 * time.Second),
	}
}

func upgradeExecutionArtifactFixtureToV2(t *testing.T, fixture *executionArtifactFixture) {
	t.Helper()
	verifiedCapability, err := fixture.capabilityVerifier.Verify(fixture.signedCapability)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := keyidentity.Derive(fixture.dispatchPublic, fixture.resultPublic)
	if err != nil {
		t.Fatal(err)
	}
	resultSigner, err := capability.NewResultSigner(
		identities.ResultKeyID,
		identities.ExecutorID,
		fixture.resultPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := mustFixtureDatabaseTime(t, fixture.row.Result.StartedAt)
	completedAt := mustFixtureDatabaseTime(t, fixture.row.Result.CompletedAt)
	readbackStartedAt := startedAt.Add(250 * time.Millisecond)
	readbackCompletedAt := completedAt.Add(-250 * time.Millisecond)
	remainingTTL := *fixture.row.Result.RemainingTTLSeconds
	exitClass := capability.NFTExitClass(*fixture.row.Result.NFTExitClass)
	checkedResult, err := capability.CheckResult(capability.Result{
		SchemaVersion: capability.ResultV2SchemaVersion,
		ResultID:      fixture.row.Result.ResultID, CapabilityID: fixture.row.Result.CapabilityID,
		CapabilityDigest: fixture.row.Result.CapabilityDigest,
		Operation:        capability.Operation(fixture.row.Result.Operation), ActionID: fixture.row.Result.ActionID,
		ArtifactDigest: fixture.row.Result.ArtifactDigest, TargetIPv4: fixture.row.Result.TargetIPv4,
		Classification: capability.Classification(fixture.row.Result.Classification), NFTExitClass: &exitClass,
		ReadbackState:       capability.ReadbackState(fixture.row.Result.ReadbackState),
		RemainingTTLSeconds: &remainingTTL, OwnedSchemaDigest: fixture.row.Result.OwnedSchemaDigest,
		StartedAt: startedAt, ReadbackStartedAt: &readbackStartedAt,
		ReadbackCompletedAt: &readbackCompletedAt, CompletedAt: completedAt,
		JournalSequence: fixture.row.Result.JournalSequence,
		ErrorCode:       capability.ResultErrorCode(fixture.row.Result.ErrorCode),
	})
	if err != nil {
		t.Fatal(err)
	}
	signedResult, err := resultSigner.SignFor(verifiedCapability, checkedResult)
	if err != nil {
		t.Fatal(err)
	}
	fixture.signedResult = signedResult
	fixture.row.Result.SchemaVersion = capability.ResultV2SchemaVersion
	fixture.row.Result.ReadbackStartedAt = stringPointer(databaseTime(readbackStartedAt))
	fixture.row.Result.ReadbackCompletedAt = stringPointer(databaseTime(readbackCompletedAt))
	fixture.row.Result.JCSHex = hex.EncodeToString(signedResult.CanonicalBytes())
	fixture.row.Result.Digest = checkedResult.Digest()
	fixture.row.Result.SignatureHex = hex.EncodeToString(signedResult.Signature())
	fixture.row.LifecycleApplication.ResultDigest = checkedResult.Digest()
}

func mustFixtureDatabaseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, ok := parseDatabaseTime(value)
	if !ok {
		t.Fatalf("invalid fixture database time %q", value)
	}
	return parsed
}

func newExecutionArtifactFollowupFixture(
	t *testing.T,
	base executionArtifactFixture,
	operation capability.Operation,
	capabilityID string,
	jobID string,
	resultID string,
	aggregateVersion int32,
) executionArtifactFixture {
	t.Helper()
	identities, err := keyidentity.Derive(base.dispatchPublic, base.resultPublic)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := capability.NewCapabilityIssuer(identities.DispatchKeyID, base.dispatchPrivate)
	if err != nil {
		t.Fatal(err)
	}
	resultSigner, err := capability.NewResultSigner(
		identities.ResultKeyID, identities.ExecutorID, base.resultPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}

	issuedAt := time.Date(2026, 7, 19, 1, 12, int(aggregateVersion), 456_000_000, time.UTC)
	originalAdd := digestBytes(
		[]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1m }\n"),
	)
	common := capability.Common{
		CapabilityID:             capabilityID,
		JobID:                    jobID,
		ActionID:                 base.row.Capability.ActionID,
		PolicyID:                 base.row.Capability.PolicyID,
		PolicyVersion:            base.row.Capability.PolicyVersion,
		TargetIPv4:               base.row.Capability.TargetIPv4,
		EvidenceSnapshotDigest:   base.row.Capability.EvidenceSnapshotDigest,
		ValidationSnapshotDigest: base.row.Capability.ValidationSnapshotDigest,
		AuthorizationDigest:      digestBytes([]byte("authorization-" + string(operation))),
		ActorID:                  base.row.Capability.ActorID,
		ReasonDigest:             base.row.Capability.ReasonDigest,
		OwnedSchemaDigest:        base.row.Capability.OwnedSchemaDigest,
		IssuedAt:                 issuedAt,
		NotBefore:                issuedAt,
		ExpiresAt:                issuedAt.Add(time.Minute),
		Nonce: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{byte(0x40 + aggregateVersion)}, 16),
		),
	}

	var checked capability.CheckedCapability
	var classification capability.Classification
	var resultingState string
	var readback capability.ReadbackState
	exitClass := capability.NFTExitSuccess
	var remainingTTL *uint64
	switch operation {
	case capability.OperationInspect:
		checked, err = capability.CheckInspect(capability.Inspect{
			Common: common, OriginalAddDigest: originalAdd,
			Artifact: capability.InspectArtifact{
				SchemaVersion: capability.InspectSchemaVersion,
				ActionID:      common.ActionID, TargetIPv4: common.TargetIPv4,
				OriginalAddDigest: originalAdd,
				OwnedSchemaDigest: common.OwnedSchemaDigest,
				Purpose:           "reconciliation",
			},
		})
		classification = capability.ClassificationInspectMismatch
		resultingState = "indeterminate"
		readback = capability.ReadbackMismatch
	case capability.OperationRevoke:
		checked, err = capability.CheckRevoke(capability.Revoke{
			Common: common, OriginalAddDigest: originalAdd,
			CanonicalDelete: []byte(
				"delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n",
			),
		})
		classification = capability.ClassificationRevoked
		resultingState = "revoked"
		readback = capability.ReadbackAbsent
	default:
		t.Fatalf("unsupported follow-up operation %q", operation)
	}
	if err != nil {
		t.Fatal(err)
	}
	signedCapability, err := issuer.Sign(checked)
	if err != nil {
		t.Fatal(err)
	}
	verifiedCapability, err := base.capabilityVerifier.Verify(signedCapability)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := issuedAt.Add(time.Second)
	completedAt := issuedAt.Add(2 * time.Second)
	checkedResult, err := capability.CheckResult(capability.Result{
		ResultID: resultID, CapabilityID: capabilityID,
		CapabilityDigest: verifiedCapability.Digest(), Operation: operation,
		ActionID: common.ActionID, ArtifactDigest: checked.Value().ArtifactDigest,
		TargetIPv4: common.TargetIPv4, Classification: classification,
		NFTExitClass: &exitClass, ReadbackState: readback,
		RemainingTTLSeconds: remainingTTL, OwnedSchemaDigest: common.OwnedSchemaDigest,
		StartedAt: startedAt, CompletedAt: completedAt,
		JournalSequence: 1, ErrorCode: capability.ResultErrorNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	signedResult, err := resultSigner.SignFor(verifiedCapability, checkedResult)
	if err != nil {
		t.Fatal(err)
	}
	nonceDigest, ok := executionNonceDigest(common.Nonce)
	if !ok {
		t.Fatal("follow-up fixture nonce rejected")
	}
	artifactHex := hex.EncodeToString(checked.ArtifactBytes())
	originalAddPointer := stringPointer(originalAdd)
	row := executionArtifactRow{
		SchemaVersion: executionArtifactRowVersion,
		Job: executionArtifactJob{
			JobID: jobID, Kind: "dispatch_" + string(operation), Operation: string(operation),
			State: "completed", AggregateType: "enforcement_action",
			AggregateID: common.ActionID, AggregateVersion: aggregateVersion,
			AvailableAt: databaseTime(issuedAt), Attempts: 1, MaxAttempts: 8,
			UpdatedAt: databaseTime(completedAt.Add(time.Second)),
		},
		Operation: executionArtifactOperation{
			JobID: jobID, Operation: string(operation), ActionID: common.ActionID,
			PolicyID: common.PolicyID, PolicyVersion: common.PolicyVersion,
			TargetIPv4: common.TargetIPv4, ArtifactHex: artifactHex,
			ArtifactDigest:           checked.Value().ArtifactDigest,
			OriginalAddDigest:        originalAddPointer,
			EvidenceSnapshotDigest:   common.EvidenceSnapshotDigest,
			ValidationSnapshotDigest: common.ValidationSnapshotDigest,
			AuthorizationDigest:      common.AuthorizationDigest,
			ActorID:                  common.ActorID, ReasonDigest: common.ReasonDigest,
			OwnedSchemaDigest: common.OwnedSchemaDigest,
			NotBefore:         databaseTime(common.NotBefore), ValidUntil: databaseTime(common.ExpiresAt),
		},
		Capability: executionArtifactCapability{
			CapabilityID: capabilityID, SchemaVersion: capability.CapabilitySchemaVersion,
			JobID: jobID, Operation: string(operation), ActionID: common.ActionID,
			PolicyID: common.PolicyID, PolicyVersion: common.PolicyVersion,
			TargetIPv4: common.TargetIPv4, ArtifactHex: artifactHex,
			ArtifactDigest:           checked.Value().ArtifactDigest,
			OriginalAddDigest:        originalAddPointer,
			EvidenceSnapshotDigest:   common.EvidenceSnapshotDigest,
			ValidationSnapshotDigest: common.ValidationSnapshotDigest,
			AuthorizationDigest:      common.AuthorizationDigest,
			ActorID:                  common.ActorID, ReasonDigest: common.ReasonDigest,
			OwnedSchemaDigest: common.OwnedSchemaDigest,
			JCSHex:            hex.EncodeToString(signedCapability.CanonicalBytes()),
			Digest:            verifiedCapability.Digest(),
			SignatureHex:      hex.EncodeToString(signedCapability.Signature()),
			NonceDigest:       nonceDigest,
			IssuedAt:          databaseTime(common.IssuedAt), NotBefore: databaseTime(common.NotBefore),
			ExpiresAt:  databaseTime(common.ExpiresAt),
			ConsumedAt: stringPointer(databaseTime(completedAt)),
		},
		Result: &executionArtifactResult{
			ResultID: resultID, SchemaVersion: capability.ResultSchemaVersion,
			CapabilityID: capabilityID, CapabilityDigest: verifiedCapability.Digest(),
			Operation: string(operation), ActionID: common.ActionID,
			ArtifactDigest: checked.Value().ArtifactDigest, TargetIPv4: common.TargetIPv4,
			Classification: string(classification), NFTExitClass: stringPointer(string(exitClass)),
			ReadbackState: string(readback), RemainingTTLSeconds: remainingTTL,
			OwnedSchemaDigest: common.OwnedSchemaDigest,
			StartedAt:         databaseTime(startedAt), CompletedAt: databaseTime(completedAt),
			JournalSequence: 1, ErrorCode: string(capability.ResultErrorNone),
			JCSHex:       hex.EncodeToString(signedResult.CanonicalBytes()),
			Digest:       checkedResult.Digest(),
			SignatureHex: hex.EncodeToString(signedResult.Signature()),
			PersistedAt:  databaseTime(completedAt.Add(time.Second)),
		},
		LifecycleApplication: &executionArtifactLifecycleApplication{
			SchemaVersion: lifecycleApplicationVersion,
			JobID:         jobID, CapabilityID: capabilityID,
			ResultID: resultID, ResultDigest: checkedResult.Digest(),
			ActionID: common.ActionID, Operation: string(operation),
			Classification: string(classification), ResultingState: resultingState,
			ResultingActionVersion: aggregateVersion,
			ProcessedAt:            databaseTime(completedAt.Add(time.Second)),
		},
	}
	return executionArtifactFixture{
		row: row, dispatchPublic: base.dispatchPublic, dispatchPrivate: base.dispatchPrivate,
		resultPublic: base.resultPublic, resultPrivate: base.resultPrivate,
		capabilityVerifier: base.capabilityVerifier, resultVerifier: base.resultVerifier,
		signedCapability: signedCapability, signedResult: signedResult,
		receivedAt: issuedAt, deadlineAt: completedAt,
	}
}

func mustResultVerifier(t *testing.T, identities keyidentity.Set, public ed25519.PublicKey) capability.ResultVerifier {
	t.Helper()
	verifier, err := capability.NewResultVerifier(identities.ResultKeyID, identities.ExecutorID, public)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func validateExecutionArtifactFixture(fixture executionArtifactFixture) error {
	encoded := executionArtifactFixtureBytes(nil, fixture)
	return ValidateExecutionArtifactRows(bytes.NewReader(encoded), fixture.dispatchPublic, fixture.resultPublic)
}

func executionArtifactFixtureBytes(t *testing.T, fixture executionArtifactFixture) []byte {
	encoded, err := json.Marshal(fixture.row)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		return nil
	}
	encoded = append(encoded, '\n')
	return encoded
}

func terminalJournalBytes(t *testing.T, fixture executionArtifactFixture, terminal bool) []byte {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "replay.json")
	opened, err := journal.Open(journal.Options{
		Path: path, CapabilityVerifier: fixture.capabilityVerifier, ResultVerifier: fixture.resultVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	started, err := opened.Begin(fixture.signedCapability, fixture.receivedAt, fixture.deadlineAt)
	if err != nil || started.Started().Sequence != 1 {
		t.Fatalf("begin journal fixture: %v %#v", err, started.Started())
	}
	if terminal {
		if snapshot, appended, err := opened.Complete(fixture.signedResult); err != nil || !appended || snapshot.StartedSequence() != 1 {
			t.Fatalf("complete journal fixture: %v %v %#v", err, appended, snapshot)
		}
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func resignCapabilityFixture(t *testing.T, fixture *executionArtifactFixture, raw []byte) {
	t.Helper()
	fixture.row.Capability.JCSHex = hex.EncodeToString(raw)
	fixture.row.Capability.Digest = digestBytes(raw)
	fixture.row.Capability.SignatureHex = hex.EncodeToString(signFixtureDomain(capability.CapabilitySigningDomain, raw, fixture.dispatchPrivate))
}

func resignResultFixture(t *testing.T, fixture *executionArtifactFixture, raw []byte) {
	t.Helper()
	fixture.row.Result.JCSHex = hex.EncodeToString(raw)
	fixture.row.Result.Digest = digestBytes(raw)
	fixture.row.Result.SignatureHex = hex.EncodeToString(signFixtureDomain(capability.ResultSigningDomain, raw, fixture.resultPrivate))
}

func signFixtureDomain(domain string, canonical []byte, private ed25519.PrivateKey) []byte {
	digest := sha256.Sum256(canonical)
	message := append(append([]byte(domain), '\n'), digest[:]...)
	return ed25519.Sign(private, message)
}

func decodeFixtureHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func databaseTime(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05.000000Z") }

func stringPointer(value string) *string { return &value }

func int32Pointer(value int32) *int32 { return &value }

func setFixtureDeadLetter(job *executionArtifactJob, capabilityDigest, state string) {
	job.DeadLetterState = stringPointer(state)
	job.DeadLetterJobID = stringPointer(job.JobID)
	job.DeadLetterKind = stringPointer(job.Kind)
	job.DeadLetterAggregateType = stringPointer(job.AggregateType)
	job.DeadLetterAggregateID = stringPointer(job.AggregateID)
	job.DeadLetterAggregateVersion = int32Pointer(job.AggregateVersion)
	job.DeadLetterAttempts = int32Pointer(job.Attempts)
	job.DeadLetterFailureCode = stringPointer("fixture_crash")
	job.DeadLetterFailureDigest = stringPointer(digestBytes([]byte("fixture_crash")))
	job.DeadLetterDeadAt = stringPointer(job.UpdatedAt)
	if state == "unresolved" {
		return
	}
	job.DeadLetterResolvedAt = stringPointer(job.UpdatedAt)
	job.DeadLetterResolutionActor = stringPointer("sentinelflow_recovery")
	job.DeadLetterResolutionDigest = stringPointer(recoveryStartedDigest(*job, capabilityDigest))
}
