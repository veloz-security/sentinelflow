package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

const (
	testDispatchKeyID = "dispatcher-test-v1"
	testResultKeyID   = "executor-result-test-v1"
	testExecutorID    = "executor-test"
	testTarget        = "203.0.113.20"
)

var (
	testAddArtifact    = []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n")
	testRevokeArtifact = []byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n")
)

type lockedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *lockedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *lockedClock) Set(value time.Time) {
	c.mu.Lock()
	c.now = value
	c.mu.Unlock()
}

type fakeRunner struct {
	mu                sync.Mutex
	target            string
	schema            string
	state             Observation
	queued            []Observation
	inspectErrors     map[int]error
	inspectCalls      int
	mutateCalls       int
	mutations         []Mutation
	mutationOutcome   MutationOutcome
	mutationError     error
	blockMutation     bool
	disableTransition bool
}

func newFakeRunner() *fakeRunner {
	runner := &fakeRunner{
		target: testTarget, schema: nftvalidate.PinnedLiveSchemaDigest,
		mutationOutcome: MutationOutcome{ExitClass: capability.NFTExitSuccess},
		inspectErrors:   make(map[int]error),
	}
	runner.state = runner.absent()
	return runner
}

func (r *fakeRunner) absent() Observation {
	return Observation{State: capability.ReadbackAbsent, TargetIPv4: r.target, OwnedSchemaDigest: r.schema}
}

func (r *fakeRunner) active(ttl uint64) Observation {
	return Observation{State: capability.ReadbackActive, TargetIPv4: r.target, OwnedSchemaDigest: r.schema,
		RemainingTTLSeconds: ttl}
}

func (r *fakeRunner) mismatch() Observation {
	return Observation{State: capability.ReadbackMismatch, TargetIPv4: r.target, OwnedSchemaDigest: r.schema}
}

func (r *fakeRunner) setState(value Observation) {
	r.mu.Lock()
	r.state = value
	r.mu.Unlock()
}

func (r *fakeRunner) queue(values ...Observation) {
	r.mu.Lock()
	r.queued = append(r.queued, values...)
	r.mu.Unlock()
}

func (r *fakeRunner) Mutate(ctx context.Context, mutation Mutation) (MutationOutcome, error) {
	r.mu.Lock()
	r.mutateCalls++
	copyMutation := Mutation{operation: mutation.operation, stdin: mutation.Stdin()}
	r.mutations = append(r.mutations, copyMutation)
	block := r.blockMutation
	outcome := r.mutationOutcome
	err := r.mutationError
	disableTransition := r.disableTransition
	r.mu.Unlock()
	if block {
		<-ctx.Done()
		return MutationOutcome{ExitClass: capability.NFTExitTimeout}, ctx.Err()
	}
	if !disableTransition && err == nil && outcome.ExitClass == capability.NFTExitSuccess {
		r.mu.Lock()
		switch mutation.Operation() {
		case capability.OperationAdd:
			r.state = r.active(1800)
		case capability.OperationRevoke:
			r.state = r.absent()
		}
		r.mu.Unlock()
	}
	return outcome, err
}

func (r *fakeRunner) Inspect(ctx context.Context, inspection Inspection) (Observation, error) {
	r.mu.Lock()
	r.inspectCalls++
	call := r.inspectCalls
	if err := r.inspectErrors[call]; err != nil {
		r.mu.Unlock()
		return Observation{}, err
	}
	if len(r.queued) != 0 {
		value := r.queued[0]
		r.queued = r.queued[1:]
		r.mu.Unlock()
		return value, nil
	}
	value := r.state
	r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if inspection.Path() != FixedNFTBinaryPath ||
		fmt.Sprint(inspection.Arguments()) != fmt.Sprint([]string{"--json", "list", "set", "inet", "sentinelflow", "blacklist_ipv4"}) {
		return Observation{}, errors.New("fixed inspect invocation changed")
	}
	return value, nil
}

func (r *fakeRunner) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutateCalls, r.inspectCalls
}

func (r *fakeRunner) lastMutation() Mutation {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.mutations) == 0 {
		return Mutation{}
	}
	value := r.mutations[len(r.mutations)-1]
	return Mutation{operation: value.operation, stdin: value.Stdin()}
}

type fixture struct {
	t               *testing.T
	base            time.Time
	clock           *lockedClock
	runner          *fakeRunner
	issuer          capability.CapabilityIssuer
	verifier        capability.CapabilityVerifier
	resultSigner    capability.ResultSigner
	resultVerifier  capability.ResultVerifier
	journal         *journal.Journal
	service         *Service
	resultIDs       atomic.Uint64
	dispatchPrivate ed25519.PrivateKey
	resultPrivate   ed25519.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Millisecond)
	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
	issuer, err := capability.NewCapabilityIssuer(testDispatchKeyID, dispatchPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewCapabilityVerifier(testDispatchKeyID, testExecutorID, dispatchPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	resultSigner, err := capability.NewResultSigner(testResultKeyID, testExecutorID, resultPrivate)
	if err != nil {
		t.Fatal(err)
	}
	resultVerifier, err := capability.NewResultVerifier(testResultKeyID, testExecutorID, resultPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	journalValue, err := journal.Open(journal.Options{
		Path: filepath.Join(directory, "executor.journal"), CapabilityVerifier: verifier, ResultVerifier: resultVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journalValue.Close() })
	value := &fixture{
		t: t, base: base, clock: &lockedClock{now: base}, runner: newFakeRunner(),
		issuer: issuer, verifier: verifier, resultSigner: resultSigner, resultVerifier: resultVerifier,
		journal: journalValue, dispatchPrivate: dispatchPrivate, resultPrivate: resultPrivate,
	}
	value.service = value.newService(value.journal, value.runner, value.resultSigner)
	return value
}

func (f *fixture) newService(replay ReplayJournal, runner Runner, signer capability.ResultSigner) *Service {
	f.t.Helper()
	service, err := New(Config{
		CapabilityVerifier: f.verifier, ResultSigner: signer, Journal: replay, Runner: runner,
		DispatchKeyID: testDispatchKeyID,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	service.clock = f.clock.Now
	service.newResultID = func() (string, error) {
		value := f.resultIDs.Add(1)
		return fmt.Sprintf("019b0000-0000-4000-8000-%012d", value), nil
	}
	return service
}

func (f *fixture) signed(operation capability.Operation, number int) capability.SignedCapability {
	f.t.Helper()
	return f.signedAt(operation, number, f.base, testAddArtifact)
}

func (f *fixture) signedAt(operation capability.Operation, number int, base time.Time, addArtifact []byte) capability.SignedCapability {
	f.t.Helper()
	common := capability.Common{
		CapabilityID: id(number), JobID: id(number + 100), ActionID: id(number + 200), PolicyID: id(number + 300),
		PolicyVersion: 1, TargetIPv4: testTarget,
		EvidenceSnapshotDigest: digest("evidence"), ValidationSnapshotDigest: digest("validation"),
		AuthorizationDigest: digest("authorization"), ActorID: "admin", ReasonDigest: digest("reason"),
		OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest,
		IssuedAt:          base.Add(-time.Second), NotBefore: base.Add(-time.Second), ExpiresAt: base.Add(30 * time.Second),
		Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(number)}, 16)),
	}
	var checked capability.CheckedCapability
	var err error
	switch operation {
	case capability.OperationAdd:
		checked, err = capability.CheckAdd(capability.Add{Common: common, CanonicalCommand: addArtifact})
	case capability.OperationRevoke:
		checked, err = capability.CheckRevoke(capability.Revoke{Common: common, OriginalAddDigest: digestBytes(testAddArtifact), CanonicalDelete: testRevokeArtifact})
	case capability.OperationInspect:
		checked, err = capability.CheckInspect(capability.Inspect{
			Common: common, OriginalAddDigest: digestBytes(testAddArtifact),
			Artifact: capability.InspectArtifact{
				SchemaVersion: capability.InspectSchemaVersion, ActionID: common.ActionID, TargetIPv4: common.TargetIPv4,
				OriginalAddDigest: digestBytes(testAddArtifact), OwnedSchemaDigest: common.OwnedSchemaDigest, Purpose: "reconciliation",
			},
		})
	default:
		f.t.Fatalf("unsupported operation %q", operation)
	}
	if err != nil {
		f.t.Fatal(err)
	}
	signed, err := f.issuer.Sign(checked)
	if err != nil {
		f.t.Fatal(err)
	}
	return signed
}

func (f *fixture) signedAddWithSchema(number int, schema string) capability.SignedCapability {
	f.t.Helper()
	seed := f.signed(capability.OperationAdd, number)
	verified, err := f.verifier.Verify(seed)
	if err != nil {
		f.t.Fatal(err)
	}
	value := verified.Value()
	checked, err := capability.CheckAdd(capability.Add{
		Common: capability.Common{
			CapabilityID: value.CapabilityID, JobID: value.JobID, ActionID: value.ActionID,
			PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion, TargetIPv4: value.TargetIPv4,
			EvidenceSnapshotDigest: value.EvidenceSnapshotDigest, ValidationSnapshotDigest: value.ValidationSnapshotDigest,
			AuthorizationDigest: value.AuthorizationDigest, ActorID: value.ActorID, ReasonDigest: value.ReasonDigest,
			OwnedSchemaDigest: schema, IssuedAt: value.IssuedAt, NotBefore: value.NotBefore,
			ExpiresAt: value.ExpiresAt, Nonce: value.Nonce,
		},
		CanonicalCommand: testAddArtifact,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	signed, err := f.issuer.Sign(checked)
	if err != nil {
		f.t.Fatal(err)
	}
	return signed
}

func (f *fixture) verifiedResult(signedCapability capability.SignedCapability, signedResult capability.SignedResult) capability.ResultValue {
	f.t.Helper()
	verifiedCapability, err := f.verifier.Verify(signedCapability)
	if err != nil {
		f.t.Fatal(err)
	}
	verifiedResult, err := f.resultVerifier.Verify(signedResult)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := verifiedResult.BindTo(verifiedCapability); err != nil {
		f.t.Fatal(err)
	}
	return verifiedResult.Value()
}

func id(value int) string { return fmt.Sprintf("019b0000-0000-7000-8000-%012d", value) }

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func requireCode(t *testing.T, err error, expected ErrorCode) {
	t.Helper()
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Code != expected {
		t.Fatalf("error = %v, want executor code %q", err, expected)
	}
}
