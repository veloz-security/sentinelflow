package dispatchruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/dispatchstore"
	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/keyidentity"
)

func TestRuntimePersistsCapabilityThenVerifiedResultBeforeFencedFinish(t *testing.T) {
	fixture := newRuntimeFixture(t, capability.OperationAdd)
	outcome, err := fixture.runtime.ProcessNext(context.Background())
	if err != nil || outcome != OutcomeCompleted {
		t.Fatalf("outcome=%s err=%v", outcome, err)
	}
	want := []string{"claim_recovery", "claim", "recover", "persist_capability", "persist_result", "finish_completed"}
	if !equalStrings(fixture.store.calls, want) {
		t.Fatalf("store call order=%v want=%v", fixture.store.calls, want)
	}
	if fixture.store.lastFinish.Result == nil || fixture.exchange.calls != 1 {
		t.Fatal("result was not durably fenced before completion")
	}
	if _, err := fixture.capabilityVerifier.Verify(fixture.store.lastCapability); err != nil {
		t.Fatalf("persisted capability signature: %v", err)
	}
}

func TestRuntimeRetriesExactCapabilityOnlyInsideSameLiveLease(t *testing.T) {
	fixture := newRuntimeFixture(t, capability.OperationAdd)
	fixture.exchange.errors = []error{ErrTransport, nil}
	outcome, err := fixture.runtime.ProcessNext(context.Background())
	if err != nil || outcome != OutcomeCompleted || fixture.exchange.calls != 2 {
		t.Fatalf("outcome=%s calls=%d err=%v", outcome, fixture.exchange.calls, err)
	}
	if len(fixture.exchange.capabilities) != 2 ||
		!sameSignedCapability(fixture.exchange.capabilities[0], fixture.exchange.capabilities[1]) {
		t.Fatal("same-lease transport retry changed the persisted capability")
	}
}

func TestRuntimeNeverStartsExpiredCapabilityReplay(t *testing.T) {
	fixture := newRuntimeFixture(t, capability.OperationAdd)
	fixture.runtime.config.CapabilityTTL = time.Second
	fixture.exchange.errors = []error{ErrTransport, nil}
	fixture.clock.sleepAdvance = 2 * time.Second
	outcome, err := fixture.runtime.ProcessNext(context.Background())
	if !errors.Is(err, ErrRecoverRequired) || outcome != OutcomeRecoverRequired ||
		fixture.exchange.calls != 1 || fixture.store.finishCalls != 0 {
		t.Fatalf("outcome=%s exchange=%d finish=%d err=%v", outcome, fixture.exchange.calls, fixture.store.finishCalls, err)
	}
}

func TestRuntimeAcceptsLateReadOnlyRecoveryButRejectsLateMutation(t *testing.T) {
	for _, test := range []struct {
		name           string
		classification capability.Classification
		exit           capability.NFTExitClass
		wantOutcome    Outcome
		wantErr        error
		wantPersist    int
		startOffset    time.Duration
	}{
		{
			name: "read-only recovery", classification: capability.ClassificationRecoveredActive,
			exit: capability.NFTExitNotInvoked, wantOutcome: OutcomeCompleted, wantPersist: 1,
			startOffset: time.Millisecond,
		},
		{
			name: "late mutation", classification: capability.ClassificationApplied,
			exit: capability.NFTExitSuccess, wantOutcome: OutcomeRecoverRequired,
			wantErr: ErrRecoverRequired, startOffset: time.Millisecond,
		},
		{
			name: "mutation at half-open expiry boundary", classification: capability.ClassificationApplied,
			exit: capability.NFTExitSuccess, wantOutcome: OutcomeRecoverRequired,
			wantErr: ErrRecoverRequired, startOffset: 0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRuntimeFixture(t, capability.OperationAdd)
			fixture.runtime.config.CapabilityTTL = time.Second
			fixture.exchange.resultFactory = func(verified capability.VerifiedCapability) capability.SignedResult {
				started := verified.Value().ExpiresAt.Add(test.startOffset)
				return signAddResult(t, fixture.resultSigner, verified, test.classification, test.exit, started)
			}
			outcome, err := fixture.runtime.ProcessNext(context.Background())
			if outcome != test.wantOutcome || !errors.Is(err, test.wantErr) ||
				fixture.store.persistResultCalls != test.wantPersist {
				t.Fatalf("outcome=%s persist=%d err=%v", outcome, fixture.store.persistResultCalls, err)
			}
		})
	}
}

func TestRuntimeRejectsWrongResultKeyAndDigestBinding(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(*runtimeFixture) capability.SignedResult
	}{
		{
			name: "wrong key",
			build: func(f *runtimeFixture) capability.SignedResult {
				verified, _ := f.capabilityVerifier.Verify(f.store.lastCapability)
				wrongPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
				wrongSigner, _ := capability.NewResultSigner(
					f.identities.ResultKeyID, f.identities.ExecutorID, wrongPrivate,
				)
				return signAddResult(t, wrongSigner, verified, capability.ClassificationApplied,
					capability.NFTExitSuccess, verified.Value().NotBefore)
			},
		},
		{
			name: "wrong digest binding",
			build: func(f *runtimeFixture) capability.SignedResult {
				otherClaim := fixtureClaim(capability.OperationAdd, f.clock.now, 1, 3)
				otherClaim.job.jobID = "019b0000-0000-7000-8000-000000000909"
				issued, err := f.issuer.Issue(otherClaim, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				return signAddResult(t, f.resultSigner, issued.Verified,
					capability.ClassificationApplied, capability.NFTExitSuccess,
					issued.Verified.Value().NotBefore)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRuntimeFixture(t, capability.OperationAdd)
			fixture.exchange.resultFactory = func(capability.VerifiedCapability) capability.SignedResult {
				return test.build(fixture)
			}
			outcome, err := fixture.runtime.ProcessNext(context.Background())
			if outcome != OutcomeRecoverRequired || !errors.Is(err, ErrRecoverRequired) ||
				fixture.store.persistResultCalls != 0 || fixture.store.finishCalls != 0 {
				t.Fatalf("outcome=%s persist=%d finish=%d err=%v", outcome,
					fixture.store.persistResultCalls, fixture.store.finishCalls, err)
			}
		})
	}
}

func TestRuntimeRetriesExactResultPersistenceAndPreservesUncertainState(t *testing.T) {
	for _, test := range []struct {
		name          string
		capabilityErr error
		resultErrors  []error
		finishErr     error
		wantOutcome   Outcome
		wantErr       error
		wantPersists  int
		wantFinishes  int
	}{
		{
			name: "idempotent result retry", resultErrors: []error{dispatchstore.ErrUnavailable, nil},
			wantOutcome: OutcomeCompleted, wantPersists: 2, wantFinishes: 1,
		},
		{
			name: "capability conflict requires recovery", capabilityErr: dispatchstore.ErrConflict,
			wantOutcome: OutcomeRecoverRequired, wantErr: ErrRecoverRequired,
		},
		{
			name: "stale result lease requires recovery", resultErrors: []error{dispatchstore.ErrLeaseLost},
			wantOutcome: OutcomeRecoverRequired, wantErr: ErrRecoverRequired, wantPersists: 1,
		},
		{
			name: "finish uncertainty preserves durable result", finishErr: dispatchstore.ErrLeaseLost,
			wantOutcome: OutcomeRecoverRequired, wantErr: ErrRecoverRequired,
			wantPersists: 1, wantFinishes: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRuntimeFixture(t, capability.OperationAdd)
			fixture.store.persistCapabilityErr = test.capabilityErr
			fixture.store.persistResultErrors = test.resultErrors
			fixture.store.finishErr = test.finishErr
			outcome, err := fixture.runtime.ProcessNext(context.Background())
			if outcome != test.wantOutcome || !errors.Is(err, test.wantErr) ||
				fixture.store.persistResultCalls != test.wantPersists ||
				fixture.store.finishCalls != test.wantFinishes {
				t.Fatalf("outcome=%s persists=%d finishes=%d err=%v", outcome,
					fixture.store.persistResultCalls, fixture.store.finishCalls, err)
			}
		})
	}
}

func TestRuntimeRecoversExactPersistedStateBeforeMintingNewAuthority(t *testing.T) {
	t.Run("capability only", func(t *testing.T) {
		fixture := newRuntimeFixture(t, capability.OperationAdd)
		issued, err := fixture.issuer.Issue(fixture.store.claim, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		fixture.store.recovery = RecoveredExecution{
			state:            RecoveryCapability,
			capability:       StoredCapability{claim: fixture.store.claim, signed: issued.Signed},
			signedCapability: issued.Signed,
		}
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if err != nil || outcome != OutcomeCompleted || fixture.store.persistCapabilityCalls != 0 ||
			fixture.exchange.calls != 1 || !sameSignedCapability(issued.Signed, fixture.exchange.capabilities[0]) {
			t.Fatalf("outcome=%s cap_persist=%d exchange=%d err=%v", outcome,
				fixture.store.persistCapabilityCalls, fixture.exchange.calls, err)
		}
	})

	t.Run("durable result", func(t *testing.T) {
		fixture := newRuntimeFixture(t, capability.OperationAdd)
		issued, err := fixture.issuer.Issue(fixture.store.claim, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		signedResult := signAddResult(t, fixture.resultSigner, issued.Verified,
			capability.ClassificationApplied, capability.NFTExitSuccess,
			issued.Verified.Value().NotBefore)
		verifiedResult, err := fixture.runtime.resultVerifier.Verify(signedResult)
		if err != nil {
			t.Fatal(err)
		}
		storedCapability := StoredCapability{claim: fixture.store.claim, signed: issued.Signed}
		fixture.store.recovery = RecoveredExecution{
			state: RecoveryResult, capability: storedCapability, signedCapability: issued.Signed,
			result:       StoredResult{capability: storedCapability, verified: verifiedResult},
			signedResult: signedResult,
		}
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if err != nil || outcome != OutcomeCompleted || fixture.exchange.calls != 0 ||
			fixture.store.persistCapabilityCalls != 0 || fixture.store.persistResultCalls != 0 ||
			fixture.store.finishCalls != 1 {
			t.Fatalf("outcome=%s exchange=%d cap=%d result=%d finish=%d err=%v", outcome,
				fixture.exchange.calls, fixture.store.persistCapabilityCalls,
				fixture.store.persistResultCalls, fixture.store.finishCalls, err)
		}
	})

	t.Run("expired capability uses only recovery exchange", func(t *testing.T) {
		fixture := newRuntimeFixture(t, capability.OperationAdd)
		issued, err := fixture.issuer.Issue(fixture.store.claim, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		fixture.clock.now = issued.Verified.Value().ExpiresAt
		fixture.store.recovery = RecoveredExecution{
			state:            RecoveryCapability,
			capability:       StoredCapability{claim: fixture.store.claim, signed: issued.Signed},
			signedCapability: issued.Signed,
		}
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if outcome != OutcomeCompleted || err != nil || fixture.exchange.calls != 0 ||
			fixture.exchange.recoveryCalls != 1 || fixture.store.persistResultCalls != 1 ||
			fixture.store.finishCalls != 1 {
			t.Fatalf("outcome=%s exchange=%d recovery=%d result=%d finish=%d err=%v", outcome,
				fixture.exchange.calls, fixture.exchange.recoveryCalls,
				fixture.store.persistResultCalls, fixture.store.finishCalls, err)
		}
	})
}

func TestRuntimeExpiredPersistedCapabilityRecoveryOnlyExchange(t *testing.T) {
	setup := func(t *testing.T) (*runtimeFixture, IssuedCapability) {
		t.Helper()
		fixture := newRuntimeFixture(t, capability.OperationAdd)
		issued, err := fixture.issuer.Issue(fixture.store.claim, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		fixture.clock.now = issued.Verified.Value().ExpiresAt
		fixture.store.recovery = RecoveredExecution{
			state: RecoveryCapability,
			capability: StoredCapability{
				claim: fixture.store.claim, signed: issued.Signed, verified: issued.Verified,
			},
			signedCapability: issued.Signed,
		}
		return fixture, issued
	}

	t.Run("terminal journal replay persists and finishes", func(t *testing.T) {
		fixture, issued := setup(t)
		fixture.exchange.recoveryResultFactory = func(verified capability.VerifiedCapability) capability.SignedResult {
			return signAddResult(t, fixture.resultSigner, verified, capability.ClassificationApplied,
				capability.NFTExitSuccess, issued.Verified.Value().NotBefore)
		}
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if outcome != OutcomeCompleted || err != nil || fixture.exchange.calls != 0 ||
			fixture.exchange.recoveryCalls != 1 || fixture.store.persistResultCalls != 1 ||
			fixture.store.finishCalls != 1 || fixture.store.lastFinish.Result == nil {
			t.Fatalf("outcome=%s ordinary=%d recovery=%d persist=%d finish=%d err=%v", outcome,
				fixture.exchange.calls, fixture.exchange.recoveryCalls,
				fixture.store.persistResultCalls, fixture.store.finishCalls, err)
		}
	})

	t.Run("started-only journal returns read-only recovery", func(t *testing.T) {
		fixture, issued := setup(t)
		fixture.exchange.recoveryResultFactory = func(verified capability.VerifiedCapability) capability.SignedResult {
			return signAddResult(t, fixture.resultSigner, verified,
				capability.ClassificationRecoveredActive, capability.NFTExitNotInvoked,
				issued.Verified.Value().ExpiresAt.Add(time.Millisecond))
		}
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if outcome != OutcomeCompleted || err != nil || fixture.exchange.recoveryCalls != 1 ||
			fixture.store.persistResultCalls != 1 || fixture.store.finishCalls != 1 {
			t.Fatalf("outcome=%s recovery=%d persist=%d finish=%d err=%v", outcome,
				fixture.exchange.recoveryCalls, fixture.store.persistResultCalls,
				fixture.store.finishCalls, err)
		}
	})

	t.Run("unseen expired journal fails before persistence", func(t *testing.T) {
		fixture, _ := setup(t)
		fixture.exchange.recoveryErrors = []error{ErrTransport, ErrTransport}
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if outcome != OutcomeRecoverRequired || !errors.Is(err, ErrRecoverRequired) ||
			fixture.exchange.calls != 0 || fixture.exchange.recoveryCalls != 2 ||
			fixture.store.persistResultCalls != 0 || fixture.store.finishCalls != 0 {
			t.Fatalf("outcome=%s ordinary=%d recovery=%d persist=%d finish=%d err=%v", outcome,
				fixture.exchange.calls, fixture.exchange.recoveryCalls,
				fixture.store.persistResultCalls, fixture.store.finishCalls, err)
		}
	})

	t.Run("wrong binding fails closed", func(t *testing.T) {
		fixture, _ := setup(t)
		other := newRuntimeFixture(t, capability.OperationAdd)
		other.store.claim.job.actionID = "019b0000-0000-7000-8000-000000000299"
		otherIssued, issueErr := other.issuer.Issue(other.store.claim, time.Second)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		fixture.exchange.recoveryResultFactory = func(capability.VerifiedCapability) capability.SignedResult {
			return signAddResult(t, fixture.resultSigner, otherIssued.Verified,
				capability.ClassificationApplied, capability.NFTExitSuccess,
				otherIssued.Verified.Value().NotBefore)
		}
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if outcome != OutcomeRecoverRequired || !errors.Is(err, ErrRecoverRequired) ||
			fixture.store.persistResultCalls != 0 || fixture.store.finishCalls != 0 {
			t.Fatalf("outcome=%s persist=%d finish=%d err=%v", outcome,
				fixture.store.persistResultCalls, fixture.store.finishCalls, err)
		}
	})

	t.Run("post-expiry mutation attestation is rejected", func(t *testing.T) {
		fixture, issued := setup(t)
		fixture.exchange.recoveryResultFactory = func(verified capability.VerifiedCapability) capability.SignedResult {
			return signAddResult(t, fixture.resultSigner, verified, capability.ClassificationApplied,
				capability.NFTExitSuccess, issued.Verified.Value().ExpiresAt.Add(time.Millisecond))
		}
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if outcome != OutcomeRecoverRequired || !errors.Is(err, ErrRecoverRequired) ||
			fixture.store.persistResultCalls != 0 || fixture.store.finishCalls != 0 {
			t.Fatalf("outcome=%s persist=%d finish=%d err=%v", outcome,
				fixture.store.persistResultCalls, fixture.store.finishCalls, err)
		}
	})

	t.Run("expired lease blocks recovery exchange", func(t *testing.T) {
		fixture, _ := setup(t)
		fixture.clock.now = fixture.store.claim.LeaseUntil()
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if outcome != OutcomeRecoverRequired || !errors.Is(err, ErrRecoverRequired) ||
			fixture.exchange.recoveryCalls != 0 || fixture.store.persistResultCalls != 0 ||
			fixture.store.finishCalls != 0 {
			t.Fatalf("outcome=%s recovery=%d persist=%d finish=%d err=%v", outcome,
				fixture.exchange.recoveryCalls, fixture.store.persistResultCalls,
				fixture.store.finishCalls, err)
		}
	})
}

func TestRuntimeSeparatesPreCapabilityRetryFromTerminalDeadLetter(t *testing.T) {
	for _, test := range []struct {
		name        string
		claim       Claim
		entropy     io.Reader
		wantOutcome Outcome
		wantFinish  FinishOutcome
	}{
		{
			name: "entropy transient", entropy: errReader{},
			claim:       fixtureClaim(capability.OperationAdd, time.Now().UTC().Truncate(time.Millisecond), 1, 3),
			wantOutcome: OutcomeRetry, wantFinish: FinishRetry,
		},
		{
			name: "final entropy attempt", entropy: errReader{},
			claim:       fixtureClaim(capability.OperationAdd, time.Now().UTC().Truncate(time.Millisecond), 3, 3),
			wantOutcome: OutcomeDead, wantFinish: FinishDead,
		},
		{
			name: "invalid exact artifact",
			claim: func() Claim {
				claim := fixtureClaim(capability.OperationAdd, time.Now().UTC().Truncate(time.Millisecond), 1, 3)
				claim.job.artifact = []byte("not an nft artifact")
				claim.job.artifactDigest = digestTestBytes(claim.job.artifact)
				return claim
			}(),
			wantOutcome: OutcomeDead, wantFinish: FinishDead,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRuntimeFixtureForClaim(t, test.claim, test.entropy)
			outcome, err := fixture.runtime.ProcessNext(context.Background())
			if outcome != test.wantOutcome || fixture.store.lastFinish.Outcome != test.wantFinish ||
				fixture.store.persistCapabilityCalls != 0 {
				t.Fatalf("outcome=%s finish=%s cap_persist=%d err=%v", outcome,
					fixture.store.lastFinish.Outcome, fixture.store.persistCapabilityCalls, err)
			}
		})
	}
}

func TestRuntimeCancellationBeforePersistenceRequeuesButAfterPersistencePreserves(t *testing.T) {
	t.Run("before persistence", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		claim := fixtureClaim(capability.OperationAdd, time.Now().UTC().Truncate(time.Millisecond), 1, 3)
		fixture := newRuntimeFixtureForClaim(t, claim, &cancelReader{cancel: cancel})
		outcome, err := fixture.runtime.ProcessNext(ctx)
		if outcome != OutcomeRetry || !errors.Is(err, ErrCancelled) ||
			fixture.store.lastFinish.Outcome != FinishRetry || fixture.store.persistCapabilityCalls != 0 {
			t.Fatalf("outcome=%s finish=%s persist=%d err=%v", outcome,
				fixture.store.lastFinish.Outcome, fixture.store.persistCapabilityCalls, err)
		}
	})

	t.Run("after persistence", func(t *testing.T) {
		fixture := newRuntimeFixture(t, capability.OperationAdd)
		fixture.exchange.errors = []error{ErrCancelled}
		outcome, err := fixture.runtime.ProcessNext(context.Background())
		if outcome != OutcomeRecoverRequired || !errors.Is(err, ErrRecoverRequired) ||
			fixture.store.persistCapabilityCalls != 1 || fixture.store.finishCalls != 0 {
			t.Fatalf("outcome=%s cap=%d finish=%d err=%v", outcome,
				fixture.store.persistCapabilityCalls, fixture.store.finishCalls, err)
		}
	})
}

func TestRunStopsCleanlyOnCancellationWhileIdle(t *testing.T) {
	fixture := newRuntimeFixture(t, capability.OperationAdd)
	fixture.store.found = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.runtime.Run(ctx); err != nil {
		t.Fatalf("Run cancellation error=%v", err)
	}
}

func TestIssuerConstructsAddRevokeAndCanonicalReadOnlyInspect(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, operation := range []capability.Operation{
		capability.OperationAdd, capability.OperationRevoke, capability.OperationInspect,
	} {
		t.Run(string(operation), func(t *testing.T) {
			fixture := newRuntimeFixture(t, operation)
			issued, err := fixture.issuer.Issue(fixture.store.claim, time.Minute)
			if err != nil || issued.Verified.Value().Operation != operation ||
				!bytes.Equal(issued.Signed.ArtifactBytes(), fixture.store.claim.job.artifact) {
				t.Fatalf("operation=%s err=%v", issued.Verified.Value().Operation, err)
			}
		})
	}
	claim := fixtureClaim(capability.OperationInspect, now, 1, 3)
	claim.job.artifact = append([]byte(" "), claim.job.artifact...)
	claim.job.artifactDigest = digestTestBytes(claim.job.artifact)
	fixture := newRuntimeFixtureForClaim(t, claim, nil)
	if _, err := fixture.issuer.Issue(claim, time.Minute); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("non-canonical inspect error=%v", err)
	}
}

func TestRuntimeFormattingAndErrorsRedactAuthority(t *testing.T) {
	fixture := newRuntimeFixture(t, capability.OperationAdd)
	client := &UDSClient{socketPath: "/private/executor.sock"}
	formatted := fmt.Sprintf("%#v %#v %#v %#v %v",
		fixture.runtime, fixture.issuer, client, fixture.store.claim.Job(), ErrRecoverRequired)
	for _, forbidden := range []string{
		"203.0.113.20", "add element", "/private/executor.sock", "PRIVATE KEY",
	} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("formatted authority leaked %q", forbidden)
		}
	}
	if !strings.Contains(formatted, "REDACTED") ||
		strings.Contains(ErrRecoverRequired.Error(), "203.0.113.20") {
		t.Fatal("redacted formatting contract was not retained")
	}
}

type runtimeFixture struct {
	runtime            *Runtime
	store              *fakeStore
	exchange           *fakeExchange
	clock              *fakeClock
	issuer             *Issuer
	capabilityVerifier capability.CapabilityVerifier
	resultSigner       capability.ResultSigner
	identities         keyidentity.Set
}

func newRuntimeFixture(t *testing.T, operation capability.Operation) *runtimeFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	return newRuntimeFixtureForClaim(t, fixtureClaim(operation, now, 1, 3), nil)
}

func newRuntimeFixtureForClaim(t *testing.T, claim Claim, entropy io.Reader) *runtimeFixture {
	t.Helper()
	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	identities, err := keyidentity.Derive(
		dispatchPrivate.Public().(ed25519.PublicKey), resultPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	capabilityIssuer, _ := capability.NewCapabilityIssuer(identities.DispatchKeyID, dispatchPrivate)
	capabilityVerifier, _ := capability.NewCapabilityVerifier(
		identities.DispatchKeyID, identities.ExecutorID, dispatchPrivate.Public().(ed25519.PublicKey),
	)
	resultSigner, _ := capability.NewResultSigner(identities.ResultKeyID, identities.ExecutorID, resultPrivate)
	resultVerifier, _ := capability.NewResultVerifier(
		identities.ResultKeyID, identities.ExecutorID, resultPrivate.Public().(ed25519.PublicKey),
	)
	if entropy == nil {
		entropy = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32*16))
	}
	issuer, err := NewIssuer(capabilityIssuer, capabilityVerifier, entropy)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{
		claim: claim, found: true,
		recovery: RecoveredExecution{state: RecoveryNone},
	}
	clock := &fakeClock{now: claim.claimedAt}
	exchange := &fakeExchange{verifier: capabilityVerifier, signer: resultSigner}
	config := DefaultConfig("dispatcher-test")
	runtime, err := New(store, issuer, resultVerifier, exchange, config, Dependencies{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return &runtimeFixture{
		runtime: runtime, store: store, exchange: exchange, clock: clock, issuer: issuer,
		capabilityVerifier: capabilityVerifier, resultSigner: resultSigner, identities: identities,
	}
}

func fixtureClaim(operation capability.Operation, now time.Time, attempt, maxAttempts int32) Claim {
	const (
		jobID    = "019b0000-0000-7000-8000-000000000101"
		actionID = "019b0000-0000-7000-8000-000000000201"
		policyID = "019b0000-0000-7000-8000-000000000202"
		target   = "203.0.113.20"
	)
	original := "sha256:" + stringsRepeat("6", 64)
	owned := "sha256:" + stringsRepeat("5", 64)
	var artifact []byte
	kind := "dispatch_" + string(operation)
	hasOriginal := operation != capability.OperationAdd
	switch operation {
	case capability.OperationAdd:
		artifact = []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1m }\n")
	case capability.OperationRevoke:
		artifact = []byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n")
	case capability.OperationInspect:
		artifact = []byte(`{"action_id":"019b0000-0000-7000-8000-000000000201","operation":"inspect","original_add_digest":"` + original + `","owned_schema_digest":"` + owned + `","purpose":"reconciliation","schema_version":"nft-inspect-v1","target_ipv4":"203.0.113.20"}`)
	}
	job := Job{
		jobID: jobID, kind: kind, operation: operation, actionID: actionID,
		policyID: policyID, policyVersion: 1, targetIPv4: target,
		artifact: artifact, artifactDigest: digestTestBytes(artifact),
		originalAddDigest: original, hasOriginalAddDigest: hasOriginal,
		evidenceSnapshotDigest:   "sha256:" + stringsRepeat("1", 64),
		validationSnapshotDigest: "sha256:" + stringsRepeat("2", 64),
		authorizationDigest:      "sha256:" + stringsRepeat("3", 64), actorID: "admin-test",
		reasonDigest: "sha256:" + stringsRepeat("4", 64), ownedSchemaDigest: owned,
		availableAt: now.Add(-time.Second), attempts: attempt - 1, maxAttempts: maxAttempts,
		notBefore: now.Add(-time.Second), validUntil: now.Add(2 * time.Minute),
	}
	return Claim{
		job: job, claimedAt: now, leaseUntil: now.Add(time.Minute), attempt: attempt,
	}
}

type fakeStore struct {
	mu                     sync.Mutex
	claim                  Claim
	found                  bool
	claimErr               error
	recoveryClaim          Claim
	recoveryFound          bool
	recoveryClaimErr       error
	recovery               RecoveredExecution
	recoverErrors          []error
	recoverCalls           int
	persistCapabilityErr   error
	persistResultErrors    []error
	finishErr              error
	calls                  []string
	persistCapabilityCalls int
	persistResultCalls     int
	finishCalls            int
	lastCapability         capability.SignedCapability
	lastResult             capability.SignedResult
	lastFinish             FinishRequest
}

func (s *fakeStore) ClaimNext(context.Context, ClaimRequest) (Claim, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "claim")
	return s.claim, s.found, s.claimErr
}

func (s *fakeStore) ClaimRecoveryNext(context.Context, ClaimRequest) (Claim, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "claim_recovery")
	return s.recoveryClaim, s.recoveryFound, s.recoveryClaimErr
}

func (s *fakeStore) Recover(context.Context, Claim) (RecoveredExecution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "recover")
	index := s.recoverCalls
	s.recoverCalls++
	if index < len(s.recoverErrors) && s.recoverErrors[index] != nil {
		return RecoveredExecution{}, s.recoverErrors[index]
	}
	return s.recovery, nil
}

func (s *fakeStore) PersistCapability(
	_ context.Context,
	claim Claim,
	signed capability.SignedCapability,
	verified capability.VerifiedCapability,
) (StoredCapability, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "persist_capability")
	s.persistCapabilityCalls++
	s.lastCapability = signed
	if s.persistCapabilityErr != nil {
		return StoredCapability{}, s.persistCapabilityErr
	}
	return StoredCapability{claim: claim, signed: signed, verified: verified}, nil
}

func (s *fakeStore) PersistResult(
	_ context.Context,
	stored StoredCapability,
	signed capability.SignedResult,
	verified capability.VerifiedResult,
) (StoredResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "persist_result")
	index := s.persistResultCalls
	s.persistResultCalls++
	s.lastResult = signed
	if index < len(s.persistResultErrors) && s.persistResultErrors[index] != nil {
		return StoredResult{}, s.persistResultErrors[index]
	}
	return StoredResult{capability: stored, verified: verified}, nil
}

func (s *fakeStore) Finish(_ context.Context, _ Claim, request FinishRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishCalls++
	s.lastFinish = request
	s.calls = append(s.calls, "finish_"+string(request.Outcome))
	return s.finishErr
}

type fakeExchange struct {
	verifier              capability.CapabilityVerifier
	signer                capability.ResultSigner
	errors                []error
	calls                 int
	recoveryErrors        []error
	recoveryCalls         int
	capabilities          []capability.SignedCapability
	resultFactory         func(capability.VerifiedCapability) capability.SignedResult
	recoveryResultFactory func(capability.VerifiedCapability) capability.SignedResult
}

func (e *fakeExchange) ExchangeRecovery(
	_ context.Context,
	signed capability.SignedCapability,
) (capability.SignedResult, error) {
	e.capabilities = append(e.capabilities, signed)
	index := e.recoveryCalls
	e.recoveryCalls++
	if index < len(e.recoveryErrors) && e.recoveryErrors[index] != nil {
		return capability.SignedResult{}, e.recoveryErrors[index]
	}
	verified, err := e.verifier.Verify(signed)
	if err != nil {
		return capability.SignedResult{}, ErrContractRejected
	}
	if e.recoveryResultFactory != nil {
		return e.recoveryResultFactory(verified), nil
	}
	if e.resultFactory != nil {
		return e.resultFactory(verified), nil
	}
	return signAddResult(nil, e.signer, verified, capability.ClassificationApplied,
		capability.NFTExitSuccess, verified.Value().NotBefore), nil
}

func (e *fakeExchange) Exchange(
	_ context.Context,
	signed capability.SignedCapability,
) (capability.SignedResult, error) {
	e.capabilities = append(e.capabilities, signed)
	index := e.calls
	e.calls++
	if index < len(e.errors) && e.errors[index] != nil {
		return capability.SignedResult{}, e.errors[index]
	}
	verified, err := e.verifier.Verify(signed)
	if err != nil {
		return capability.SignedResult{}, ErrContractRejected
	}
	if e.resultFactory != nil {
		return e.resultFactory(verified), nil
	}
	return signAddResult(nil, e.signer, verified, capability.ClassificationApplied,
		capability.NFTExitSuccess, verified.Value().NotBefore), nil
}

type fakeClock struct {
	now          time.Time
	sleepAdvance time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	advance := duration
	if c.sleepAdvance != 0 {
		advance = c.sleepAdvance
	}
	c.now = c.now.Add(advance)
	return nil
}

func signAddResult(
	t *testing.T,
	signer capability.ResultSigner,
	verified capability.VerifiedCapability,
	classification capability.Classification,
	exit capability.NFTExitClass,
	started time.Time,
) capability.SignedResult {
	ttl := uint64(59)
	errorCode := capability.ResultErrorNone
	if classification == capability.ClassificationFailed || classification == capability.ClassificationIndeterminate {
		errorCode = capability.ResultErrorIndeterminate
	}
	checked, err := capability.CheckResult(capability.Result{
		ResultID:     "019b0000-0000-7000-8000-000000000301",
		CapabilityID: verified.Value().CapabilityID, CapabilityDigest: verified.Digest(),
		Operation: verified.Value().Operation, ActionID: verified.Value().ActionID,
		ArtifactDigest: verified.Value().ArtifactDigest, TargetIPv4: verified.Value().TargetIPv4,
		Classification: classification, NFTExitClass: &exit, ReadbackState: capability.ReadbackActive,
		RemainingTTLSeconds: &ttl, OwnedSchemaDigest: verified.Value().OwnedSchemaDigest,
		StartedAt:       started.Truncate(time.Millisecond),
		CompletedAt:     started.Truncate(time.Millisecond).Add(time.Millisecond),
		JournalSequence: 1, ErrorCode: errorCode,
	})
	if err != nil {
		if t != nil {
			t.Fatalf("check result: %v", err)
		}
		return capability.SignedResult{}
	}
	signed, err := signer.SignFor(verified, checked)
	if err != nil {
		if t != nil {
			t.Fatalf("sign result: %v", err)
		}
		return capability.SignedResult{}
	}
	return signed
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("unavailable") }

type cancelReader struct{ cancel context.CancelFunc }

func (r *cancelReader) Read(value []byte) (int, error) {
	for index := range value {
		value[index] = 0x7a
	}
	r.cancel()
	return len(value), nil
}

func sameSignedCapability(left, right capability.SignedCapability) bool {
	return left.KeyID() == right.KeyID() && bytes.Equal(left.CanonicalBytes(), right.CanonicalBytes()) &&
		bytes.Equal(left.Signature(), right.Signature()) &&
		bytes.Equal(left.ArtifactBytes(), right.ArtifactBytes())
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func stringsRepeat(value string, count int) string {
	result := make([]byte, 0, len(value)*count)
	for range count {
		result = append(result, value...)
	}
	return string(result)
}

func digestTestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
