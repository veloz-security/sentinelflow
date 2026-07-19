package dispatchruntime

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/executor"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

func TestExpiredPersistedCapabilityUsesExecutorJournalFirstRecovery(t *testing.T) {
	for _, state := range []string{"terminal", "started", "unseen"} {
		t.Run(state, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Millisecond)
			claim := fixtureClaim(capability.OperationAdd, now.Add(-2*time.Second), 1, 3)
			claim.job.ownedSchemaDigest = nftvalidate.PinnedLiveSchemaDigest
			fixture := newRuntimeFixtureForClaim(t, claim, nil)
			issued, err := fixture.issuer.Issue(claim, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			fixture.clock.now = now
			fixture.store.recovery = RecoveredExecution{
				state: RecoveryCapability,
				capability: StoredCapability{
					claim: claim, signed: issued.Signed, verified: issued.Verified,
				},
				signedCapability: issued.Signed,
			}

			journalPath := filepath.Join(t.TempDir(), "replay.json")
			replay, err := journal.Open(journal.Options{
				Path: journalPath, CapabilityVerifier: fixture.capabilityVerifier,
				ResultVerifier: fixture.runtime.resultVerifier,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = replay.Close() })
			if state == "terminal" || state == "started" {
				beginAt := issued.Verified.Value().NotBefore
				if _, err := replay.Begin(issued.Signed, beginAt, beginAt.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			var terminal capability.SignedResult
			if state == "terminal" {
				terminal = signAddResult(t, fixture.resultSigner, issued.Verified,
					capability.ClassificationApplied, capability.NFTExitSuccess,
					issued.Verified.Value().NotBefore)
				if _, appended, err := replay.Complete(terminal); err != nil || !appended {
					t.Fatalf("terminal journal append=%v err=%v", appended, err)
				}
			}

			runner := &journalFirstRunner{}
			service, err := executor.New(executor.Config{
				CapabilityVerifier: fixture.capabilityVerifier,
				ResultSigner:       fixture.resultSigner,
				Journal:            replay, Runner: runner,
				DispatchKeyID: fixture.identities.DispatchKeyID,
			})
			if err != nil {
				t.Fatal(err)
			}
			client := &journalFirstRecoveryClient{service: service}
			fixture.runtime.client = client

			outcome, processErr := fixture.runtime.ProcessNext(context.Background())
			switch state {
			case "terminal":
				if processErr != nil || outcome != OutcomeCompleted || client.ordinaryCalls != 0 ||
					client.recoveryCalls != 1 || runner.mutationCount() != 0 || runner.inspectionCount() != 0 ||
					fixture.store.persistResultCalls != 1 || fixture.store.finishCalls != 1 ||
					!sameSignedResult(fixture.store.lastResult, terminal) {
					t.Fatalf("outcome=%s ordinary=%d recovery=%d mutate=%d inspect=%d persist=%d finish=%d err=%v",
						outcome, client.ordinaryCalls, client.recoveryCalls, runner.mutationCount(),
						runner.inspectionCount(), fixture.store.persistResultCalls,
						fixture.store.finishCalls, processErr)
				}
			case "started":
				if processErr != nil || outcome != OutcomeCompleted || client.ordinaryCalls != 0 ||
					client.recoveryCalls != 1 || runner.mutationCount() != 0 || runner.inspectionCount() != 1 ||
					fixture.store.persistResultCalls != 1 || fixture.store.finishCalls != 1 {
					t.Fatalf("outcome=%s ordinary=%d recovery=%d mutate=%d inspect=%d persist=%d finish=%d err=%v",
						outcome, client.ordinaryCalls, client.recoveryCalls, runner.mutationCount(),
						runner.inspectionCount(), fixture.store.persistResultCalls,
						fixture.store.finishCalls, processErr)
				}
			case "unseen":
				lookup, lookupErr := replay.Lookup(issued.Signed)
				if outcome != OutcomeRecoverRequired || !errors.Is(processErr, ErrRecoverRequired) ||
					client.ordinaryCalls != 0 || client.recoveryCalls != fixture.runtime.config.SameLeaseAttempts ||
					runner.mutationCount() != 0 || runner.inspectionCount() != 0 ||
					fixture.store.persistResultCalls != 0 || fixture.store.finishCalls != 0 ||
					lookupErr != nil || lookup.State() != journal.StateUnseen {
					t.Fatalf("outcome=%s ordinary=%d recovery=%d mutate=%d inspect=%d persist=%d finish=%d lookup=%s lookup_err=%v err=%v",
						outcome, client.ordinaryCalls, client.recoveryCalls, runner.mutationCount(),
						runner.inspectionCount(), fixture.store.persistResultCalls,
						fixture.store.finishCalls, lookup.State(), lookupErr, processErr)
				}
			}
		})
	}
}

func TestRecoveryOnlyClaimCannotMintOrOrdinaryExchangeUnderClockSkew(t *testing.T) {
	for _, state := range []string{"started", "unseen"} {
		t.Run(state, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Millisecond)
			ordinaryClaim := fixtureClaim(capability.OperationAdd, now.Add(-2*time.Second), 3, 3)
			ordinaryClaim.job.ownedSchemaDigest = nftvalidate.PinnedLiveSchemaDigest
			fixture := newRuntimeFixtureForClaim(t, ordinaryClaim, nil)
			issued, err := fixture.issuer.Issue(ordinaryClaim, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			recoveryClaim := ordinaryClaim
			recoveryClaim.job.recoveryOnly = true
			recoveryClaim.attempt = ordinaryClaim.attempt
			fixture.store.recoveryClaim = recoveryClaim
			fixture.store.recoveryFound = true
			fixture.store.found = true // ordinary claim must still never be reached.
			fixture.store.recovery = RecoveredExecution{
				state: RecoveryCapability,
				capability: StoredCapability{
					claim: recoveryClaim, signed: issued.Signed, verified: issued.Verified,
				},
				signedCapability: issued.Signed,
			}
			// Deliberately behind the signed expiry. Recovery-only routing must be
			// derived from the DB claim, never this local clock.
			fixture.clock.now = issued.Verified.Value().IssuedAt
			if _, err := fixture.issuer.Issue(recoveryClaim, time.Second); !errors.Is(err, ErrContractRejected) {
				t.Fatalf("recovery-only claim retained issuer authority: %v", err)
			}

			journalPath := filepath.Join(t.TempDir(), "replay.json")
			replay, err := journal.Open(journal.Options{
				Path: journalPath, CapabilityVerifier: fixture.capabilityVerifier,
				ResultVerifier: fixture.runtime.resultVerifier,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = replay.Close() })
			if state == "started" {
				beginAt := issued.Verified.Value().NotBefore
				if _, err := replay.Begin(issued.Signed, beginAt, beginAt.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			runner := &journalFirstRunner{}
			service, err := executor.New(executor.Config{
				CapabilityVerifier: fixture.capabilityVerifier,
				ResultSigner:       fixture.resultSigner, Journal: replay, Runner: runner,
				DispatchKeyID: fixture.identities.DispatchKeyID,
			})
			if err != nil {
				t.Fatal(err)
			}
			client := &journalFirstRecoveryClient{service: service}
			fixture.runtime.client = client

			outcome, processErr := fixture.runtime.ProcessNext(context.Background())
			if state == "started" {
				if processErr != nil || outcome != OutcomeCompleted || client.ordinaryCalls != 0 ||
					client.recoveryCalls != 1 || runner.mutationCount() != 0 || runner.inspectionCount() != 1 ||
					fixture.store.persistCapabilityCalls != 0 || fixture.store.persistResultCalls != 1 ||
					fixture.store.finishCalls != 1 {
					t.Fatalf("outcome=%s ordinary=%d recovery=%d mutate=%d inspect=%d cap=%d result=%d finish=%d err=%v",
						outcome, client.ordinaryCalls, client.recoveryCalls, runner.mutationCount(),
						runner.inspectionCount(), fixture.store.persistCapabilityCalls,
						fixture.store.persistResultCalls, fixture.store.finishCalls, processErr)
				}
			} else if outcome != OutcomeRecoverRequired || !errors.Is(processErr, ErrRecoverRequired) ||
				client.ordinaryCalls != 0 || runner.mutationCount() != 0 || runner.inspectionCount() != 0 ||
				fixture.store.persistCapabilityCalls != 0 || fixture.store.persistResultCalls != 0 ||
				fixture.store.finishCalls != 0 {
				t.Fatalf("outcome=%s ordinary=%d recovery=%d mutate=%d inspect=%d cap=%d result=%d finish=%d err=%v",
					outcome, client.ordinaryCalls, client.recoveryCalls, runner.mutationCount(),
					runner.inspectionCount(), fixture.store.persistCapabilityCalls,
					fixture.store.persistResultCalls, fixture.store.finishCalls, processErr)
			}
		})
	}
}

type journalFirstRecoveryClient struct {
	service       *executor.Service
	ordinaryCalls int
	recoveryCalls int
}

func (c *journalFirstRecoveryClient) Exchange(context.Context, capability.SignedCapability) (capability.SignedResult, error) {
	c.ordinaryCalls++
	return capability.SignedResult{}, ErrTransport
}

func (c *journalFirstRecoveryClient) ExchangeRecovery(ctx context.Context, signed capability.SignedCapability) (capability.SignedResult, error) {
	c.recoveryCalls++
	result, err := c.service.ProcessRecovery(ctx, signed)
	if err != nil {
		return capability.SignedResult{}, ErrTransport
	}
	return result, nil
}

type journalFirstRunner struct {
	mu          sync.Mutex
	mutations   int
	inspections int
}

func (r *journalFirstRunner) Mutate(context.Context, executor.Mutation) (executor.MutationOutcome, error) {
	r.mu.Lock()
	r.mutations++
	r.mu.Unlock()
	return executor.MutationOutcome{ExitClass: capability.NFTExitSuccess}, nil
}

func (r *journalFirstRunner) Inspect(_ context.Context, inspection executor.Inspection) (executor.Observation, error) {
	r.mu.Lock()
	r.inspections++
	r.mu.Unlock()
	return executor.Observation{
		State: capability.ReadbackActive, TargetIPv4: inspection.TargetIPv4(),
		OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest, RemainingTTLSeconds: 30,
	}, nil
}

func (r *journalFirstRunner) mutationCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutations
}

func (r *journalFirstRunner) inspectionCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inspections
}

func sameSignedResult(left, right capability.SignedResult) bool {
	return left.KeyID() == right.KeyID() && left.ExecutorID() == right.ExecutorID() &&
		string(left.CanonicalBytes()) == string(right.CanonicalBytes()) &&
		string(left.Signature()) == string(right.Signature())
}
