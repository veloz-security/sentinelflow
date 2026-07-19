package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
)

func TestAddLifecycleTerminalReplayAndIPCEnvelope(t *testing.T) {
	f := newFixture(t)
	signed := f.signed(capability.OperationAdd, 1)

	result, err := f.service.Process(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	value := f.verifiedResult(signed, result)
	if value.Classification != capability.ClassificationApplied || value.ReadbackState != capability.ReadbackActive ||
		value.NFTExitClass == nil || *value.NFTExitClass != capability.NFTExitSuccess ||
		value.ElementHandle != nil ||
		value.RemainingTTLSeconds == nil || *value.RemainingTTLSeconds != 1800 {
		t.Fatalf("unexpected applied result: %+v", value)
	}
	mutations, inspections := f.runner.counts()
	if mutations != 1 || inspections != 2 {
		t.Fatalf("runner calls = mutate %d inspect %d, want 1/2", mutations, inspections)
	}
	mutation := f.runner.lastMutation()
	if mutation.Path() != FixedNFTBinaryPath || fmt.Sprint(mutation.Arguments()) != fmt.Sprint([]string{"-f", "-"}) ||
		mutation.Operation() != capability.OperationAdd || !bytes.Equal(mutation.Stdin(), testAddArtifact) {
		t.Fatalf("mutation contract changed: %v %v %v", mutation.Path(), mutation.Arguments(), mutation.Operation())
	}

	// A stale exact retry resolves from the terminal journal before freshness.
	f.clock.Set(f.base.Add(time.Minute))
	replayed, err := f.service.Process(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed.CanonicalBytes(), result.CanonicalBytes()) || !bytes.Equal(replayed.Signature(), result.Signature()) {
		t.Fatal("terminal retry did not return exact signed bytes")
	}
	if gotMutations, gotInspections := f.runner.counts(); gotMutations != 1 || gotInspections != 2 {
		t.Fatalf("terminal retry touched runner: %d/%d", gotMutations, gotInspections)
	}

	request, err := ipc.NewRequestEnvelope(signed.CanonicalBytes(), signed.Signature(), signed.ArtifactBytes())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ipc.EncodeRequestEnvelope(request)
	if err != nil {
		t.Fatal(err)
	}
	responsePayload, err := f.service.HandlePayload(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	response, err := ipc.DecodeResponseEnvelope(responsePayload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.ResultJCS(), result.CanonicalBytes()) || !bytes.Equal(response.ResultSignature(), result.Signature()) {
		t.Fatal("IPC response did not preserve exact terminal result")
	}
}

func TestConcurrentExactDuplicatesMutateOnce(t *testing.T) {
	f := newFixture(t)
	signed := f.signed(capability.OperationAdd, 2)
	const workers = 32
	results := make([]capability.SignedResult, workers)
	errorsSeen := make([]error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index], errorsSeen[index] = f.service.Process(context.Background(), signed)
		}(index)
	}
	group.Wait()
	for index := range errorsSeen {
		if errorsSeen[index] != nil {
			t.Fatalf("worker %d: %v", index, errorsSeen[index])
		}
		if !bytes.Equal(results[index].CanonicalBytes(), results[0].CanonicalBytes()) ||
			!bytes.Equal(results[index].Signature(), results[0].Signature()) {
			t.Fatalf("worker %d received a non-identical result", index)
		}
	}
	if mutations, inspections := f.runner.counts(); mutations != 1 || inspections != 2 {
		t.Fatalf("concurrent retry calls = %d/%d, want 1/2", mutations, inspections)
	}
}

func TestFreshAddConsumesCapabilityButNeverMutatesExistingTarget(t *testing.T) {
	f := newFixture(t)
	f.runner.setState(f.runner.active(900))
	signed := f.signed(capability.OperationAdd, 3)
	result, err := f.service.Process(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	value := f.verifiedResult(signed, result)
	if value.Classification != capability.ClassificationFailed || value.ErrorCode != capability.ResultErrorTargetExists ||
		value.NFTExitClass == nil || *value.NFTExitClass != capability.NFTExitNotInvoked ||
		value.ReadbackState != capability.ReadbackActive {
		t.Fatalf("unexpected target-exists result: %+v", value)
	}
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
		t.Fatalf("existing target calls = %d/%d", mutations, inspections)
	}
	outcome, err := f.journal.Lookup(signed)
	if err != nil || outcome.State() != journal.StateTerminal {
		t.Fatalf("target-exists request was not terminally journaled: %v %v", outcome.State(), err)
	}
	f.runner.setState(f.runner.absent())
	replayed, err := f.service.Process(context.Background(), signed)
	if err != nil || !bytes.Equal(replayed.CanonicalBytes(), result.CanonicalBytes()) {
		t.Fatalf("target-exists retry changed result: %v", err)
	}
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
		t.Fatalf("target-exists retry reached runner: %d/%d", mutations, inspections)
	}
}

func TestFreshnessSignatureArtifactAndSchemaFailuresDoNotReachRunner(t *testing.T) {
	tests := []struct {
		name string
		run  func(*fixture) error
		code ErrorCode
	}{
		{"expired", func(f *fixture) error {
			f.clock.Set(f.base.Add(time.Minute))
			_, err := f.service.Process(context.Background(), f.signed(capability.OperationAdd, 4))
			return err
		}, ErrorFreshness},
		{"signature", func(f *fixture) error {
			signed := f.signed(capability.OperationAdd, 5)
			signature := signed.Signature()
			signature[0] ^= 0xff
			_, err := f.service.Process(context.Background(), capability.NewUntrustedSignedCapability(
				signed.KeyID(), signed.CanonicalBytes(), signature, signed.ArtifactBytes()))
			return err
		}, ErrorCapability},
		{"artifact", func(f *fixture) error {
			signed := f.signed(capability.OperationAdd, 6)
			artifact := signed.ArtifactBytes()
			artifact[10] ^= 1
			_, err := f.service.Process(context.Background(), capability.NewUntrustedSignedCapability(
				signed.KeyID(), signed.CanonicalBytes(), signed.Signature(), artifact))
			return err
		}, ErrorCapability},
		{"cancelled", func(f *fixture) error {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := f.service.Process(ctx, f.signed(capability.OperationAdd, 7))
			return err
		}, ErrorDeadline},
		{"valid signature with unowned schema", func(f *fixture) error {
			_, err := f.service.Process(context.Background(), f.signedAddWithSchema(9, digest("not-owned")))
			return err
		}, ErrorSchema},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			requireCode(t, test.run(f), test.code)
			if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 0 {
				t.Fatalf("invalid request reached runner: %d/%d", mutations, inspections)
			}
		})
	}
}

func TestPreflightMismatchLeavesCapabilityUnseenAndNeverMutates(t *testing.T) {
	f := newFixture(t)
	f.runner.setState(f.runner.mismatch())
	signed := f.signed(capability.OperationAdd, 10)
	_, err := f.service.Process(context.Background(), signed)
	requireCode(t, err, ErrorTargetState)
	outcome, lookupErr := f.journal.Lookup(signed)
	if lookupErr != nil || outcome.State() != journal.StateUnseen {
		t.Fatalf("preflight mismatch journal state = %v err=%v", outcome.State(), lookupErr)
	}
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
		t.Fatalf("preflight mismatch calls = %d/%d", mutations, inspections)
	}
}

func TestConflictingCapabilityIDFailsWithoutSecondMutation(t *testing.T) {
	f := newFixture(t)
	first := f.signed(capability.OperationAdd, 8)
	if _, err := f.service.Process(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	f.runner.setState(f.runner.absent())
	conflictingArtifact := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1h }\n")
	conflicting := f.signedAt(capability.OperationAdd, 8, f.base, conflictingArtifact)
	_, err := f.service.Process(context.Background(), conflicting)
	requireCode(t, err, ErrorReplay)
	if mutations, _ := f.runner.counts(); mutations != 1 {
		t.Fatalf("conflicting replay mutations = %d", mutations)
	}
}

func TestRevokeAndInspectAreOperationSeparated(t *testing.T) {
	t.Run("already absent revoke", func(t *testing.T) {
		f := newFixture(t)
		signed := f.signed(capability.OperationRevoke, 20)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationRevoked || value.NFTExitClass == nil ||
			*value.NFTExitClass != capability.NFTExitNotInvoked || value.ReadbackState != capability.ReadbackAbsent {
			t.Fatalf("unexpected absent revoke: %+v", value)
		}
		if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
			t.Fatalf("absent revoke calls = %d/%d", mutations, inspections)
		}
	})

	t.Run("active revoke", func(t *testing.T) {
		f := newFixture(t)
		f.runner.setState(f.runner.active(1200))
		signed := f.signed(capability.OperationRevoke, 21)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationRevoked || value.NFTExitClass == nil ||
			*value.NFTExitClass != capability.NFTExitSuccess {
			t.Fatalf("unexpected active revoke: %+v", value)
		}
		mutation := f.runner.lastMutation()
		if mutation.Operation() != capability.OperationRevoke || !bytes.Equal(mutation.Stdin(), testRevokeArtifact) {
			t.Fatalf("wrong revoke mutation: %v", mutation)
		}
	})

	t.Run("read only inspect", func(t *testing.T) {
		f := newFixture(t)
		f.runner.setState(f.runner.active(600))
		signed := f.signed(capability.OperationInspect, 22)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationInspectActive || value.NFTExitClass == nil ||
			*value.NFTExitClass != capability.NFTExitSuccess {
			t.Fatalf("unexpected inspect: %+v", value)
		}
		if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
			t.Fatalf("inspect calls = %d/%d", mutations, inspections)
		}
	})
}

func TestMutationAndReadbackFailuresAreSignedButNeverSuccess(t *testing.T) {
	t.Run("mutation timeout", func(t *testing.T) {
		f := newFixture(t)
		f.runner.mutationOutcome = MutationOutcome{ExitClass: capability.NFTExitTimeout}
		f.runner.disableTransition = true
		signed := f.signed(capability.OperationAdd, 30)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationFailed || value.ErrorCode != capability.ResultErrorDeadlineExceeded ||
			value.NFTExitClass == nil || *value.NFTExitClass != capability.NFTExitTimeout {
			t.Fatalf("unexpected timeout: %+v", value)
		}
	})

	t.Run("nonzero add with active readback is indeterminate", func(t *testing.T) {
		f := newFixture(t)
		f.runner.mutationOutcome = MutationOutcome{ExitClass: capability.NFTExitNonzero}
		f.runner.disableTransition = true
		f.runner.queue(f.runner.absent(), f.runner.active(1200))
		signed := f.signed(capability.OperationAdd, 39)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationIndeterminate ||
			value.ErrorCode != capability.ResultErrorNFTFailed || value.ReadbackState != capability.ReadbackActive {
			t.Fatalf("unexpected ambiguous add: %+v", value)
		}
	})

	t.Run("success with mismatch", func(t *testing.T) {
		f := newFixture(t)
		f.runner.disableTransition = true
		f.runner.queue(f.runner.absent(), f.runner.mismatch())
		signed := f.signed(capability.OperationAdd, 31)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationIndeterminate ||
			value.ErrorCode != capability.ResultErrorReadbackMismatch || value.ReadbackState != capability.ReadbackMismatch {
			t.Fatalf("unexpected mismatch: %+v", value)
		}
	})

	t.Run("remaining TTL beyond approved add is mismatch", func(t *testing.T) {
		f := newFixture(t)
		f.runner.disableTransition = true
		f.runner.queue(f.runner.absent(), f.runner.active(1801))
		signed := f.signed(capability.OperationAdd, 38)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationIndeterminate ||
			value.ErrorCode != capability.ResultErrorReadbackMismatch || value.ReadbackState != capability.ReadbackMismatch {
			t.Fatalf("unexpected over-TTL result: %+v", value)
		}
	})

	t.Run("readback unavailable", func(t *testing.T) {
		f := newFixture(t)
		f.runner.inspectErrors[2] = errors.New("sensitive process output must not escape")
		signed := f.signed(capability.OperationAdd, 32)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationIndeterminate ||
			value.ErrorCode != capability.ResultErrorReadbackFailed || value.ReadbackState != capability.ReadbackUnavailable {
			t.Fatalf("unexpected unavailable result: %+v", value)
		}
	})

	t.Run("revoke nonzero remains active", func(t *testing.T) {
		f := newFixture(t)
		f.runner.setState(f.runner.active(900))
		f.runner.mutationOutcome = MutationOutcome{ExitClass: capability.NFTExitNonzero}
		f.runner.disableTransition = true
		signed := f.signed(capability.OperationRevoke, 33)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationFailed || value.ErrorCode != capability.ResultErrorNFTFailed ||
			value.NFTExitClass == nil || *value.NFTExitClass != capability.NFTExitNonzero ||
			value.ReadbackState != capability.ReadbackActive {
			t.Fatalf("unexpected failed revoke: %+v", value)
		}
	})

	t.Run("nonzero revoke with absent readback is indeterminate", func(t *testing.T) {
		f := newFixture(t)
		f.runner.mutationOutcome = MutationOutcome{ExitClass: capability.NFTExitNonzero}
		f.runner.disableTransition = true
		f.runner.queue(f.runner.active(900), f.runner.absent())
		signed := f.signed(capability.OperationRevoke, 40)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationIndeterminate ||
			value.ErrorCode != capability.ResultErrorNFTFailed || value.ReadbackState != capability.ReadbackAbsent {
			t.Fatalf("unexpected ambiguous revoke: %+v", value)
		}
	})

	t.Run("revoke success but still active", func(t *testing.T) {
		f := newFixture(t)
		f.runner.setState(f.runner.active(900))
		f.runner.disableTransition = true
		signed := f.signed(capability.OperationRevoke, 34)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationFailed || value.ErrorCode != capability.ResultErrorReadbackFailed ||
			value.ReadbackState != capability.ReadbackActive {
			t.Fatalf("unexpected revoke readback failure: %+v", value)
		}
	})

	t.Run("inspect mismatch is typed read only result", func(t *testing.T) {
		f := newFixture(t)
		f.runner.setState(f.runner.mismatch())
		signed := f.signed(capability.OperationInspect, 35)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationInspectMismatch || value.ErrorCode != capability.ResultErrorNone ||
			value.NFTExitClass == nil || *value.NFTExitClass != capability.NFTExitSuccess ||
			value.ReadbackState != capability.ReadbackMismatch {
			t.Fatalf("unexpected inspect mismatch: %+v", value)
		}
		if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
			t.Fatalf("inspect mismatch calls = %d/%d", mutations, inspections)
		}
	})

	t.Run("inspect runner failure is indeterminate", func(t *testing.T) {
		f := newFixture(t)
		f.runner.inspectErrors[1] = errors.New("unavailable")
		signed := f.signed(capability.OperationInspect, 36)
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationIndeterminate ||
			value.ErrorCode != capability.ResultErrorReadbackFailed || value.ReadbackState != capability.ReadbackUnavailable {
			t.Fatalf("unexpected inspect failure: %+v", value)
		}
	})
}

func TestPermitDeadlineFailureIsJournaledWithoutMutation(t *testing.T) {
	f := newFixture(t)
	var calls int
	f.service.clock = func() time.Time {
		calls++
		if calls <= 2 {
			return f.base
		}
		return f.base.Add(2 * time.Second)
	}
	signed := f.signed(capability.OperationAdd, 37)
	result, err := f.service.Process(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	value := f.verifiedResult(signed, result)
	if value.Classification != capability.ClassificationFailed || value.ErrorCode != capability.ResultErrorDeadlineExceeded ||
		value.NFTExitClass == nil || *value.NFTExitClass != capability.NFTExitNotInvoked {
		t.Fatalf("unexpected permit deadline result: %+v", value)
	}
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
		t.Fatalf("expired permit reached mutation: %d/%d", mutations, inspections)
	}
}

func TestMalformedIPCEnvelopeIsRejectedWithoutRunner(t *testing.T) {
	f := newFixture(t)
	_, err := f.service.HandlePayload(context.Background(), []byte(`{"schema_version":"executor-request-envelope-v1"}`))
	requireCode(t, err, ErrorRequest)
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 0 {
		t.Fatalf("malformed envelope reached runner: %d/%d", mutations, inspections)
	}
}
