package executor

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
)

func TestRecoveryEnvelopeNeverBeginsUnseenCapability(t *testing.T) {
	f := newFixture(t)
	signed := f.signed(capability.OperationAdd, 39)
	request, err := ipc.NewRecoveryRequestEnvelope(
		signed.CanonicalBytes(), signed.Signature(), signed.ArtifactBytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ipc.EncodeRequestEnvelope(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.HandlePayload(context.Background(), payload); err == nil {
		t.Fatal("unseen recovery envelope began a lifecycle")
	}
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 0 {
		t.Fatalf("unseen recovery touched runner: %d/%d", mutations, inspections)
	}
	lookup, err := f.journal.Lookup(signed)
	if err != nil || lookup.State() != journal.StateUnseen {
		t.Fatalf("unseen recovery wrote journal: %v %v", lookup.State(), err)
	}
}

func TestRecoveryEnvelopeInspectsStartedWithoutMutation(t *testing.T) {
	f := newFixture(t)
	signed := f.signed(capability.OperationAdd, 38)
	if _, err := f.journal.Begin(signed, f.base, f.base.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	f.runner.setState(f.runner.active(300))
	request, err := ipc.NewRecoveryRequestEnvelope(
		signed.CanonicalBytes(), signed.Signature(), signed.ArtifactBytes(),
	)
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
	result := capability.NewUntrustedSignedResult(
		f.resultVerifier.KeyID(), f.resultVerifier.ExecutorID(),
		response.ResultJCS(), response.ResultSignature(),
	)
	value := f.verifiedResult(signed, result)
	if value.Classification != capability.ClassificationRecoveredActive {
		t.Fatalf("unexpected recovery result: %+v", value)
	}
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
		t.Fatalf("recovery envelope calls = %d/%d", mutations, inspections)
	}
}

func TestStartedOnlyAddRecoveryReadsBackWithoutMutationAfterExpiry(t *testing.T) {
	f := newFixture(t)
	signed := f.signed(capability.OperationAdd, 40)
	outcome, err := f.journal.Begin(signed, f.base, f.base.Add(2*time.Second))
	if err != nil || outcome.State() != journal.StateNewStarted {
		t.Fatalf("begin = %v %v", outcome.State(), err)
	}
	f.runner.setState(f.runner.active(300))
	f.clock.Set(f.base.Add(time.Minute))

	result, err := f.service.Process(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	value := f.verifiedResult(signed, result)
	if value.Classification != capability.ClassificationRecoveredActive || value.NFTExitClass == nil ||
		*value.NFTExitClass != capability.NFTExitNotInvoked || value.ReadbackState != capability.ReadbackActive {
		t.Fatalf("unexpected recovered result: %+v", value)
	}
	if !value.StartedAt.Equal(f.base.Add(time.Minute)) || !value.CompletedAt.Equal(f.base.Add(time.Minute)) {
		t.Fatalf("recovery timestamps = %s..%s, want actual recovery clock", value.StartedAt, value.CompletedAt)
	}
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
		t.Fatalf("recovery calls = %d/%d", mutations, inspections)
	}
	replayed, err := f.service.Process(context.Background(), signed)
	if err != nil || !bytes.Equal(replayed.CanonicalBytes(), result.CanonicalBytes()) ||
		!bytes.Equal(replayed.Signature(), result.Signature()) {
		t.Fatalf("terminal recovery replay mismatch: %v", err)
	}
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
		t.Fatalf("recovery replay touched runner: %d/%d", mutations, inspections)
	}
}

func TestStartedOnlyRecoveryClassifiesAbsentAndRevokeWithoutMutation(t *testing.T) {
	tests := []struct {
		name           string
		operation      capability.Operation
		classification capability.Classification
		errorCode      capability.ResultErrorCode
		exitClass      capability.NFTExitClass
	}{
		{"add absent is indeterminate", capability.OperationAdd, capability.ClassificationIndeterminate, capability.ResultErrorIndeterminate, capability.NFTExitNotInvoked},
		{"revoke absent is revoked", capability.OperationRevoke, capability.ClassificationRevoked, capability.ResultErrorNone, capability.NFTExitNotInvoked},
		{"inspect absent is observed", capability.OperationInspect, capability.ClassificationInspectAbsent, capability.ResultErrorNone, capability.NFTExitSuccess},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			signed := f.signed(test.operation, 50+index)
			outcome, err := f.journal.Begin(signed, f.base, f.base.Add(2*time.Second))
			if err != nil || outcome.State() != journal.StateNewStarted {
				t.Fatalf("begin = %v %v", outcome.State(), err)
			}
			result, err := f.service.Process(context.Background(), signed)
			if err != nil {
				t.Fatal(err)
			}
			value := f.verifiedResult(signed, result)
			if value.Classification != test.classification || value.ErrorCode != test.errorCode ||
				value.NFTExitClass == nil || *value.NFTExitClass != test.exitClass {
				t.Fatalf("unexpected recovery: %+v", value)
			}
			if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
				t.Fatalf("recovery calls = %d/%d", mutations, inspections)
			}
		})
	}
}

func TestStartedOnlyRecoveryMismatchAndUnavailableRemainIndeterminate(t *testing.T) {
	t.Run("add mismatch", func(t *testing.T) {
		f := newFixture(t)
		signed := f.signed(capability.OperationAdd, 55)
		if _, err := f.journal.Begin(signed, f.base, f.base.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		f.runner.setState(f.runner.mismatch())
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationIndeterminate ||
			value.ErrorCode != capability.ResultErrorReadbackMismatch || value.ReadbackState != capability.ReadbackMismatch {
			t.Fatalf("unexpected mismatch recovery: %+v", value)
		}
	})

	t.Run("add TTL beyond authorization", func(t *testing.T) {
		f := newFixture(t)
		signed := f.signed(capability.OperationAdd, 57)
		if _, err := f.journal.Begin(signed, f.base, f.base.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		f.runner.setState(f.runner.active(1801))
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationIndeterminate ||
			value.ErrorCode != capability.ResultErrorReadbackMismatch || value.ReadbackState != capability.ReadbackMismatch ||
			value.ElementHandle != nil || value.RemainingTTLSeconds != nil {
			t.Fatalf("unexpected over-TTL recovery: %+v", value)
		}
		outcome, err := f.journal.Lookup(signed)
		if err != nil || outcome.State() != journal.StateTerminal {
			t.Fatalf("over-TTL recovery not terminal: %v %v", outcome.State(), err)
		}
	})

	t.Run("revoke unavailable", func(t *testing.T) {
		f := newFixture(t)
		signed := f.signed(capability.OperationRevoke, 56)
		if _, err := f.journal.Begin(signed, f.base, f.base.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		f.runner.inspectErrors[1] = errors.New("unavailable")
		result, err := f.service.Process(context.Background(), signed)
		if err != nil {
			t.Fatal(err)
		}
		value := f.verifiedResult(signed, result)
		if value.Classification != capability.ClassificationIndeterminate ||
			value.ErrorCode != capability.ResultErrorReadbackFailed || value.ReadbackState != capability.ReadbackUnavailable {
			t.Fatalf("unexpected unavailable recovery: %+v", value)
		}
	})
}

type completeFailJournal struct{ ReplayJournal }

func (j completeFailJournal) Complete(capability.SignedResult) (journal.TerminalSnapshot, bool, error) {
	return journal.TerminalSnapshot{}, false, errors.New("disk failure detail")
}

func TestTerminalDurabilityFailureRecoversWithoutSecondMutation(t *testing.T) {
	f := newFixture(t)
	poisoned := f.newService(completeFailJournal{ReplayJournal: f.journal}, f.runner, f.resultSigner)
	signed := f.signed(capability.OperationAdd, 60)
	_, err := poisoned.Process(context.Background(), signed)
	requireCode(t, err, ErrorResultDurability)
	if mutations, inspections := f.runner.counts(); mutations != 1 || inspections != 2 {
		t.Fatalf("first attempt calls = %d/%d", mutations, inspections)
	}

	result, err := f.service.Process(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	value := f.verifiedResult(signed, result)
	if value.Classification != capability.ClassificationRecoveredActive || value.NFTExitClass == nil ||
		*value.NFTExitClass != capability.NFTExitNotInvoked {
		t.Fatalf("unexpected durability recovery: %+v", value)
	}
	if mutations, inspections := f.runner.counts(); mutations != 1 || inspections != 3 {
		t.Fatalf("durability recovery re-mutated: %d/%d", mutations, inspections)
	}
}

func TestResultSigningFailureLeavesStartedOnlyAndNeverReapplies(t *testing.T) {
	f := newFixture(t)
	wrongSigner, err := capability.NewResultSigner(testResultKeyID, "wrong-executor", f.resultPrivate)
	if err != nil {
		t.Fatal(err)
	}
	badService := f.newService(f.journal, f.runner, wrongSigner)
	signed := f.signed(capability.OperationAdd, 61)
	_, err = badService.Process(context.Background(), signed)
	requireCode(t, err, ErrorResultSigning)
	if mutations, _ := f.runner.counts(); mutations != 1 {
		t.Fatalf("signing failure mutations = %d", mutations)
	}

	if _, err := f.service.Process(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	if mutations, _ := f.runner.counts(); mutations != 1 {
		t.Fatalf("signing recovery re-mutated: %d", mutations)
	}
}

func TestResultIDFailureLeavesStartedOnlyAndNeverReapplies(t *testing.T) {
	f := newFixture(t)
	goodID := f.service.newResultID
	f.service.newResultID = func() (string, error) { return "", errors.New("entropy unavailable") }
	signed := f.signed(capability.OperationAdd, 64)
	_, err := f.service.Process(context.Background(), signed)
	requireCode(t, err, ErrorResult)
	if mutations, _ := f.runner.counts(); mutations != 1 {
		t.Fatalf("result ID failure mutations = %d", mutations)
	}
	f.service.newResultID = goodID
	if _, err := f.service.Process(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	if mutations, _ := f.runner.counts(); mutations != 1 {
		t.Fatalf("result ID recovery re-mutated: %d", mutations)
	}
}

type lookupFailJournal struct{ ReplayJournal }

func (j lookupFailJournal) Lookup(capability.SignedCapability) (journal.Outcome, error) {
	return journal.Outcome{}, errors.New("journal poison detail")
}

func TestJournalFailurePreventsInspectionAndMutation(t *testing.T) {
	f := newFixture(t)
	service := f.newService(lookupFailJournal{ReplayJournal: f.journal}, f.runner, f.resultSigner)
	_, err := service.Process(context.Background(), f.signed(capability.OperationAdd, 62))
	requireCode(t, err, ErrorJournal)
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 0 {
		t.Fatalf("journal failure reached runner: %d/%d", mutations, inspections)
	}
}

type beginFailJournal struct{ ReplayJournal }

func (j beginFailJournal) Begin(capability.SignedCapability, time.Time, time.Time) (journal.Outcome, error) {
	return journal.Outcome{}, errors.New("begin fsync failed")
}

func TestStartedFsyncFailurePreventsMutation(t *testing.T) {
	f := newFixture(t)
	service := f.newService(beginFailJournal{ReplayJournal: f.journal}, f.runner, f.resultSigner)
	_, err := service.Process(context.Background(), f.signed(capability.OperationAdd, 63))
	requireCode(t, err, ErrorJournal)
	if mutations, inspections := f.runner.counts(); mutations != 0 || inspections != 1 {
		t.Fatalf("started fsync failure calls = %d/%d", mutations, inspections)
	}
}
