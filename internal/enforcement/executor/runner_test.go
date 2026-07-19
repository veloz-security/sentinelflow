package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

func TestFixedCommandValuesAreClosedDefensiveAndRedacted(t *testing.T) {
	mutation := Mutation{operation: capability.OperationAdd, stdin: testAddArtifact}
	if mutation.Path() != nftcheck.FixedNFTBinaryPath || mutation.Path() != "/usr/sbin/nft" ||
		fmt.Sprint(mutation.Arguments()) != fmt.Sprint([]string{"-f", "-"}) {
		t.Fatalf("mutation invocation = %s %v", mutation.Path(), mutation.Arguments())
	}
	arguments := mutation.Arguments()
	arguments[0] = "--evil"
	stdin := mutation.Stdin()
	stdin[0] = 'x'
	if mutation.Arguments()[0] != "-f" || !bytes.Equal(mutation.Stdin(), testAddArtifact) {
		t.Fatal("mutation accessors did not return defensive copies")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", mutation, mutation), testTarget) {
		t.Fatal("mutation formatting exposed artifact")
	}

	inspection := Inspection{actionID: id(1), targetIPv4: testTarget, originalAddDigest: digest("add"), ownedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest}
	if inspection.Path() != "/usr/sbin/nft" ||
		fmt.Sprint(inspection.Arguments()) != fmt.Sprint([]string{"--json", "list", "set", "inet", "sentinelflow", "blacklist_ipv4"}) {
		t.Fatalf("inspect invocation = %s %v", inspection.Path(), inspection.Arguments())
	}
	inspectArguments := inspection.Arguments()
	inspectArguments[0] = "delete"
	if inspection.Arguments()[0] != "--json" || strings.Contains(fmt.Sprintf("%v %#v", inspection, inspection), testTarget) {
		t.Fatal("inspection was mutable or exposed target")
	}
	if inspection.ActionID() != id(1) || inspection.TargetIPv4() != testTarget ||
		inspection.OriginalAddDigest() != digest("add") || inspection.OwnedSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest {
		t.Fatal("inspection accessors changed")
	}
}

func TestObservationValidationRejectsWrongSchemaTargetAndBounds(t *testing.T) {
	expected := Inspection{targetIPv4: testTarget, ownedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest}
	valid := Observation{State: capability.ReadbackActive, TargetIPv4: testTarget,
		OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest, RemainingTTLSeconds: 60}
	if _, ok := validateObservation(valid, expected, 60); !ok {
		t.Fatal("valid observation rejected")
	}
	tests := []Observation{
		{State: capability.ReadbackActive, TargetIPv4: "203.0.113.21", OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest, RemainingTTLSeconds: 60},
		{State: capability.ReadbackActive, TargetIPv4: testTarget, OwnedSchemaDigest: digest("wrong"), RemainingTTLSeconds: 60},
		{State: capability.ReadbackActive, TargetIPv4: testTarget, OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest},
		{State: capability.ReadbackActive, TargetIPv4: testTarget, OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest, RemainingTTLSeconds: 61},
		{State: capability.ReadbackAbsent, TargetIPv4: testTarget, OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest, RemainingTTLSeconds: 1},
		{State: "unknown", TargetIPv4: testTarget, OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest},
	}
	for index, input := range tests {
		if output, ok := validateObservation(input, expected, 60); ok || output.State != capability.ReadbackMismatch {
			t.Fatalf("case %d accepted: %+v", index, output)
		}
	}
}

func TestConfigurationDeadlineAndDefaultID(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty configuration accepted")
	}
	f := newFixture(t)
	if _, err := New(Config{CapabilityVerifier: f.verifier, ResultSigner: f.resultSigner,
		Journal: f.journal, Runner: f.runner, DispatchKeyID: "wrong-key"}); err == nil {
		t.Fatal("mismatched dispatch key accepted")
	}
	if _, err := (*Service)(nil).Process(context.Background(), capability.SignedCapability{}); err == nil {
		t.Fatal("nil service accepted a request")
	}
	identifier, err := newUUIDv4()
	if err != nil || len(identifier) != 36 || identifier[14] != '4' || (identifier[19] != '8' && identifier[19] != '9' && identifier[19] != 'a' && identifier[19] != 'b') {
		t.Fatalf("UUID = %q err=%v", identifier, err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := operationDeadline(context.Background(), now, now); err == nil {
		t.Fatal("zero validity deadline accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := operationDeadline(ctx, now, now.Add(time.Second)); err == nil {
		t.Fatal("cancelled deadline accepted")
	}
}

func TestServiceAndErrorsAreRedacted(t *testing.T) {
	f := newFixture(t)
	formatted := fmt.Sprintf("%v %#v", f.service, f.service)
	if strings.Contains(formatted, testTarget) || strings.Contains(formatted, testDispatchKeyID) {
		t.Fatalf("service formatting leaked state: %s", formatted)
	}
	var nilError *Error
	if nilError.Error() != "executor service rejected" {
		t.Fatalf("nil error = %q", nilError.Error())
	}
}

func TestRealContextTimeoutProducesSignedIndeterminateResult(t *testing.T) {
	f := newFixture(t)
	f.runner.blockMutation = true
	signed := f.signed(capability.OperationAdd, 70)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	result, err := f.service.Process(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	value := f.verifiedResult(signed, result)
	if value.Classification != capability.ClassificationIndeterminate || value.NFTExitClass == nil ||
		*value.NFTExitClass != capability.NFTExitTimeout || value.ReadbackState != capability.ReadbackUnavailable {
		t.Fatalf("timeout result = %+v", value)
	}
}

func TestRunnerCannotManufactureSuccessAfterJournalDeadline(t *testing.T) {
	f := newFixture(t)
	var calls int
	f.service.clock = func() time.Time {
		calls++
		if calls < 4 {
			return f.base
		}
		return f.base.Add(1500 * time.Millisecond)
	}
	signed := f.signed(capability.OperationAdd, 72)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := f.service.Process(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	value := f.verifiedResult(signed, result)
	if value.Classification != capability.ClassificationIndeterminate ||
		value.ErrorCode != capability.ResultErrorDeadlineExceeded || value.ReadbackState != capability.ReadbackActive {
		t.Fatalf("late success was accepted: %+v", value)
	}
}

func TestServiceErrorsNeverReflectRunnerOrArtifactData(t *testing.T) {
	f := newFixture(t)
	f.runner.inspectErrors[1] = errors.New("stderr: " + string(testAddArtifact))
	_, err := f.service.Process(context.Background(), f.signed(capability.OperationAdd, 71))
	if err == nil || strings.Contains(err.Error(), testTarget) || strings.Contains(err.Error(), "add element") || strings.Contains(err.Error(), "stderr") {
		t.Fatalf("unsafe error: %v", err)
	}
}
