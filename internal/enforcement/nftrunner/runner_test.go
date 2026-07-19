package nftrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/executor"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

var testAddArtifact = []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n")

func TestMutationUsesOnlyFixedInvocationAndExactStdin(t *testing.T) {
	t.Parallel()
	original := append([]byte(nil), testAddArtifact...)
	var calls atomic.Int32
	runner := &Runner{run: func(_ context.Context, request processRequest) (processResult, bool) {
		calls.Add(1)
		if request.kind != processMutation || request.path() != executor.FixedNFTBinaryPath ||
			fmt.Sprint(request.arguments()) != fmt.Sprint([]string{"-f", "-"}) ||
			!bytes.Equal(request.stdin, original) {
			t.Fatalf("unexpected fixed request: kind=%d path=%q args=%v", request.kind, request.path(), request.arguments())
		}
		request.stdin[0] = 'x'
		return processResult{exitStatus: 0}, false
	}}
	outcome, err := runner.mutate(context.Background(), capability.OperationAdd,
		executor.FixedNFTBinaryPath, []string{"-f", "-"}, original)
	if err != nil || outcome.ExitClass != capability.NFTExitSuccess || calls.Load() != 1 {
		t.Fatalf("mutation = %+v, %v, calls=%d", outcome, err, calls.Load())
	}
	if !bytes.Equal(original, testAddArtifact) {
		t.Fatal("process mutated caller artifact")
	}
}

func TestMutationRejectsEveryOpenInvocationSurfaceBeforeProcess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		operation capability.Operation
		path      string
		arguments []string
		stdin     []byte
	}{
		{"wrong operation", capability.OperationInspect, executor.FixedNFTBinaryPath, []string{"-f", "-"}, testAddArtifact},
		{"empty operation", "", executor.FixedNFTBinaryPath, []string{"-f", "-"}, testAddArtifact},
		{"relative binary", capability.OperationAdd, "nft", []string{"-f", "-"}, testAddArtifact},
		{"other absolute binary", capability.OperationAdd, "/bin/sh", []string{"-f", "-"}, testAddArtifact},
		{"check arguments", capability.OperationAdd, executor.FixedNFTBinaryPath, []string{"--check", "-f", "-"}, testAddArtifact},
		{"extra argument", capability.OperationAdd, executor.FixedNFTBinaryPath, []string{"-f", "-", "--debug"}, testAddArtifact},
		{"empty stdin", capability.OperationAdd, executor.FixedNFTBinaryPath, []string{"-f", "-"}, nil},
		{"missing LF", capability.OperationAdd, executor.FixedNFTBinaryPath, []string{"-f", "-"}, bytes.TrimSuffix(testAddArtifact, []byte{'\n'})},
		{"extra LF", capability.OperationAdd, executor.FixedNFTBinaryPath, []string{"-f", "-"}, append(append([]byte(nil), testAddArtifact...), '\n')},
		{"NUL", capability.OperationAdd, executor.FixedNFTBinaryPath, []string{"-f", "-"}, []byte("add\x00\n")},
		{"oversized", capability.OperationAdd, executor.FixedNFTBinaryPath, []string{"-f", "-"}, append(bytes.Repeat([]byte{'x'}, maxMutationBytes), '\n')},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var called atomic.Bool
			runner := &Runner{run: func(context.Context, processRequest) (processResult, bool) {
				called.Store(true)
				return processResult{}, true
			}}
			outcome, err := runner.mutate(context.Background(), test.operation, test.path, test.arguments, test.stdin)
			requireErrorCode(t, err, ErrorInvalidInput)
			if called.Load() || outcome.ExitClass != capability.NFTExitNonzero {
				t.Fatalf("process reached or wrong outcome: called=%t outcome=%+v", called.Load(), outcome)
			}
		})
	}
}

func TestMutationClassifiesProcessFailureWithoutOutputLeakage(t *testing.T) {
	t.Parallel()
	secret := "203.0.113.20 add element secret stderr"
	tests := []struct {
		name   string
		result processResult
		runErr bool
		exit   capability.NFTExitClass
		code   ErrorCode
	}{
		{"nonzero", processResult{exitStatus: 2, stderr: []byte(secret)}, true, capability.NFTExitNonzero, ErrorProcessNonzero},
		{"signaled", processResult{exitStatus: -1, signaled: true, stderr: []byte(secret)}, true, capability.NFTExitSignaled, ErrorProcessSignaled},
		{"contradictory signal", processResult{exitStatus: 0, signaled: true, stderr: []byte(secret)}, false, capability.NFTExitSignaled, ErrorProcessSignaled},
		{"unavailable", processResult{exitStatus: -1, stderr: []byte(secret)}, true, capability.NFTExitNonzero, ErrorProcessUnavailable},
		{"overflow marker", processResult{exitStatus: -1, overflow: true, stderr: []byte(secret)}, true, capability.NFTExitNonzero, ErrorOutputLimit},
		{"oversized stdout", processResult{exitStatus: 0, stdout: bytes.Repeat([]byte{'x'}, MaxProcessOutput+1)}, false, capability.NFTExitNonzero, ErrorOutputLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &Runner{run: func(context.Context, processRequest) (processResult, bool) {
				return test.result, test.runErr
			}}
			outcome, err := runner.mutate(context.Background(), capability.OperationAdd,
				executor.FixedNFTBinaryPath, []string{"-f", "-"}, testAddArtifact)
			requireErrorCode(t, err, test.code)
			if outcome.ExitClass != test.exit || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), testTarget) {
				t.Fatalf("classification leaked or changed: %+v %q", outcome, err)
			}
		})
	}
}

func TestMutationCancellationTimeoutAndLateSuccessCannotBecomeSuccess(t *testing.T) {
	t.Parallel()
	t.Run("cancelled before process", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		runner := &Runner{run: func(context.Context, processRequest) (processResult, bool) {
			t.Fatal("cancelled request reached process")
			return processResult{}, true
		}}
		outcome, err := runner.mutate(ctx, capability.OperationAdd,
			executor.FixedNFTBinaryPath, []string{"-f", "-"}, testAddArtifact)
		requireErrorCode(t, err, ErrorCancelled)
		if outcome.ExitClass != capability.NFTExitTimeout {
			t.Fatalf("outcome = %+v", outcome)
		}
	})

	t.Run("late process success", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		runner := &Runner{run: func(ctx context.Context, _ processRequest) (processResult, bool) {
			<-ctx.Done()
			return processResult{exitStatus: 0}, false
		}}
		outcome, err := runner.mutate(ctx, capability.OperationAdd,
			executor.FixedNFTBinaryPath, []string{"-f", "-"}, testAddArtifact)
		requireErrorCode(t, err, ErrorTimeout)
		if outcome.ExitClass != capability.NFTExitTimeout {
			t.Fatalf("late success outcome = %+v", outcome)
		}
	})
}

func TestInspectionUsesOnlyFixedReadOnlyInvocationAndParsesProjection(t *testing.T) {
	t.Parallel()
	runner := &Runner{run: func(_ context.Context, request processRequest) (processResult, bool) {
		if request.kind != processInspect || request.path() != executor.FixedNFTBinaryPath ||
			fmt.Sprint(request.arguments()) != fmt.Sprint([]string{"--json", "list", "set", "inet", "sentinelflow", "blacklist_ipv4"}) ||
			len(request.stdin) != 0 {
			t.Fatalf("unexpected inspect request: kind=%d path=%q args=%v stdin=%d",
				request.kind, request.path(), request.arguments(), len(request.stdin))
		}
		return processResult{exitStatus: 0, stdout: []byte(realNFT111ActiveJSON)}, false
	}}
	observation, err := runner.inspect(context.Background(), validInspectInput())
	if err != nil || observation.State != capability.ReadbackActive || observation.RemainingTTLSeconds != 1799 {
		t.Fatalf("inspection = %+v, %v", observation, err)
	}
}

func TestAdapterAlwaysAddsItsOwnBoundedDeadline(t *testing.T) {
	t.Parallel()
	assertDeadline := func(ctx context.Context) {
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining <= 0 || remaining > MaxOperationDuration {
			t.Fatalf("process deadline = %v, remaining %s", ok, remaining)
		}
	}
	runner := &Runner{run: func(ctx context.Context, request processRequest) (processResult, bool) {
		assertDeadline(ctx)
		if request.kind == processInspect {
			return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyJSON)}, false
		}
		return processResult{exitStatus: 0}, false
	}}
	if _, err := runner.mutate(context.Background(), capability.OperationAdd,
		executor.FixedNFTBinaryPath, mutationArguments[:], testAddArtifact); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.inspect(context.Background(), validInspectInput()); err != nil {
		t.Fatal(err)
	}
}

func TestInspectionRejectsInvocationOutputAndProcessFailures(t *testing.T) {
	t.Parallel()
	invalidInputs := []inspectInput{
		{},
		{path: "nft", arguments: inspectArguments[:], targetIPv4: testTarget, ownedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest},
		{path: executor.FixedNFTBinaryPath, arguments: []string{"list", "ruleset"}, targetIPv4: testTarget, ownedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest},
		{path: executor.FixedNFTBinaryPath, arguments: inspectArguments[:], targetIPv4: "203.000.113.20", ownedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest},
		{path: executor.FixedNFTBinaryPath, arguments: inspectArguments[:], targetIPv4: testTarget, ownedSchemaDigest: "sha256:wrong"},
	}
	for index, input := range invalidInputs {
		var called atomic.Bool
		runner := &Runner{run: func(context.Context, processRequest) (processResult, bool) {
			called.Store(true)
			return processResult{}, true
		}}
		_, err := runner.inspect(context.Background(), input)
		requireErrorCode(t, err, ErrorInvalidInput)
		if called.Load() {
			t.Fatalf("case %d reached process", index)
		}
	}

	secret := "raw nft output 203.0.113.20"
	processCases := []struct {
		name   string
		result processResult
		runErr bool
		code   ErrorCode
	}{
		{"stderr on zero", processResult{exitStatus: 0, stdout: []byte(realNFT111ActiveJSON), stderr: []byte(secret)}, false, ErrorProcessUnavailable},
		{"nonzero", processResult{exitStatus: 1, stderr: []byte(secret)}, true, ErrorProcessNonzero},
		{"signaled", processResult{exitStatus: -1, signaled: true, stderr: []byte(secret)}, true, ErrorProcessSignaled},
		{"unavailable", processResult{exitStatus: -1, stderr: []byte(secret)}, true, ErrorProcessUnavailable},
		{"overflow", processResult{exitStatus: 0, overflow: true, stdout: []byte(secret)}, false, ErrorOutputLimit},
		{"oversized", processResult{exitStatus: 0, stdout: bytes.Repeat([]byte{'x'}, MaxProcessOutput+1)}, false, ErrorOutputLimit},
		{"malformed", processResult{exitStatus: 0, stdout: []byte(`{"nftables":`)}, false, ErrorReadbackInvalid},
	}
	for _, test := range processCases {
		t.Run(test.name, func(t *testing.T) {
			runner := &Runner{run: func(context.Context, processRequest) (processResult, bool) {
				return test.result, test.runErr
			}}
			_, err := runner.inspect(context.Background(), validInspectInput())
			requireErrorCode(t, err, test.code)
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), testTarget) {
				t.Fatalf("inspection error leaked process data: %q", err)
			}
		})
	}
}

func TestInspectionCancellationAndLateSuccessFailClosed(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	runner := &Runner{run: func(ctx context.Context, _ processRequest) (processResult, bool) {
		<-ctx.Done()
		return processResult{exitStatus: 0, stdout: []byte(realNFT111ActiveJSON)}, false
	}}
	_, err := runner.inspect(ctx, validInspectInput())
	requireErrorCode(t, err, ErrorTimeout)
}

func TestRunnerAndErrorsAreRedacted(t *testing.T) {
	t.Parallel()
	runner := &Runner{}
	formatted := fmt.Sprintf("%v %#v", runner, runner)
	if strings.Contains(formatted, testTarget) || strings.Contains(formatted, "/usr/sbin/nft") {
		t.Fatalf("runner formatting leaked data: %q", formatted)
	}
	var nilError *Error
	if nilError.Error() != "nft runner rejected" {
		t.Fatalf("nil error = %q", nilError.Error())
	}
	if _, err := (*Runner)(nil).inspect(context.Background(), validInspectInput()); err == nil {
		t.Fatal("nil runner accepted inspection")
	}
	if _, err := (*Runner)(nil).mutate(context.Background(), capability.OperationAdd,
		executor.FixedNFTBinaryPath, mutationArguments[:], testAddArtifact); err == nil {
		t.Fatal("nil runner accepted mutation")
	}
	if _, err := runner.Mutate(context.Background(), executor.Mutation{}); err == nil {
		t.Fatal("public runner accepted a zero mutation")
	}
	if _, err := runner.Inspect(context.Background(), executor.Inspection{}); err == nil {
		t.Fatal("public runner accepted a zero inspection")
	}
}

func validInspectInput() inspectInput {
	return inspectInput{
		path: executor.FixedNFTBinaryPath, arguments: inspectArguments[:],
		targetIPv4: testTarget, ownedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest,
	}
}

func TestErrorDoesNotWrapArbitraryCauses(t *testing.T) {
	t.Parallel()
	err := reject(ErrorProcessUnavailable)
	if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "arbitrary") {
		t.Fatalf("error unexpectedly wrapped a cause: %v", err)
	}
}
