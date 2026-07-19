package nftbootstrap

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

func TestBootstrapUsesOnlyFixedInventoryApplyAndVerifySequence(t *testing.T) {
	t.Parallel()
	original := []byte(testBaseContract)
	var calls atomic.Int32
	manager := &Manager{run: func(ctx context.Context, request processRequest) (processResult, bool) {
		call := calls.Add(1)
		assertBoundedDeadline(t, ctx)
		if request.path() != FixedNFTBinaryPath {
			t.Fatalf("call %d path = %q", call, request.path())
		}
		switch call {
		case 1:
			if request.kind != processInventory || fmt.Sprint(request.arguments()) != fmt.Sprint(inventoryArguments) || len(request.stdin) != 0 {
				t.Fatalf("inventory request = %+v args=%v", request, request.arguments())
			}
			return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyInventoryJSON)}, false
		case 2:
			if request.kind != processApply || fmt.Sprint(request.arguments()) != fmt.Sprint(applyArguments) ||
				!bytes.Equal(request.stdin, original) {
				t.Fatalf("apply request = %+v args=%v", request, request.arguments())
			}
			request.stdin[0] = 'X'
			return processResult{exitStatus: 0}, false
		case 3:
			if request.kind != processInventory || fmt.Sprint(request.arguments()) != fmt.Sprint(inventoryArguments) || len(request.stdin) != 0 {
				t.Fatalf("post-bootstrap snapshot request = %+v args=%v", request, request.arguments())
			}
			return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyLiveJSON)}, false
		case 4:
			if request.kind != processVerifyLive || fmt.Sprint(request.arguments()) != fmt.Sprint(verifyArguments) || len(request.stdin) != 0 {
				t.Fatalf("scoped verify request = %+v args=%v", request, request.arguments())
			}
			return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyLiveJSON)}, false
		default:
			t.Fatalf("unexpected call %d", call)
			return processResult{}, true
		}
	}}

	proof, err := manager.Bootstrap(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 || proof.Operation() != OperationBootstrap || !proof.BootstrapWasPerformed() ||
		proof.IsReadOnlyVerification() || proof.BoundaryVersion() != BoundaryVersion ||
		proof.NFTBinaryPath() != "/usr/sbin/nft" ||
		proof.BaseContractDigest() != nftvalidate.PinnedBaseChainRawDigest ||
		proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest || proof.NFTVersion() != "1.1.1" {
		t.Fatalf("bootstrap proof = %+v calls=%d", proof, calls.Load())
	}
	if !bytes.Equal(original, []byte(testBaseContract)) {
		t.Fatal("process mutated caller contract")
	}
	canonical := proof.LiveCanonicalBytes()
	canonical[0] = 'X'
	if bytes.Equal(canonical, proof.LiveCanonicalBytes()) {
		t.Fatal("proof exposed mutable canonical bytes")
	}
}

func TestBootstrapRejectsInvalidContractBeforeAnyProcess(t *testing.T) {
	t.Parallel()
	tests := [][]byte{
		nil,
		[]byte("table inet attacker {}\n"),
		append([]byte(testBaseContract), '\n'),
		bytes.Repeat([]byte{'x'}, MaxBaseContractBytes+1),
	}
	for index, contract := range tests {
		var called atomic.Bool
		manager := &Manager{run: func(context.Context, processRequest) (processResult, bool) {
			called.Store(true)
			return processResult{}, true
		}}
		proof, err := manager.Bootstrap(context.Background(), contract)
		requireErrorCode(t, err, ErrorBaseContract)
		if called.Load() || !zeroProof(proof) {
			t.Fatalf("case %d reached process or returned proof: %+v", index, proof)
		}
	}
}

func TestBootstrapRefusesOwnedNamespaceWithoutMutation(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	manager := &Manager{run: func(_ context.Context, request processRequest) (processResult, bool) {
		if calls.Add(1) != 1 || request.kind != processInventory {
			t.Fatal("bootstrap reached mutation after existing owned table")
		}
		return processResult{exitStatus: 0, stdout: []byte(realNFT111OwnedInventoryJSON)}, false
	}}
	proof, err := manager.Bootstrap(context.Background(), []byte(testBaseContract))
	requireErrorCode(t, err, ErrorOwnedTableExists)
	if calls.Load() != 1 || !zeroProof(proof) {
		t.Fatalf("calls=%d proof=%+v", calls.Load(), proof)
	}
}

func TestBootstrapPreservesArbitraryForeignTable(t *testing.T) {
	t.Parallel()
	foreign := `{"table":{"family":"ip","name":"arbitrary-foreign","handle":42}}`
	before := strings.Replace(realNFT111EmptyInventoryJSON, `]}`, `,`+foreign+`]}`, 1)
	after := strings.Replace(realNFT111EmptyLiveJSON, `, {"table": {"family": "inet"`, `,`+foreign+`, {"table": {"family": "inet"`, 1)
	var calls atomic.Int32
	manager := &Manager{run: func(_ context.Context, request processRequest) (processResult, bool) {
		switch calls.Add(1) {
		case 1:
			return processResult{exitStatus: 0, stdout: []byte(before)}, false
		case 2:
			if request.kind != processApply {
				t.Fatal("foreign snapshot did not advance to the owned apply")
			}
			return processResult{exitStatus: 0}, false
		case 3:
			return processResult{exitStatus: 0, stdout: []byte(after)}, false
		case 4:
			if request.kind != processVerifyLive {
				t.Fatal("fourth call was not the scoped owned-table verification")
			}
			return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyLiveJSON)}, false
		default:
			t.Fatal("unexpected process call")
			return processResult{}, true
		}
	}}
	proof, err := manager.Bootstrap(context.Background(), []byte(testBaseContract))
	if err != nil || proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest || calls.Load() != 4 {
		t.Fatalf("proof=%+v err=%v calls=%d", proof, err, calls.Load())
	}
}

func TestVerifyLiveUsesOnlyOneFixedReadOnlyRulesetQuery(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	manager := &Manager{run: func(ctx context.Context, request processRequest) (processResult, bool) {
		calls.Add(1)
		assertBoundedDeadline(t, ctx)
		if request.path() != "/usr/sbin/nft" || len(request.stdin) != 0 {
			t.Fatalf("unexpected read-only query: kind=%d path=%q args=%v stdin=%d", request.kind, request.path(), request.arguments(), len(request.stdin))
		}
		if request.kind != processVerifyLive ||
			fmt.Sprint(request.arguments()) != fmt.Sprint([]string{"--json", "--stateless", "list", "table", "inet", "sentinelflow"}) {
			t.Fatalf("unexpected operation %d", request.kind)
		}
		return processResult{exitStatus: 0, stdout: []byte(realNFT111ActiveLiveJSON)}, false
	}}
	proof, err := manager.VerifyLive(context.Background())
	if err != nil || calls.Load() != 1 || proof.Operation() != OperationVerifyLive ||
		!proof.IsReadOnlyVerification() || proof.BootstrapWasPerformed() || proof.BaseContractDigest() != "" ||
		proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest || proof.NFTVersion() != "1.1.1" {
		t.Fatalf("verify proof = %+v err=%v calls=%d", proof, err, calls.Load())
	}
}

func TestSteadyStateVerifyNeverReadsOversizedForeignRuleset(t *testing.T) {
	t.Parallel()
	foreignStateBeyondBound := bytes.Repeat([]byte{'x'}, MaxProcessOutput+1)
	manager := &Manager{run: func(_ context.Context, request processRequest) (processResult, bool) {
		if request.kind != processVerifyLive ||
			fmt.Sprint(request.arguments()) != fmt.Sprint([]string{"--json", "--stateless", "list", "table", "inet", "sentinelflow"}) ||
			len(request.stdin) != 0 {
			t.Fatalf("steady-state verification escaped owned scope: kind=%d args=%v", request.kind, request.arguments())
		}
		// The simulated foreign state is intentionally not part of the fixed
		// owned-table response and therefore cannot consume the process bound.
		if len(foreignStateBeyondBound) <= MaxProcessOutput {
			t.Fatal("test did not construct an oversized foreign ruleset")
		}
		return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyLiveJSON)}, false
	}}
	proof, err := manager.VerifyLive(context.Background())
	if err != nil || proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest {
		t.Fatalf("scoped proof=%+v err=%v", proof, err)
	}
}

func TestVerifyLiveAcceptsForeignTableButStillPinsOwnedProjection(t *testing.T) {
	t.Parallel()
	extraRuleset := strings.Replace(realNFT111EmptyLiveJSON, `, {"rule":`,
		`, {"table":{"family":"ip","name":"unrelated","handle":2}}, {"rule":`, 1)
	var calls atomic.Int32
	manager := &Manager{run: func(_ context.Context, request processRequest) (processResult, bool) {
		calls.Add(1)
		return processResult{exitStatus: 0, stdout: []byte(extraRuleset)}, false
	}}
	proof, err := manager.VerifyLive(context.Background())
	if err != nil || proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest || calls.Load() != 1 {
		t.Fatalf("proof=%+v err=%v calls=%d", proof, err, calls.Load())
	}
}

func TestBootstrapRejectsNFTVersionChangeAcrossProvisioning(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	manager := &Manager{run: func(_ context.Context, request processRequest) (processResult, bool) {
		switch calls.Add(1) {
		case 1:
			return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyInventoryJSON)}, false
		case 2:
			return processResult{exitStatus: 0}, false
		case 3:
			return processResult{exitStatus: 0, stdout: []byte(strings.Replace(realNFT111EmptyLiveJSON,
				`"version": "1.1.1"`, `"version":"1.1.2"`, 1))}, false
		default:
			t.Fatalf("unexpected request %d", request.kind)
			return processResult{}, true
		}
	}}
	proof, err := manager.Bootstrap(context.Background(), []byte(testBaseContract))
	requireErrorCode(t, err, ErrorLiveSchemaMismatch)
	if !zeroProof(proof) || calls.Load() != 3 {
		t.Fatalf("proof=%+v calls=%d", proof, calls.Load())
	}
}

func TestBootstrapRejectsForeignSnapshotChangeAfterOwnedApply(t *testing.T) {
	t.Parallel()
	foreignBefore := `{"table":{"family":"ip","name":"foreign-before","handle":9}}`
	foreignAfter := `{"table":{"family":"ip","name":"foreign-after","handle":9}}`
	before := strings.Replace(realNFT111EmptyInventoryJSON, `]}`, `,`+foreignBefore+`]}`, 1)
	after := strings.Replace(realNFT111EmptyLiveJSON, `, {"table": {"family": "inet"`, `,`+foreignAfter+`, {"table": {"family": "inet"`, 1)
	var calls atomic.Int32
	manager := &Manager{run: func(_ context.Context, _ processRequest) (processResult, bool) {
		switch calls.Add(1) {
		case 1:
			return processResult{exitStatus: 0, stdout: []byte(before)}, false
		case 2:
			return processResult{exitStatus: 0}, false
		case 3:
			return processResult{exitStatus: 0, stdout: []byte(after)}, false
		default:
			return processResult{}, true
		}
	}}
	proof, err := manager.Bootstrap(context.Background(), []byte(testBaseContract))
	requireErrorCode(t, err, ErrorForeignStateChanged)
	if !zeroProof(proof) || calls.Load() != 3 {
		t.Fatalf("proof=%+v calls=%d", proof, calls.Load())
	}
}

func TestFailedApplyMustProveNoPartialOwnedMutation(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	manager := &Manager{run: func(_ context.Context, request processRequest) (processResult, bool) {
		switch calls.Add(1) {
		case 1:
			return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyInventoryJSON)}, false
		case 2:
			if request.kind != processApply {
				t.Fatal("second call was not the owned apply")
			}
			return processResult{exitStatus: 1, stderr: []byte("redacted process detail")}, true
		case 3:
			return processResult{exitStatus: 0, stdout: []byte(realNFT111OwnedInventoryJSON)}, false
		default:
			return processResult{}, true
		}
	}}
	proof, err := manager.Bootstrap(context.Background(), []byte(testBaseContract))
	requireErrorCode(t, err, ErrorApplyRollback)
	if !zeroProof(proof) || calls.Load() != 3 || strings.Contains(err.Error(), "process detail") {
		t.Fatalf("proof=%+v err=%v calls=%d", proof, err, calls.Load())
	}
}

func TestManagerRejectsProcessFailuresOutputAndLateSuccess(t *testing.T) {
	t.Parallel()
	secret := "SECRET=203.0.113.20 raw nft diagnostic"
	tests := []struct {
		name   string
		result processResult
		runErr bool
		code   ErrorCode
	}{
		{"nonzero", processResult{exitStatus: 1, stderr: []byte(secret)}, true, ErrorProcessNonzero},
		{"signaled", processResult{exitStatus: -1, signaled: true, stderr: []byte(secret)}, true, ErrorProcessSignaled},
		{"run error after zero", processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyLiveJSON)}, true, ErrorProcessUnavailable},
		{"stderr on success", processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyLiveJSON), stderr: []byte(secret)}, false, ErrorUnexpectedOutput},
		{"empty read output", processResult{exitStatus: 0}, false, ErrorUnexpectedOutput},
		{"overflow marker", processResult{exitStatus: 0, stdout: []byte(secret), overflow: true}, false, ErrorOutputLimit},
		{"oversized output", processResult{exitStatus: 0, stdout: bytes.Repeat([]byte{'x'}, MaxProcessOutput+1)}, false, ErrorOutputLimit},
		{"combined oversized", processResult{exitStatus: 0, stdout: bytes.Repeat([]byte{'x'}, MaxProcessOutput), stderr: []byte("x")}, false, ErrorOutputLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &Manager{run: func(context.Context, processRequest) (processResult, bool) {
				return test.result, test.runErr
			}}
			proof, err := manager.VerifyLive(context.Background())
			requireErrorCode(t, err, test.code)
			if !zeroProof(proof) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "203.0.113.20") {
				t.Fatalf("error leaked or proof returned: %q %+v", err, proof)
			}
		})
	}

	t.Run("late success after deadline", func(t *testing.T) {
		manager := &Manager{run: func(ctx context.Context, _ processRequest) (processResult, bool) {
			<-ctx.Done()
			return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyLiveJSON)}, false
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		proof, err := manager.VerifyLive(ctx)
		requireErrorCode(t, err, ErrorTimeout)
		if !zeroProof(proof) {
			t.Fatalf("late success returned proof: %+v", proof)
		}
	})
}

func TestBootstrapApplyRequiresSilentSuccessAndPreservesErrorClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result processResult
		runErr bool
		code   ErrorCode
	}{
		{"nonzero", processResult{exitStatus: 1, stderr: []byte("private detail")}, true, ErrorProcessNonzero},
		{"stdout", processResult{exitStatus: 0, stdout: []byte("unexpected")}, false, ErrorUnexpectedOutput},
		{"stderr", processResult{exitStatus: 0, stderr: []byte("unexpected")}, false, ErrorUnexpectedOutput},
		{"overflow", processResult{exitStatus: 0, overflow: true}, false, ErrorOutputLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			manager := &Manager{run: func(_ context.Context, request processRequest) (processResult, bool) {
				switch calls.Add(1) {
				case 1:
					return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyInventoryJSON)}, false
				case 2:
					if request.kind != processApply {
						t.Fatal("unexpected post-inventory operation")
					}
					return test.result, test.runErr
				case 3:
					if request.kind != processInventory {
						t.Fatal("failed apply did not use a read-only rollback snapshot")
					}
					return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyInventoryJSON)}, false
				default:
					t.Fatal("unexpected process call")
				}
				return processResult{}, true
			}}
			proof, err := manager.Bootstrap(context.Background(), []byte(testBaseContract))
			requireErrorCode(t, err, test.code)
			if !zeroProof(proof) || calls.Load() != 3 {
				t.Fatalf("proof=%+v calls=%d", proof, calls.Load())
			}
		})
	}
}

func TestManagerRejectsNilCancelledAndInvalidReceiver(t *testing.T) {
	t.Parallel()
	manager := &Manager{run: func(context.Context, processRequest) (processResult, bool) {
		t.Fatal("invalid request reached process")
		return processResult{}, true
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name string
		call func() (Proof, error)
		code ErrorCode
	}{
		//lint:ignore SA1012 This negative test proves the public boundary rejects a nil context.
		{"nil context", func() (Proof, error) { return manager.VerifyLive(nil) }, ErrorInvalidInput},
		{"cancelled", func() (Proof, error) { return manager.VerifyLive(ctx) }, ErrorCancelled},
		{"nil receiver", func() (Proof, error) { return (*Manager)(nil).VerifyLive(context.Background()) }, ErrorInvalidInput},
		{"nil runner", func() (Proof, error) { return (&Manager{}).VerifyLive(context.Background()) }, ErrorInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof, err := test.call()
			requireErrorCode(t, err, test.code)
			if !zeroProof(proof) {
				t.Fatalf("proof = %+v", proof)
			}
		})
	}
}

func TestConcurrentVerifyLiveHasNoSharedMutableState(t *testing.T) {
	t.Parallel()
	manager := &Manager{run: func(_ context.Context, request processRequest) (processResult, bool) {
		return processResult{exitStatus: 0, stdout: []byte(realNFT111EmptyLiveJSON)}, false
	}}
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			proof, err := manager.VerifyLive(context.Background())
			if err != nil || proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest {
				t.Errorf("verify = %+v, %v", proof, err)
			}
		}()
	}
	wait.Wait()
}

func TestManagerAndErrorsAreRedacted(t *testing.T) {
	t.Parallel()
	manager := &Manager{}
	formatted := fmt.Sprintf("%v %#v", manager, manager)
	if strings.Contains(formatted, "/usr/sbin/nft") || strings.Contains(formatted, "sentinelflow") {
		t.Fatalf("manager formatting leaked implementation details: %q", formatted)
	}
	var nilError *Error
	if nilError.Error() != "nftables bootstrap boundary rejected" {
		t.Fatalf("nil error = %q", nilError.Error())
	}
}

func assertBoundedDeadline(t *testing.T, ctx context.Context) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining <= 0 || remaining > OperationTimeout {
		t.Fatalf("deadline = %v remaining=%s", ok, remaining)
	}
}

func zeroProof(proof Proof) bool {
	return proof.operation == "" && proof.baseContractDigest == "" &&
		proof.liveSchemaDigest == "" && proof.liveCanonical == nil && proof.nftVersion == ""
}
