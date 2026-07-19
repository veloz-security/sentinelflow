//go:build linux && integration

package nftbootstrap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"golang.org/x/sys/unix"
)

// TestProductionBootstrapInDisposableNetworkNamespace requires root, nftables,
// CAP_SYS_ADMIN for a nested network namespace, and CAP_NET_ADMIN within it.
// The explicit environment opt-in prevents an integration-tag invocation from
// touching the caller's namespace. The test snapshots the original stateless
// ruleset, enters a disposable namespace on one locked OS thread, exercises the
// production fixed-path process boundary, restores the original namespace, and
// proves its snapshot is byte-identical.
func TestProductionBootstrapInDisposableNetworkNamespace(t *testing.T) {
	if os.Getenv("SENTINELFLOW_NFTBOOTSTRAP_INTEGRATION") != "1" {
		t.Skip("set SENTINELFLOW_NFTBOOTSTRAP_INTEGRATION=1 in a disposable privileged test container")
	}
	if os.Geteuid() != 0 {
		t.Skip("integration requires root in a disposable test container")
	}
	if _, err := os.Stat(FixedNFTBinaryPath); err != nil {
		t.Skipf("fixed nft binary unavailable: %v", err)
	}

	testCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hostBefore, err := runTestNFT(testCtx, []string{"--json", "--stateless", "list", "ruleset"}, nil)
	if err != nil {
		t.Skipf("cannot snapshot original namespace: %v", err)
	}
	originalNamespace, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("cannot open original network namespace: %v", err)
	}
	defer unix.Close(originalNamespace)

	runtime.LockOSThread()
	unshared := false
	restored := false
	defer func() {
		if unshared && !restored {
			if restoreErr := unix.Setns(originalNamespace, unix.CLONE_NEWNET); restoreErr != nil {
				t.Errorf("restore original network namespace: %v", restoreErr)
			} else {
				restored = true
			}
		}
		runtime.UnlockOSThread()
		if unshared && !restored {
			return
		}
		snapshotCtx, snapshotCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer snapshotCancel()
		hostAfter, snapshotErr := runTestNFT(snapshotCtx, []string{"--json", "--stateless", "list", "ruleset"}, nil)
		if snapshotErr != nil {
			t.Errorf("snapshot original namespace after test: %v", snapshotErr)
			return
		}
		if !bytes.Equal(hostBefore, hostAfter) {
			t.Errorf("original namespace nftables changed: before=%s after=%s", digest(hostBefore), digest(hostAfter))
		}
	}()

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skipf("cannot create disposable network namespace: %v", err)
	}
	unshared = true

	baseContract := readIntegrationContract(t)
	manager, err := NewProductionManager()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.VerifyLive(testCtx); err == nil {
		t.Fatal("empty namespace unexpectedly passed live verification")
	} else {
		requireErrorCode(t, err, ErrorProcessNonzero)
	}

	if _, err := runTestNFT(testCtx, []string{"add", "table", "inet", "sentinelflow"}, nil); err != nil {
		t.Fatalf("create partial owned table: %v", err)
	}
	partialBefore, err := runTestNFT(testCtx, inventoryArguments[:], nil)
	if err != nil {
		t.Fatalf("snapshot partial owned table: %v", err)
	}
	if _, err := manager.Bootstrap(testCtx, baseContract); err == nil {
		t.Fatal("bootstrap accepted a partial owned table")
	} else {
		requireErrorCode(t, err, ErrorOwnedTableExists)
	}
	partialAfter, err := runTestNFT(testCtx, inventoryArguments[:], nil)
	if err != nil || !bytes.Equal(partialBefore, partialAfter) {
		t.Fatalf("rejected partial owned table changed: err=%v before=%s after=%s", err, digest(partialBefore), digest(partialAfter))
	}
	if _, err := runTestNFT(testCtx, []string{"delete", "table", "inet", "sentinelflow"}, nil); err != nil {
		t.Fatalf("remove partial owned table: %v", err)
	}

	foreignContract := []byte(`table ip nat {
  chain DOCKER_OUTPUT {
  }
  chain OUTPUT {
    type nat hook output priority -100
    policy accept
    ip daddr 127.0.0.11 jump DOCKER_OUTPUT
  }
}
table ip arbitrary_foreign {
  chain foreign_input {
    type filter hook input priority 10
    policy accept
  }
}
`)
	if _, err := runTestNFT(testCtx, applyArguments[:], foreignContract); err != nil {
		t.Fatalf("create synthetic Docker-like and arbitrary foreign state: %v", err)
	}
	foreignBeforeSnapshot := readIntegrationSnapshot(t, testCtx)
	foreignBefore := foreignBeforeSnapshot.foreignCanonical

	proof, err := manager.Bootstrap(testCtx, baseContract)
	if err != nil || proof.BaseContractDigest() != nftvalidate.PinnedBaseChainRawDigest ||
		proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest ||
		proof.NFTVersion() != foreignBeforeSnapshot.metainfo.Version {
		t.Fatalf("bootstrap = %+v, %v", proof, err)
	}
	foreignAfter := readIntegrationSnapshot(t, testCtx).foreignCanonical
	if !bytes.Equal(foreignBefore, foreignAfter) {
		t.Fatalf("bootstrap changed foreign state: before=%s after=%s", digest(foreignBefore), digest(foreignAfter))
	}

	add := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1m }\n")
	if _, err := runTestNFT(testCtx, applyArguments[:], add); err != nil {
		t.Fatalf("add synthetic timed element: %v", err)
	}
	activeProof, err := manager.VerifyLive(testCtx)
	if err != nil || activeProof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest {
		t.Fatalf("active live verification = %+v, %v", activeProof, err)
	}

	if _, err := manager.Bootstrap(testCtx, baseContract); err == nil {
		t.Fatal("second bootstrap unexpectedly reapplied the contract")
	} else {
		requireErrorCode(t, err, ErrorOwnedTableExists)
	}

	if _, err := runTestNFT(testCtx, []string{"add", "table", "ip", "late_foreign"}, nil); err != nil {
		t.Fatalf("add extra namespace table: %v", err)
	}
	if lateForeignProof, err := manager.VerifyLive(testCtx); err != nil ||
		lateForeignProof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest {
		t.Fatalf("owned live verification depended on late foreign state: %+v, %v", lateForeignProof, err)
	}
	if _, err := runTestNFT(testCtx, []string{"delete", "table", "ip", "late_foreign"}, nil); err != nil {
		t.Fatalf("remove extra namespace table: %v", err)
	}

	var oversizedForeign strings.Builder
	oversizedForeign.WriteString("table ip oversized_foreign {\n")
	for index := 0; index < 1400; index++ {
		fmt.Fprintf(&oversizedForeign, "chain foreign_chain_%04d_padding_padding_padding_padding { }\n", index)
	}
	oversizedForeign.WriteString("}\n")
	if _, err := runTestNFT(testCtx, applyArguments[:], []byte(oversizedForeign.String())); err != nil {
		t.Fatalf("create oversized foreign ruleset: %v", err)
	}
	oversizedSnapshot, err := runTestNFT(testCtx, inventoryArguments[:], nil)
	if err != nil || len(oversizedSnapshot) <= MaxProcessOutput {
		t.Fatalf("foreign ruleset did not exceed steady-state bound: bytes=%d err=%v", len(oversizedSnapshot), err)
	}
	if oversizedProof, err := manager.VerifyLive(testCtx); err != nil ||
		oversizedProof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest {
		t.Fatalf("oversized foreign state disabled scoped verification: %+v, %v", oversizedProof, err)
	}

	if _, err := runTestNFT(testCtx, []string{"add", "chain", "inet", "sentinelflow", "unexpected"}, nil); err != nil {
		t.Fatalf("add extra owned object: %v", err)
	}
	if _, err := manager.VerifyLive(testCtx); err == nil {
		t.Fatal("live verification accepted an extra owned chain")
	} else {
		requireErrorCode(t, err, ErrorLiveReadbackInvalid)
	}

	if err := unix.Setns(originalNamespace, unix.CLONE_NEWNET); err != nil {
		t.Fatalf("restore original network namespace: %v", err)
	}
	restored = true
}

func readIntegrationSnapshot(t *testing.T, ctx context.Context) rulesetSnapshot {
	t.Helper()
	raw, err := runTestNFT(ctx, inventoryArguments[:], nil)
	if err != nil {
		t.Fatalf("read foreign ruleset snapshot: %v", err)
	}
	snapshot, err := parseRulesetSnapshot(raw, ErrorInventoryInvalid)
	if err != nil {
		t.Fatalf("parse foreign ruleset snapshot: %v", err)
	}
	return snapshot
}

func readIntegrationContract(t *testing.T) []byte {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test path")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../../../contracts/enforcement/nft_base_chain_v1.nft"))
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read base-chain contract: %v", err)
	}
	return value
}

func runTestNFT(ctx context.Context, arguments []string, stdin []byte) ([]byte, error) {
	command := exec.CommandContext(ctx, FixedNFTBinaryPath, arguments...)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	if stdin != nil {
		command.Stdin = bytes.NewReader(append([]byte(nil), stdin...))
	}
	return command.Output()
}
