//go:build linux && integration

package nftbinary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

// This test is intended for a disposable network namespace whose owned base
// chain has already been loaded. It invokes only fixed --version and --check
// operations and never changes the ruleset itself.
func TestProductionAttestationAndSyntaxCheckInDisposableNamespace(t *testing.T) {
	rawBinary, err := os.ReadFile(nftcheck.FixedNFTBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rawBinary)
	expectedDigest := "sha256:" + hex.EncodeToString(sum[:])

	runner, err := nftcheck.NewProductionRunner()
	if err != nil {
		t.Fatal(err)
	}
	versionResult, err := runner.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	matches := observedVersionPattern.FindSubmatch(versionResult.Stdout)
	if len(matches) != 2 {
		t.Fatalf("unexpected normalized version output digest only")
	}
	expectedVersion := "nftables v" + string(matches[1])
	evidence, err := Verify(context.Background(), runner, expectedDigest, expectedVersion)
	if err != nil || evidence.BinaryDigest != expectedDigest || evidence.Version != expectedVersion {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}

	base, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "enforcement", "nft_base_chain_v1.nft"))
	if err != nil {
		t.Fatal(err)
	}
	checker, err := nftcheck.New(runner, expectedVersion)
	if err != nil {
		t.Fatal(err)
	}
	candidate := []byte("add element inet sentinelflow blacklist_ipv4 { 8.8.8.8 timeout 30m }\n")
	candidateSum := sha256.Sum256(candidate)
	_, err = checker.Check(context.Background(), nftcheck.Input{
		CanonicalBytes:     candidate,
		CanonicalDigest:    "sha256:" + hex.EncodeToString(candidateSum[:]),
		BaseContract:       base,
		BaseContractDigest: nftcheck.PinnedBaseContractDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
}
