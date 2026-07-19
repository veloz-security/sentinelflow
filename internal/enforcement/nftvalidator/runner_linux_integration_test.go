//go:build linux

package nftvalidator

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftbinary"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

func TestProductionRunnerChecksPinnedTransactionWithoutRulesetMutation(t *testing.T) {
	if os.Getenv("SENTINELFLOW_NFT_VALIDATOR_INTEGRATION") != "1" {
		t.Skip("set SENTINELFLOW_NFT_VALIDATOR_INTEGRATION=1 inside an isolated NET_ADMIN namespace")
	}
	basePath := os.Getenv("SENTINELFLOW_NFT_BASE_CONTRACT")
	expectedDigest := os.Getenv("NFT_BINARY_EXPECTED_DIGEST")
	expectedVersion := os.Getenv("NFT_EXPECTED_VERSION")
	if basePath == "" || !digestPattern.MatchString(expectedDigest) || !validNFTVersion(expectedVersion) {
		t.Fatal("integration attestation inputs are missing")
	}
	base, err := LoadPinnedBaseContract(basePath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before := readRuleset(t, ctx)
	runner, err := NewProductionRunner(base)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := nftbinary.Verify(ctx, runner, expectedDigest, expectedVersion)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := nftcheck.New(runner, attestation.Version)
	if err != nil {
		t.Fatal(err)
	}
	validCandidate := []byte(testCandidate)
	evidence, err := checker.Check(ctx, nftcheck.Input{
		CanonicalBytes: validCandidate, CanonicalDigest: digestBytes(validCandidate),
		BaseContract: base, BaseContractDigest: nftcheck.PinnedBaseContractDigest,
	})
	if err != nil || evidence.SyntaxExitStatus != 0 || evidence.NFTVersion != expectedVersion {
		t.Fatalf("positive check evidence=%#v error=%v", evidence, err)
	}
	invalidCandidate := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout }\n")
	_, err = checker.Check(ctx, nftcheck.Input{
		CanonicalBytes: invalidCandidate, CanonicalDigest: digestBytes(invalidCandidate),
		BaseContract: base, BaseContractDigest: nftcheck.PinnedBaseContractDigest,
	})
	var syntaxError *nftcheck.Error
	if !errors.As(err, &syntaxError) || syntaxError.Code != nftcheck.ErrorSyntaxRejected {
		t.Fatalf("invalid syntax error=%v", err)
	}
	after := readRuleset(t, ctx)
	if !bytes.Equal(before, after) || len(bytes.TrimSpace(after)) != 0 {
		t.Fatalf("nft --check mutated or inherited a non-empty validator ruleset")
	}
}

func readRuleset(t *testing.T, ctx context.Context) []byte {
	t.Helper()
	command := exec.CommandContext(ctx, nftcheck.FixedNFTBinaryPath, "list", "ruleset")
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	value, err := command.Output()
	if err != nil || len(value) > nftcheck.MaxProcessOutput || strings.Contains(string(value), "sentinelflow") {
		t.Fatalf("isolated ruleset read failed or was not empty")
	}
	return value
}
