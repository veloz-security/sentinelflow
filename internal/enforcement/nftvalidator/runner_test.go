package nftvalidator

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

func TestCombineCheckScriptUsesPinnedBaseAndOneCandidateWithoutMutation(t *testing.T) {
	base := testBaseContract(t)
	candidate := []byte(testCandidate)
	baseBefore := append([]byte(nil), base...)
	candidateBefore := append([]byte(nil), candidate...)
	value, err := combineCheckScript(base, candidate)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), base...), candidate...)
	if !bytes.Equal(value, want) {
		t.Fatalf("combined script mismatch")
	}
	value[0] ^= 1
	if !bytes.Equal(base, baseBefore) || !bytes.Equal(candidate, candidateBefore) {
		t.Fatal("combined script aliases caller-owned bytes")
	}
}

func TestCombineCheckScriptRejectsCallerSelectedBaseAndNonCanonicalCandidate(t *testing.T) {
	base := testBaseContract(t)
	for _, test := range []struct {
		name      string
		base      []byte
		candidate []byte
	}{
		{name: "mutated base", base: append([]byte{'x'}, base[1:]...), candidate: []byte(testCandidate)},
		{name: "empty base", candidate: []byte(testCandidate)},
		{name: "multiple statements", base: base, candidate: []byte(testCandidate + testCandidate)},
		{name: "missing newline", base: base, candidate: bytes.TrimSuffix([]byte(testCandidate), []byte{'\n'})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := combineCheckScript(test.base, test.candidate); err == nil {
				t.Fatal("invalid check script accepted")
			}
		})
	}
}

func TestRuntimeBaseContractStillMatchesRunnerPin(t *testing.T) {
	value, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "enforcement", "nft_base_chain_v1.nft"))
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(value) != nftcheck.PinnedBaseContractDigest {
		t.Fatal("base contract drifted from syntax runner pin")
	}
}

func FuzzCombineCheckScript(f *testing.F) {
	base, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "enforcement", "nft_base_chain_v1.nft"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(testCandidate))
	f.Add([]byte("invalid\nsecond\n"))
	f.Fuzz(func(t *testing.T, candidate []byte) {
		value, err := combineCheckScript(base, candidate)
		if err == nil {
			if !bytes.HasPrefix(value, base) || !bytes.Equal(value[len(base):], candidate) || !validCandidateEnvelope(candidate) {
				t.Fatal("combiner accepted or produced invalid bytes")
			}
		}
	})
}
