package nftvalidate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func FuzzCanonicalizeNeverBroadensGrammar(f *testing.F) {
	for _, seed := range []struct {
		candidate string
		ttl       uint32
	}{
		{validCandidate, 1800},
		{validCandidate + "\n", 1800},
		{"add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1800s }", 1800},
		{"add element inet sentinelflow blacklist_ipv4 { 10.0.0.1 timeout 1m }", 60},
		{"delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }", 1800},
	} {
		f.Add([]byte(seed.candidate), seed.ttl)
	}
	f.Fuzz(func(t *testing.T, candidate []byte, policyTTL uint32) {
		artifact, err := Canonicalize(candidate, policyTTL)
		if err != nil {
			return
		}
		if artifact.TTLSeconds() < MinTTLSeconds || artifact.TTLSeconds() > MaxTTLSeconds ||
			artifact.TTLSeconds() != policyTTL || !artifact.Target().Is4() || !artifact.Target().IsGlobalUnicast() {
			t.Fatalf("accepted artifact violates bounds: target=%s ttl=%d policy=%d", artifact.Target(), artifact.TTLSeconds(), policyTTL)
		}
		canonical := artifact.CanonicalBytes()
		if len(canonical) == 0 || canonical[len(canonical)-1] != '\n' || bytes.Count(canonical, []byte{'\n'}) != 1 {
			t.Fatalf("canonical terminator invalid: %q", canonical)
		}
		roundTrip, err := Canonicalize(canonical, policyTTL)
		if err != nil || !bytes.Equal(roundTrip.CanonicalBytes(), canonical) || roundTrip.CanonicalDigest() != artifact.CanonicalDigest() {
			t.Fatalf("canonical round trip failed: err=%v bytes=%q", err, canonical)
		}
	})
}

func FuzzLiveSchemaValidationFailsClosed(f *testing.F) {
	root := filepath.Join("..", "..", "..", "contracts", "enforcement")
	base, err := os.ReadFile(filepath.Join(root, "nft_base_chain_v1.nft"))
	if err != nil {
		f.Fatalf("read base contract: %v", err)
	}
	live, err := os.ReadFile(filepath.Join(root, "nft_base_chain_v1.live.json"))
	if err != nil {
		f.Fatalf("read live schema: %v", err)
	}
	f.Add(live)
	f.Add(canonicalLiveSchema())
	f.Add([]byte(`{"family":"inet"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, candidate []byte) {
		proof, err := ValidateOwnedSchema(base, candidate)
		if err != nil {
			return
		}
		if proof.BaseContractDigest() != PinnedBaseChainRawDigest || proof.LiveSchemaDigest() != PinnedLiveSchemaDigest ||
			digest(proof.LiveCanonicalBytes()) != PinnedLiveSchemaDigest {
			t.Fatalf("accepted schema escaped pinned identity: raw=%s live=%s", proof.BaseContractDigest(), proof.LiveSchemaDigest())
		}
	})
}
