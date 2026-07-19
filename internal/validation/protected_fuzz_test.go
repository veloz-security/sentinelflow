package validation

import (
	"net/netip"
	"path/filepath"
	"testing"
)

func FuzzProtectedGateNeverAllowsInvalidOrBuiltInTarget(f *testing.F) {
	contract, err := LoadProtectedContractFile(filepath.Join("..", "..", "contracts", "enforcement", "protected_ipv4_v1.json"))
	if err != nil {
		f.Fatalf("load contract: %v", err)
	}
	gate, err := NewProtectedGate(contract, baseConfig(EnvironmentProduction))
	if err != nil {
		f.Fatalf("new gate: %v", err)
	}
	for _, seed := range []string{"8.8.8.8", "203.0.113.20", "10.0.0.1", "127.0.0.1", "0.0.0.0", "::1", "008.008.008.008", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, target string) {
		result := gate.Check(passedInput(target))
		if !result.Allowed() {
			return
		}
		address, err := netip.ParseAddr(target)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.String() != target {
			t.Fatalf("allowed noncanonical/non-global target %q: %+v", target, result)
		}
		for _, entry := range contract.entries {
			for _, prefix := range entry.cidrs {
				if prefix.Contains(address) {
					t.Fatalf("allowed built-in target %q in %s/%s", target, entry.id, prefix)
				}
			}
		}
	})
}

func FuzzConfiguredCIDRParserIsCanonical(f *testing.F) {
	for _, seed := range []string{"8.8.8.0/24", "8.8.8.1/24", "0.0.0.0/0", "2001:db8::/32", "", "008.008.008.000/24"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		prefix, err := parseCanonicalIPv4Prefix(value)
		if err != nil {
			return
		}
		if !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != value {
			t.Fatalf("accepted noncanonical prefix %q as %s", value, prefix)
		}
	})
}
