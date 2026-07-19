package validation

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestCheckedContractAndVectorDigest(t *testing.T) {
	t.Parallel()
	raw := checkedContractBytes(t)
	contract, err := ParseProtectedContract(raw, PinnedProtectedIPv4Digest)
	if err != nil {
		t.Fatalf("ParseProtectedContract() error = %v", err)
	}
	if contract.Digest() != PinnedProtectedIPv4Digest || contract.RawDigest() == "" || contract.RawDigest() == contract.Digest() {
		t.Fatalf("contract digests = JCS %s raw %s", contract.Digest(), contract.RawDigest())
	}
	if len(contract.entries) != 26 {
		t.Fatalf("entries = %d, want 26", len(contract.entries))
	}

	var vectors struct {
		ArtifactDigests struct {
			Protected string `json:"protected_ipv4_jcs_sha256"`
		} `json:"artifact_digests"`
	}
	vectorBytes, err := os.ReadFile(filepath.Join("..", "..", "contracts", "vectors", "contract_vectors_v1.json"))
	if err != nil || json.Unmarshal(vectorBytes, &vectors) != nil {
		t.Fatalf("read checked vector: %v", err)
	}
	if vectors.ArtifactDigests.Protected != contract.Digest() {
		t.Fatalf("vector digest = %s, contract = %s", vectors.ArtifactDigests.Protected, contract.Digest())
	}

	// JCS intentionally makes insignificant source whitespace digest-neutral.
	spaced := append(bytes.Clone(raw), []byte(" \n\t")...)
	whitespaceContract, err := ParseProtectedContract(spaced, PinnedProtectedIPv4Digest)
	if err != nil || whitespaceContract.Digest() != contract.Digest() || whitespaceContract.RawDigest() == contract.RawDigest() {
		t.Fatalf("JCS whitespace behavior: contract=%+v err=%v", whitespaceContract, err)
	}
}

func TestContractRejectsDigestAndStructuralMutation(t *testing.T) {
	t.Parallel()
	raw := checkedContractBytes(t)
	tests := []struct {
		name     string
		raw      []byte
		digest   string
		wantCode ProtectedErrorCode
	}{
		{"wrong pin", raw, testDigest, ErrDigestMismatch},
		{"content mutation", bytes.Replace(bytes.Clone(raw), []byte(`"production_protected": true`), []byte(`"production_protected": false`), 1), PinnedProtectedIPv4Digest, ErrDigestMismatch},
		{"duplicate key", bytes.Replace(bytes.Clone(raw), []byte(`"schema_version": "protected-ipv4-v1"`), []byte(`"schema_version":"protected-ipv4-v1","schema_version": "protected-ipv4-v1"`), 1), PinnedProtectedIPv4Digest, ErrContractInvalid},
		{"trailing value", append(bytes.Clone(raw), []byte(`{}`)...), PinnedProtectedIPv4Digest, ErrContractInvalid},
		{"empty", nil, PinnedProtectedIPv4Digest, ErrContractInvalid},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseProtectedContract(test.raw, test.digest)
			assertProtectedError(t, err, test.wantCode)
		})
	}
}

func TestAllBuiltInCIDRBoundariesFailClosed(t *testing.T) {
	t.Parallel()
	contract := checkedContract(t)
	gate := newGate(t, contract, baseConfig(EnvironmentProduction))
	for _, entry := range contract.entries {
		for _, prefix := range entry.cidrs {
			prefix := prefix
			for _, address := range []netip.Addr{prefix.Addr(), lastAddress(prefix)} {
				address := address
				t.Run(entry.id+"_"+address.String(), func(t *testing.T) {
					t.Parallel()
					result := gate.Check(passedInput(address.String()))
					if result.Allowed() {
						t.Fatalf("built-in boundary allowed: entry=%s cidr=%s address=%s", entry.id, prefix, address)
					}
					if result.StaticContractDigest != PinnedProtectedIPv4Digest || result.EffectiveConfigDigest == "" {
						t.Fatalf("missing digest binding: %+v", result)
					}
				})
			}
		}
	}
}

func TestOrdinaryPublicCanonicalTargetsAreAllowed(t *testing.T) {
	t.Parallel()
	gate := newGate(t, checkedContract(t), baseConfig(EnvironmentProduction))
	for _, target := range []string{"1.1.1.1", "8.8.8.8", "11.0.0.1", "93.184.216.34", "100.63.255.255", "100.128.0.1"} {
		target := target
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			result := gate.Check(passedInput(target))
			if !result.Allowed() || result.Reason != ReasonAllowed || result.TargetIPv4 != target || result.DemoExceptionApplied {
				t.Fatalf("Check(%s) = %+v", target, result)
			}
		})
	}
}

func TestRuntimeProtectedCategoriesAndAdditionsOverrideAllow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		reason ProtectedReason
		apply  func(*ProtectedConfig, string)
	}{
		{"configured", ReasonConfiguredCIDR, func(c *ProtectedConfig, _ string) { c.ProtectedCIDRs = []string{"8.8.8.0/24"} }},
		{"origin", ReasonOrigin, func(c *ProtectedConfig, target string) { c.OriginIPv4 = []string{target} }},
		{"gateway", ReasonGateway, func(c *ProtectedConfig, target string) { c.GatewayIPv4 = []string{target} }},
		{"executor", ReasonExecutor, func(c *ProtectedConfig, target string) { c.ExecutorIPv4 = []string{target} }},
		{"management", ReasonManagement, func(c *ProtectedConfig, target string) { c.ManagementIPv4 = []string{target} }},
		{"administrator", ReasonCurrentAdministratorPath, func(c *ProtectedConfig, target string) { c.CurrentAdminIPv4 = []string{target} }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := baseConfig(EnvironmentProduction)
			test.apply(&config, "8.8.8.8")
			gate := newGate(t, checkedContract(t), config)
			result := gate.Check(passedInput("8.8.8.8"))
			if result.Allowed() || result.Reason != test.reason || result.MatchedCIDR == "" {
				t.Fatalf("result = %+v, want %s", result, test.reason)
			}
		})
	}
}

func TestDemoExceptionRequiresExactIsolationAndAllowsOnlyFlaggedRFC5737Ranges(t *testing.T) {
	t.Parallel()
	contract := checkedContract(t)
	production := newGate(t, contract, baseConfig(EnvironmentProduction))
	if result := production.Check(passedInput("203.0.113.20")); result.Allowed() || result.Reason != ReasonBuiltInProtected {
		t.Fatalf("production documentation target = %+v", result)
	}
	disabled := newGate(t, contract, baseConfig(EnvironmentTest))
	if result := disabled.Check(passedInput("198.51.100.20")); result.Allowed() || result.Reason != ReasonBuiltInProtected {
		t.Fatalf("disabled-profile documentation target = %+v", result)
	}

	config := baseConfig(EnvironmentTest)
	config.Demo = DemoExceptionConfig{
		Profile:              DemoExceptionIsolatedRFC5737,
		AllowRFC5737:         true,
		IsolationVerified:    true,
		HostRulesetUnchanged: true,
		ClientCIDR:           "203.0.113.0/24",
		AttackSourceIPv4:     "203.0.113.20",
	}
	gate := newGate(t, contract, config)
	demoConfig := config
	demoConfig.Environment = EnvironmentDemo
	demoGate := newGate(t, contract, demoConfig)
	if result := demoGate.Check(passedInput("203.0.113.22")); !result.Allowed() ||
		result.Reason != ReasonAllowedDemoException || !result.DemoExceptionApplied {
		t.Fatalf("demo-environment RFC5737 target = %+v", result)
	}
	var demoEffective struct {
		Profile string   `json:"demo_exception_profile"`
		CIDRs   []string `json:"demo_exception_cidrs"`
	}
	if err := json.Unmarshal(gate.EffectiveConfigBytes(), &demoEffective); err != nil ||
		demoEffective.Profile != string(DemoExceptionIsolatedRFC5737) || !equalStrings(demoEffective.CIDRs, rfc5737CIDRs) {
		t.Fatalf("demo effective config = %+v, err=%v", demoEffective, err)
	}
	for _, target := range []string{
		"192.0.2.0", "192.0.2.20", "192.0.2.255",
		"198.51.100.0", "198.51.100.20", "198.51.100.255",
		"203.0.113.0", "203.0.113.19", "203.0.113.20", "203.0.113.21",
		"203.0.113.22", "203.0.113.23", "203.0.113.24", "203.0.113.255",
	} {
		result := gate.Check(passedInput(target))
		if !result.Allowed() || result.Reason != ReasonAllowedDemoException || !result.DemoExceptionApplied {
			t.Fatalf("isolated RFC5737 target %s = %+v", target, result)
		}
	}
	for _, target := range []string{"8.8.8.8", "11.0.0.1"} {
		result := gate.Check(passedInput(target))
		if !result.Allowed() || result.Reason != ReasonAllowed || result.DemoExceptionApplied {
			t.Fatalf("ordinary target %s = %+v", target, result)
		}
	}
	for _, target := range []string{"10.0.0.1", "100.64.0.1", "169.254.1.1", "198.18.0.1"} {
		result := gate.Check(passedInput(target))
		if result.Allowed() || result.DemoExceptionApplied {
			t.Fatalf("non-RFC5737 protected target %s = %+v", target, result)
		}
	}

	config.ProtectedCIDRs = []string{"203.0.113.22/32"}
	additive := newGate(t, contract, config)
	if result := additive.Check(passedInput("203.0.113.22")); result.Allowed() || result.Reason != ReasonConfiguredCIDR {
		t.Fatalf("additive override = %+v", result)
	}
	config.ProtectedCIDRs = nil
	config.CurrentAdminIPv4 = []string{"203.0.113.24"}
	runtime := newGate(t, contract, config)
	if result := runtime.Check(passedInput("203.0.113.24")); result.Allowed() || result.Reason != ReasonCurrentAdministratorPath {
		t.Fatalf("runtime override = %+v", result)
	}
}

func TestInvalidDemoAndProtectedConfigurationFailsAtConstruction(t *testing.T) {
	t.Parallel()
	contract := checkedContract(t)
	tests := []struct {
		name  string
		apply func(*ProtectedConfig)
	}{
		{"unknown environment", func(c *ProtectedConfig) { c.Environment = "staging" }},
		{"unknown profile", func(c *ProtectedConfig) { c.Demo.Profile = "enabled" }},
		{"production exception", func(c *ProtectedConfig) { enableDemo(c, EnvironmentProduction) }},
		{"development exception", func(c *ProtectedConfig) { enableDemo(c, EnvironmentDevelopment) }},
		{"missing allow", func(c *ProtectedConfig) { enableDemo(c, EnvironmentTest); c.Demo.AllowRFC5737 = false }},
		{"missing isolation", func(c *ProtectedConfig) { enableDemo(c, EnvironmentTest); c.Demo.IsolationVerified = false }},
		{"missing host proof", func(c *ProtectedConfig) { enableDemo(c, EnvironmentTest); c.Demo.HostRulesetUnchanged = false }},
		{"wrong demo CIDR", func(c *ProtectedConfig) { enableDemo(c, EnvironmentTest); c.Demo.ClientCIDR = "8.8.8.0/24" }},
		{"attack outside", func(c *ProtectedConfig) { enableDemo(c, EnvironmentTest); c.Demo.AttackSourceIPv4 = "198.51.100.20" }},
		{"disabled with allow", func(c *ProtectedConfig) { c.Demo.AllowRFC5737 = true }},
		{"noncanonical addition", func(c *ProtectedConfig) { c.ProtectedCIDRs = []string{"8.8.8.1/24"} }},
		{"IPv6 addition", func(c *ProtectedConfig) { c.ProtectedCIDRs = []string{"2001:db8::/32"} }},
		{"unordered additions", func(c *ProtectedConfig) { c.ProtectedCIDRs = []string{"9.0.0.0/8", "8.0.0.0/8"} }},
		{"duplicate additions", func(c *ProtectedConfig) { c.ProtectedCIDRs = []string{"8.0.0.0/8", "8.0.0.0/8"} }},
		{"noncanonical runtime", func(c *ProtectedConfig) { c.GatewayIPv4 = []string{"008.008.008.008"} }},
		{"IPv6 runtime", func(c *ProtectedConfig) { c.GatewayIPv4 = []string{"2001:4860:4860::8888"} }},
		{"unordered runtime", func(c *ProtectedConfig) { c.GatewayIPv4 = []string{"9.9.9.9", "8.8.8.8"} }},
		{"duplicate category", func(c *ProtectedConfig) { c.GatewayIPv4 = []string{"8.8.8.8"}; c.ExecutorIPv4 = []string{"8.8.8.8"} }},
		{"too many runtime addresses", func(c *ProtectedConfig) {
			c.GatewayIPv4 = make([]string, 65)
			for index := range c.GatewayIPv4 {
				c.GatewayIPv4[index] = fmt.Sprintf("8.8.8.%d", index+1)
			}
		}},
		{"too many additions", func(c *ProtectedConfig) {
			c.ProtectedCIDRs = make([]string, 257)
			for index := range c.ProtectedCIDRs {
				c.ProtectedCIDRs[index] = fmt.Sprintf("8.8.%d.%d/32", index/256, index%256)
			}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := baseConfig(EnvironmentProduction)
			test.apply(&config)
			_, err := NewProtectedGate(contract, config)
			assertProtectedError(t, err, ErrConfigInvalid)
		})
	}
}

func TestGateRejectsZeroContract(t *testing.T) {
	t.Parallel()
	_, err := NewProtectedGate(ProtectedContract{}, baseConfig(EnvironmentProduction))
	assertProtectedError(t, err, ErrContractInvalid)
}

func TestConsistencyProofIsRequiredBeforeTargetEvaluation(t *testing.T) {
	t.Parallel()
	gate := newGate(t, checkedContract(t), baseConfig(EnvironmentProduction))
	tests := []ProtectedInput{
		{TargetIPv4: "8.8.8.8"},
		{TargetIPv4: "8.8.8.8", Consistency: ConsistencyResult{Status: "failed", TargetIPv4: "8.8.8.8", PolicyDigest: testDigest, CanonicalCommandDigest: testDigest}},
		{TargetIPv4: "8.8.8.8", Consistency: ConsistencyResult{Status: ConsistencyPassed, TargetIPv4: "8.8.4.4", PolicyDigest: testDigest, CanonicalCommandDigest: testDigest}},
		{TargetIPv4: "8.8.8.8", Consistency: ConsistencyResult{Status: ConsistencyPassed, TargetIPv4: "8.8.8.8", PolicyDigest: "bad", CanonicalCommandDigest: testDigest}},
		{TargetIPv4: "8.8.8.8", Consistency: ConsistencyResult{Status: ConsistencyPassed, TargetIPv4: "8.8.8.8", PolicyDigest: testDigest, CanonicalCommandDigest: strings.ToUpper(testDigest)}},
	}
	for _, input := range tests {
		result := gate.Check(input)
		if result.Allowed() || result.Reason != ReasonConsistencyNotPassed || result.TargetIPv4 != "" {
			t.Fatalf("unproven consistency = %+v", result)
		}
	}
	var nilGate *ProtectedGate
	if result := nilGate.Check(passedInput("8.8.8.8")); result.Allowed() {
		t.Fatalf("nil gate allowed: %+v", result)
	}
}

func TestInvalidOrNonGlobalTargetsFailClosed(t *testing.T) {
	t.Parallel()
	gate := newGate(t, checkedContract(t), baseConfig(EnvironmentProduction))
	for _, target := range []string{"", "008.008.008.008", "8.8.8.8 ", "::1", "2001:4860:4860::8888", "0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255"} {
		target := target
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			t.Parallel()
			result := gate.Check(passedInput(target))
			if result.Allowed() || result.Reason != ReasonInvalidTarget {
				t.Fatalf("target %q = %+v", target, result)
			}
		})
	}
}

func TestEffectiveConfigurationIsCanonicalAndDefensivelyCopied(t *testing.T) {
	t.Parallel()
	contract := checkedContract(t)
	config := baseConfig(EnvironmentProduction)
	config.ProtectedCIDRs = []string{"8.8.8.0/24", "9.9.9.9/32"}
	config.GatewayIPv4 = []string{"1.1.1.1"}
	config.ExecutorIPv4 = []string{"2.2.2.2"}
	gate := newGate(t, contract, config)
	digestBefore := gate.EffectiveConfigDigest()
	bytesBefore := gate.EffectiveConfigBytes()
	if sha256Digest(bytesBefore) != digestBefore || digestBefore == "" {
		t.Fatalf("effective digest mismatch: %s %s", digestBefore, sha256Digest(bytesBefore))
	}
	var effective struct {
		SchemaVersion    string   `json:"schema_version"`
		StaticDigest     string   `json:"static_contract_digest"`
		ConfiguredCIDRs  []string `json:"configured_protected_cidrs"`
		RuntimeAddresses []string `json:"runtime_protected_ipv4"`
		DemoProfile      string   `json:"demo_exception_profile"`
		DemoCIDRs        []string `json:"demo_exception_cidrs"`
	}
	if err := json.Unmarshal(bytesBefore, &effective); err != nil {
		t.Fatal(err)
	}
	if effective.SchemaVersion != "protected-ipv4-effective-config-v1" || effective.StaticDigest != PinnedProtectedIPv4Digest || effective.DemoProfile != "disabled" || len(effective.DemoCIDRs) != 0 {
		t.Fatalf("effective config = %+v", effective)
	}

	config.ProtectedCIDRs[0] = "7.7.7.0/24"
	config.GatewayIPv4[0] = "3.3.3.3"
	contract.entries[0].cidrs[0] = netip.MustParsePrefix("8.0.0.0/8")
	bytesBefore[0] = 'x'
	if gate.EffectiveConfigDigest() != digestBefore || gate.EffectiveConfigBytes()[0] != '{' {
		t.Fatal("effective configuration mutated through caller-owned memory")
	}
	if result := gate.Check(passedInput("8.8.8.8")); result.Allowed() || result.Reason != ReasonConfiguredCIDR {
		t.Fatalf("configured protection changed after input mutation: %+v", result)
	}
	if result := gate.Check(passedInput("7.7.7.7")); !result.Allowed() {
		t.Fatalf("mutated caller config affected gate: %+v", result)
	}

	config2 := baseConfig(EnvironmentProduction)
	config2.ProtectedCIDRs = []string{"8.8.8.0/24", "9.9.9.9/32"}
	config2.GatewayIPv4 = []string{"1.1.1.1"}
	config2.ExecutorIPv4 = []string{"2.2.2.2"}
	gate2 := newGate(t, checkedContract(t), config2)
	if gate2.EffectiveConfigDigest() != digestBefore || !bytes.Equal(gate2.EffectiveConfigBytes(), gate.EffectiveConfigBytes()) {
		t.Fatal("semantically identical effective configuration was not deterministic")
	}
}

func TestErrorsAreTypedAndDoNotEchoConfig(t *testing.T) {
	t.Parallel()
	config := baseConfig(EnvironmentProduction)
	const secretShaped = "super-secret.invalid/24"
	config.ProtectedCIDRs = []string{secretShaped}
	_, err := NewProtectedGate(checkedContract(t), config)
	assertProtectedError(t, err, ErrConfigInvalid)
	if strings.Contains(err.Error(), secretShaped) || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("error leaked config: %v", err)
	}
}

func checkedContract(t *testing.T) ProtectedContract {
	t.Helper()
	contract, err := LoadProtectedContractFile(filepath.Join("..", "..", "contracts", "enforcement", "protected_ipv4_v1.json"))
	if err != nil {
		t.Fatalf("LoadProtectedContractFile() error = %v", err)
	}
	return contract
}

func checkedContractBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "enforcement", "protected_ipv4_v1.json"))
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	return raw
}

func baseConfig(environment Environment) ProtectedConfig {
	return ProtectedConfig{
		Environment: environment,
		Demo: DemoExceptionConfig{
			Profile:          DemoExceptionDisabled,
			ClientCIDR:       "203.0.113.0/24",
			AttackSourceIPv4: "203.0.113.20",
		},
	}
}

func enableDemo(config *ProtectedConfig, environment Environment) {
	config.Environment = environment
	config.Demo = DemoExceptionConfig{
		Profile:              DemoExceptionIsolatedRFC5737,
		AllowRFC5737:         true,
		IsolationVerified:    true,
		HostRulesetUnchanged: true,
		ClientCIDR:           "203.0.113.0/24",
		AttackSourceIPv4:     "203.0.113.20",
	}
}

func newGate(t *testing.T, contract ProtectedContract, config ProtectedConfig) *ProtectedGate {
	t.Helper()
	gate, err := NewProtectedGate(contract, config)
	if err != nil {
		t.Fatalf("NewProtectedGate() error = %v", err)
	}
	return gate
}

func passedInput(target string) ProtectedInput {
	return ProtectedInput{
		TargetIPv4: target,
		Consistency: ConsistencyResult{
			Status:                 ConsistencyPassed,
			TargetIPv4:             target,
			PolicyDigest:           testDigest,
			CanonicalCommandDigest: testDigest,
		},
	}
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	bytes4 := prefix.Addr().As4()
	network := binary.BigEndian.Uint32(bytes4[:])
	hostBits := 32 - prefix.Bits()
	var hostMask uint32
	if hostBits == 32 {
		hostMask = ^uint32(0)
	} else if hostBits > 0 {
		hostMask = uint32(1<<hostBits) - 1
	}
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], network|hostMask)
	return netip.AddrFrom4(result)
}

func assertProtectedError(t *testing.T, err error, code ProtectedErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	var typed *ProtectedError
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error = %T %v, want %s", err, err, code)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func ExampleProtectedGate_Check() {
	// Construction requires the checked contract; this example shows only the
	// typed ordered-gate input shape used after M5-011.
	input := passedInput("8.8.8.8")
	fmt.Println(input.Consistency.Status, input.TargetIPv4)
	// Output: passed 8.8.8.8
}
