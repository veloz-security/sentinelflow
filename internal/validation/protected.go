package validation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
)

var rfc5737CIDRs = []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}

type runtimeProtected struct {
	reason ProtectedReason
}

type ProtectedGate struct {
	contract        ProtectedContract
	additions       []netip.Prefix
	runtime         map[netip.Addr]runtimeProtected
	demoActive      bool
	effectiveBytes  []byte
	effectiveDigest string
}

func NewProtectedGate(contract ProtectedContract, config ProtectedConfig) (*ProtectedGate, error) {
	if contract.digest != PinnedProtectedIPv4Digest || len(contract.entries) != 26 {
		return nil, &ProtectedError{Code: ErrContractInvalid}
	}
	if config.Environment != EnvironmentDevelopment && config.Environment != EnvironmentTest &&
		config.Environment != EnvironmentDemo && config.Environment != EnvironmentProduction {
		return nil, &ProtectedError{Code: ErrConfigInvalid}
	}

	additions, err := parseOrderedPrefixes(config.ProtectedCIDRs)
	if err != nil {
		return nil, &ProtectedError{Code: ErrConfigInvalid}
	}
	runtime := make(map[netip.Addr]runtimeProtected)
	categoryInputs := []struct {
		values []string
		reason ProtectedReason
	}{
		{config.OriginIPv4, ReasonOrigin},
		{config.GatewayIPv4, ReasonGateway},
		{config.ExecutorIPv4, ReasonExecutor},
		{config.ManagementIPv4, ReasonManagement},
		{config.CurrentAdminIPv4, ReasonCurrentAdministratorPath},
	}
	for _, category := range categoryInputs {
		addresses, err := parseOrderedAddresses(category.values)
		if err != nil {
			return nil, &ProtectedError{Code: ErrConfigInvalid}
		}
		for _, address := range addresses {
			if _, duplicate := runtime[address]; duplicate {
				return nil, &ProtectedError{Code: ErrConfigInvalid}
			}
			runtime[address] = runtimeProtected{reason: category.reason}
		}
	}
	if len(runtime) > 64 {
		return nil, &ProtectedError{Code: ErrConfigInvalid}
	}

	demoActive, _, _, err := validateDemoConfig(config.Environment, config.Demo)
	if err != nil {
		return nil, &ProtectedError{Code: ErrConfigInvalid}
	}
	runtimeStrings := make([]string, 0, len(runtime))
	for address := range runtime {
		runtimeStrings = append(runtimeStrings, address.String())
	}
	sort.Slice(runtimeStrings, func(i, j int) bool {
		left, _ := netip.ParseAddr(runtimeStrings[i])
		right, _ := netip.ParseAddr(runtimeStrings[j])
		return left.Compare(right) < 0
	})
	configured := make([]string, len(additions))
	for index, prefix := range additions {
		configured[index] = prefix.String()
	}
	demoCIDRs := []string{}
	profile := string(DemoExceptionDisabled)
	if demoActive {
		profile = string(DemoExceptionIsolatedRFC5737)
		demoCIDRs = append([]string(nil), rfc5737CIDRs...)
	}
	effective := map[string]any{
		"schema_version":             "protected-ipv4-effective-config-v1",
		"static_contract_digest":     contract.digest,
		"configured_protected_cidrs": configured,
		"runtime_protected_ipv4":     runtimeStrings,
		"demo_exception_profile":     profile,
		"demo_exception_cidrs":       demoCIDRs,
	}
	rawEffective, err := json.Marshal(effective)
	if err != nil {
		return nil, &ProtectedError{Code: ErrConfigInvalid}
	}
	canonicalEffective, err := canonicalJSON(rawEffective)
	if err != nil {
		return nil, &ProtectedError{Code: ErrConfigInvalid}
	}

	entries := make([]protectedEntry, len(contract.entries))
	for index, entry := range contract.entries {
		entries[index] = protectedEntry{id: entry.id, cidrs: append([]netip.Prefix(nil), entry.cidrs...), demoExceptionAllowed: entry.demoExceptionAllowed}
	}
	return &ProtectedGate{
		contract:        ProtectedContract{entries: entries, digest: contract.digest, rawDigest: contract.rawDigest},
		additions:       append([]netip.Prefix(nil), additions...),
		runtime:         runtime,
		demoActive:      demoActive,
		effectiveBytes:  bytes.Clone(canonicalEffective),
		effectiveDigest: sha256Digest(canonicalEffective),
	}, nil
}

func (g *ProtectedGate) EffectiveConfigBytes() []byte {
	if g == nil {
		return nil
	}
	return bytes.Clone(g.effectiveBytes)
}

func (g *ProtectedGate) EffectiveConfigDigest() string {
	if g == nil {
		return ""
	}
	return g.effectiveDigest
}

func (g *ProtectedGate) Check(input ProtectedInput) ProtectedResult {
	base := ProtectedResult{Decision: DecisionBlocked}
	if g == nil {
		base.Reason = ReasonConsistencyNotPassed
		return base
	}
	base.StaticContractDigest = g.contract.digest
	base.EffectiveConfigDigest = g.effectiveDigest
	if input.Consistency.Status != ConsistencyPassed || input.Consistency.TargetIPv4 != input.TargetIPv4 ||
		!validDigest(input.Consistency.PolicyDigest) || !validDigest(input.Consistency.CanonicalCommandDigest) {
		base.Reason = ReasonConsistencyNotPassed
		return base
	}
	target, err := parseCanonicalIPv4(input.TargetIPv4)
	if err != nil || !target.IsGlobalUnicast() {
		base.Reason = ReasonInvalidTarget
		return base
	}
	base.TargetIPv4 = target.String()
	if matched, exists := g.runtime[target]; exists {
		base.Reason = matched.reason
		base.MatchedCIDR = target.String() + "/32"
		return base
	}
	for _, prefix := range g.additions {
		if prefix.Contains(target) {
			base.Reason = ReasonConfiguredCIDR
			base.MatchedCIDR = prefix.String()
			return base
		}
	}
	demoApplied := false
	for _, entry := range g.contract.entries {
		for _, prefix := range entry.cidrs {
			if !prefix.Contains(target) {
				continue
			}
			if entry.demoExceptionAllowed && g.demoActive {
				demoApplied = true
				continue
			}
			base.Reason = ReasonBuiltInProtected
			base.MatchedEntryID = entry.id
			base.MatchedCIDR = prefix.String()
			return base
		}
	}
	base.Decision = DecisionAllowed
	base.Reason = ReasonAllowed
	if demoApplied {
		base.Reason = ReasonAllowedDemoException
		base.DemoExceptionApplied = true
	}
	return base
}

func validateDemoConfig(environment Environment, config DemoExceptionConfig) (bool, netip.Prefix, netip.Addr, error) {
	var client netip.Prefix
	var attack netip.Addr
	if config.ClientCIDR != "" || config.AttackSourceIPv4 != "" {
		var err error
		client, err = parseCanonicalIPv4Prefix(config.ClientCIDR)
		if err != nil || !isRFC5737Prefix(client) {
			return false, netip.Prefix{}, netip.Addr{}, errConfig
		}
		attack, err = parseCanonicalIPv4(config.AttackSourceIPv4)
		if err != nil || !client.Contains(attack) {
			return false, netip.Prefix{}, netip.Addr{}, errConfig
		}
	}
	switch config.Profile {
	case DemoExceptionDisabled:
		if config.AllowRFC5737 || config.IsolationVerified || config.HostRulesetUnchanged {
			return false, netip.Prefix{}, netip.Addr{}, errConfig
		}
		return false, client, attack, nil
	case DemoExceptionIsolatedRFC5737:
		if environment != EnvironmentDemo && environment != EnvironmentTest {
			return false, netip.Prefix{}, netip.Addr{}, errConfig
		}
		if !config.AllowRFC5737 || !config.IsolationVerified || !config.HostRulesetUnchanged || !client.IsValid() || !attack.IsValid() {
			return false, netip.Prefix{}, netip.Addr{}, errConfig
		}
		return true, client, attack, nil
	default:
		return false, netip.Prefix{}, netip.Addr{}, errConfig
	}
}

var errConfig = &ProtectedError{Code: ErrConfigInvalid}

func parseOrderedPrefixes(values []string) ([]netip.Prefix, error) {
	if len(values) > 256 {
		return nil, errConfig
	}
	result := make([]netip.Prefix, len(values))
	for index, text := range values {
		prefix, err := parseCanonicalIPv4Prefix(text)
		if err != nil {
			return nil, errConfig
		}
		if index > 0 && comparePrefixes(result[index-1], prefix) >= 0 {
			return nil, errConfig
		}
		result[index] = prefix
	}
	return result, nil
}

func parseOrderedAddresses(values []string) ([]netip.Addr, error) {
	if len(values) > 64 {
		return nil, errConfig
	}
	result := make([]netip.Addr, len(values))
	for index, text := range values {
		address, err := parseCanonicalIPv4(text)
		if err != nil {
			return nil, errConfig
		}
		if index > 0 && result[index-1].Compare(address) >= 0 {
			return nil, errConfig
		}
		result[index] = address
	}
	return result, nil
}

func parseCanonicalIPv4(text string) (netip.Addr, error) {
	address, err := netip.ParseAddr(text)
	if err != nil || !address.Is4() || address.String() != text {
		return netip.Addr{}, errConfig
	}
	return address, nil
}

func parseCanonicalIPv4Prefix(text string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != text {
		return netip.Prefix{}, errConfig
	}
	return prefix, nil
}

func comparePrefixes(left, right netip.Prefix) int {
	if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
		return comparison
	}
	switch {
	case left.Bits() < right.Bits():
		return -1
	case left.Bits() > right.Bits():
		return 1
	default:
		return 0
	}
}

func isRFC5737Prefix(prefix netip.Prefix) bool {
	for _, allowed := range rfc5737CIDRs {
		if prefix.String() == allowed {
			return true
		}
	}
	return false
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}
