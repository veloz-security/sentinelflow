// Package validation implements ordered, fail-closed validation gates.
package validation

import "net/netip"

const PinnedProtectedIPv4Digest = "sha256:d3dfb63a573925e19f29e8595fd5574bc441a9c468d2f9ef6d2f004abb101104"

type ProtectedErrorCode string

const (
	ErrContractInvalid ProtectedErrorCode = "protected_contract_invalid"
	ErrDigestMismatch  ProtectedErrorCode = "protected_contract_digest_mismatch"
	ErrConfigInvalid   ProtectedErrorCode = "protected_config_invalid"
)

type ProtectedError struct{ Code ProtectedErrorCode }

func (e *ProtectedError) Error() string {
	if e == nil {
		return "protected IPv4 gate rejected configuration"
	}
	return "protected IPv4 gate rejected configuration: " + string(e.Code)
}

type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentTest        Environment = "test"
	EnvironmentDemo        Environment = "demo"
	EnvironmentProduction  Environment = "production"
)

type DemoExceptionProfile string

const (
	DemoExceptionDisabled        DemoExceptionProfile = "disabled"
	DemoExceptionIsolatedRFC5737 DemoExceptionProfile = "isolated-rfc5737"
)

type DemoExceptionConfig struct {
	Profile              DemoExceptionProfile
	AllowRFC5737         bool
	IsolationVerified    bool
	HostRulesetUnchanged bool
	ClientCIDR           string
	AttackSourceIPv4     string
}

// ProtectedConfig has no exclusion field: configured CIDRs can only add
// protection. Runtime categories are separate so a result has one typed reason.
type ProtectedConfig struct {
	Environment      Environment
	ProtectedCIDRs   []string
	OriginIPv4       []string
	GatewayIPv4      []string
	ExecutorIPv4     []string
	ManagementIPv4   []string
	CurrentAdminIPv4 []string
	Demo             DemoExceptionConfig
}

type ConsistencyStatus string

const (
	ConsistencyPassed ConsistencyStatus = "passed"
	ConsistencyFailed ConsistencyStatus = "failed"
)

// ConsistencyResult is produced by the preceding M5-011 gate. This package
// refuses to run on a missing/failed result and does not orchestrate that gate.
type ConsistencyResult struct {
	Status                 ConsistencyStatus
	FailureCode            ConsistencyFailureCode
	TargetIPv4             string
	PolicyDigest           string
	GeneratedCommandDigest string
	CanonicalCommandDigest string
	EvidenceSnapshotDigest string
	AnalysisInputDigest    string
	AnalysisOutputDigest   string
	RationaleDigest        string
}

type ProtectedInput struct {
	TargetIPv4  string
	Consistency ConsistencyResult
}

type ProtectedDecision string

const (
	DecisionAllowed ProtectedDecision = "allowed"
	DecisionBlocked ProtectedDecision = "blocked"
)

type ProtectedReason string

const (
	ReasonAllowed                  ProtectedReason = "allowed"
	ReasonAllowedDemoException     ProtectedReason = "allowed_demo_rfc5737_exception"
	ReasonConsistencyNotPassed     ProtectedReason = "consistency_not_passed"
	ReasonInvalidTarget            ProtectedReason = "invalid_or_non_global_ipv4"
	ReasonBuiltInProtected         ProtectedReason = "built_in_protected"
	ReasonConfiguredCIDR           ProtectedReason = "configured_protected_cidr"
	ReasonOrigin                   ProtectedReason = "origin_address"
	ReasonGateway                  ProtectedReason = "gateway_address"
	ReasonExecutor                 ProtectedReason = "executor_address"
	ReasonManagement               ProtectedReason = "management_address"
	ReasonCurrentAdministratorPath ProtectedReason = "current_administrator_path"
)

type ProtectedResult struct {
	Decision              ProtectedDecision
	Reason                ProtectedReason
	TargetIPv4            string
	MatchedEntryID        string
	MatchedCIDR           string
	StaticContractDigest  string
	EffectiveConfigDigest string
	DemoExceptionApplied  bool
}

func (r ProtectedResult) Allowed() bool { return r.Decision == DecisionAllowed }

type protectedEntry struct {
	id                   string
	cidrs                []netip.Prefix
	demoExceptionAllowed bool
}

type ProtectedContract struct {
	entries   []protectedEntry
	digest    string
	rawDigest string
}

func (c ProtectedContract) Digest() string    { return c.digest }
func (c ProtectedContract) RawDigest() string { return c.rawDigest }
