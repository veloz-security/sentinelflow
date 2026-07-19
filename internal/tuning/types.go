// Package tuning performs offline, evidence-only threshold comparisons. It
// cannot mutate the frozen detector configuration or activate a profile.
package tuning

import (
	"errors"
	"regexp"
	"time"
)

const (
	CorpusSchemaVersion  = "threshold-comparison-corpus-v1"
	ReportSchemaVersion  = "threshold-comparison-report-v1"
	ProfileSchemaVersion = "threshold-profile-v1"

	RulePathScan           = "path_scan.v1"
	RuleRequestBurst       = "request_burst.v1"
	RuleLoginBruteForce    = "login_bruteforce.v1"
	RuleCredentialStuffing = "credential_stuffing.v1"

	EvidenceComplete   = "complete"
	EvidenceIncomplete = "incomplete"
	EvidenceUntrusted  = "untrusted"
	EvidenceUnverified = "unverified"

	DecisionMatched    = "matched"
	DecisionNoMatch    = "no_match"
	DecisionIncomplete = "incomplete"

	MaximumCorpusBytes = 256 << 10
	MaximumCases       = 1000
)

var (
	ErrInvalidCorpus = errors.New("threshold corpus rejected")
	ErrInvalidReport = errors.New("threshold report rejected")
	ErrUnsafeOutput  = errors.New("threshold report output rejected")

	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Observed struct {
	RawEventCount    int `json:"raw_event_count"`
	UniqueEventCount int `json:"unique_event_count"`
	DistinctCount    int `json:"distinct_count"`
}

type CorpusCase struct {
	CaseID               string   `json:"case_id"`
	RuleID               string   `json:"rule_id"`
	ExpectedAttack       bool     `json:"expected_attack"`
	EvidenceState        string   `json:"evidence_state"`
	Observed             Observed `json:"observed"`
	FalsePositiveFactors []string `json:"false_positive_factors"`
}

type Corpus struct {
	SchemaVersion   string       `json:"schema_version"`
	DatasetID       string       `json:"dataset_id"`
	Cases           []CorpusCase `json:"cases"`
	rawDigest       string
	canonicalDigest string
}

func (c Corpus) RawDigest() string       { return c.rawDigest }
func (c Corpus) CanonicalDigest() string { return c.canonicalDigest }

type Profile struct {
	SchemaVersion                      string `json:"schema_version"`
	ProfileID                          string `json:"profile_id"`
	PathScanDistinctThreshold          int    `json:"path_scan_distinct_threshold"`
	RequestBurstEventThreshold         int    `json:"request_burst_event_threshold"`
	LoginBruteForceEventThreshold      int    `json:"login_bruteforce_event_threshold"`
	CredentialStuffingEventThreshold   int    `json:"credential_stuffing_event_threshold"`
	CredentialStuffingAccountThreshold int    `json:"credential_stuffing_account_threshold"`
	ProfileDigest                      string `json:"profile_digest"`
}

type CaseResult struct {
	CaseID               string   `json:"case_id"`
	RuleID               string   `json:"rule_id"`
	ExpectedAttack       bool     `json:"expected_attack"`
	EvidenceState        string   `json:"evidence_state"`
	Decision             string   `json:"decision"`
	Correct              bool     `json:"correct"`
	ExplanationCode      string   `json:"explanation_code"`
	FalsePositiveFactors []string `json:"false_positive_factors"`
}

type ConfusionMatrix struct {
	TruePositive  int `json:"true_positive"`
	TrueNegative  int `json:"true_negative"`
	FalsePositive int `json:"false_positive"`
	FalseNegative int `json:"false_negative"`
	Incomplete    int `json:"incomplete"`
}

type ProfileResult struct {
	Profile            Profile         `json:"profile"`
	Matrix             ConfusionMatrix `json:"matrix"`
	GuardFailureCount  int             `json:"guard_failure_count"`
	ActivationEligible bool            `json:"activation_eligible"`
	ActivationReason   string          `json:"activation_reason"`
	Cases              []CaseResult    `json:"cases"`
}

type Report struct {
	SchemaVersion                     string          `json:"schema_version"`
	ReportID                          string          `json:"report_id"`
	Author                            string          `json:"author"`
	EvaluatedAt                       string          `json:"evaluated_at"`
	DatasetID                         string          `json:"dataset_id"`
	DatasetRawDigest                  string          `json:"dataset_raw_digest"`
	DatasetCanonicalDigest            string          `json:"dataset_canonical_digest"`
	ActiveRuntimeConfigurationVersion string          `json:"active_runtime_configuration_version"`
	ActiveRuntimeConfigurationDigest  string          `json:"active_runtime_configuration_digest"`
	PriorActiveProfile                Profile         `json:"prior_active_profile"`
	Results                           []ProfileResult `json:"results"`
	Recommendation                    string          `json:"recommendation"`
	SelectedProfileID                 string          `json:"selected_profile_id"`
	ActivationPerformed               bool            `json:"activation_performed"`
	ReportDigest                      string          `json:"report_digest"`
}

type Result struct {
	ReportID     string `json:"report_id"`
	ReportDigest string `json:"report_digest"`
	OutputPath   string `json:"output_path,omitempty"`
}

func canonicalTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
