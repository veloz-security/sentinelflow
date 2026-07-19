package tuning

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

func Compare(corpus Corpus, author string, evaluatedAt time.Time) (Report, error) {
	if err := validateCorpus(corpus); err != nil || !digestPattern.MatchString(corpus.RawDigest()) ||
		!digestPattern.MatchString(corpus.CanonicalDigest()) || !idPattern.MatchString(author) ||
		evaluatedAt.IsZero() {
		return Report{}, ErrInvalidReport
	}
	profiles := []Profile{
		newProfile("baseline-v1", 8, 120, 10, 20, 8),
		newProfile("conservative-v1", 8, 150, 12, 24, 10),
		newProfile("sensitive-v1", 7, 100, 8, 16, 6),
	}
	results := make([]ProfileResult, len(profiles))
	for index, profile := range profiles {
		results[index] = compareProfile(corpus, profile)
	}
	baseline := results[0].Matrix
	for index := range results {
		result := &results[index]
		result.ActivationEligible = result.GuardFailureCount == 0 &&
			result.Matrix.FalseNegative <= baseline.FalseNegative &&
			result.Matrix.FalsePositive <= baseline.FalsePositive
		switch {
		case result.GuardFailureCount > 0:
			result.ActivationReason = "evidence_guard_regression"
		case result.Matrix.FalseNegative > baseline.FalseNegative:
			result.ActivationReason = "attack_detection_regression"
		case result.Matrix.FalsePositive > baseline.FalsePositive:
			result.ActivationReason = "false_positive_regression"
		default:
			result.ActivationReason = "normal_attack_regression_clear"
		}
	}
	active := detection.NewDefault()
	report := Report{
		SchemaVersion: ReportSchemaVersion, Author: author,
		EvaluatedAt: canonicalTime(evaluatedAt), DatasetID: corpus.DatasetID,
		DatasetRawDigest: corpus.RawDigest(), DatasetCanonicalDigest: corpus.CanonicalDigest(),
		ActiveRuntimeConfigurationVersion: detection.DefaultConfigurationVersion,
		ActiveRuntimeConfigurationDigest:  active.ConfigurationDigest(),
		PriorActiveProfile:                profiles[0], Results: results,
		Recommendation: "retain_frozen_baseline", SelectedProfileID: profiles[0].ProfileID,
		ActivationPerformed: false,
	}
	report.ReportID = reportIdentity(report)
	var err error
	report.ReportDigest, err = digestJSON("sentinelflow threshold report v1", reportForDigest(report))
	if err != nil {
		return Report{}, ErrInvalidReport
	}
	return report, nil
}

func compareProfile(corpus Corpus, profile Profile) ProfileResult {
	result := ProfileResult{Profile: profile, Cases: make([]CaseResult, 0, len(corpus.Cases))}
	for _, item := range corpus.Cases {
		decision := evaluate(item, profile)
		caseResult := CaseResult{
			CaseID: item.CaseID, RuleID: item.RuleID, ExpectedAttack: item.ExpectedAttack,
			EvidenceState: item.EvidenceState, Decision: decision,
			FalsePositiveFactors: append([]string(nil), item.FalsePositiveFactors...),
		}
		switch {
		case item.EvidenceState != EvidenceComplete:
			result.Matrix.Incomplete++
			caseResult.Correct = decision == DecisionIncomplete
			caseResult.ExplanationCode = "evidence_guard_fail_closed"
			if decision != DecisionIncomplete {
				result.GuardFailureCount++
			}
		case decision == DecisionMatched && item.ExpectedAttack:
			result.Matrix.TruePositive++
			caseResult.Correct = true
			caseResult.ExplanationCode = "expected_attack_detected"
		case decision == DecisionNoMatch && !item.ExpectedAttack:
			result.Matrix.TrueNegative++
			caseResult.Correct = true
			caseResult.ExplanationCode = "expected_benign_not_detected"
		case decision == DecisionMatched:
			result.Matrix.FalsePositive++
			caseResult.ExplanationCode = "candidate_threshold_false_positive"
		default:
			result.Matrix.FalseNegative++
			caseResult.ExplanationCode = "candidate_threshold_false_negative"
		}
		result.Cases = append(result.Cases, caseResult)
	}
	return result
}

func evaluate(item CorpusCase, profile Profile) string {
	if item.EvidenceState != EvidenceComplete {
		return DecisionIncomplete
	}
	matched := false
	switch item.RuleID {
	case RulePathScan:
		matched = item.Observed.DistinctCount >= profile.PathScanDistinctThreshold
	case RuleRequestBurst:
		matched = item.Observed.UniqueEventCount >= profile.RequestBurstEventThreshold
	case RuleLoginBruteForce:
		matched = item.Observed.UniqueEventCount >= profile.LoginBruteForceEventThreshold
	case RuleCredentialStuffing:
		matched = item.Observed.UniqueEventCount >= profile.CredentialStuffingEventThreshold &&
			item.Observed.DistinctCount >= profile.CredentialStuffingAccountThreshold
	}
	if matched {
		return DecisionMatched
	}
	return DecisionNoMatch
}

func newProfile(id string, path, burst, brute, credentialEvents, credentialAccounts int) Profile {
	profile := Profile{
		SchemaVersion: ProfileSchemaVersion, ProfileID: id,
		PathScanDistinctThreshold: path, RequestBurstEventThreshold: burst,
		LoginBruteForceEventThreshold:      brute,
		CredentialStuffingEventThreshold:   credentialEvents,
		CredentialStuffingAccountThreshold: credentialAccounts,
	}
	profile.ProfileDigest, _ = digestJSON("sentinelflow threshold profile v1", profileForDigest(profile))
	return profile
}

func VerifyReport(report Report, corpus Corpus) error {
	if report.SchemaVersion != ReportSchemaVersion || !idPattern.MatchString(report.Author) ||
		!digestPattern.MatchString(report.ReportID) || !digestPattern.MatchString(report.ReportDigest) ||
		report.DatasetID != corpus.DatasetID || report.DatasetRawDigest != corpus.RawDigest() ||
		report.DatasetCanonicalDigest != corpus.CanonicalDigest() || report.ActivationPerformed ||
		report.Recommendation != "retain_frozen_baseline" || report.SelectedProfileID != "baseline-v1" {
		return ErrInvalidReport
	}
	evaluatedAt, err := parseCanonicalTime(report.EvaluatedAt)
	if err != nil {
		return ErrInvalidReport
	}
	expected, err := Compare(corpus, report.Author, evaluatedAt)
	if err != nil {
		return ErrInvalidReport
	}
	actualBytes, err := json.Marshal(report)
	if err != nil {
		return ErrInvalidReport
	}
	expectedBytes, err := json.Marshal(expected)
	if err != nil || !hmac.Equal(actualBytes, expectedBytes) {
		return ErrInvalidReport
	}
	return nil
}

func EncodeReport(report Report, corpus Corpus) ([]byte, Result, error) {
	if err := VerifyReport(report, corpus); err != nil {
		return nil, Result{}, err
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil || len(encoded)+1 > MaximumCorpusBytes {
		return nil, Result{}, ErrInvalidReport
	}
	encoded = append(encoded, '\n')
	return encoded, Result{ReportID: report.ReportID, ReportDigest: report.ReportDigest}, nil
}

func DecodeAndVerifyReport(raw []byte, corpus Corpus) (Report, Result, error) {
	if len(raw) == 0 || len(raw) > MaximumCorpusBytes {
		return Report{}, Result{}, ErrInvalidReport
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, Result{}, ErrInvalidReport
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Report{}, Result{}, ErrInvalidReport
	}
	if err := VerifyReport(report, corpus); err != nil {
		return Report{}, Result{}, err
	}
	return report, Result{ReportID: report.ReportID, ReportDigest: report.ReportDigest}, nil
}

func reportIdentity(report Report) string {
	profileDigests := make([]string, 0, len(report.Results)+1)
	profileDigests = append(profileDigests, report.PriorActiveProfile.ProfileDigest)
	for _, result := range report.Results {
		profileDigests = append(profileDigests, result.Profile.ProfileDigest,
			result.ActivationReason,
			integerText(result.Matrix.TruePositive), integerText(result.Matrix.TrueNegative),
			integerText(result.Matrix.FalsePositive), integerText(result.Matrix.FalseNegative),
			integerText(result.Matrix.Incomplete), integerText(result.GuardFailureCount))
	}
	values := []string{
		report.Author, report.EvaluatedAt, report.DatasetID, report.DatasetRawDigest,
		report.DatasetCanonicalDigest, report.ActiveRuntimeConfigurationVersion,
		report.ActiveRuntimeConfigurationDigest,
	}
	values = append(values, profileDigests...)
	return digestStrings("sentinelflow threshold report id v1", values)
}

func profileForDigest(value Profile) Profile {
	value.ProfileDigest = ""
	return value
}

func reportForDigest(value Report) Report {
	value.ReportDigest = ""
	return value
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || canonicalTime(parsed) != value {
		return time.Time{}, ErrInvalidReport
	}
	return parsed, nil
}
