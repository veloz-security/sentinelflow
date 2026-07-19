package tuning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

var allowedRules = set(
	RulePathScan, RuleRequestBurst, RuleLoginBruteForce, RuleCredentialStuffing,
)
var allowedEvidenceStates = set(
	EvidenceComplete, EvidenceIncomplete, EvidenceUntrusted, EvidenceUnverified,
)
var allowedFalsePositiveFactors = set(
	"none", "authorized_scanner", "load_test", "shared_nat", "credential_rotation",
)

func LoadCorpus(raw []byte) (Corpus, error) {
	if len(raw) == 0 || len(raw) > MaximumCorpusBytes {
		return Corpus{}, ErrInvalidCorpus
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var corpus Corpus
	if err := decoder.Decode(&corpus); err != nil {
		return Corpus{}, ErrInvalidCorpus
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Corpus{}, ErrInvalidCorpus
	}
	if err := validateCorpus(corpus); err != nil {
		return Corpus{}, err
	}
	canonical, err := json.Marshal(struct {
		SchemaVersion string       `json:"schema_version"`
		DatasetID     string       `json:"dataset_id"`
		Cases         []CorpusCase `json:"cases"`
	}{corpus.SchemaVersion, corpus.DatasetID, corpus.Cases})
	if err != nil {
		return Corpus{}, ErrInvalidCorpus
	}
	corpus.rawDigest = sha256Digest(raw)
	corpus.canonicalDigest = sha256Digest(canonical)
	return corpus, nil
}

func validateCorpus(corpus Corpus) error {
	if corpus.SchemaVersion != CorpusSchemaVersion || !idPattern.MatchString(corpus.DatasetID) ||
		len(corpus.Cases) == 0 || len(corpus.Cases) > MaximumCases {
		return ErrInvalidCorpus
	}
	type coverage struct{ attack, benign, guarded bool }
	covered := make(map[string]coverage, len(allowedRules))
	for index, item := range corpus.Cases {
		if !idPattern.MatchString(item.CaseID) || !allowedRules[item.RuleID] ||
			!allowedEvidenceStates[item.EvidenceState] ||
			(index > 0 && corpus.Cases[index-1].CaseID >= item.CaseID) ||
			item.Observed.RawEventCount < 0 || item.Observed.RawEventCount > 1_000_000 ||
			item.Observed.UniqueEventCount < 0 || item.Observed.UniqueEventCount > item.Observed.RawEventCount ||
			item.Observed.DistinctCount < 0 || item.Observed.DistinctCount > item.Observed.UniqueEventCount ||
			len(item.FalsePositiveFactors) == 0 || len(item.FalsePositiveFactors) > 5 ||
			!sortedUniqueAllowed(item.FalsePositiveFactors, allowedFalsePositiveFactors) {
			return ErrInvalidCorpus
		}
		switch item.RuleID {
		case RulePathScan:
			if item.Observed.DistinctCount > 8 {
				return ErrInvalidCorpus
			}
		case RuleRequestBurst, RuleLoginBruteForce:
			if item.Observed.DistinctCount != 0 {
				return ErrInvalidCorpus
			}
		case RuleCredentialStuffing:
			if item.Observed.DistinctCount > 1000 {
				return ErrInvalidCorpus
			}
		}
		if item.ExpectedAttack &&
			(len(item.FalsePositiveFactors) != 1 || item.FalsePositiveFactors[0] != "none") {
			return ErrInvalidCorpus
		}
		if len(item.FalsePositiveFactors) > 1 {
			for _, factor := range item.FalsePositiveFactors {
				if factor == "none" {
					return ErrInvalidCorpus
				}
			}
		}
		value := covered[item.RuleID]
		if item.EvidenceState == EvidenceComplete {
			if item.ExpectedAttack {
				value.attack = true
			} else {
				value.benign = true
			}
		} else {
			value.guarded = true
		}
		covered[item.RuleID] = value
	}
	for rule := range allowedRules {
		value := covered[rule]
		if !value.attack || !value.benign || !value.guarded {
			return ErrInvalidCorpus
		}
	}
	return nil
}

func sortedUniqueAllowed(values []string, allowed map[string]bool) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !allowed[value] || (index > 0 && values[index-1] == value) {
			return false
		}
	}
	return true
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func set(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
