package policy

import (
	"bytes"
	"regexp"
)

var evidenceIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func CanonicalBytes(ast AST) ([]byte, error) {
	if !ast.target.IsValid() || !ast.target.Is4() || !ast.target.IsGlobalUnicast() || ast.target.String() == "" {
		return nil, reject(ErrorTarget)
	}
	token, err := CanonicalTTL(ast.ttlSeconds)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, 96)
	result = append(result, "add element inet sentinelflow blacklist_ipv4 { "...)
	result = append(result, ast.target.String()...)
	result = append(result, " timeout "...)
	result = append(result, token...)
	result = append(result, " }\n"...)
	return result, nil
}

// BuildArtifact applies the command-schema and policy/command consistency
// checks that can be proven without protected-range, history, nft, HIL, or DB
// access.
func BuildArtifact(policy Policy, candidate Candidate) (Artifact, error) {
	if policy.SchemaVersion != PolicySchemaVersion || candidate.SchemaVersion != CandidateSchemaVersion {
		return Artifact{}, reject(ErrorSchema)
	}
	if policy.Action != ActionBlockIP {
		return Artifact{}, reject(ErrorAction)
	}
	if !validEvidenceIDs(policy.EvidenceIDs) || !validEvidenceIDs(candidate.EvidenceIDs) || !equalEvidence(policy.EvidenceIDs, candidate.EvidenceIDs) {
		return Artifact{}, reject(ErrorEvidence)
	}
	ast, err := Parse(candidate.GeneratedBytes)
	if err != nil {
		return Artifact{}, err
	}
	if candidate.TargetIPv4 != ast.TargetIPv4() || policy.TargetIPv4 != ast.TargetIPv4() {
		return Artifact{}, reject(ErrorTargetMismatch)
	}
	if candidate.TimeoutToken != ast.InputTTLToken() {
		return Artifact{}, reject(ErrorCandidateMismatch)
	}
	if policy.TTLSeconds != ast.TTLSeconds() {
		return Artifact{}, reject(ErrorTTLMismatch)
	}
	canonicalToken, err := CanonicalTTL(ast.TTLSeconds())
	if err != nil {
		return Artifact{}, err
	}
	canonical, err := CanonicalBytes(ast)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		ast:             ast,
		generatedBytes:  bytes.Clone(candidate.GeneratedBytes),
		generatedDigest: Digest(candidate.GeneratedBytes),
		canonicalBytes:  canonical,
		canonicalDigest: Digest(canonical),
		canonicalToken:  canonicalToken,
		evidenceIDs:     append([]string(nil), policy.EvidenceIDs...),
	}, nil
}

func validEvidenceIDs(ids []string) bool {
	if len(ids) == 0 || len(ids) > MaxEvidenceIDs {
		return false
	}
	previous := ""
	for index, id := range ids {
		if !evidenceIDPattern.MatchString(id) || index > 0 && id <= previous {
			return false
		}
		previous = id
	}
	return true
}

func equalEvidence(left, right []string) bool {
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
