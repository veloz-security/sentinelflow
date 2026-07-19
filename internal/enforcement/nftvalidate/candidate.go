package nftvalidate

import (
	"bytes"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"unicode/utf8"
)

var (
	candidatePattern = regexp.MustCompile(`^add element inet sentinelflow blacklist_ipv4 \{ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) timeout ([1-9][0-9]{0,4}[smh]) \}\n?$`)
	ttlPattern       = regexp.MustCompile(`^([1-9][0-9]{0,4})([smh])$`)
)

// Canonicalize parses the closed candidate grammar and checks exact equality
// with the structured policy TTL. It intentionally does not perform the
// protected-target or owned-schema gates; callers that need a gate-complete
// value must use Validate.
func Canonicalize(generated []byte, policyTTLSeconds uint32) (Artifact, error) {
	if policyTTLSeconds < MinTTLSeconds || policyTTLSeconds > MaxTTLSeconds {
		return Artifact{}, reject(ErrorTTL)
	}
	if len(generated) == 0 || len(generated) > MaxCandidateBytes ||
		!utf8.Valid(generated) || bytes.HasPrefix(generated, []byte{0xef, 0xbb, 0xbf}) {
		return Artifact{}, reject(ErrorCandidateSyntax)
	}
	for _, value := range generated {
		// The frozen grammar is ASCII. This also rejects NUL and every hidden
		// Unicode whitespace or metacharacter despite otherwise valid UTF-8.
		if value == 0 || value > 0x7f {
			return Artifact{}, reject(ErrorCandidateSyntax)
		}
	}

	matches := candidatePattern.FindSubmatch(generated)
	if len(matches) != 3 {
		return Artifact{}, reject(ErrorCandidateSyntax)
	}
	targetText := string(matches[1])
	target, err := netip.ParseAddr(targetText)
	if err != nil || !target.Is4() || !target.IsGlobalUnicast() || target.String() != targetText {
		return Artifact{}, reject(ErrorTarget)
	}
	inputToken := string(matches[2])
	seconds, err := parseTTL(inputToken)
	if err != nil {
		return Artifact{}, err
	}
	if seconds != policyTTLSeconds {
		return Artifact{}, reject(ErrorTTLMismatch)
	}
	canonicalToken, err := canonicalTTL(seconds)
	if err != nil {
		return Artifact{}, err
	}
	canonical := make([]byte, 0, 96)
	canonical = append(canonical, "add element inet sentinelflow blacklist_ipv4 { "...)
	canonical = append(canonical, targetText...)
	canonical = append(canonical, " timeout "...)
	canonical = append(canonical, canonicalToken...)
	canonical = append(canonical, " }\n"...)

	return Artifact{
		target:          target,
		ttlSeconds:      seconds,
		inputTTLToken:   inputToken,
		canonicalToken:  canonicalToken,
		generated:       append([]byte(nil), generated...),
		generatedDigest: digest(generated),
		canonical:       canonical,
		canonicalDigest: digest(canonical),
	}, nil
}

func parseTTL(token string) (uint32, error) {
	matches := ttlPattern.FindStringSubmatch(token)
	if len(matches) != 3 {
		return 0, reject(ErrorTTL)
	}
	value, err := strconv.ParseUint(matches[1], 10, 64)
	if err != nil {
		return 0, reject(ErrorTTL)
	}
	multiplier := uint64(1)
	switch matches[2] {
	case "m":
		multiplier = 60
	case "h":
		multiplier = 3600
	}
	if value > math.MaxUint64/multiplier {
		return 0, reject(ErrorTTL)
	}
	seconds := value * multiplier
	if seconds < uint64(MinTTLSeconds) || seconds > uint64(MaxTTLSeconds) {
		return 0, reject(ErrorTTL)
	}
	return uint32(seconds), nil
}

func canonicalTTL(seconds uint32) (string, error) {
	if seconds < MinTTLSeconds || seconds > MaxTTLSeconds {
		return "", reject(ErrorTTL)
	}
	switch {
	case seconds%3600 == 0:
		return strconv.FormatUint(uint64(seconds/3600), 10) + "h", nil
	case seconds%60 == 0:
		return strconv.FormatUint(uint64(seconds/60), 10) + "m", nil
	default:
		return strconv.FormatUint(uint64(seconds), 10) + "s", nil
	}
}

// Validate runs the complete pure gate in frozen order. A successful result
// still requires an isolated fixed-binary nft --check before HIL eligibility.
func Validate(input Input) (Result, error) {
	artifact, err := Canonicalize(input.GeneratedCandidate, input.PolicyTTLSeconds)
	if err != nil {
		return Result{}, err
	}
	if input.AuthorizeTarget == nil || !input.AuthorizeTarget(artifact.target) {
		return Result{}, reject(ErrorTargetDenied)
	}
	proof, err := ValidateOwnedSchema(input.BaseContract, input.LiveSchema)
	if err != nil {
		return Result{}, err
	}
	return Result{artifact: cloneArtifact(artifact), schema: cloneSchemaProof(proof)}, nil
}
