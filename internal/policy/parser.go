package policy

import (
	"bytes"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"unicode/utf8"
)

var commandPattern = regexp.MustCompile(`^add element inet sentinelflow blacklist_ipv4 \{ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) timeout ([1-9][0-9]{0,4}[smh]) \}\n?$`)

var ttlPattern = regexp.MustCompile(`^([1-9][0-9]{0,4})([smh])$`)

// Parse accepts one generated add statement with exact ASCII token spacing and
// either no terminator or exactly one LF. Canonical serializing always emits
// exactly one LF.
func Parse(generated []byte) (AST, error) {
	if len(generated) == 0 || len(generated) > MaxGeneratedBytes || !utf8.Valid(generated) || bytes.HasPrefix(generated, []byte{0xef, 0xbb, 0xbf}) {
		return AST{}, reject(ErrorSyntax)
	}
	for _, value := range generated {
		if value > 0x7f || value == 0 {
			return AST{}, reject(ErrorSyntax)
		}
	}
	matches := commandPattern.FindSubmatch(generated)
	if len(matches) != 3 {
		return AST{}, reject(ErrorSyntax)
	}
	addressText := string(matches[1])
	address, err := netip.ParseAddr(addressText)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.String() != addressText {
		return AST{}, reject(ErrorTarget)
	}
	seconds, err := ParseTTL(string(matches[2]))
	if err != nil {
		return AST{}, err
	}
	return AST{target: address, ttlSeconds: seconds, inputTTLToken: string(matches[2])}, nil
}

// ParseTTL uses checked integer arithmetic and accepts only the frozen token
// grammar. It does not silently canonicalize the supplied token.
func ParseTTL(token string) (uint32, error) {
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

func CanonicalTTL(seconds uint32) (string, error) {
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
