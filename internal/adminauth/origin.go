package adminauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/url"
	"strconv"
	"strings"
)

// OriginPolicy stores only fixed-size digests of exact, canonical origins.
type OriginPolicy struct {
	digests [][sha256.Size]byte
}

func NewOriginPolicy(origins []string) (*OriginPolicy, error) {
	if len(origins) == 0 || len(origins) > 32 {
		return nil, ErrInvalidConfiguration
	}
	policy := &OriginPolicy{digests: make([][sha256.Size]byte, 0, len(origins))}
	seen := make(map[[sha256.Size]byte]struct{}, len(origins))
	for _, origin := range origins {
		if !canonicalOrigin(origin) {
			return nil, ErrInvalidConfiguration
		}
		digest := sha256.Sum256([]byte(origin))
		if _, exists := seen[digest]; exists {
			return nil, ErrInvalidConfiguration
		}
		seen[digest] = struct{}{}
		policy.digests = append(policy.digests, digest)
	}
	return policy, nil
}

func canonicalOrigin(origin string) bool {
	if len(origin) < 8 || len(origin) > 512 || strings.HasSuffix(origin, "/") {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.String() != origin {
		return false
	}
	if parsed.Scheme == "http" && parsed.Hostname() != "localhost" && !strings.HasSuffix(parsed.Hostname(), ".localhost") {
		return false
	}
	host := parsed.Hostname()
	if !canonicalASCIIHostname(host) {
		return false
	}
	if port := parsed.Port(); port != "" {
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort < 1 || parsedPort > 65535 || strconv.Itoa(parsedPort) != port {
			return false
		}
	}
	return true
}

func canonicalASCIIHostname(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) ||
		strings.HasSuffix(host, ".") || strings.ContainsAny(host, " \t\r\n") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			value := label[index]
			if !(value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-') {
				return false
			}
		}
	}
	return true
}

// Validate performs a constant-time comparison across the complete allowlist.
func (p *OriginPolicy) Validate(origin string) error {
	if p == nil || !canonicalOrigin(origin) {
		return ErrBrowserRequest
	}
	candidate := sha256.Sum256([]byte(origin))
	matched := 0
	for i := range p.digests {
		matched |= subtle.ConstantTimeCompare(candidate[:], p.digests[i][:])
	}
	if matched != 1 {
		return ErrBrowserRequest
	}
	return nil
}
