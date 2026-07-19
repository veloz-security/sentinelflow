package config

import (
	"crypto/sha256"
	"net/url"
	"strconv"
	"strings"
)

// These syntax-only checks intentionally mirror adminauth's runtime policy
// without importing the administrator package into every service binary that
// consumes shared configuration. Runtime construction performs the same check
// again before accepting browser traffic.
func validAdminOrigins(origins []string) bool {
	if len(origins) == 0 || len(origins) > 32 {
		return false
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(origins))
	for _, origin := range origins {
		if !canonicalAdminOrigin(origin) {
			return false
		}
		digest := sha256.Sum256([]byte(origin))
		if _, exists := seen[digest]; exists {
			return false
		}
		seen[digest] = struct{}{}
	}
	return true
}

func canonicalAdminOrigin(origin string) bool {
	if len(origin) < 8 || len(origin) > 512 || strings.HasSuffix(origin, "/") {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" ||
		parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.String() != origin {
		return false
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" && host != "localhost" && !strings.HasSuffix(host, ".localhost") {
		return false
	}
	if !canonicalAdminHostname(host) {
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

func canonicalAdminHostname(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) ||
		strings.HasSuffix(host, ".") || strings.ContainsAny(host, " \t\r\n") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
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

func validCookieName(name string) bool {
	return name != "" && len(name) <= 128 &&
		!strings.ContainsAny(name, "()<>@,;:\\\"/[]?={} \t\r\n")
}
