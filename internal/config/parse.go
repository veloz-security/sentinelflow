package config

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var databaseNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

type loader struct {
	lookup LookupFunc
	err    error
}

func newLoader(lookup LookupFunc) *loader { return &loader{lookup: lookup} }

func (l *loader) fail(name, problem string) {
	if l.err == nil {
		l.err = configError(name, problem)
	}
}

func (l *loader) raw(name, fallback string) string {
	if value, ok := l.lookup(name); ok {
		return value
	}
	return fallback
}

func (l *loader) text(name, fallback string) string {
	value := strings.TrimSpace(l.raw(name, fallback))
	if value == "" {
		l.fail(name, "must not be empty")
	}
	if strings.IndexByte(value, 0) >= 0 || containsControl(value) {
		l.fail(name, "contains invalid characters")
	}
	return value
}

func (l *loader) optionalText(name string) string {
	value := strings.TrimSpace(l.raw(name, ""))
	if strings.IndexByte(value, 0) >= 0 || containsControl(value) {
		l.fail(name, "contains invalid characters")
	}
	return value
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func (l *loader) enum(name, fallback string, allowed ...string) string {
	value := l.text(name, fallback)
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	l.fail(name, "has an unsupported value")
	return value
}

func (l *loader) integer(name string, fallback, min, max int) int {
	raw := strings.TrimSpace(l.raw(name, strconv.Itoa(fallback)))
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		l.fail(name, "must be a base-10 integer in the allowed range")
		return fallback
	}
	return value
}

func (l *loader) int64(name string, fallback, min, max int64) int64 {
	raw := strings.TrimSpace(l.raw(name, strconv.FormatInt(fallback, 10)))
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < min || value > max {
		l.fail(name, "must be a base-10 integer in the allowed range")
		return fallback
	}
	return value
}

func (l *loader) decimal(name string, fallback, min, max float64, optional bool) float64 {
	raw := strings.TrimSpace(l.raw(name, ""))
	if raw == "" {
		if optional {
			return 0
		}
		raw = strconv.FormatFloat(fallback, 'f', -1, 64)
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < min || value > max {
		l.fail(name, "must be a finite decimal in the allowed range")
		return fallback
	}
	return value
}

func (l *loader) boolean(name string, fallback bool) bool {
	raw := strings.TrimSpace(l.raw(name, strconv.FormatBool(fallback)))
	switch raw {
	case "true":
		return true
	case "false":
		return false
	default:
		l.fail(name, "must be exactly true or false")
		return fallback
	}
}

func (l *loader) duration(name, fallback string, min, max time.Duration) time.Duration {
	raw := strings.TrimSpace(l.raw(name, fallback))
	value, err := time.ParseDuration(raw)
	if err != nil || value < min || value > max {
		l.fail(name, "must be a duration in the allowed range")
		value, _ = time.ParseDuration(fallback)
	}
	return value
}

func (l *loader) path(name, fallback string, optional bool) string {
	value := strings.TrimSpace(l.raw(name, fallback))
	if value == "" {
		if !optional {
			l.fail(name, "must not be empty")
		}
		return ""
	}
	if strings.IndexByte(value, 0) >= 0 || filepath.Clean(value) == "." {
		l.fail(name, "must be a valid file path")
	}
	return value
}

func (l *loader) secretFile(name string) string {
	value := l.path(name, "", true)
	if value != "" && !filepath.IsAbs(value) {
		l.fail(name, "must be an absolute secret-file path")
	}
	return value
}

func (l *loader) opaqueSecret(name string) Secret {
	value := l.raw(name, "")
	if value != "" && (strings.TrimSpace(value) != value || containsControl(value)) {
		l.fail(name, "credential has invalid encoding")
	}
	return makeSecret(value)
}

func (l *loader) base64Secret(name string) Secret {
	secret := l.opaqueSecret(name)
	if !secret.IsSet() {
		return secret
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(secret.Reveal())
	if err != nil {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(secret.Reveal())
	}
	if err != nil || len(decoded) < 32 {
		l.fail(name, "must be standard base64 encoding of at least 32 bytes")
	}
	return secret
}

func (l *loader) databaseURL(name string) Secret {
	secret := l.opaqueSecret(name)
	if !secret.IsSet() {
		return secret
	}
	raw := secret.Reveal()
	parsed, err := url.Parse(raw)
	password, passwordPresent := "", false
	if parsed != nil && parsed.User != nil {
		password, passwordPresent = parsed.User.Password()
	}
	port := ""
	if parsed != nil {
		port = parsed.Port()
	}
	portNumber, portErr := strconv.Atoi(port)
	database := ""
	if parsed != nil && strings.HasPrefix(parsed.Path, "/") {
		database = strings.TrimPrefix(parsed.Path, "/")
	}
	if err != nil || parsed == nil || parsed.Scheme != "postgresql" || parsed.Opaque != "" ||
		parsed.Hostname() == "" || portErr != nil || portNumber < 1 || portNumber > 65535 ||
		port != strconv.Itoa(portNumber) || parsed.User == nil || parsed.User.Username() == "" ||
		!passwordPresent || password == "" || !databaseNamePattern.MatchString(database) ||
		parsed.EscapedPath() != "/"+database || parsed.ForceQuery || parsed.Fragment != "" ||
		(parsed.RawQuery != "sslmode=disable" && parsed.RawQuery != "sslmode=verify-full") ||
		parsed.String() != raw {
		l.fail(name, "must be a canonical credentialed postgresql URL with only an explicit sslmode")
		return secret
	}
	return secret
}

func (l *loader) httpURL(name, fallback, exactPath string) url.URL {
	raw := strings.TrimSpace(l.raw(name, fallback))
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		l.fail(name, "must be an http URL with a host and no credentials, query, or fragment")
		return url.URL{}
	}
	if exactPath != "" && parsed.EscapedPath() != exactPath {
		l.fail(name, "has an unexpected endpoint path")
	}
	return *parsed
}

func (l *loader) cidrs(name, fallback string, requirePrivate, requireSorted bool) []netip.Prefix {
	raw := strings.TrimSpace(l.raw(name, fallback))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	var previous netip.Prefix
	for _, part := range parts {
		part = strings.TrimSpace(part)
		prefix, err := netip.ParsePrefix(part)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			l.fail(name, "must contain canonical IPv4 CIDR prefixes")
			return nil
		}
		if requirePrivate && (prefix.Bits() < 16 || !privatePrefix(prefix)) {
			l.fail(name, "must contain only non-broad RFC 1918 IPv4 CIDRs")
			return nil
		}
		if _, exists := seen[prefix]; exists {
			l.fail(name, "must not contain duplicate CIDRs")
			return nil
		}
		if requireSorted && previous.IsValid() && comparePrefixes(previous, prefix) >= 0 {
			l.fail(name, "must contain unique CIDRs in ascending numeric order")
			return nil
		}
		seen[prefix] = struct{}{}
		previous = prefix
		result = append(result, prefix)
	}
	return result
}

func comparePrefixes(left, right netip.Prefix) int {
	if compared := left.Addr().Compare(right.Addr()); compared != 0 {
		return compared
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

func privatePrefix(prefix netip.Prefix) bool {
	private := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	last := prefix.Masked().Addr()
	for i := 0; i < 32-prefix.Bits(); i++ {
		last = last.Next()
	}
	for _, allowed := range private {
		if allowed.Contains(prefix.Addr()) && allowed.Contains(last) {
			return true
		}
	}
	return false
}

func (l *loader) prefix(name, fallback string) netip.Prefix {
	items := l.cidrs(name, fallback, false, false)
	if len(items) != 1 {
		l.fail(name, "must contain exactly one canonical IPv4 CIDR")
		return netip.Prefix{}
	}
	return items[0]
}

func (l *loader) address(name, fallback string) netip.Addr {
	raw := strings.TrimSpace(l.raw(name, fallback))
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() || raw != addr.String() {
		l.fail(name, "must be a canonical IPv4 address")
		return netip.Addr{}
	}
	return addr
}

func (l *loader) addresses(name, fallback string) []netip.Addr {
	raw := strings.TrimSpace(l.raw(name, fallback))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 64 {
		l.fail(name, "must contain at most 64 canonical IPv4 addresses")
		return nil
	}
	result := make([]netip.Addr, 0, len(parts))
	var previous netip.Addr
	for _, part := range parts {
		part = strings.TrimSpace(part)
		address, err := netip.ParseAddr(part)
		if err != nil || !address.Is4() || address.String() != part {
			l.fail(name, "must contain canonical IPv4 addresses")
			return nil
		}
		if previous.IsValid() && previous.Compare(address) >= 0 {
			l.fail(name, "must contain unique IPv4 addresses in ascending numeric order")
			return nil
		}
		result = append(result, address)
		previous = address
	}
	return result
}

func (l *loader) rfc3339(name, fallback string) time.Time {
	raw := strings.TrimSpace(l.raw(name, fallback))
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil || value.Format(time.RFC3339) != raw {
		l.fail(name, "must be a canonical RFC3339 timestamp")
		return time.Time{}
	}
	return value
}

func (l *loader) optionalMillisecondUTC(name string) time.Time {
	raw := strings.TrimSpace(l.raw(name, ""))
	if raw == "" {
		return time.Time{}
	}
	const layout = "2006-01-02T15:04:05.000Z"
	value, err := time.Parse(layout, raw)
	if err != nil || value.Format(layout) != raw {
		l.fail(name, "must be a millisecond-precision UTC timestamp")
		return time.Time{}
	}
	return value
}

func (l *loader) optionalSHA256Digest(name string) string {
	value := l.optionalText(name)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		l.fail(name, "must use lowercase sha256: encoding")
		return value
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
		l.fail(name, "must use lowercase sha256: encoding")
	}
	return value
}

func (l *loader) digest(name, fallback string) string {
	value := strings.TrimSpace(l.raw(name, fallback))
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
		l.fail(name, "must be exactly 64 lowercase hexadecimal characters")
	}
	return value
}

func (l *loader) optionalDigest(name string) string {
	value := strings.TrimSpace(l.raw(name, ""))
	if value == "" {
		return ""
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
		l.fail(name, "must be exactly 64 lowercase hexadecimal characters")
	}
	return value
}

func (l *loader) csv(name, fallback string) []string {
	raw := strings.TrimSpace(l.raw(name, fallback))
	if raw == "" {
		l.fail(name, "must not be empty")
		return nil
	}
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if parts[i] == "" || !safeIDPattern.MatchString(parts[i]) {
			l.fail(name, "contains an invalid identifier")
		}
		if _, exists := seen[parts[i]]; exists {
			l.fail(name, "contains a duplicate identifier")
		}
		seen[parts[i]] = struct{}{}
	}
	return parts
}

func (l *loader) origins(name, fallback string) []string {
	raw := strings.TrimSpace(l.raw(name, fallback))
	if raw == "" {
		l.fail(name, "must not be empty")
		return nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 32 {
		l.fail(name, "must contain at most 32 origins")
		return nil
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if parts[i] == "" || containsControl(parts[i]) {
			l.fail(name, "contains an invalid origin")
			return nil
		}
	}
	return parts
}

var safeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

var canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var eventLabelPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func (l *loader) eventLabel(name, fallback string) string {
	value := l.text(name, fallback)
	if !eventLabelPattern.MatchString(value) {
		l.fail(name, "must be a lowercase event label of 1 to 64 characters")
	}
	return value
}

func (l *loader) optionalSafeID(name string) string {
	value := l.optionalText(name)
	if value != "" && !safeIDPattern.MatchString(value) {
		l.fail(name, "must be a lowercase identifier of 1 to 64 characters")
	}
	return value
}

func (l *loader) optionalUUID(name string) string {
	value := l.optionalText(name)
	if value != "" && !canonicalUUIDPattern.MatchString(value) {
		l.fail(name, "must be a canonical lowercase UUID")
	}
	return value
}

func (l *loader) senderID(name, fallback string) string {
	value := l.text(name, fallback)
	if !safeIDPattern.MatchString(value) {
		l.fail(name, "must be a lowercase sender identifier of 1 to 64 characters")
	}
	return value
}

func (l *loader) listenAddress(name, fallback string, privateOnly bool) string {
	value := l.text(name, fallback)
	host, portText, err := net.SplitHostPort(value)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 {
		l.fail(name, "must be a valid host:port listener")
		return value
	}
	if privateOnly {
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil || !addr.Is4() || !addr.IsPrivate() {
			l.fail(name, "must bind a private IPv4 address")
		}
	}
	return value
}

func (l *loader) privateMetricsListenAddress(name, fallback string) string {
	raw := l.raw(name, fallback)
	value := l.text(name, fallback)
	host, portText, err := net.SplitHostPort(value)
	port, portErr := strconv.Atoi(portText)
	address, addressErr := netip.ParseAddr(host)
	if raw != value || err != nil || portErr != nil || addressErr != nil ||
		!address.Is4() || (!address.IsLoopback() && !address.IsPrivate()) ||
		address.String() != host ||
		port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		l.fail(name, "must bind a canonical loopback or private IPv4 host:port listener")
	}
	return value
}

func (l *loader) host(name, fallback string) string {
	value := l.text(name, fallback)
	if value != strings.ToLower(value) || !isASCII(value) || strings.ContainsAny(value, "@/?#") {
		l.fail(name, "must be a lowercase ASCII DNS host with an optional port")
		return value
	}
	host := value
	if strings.Contains(value, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil {
			l.fail(name, "must have an unambiguous optional port")
			return value
		}
		parsed, err := strconv.Atoi(port)
		if err != nil || parsed < 1 || parsed > 65535 {
			l.fail(name, "contains an invalid port")
		}
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || net.ParseIP(host) != nil || !validDNSName(host) {
		l.fail(name, "must contain a DNS name rather than an IP literal")
	}
	return value
}

func validDNSName(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > 0x7f {
			return false
		}
	}
	return true
}

func validateArgon2idPHC(value string) bool {
	if len(value) == 0 || len(value) > 8192 {
		return false
	}
	parts := strings.Split(value, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 || !strings.HasPrefix(params[0], "m=") ||
		!strings.HasPrefix(params[1], "t=") || !strings.HasPrefix(params[2], "p=") {
		return false
	}
	parsed := map[string]int{}
	for index, param := range params {
		pair := strings.SplitN(param, "=", 2)
		if len(pair) != 2 || pair[1] == "" || len(pair[1]) > 10 ||
			(len(pair[1]) > 1 && pair[1][0] == '0') {
			return false
		}
		for _, character := range pair[1] {
			if character < '0' || character > '9' {
				return false
			}
		}
		v, err := strconv.Atoi(pair[1])
		if err != nil {
			return false
		}
		expected := []string{"m", "t", "p"}[index]
		if pair[0] != expected {
			return false
		}
		parsed[pair[0]] = v
	}
	if parsed["m"] < 65536 || parsed["m"] > 262144 ||
		parsed["t"] < 3 || parsed["t"] > 10 ||
		parsed["p"] < 2 || parsed["p"] > 16 {
		return false
	}
	salt, errSalt := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	hash, errHash := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	return errSalt == nil && errHash == nil &&
		base64.RawStdEncoding.EncodeToString(salt) == parts[4] &&
		base64.RawStdEncoding.EncodeToString(hash) == parts[5] &&
		len(salt) >= 16 && len(salt) <= 64 && len(hash) >= 32 && len(hash) <= 64
}
