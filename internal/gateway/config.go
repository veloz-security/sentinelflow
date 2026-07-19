// Package gateway implements SentinelFlow's bounded HTTP/1.1 data plane.
package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/config"
)

const (
	DefaultMaxHeaderBytes              = 32 * 1024
	DefaultMaxRequestTargetBytes       = 4 * 1024
	DefaultMaxPathBytes                = 2 * 1024
	DefaultMaxBodyBytes          int64 = 10 * 1024 * 1024
)

var labelRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Config is immutable after New. Client input cannot select any field in it.
type Config struct {
	PublicHosts           []string
	TLS                   bool
	ServiceLabel          string
	UpstreamURL           *url.URL
	UpstreamHost          string
	OriginCIDRs           []netip.Prefix
	MaxRequestTarget      int
	MaxClassificationPath int
	MaxBodyBytes          int64
	RequestTimeout        time.Duration
	UpstreamTimeout       time.Duration
	PathCatalogVersion    string
	LoginRoutePath        string
	LoginRouteLabel       string
}

// ConfigFromRuntime copies the role-specific startup configuration into the
// smaller data-plane contract used by this package.
func ConfigFromRuntime(c config.GatewayConfig) Config {
	u := c.UpstreamURL
	return Config{
		PublicHosts:           []string{c.PublicHost},
		TLS:                   c.TLSCertFile != "",
		ServiceLabel:          c.ServiceLabel,
		UpstreamURL:           &u,
		UpstreamHost:          c.UpstreamHost,
		OriginCIDRs:           append([]netip.Prefix(nil), c.OriginCIDRs...),
		MaxRequestTarget:      c.MaxRequestTargetBytes,
		MaxClassificationPath: c.MaxClassificationPathBytes,
		MaxBodyBytes:          c.MaxBodyBytes,
		RequestTimeout:        c.RequestTimeout,
		UpstreamTimeout:       c.UpstreamTimeout,
		PathCatalogVersion:    c.PathCatalogVersion,
		LoginRoutePath:        c.AuthRoutePath,
		LoginRouteLabel:       c.AuthRouteLabel,
	}
}

func (c *Config) setDefaults() {
	if c.MaxRequestTarget == 0 {
		c.MaxRequestTarget = DefaultMaxRequestTargetBytes
	}
	if c.MaxClassificationPath == 0 {
		c.MaxClassificationPath = DefaultMaxPathBytes
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 30 * time.Second
	}
	if c.UpstreamTimeout == 0 {
		c.UpstreamTimeout = 30 * time.Second
	}
	if c.PathCatalogVersion == "" {
		c.PathCatalogVersion = "path-catalog-v1"
	}
	if c.LoginRouteLabel == "" {
		c.LoginRouteLabel = "login"
	}
}

func (c Config) validate() error {
	if len(c.PublicHosts) == 0 {
		return errors.New("gateway: at least one public host is required")
	}
	seen := make(map[string]struct{}, len(c.PublicHosts))
	for _, value := range c.PublicHosts {
		normalized, err := normalizeConfiguredHost(value, c.TLS)
		if err != nil {
			return fmt.Errorf("gateway: invalid public host: %w", err)
		}
		if normalized != value {
			return fmt.Errorf("gateway: public host %q is not canonical lowercase ASCII", value)
		}
		if _, exists := seen[normalized]; exists {
			return fmt.Errorf("gateway: duplicate public host %q", value)
		}
		seen[normalized] = struct{}{}
	}
	if !labelRE.MatchString(c.ServiceLabel) {
		return errors.New("gateway: service label must be a lowercase ASCII label")
	}
	if c.UpstreamURL == nil {
		return errors.New("gateway: one upstream URL is required")
	}
	if c.UpstreamURL.Scheme != "http" || c.UpstreamURL.Host == "" {
		return errors.New("gateway: upstream must be one absolute http URL")
	}
	if c.UpstreamURL.User != nil || c.UpstreamURL.RawQuery != "" || c.UpstreamURL.Fragment != "" ||
		(c.UpstreamURL.Path != "" && c.UpstreamURL.Path != "/") || c.UpstreamURL.RawPath != "" {
		return errors.New("gateway: upstream URL must contain only scheme and authority")
	}
	normalizedUpstreamHost, err := normalizeConfiguredHost(c.UpstreamHost, false)
	if err != nil {
		return fmt.Errorf("gateway: invalid fixed upstream host: %w", err)
	}
	if normalizedUpstreamHost != c.UpstreamHost {
		return errors.New("gateway: fixed upstream host is not canonical lowercase ASCII")
	}
	if c.MaxRequestTarget < 256 || c.MaxRequestTarget > DefaultMaxRequestTargetBytes {
		return errors.New("gateway: request-target limit must be between 256 and 4096 bytes")
	}
	if c.MaxClassificationPath < 128 || c.MaxClassificationPath > DefaultMaxPathBytes || c.MaxClassificationPath > c.MaxRequestTarget {
		return errors.New("gateway: classification path limit must be between 128 and 2048 bytes and not exceed request-target limit")
	}
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > DefaultMaxBodyBytes {
		return errors.New("gateway: body limit must be between 1 byte and 10 MiB")
	}
	if c.RequestTimeout <= 0 || c.RequestTimeout > 30*time.Second || c.UpstreamTimeout <= 0 || c.UpstreamTimeout > 30*time.Second {
		return errors.New("gateway: request and upstream timeouts must be positive and at most 30 seconds")
	}
	if c.PathCatalogVersion != "path-catalog-v1" {
		return errors.New("gateway: unsupported path catalog version")
	}
	if !labelRE.MatchString(c.LoginRouteLabel) {
		return errors.New("gateway: login route label must be a lowercase ASCII label")
	}
	if len(c.OriginCIDRs) == 0 {
		return errors.New("gateway: at least one private origin CIDR is required")
	}
	for _, prefix := range c.OriginCIDRs {
		if err := validateOriginPrefix(prefix); err != nil {
			return err
		}
	}
	if ip, err := netip.ParseAddr(c.UpstreamURL.Hostname()); err == nil && !allowedOrigin(ip, c.OriginCIDRs) {
		return errors.New("gateway: literal upstream address is outside the origin CIDRs")
	}
	canonicalLogin, err := canonicalPath(c.LoginRoutePath, c.MaxClassificationPath)
	if err != nil || canonicalLogin != c.LoginRoutePath || strings.Contains(c.LoginRoutePath, "?") {
		return errors.New("gateway: login route path must be a canonical bounded path")
	}
	return nil
}

func validateOriginPrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < 16 {
		return errors.New("gateway: origin CIDRs must be canonical IPv4 prefixes of /16 or narrower")
	}
	private := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	for _, allowed := range private {
		if allowed.Contains(prefix.Addr()) && allowed.Contains(prefixLastAddr(prefix)) {
			return nil
		}
	}
	return errors.New("gateway: origin CIDRs must be wholly inside RFC1918 space")
}

func prefixLastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr().As4()
	bits := prefix.Bits()
	for bit := bits; bit < 32; bit++ {
		byteIndex := bit / 8
		bitIndex := 7 - (bit % 8)
		addr[byteIndex] |= byte(1 << bitIndex)
	}
	return netip.AddrFrom4(addr)
}
