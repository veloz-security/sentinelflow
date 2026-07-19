package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"time"
)

// Resolver is intentionally small so DNS rebinding and mixed-address cases
// can be tested without replacing the transport.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type netResolver struct{ resolver *net.Resolver }

func (r netResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return r.resolver.LookupNetIP(ctx, network, host)
}

// OriginPolicy validates every address returned for the fixed origin. It never
// filters a mixed answer set down to an allowed subset.
type OriginPolicy struct {
	host     string
	port     string
	prefixes []netip.Prefix
	resolver Resolver
	dialer   net.Dialer
}

func NewOriginPolicy(hostport string, prefixes []netip.Prefix, resolver Resolver) (*OriginPolicy, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, errors.New("gateway: upstream URL must include a valid port")
	}
	if resolver == nil {
		resolver = netResolver{resolver: net.DefaultResolver}
	}
	policy := &OriginPolicy{host: host, port: port, prefixes: append([]netip.Prefix(nil), prefixes...), resolver: resolver}
	for _, prefix := range policy.prefixes {
		if err := validateOriginPrefix(prefix); err != nil {
			return nil, err
		}
	}
	return policy, nil
}

func (p *OriginPolicy) Resolve(ctx context.Context) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(p.host); err == nil {
		if !allowedOrigin(literal, p.prefixes) {
			return nil, errors.New("gateway: fixed origin literal is not allowed")
		}
		return []netip.Addr{literal}, nil
	}
	addresses, err := p.resolver.LookupNetIP(ctx, "ip", p.host)
	if err != nil {
		return nil, errors.New("gateway: fixed origin resolution failed")
	}
	if len(addresses) == 0 {
		return nil, errors.New("gateway: fixed origin returned no addresses")
	}
	seen := make(map[netip.Addr]struct{}, len(addresses))
	allowed := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if !allowedOrigin(address, p.prefixes) {
			return nil, errors.New("gateway: fixed origin returned IPv6, public, or mixed addresses")
		}
		if _, duplicate := seen[address]; !duplicate {
			seen[address] = struct{}{}
			allowed = append(allowed, address)
		}
	}
	sort.Slice(allowed, func(i, j int) bool { return allowed[i].Less(allowed[j]) })
	return allowed, nil
}

func (p *OriginPolicy) Check(ctx context.Context) error {
	_, err := p.Resolve(ctx)
	return err
}

func (p *OriginPolicy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("gateway: unsupported origin network")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != p.host || port != p.port {
		return nil, errors.New("gateway: attempted dynamic origin")
	}
	addresses, err := p.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, candidate := range addresses {
		connection, dialErr := p.dialer.DialContext(ctx, "tcp4", net.JoinHostPort(candidate.String(), p.port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	return nil, fmt.Errorf("gateway: fixed origin connection failed: %w", lastErr)
}

func allowedOrigin(address netip.Addr, prefixes []netip.Prefix) bool {
	if !address.Is4() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// NewOriginTransport returns a dedicated, proxy-free HTTP/1 transport. New
// connections resolve and revalidate the fixed origin before dialing an IP.
func NewOriginTransport(policy *OriginPolicy, timeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           policy.DialContext,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       60 * time.Second,
	}
}
